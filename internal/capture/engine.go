package capture

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/redborder/redborder-flow-agent/internal/config"
)

// Engine coordinates multi-interface packet ingestion.
type Engine struct {
	cfg        *config.CaptureConfig
	packetChan chan *ParsedPacket
	workers    []*InterfaceWorker
	logger     *slog.Logger
	cancelFunc context.CancelFunc
	wg         sync.WaitGroup
}

// NewEngine initializes the capture engine.
func NewEngine(cfg *config.CaptureConfig, bufSize int, logger *slog.Logger) (*Engine, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if bufSize <= 0 {
		bufSize = 65536
	}

	return &Engine{
		cfg:        cfg,
		packetChan: make(chan *ParsedPacket, bufSize),
		logger:     logger,
	}, nil
}

// PacketChan returns the channel where decoded packets are published.
func (e *Engine) PacketChan() <-chan *ParsedPacket {
	return e.packetChan
}

// Start launches capture across all configured interfaces or from PCAP file.
func (e *Engine) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	e.cancelFunc = cancel

	if e.cfg.PcapFile != "" {
		e.wg.Add(1)
		go e.readPcapLoop(ctx)
		return nil
	}

	for _, ifaceName := range e.cfg.Interfaces {
		w, err := NewInterfaceWorker(
			ifaceName,
			e.cfg.Promiscuous,
			e.cfg.SnapLen,
			e.cfg.WorkersPerInterface,
			e.packetChan,
			e.logger,
		)
		if err != nil {
			e.Close()
			return fmt.Errorf("failed to initialize capture on interface %s: %w", ifaceName, err)
		}

		if err := w.Start(ctx); err != nil {
			e.Close()
			return fmt.Errorf("failed to start capture on interface %s: %w", ifaceName, err)
		}
		e.workers = append(e.workers, w)
	}

	return nil
}

// readPcapLoop replays packets from an offline PCAP file for testing and verification.
func (e *Engine) readPcapLoop(ctx context.Context) {
	defer e.wg.Done()
	e.logger.Info("opening offline PCAP file", "path", e.cfg.PcapFile)

	f, err := os.Open(e.cfg.PcapFile)
	if err != nil {
		e.logger.Error("failed to open PCAP file", "err", err)
		return
	}
	defer f.Close()

	header := make([]byte, 24)
	if _, err := io.ReadFull(f, header); err != nil {
		e.logger.Error("failed to read PCAP global header", "err", err)
		return
	}

	var isLittle bool
	if bytes.Equal(header[0:4], []byte{0xd4, 0xc3, 0xb2, 0xa1}) {
		isLittle = true
	} else if bytes.Equal(header[0:4], []byte{0xa1, 0xb2, 0xc3, 0xd4}) {
		isLittle = false
	} else {
		e.logger.Error("unsupported PCAP magic header format")
		return
	}

	ph := make([]byte, 16)
	for {
		select {
		case <-ctx.Done():
			return
		default:
			if _, err := io.ReadFull(f, ph); err != nil {
				e.logger.Info("finished reading PCAP file")
				return
			}

			var inclLen, origLen uint32
			if isLittle {
				inclLen = binary.LittleEndian.Uint32(ph[8:12])
				origLen = binary.LittleEndian.Uint32(ph[12:16])
			} else {
				inclLen = binary.BigEndian.Uint32(ph[8:12])
				origLen = binary.BigEndian.Uint32(ph[12:16])
			}

			pktData := make([]byte, inclLen)
			if _, err := io.ReadFull(f, pktData); err != nil {
				return
			}

			parsed, err := FastDecode(pktData, time.Now(), int(inclLen), int(origLen), "pcap0", 1)
			if err != nil {
				continue
			}

			select {
			case e.packetChan <- parsed:
			case <-ctx.Done():
				return
			}
		}
	}
}

// Close stops all workers and releases raw sockets.
func (e *Engine) Close() {
	if e.cancelFunc != nil {
		e.cancelFunc()
	}
	for _, w := range e.workers {
		w.Close()
	}
	e.wg.Wait()
}
