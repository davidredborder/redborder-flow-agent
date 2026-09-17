package exporter

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/redborder/redborder-flow-agent/internal/config"
	"github.com/redborder/redborder-flow-agent/internal/flow"
)

type SFlowExporter struct {
	cfg       *config.ExporterConfig
	conn      net.Conn
	bootTime  time.Time
	dgSeq     uint32
	sampleSeq uint32
	agentIP   [4]byte
	mu        sync.Mutex
}

func NewSFlowExporter(cfg *config.ExporterConfig) (*SFlowExporter, error) {
	if cfg.SFlowSamplingRate <= 0 {
		cfg.SFlowSamplingRate = 1
	}
	return &SFlowExporter{
		cfg:      cfg,
		bootTime: time.Now().Add(-100 * time.Second),
		agentIP:  [4]byte{127, 0, 0, 1},
	}, nil
}

func (e *SFlowExporter) Start(ctx context.Context, inChan <-chan *flow.Record) error {
	addr := net.JoinHostPort(e.cfg.Target, fmt.Sprintf("%d", e.cfg.Port))
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to dial sFlow exporter %s: %w", addr, err)
	}
	e.conn = conn

	if localAddr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		if ip4 := localAddr.IP.To4(); ip4 != nil {
			copy(e.agentIP[:], ip4)
		}
	}

	batch := make([]*flow.Record, 0, 10)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			if len(batch) > 0 {
				e.sendBatch(batch)
			}
			return nil
		case rec, ok := <-inChan:
			if !ok {
				if len(batch) > 0 {
					e.sendBatch(batch)
				}
				return nil
			}
			batch = append(batch, rec)
			if len(batch) >= 10 {
				e.sendBatch(batch)
				batch = make([]*flow.Record, 0, 10)
			}
		case <-ticker.C:
			if len(batch) > 0 {
				e.sendBatch(batch)
				batch = make([]*flow.Record, 0, 10)
			}
		}
	}
}

func (e *SFlowExporter) sendBatch(batch []*flow.Record) {
	if len(batch) == 0 || e.conn == nil {
		return
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	buf := new(bytes.Buffer)
	uptime := uint32(time.Since(e.bootTime).Milliseconds())

	// sFlow Datagram Header
	_ = binary.Write(buf, binary.BigEndian, uint32(5)) // Version 5
	_ = binary.Write(buf, binary.BigEndian, uint32(1)) // IP Version (IPv4)
	_ = binary.Write(buf, binary.BigEndian, e.agentIP)  // Agent IP
	_ = binary.Write(buf, binary.BigEndian, uint32(0)) // Sub-agent ID
	_ = binary.Write(buf, binary.BigEndian, e.dgSeq)   // Datagram Sequence
	_ = binary.Write(buf, binary.BigEndian, uptime)    // Switch Uptime
	_ = binary.Write(buf, binary.BigEndian, uint32(len(batch))) // Num Samples
	e.dgSeq++

	for _, r := range batch {
		sampleBuf := new(bytes.Buffer)
		_ = binary.Write(sampleBuf, binary.BigEndian, e.sampleSeq)
		_ = binary.Write(sampleBuf, binary.BigEndian, uint32(r.IfIndex))
		_ = binary.Write(sampleBuf, binary.BigEndian, e.cfg.SFlowSamplingRate)
		_ = binary.Write(sampleBuf, binary.BigEndian, e.sampleSeq*e.cfg.SFlowSamplingRate) // Sample pool
		_ = binary.Write(sampleBuf, binary.BigEndian, uint32(0))                           // Drops
		_ = binary.Write(sampleBuf, binary.BigEndian, uint32(r.IfIndex))                   // Input If
		_ = binary.Write(sampleBuf, binary.BigEndian, uint32(r.IfIndex))                   // Output If
		_ = binary.Write(sampleBuf, binary.BigEndian, uint32(1))                           // Num Flow Records
		e.sampleSeq++

		// Synthesize Sampled Raw Ethernet/IP Header
		hBuf := new(bytes.Buffer)
		dstMAC := make([]byte, 6)
		srcMAC := make([]byte, 6)
		copy(dstMAC, r.DstMAC)
		copy(srcMAC, r.SrcMAC)
		hBuf.Write(dstMAC)
		hBuf.Write(srcMAC)
		if r.VLANID > 0 {
			hBuf.Write([]byte{0x81, 0x00}) // 802.1Q Tag Type
			_ = binary.Write(hBuf, binary.BigEndian, r.VLANID&0x0FFF)
		}
		hBuf.Write([]byte{0x08, 0x00}) // IPv4 EtherType

		src4 := r.SrcIP.To4()
		dst4 := r.DstIP.To4()
		if src4 == nil {
			src4 = net.IPv4zero.To4()
		}
		if dst4 == nil {
			dst4 = net.IPv4zero.To4()
		}

		// IPv4 Total Length: 20 IP bytes + L4 bytes
		l4Len := uint16(8)
		if r.IPProto == 6 { // TCP
			l4Len = 20
		}
		ipTotalLen := uint16(20 + l4Len)
		hBuf.Write([]byte{0x45, 0x00, byte(ipTotalLen >> 8), byte(ipTotalLen & 0xff), 0x00, 0x00, 0x40, 0x00, 0x40, r.IPProto, 0x00, 0x00})
		hBuf.Write(src4)
		hBuf.Write(dst4)

		// L4 Transport Header
		_ = binary.Write(hBuf, binary.BigEndian, r.SrcPort)
		_ = binary.Write(hBuf, binary.BigEndian, r.DstPort)
		if r.IPProto == 6 {
			// TCP: Seq (4), Ack (4), DataOffset (0x50), Flags, Window (2), Checksum (2), UrgPtr (2)
			_ = binary.Write(hBuf, binary.BigEndian, uint32(0)) // Seq
			_ = binary.Write(hBuf, binary.BigEndian, uint32(0)) // Ack
			hBuf.WriteByte(0x50)                                // Data offset (5 words = 20 bytes)
			hBuf.WriteByte(r.TCPFlags)                          // Flags
			_ = binary.Write(hBuf, binary.BigEndian, uint16(65535)) // Window
			_ = binary.Write(hBuf, binary.BigEndian, uint16(0))     // Checksum
			_ = binary.Write(hBuf, binary.BigEndian, uint16(0))     // UrgPtr
		} else {
			// UDP: Length (2), Checksum (2)
			_ = binary.Write(hBuf, binary.BigEndian, uint16(8))
			_ = binary.Write(hBuf, binary.BigEndian, uint16(0))
		}
		headerBytes := hBuf.Bytes()

		frameLen := r.TotalBytes
		if e.cfg.SFlowSamplingRate > 1 {
			frameLen = r.TotalBytes / uint64(e.cfg.SFlowSamplingRate)
			if frameLen == 0 && r.TotalBytes > 0 {
				frameLen = 1
			}
		}

		// Flow Record: Sampled Header (Enterprise 0, Format 1)
		recBuf := new(bytes.Buffer)
		_ = binary.Write(recBuf, binary.BigEndian, uint32(1)) // Protocol: Ethernet
		_ = binary.Write(recBuf, binary.BigEndian, uint32(frameLen)) // Frame length
		_ = binary.Write(recBuf, binary.BigEndian, uint32(0)) // Stripped bytes
		_ = binary.Write(recBuf, binary.BigEndian, uint32(len(headerBytes)))
		recBuf.Write(headerBytes)
		for recBuf.Len()%4 != 0 {
			recBuf.WriteByte(0)
		}

		// Record Header
		_ = binary.Write(sampleBuf, binary.BigEndian, uint32(1)) // Enterprise 0, Format 1
		_ = binary.Write(sampleBuf, binary.BigEndian, uint32(recBuf.Len()))
		sampleBuf.Write(recBuf.Bytes())

		// Sample Header
		_ = binary.Write(buf, binary.BigEndian, uint32(1)) // Flow Sample (Format 1)
		_ = binary.Write(buf, binary.BigEndian, uint32(sampleBuf.Len()))
		buf.Write(sampleBuf.Bytes())
	}

	_, _ = e.conn.Write(buf.Bytes())
}

func (e *SFlowExporter) Close() error {
	if e.conn != nil {
		return e.conn.Close()
	}
	return nil
}
