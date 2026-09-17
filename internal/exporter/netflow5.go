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

type NetFlowV5Header struct {
	Version          uint16
	Count            uint16
	SysUptime        uint32
	UnixSecs         uint32
	UnixNanos        uint32
	FlowSequence     uint32
	EngineType       uint8
	EngineID         uint8
	SamplingInterval uint16
}

type NetFlowV5Record struct {
	SrcAddr  [4]byte
	DstAddr  [4]byte
	NextHop  [4]byte
	Input    uint16
	Output   uint16
	DPkts    uint32
	DOctets  uint32
	First    uint32
	Last     uint32
	SrcPort  uint16
	DstPort  uint16
	Pad1     uint8
	TCPFlags uint8
	Prot     uint8
	Tos      uint8
	SrcAs    uint16
	DstAs    uint16
	SrcMask  uint8
	DstMask  uint8
	Pad2     uint16
}

type NetFlowV5Exporter struct {
	cfg       *config.ExporterConfig
	conn      net.Conn
	bootTime  time.Time
	flowSeq   uint32
	mu        sync.Mutex
}

func NewNetFlowV5Exporter(cfg *config.ExporterConfig) (*NetFlowV5Exporter, error) {
	return &NetFlowV5Exporter{
		cfg:      cfg,
		bootTime: time.Now().Add(-100 * time.Second),
	}, nil
}

func (e *NetFlowV5Exporter) Start(ctx context.Context, inChan <-chan *flow.Record) error {
	addr := net.JoinHostPort(e.cfg.Target, fmt.Sprintf("%d", e.cfg.Port))
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to dial UDP exporter %s: %w", addr, err)
	}
	e.conn = conn

	batch := make([]*flow.Record, 0, 30)
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
			// NetFlow v5 only supports IPv4
			if rec.SrcIP.To4() != nil && rec.DstIP.To4() != nil {
				batch = append(batch, rec)
				if len(batch) >= 30 {
					e.sendBatch(batch)
					batch = make([]*flow.Record, 0, 30)
				}
			}
		case <-ticker.C:
			if len(batch) > 0 {
				e.sendBatch(batch)
				batch = make([]*flow.Record, 0, 30)
			}
		}
	}
}

func (e *NetFlowV5Exporter) sendBatch(batch []*flow.Record) {
	if len(batch) == 0 || e.conn == nil {
		return
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	now := time.Now()
	uptime := uint32(time.Since(e.bootTime).Milliseconds())

	buf := new(bytes.Buffer)
	hdr := NetFlowV5Header{
		Version:          5,
		Count:            uint16(len(batch)),
		SysUptime:        uptime,
		UnixSecs:         uint32(now.Unix()),
		UnixNanos:        uint32(now.UnixNano() % 1000000000),
		FlowSequence:     e.flowSeq,
		EngineType:       e.cfg.EngineType,
		EngineID:         e.cfg.EngineID,
		SamplingInterval: 0,
	}
	e.flowSeq += uint32(len(batch))

	_ = binary.Write(buf, binary.BigEndian, hdr)

	for _, r := range batch {
		src4 := r.SrcIP.To4()
		dst4 := r.DstIP.To4()
		firstMs := uint32(r.StartTime.Sub(e.bootTime).Milliseconds())
		lastMs := uint32(r.LastSeen.Sub(e.bootTime).Milliseconds())

		rec := NetFlowV5Record{
			Input:    uint16(r.IfIndex),
			Output:   uint16(r.IfIndex),
			DPkts:    uint32(r.TotalPackets),
			DOctets:  uint32(r.TotalBytes),
			First:    firstMs,
			Last:     lastMs,
			SrcPort:  r.SrcPort,
			DstPort:  r.DstPort,
			TCPFlags: r.TCPFlags,
			Prot:     r.IPProto,
			Tos:      r.TOS,
			SrcMask:  24,
			DstMask:  24,
		}
		copy(rec.SrcAddr[:], src4)
		copy(rec.DstAddr[:], dst4)

		_ = binary.Write(buf, binary.BigEndian, rec)
	}

	_, _ = e.conn.Write(buf.Bytes())
}

func (e *NetFlowV5Exporter) Close() error {
	if e.conn != nil {
		return e.conn.Close()
	}
	return nil
}
