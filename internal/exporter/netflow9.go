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

type NetFlowV9Header struct {
	Version      uint16
	Count        uint16
	SysUptime    uint32
	UnixSecs     uint32
	FlowSequence uint32
	SourceID     uint32
}

type NetFlowV9Field struct {
	Type   uint16
	Length uint16
}

type NetFlowV9Exporter struct {
	cfg       *config.ExporterConfig
	conn      net.Conn
	bootTime  time.Time
	flowSeq   uint32
	lastTmpl  time.Time
	mu        sync.Mutex
}

func NewNetFlowV9Exporter(cfg *config.ExporterConfig) (*NetFlowV9Exporter, error) {
	return &NetFlowV9Exporter{
		cfg:      cfg,
		bootTime: time.Now().Add(-100 * time.Second),
		lastTmpl: time.Now().Add(-1 * time.Hour),
	}, nil
}

func (e *NetFlowV9Exporter) Start(ctx context.Context, inChan <-chan *flow.Record) error {
	addr := net.JoinHostPort(e.cfg.Target, fmt.Sprintf("%d", e.cfg.Port))
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to dial UDP exporter %s: %w", addr, err)
	}
	e.conn = conn

	tmplInterval := time.Duration(e.cfg.TemplateIntervalSec) * time.Second
	if tmplInterval <= 0 {
		tmplInterval = 30 * time.Second
	}

	batch := make([]*flow.Record, 0, 20)
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
			if time.Since(e.lastTmpl) > tmplInterval {
				e.sendTemplate()
			}
			batch = append(batch, rec)
			if len(batch) >= 20 {
				e.sendBatch(batch)
				batch = make([]*flow.Record, 0, 20)
			}
		case <-ticker.C:
			if time.Since(e.lastTmpl) > tmplInterval {
				e.sendTemplate()
			}
			if len(batch) > 0 {
				e.sendBatch(batch)
				batch = make([]*flow.Record, 0, 20)
			}
		}
	}
}

func (e *NetFlowV9Exporter) sendTemplate() {
	e.mu.Lock()
	defer e.mu.Unlock()

	// NetFlow v9 Template Fields:
	// 8:   IPV4_SRC_ADDR (4)
	// 12:  IPV4_DST_ADDR (4)
	// 56:  IN_SRC_MAC (6)
	// 80:  OUT_DST_MAC (6)
	// 58:  SRC_VLAN (2)
	// 7:   L4_SRC_PORT (2)
	// 11:  L4_DST_PORT (2)
	// 4:   PROTOCOL (1)
	// 6:   TCP_FLAGS (1)
	// 1:   IN_BYTES (4)
	// 2:   IN_PKTS (4)
	// 61:  DIRECTION (1)
	// 22:  FIRST_SWITCHED (4)
	// 21:  LAST_SWITCHED (4)
	// 95:  APPLICATION_ID (4)
	// 96:  APPLICATION_NAME (16)
	// 87:  HTTP_HOST (32)
	// 301: IS_OPEN_PORT (1)
	// 302: TCP_RTT_MS (4)
	// 305: SENSOR_NAME (16)
	// 306: TAG_NAME (16)
	// 307: TAG2_NAME (16)
	// 308: JA4_FINGERPRINT (36)
	// 309: OS_NAME (16)
	// Total record length = 4+4+6+6+2+2+2+1+1+4+4+1+4+4+4+16+32+1+4+16+16+16+36+16 = 200 bytes
	fields := []NetFlowV9Field{
		{8, 4},   // Src IP
		{12, 4},  // Dst IP
		{56, 6},  // Src MAC
		{80, 6},  // Dst MAC
		{58, 2},  // VLAN
		{7, 2},   // Src Port
		{11, 2},  // Dst Port
		{4, 1},   // Protocol
		{6, 1},   // TCP Flags
		{1, 4},   // Octets
		{2, 4},   // Packets
		{61, 1},  // Direction (0=downstream/ingress, 1=upstream/egress)
		{22, 4},  // Start
		{21, 4},  // End
		{95, 4},  // Cisco NBAR Application ID (4-byte uint32)
		{96, 16}, // Application protocol name (16-byte string)
		{87, 32}, // Website / URL / SNI
		{301, 1}, // Is Open Port
		{302, 4}, // TCP RTT Latency (ms)
		{305, 16},// Sensor Name
		{306, 16},// Tag Name
		{307, 16},// Tag2 Name
		{308, 36},// JA4 TLS Client Fingerprint
		{309, 16},// Inferred Client OS
	}

	buf := new(bytes.Buffer)
	uptime := uint32(time.Since(e.bootTime).Milliseconds())

	hdr := NetFlowV9Header{
		Version:      9,
		Count:        1,
		SysUptime:    uptime,
		UnixSecs:     uint32(time.Now().Unix()),
		FlowSequence: e.flowSeq,
		SourceID:     e.cfg.SourceID,
	}
	e.flowSeq++
	_ = binary.Write(buf, binary.BigEndian, hdr)

	flowSetLen := uint16(4 + 4 + (len(fields) * 4))
	_ = binary.Write(buf, binary.BigEndian, uint16(0))          // FlowSet ID (Template)
	_ = binary.Write(buf, binary.BigEndian, flowSetLen)          // FlowSet Length
	_ = binary.Write(buf, binary.BigEndian, uint16(257))        // Template ID
	_ = binary.Write(buf, binary.BigEndian, uint16(len(fields))) // Field Count

	for _, f := range fields {
		_ = binary.Write(buf, binary.BigEndian, f)
	}

	_, _ = e.conn.Write(buf.Bytes())
	e.lastTmpl = time.Now()
}

func (e *NetFlowV9Exporter) sendBatch(batch []*flow.Record) {
	if len(batch) == 0 || e.conn == nil {
		return
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	uptime := uint32(time.Since(e.bootTime).Milliseconds())
	recordSize := 200
	flowSetLen := uint16(4 + (len(batch) * recordSize))

	buf := new(bytes.Buffer)
	hdr := NetFlowV9Header{
		Version:      9,
		Count:        1,
		SysUptime:    uptime,
		UnixSecs:     uint32(time.Now().Unix()),
		FlowSequence: e.flowSeq,
		SourceID:     e.cfg.SourceID,
	}
	e.flowSeq += uint32(len(batch))
	_ = binary.Write(buf, binary.BigEndian, hdr)

	// FlowSet ID 257 = Data FlowSet
	_ = binary.Write(buf, binary.BigEndian, uint16(257))
	_ = binary.Write(buf, binary.BigEndian, flowSetLen)

	for _, r := range batch {
		src4 := r.SrcIP.To4()
		dst4 := r.DstIP.To4()
		if src4 == nil {
			src4 = net.IPv4zero.To4()
		}
		if dst4 == nil {
			dst4 = net.IPv4zero.To4()
		}

		srcMAC := make([]byte, 6)
		dstMAC := make([]byte, 6)
		copy(srcMAC, r.SrcMAC)
		copy(dstMAC, r.DstMAC)

		var dirByte uint8 = 1 // 1 = egress / upstream
		if r.Direction == "downstream" {
			dirByte = 0 // 0 = ingress / downstream
		}

		var openByte uint8
		if r.IsOpenPort {
			openByte = 1
		}

		var engineID uint32 = 13
		var appID uint32 = uint32(r.AppProtocolID)
		appName := r.AppProtocol

		if appID == 0 {
			engineID = 3 // IANA-L4
			if r.DstPort == 80 || r.SrcPort == 80 {
				appID = 80
				if appName == "" {
					appName = "http"
				}
			} else if r.DstPort == 443 || r.SrcPort == 443 {
				appID = 443
				if appName == "" {
					appName = "tls"
				}
			} else if r.DstPort == 53 || r.SrcPort == 53 {
				appID = 53
				if appName == "" {
					appName = "dns"
				}
			} else if r.DstPort == 22 || r.SrcPort == 22 {
				appID = 22
				if appName == "" {
					appName = "ssh"
				}
			} else if r.DstPort == 123 || r.SrcPort == 123 {
				appID = 123
				if appName == "" {
					appName = "ntp"
				}
			} else if r.DstPort == 67 || r.SrcPort == 67 || r.DstPort == 68 || r.SrcPort == 68 {
				appID = 67
				if appName == "" {
					appName = "dhcp"
				}
			} else if r.DstPort != 0 {
				appID = uint32(r.DstPort)
			} else {
				appID = uint32(r.SrcPort)
			}
		} else if r.EngineID != 0 {
			engineID = uint32(r.EngineID)
		}
		fullAppID := (engineID << 24) | (appID & 0x00FFFFFF)

		webBuf := make([]byte, 32)
		copy(webBuf, []byte(r.Website))

		appBuf := make([]byte, 16)
		copy(appBuf, []byte(appName))

		sensorBuf := make([]byte, 16)
		copy(sensorBuf, []byte(r.Sensor))

		tagBuf := make([]byte, 16)
		copy(tagBuf, []byte(r.Tag))

		tag2Buf := make([]byte, 16)
		copy(tag2Buf, []byte(r.Tag2))

		ja4Buf := make([]byte, 36)
		copy(ja4Buf, []byte(r.JA4))

		osBuf := make([]byte, 16)
		copy(osBuf, []byte(r.OS))

		firstMs := uint32(r.StartTime.Sub(e.bootTime).Milliseconds())
		lastMs := uint32(r.LastSeen.Sub(e.bootTime).Milliseconds())

		_ = binary.Write(buf, binary.BigEndian, src4)
		_ = binary.Write(buf, binary.BigEndian, dst4)
		_ = binary.Write(buf, binary.BigEndian, srcMAC)
		_ = binary.Write(buf, binary.BigEndian, dstMAC)
		_ = binary.Write(buf, binary.BigEndian, r.VLANID)
		_ = binary.Write(buf, binary.BigEndian, r.SrcPort)
		_ = binary.Write(buf, binary.BigEndian, r.DstPort)
		_ = binary.Write(buf, binary.BigEndian, r.IPProto)
		_ = binary.Write(buf, binary.BigEndian, r.TCPFlags)
		_ = binary.Write(buf, binary.BigEndian, uint32(r.TotalBytes))
		_ = binary.Write(buf, binary.BigEndian, uint32(r.TotalPackets))
		_ = binary.Write(buf, binary.BigEndian, dirByte)
		_ = binary.Write(buf, binary.BigEndian, firstMs)
		_ = binary.Write(buf, binary.BigEndian, lastMs)
		_ = binary.Write(buf, binary.BigEndian, fullAppID)
		_ = binary.Write(buf, binary.BigEndian, appBuf)
		_ = binary.Write(buf, binary.BigEndian, webBuf)
		_ = binary.Write(buf, binary.BigEndian, openByte)
		_ = binary.Write(buf, binary.BigEndian, uint32(r.TCPRTTMs))
		_ = binary.Write(buf, binary.BigEndian, sensorBuf)
		_ = binary.Write(buf, binary.BigEndian, tagBuf)
		_ = binary.Write(buf, binary.BigEndian, tag2Buf)
		_ = binary.Write(buf, binary.BigEndian, ja4Buf)
		_ = binary.Write(buf, binary.BigEndian, osBuf)
	}

	for buf.Len()%4 != 0 {
		buf.WriteByte(0)
	}

	_, _ = e.conn.Write(buf.Bytes())
}

func (e *NetFlowV9Exporter) Close() error {
	if e.conn != nil {
		return e.conn.Close()
	}
	return nil
}
