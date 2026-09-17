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

type IPFIXHeader struct {
	Version        uint16
	Length         uint16
	ExportTime     uint32
	SequenceNumber uint32
	DomainID       uint32
}

type IPFIXField struct {
	Type   uint16
	Length uint16
}

type IPFIXExporter struct {
	cfg       *config.ExporterConfig
	conn      net.Conn
	seq       uint32
	lastTmpl  time.Time
	mu        sync.Mutex
}

func NewIPFIXExporter(cfg *config.ExporterConfig) (*IPFIXExporter, error) {
	return &IPFIXExporter{
		cfg:      cfg,
		lastTmpl: time.Now().Add(-1 * time.Hour),
	}, nil
}

func (e *IPFIXExporter) Start(ctx context.Context, inChan <-chan *flow.Record) error {
	addr := net.JoinHostPort(e.cfg.Target, fmt.Sprintf("%d", e.cfg.Port))
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to dial IPFIX exporter %s: %w", addr, err)
	}
	e.conn = conn

	tmplInterval := time.Duration(e.cfg.TemplateIntervalSec) * time.Second
	if tmplInterval <= 0 {
		tmplInterval = 30 * time.Second
	}

	batch := make([]*flow.Record, 0, 5)
	ticker := time.NewTicker(200 * time.Millisecond)
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
			if len(batch) >= 5 {
				e.sendBatch(batch)
				batch = make([]*flow.Record, 0, 5)
			}
		case <-ticker.C:
			if time.Since(e.lastTmpl) > tmplInterval {
				e.sendTemplate()
			}
			if len(batch) > 0 {
				e.sendBatch(batch)
				batch = make([]*flow.Record, 0, 5)
			}
		}
	}
}

func (e *IPFIXExporter) sendTemplate() {
	e.mu.Lock()
	defer e.mu.Unlock()

	// IPFIX Information Elements (IANA RFC 7011 / RFC 6759 / Cisco NBAR):
	// 8:   sourceIPv4Address (4)
	// 12:  destinationIPv4Address (4)
	// 56:  sourceMacAddress (6)
	// 80:  destinationMacAddress (6)
	// 58:  vlanId (2)
	// 7:   sourceTransportPort (2)
	// 11:  destinationTransportPort (2)
	// 4:   protocolIdentifier (1)
	// 6:   tcpControlBits (1)
	// 1:   octetDeltaCount (8)
	// 2:   packetDeltaCount (8)
	// 61:  flowDirection (1: 0=ingress/downstream, 1=egress/upstream)
	// 150: flowStartSeconds (4)
	// 151: flowEndSeconds (4)
	// 95:  applicationId (4 bytes: (engineID<<24)|appID)
	// 96:  applicationName (16 bytes string)
	// 87:  httpHostName / website URL / SNI (32 bytes)
	// 301: isOpenPort (1 byte)
	// 302: tcpRoundTripTime (4 bytes: latency in ms)
	// 305: sensorName (16 bytes)
	// 306: tagName (16 bytes)
	// 307: tag2Name (16 bytes)
	// 308: ja4Fingerprint (36 bytes)
	// 309: osName (16 bytes)
	fields := []IPFIXField{
		{8, 4},   // Src IP
		{12, 4},  // Dst IP
		{56, 6},  // Src MAC
		{80, 6},  // Dst MAC
		{58, 2},  // VLAN
		{7, 2},   // Src Port
		{11, 2},  // Dst Port
		{4, 1},   // Protocol
		{6, 1},   // TCP Flags
		{1, 8},   // Bytes (64-bit)
		{2, 8},   // Packets (64-bit)
		{61, 1},  // Direction (0=downstream/ingress, 1=upstream/egress)
		{150, 4}, // Start time
		{151, 4}, // End time
		{95, 4},  // Cisco NBAR Application ID (4-byte uint32)
		{96, 16}, // Application protocol name (16-byte string)
		{87, 32}, // Website Domain / Host / SNI / URL
		{301, 1}, // Is Open Port (1 = open, 0 = closed)
		{302, 4}, // TCP RTT latency in ms
		{305, 16},// Sensor Name
		{306, 16},// Tag Name
		{307, 16},// Tag2 Name
		{308, 36},// JA4 TLS Client Fingerprint
		{309, 16},// Inferred Client OS
	}

	buf := new(bytes.Buffer)
	buf.Write(make([]byte, 16)) // Placeholder for 16-byte IPFIX Header

	// Set ID 2 = Template Set
	setLen := uint16(4 + 4 + (len(fields) * 4))
	_ = binary.Write(buf, binary.BigEndian, uint16(2))          // Template Set ID
	_ = binary.Write(buf, binary.BigEndian, setLen)             // Set Length
	_ = binary.Write(buf, binary.BigEndian, uint16(260))        // Template ID 260
	_ = binary.Write(buf, binary.BigEndian, uint16(len(fields)))// Field Count

	for _, f := range fields {
		_ = binary.Write(buf, binary.BigEndian, f)
	}

	data := buf.Bytes()
	binary.BigEndian.PutUint16(data[0:2], 10)                        // IPFIX Version 10
	binary.BigEndian.PutUint16(data[2:4], uint16(len(data)))         // Total Length
	binary.BigEndian.PutUint32(data[4:8], uint32(time.Now().Unix())) // Export Time
	binary.BigEndian.PutUint32(data[8:12], e.seq)                    // Sequence Number
	binary.BigEndian.PutUint32(data[12:16], e.cfg.SourceID)          // Observation Domain ID

	e.seq++
	_, _ = e.conn.Write(data)
	e.lastTmpl = time.Now()
}

func (e *IPFIXExporter) sendBatch(batch []*flow.Record) {
	if len(batch) == 0 || e.conn == nil {
		return
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// Record size: 4+4+6+6+2+2+2+1+1+8+8+1+4+4+4+16+32+1+4+16+16+16+36+16 = 210 bytes
	recordSize := 210
	setLen := uint16(4 + (len(batch) * recordSize))

	buf := new(bytes.Buffer)
	buf.Write(make([]byte, 16)) // Placeholder for IPFIX Header

	// Set ID 260 = Data Set for Template 260
	_ = binary.Write(buf, binary.BigEndian, uint16(260))
	_ = binary.Write(buf, binary.BigEndian, setLen)

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

		_ = binary.Write(buf, binary.BigEndian, src4)
		_ = binary.Write(buf, binary.BigEndian, dst4)
		_ = binary.Write(buf, binary.BigEndian, srcMAC)
		_ = binary.Write(buf, binary.BigEndian, dstMAC)
		_ = binary.Write(buf, binary.BigEndian, r.VLANID)
		_ = binary.Write(buf, binary.BigEndian, r.SrcPort)
		_ = binary.Write(buf, binary.BigEndian, r.DstPort)
		_ = binary.Write(buf, binary.BigEndian, r.IPProto)
		_ = binary.Write(buf, binary.BigEndian, r.TCPFlags)
		_ = binary.Write(buf, binary.BigEndian, r.TotalBytes)
		_ = binary.Write(buf, binary.BigEndian, r.TotalPackets)
		_ = binary.Write(buf, binary.BigEndian, dirByte)
		_ = binary.Write(buf, binary.BigEndian, uint32(r.StartTime.Unix()))
		_ = binary.Write(buf, binary.BigEndian, uint32(r.LastSeen.Unix()))
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

	data := buf.Bytes()
	binary.BigEndian.PutUint16(data[0:2], 10)
	binary.BigEndian.PutUint16(data[2:4], uint16(len(data)))
	binary.BigEndian.PutUint32(data[4:8], uint32(time.Now().Unix()))
	binary.BigEndian.PutUint32(data[8:12], e.seq)
	binary.BigEndian.PutUint32(data[12:16], e.cfg.SourceID)

	e.seq += uint32(len(batch))
	_, _ = e.conn.Write(data)
}

func (e *IPFIXExporter) Close() error {
	if e.conn != nil {
		return e.conn.Close()
	}
	return nil
}
