package flow

import (
	"net"
	"time"

	"github.com/redborder/redborder-flow-agent/internal/inspector"
)

// Record holds all aggregated L2-L7 state for a single flow session.
type Record struct {
	FlowKey         string
	ConversationKey string // Canonical bidirectional conversation identifier
	Direction       string // "upstream" (client->server) or "downstream" (server->client)
	Sensor          string // Assigned sensor name
	SensorName      string // Canonical sensor name alias
	SensorIP        string // Sensor host/probe IP
	Tag             string // Primary classification/location tag
	Tag2            string // Secondary classification tag
	ExtraEnrichments map[string]string // Key-value enrichments

	// Layer 2
	SrcMAC net.HardwareAddr
	DstMAC net.HardwareAddr
	VLANID uint16 // Legacy single VLAN tag
	LanVLAN uint16 // LAN endpoint VLAN
	WanVLAN uint16 // WAN / Remote endpoint VLAN (if routed between VLANs)

	// Layer 3
	SrcIP     net.IP
	DstIP     net.IP
	IPProto   uint8
	TOS       uint8
	SrcTTL    uint8
	DstTTL    uint8
	Interface string
	IfIndex   uint32

	// Layer 4
	SrcPort  uint16
	DstPort  uint16
	TCPFlags uint8

	// Volume & Timing
	StartTime    time.Time
	LastSeen     time.Time
	ClosedTime   time.Time
	TotalPackets uint64
	TotalBytes   uint64

	// Directional breakdown
	ForwardPackets uint64
	ForwardBytes   uint64
	ReversePackets uint64
	ReverseBytes   uint64

	// TCP Telemetry & Quality Metrics
	TCPRTTMs           int64 // SYN to SYN-ACK handshake latency in milliseconds
	TCPRetransmissions uint32
	TCPWindowSize      uint16
	TCPSYNTime         time.Time
	TCPSYNACKTime      time.Time

	// L7 & State Enrichment
	PortState      inspector.PortState
	IsOpenPort     bool
	FlowState      string // "ESTABLISHED", "CLOSED_RST", "CLOSED_FIN", "SYN_SENT", "UDP_ACTIVE"
	Website        string // TLS SNI or HTTP Host or DNS Domain
	TLSVersion     string // "TLS 1.3", "TLS 1.2"
	JA4            string // JA4 TLS Client Fingerprint (e.g. "t13d1516h2_8daaf6152771_e562703ab85f")
	JA4_r          string // Raw JA4 signature
	ClientType     string // "browser", "bot", "scanner", "malware", "os_service"
	ClientApp      string // e.g. "Chrome", "Firefox", "curl", "python-requests", "CobaltStrike"
	IsBot          bool   // True if automated tool, bot, crawler, scanner, or malware
	IsThreat       bool   // True if confirmed malicious / C2 fingerprint
	OS             string // Inferred Client OS (e.g. "Linux", "Windows", "macOS/iOS")
	OSFingerprint  string // TCP SYN OS signature (e.g. "ttl64:win64240:mss,sack,ts,nop,ws")
	HTTPMethod     string // "GET", "POST", etc.
	HTTPURI        string
	HTTPStatusCode int    // 200, 404, etc.
	HTTPUserAgent  string
	AppProtocol    string // "HTTP", "TLS", "DNS", or nDPI protocol name
	AppProtocolID  uint16 // Numeric protocol ID (e.g. nDPI 453, 91, 7, 5)
	EngineID       uint16 // Inspection engine ID (default: 13 for nDPI / NBAR)
	NDPIFlow       inspector.NDPIFlow `json:"-"`
}

// Clone returns a shallow-safe copy for export dispatch.
func (r *Record) Clone() *Record {
	cp := *r
	cp.NDPIFlow = nil

	if len(r.SrcMAC) > 0 {
		cp.SrcMAC = make(net.HardwareAddr, len(r.SrcMAC))
		copy(cp.SrcMAC, r.SrcMAC)
	}
	if len(r.DstMAC) > 0 {
		cp.DstMAC = make(net.HardwareAddr, len(r.DstMAC))
		copy(cp.DstMAC, r.DstMAC)
	}
	if len(r.SrcIP) > 0 {
		cp.SrcIP = make(net.IP, len(r.SrcIP))
		copy(cp.SrcIP, r.SrcIP)
	}
	if len(r.DstIP) > 0 {
		cp.DstIP = make(net.IP, len(r.DstIP))
		copy(cp.DstIP, r.DstIP)
	}
	return &cp
}
