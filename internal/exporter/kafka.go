package exporter

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/redborder/redborder-flow-agent/internal/config"
	"github.com/redborder/redborder-flow-agent/internal/flow"
	"github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/compress"
)

// JSONFlowRecord defines the structured JSON format streamed to Kafka and stdout.
type JSONFlowRecord struct {
	Type                     string            `json:"type,omitempty"`                       // e.g. "netflowv10" / "flow"
	FlowSequence             string            `json:"flow_sequence,omitempty"`              // Flow sequence identifier
	IPProtocolVersion        uint8             `json:"ip_protocol_version"`                 // 4 or 6
	L4Proto                  uint8             `json:"l4_proto"`                            // Layer 4 protocol number (6 = TCP, 17 = UDP)
	Bytes                    uint64            `json:"bytes"`                               // Byte volume (pmacct / redBorder format)
	Pkts                     uint64            `json:"pkts"`                                // Packet count (pmacct / redBorder format)
	InputVRF                 uint32            `json:"input_vrf"`                           // Input VRF ID
	OutputVRF                uint32            `json:"output_vrf"`                          // Output VRF ID
	FlowEndReason            string            `json:"flow_end_reason,omitempty"`           // "idle timeout", "active timeout", "rst", "fin"
	BiflowDirection          string            `json:"biflow_direction,omitempty"`          // "initiator" or "reverse initiator"
	ApplicationIDName        string            `json:"application_id_name,omitempty"`       // e.g. "13:453", "13:91", "13:7"
	EngineIDName             string            `json:"engine_id_name,omitempty"`            // e.g. "13"
	Host                     string            `json:"host,omitempty"`                      // TLS SNI, HTTP Host, or DNS domain
	LanIP                    string            `json:"lan_ip"`                              // Local / Home Network IP
	WanIP                    string            `json:"wan_ip"`                              // Remote / External Network IP
	LanL4Port                uint16            `json:"lan_l4_port"`                         // Local / LAN port
	WanL4Port                uint16            `json:"wan_l4_port"`                         // Remote / WAN port
	ClientMAC                string            `json:"client_mac,omitempty"`                // Client MAC address
	LanVLAN                  string            `json:"lan_vlan,omitempty"`                  // LAN VLAN ID
	WanVLAN                  string            `json:"wan_vlan,omitempty"`                  // WAN VLAN ID (omitted for non-internal traffic)
	LanInterface             uint32            `json:"lan_interface,omitempty"`             // LAN interface index
	WanInterface             uint32            `json:"wan_interface,omitempty"`             // WAN interface index
	LanInterfaceName         string            `json:"lan_interface_name,omitempty"`        // LAN interface name
	WanInterfaceName         string            `json:"wan_interface_name,omitempty"`        // WAN interface name
	LanInterfaceDescription  string            `json:"lan_interface_description,omitempty"` // LAN interface description
	WanInterfaceDescription  string            `json:"wan_interface_description,omitempty"` // WAN interface description
	Timestamp                int64             `json:"timestamp"`                           // Current unix epoch timestamp (seconds)
	StartTime                int64             `json:"start_time"`                          // Flow start unix epoch timestamp (seconds)
	EndTime                  int64             `json:"end_time"`                            // Flow last seen unix epoch timestamp (seconds)
	Duration                 int64             `json:"duration"`                            // Flow duration in milliseconds
	Interface                string            `json:"interface"`
	IfIndex                  uint32            `json:"ifindex"`
	Sensor                   string            `json:"sensor,omitempty"`
	SensorName               string            `json:"sensor_name,omitempty"`
	SensorIP                 string            `json:"sensor_ip,omitempty"`
	Tag                      string            `json:"tag,omitempty"`
	Tag2                     string            `json:"tag2,omitempty"`
	Enrichments              map[string]string `json:"-"`                                   // Flattened into top-level JSON output
	Direction                string            `json:"direction"`                           // "upstream" or "downstream"
	Conversation             string            `json:"conversation"`                        // Canonical bidirectional conversation key
	SrcMAC                   string            `json:"src_mac"`
	DstMAC                   string            `json:"dst_mac"`
	Protocol                 uint8             `json:"protocol"`
	ProtoName         string            `json:"proto_name"`
	TCPFlags          string            `json:"tcp_flags,omitempty"`
	TOS               uint8             `json:"tos"`
	SrcTTL            uint8             `json:"src_ttl,omitempty"`
	DstTTL            uint8             `json:"dst_ttl,omitempty"`
	TotalPackets      uint64            `json:"total_packets"`
	TotalBytes        uint64            `json:"total_bytes"`
	IsOpenPort        bool              `json:"is_open_port"`
	FlowState         string            `json:"flow_state,omitempty"`
	TCPRTT            int64             `json:"tcp_rtt,omitempty"` // Handshake latency (ms)
	TCPWindow         uint16            `json:"tcp_window,omitempty"`
	Website           string            `json:"website,omitempty"`
	TLSVersion        string            `json:"tls_version,omitempty"`
	JA4               string            `json:"ja4,omitempty"`
	JA4_r             string            `json:"ja4_r,omitempty"`
	ClientType        string            `json:"client_type,omitempty"`
	ClientApp         string            `json:"client_app,omitempty"`
	IsBot             *bool             `json:"is_bot,omitempty"`
	IsThreat          *bool             `json:"is_threat,omitempty"`
	OS                string            `json:"os,omitempty"`
	OSFingerprint     string            `json:"os_fingerprint,omitempty"`
	HTTPMethod        string            `json:"http_method,omitempty"`
	HTTPURI           string            `json:"http_uri,omitempty"`
	HTTPStatusCode    int               `json:"http_status_code,omitempty"`
	HTTPUserAgent     string            `json:"http_user_agent,omitempty"`
	AppProtocol       string            `json:"app_protocol,omitempty"`
}

// MarshalJSON flattens enrichments into the top-level JSON object.
func (r JSONFlowRecord) MarshalJSON() ([]byte, error) {
	type Alias JSONFlowRecord
	data, err := json.Marshal(Alias(r))
	if err != nil {
		return nil, err
	}
	if len(r.Enrichments) == 0 {
		return data, nil
	}

	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	for k, v := range r.Enrichments {
		m[k] = v
	}
	return json.Marshal(m)
}

// KafkaExporter streams enriched JSON flow records to Kafka topics.
type KafkaExporter struct {
	cfg    *config.KafkaConfig
	writer *kafka.Writer
	logger *slog.Logger
}

func NewKafkaExporter(cfg *config.KafkaConfig) (*KafkaExporter, error) {
	var compressionCodec kafka.Compression
	switch strings.ToLower(cfg.Compression) {
	case "snappy":
		compressionCodec = compress.Snappy
	case "gzip":
		compressionCodec = compress.Gzip
	case "lz4":
		compressionCodec = compress.Lz4
	case "zstd":
		compressionCodec = compress.Zstd
	default:
		compressionCodec = 0
	}

	batchSize := cfg.BatchSize
	if batchSize <= 0 {
		batchSize = 100
	}

	writer := &kafka.Writer{
		Addr:         kafka.TCP(cfg.Brokers...),
		Topic:        cfg.Topic,
		Balancer:     &kafka.LeastBytes{},
		BatchSize:    batchSize,
		BatchTimeout: 100 * time.Millisecond,
		Compression:  compressionCodec,
		Async:        true,
	}

	return &KafkaExporter{
		cfg:    cfg,
		writer: writer,
		logger: slog.Default(),
	}, nil
}

func (e *KafkaExporter) Start(ctx context.Context, inChan <-chan *flow.Record) error {
	e.logger.Info("Kafka flow exporter running", "brokers", e.cfg.Brokers, "topic", e.cfg.Topic)

	msgs := make([]kafka.Message, 0, e.cfg.BatchSize)
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			if len(msgs) > 0 {
				_ = e.writer.WriteMessages(context.Background(), msgs...)
			}
			return nil
		case rec, ok := <-inChan:
			if !ok {
				if len(msgs) > 0 {
					_ = e.writer.WriteMessages(context.Background(), msgs...)
				}
				return nil
			}

			jsonRec := formatJSONRecord(rec)
			data, err := json.Marshal(jsonRec)
			if err != nil {
				continue
			}

			msgs = append(msgs, kafka.Message{
				Key:   []byte(rec.FlowKey),
				Value: data,
			})

			if len(msgs) >= e.cfg.BatchSize {
				if err := e.writer.WriteMessages(ctx, msgs...); err != nil {
					e.logger.Error("Failed to publish flows to Kafka", "err", err)
				}
				msgs = make([]kafka.Message, 0, e.cfg.BatchSize)
			}

		case <-ticker.C:
			if len(msgs) > 0 {
				if err := e.writer.WriteMessages(ctx, msgs...); err != nil {
					e.logger.Error("Failed to publish flows to Kafka", "err", err)
				}
				msgs = make([]kafka.Message, 0, e.cfg.BatchSize)
			}
		}
	}
}

func formatJSONRecord(r *flow.Record) JSONFlowRecord {
	protoName := fmt.Sprintf("%d", r.IPProto)
	switch r.IPProto {
	case 6:
		protoName = "TCP"
	case 17:
		protoName = "UDP"
	case 1:
		protoName = "ICMP"
	case 58:
		protoName = "ICMPv6"
	}

	var flagsStr string
	if r.IPProto == 6 {
		var flags []string
		if r.TCPFlags&0x02 != 0 {
			flags = append(flags, "SYN")
		}
		if r.TCPFlags&0x10 != 0 {
			flags = append(flags, "ACK")
		}
		if r.TCPFlags&0x01 != 0 {
			flags = append(flags, "FIN")
		}
		if r.TCPFlags&0x04 != 0 {
			flags = append(flags, "RST")
		}
		if r.TCPFlags&0x08 != 0 {
			flags = append(flags, "PSH")
		}
		if r.TCPFlags&0x20 != 0 {
			flags = append(flags, "URG")
		}
		flagsStr = strings.Join(flags, "|")
	}

	now := time.Now()

	direction := r.Direction
	if direction == "" {
		direction = "upstream"
	}

	conversation := r.ConversationKey
	if conversation == "" {
		conversation = r.FlowKey
	}

	ipProtoVer := uint8(4)
	if r.SrcIP != nil && r.SrcIP.To4() == nil && len(r.SrcIP) == net.IPv6len {
		ipProtoVer = 6
	}

	flowEndReason := "idle timeout"
	switch r.FlowState {
	case "CLOSED_RST":
		flowEndReason = "rst"
	case "CLOSED_FIN":
		flowEndReason = "fin"
	}

	var srcIPStr, dstIPStr string
	if r.SrcIP != nil {
		srcIPStr = r.SrcIP.String()
	}
	var srcMACStr, dstMACStr string
	if len(r.SrcMAC) > 0 {
		srcMACStr = r.SrcMAC.String()
	}
	if len(r.DstMAC) > 0 {
		dstMACStr = r.DstMAC.String()
	}
	if r.DstIP != nil {
		dstIPStr = r.DstIP.String()
	}

	engineID := uint16(13)
	if r.EngineID != 0 {
		engineID = r.EngineID
	}
	engineIDName := fmt.Sprintf("%d", engineID)

	var appIDName string
	if r.AppProtocol != "" {
		appIDName = strings.ToLower(r.AppProtocol)
	} else if r.AppProtocolID > 0 {
		appIDName = fmt.Sprintf("%d:%d", engineID, r.AppProtocolID)
	} else if r.DstPort == 80 || r.SrcPort == 80 {
		appIDName = "http"
	} else if r.DstPort == 443 || r.SrcPort == 443 {
		appIDName = "tls"
	} else if r.DstPort == 53 || r.SrcPort == 53 {
		appIDName = "dns"
	} else if r.DstPort == 22 || r.SrcPort == 22 {
		appIDName = "ssh"
	} else if r.DstPort == 123 || r.SrcPort == 123 {
		appIDName = "ntp"
	} else if r.DstPort == 67 || r.SrcPort == 67 || r.DstPort == 68 || r.SrcPort == 68 {
		appIDName = "dhcp"
	}

	biflowDir := "initiator"
	if direction == "downstream" {
		biflowDir = "reverse initiator"
	}

	lanIfName := r.Interface
	if lanIfName == "" {
		lanIfName = fmt.Sprintf("%d", r.IfIndex)
	}

	clientMAC := srcMACStr
	if clientMAC == "" {
		clientMAC = dstMACStr
	}

	var lanVLANStr, wanVLANStr string
	if r.LanVLAN > 0 {
		lanVLANStr = fmt.Sprintf("%d", r.LanVLAN)
	} else if r.VLANID > 0 {
		lanVLANStr = fmt.Sprintf("%d", r.VLANID)
	}
	if r.WanVLAN > 0 {
		wanVLANStr = fmt.Sprintf("%d", r.WanVLAN)
	}

	return JSONFlowRecord{
		Type:                     "netflowv10",
		IPProtocolVersion:        ipProtoVer,
		L4Proto:                  r.IPProto,
		Bytes:                    r.TotalBytes,
		Pkts:                     r.TotalPackets,
		InputVRF:                 0,
		OutputVRF:                0,
		FlowEndReason:            flowEndReason,
		BiflowDirection:          biflowDir,
		ApplicationIDName:        appIDName,
		EngineIDName:             engineIDName,
		Host:                     r.Website,
		LanIP:                    srcIPStr,
		WanIP:                    dstIPStr,
		LanL4Port:                r.SrcPort,
		WanL4Port:                r.DstPort,
		ClientMAC:                clientMAC,
		LanVLAN:                  lanVLANStr,
		WanVLAN:                  wanVLANStr,
		LanInterface:             r.IfIndex,
		WanInterface:             r.IfIndex,
		LanInterfaceName:         lanIfName,
		WanInterfaceName:         lanIfName,
		LanInterfaceDescription:  lanIfName,
		WanInterfaceDescription:  lanIfName,
		Timestamp:                now.Unix(),
		StartTime:                r.StartTime.Unix(),
		EndTime:                  r.LastSeen.Unix(),
		Duration:                 r.LastSeen.Sub(r.StartTime).Milliseconds(),
		Interface:                r.Interface,
		IfIndex:                  r.IfIndex,
		Sensor:                   r.Sensor,
		SensorName:               r.SensorName,
		SensorIP:                 r.SensorIP,
		Tag:                      r.Tag,
		Tag2:                     r.Tag2,
		Enrichments:              r.ExtraEnrichments,
		Direction:                direction,
		Conversation:             conversation,
		SrcMAC:                   srcMACStr,
		DstMAC:                   dstMACStr,
		Protocol:                 r.IPProto,
		ProtoName:                protoName,
		TCPFlags:                 flagsStr,
		TOS:                      r.TOS,
		SrcTTL:                   r.SrcTTL,
		DstTTL:                   r.DstTTL,
		TotalPackets:             r.TotalPackets,
		TotalBytes:               r.TotalBytes,
		IsOpenPort:               r.IsOpenPort,
		FlowState:                r.FlowState,
		TCPRTT:                   r.TCPRTTMs,
		TCPWindow:                r.TCPWindowSize,
		Website:                  r.Website,
		TLSVersion:               r.TLSVersion,
		JA4:                      r.JA4,
		JA4_r:                    r.JA4_r,
		ClientType:               r.ClientType,
		ClientApp:                r.ClientApp,
		IsBot:                    func() *bool { if r.JA4 != "" { b := r.IsBot; return &b }; return nil }(),
		IsThreat:                 func() *bool { if r.JA4 != "" { t := r.IsThreat; return &t }; return nil }(),
		OS:                       r.OS,
		OSFingerprint:            r.OSFingerprint,
		HTTPMethod:               r.HTTPMethod,
		HTTPURI:                  r.HTTPURI,
		HTTPStatusCode:           r.HTTPStatusCode,
		HTTPUserAgent:            r.HTTPUserAgent,
		AppProtocol:              r.AppProtocol,
	}
}

func (e *KafkaExporter) Close() error {
	if e.writer != nil {
		return e.writer.Close()
	}
	return nil
}
