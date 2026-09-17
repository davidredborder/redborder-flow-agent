package flow

import (
	"context"
	"fmt"
	"hash/fnv"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/redborder/redborder-flow-agent/internal/capture"
	"github.com/redborder/redborder-flow-agent/internal/config"
	"github.com/redborder/redborder-flow-agent/internal/inspector"
	"github.com/redborder/redborder-flow-agent/internal/stats"
)

// ShardedFlowTable partitions active flows across shards to maximize concurrent throughput.
type ShardedFlowTable struct {
	cfg           *config.FlowConfig
	analysis      *config.AnalysisConfig
	sensorMatcher *SensorMatcher
	numShards     int
	shards        []*flowShard
	dnsCache      *inspector.DNSCache
	ndpi          inspector.NDPIClassifier
	ja4Classifier *inspector.JA4Classifier
	exportChan    chan *Record
	logger        *slog.Logger
}

type flowShard struct {
	flows map[string]*Record
	mu    sync.RWMutex
}

// NewShardedFlowTable creates an optimized sharded flow tracking engine.
func NewShardedFlowTable(cfg *config.FlowConfig, analysis *config.AnalysisConfig, sensorMatcher *SensorMatcher, dnsCache *inspector.DNSCache, ndpi inspector.NDPIClassifier, ja4Classifier *inspector.JA4Classifier, bufSize int, logger *slog.Logger) *ShardedFlowTable {
	if logger == nil {
		logger = slog.Default()
	}
	numShards := cfg.Shards
	if numShards <= 0 {
		numShards = 64
	}

	shards := make([]*flowShard, numShards)
	for i := 0; i < numShards; i++ {
		shards[i] = &flowShard{
			flows: make(map[string]*Record, cfg.MaxActiveFlows/numShards),
		}
	}

	return &ShardedFlowTable{
		cfg:           cfg,
		analysis:      analysis,
		sensorMatcher: sensorMatcher,
		numShards:     numShards,
		shards:        shards,
		dnsCache:      dnsCache,
		ndpi:          ndpi,
		ja4Classifier: ja4Classifier,
		exportChan:    make(chan *Record, bufSize),
		logger:        logger,
	}
}

// ExportChan returns the channel where expired/completed flow records are emitted.
func (t *ShardedFlowTable) ExportChan() <-chan *Record {
	return t.exportChan
}

func (t *ShardedFlowTable) getShard(key string) *flowShard {
	h := fnv.New32a()
	h.Write([]byte(key))
	idx := h.Sum32() % uint32(t.numShards)
	return t.shards[idx]
}

// IngestPacket processes a decoded packet into the flow table and performs L7 inspections.
func (t *ShardedFlowTable) IngestPacket(p *capture.ParsedPacket) {
	if p == nil || p.SrcIP == nil || p.DstIP == nil {
		return
	}

	key := p.FlowKey()
	if key == "" {
		return
	}

	now := p.Timestamp
	if now.IsZero() {
		now = time.Now()
	}

	wireLen := p.WireLen
	if wireLen == 0 {
		wireLen = p.CaptureLen
	}

	shard := t.getShard(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	rec, exists := shard.flows[key]
	if !exists {
		if len(shard.flows) >= (t.cfg.MaxActiveFlows / t.numShards) {
			stats.GlobalCollector.IncFlowsDroppedTableFull()
			return // Shard flow capacity reached
		}

		shouldSwap := false
		if t.sensorMatcher != nil {
			shouldSwap = t.sensorMatcher.ShouldSwapClientServer(p.SrcIP, p.DstIP, p.SrcPort, p.DstPort, p.TCPFlags)
		}

		clientIP := p.SrcIP
		serverIP := p.DstIP
		clientPort := p.SrcPort
		serverPort := p.DstPort
		clientMAC := p.SrcMAC
		serverMAC := p.DstMAC
		clientTTL := p.TTL
		serverTTL := uint8(0)

		if shouldSwap {
			clientIP = p.DstIP
			serverIP = p.SrcIP
			clientPort = p.DstPort
			serverPort = p.SrcPort
			clientMAC = p.DstMAC
			serverMAC = p.SrcMAC
			clientTTL = 0
			serverTTL = p.TTL
		}

		var assign SensorAssignment
		if t.sensorMatcher != nil {
			assign = t.sensorMatcher.Match(clientIP, serverIP)
		} else {
			assign.SensorName = "default_sensor"
		}

		var lanVlan, wanVlan uint16
		clientIsLocal := false
		serverIsLocal := false
		if t.sensorMatcher != nil {
			clientIsLocal = t.sensorMatcher.IsLocalIP(clientIP)
			serverIsLocal = t.sensorMatcher.IsLocalIP(serverIP)
		}
		if p.VLANID > 0 {
			if clientIsLocal && serverIsLocal {
				if p.SrcIP.Equal(clientIP) {
					lanVlan = p.VLANID
				} else {
					wanVlan = p.VLANID
				}
			} else {
				lanVlan = p.VLANID
			}
		}

		rec = &Record{
			FlowKey:          key,
			ConversationKey:  key,
			Sensor:           assign.SensorName,
			SensorName:       assign.SensorName,
			SensorIP:         assign.SensorIP,
			Tag:              assign.Tag,
			Tag2:             assign.Tag2,
			ExtraEnrichments: assign.Enrichments,
			SrcMAC:           clientMAC,
			DstMAC:           serverMAC,
			VLANID:           p.VLANID,
			LanVLAN:          lanVlan,
			WanVLAN:          wanVlan,
			SrcIP:            clientIP,
			DstIP:            serverIP,
			IPProto:          p.IPProto,
			TOS:              p.TOS,
			SrcTTL:           clientTTL,
			DstTTL:           serverTTL,
			Interface:        p.Interface,
			IfIndex:          p.IfIndex,
			SrcPort:          clientPort,
			DstPort:          serverPort,
			StartTime:        now,
			LastSeen:         now,
		}

		if p.IPProto == capture.ProtoTCP {
			rec.TCPWindowSize = p.Window
			if p.TCPFlags&capture.FlagSYN != 0 && p.TCPFlags&capture.FlagACK == 0 {
				rec.TCPSYNTime = now
				rec.FlowState = "SYN_SENT"
			} else if p.TCPFlags&capture.FlagSYN != 0 && p.TCPFlags&capture.FlagACK != 0 {
				rec.TCPSYNACKTime = now
				rec.FlowState = "SYN_RECEIVED"
			}
		} else if p.IPProto == capture.ProtoUDP {
			rec.FlowState = "UDP"
		} else if p.IPProto == capture.ProtoICMP || p.IPProto == capture.ProtoICMPv6 {
			rec.FlowState = "ICMP"
		}

		// Initial DNS lookup for Destination (Server) IP
		if t.dnsCache != nil && t.analysis.ExtractDNSDomains {
			if domain := t.dnsCache.Lookup(serverIP); domain != "" {
				rec.Website = domain
				rec.AppProtocol = "DNS-Resolved"
			}
		}

		if t.ndpi != nil {
			rec.NDPIFlow = t.ndpi.AllocFlow()
		}

		shard.flows[key] = rec
	}

	// Determine direction: Forward is initial initiator (SrcIP matches rec.SrcIP)
	isForward := p.SrcIP.Equal(rec.SrcIP) && p.SrcPort == rec.SrcPort
	rec.LastSeen = now
	rec.TotalPackets++
	rec.TotalBytes += uint64(wireLen)
	rec.TCPFlags |= p.TCPFlags
	if p.VLANID > 0 && rec.VLANID == 0 {
		rec.VLANID = p.VLANID
	}


	if isForward {
		rec.ForwardPackets++
		rec.ForwardBytes += uint64(wireLen)
		rec.SrcTTL = p.TTL
	} else {
		rec.ReversePackets++
		rec.ReverseBytes += uint64(wireLen)
		rec.DstTTL = p.TTL
	}

	if p.VLANID > 0 {
		clientIsLocal := false
		serverIsLocal := false
		if t.sensorMatcher != nil {
			clientIsLocal = t.sensorMatcher.IsLocalIP(rec.SrcIP)
			serverIsLocal = t.sensorMatcher.IsLocalIP(rec.DstIP)
		}
		if clientIsLocal && serverIsLocal {
			if p.SrcIP.Equal(rec.SrcIP) {
				rec.LanVLAN = p.VLANID
			} else {
				rec.WanVLAN = p.VLANID
			}
		} else {
			rec.LanVLAN = p.VLANID
		}
	}

	// 1. TCP Port State Tracking, OS Detection & RTT Latency Calculation
	if p.IPProto == capture.ProtoTCP {
		// Passive OS Detection on initial TCP SYN from Client
		if p.TCPFlags&capture.FlagSYN != 0 && p.TCPFlags&capture.FlagACK == 0 && rec.OS == "" {
			osFp := inspector.DetectOSFromTCPSYN(p.TTL, p.Window, p.TCPOptions)
			rec.OS = osFp.OS
			rec.OSFingerprint = osFp.Fingerprint
		} else if isForward && rec.OS == "" && p.TTL > 0 {
			// Fallback OS detection from observed Client TTL
			rec.OS = inspector.DetectOSFromTTL(p.TTL)
		}

		if t.analysis.TrackTCPMetrics {
			// Handshake latency calculation: SYN -> SYN-ACK
			if p.TCPFlags&capture.FlagSYN != 0 && p.TCPFlags&capture.FlagACK == 0 {
				rec.TCPSYNTime = now
				rec.FlowState = "SYN_SENT"
			} else if p.TCPFlags&capture.FlagSYN != 0 && p.TCPFlags&capture.FlagACK != 0 {
				rec.TCPSYNACKTime = now
				if !rec.TCPSYNTime.IsZero() && rec.TCPRTTMs == 0 {
					rec.TCPRTTMs = now.Sub(rec.TCPSYNTime).Milliseconds()
					stats.GlobalCollector.IncTCPHandshakes()
				}
				rec.FlowState = "SYN_RECEIVED"
			}
			if p.Window > 0 {
				rec.TCPWindowSize = p.Window
			}
		}

		if t.analysis.TrackOpenPorts {
			state, isOpen := inspector.EvaluateTCPFlags(p.TCPFlags, isForward, rec.PortState)
			rec.PortState = state
			// If handshake was observed OR if active bidirectional communication occurs
			if isOpen || (rec.ForwardPackets > 0 && rec.ReversePackets > 0) {
				if !rec.IsOpenPort {
					stats.GlobalCollector.IncOpenPorts()
				}
				rec.IsOpenPort = true
				if rec.FlowState == "" || rec.FlowState == "SYN_SENT" || rec.FlowState == "SYN_RECEIVED" {
					rec.FlowState = "ESTABLISHED"
				}
			}
			if p.TCPFlags&capture.FlagRST != 0 {
				rec.FlowState = "CLOSED_RST"
				if rec.ClosedTime.IsZero() {
					rec.ClosedTime = now
				}
			} else if p.TCPFlags&capture.FlagFIN != 0 {
				rec.FlowState = "CLOSED_FIN"
				if rec.ClosedTime.IsZero() {
					rec.ClosedTime = now
				}
			}
		}
	} else if p.IPProto == capture.ProtoUDP {
		if rec.ForwardPackets > 0 && rec.ReversePackets > 0 {
			if !rec.IsOpenPort {
				stats.GlobalCollector.IncOpenPorts()
			}
			rec.IsOpenPort = true
			rec.FlowState = "UDP_ACTIVE"
		}
	}

	// 2. nDPI Deep Packet Inspection Classification
	if t.ndpi != nil && len(p.IPData) > 0 {
		protoName, protoID, _ := t.ndpi.ProcessFlowPacket(rec.NDPIFlow, p.IPData, now.UnixMilli())
		if protoName != "" {
			rec.AppProtocol = protoName
		}
		if protoID > 0 {
			rec.AppProtocolID = protoID
		}
	}

	// 3. L7 Website & Protocol Inspection
	if len(p.Payload) > 0 {
		// DNS Snooping (Port 53 or 853)
		if (p.SrcPort == 53 || p.DstPort == 53 || p.SrcPort == 853 || p.DstPort == 853) && t.analysis.ExtractDNSDomains {
			queryDomain, answers, err := inspector.ParseDNSPacket(p.Payload)
			if err == nil && queryDomain != "" {
				stats.GlobalCollector.IncDNSQueries()
				if rec.AppProtocol == "" || rec.AppProtocol == "DNS-Resolved" {
					rec.AppProtocol = "DNS"
				}
				if rec.Website == "" {
					rec.Website = queryDomain
				}
				if t.dnsCache != nil {
					for _, ansIP := range answers {
						t.dnsCache.Put(ansIP, queryDomain, 10*time.Minute)
					}
				}
			}
		}

		// TLS SNI, Version, and JA4 Client Fingerprinting (Port 443 / HTTPS / TLS)
		if p.IPProto == capture.ProtoTCP {
			if inspector.IsTLSHandshake(p.Payload) {
				stats.GlobalCollector.IncTLSClientHellos()
				if rec.JA4 == "" {
					if ja4Fp := inspector.ComputeJA4(p.Payload); ja4Fp != nil {
						rec.JA4 = ja4Fp.JA4
						rec.JA4_r = ja4Fp.JA4_r
						if t.ja4Classifier != nil {
							if match, ok := t.ja4Classifier.Lookup(rec.JA4); ok {
								rec.ClientType = match.ClientType
								rec.ClientApp = match.ClientApp
								rec.IsBot = match.IsBot
								rec.IsThreat = match.IsThreat
							}
						}
					}
				}
				if t.analysis.ExtractTLSSNI || t.analysis.ExtractTLSVersion {
					sni, tlsVer := inspector.ExtractTLSDetails(p.Payload)
					if t.analysis.ExtractTLSSNI && sni != "" && (rec.Website == "" || !strings.Contains(rec.Website, ".")) {
						rec.Website = sni
					}
					if t.analysis.ExtractTLSVersion && tlsVer != "" && rec.TLSVersion == "" {
						rec.TLSVersion = tlsVer
					}
					if rec.AppProtocol == "" || rec.AppProtocol == "DNS-Resolved" {
						rec.AppProtocol = "TLS"
					}
				}
			}

			// HTTP Host, Method, URI, User-Agent & Status Codes
			if t.analysis.ExtractHTTPHost || t.analysis.ExtractHTTPDetails {
				httpData := inspector.ExtractFullHTTP(p.Payload)
				if t.analysis.ExtractHTTPDetails {
					if httpData.Method != "" && rec.HTTPMethod == "" {
						rec.HTTPMethod = httpData.Method
					}
					if httpData.URI != "" && rec.HTTPURI == "" {
						rec.HTTPURI = httpData.URI
					}
					if httpData.UserAgent != "" && rec.HTTPUserAgent == "" {
						rec.HTTPUserAgent = httpData.UserAgent
					}
					if httpData.StatusCode != 0 && rec.HTTPStatusCode == 0 {
						rec.HTTPStatusCode = httpData.StatusCode
					}
				}

				if t.analysis.ExtractHTTPHost && httpData.Host != "" {
					if rec.HTTPURI != "" && rec.HTTPURI != "/" {
						rec.Website = fmt.Sprintf("%s%s", httpData.Host, rec.HTTPURI)
					} else {
						rec.Website = httpData.Host
					}
				}

				if (httpData.Host != "" || httpData.Method != "") && (rec.AppProtocol == "" || rec.AppProtocol == "DNS-Resolved") {
					rec.AppProtocol = "HTTP"
				}
			}
		}
	}
}

// emitRecord handles dispatching records according to flow mode (unidirectional Model A vs bidirectional).
func (t *ShardedFlowTable) emitRecord(rec *Record) {
	if t.cfg.Mode == "bidirectional" {
		// Single biflow record
		bf := rec.Clone()
		bf.Direction = "bidirectional"
		select {
		case t.exportChan <- bf:
		default:
		}
		return
	}

	// 1. Emit Upstream Flow (Traffic from Local -> Remote)
	if rec.ForwardPackets > 0 {
		fwd := rec.Clone()
		fwd.Direction = "upstream"
		fwd.TotalPackets = rec.ForwardPackets
		fwd.TotalBytes = rec.ForwardBytes
		select {
		case t.exportChan <- fwd:
			stats.GlobalCollector.IncExportedFlows(1)
		default:
		}
	}

	// 2. Emit Downstream Flow (Traffic from Remote -> Local)
	// In RedBorder standard: src_ip is ALWAYS the local home_net IP, and dst_ip is the remote IP.
	// The direction field ("downstream") defines that data flowed from remote to local.
	if rec.ReversePackets > 0 {
		rev := rec.Clone()
		rev.Direction = "downstream"
		// Retain local IP as SrcIP and remote IP as DstIP
		rev.TotalPackets = rec.ReversePackets
		rev.TotalBytes = rec.ReverseBytes
		select {
		case t.exportChan <- rev:
			stats.GlobalCollector.IncExportedFlows(1)
		default:
		}
	}
}

// StartCleaner runs a timer to evict active/inactive flows and send them to the exporter.
func (t *ShardedFlowTable) StartCleaner(ctx context.Context) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	activeTimeout := time.Duration(t.cfg.ActiveTimeoutSec) * time.Second
	inactiveTimeout := time.Duration(t.cfg.InactiveTimeoutSec) * time.Second

	for {
		select {
		case <-ctx.Done():
			t.flushAll()
			return
		case <-ticker.C:
			now := time.Now()
			for _, shard := range t.shards {
				shard.mu.Lock()
				for k, rec := range shard.flows {
					isInactiveExpired := now.Sub(rec.LastSeen) > inactiveTimeout
					isActiveExpired := now.Sub(rec.StartTime) > activeTimeout
					isClosedExpired := !rec.ClosedTime.IsZero() && now.Sub(rec.ClosedTime) >= 1*time.Second

					if isInactiveExpired || isActiveExpired || isClosedExpired {
						delete(shard.flows, k)
						if t.ndpi != nil && rec.NDPIFlow != nil {
							t.ndpi.FreeFlow(rec.NDPIFlow)
							rec.NDPIFlow = nil
						}
						t.emitRecord(rec)
					}
				}
				shard.mu.Unlock()
			}
		}
	}
}

func (t *ShardedFlowTable) flushAll() {
	for _, shard := range t.shards {
		shard.mu.Lock()
		for k, rec := range shard.flows {
			delete(shard.flows, k)
			if t.ndpi != nil && rec.NDPIFlow != nil {
				t.ndpi.FreeFlow(rec.NDPIFlow)
				rec.NDPIFlow = nil
			}
			t.emitRecord(rec)
		}
		shard.mu.Unlock()
	}
}

// FlushAndClose immediately exports all active flows and closes the export channel.
func (t *ShardedFlowTable) FlushAndClose() {
	t.flushAll()
	close(t.exportChan)
}

// ActiveFlowsCount returns total active flows across all shards.
func (t *ShardedFlowTable) ActiveFlowsCount() int {
	total := 0
	for _, s := range t.shards {
		s.mu.RLock()
		total += len(s.flows)
		s.mu.RUnlock()
	}
	return total
}
