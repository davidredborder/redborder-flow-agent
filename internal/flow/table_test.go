package flow

import (
	"net"
	"testing"
	"time"

	"github.com/redborder/redborder-flow-agent/internal/capture"
	"github.com/redborder/redborder-flow-agent/internal/config"
	"github.com/redborder/redborder-flow-agent/internal/inspector"
)

func TestFlowTableAggregation(t *testing.T) {
	cfg := &config.FlowConfig{
		Mode:               "bidirectional",
		ActiveTimeoutSec:   1,
		InactiveTimeoutSec: 1,
		MaxActiveFlows:     1000,
		Shards:             4,
	}
	analysis := &config.AnalysisConfig{
		TrackOpenPorts:     true,
		TrackTCPMetrics:    true,
		ExtractTLSSNI:      true,
		ExtractTLSVersion:  true,
		ExtractHTTPHost:    true,
		ExtractHTTPDetails: true,
		ExtractDNSDomains:  true,
		DNSCacheSize:       100,
	}

	dnsCache := inspector.NewDNSCache(100)
	ndpi, _ := inspector.NewNDPIClassifier()
	sensorMatcher := NewSensorMatcher(&config.Config{
		Sensor: "test_sensor",
		Tag:    "test_tag",
		Tag2:   "test_tag2",
	})
	ja4Classifier := inspector.NewJA4Classifier("", nil)
	table := NewShardedFlowTable(cfg, analysis, sensorMatcher, dnsCache, ndpi, ja4Classifier, 100, nil)

	p1 := &capture.ParsedPacket{
		Timestamp: time.Now(),
		SrcIP:     net.ParseIP("192.168.1.10"),
		DstIP:     net.ParseIP("1.1.1.1"),
		SrcPort:   54321,
		DstPort:   80,
		IPProto:   capture.ProtoTCP,
		TCPFlags:  capture.FlagSYN,
		WireLen:   64,
		SrcMAC:    net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:    net.HardwareAddr{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		Payload:   []byte("GET /index.html HTTP/1.1\r\nHost: example.org\r\nUser-Agent: curl/7.68.0\r\n\r\n"),
	}

	table.IngestPacket(p1)

	if count := table.ActiveFlowsCount(); count != 1 {
		t.Fatalf("expected 1 active flow, got %d", count)
	}

	shard := table.getShard(p1.FlowKey())
	shard.mu.RLock()
	rec := shard.flows[p1.FlowKey()]
	shard.mu.RUnlock()

	if rec == nil {
		t.Fatalf("flow record not found in shard")
	}

	// Website now contains the full URL if URI was present
	if rec.Website != "example.org/index.html" {
		t.Fatalf("expected Website example.org/index.html, got %s", rec.Website)
	}
	if rec.HTTPURI != "/index.html" {
		t.Fatalf("expected HTTPURI /index.html, got %s", rec.HTTPURI)
	}
	if rec.HTTPMethod != "GET" {
		t.Fatalf("expected HTTPMethod GET, got %s", rec.HTTPMethod)
	}
	if rec.HTTPUserAgent != "curl/7.68.0" {
		t.Fatalf("expected HTTPUserAgent curl/7.68.0, got %s", rec.HTTPUserAgent)
	}
	if rec.TotalBytes != 64 {
		t.Fatalf("expected TotalBytes 64, got %d", rec.TotalBytes)
	}
}

func TestFlowTableReverseProxyLocality(t *testing.T) {
	cfg := &config.FlowConfig{
		Mode:               "unidirectional",
		ActiveTimeoutSec:   1,
		InactiveTimeoutSec: 1,
		MaxActiveFlows:     1000,
		Shards:             4,
	}
	analysis := &config.AnalysisConfig{
		TrackOpenPorts:  true,
		TrackTCPMetrics: true,
	}

	sensorMatcher := NewSensorMatcher(&config.Config{
		Sensor: "test_sensor",
	})
	table := NewShardedFlowTable(cfg, analysis, sensorMatcher, nil, nil, nil, 100, nil)

	// External client 81.45.89.232:54321 connects to internal reverse proxy 10.1.150.2:443
	p := &capture.ParsedPacket{
		Timestamp: time.Now(),
		SrcIP:     net.ParseIP("81.45.89.232"),
		DstIP:     net.ParseIP("10.1.150.2"),
		SrcPort:   54321,
		DstPort:   443,
		IPProto:   capture.ProtoTCP,
		TCPFlags:  capture.FlagSYN,
		WireLen:   60,
		SrcMAC:    net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		DstMAC:    net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
	}

	table.IngestPacket(p)

	shard := table.getShard(p.FlowKey())
	shard.mu.RLock()
	rec := shard.flows[p.FlowKey()]
	shard.mu.RUnlock()

	if rec == nil {
		t.Fatalf("flow record not found in shard")
	}

	// In RedBorder, lan_ip MUST ALWAYS be the local IP (10.1.150.2)
	if rec.SrcIP.String() != "10.1.150.2" {
		t.Fatalf("expected lan_ip (rec.SrcIP) to be 10.1.150.2, got %s", rec.SrcIP.String())
	}
	if rec.DstIP.String() != "81.45.89.232" {
		t.Fatalf("expected wan_ip (rec.DstIP) to be 81.45.89.232, got %s", rec.DstIP.String())
	}
	if rec.SrcPort != 443 {
		t.Fatalf("expected lan_l4_port to be 443, got %d", rec.SrcPort)
	}
	if rec.DstPort != 54321 {
		t.Fatalf("expected wan_l4_port to be 54321, got %d", rec.DstPort)
	}
	if rec.SrcMAC.String() != "00:11:22:33:44:55" {
		t.Fatalf("expected lan MAC to be 00:11:22:33:44:55, got %s", rec.SrcMAC.String())
	}
	if rec.DstMAC.String() != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("expected wan MAC to be aa:bb:cc:dd:ee:ff, got %s", rec.DstMAC.String())
	}
}

func TestEmitRecordDirectionalFlows(t *testing.T) {
	cfg := &config.FlowConfig{
		Mode:               "unidirectional",
		ActiveTimeoutSec:   1,
		InactiveTimeoutSec: 1,
		MaxActiveFlows:     1000,
		Shards:             4,
	}
	analysis := &config.AnalysisConfig{}
	table := NewShardedFlowTable(cfg, analysis, nil, nil, nil, nil, 100, nil)
	exportChan := table.ExportChan()

	rec := &Record{
		FlowKey:         "10.1.150.2:443-81.45.89.232:54321-6",
		ConversationKey: "10.1.150.2:443-81.45.89.232:54321-6",
		SrcIP:           net.ParseIP("10.1.150.2"),
		DstIP:           net.ParseIP("81.45.89.232"),
		SrcPort:         443,
		DstPort:         54321,
		SrcMAC:          net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:          net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		ForwardPackets:  5,
		ForwardBytes:    500,
		ReversePackets:  10,
		ReverseBytes:    1200,
	}

	table.emitRecord(rec)

	var emitted []*Record
	for len(exportChan) > 0 {
		emitted = append(emitted, <-exportChan)
	}

	if len(emitted) != 2 {
		t.Fatalf("expected 2 emitted records (upstream and downstream), got %d", len(emitted))
	}

	// 1. Upstream record (Local -> Remote)
	up := emitted[0]
	if up.Direction != "upstream" {
		t.Fatalf("expected direction 'upstream', got %s", up.Direction)
	}
	if up.SrcIP.String() != "10.1.150.2" || up.DstIP.String() != "81.45.89.232" {
		t.Fatalf("upstream IPs mismatch: %s -> %s", up.SrcIP, up.DstIP)
	}
	if up.SrcPort != 443 || up.DstPort != 54321 {
		t.Fatalf("upstream ports mismatch: %d -> %d", up.SrcPort, up.DstPort)
	}

	// 2. Downstream record (Remote -> Local, src_ip remains fixed as Local IP)
	down := emitted[1]
	if down.Direction != "downstream" {
		t.Fatalf("expected direction 'downstream', got %s", down.Direction)
	}
	if down.SrcIP.String() != "10.1.150.2" || down.DstIP.String() != "81.45.89.232" {
		t.Fatalf("downstream IPs mismatch: %s -> %s (expected local src_ip -> remote dst_ip)", down.SrcIP, down.DstIP)
	}
	if down.SrcPort != 443 || down.DstPort != 54321 {
		t.Fatalf("downstream ports mismatch: %d -> %d", down.SrcPort, down.DstPort)
	}
	if down.SrcMAC.String() != "00:11:22:33:44:55" || down.DstMAC.String() != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("downstream MACs mismatch: %s -> %s", down.SrcMAC, down.DstMAC)
	}
	if down.ConversationKey != "10.1.150.2:443-81.45.89.232:54321-6" {
		t.Fatalf("conversation key must be preserved across directions")
	}
}

