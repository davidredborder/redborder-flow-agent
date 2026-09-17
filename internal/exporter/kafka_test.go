package exporter

import (
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/redborder/redborder-flow-agent/internal/flow"
)

func TestFormatJSONRecord(t *testing.T) {
	now := time.Now()
	rec := &flow.Record{
		FlowKey:         "10.0.0.1:51234->192.168.1.50:443-6",
		ConversationKey: "10.0.0.1:51234-192.168.1.50:443-6",
		Direction:       "upstream",
		SrcMAC:          net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:          net.HardwareAddr{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		VLANID:          100,
		SrcIP:           net.ParseIP("10.0.0.1"),
		DstIP:           net.ParseIP("192.168.1.50"),
		SrcPort:         51234,
		DstPort:         443,
		IPProto:         6,
		TCPFlags:        0x12, // SYN + ACK
		SrcTTL:          64,
		DstTTL:          56,
		StartTime:       now.Add(-5 * time.Second),
		LastSeen:        now,
		TotalPackets:    14,
		TotalBytes:      12200,
		IsOpenPort:      true,
		FlowState:       "ESTABLISHED",
		TCPRTTMs:        18,
		TCPWindowSize:   64240,
		Website:         "app.redborder.com/login",
		TLSVersion:      "TLS 1.3",
		JA4:             "t13d1516h2_8daaf6152771_e562703ab85f",
		JA4_r:           "t13d1516h2_raw",
		ClientType:      "browser",
		ClientApp:       "Chrome / Chromium",
		IsBot:           false,
		IsThreat:        false,
		OS:              "Linux",
		OSFingerprint:   "ttl64:win29200:mss,sack,ts,nop,ws",
		HTTPMethod:      "GET",
		HTTPURI:         "/login",
		HTTPStatusCode:  200,
		HTTPUserAgent:   "Mozilla/5.0",
		AppProtocol:     "TLS",
		Interface:       "eth0",
		IfIndex:         2,
		Sensor:          "sensor_edge",
		SensorName:      "sensor_edge",
		SensorIP:        "192.168.1.10",
		Tag:             "production",
		Tag2:            "dc_north",
		ExtraEnrichments: map[string]string{
			"site": "datacenter_1",
		},
	}

	jsonRec := formatJSONRecord(rec)

	if jsonRec.LanIP != "10.0.0.1" || jsonRec.WanIP != "192.168.1.50" {
		t.Fatalf("unexpected IP values: %s -> %s", jsonRec.LanIP, jsonRec.WanIP)
	}
	if jsonRec.OS != "Linux" || jsonRec.JA4 != "t13d1516h2_8daaf6152771_e562703ab85f" {
		t.Fatalf("unexpected OS/JA4 values: %s / %s", jsonRec.OS, jsonRec.JA4)
	}
	if jsonRec.Sensor != "sensor_edge" || jsonRec.SensorName != "sensor_edge" || jsonRec.SensorIP != "192.168.1.10" {
		t.Fatalf("unexpected sensor values: %s/%s/%s", jsonRec.Sensor, jsonRec.SensorName, jsonRec.SensorIP)
	}
	if jsonRec.Tag != "production" || jsonRec.Tag2 != "dc_north" {
		t.Fatalf("unexpected tags: %s/%s", jsonRec.Tag, jsonRec.Tag2)
	}
	if jsonRec.Enrichments["site"] != "datacenter_1" {
		t.Fatalf("unexpected enrichments: %+v", jsonRec.Enrichments)
	}
	if jsonRec.Direction != "upstream" {
		t.Fatalf("expected Direction upstream, got %s", jsonRec.Direction)
	}
	if jsonRec.Conversation != "10.0.0.1:51234-192.168.1.50:443-6" {
		t.Fatalf("expected Conversation key, got %s", jsonRec.Conversation)
	}
	if !jsonRec.IsOpenPort {
		t.Fatalf("expected IsOpenPort true")
	}
	if jsonRec.Website != "app.redborder.com/login" {
		t.Fatalf("expected Website app.redborder.com/login, got %s", jsonRec.Website)
	}
	if jsonRec.TotalBytes != 12200 {
		t.Fatalf("expected TotalBytes 12200, got %d", jsonRec.TotalBytes)
	}

	if jsonRec.Bytes != 12200 || jsonRec.Pkts != 14 {
		t.Fatalf("expected Bytes 12200 and Pkts 14, got %d and %d", jsonRec.Bytes, jsonRec.Pkts)
	}
	if jsonRec.L4Proto != 6 || jsonRec.IPProtocolVersion != 4 {
		t.Fatalf("expected L4Proto 6 and IPProtocolVersion 4, got %d and %d", jsonRec.L4Proto, jsonRec.IPProtocolVersion)
	}
	if jsonRec.ClientMAC != "00:11:22:33:44:55" {
		t.Fatalf("expected ClientMAC 00:11:22:33:44:55, got %s", jsonRec.ClientMAC)
	}
	if jsonRec.LanL4Port != 51234 || jsonRec.WanL4Port != 443 {
		t.Fatalf("expected LanL4Port 51234 and WanL4Port 443, got %d and %d", jsonRec.LanL4Port, jsonRec.WanL4Port)
	}
	if jsonRec.LanVLAN != "100" {
		t.Fatalf("expected LanVLAN '100', got %s", jsonRec.LanVLAN)
	}
	if jsonRec.LanInterfaceName != "eth0" || jsonRec.WanInterfaceName != "eth0" {
		t.Fatalf("expected interface names 'eth0', got %s and %s", jsonRec.LanInterfaceName, jsonRec.WanInterfaceName)
	}
	if jsonRec.Type != "netflowv10" {
		t.Fatalf("expected Type netflowv10, got %s", jsonRec.Type)
	}

	if jsonRec.ApplicationIDName != "tls" || jsonRec.EngineIDName != "13" {
		t.Fatalf("expected ApplicationIDName 'tls' and EngineIDName 13, got %s and %s", jsonRec.ApplicationIDName, jsonRec.EngineIDName)
	}
	if jsonRec.Host != "app.redborder.com/login" {
		t.Fatalf("expected Host app.redborder.com/login, got %s", jsonRec.Host)
	}
	if jsonRec.BiflowDirection != "initiator" {
		t.Fatalf("expected BiflowDirection initiator, got %s", jsonRec.BiflowDirection)
	}

	// Test flattened JSON output
	data, err := json.Marshal(jsonRec)
	if err != nil {
		t.Fatalf("failed to marshal JSON: %v", err)
	}
	var rawMap map[string]interface{}
	if err := json.Unmarshal(data, &rawMap); err != nil {
		t.Fatalf("failed to unmarshal JSON map: %v", err)
	}
	if rawMap["bytes"] != float64(12200) || rawMap["pkts"] != float64(14) {
		t.Fatalf("expected bytes=12200 and pkts=14 in rawMap, got %v and %v", rawMap["bytes"], rawMap["pkts"])
	}
	if rawMap["lan_ip"] != "10.0.0.1" || rawMap["wan_ip"] != "192.168.1.50" {
		t.Fatalf("expected lan_ip and wan_ip in rawMap, got %v and %v", rawMap["lan_ip"], rawMap["wan_ip"])
	}
	if rawMap["client_mac"] != "00:11:22:33:44:55" {
		t.Fatalf("expected client_mac in rawMap, got %v", rawMap["client_mac"])
	}
	if rawMap["lan_vlan"] != "100" {
		t.Fatalf("expected lan_vlan in rawMap, got %v", rawMap["lan_vlan"])
	}
	if rawMap["application_id_name"] != "tls" || rawMap["engine_id_name"] != "13" {
		t.Fatalf("expected application_id_name 'tls' and engine_id_name '13' in rawMap, got %v and %v", rawMap["application_id_name"], rawMap["engine_id_name"])
	}
	if rawMap["host"] != "app.redborder.com/login" {
		t.Fatalf("expected host in rawMap, got %v", rawMap["host"])
	}
	if rawMap["biflow_direction"] != "initiator" {
		t.Fatalf("expected biflow_direction in rawMap, got %v", rawMap["biflow_direction"])
	}
	if rawMap["type"] != "netflowv10" {
		t.Fatalf("expected type 'netflowv10' in rawMap, got %v", rawMap["type"])
	}
	if rawMap["site"] != "datacenter_1" {
		t.Fatalf("expected top-level flattened enrichment field 'site'='datacenter_1', got %v", rawMap["site"])
	}
	if rawMap["client_type"] != "browser" || rawMap["client_app"] != "Chrome / Chromium" {
		t.Fatalf("expected client_type 'browser' and client_app 'Chrome / Chromium', got %v / %v", rawMap["client_type"], rawMap["client_app"])
	}
	if rawMap["is_bot"] != false || rawMap["is_threat"] != false {
		t.Fatalf("expected is_bot=false and is_threat=false, got %v / %v", rawMap["is_bot"], rawMap["is_threat"])
	}
	if _, exists := rawMap["enrichments"]; exists {
		t.Fatalf("did not expect nested 'enrichments' key in output: %s", string(data))
	}
}
