package flow

import (
	"net"
	"testing"

	"github.com/redborder/redborder-flow-agent/internal/config"
)

func TestSensorMatcher(t *testing.T) {
	cfg := &config.Config{
		Sensor:     "default_sensor",
		SensorName: "default_sensor",
		SensorIP:   "10.0.0.1",
		Tag:        "global_prod",
		Tag2:       "global_zone",
		ExtraEnrichments: map[string]string{
			"environment": "production",
			"cluster":     "main",
		},
		Sensors: []config.SensorMapping{
			{
				Name:       "dmz_sensor",
				SensorName: "dmz_sensor",
				SensorIP:   "192.168.10.1",
				Subnets:    []string{"192.168.10.0/24", "192.168.20.0/24"},
				Tag:        "dmz",
				Tag2:       "internal",
				ExtraEnrichments: map[string]string{
					"zone": "dmz_secure",
				},
			},
			{
				Name:     "cloud_sensor",
				SensorIP: "10.100.0.1",
				Subnets:  []string{"10.100.0.0/16"},
				Tag:      "aws_eu_west",
			},
		},
	}

	matcher := NewSensorMatcher(cfg)

	// Case 1: Match on SrcIP
	assign := matcher.Match(net.ParseIP("192.168.10.50"), net.ParseIP("8.8.8.8"))
	if assign.SensorName != "dmz_sensor" || assign.SensorIP != "192.168.10.1" || assign.Tag != "dmz" || assign.Tag2 != "internal" {
		t.Fatalf("expected dmz_sensor on src match, got %+v", assign)
	}
	if assign.Enrichments["zone"] != "dmz_secure" || assign.Enrichments["environment"] != "production" {
		t.Fatalf("expected merged enrichments, got %+v", assign.Enrichments)
	}

	// Case 2: SrcIP does not match, but DstIP matches
	assign = matcher.Match(net.ParseIP("8.8.8.8"), net.ParseIP("10.100.5.2"))
	if assign.SensorName != "cloud_sensor" || assign.SensorIP != "10.100.0.1" || assign.Tag != "aws_eu_west" || assign.Tag2 != "global_zone" {
		t.Fatalf("expected cloud_sensor on dst match fallback, got %+v", assign)
	}

	// Case 3: Neither matches -> fallback to default global sensor, IP, and tags
	assign = matcher.Match(net.ParseIP("8.8.8.8"), net.ParseIP("1.1.1.1"))
	if assign.SensorName != "default_sensor" || assign.SensorIP != "10.0.0.1" || assign.Tag != "global_prod" || assign.Tag2 != "global_zone" {
		t.Fatalf("expected default_sensor on fallback, got %+v", assign)
	}
	if assign.Enrichments["environment"] != "production" {
		t.Fatalf("expected global environment enrichment, got %+v", assign.Enrichments)
	}
}

func TestShouldSwapClientServer(t *testing.T) {
	cfg := &config.Config{
		Sensor: "default_sensor",
		Sensors: []config.SensorMapping{
			{
				Name:    "dmz",
				Subnets: []string{"192.168.10.0/24"},
			},
		},
	}
	matcher := NewSensorMatcher(cfg)

	// Case 1: First packet is from Public Server (8.8.8.8:443) -> Local Client (192.168.1.50:54321)
	// Must swap so 192.168.1.50 is Client (SrcIP)
	swap := matcher.ShouldSwapClientServer(net.ParseIP("8.8.8.8"), net.ParseIP("192.168.1.50"), 443, 54321, 0x10) // ACK
	if !swap {
		t.Fatalf("expected swap when first packet is from public server to private client")
	}

	// Case 2: First packet is from Local Client (192.168.1.50:54321) -> Public Server (8.8.8.8:443)
	// Must NOT swap
	swap = matcher.ShouldSwapClientServer(net.ParseIP("192.168.1.50"), net.ParseIP("8.8.8.8"), 54321, 443, 0x02) // SYN
	if swap {
		t.Fatalf("expected no swap when packet is from private client to public server")
	}

	// Case 3: SYN-ACK received from Server (8.8.8.8:443) -> Client (10.0.0.5:12345)
	swap = matcher.ShouldSwapClientServer(net.ParseIP("8.8.8.8"), net.ParseIP("10.0.0.5"), 443, 12345, 0x12) // SYN+ACK
	if !swap {
		t.Fatalf("expected swap on SYN-ACK")
	}

	// Case 4: Reverse Proxy Inbound - External Client (81.45.89.232:54321) sends TCP SYN to Internal Reverse Proxy (10.1.150.2:443)
	// Must swap so local proxy 10.1.150.2 is LAN (rec.SrcIP) and 81.45.89.232 is WAN (rec.DstIP)
	swap = matcher.ShouldSwapClientServer(net.ParseIP("81.45.89.232"), net.ParseIP("10.1.150.2"), 54321, 443, 0x02) // SYN
	if !swap {
		t.Fatalf("expected swap when external client sends SYN to internal reverse proxy")
	}

	// Case 5: Custom home_nets configuration
	cfgLocal := &config.Config{
		Sensor: "test_sensor",
		HomeNets: []string{
			"200.1.0.0/16",
		},
	}
	matcherLocal := NewSensorMatcher(cfgLocal)
	// 200.1.5.10 (custom home net) connects to 8.8.8.8 (public)
	swap = matcherLocal.ShouldSwapClientServer(net.ParseIP("200.1.5.10"), net.ParseIP("8.8.8.8"), 12345, 53, 0x00)
	if swap {
		t.Fatalf("expected no swap for custom local IP on src")
	}
	// 8.8.8.8 connects to 200.1.5.10 (custom home net)
	swap = matcherLocal.ShouldSwapClientServer(net.ParseIP("8.8.8.8"), net.ParseIP("200.1.5.10"), 53, 12345, 0x00)
	if !swap {
		t.Fatalf("expected swap for custom local IP on dst")
	}
}
