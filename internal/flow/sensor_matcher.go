package flow

import (
	"net"

	"github.com/redborder/redborder-flow-agent/internal/config"
)

type parsedSensorRule struct {
	name        string
	sensorIP    string
	subnets     []*net.IPNet
	tag         string
	tag2        string
	enrichments map[string]string
}

// SensorAssignment represents the matched sensor identity, IP, and metadata enrichments.
type SensorAssignment struct {
	SensorName  string            `json:"sensor_name"`
	SensorIP    string            `json:"sensor_ip,omitempty"`
	Tag         string            `json:"tag,omitempty"`
	Tag2        string            `json:"tag2,omitempty"`
	Enrichments map[string]string `json:"enrichments,omitempty"`
}

// SensorMatcher resolves sensor name, IP, tags, and enrichments for flows based on IP matching rules.
type SensorMatcher struct {
	defaultAssignment SensorAssignment
	rules             []parsedSensorRule
	homeNets          []*net.IPNet
}

// NewSensorMatcher parses config and builds CIDR lookup structures.
func NewSensorMatcher(cfg *config.Config) *SensorMatcher {
	sName := cfg.SensorName
	if sName == "" {
		sName = cfg.Sensor
	}
	if sName == "" {
		sName = "default_sensor"
	}

	defaultEnrichments := make(map[string]string, len(cfg.ExtraEnrichments))
	for k, v := range cfg.ExtraEnrichments {
		defaultEnrichments[k] = v
	}

	sm := &SensorMatcher{
		defaultAssignment: SensorAssignment{
			SensorName:  sName,
			SensorIP:    cfg.SensorIP,
			Tag:         cfg.Tag,
			Tag2:        cfg.Tag2,
			Enrichments: defaultEnrichments,
		},
	}

	homeNetsList := cfg.HomeNets
	if len(homeNetsList) == 0 && len(cfg.LocalNetworks) > 0 {
		homeNetsList = cfg.LocalNetworks
	}

	for _, subnetStr := range homeNetsList {
		_, ipNet, err := net.ParseCIDR(subnetStr)
		if err == nil {
			sm.homeNets = append(sm.homeNets, ipNet)
		} else {
			ip := net.ParseIP(subnetStr)
			if ip != nil {
				var mask net.IPMask
				if ip.To4() != nil {
					mask = net.CIDRMask(32, 32)
				} else {
					mask = net.CIDRMask(128, 128)
				}
				sm.homeNets = append(sm.homeNets, &net.IPNet{IP: ip, Mask: mask})
			}
		}
	}

	for _, s := range cfg.Sensors {
		ruleName := s.Name
		if ruleName == "" {
			ruleName = s.SensorName
		}
		ruleEnrichments := make(map[string]string, len(s.ExtraEnrichments))
		for k, v := range s.ExtraEnrichments {
			ruleEnrichments[k] = v
		}

		rule := parsedSensorRule{
			name:        ruleName,
			sensorIP:    s.SensorIP,
			tag:         s.Tag,
			tag2:        s.Tag2,
			enrichments: ruleEnrichments,
		}
		for _, subnetStr := range s.Subnets {
			_, ipNet, err := net.ParseCIDR(subnetStr)
			if err == nil {
				rule.subnets = append(rule.subnets, ipNet)
			} else {
				ip := net.ParseIP(subnetStr)
				if ip != nil {
					var mask net.IPMask
					if ip.To4() != nil {
						mask = net.CIDRMask(32, 32)
					} else {
						mask = net.CIDRMask(128, 128)
					}
					rule.subnets = append(rule.subnets, &net.IPNet{IP: ip, Mask: mask})
				}
			}
		}
		sm.rules = append(sm.rules, rule)
	}

	return sm
}

// Match resolves the sensor assignment for given source and destination IPs.
// Rule:
// 1. If srcIP matches a sensor's subnet -> assign that sensor.
// 2. Else if dstIP matches a sensor's subnet -> assign that sensor.
// 3. Else fallback to default global sensor.
// Inherits global tags/enrichments if not specifically overridden on the matched sensor.
func (m *SensorMatcher) Match(srcIP, dstIP net.IP) SensorAssignment {
	assign := SensorAssignment{
		SensorName:  m.defaultAssignment.SensorName,
		SensorIP:    m.defaultAssignment.SensorIP,
		Tag:         m.defaultAssignment.Tag,
		Tag2:        m.defaultAssignment.Tag2,
		Enrichments: make(map[string]string),
	}
	for k, v := range m.defaultAssignment.Enrichments {
		assign.Enrichments[k] = v
	}

	applyRule := func(rule *parsedSensorRule) {
		assign.SensorName = rule.name
		if rule.sensorIP != "" {
			assign.SensorIP = rule.sensorIP
		}
		if rule.tag != "" {
			assign.Tag = rule.tag
		}
		if rule.tag2 != "" {
			assign.Tag2 = rule.tag2
		}
		for k, v := range rule.enrichments {
			assign.Enrichments[k] = v
		}
	}

	// 1. Check srcIP
	if srcIP != nil {
		for i := range m.rules {
			for _, subnet := range m.rules[i].subnets {
				if subnet.Contains(srcIP) {
					applyRule(&m.rules[i])
					return assign
				}
			}
		}
	}

	// 2. Check dstIP (fallback if srcIP didn't match)
	if dstIP != nil {
		for i := range m.rules {
			for _, subnet := range m.rules[i].subnets {
				if subnet.Contains(dstIP) {
					applyRule(&m.rules[i])
					return assign
				}
			}
		}
	}

	// 3. Fallback to default
	return assign
}

// MatchesConfiguredSubnet checks if the given IP belongs to any configured sensor subnet or home network.
func (m *SensorMatcher) MatchesConfiguredSubnet(ip net.IP) bool {
	if m == nil || ip == nil {
		return false
	}
	for _, subnet := range m.homeNets {
		if subnet.Contains(ip) {
			return true
		}
	}
	for i := range m.rules {
		for _, subnet := range m.rules[i].subnets {
			if subnet.Contains(ip) {
				return true
			}
		}
	}
	return false
}

// IsLocalIP returns true if the IP is in configured sensor subnets, configured local networks, or RFC 1918 / RFC 6598 / RFC 4193 private space.
func (m *SensorMatcher) IsLocalIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if m != nil && m.MatchesConfiguredSubnet(ip) {
		return true
	}
	return IsPrivateIP(ip)
}

// IsPrivateIP checks if an IP is in RFC 1918, CGNAT (RFC 6598), loopback, link-local, or IPv6 ULA/link-local.
func IsPrivateIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsPrivate() {
		return true
	}

	ip4 := ip.To4()
	if ip4 != nil {
		// RFC 1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
		if ip4[0] == 10 {
			return true
		}
		if ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31 {
			return true
		}
		if ip4[0] == 192 && ip4[1] == 168 {
			return true
		}
		// CGNAT: 100.64.0.0/10 (100.64.0.0 - 100.127.255.255)
		if ip4[0] == 100 && (ip4[1]&0xc0) == 64 {
			return true
		}
		// Carrier/Special: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
		if ip4[0] == 192 && ip4[1] == 0 && ip4[2] == 2 {
			return true
		}
	} else if len(ip) == net.IPv6len {
		// IPv6 Unique Local (fc00::/7) or Link-Local (fe80::/10)
		if (ip[0] & 0xfe) == 0xfc || (ip[0] == 0xfe && (ip[1]&0xc0) == 0x80) {
			return true
		}
	}

	return false
}

// ShouldSwapClientServer evaluates whether packet endpoints should be swapped when initializing a flow.
// RedBorder Standard:
// - lan_ip MUST ALWAYS represent the Local / Internal network (e.g. private IP or configured subnets).
// - wan_ip MUST ALWAYS represent the Remote / External network (e.g. public IP or foreign subnets).
// Returns true if dstIP/dstPort should be the LAN endpoint (rec.SrcIP) and srcIP/srcPort the WAN endpoint (rec.DstIP).
func (m *SensorMatcher) ShouldSwapClientServer(srcIP, dstIP net.IP, srcPort, dstPort uint16, tcpFlags uint8) bool {
	if srcIP == nil || dstIP == nil {
		return false
	}

	// 1. Locality Standard: One endpoint is Local and the other is External
	// In RedBorder, lan_ip MUST ALWAYS be the local network and wan_ip the remote network.
	// Even for inbound connections (e.g. external client -> internal reverse proxy),
	// the internal server is mapped to lan_ip (rec.SrcIP) and the external client to wan_ip (rec.DstIP).
	srcIsLocal := m.IsLocalIP(srcIP)
	dstIsLocal := m.IsLocalIP(dstIP)

	if !srcIsLocal && dstIsLocal {
		// srcIP is External and dstIP is Local -> Swap so dstIP (Local) becomes LAN (rec.SrcIP)!
		return true
	}
	if srcIsLocal && !dstIsLocal {
		// srcIP is Local and dstIP is External -> srcIP (Local) is already LAN (rec.SrcIP) -> Keep!
		return false
	}

	// 2. Both endpoints have the SAME locality (both are Local, or both are External):
	// Check TCP Handshake flags:
	if tcpFlags&0x02 != 0 { // SYN is set
		if tcpFlags&0x10 == 0 { // SYN without ACK: True Client -> Server initiator
			return false
		}
		// SYN-ACK: This packet is from the Server responding to Client -> Swap!
		return true
	}

	// 3. Well-Known Server Port vs Ephemeral Client Port Heuristics
	// Used when BOTH endpoints are local private or BOTH are public:
	srcIsServerPort := isStandardServerPort(srcPort)
	dstIsServerPort := isStandardServerPort(dstPort)

	if srcIsServerPort && !dstIsServerPort {
		// src has server port (e.g. 443) -> src is Server -> Swap so dst is Client!
		return true
	}
	if !srcIsServerPort && dstIsServerPort {
		// dst has server port (e.g. 443) -> dst is Server, src is Client -> Keep!
		return false
	}

	return false
}

func isStandardServerPort(port uint16) bool {
	switch port {
	case 20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 123, 143, 161, 389, 443, 465, 587, 636, 853, 993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 6343, 6379, 8080, 8443, 9092:
		return true
	default:
		return port < 1024
	}
}
