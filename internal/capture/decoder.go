package capture

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// Standard protocol constants
const (
	ProtoICMP   = 1
	ProtoTCP    = 6
	ProtoUDP    = 17
	ProtoIPv6   = 41
	ProtoICMPv6 = 58
)

// TCP Flag bitmasks
const (
	FlagFIN uint8 = 1 << 0
	FlagSYN uint8 = 1 << 1
	FlagRST uint8 = 1 << 2
	FlagPSH uint8 = 1 << 3
	FlagACK uint8 = 1 << 4
	FlagURG uint8 = 1 << 5
	FlagECE uint8 = 1 << 6
	FlagCWR uint8 = 1 << 7
)

// ParsedPacket represents a parsed packet with Layer 2, Layer 3, Layer 4 and L7 payload pointers.
type ParsedPacket struct {
	Timestamp   time.Time
	CaptureLen  int
	WireLen     int
	Interface   string
	IfIndex     uint32

	// Layer 2
	SrcMAC net.HardwareAddr
	DstMAC net.HardwareAddr
	VLANID uint16

	// Layer 3
	SrcIP    net.IP
	DstIP    net.IP
	IPProto  uint8
	IPLength uint16
	TTL      uint8
	TOS      uint8

	// Layer 4
	SrcPort   uint16
	DstPort   uint16
	TCPFlags  uint8
	SeqNumber uint32
	AckNumber uint32
	Window     uint16
	TCPOptions []byte
	ICMPType   uint8
	ICMPCode   uint8

	// Layer 7
	Payload []byte

	// Layer 3 Raw IP Packet (passed to nDPI)
	IPData []byte

	// Raw underlying frame
	RawData []byte
}

// FlowKey generates a canonical bidirectional 5-tuple key.
func (p *ParsedPacket) FlowKey() string {
	if p.SrcIP == nil || p.DstIP == nil {
		return ""
	}
	src := p.SrcIP.String()
	dst := p.DstIP.String()
	if src < dst || (src == dst && p.SrcPort < p.DstPort) {
		return fmt.Sprintf("%s:%d-%s:%d-%d", src, p.SrcPort, dst, p.DstPort, p.IPProto)
	}
	return fmt.Sprintf("%s:%d-%s:%d-%d", dst, p.DstPort, src, p.SrcPort, p.IPProto)
}

// DirectionalKey returns a unidirectional key (Src -> Dst).
func (p *ParsedPacket) DirectionalKey() string {
	if p.SrcIP == nil || p.DstIP == nil {
		return ""
	}
	return fmt.Sprintf("%s:%d->%s:%d-%d", p.SrcIP, p.SrcPort, p.DstIP, p.DstPort, p.IPProto)
}

// FastDecode performs zero-allocation parsing of raw Ethernet/VLAN/IP/TCP/UDP packets.
func FastDecode(data []byte, ts time.Time, captureLen, wireLen int, ifaceName string, ifIndex uint32) (*ParsedPacket, error) {
	if len(data) < 14 {
		return nil, fmt.Errorf("packet too short (<14 bytes)")
	}

	p := &ParsedPacket{
		Timestamp:  ts,
		CaptureLen: captureLen,
		WireLen:    wireLen,
		Interface:  ifaceName,
		IfIndex:    ifIndex,
		SrcMAC:     net.HardwareAddr(data[6:12]),
		DstMAC:     net.HardwareAddr(data[0:6]),
		RawData:    data,
	}

	etherType := binary.BigEndian.Uint16(data[12:14])
	offset := 14

	// Linux SLL Cooked mode support (16 bytes header)
	if etherType != 0x0800 && etherType != 0x86DD && etherType != 0x8100 && etherType != 0x88A8 && len(data) >= 16 {
		sllProto := binary.BigEndian.Uint16(data[14:16])
		if sllProto == 0x0800 || sllProto == 0x86DD {
			etherType = sllProto
			offset = 16
		}
	}

	// 802.1Q VLAN Tagging
	if etherType == 0x8100 || etherType == 0x88a8 {
		if len(data) < offset+4 {
			return nil, fmt.Errorf("truncated VLAN header")
		}
		p.VLANID = binary.BigEndian.Uint16(data[offset:offset+2]) & 0x0FFF
		etherType = binary.BigEndian.Uint16(data[offset+2 : offset+4])
		offset += 4
	}

	switch etherType {
	case 0x0800: // IPv4
		if len(data) < offset+20 {
			return nil, fmt.Errorf("truncated IPv4 header")
		}
		ihl := int(data[offset]&0x0F) * 4
		if ihl < 20 || len(data) < offset+ihl {
			return nil, fmt.Errorf("invalid IPv4 IHL %d", ihl)
		}

		p.TOS = data[offset+1]
		p.IPLength = binary.BigEndian.Uint16(data[offset+2 : offset+4])
		p.TTL = data[offset+8]
		p.IPProto = data[offset+9]
		p.SrcIP = net.IPv4(data[offset+12], data[offset+13], data[offset+14], data[offset+15])
		p.DstIP = net.IPv4(data[offset+16], data[offset+17], data[offset+18], data[offset+19])

		// Bound slice to IP TotalLength to strip Ethernet minimum-frame padding
		ipEnd := offset + int(p.IPLength)
		if ipEnd > offset && ipEnd < len(data) {
			data = data[:ipEnd]
		}
		p.IPData = data[offset:]
		offset += ihl

	case 0x86DD: // IPv6
		if len(data) < offset+40 {
			return nil, fmt.Errorf("truncated IPv6 header")
		}
		p.TOS = uint8((binary.BigEndian.Uint32(data[offset:offset+4]) >> 20) & 0xFF)
		p.IPLength = binary.BigEndian.Uint16(data[offset+4 : offset+6])
		p.IPProto = data[offset+6]
		p.TTL = data[offset+7]
		p.SrcIP = net.IP(data[offset+8 : offset+24])
		p.DstIP = net.IP(data[offset+24 : offset+40])

		ipEnd := offset + 40 + int(p.IPLength)
		if ipEnd > offset && ipEnd < len(data) {
			data = data[:ipEnd]
		}
		p.IPData = data[offset:]
		offset += 40

	default:
		return p, nil
	}

	// Transport Layer Parsing
	switch p.IPProto {
	case ProtoTCP:
		if len(data) < offset+20 {
			return p, nil
		}
		p.SrcPort = binary.BigEndian.Uint16(data[offset : offset+2])
		p.DstPort = binary.BigEndian.Uint16(data[offset+2 : offset+4])
		p.SeqNumber = binary.BigEndian.Uint32(data[offset+4 : offset+8])
		p.AckNumber = binary.BigEndian.Uint32(data[offset+8 : offset+12])
		dataOffset := int(data[offset+12]>>4) * 4
		p.TCPFlags = data[offset+13]
		p.Window = binary.BigEndian.Uint16(data[offset+14 : offset+16])

		if dataOffset > 20 && len(data) >= offset+dataOffset {
			p.TCPOptions = data[offset+20 : offset+dataOffset]
		}
		if dataOffset >= 20 && len(data) >= offset+dataOffset {
			p.Payload = data[offset+dataOffset:]
		}

	case ProtoUDP:
		if len(data) < offset+8 {
			return p, nil
		}
		p.SrcPort = binary.BigEndian.Uint16(data[offset : offset+2])
		p.DstPort = binary.BigEndian.Uint16(data[offset+2 : offset+4])
		udpLen := int(binary.BigEndian.Uint16(data[offset+4 : offset+6]))
		if udpLen >= 8 && len(data) >= offset+8 {
			end := offset + udpLen
			if end > len(data) {
				end = len(data)
			}
			p.Payload = data[offset+8 : end]
		}

	case ProtoICMP, ProtoICMPv6:
		if len(data) >= offset+2 {
			p.ICMPType = data[offset]
			p.ICMPCode = data[offset+1]
			// Map ICMP type and code to port fields for flow correlation
			p.DstPort = uint16(p.ICMPType)<<8 | uint16(p.ICMPCode)
		}
		if len(data) >= offset+8 {
			p.Payload = data[offset+8:]
		}
	}

	return p, nil
}
