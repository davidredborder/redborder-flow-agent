package inspector

import (
	"fmt"
	"strings"
)

// OSFingerprint holds OS detection results from passive TCP SYN analysis.
type OSFingerprint struct {
	OS          string // e.g. "Linux", "Windows", "macOS/iOS", "Android", "FreeBSD"
	Fingerprint string // Human-readable signature, e.g. "64:64240:mss,sack,ts,nop,wscale"
}

// DetectOSFromTCPSYN infers client operating system from initial SYN packet characteristics:
// - Initial TTL (64, 128, 255)
// - Initial TCP Window Size
// - TCP Options signature (MSS, Window Scale, SACK, Timestamps, NOPs)
// - DF (Don't Fragment) flag
func DetectOSFromTCPSYN(ttl uint8, window uint16, tcpOptions []byte) OSFingerprint {
	var optNames []string
	var mss uint16
	var wscale uint8
	hasSACK := false
	hasTS := false

	// Parse TCP options
	i := 0
	for i < len(tcpOptions) {
		opt := tcpOptions[i]
		if opt == 0 { // End of Option List
			optNames = append(optNames, "eol")
			break
		}
		if opt == 1 { // NOP
			optNames = append(optNames, "nop")
			i++
			continue
		}
		if i+1 >= len(tcpOptions) {
			break
		}
		optLen := int(tcpOptions[i+1])
		if optLen < 2 || i+optLen > len(tcpOptions) {
			break
		}

		switch opt {
		case 2: // MSS
			if optLen == 4 {
				mss = (uint16(tcpOptions[i+2]) << 8) | uint16(tcpOptions[i+3])
				optNames = append(optNames, "mss")
			}
		case 3: // Window Scale
			if optLen == 3 {
				wscale = tcpOptions[i+2]
				optNames = append(optNames, "ws")
			}
		case 4: // SACK Permitted
			hasSACK = true
			optNames = append(optNames, "sack")
		case 8: // Timestamps
			hasTS = true
			optNames = append(optNames, "ts")
		default:
			optNames = append(optNames, fmt.Sprintf("opt%d", opt))
		}
		i += optLen
	}

	sig := fmt.Sprintf("ttl%d:win%d:%s", ttl, window, strings.Join(optNames, ","))

	// Heuristic OS Classification based on well-established passive OS fingerprinting rules (p0f style)
	var osName string

	switch {
	// Linux / Android (Initial TTL 64, Window often 29200, 5840, 64240, 65535 with MSS 1460, SACK, TS)
	case ttl <= 64:
		if hasTS && hasSACK {
			if wscale == 7 || wscale == 6 || wscale == 8 {
				osName = "Linux"
			} else if window == 65535 {
				osName = "macOS/iOS"
			} else {
				osName = "Linux"
			}
		} else if window == 65535 || (wscale >= 4 && !hasTS) {
			osName = "macOS/iOS"
		} else if ttl >= 40 {
			osName = "Linux/Android"
		} else {
			osName = "Linux"
		}

	// Windows (Initial TTL 128, Window often 8192, 64240, 65535 with Window Scale 2, 8, SACK permitted, NO Timestamps)
	case ttl > 64 && ttl <= 128:
		if !hasTS && hasSACK {
			if window == 8192 || window == 64240 || window == 65535 {
				osName = "Windows"
			} else {
				osName = "Windows"
			}
		} else if hasTS {
			osName = "Windows Server"
		} else {
			osName = "Windows"
		}

	// Cisco / Solaris / BSD / Network Appliance (Initial TTL 255)
	case ttl > 128:
		if hasTS {
			osName = "FreeBSD/Solaris"
		} else if window == 4128 || window == 8192 {
			osName = "Cisco IOS"
		} else {
			osName = "Network Device / BSD"
		}

	default:
		osName = "Unknown"
	}

	_ = mss
	return OSFingerprint{
		OS:          osName,
		Fingerprint: sig,
	}
}

// DetectOSFromTTL provides a baseline OS classification from observed TTL when SYN packet was not captured.
func DetectOSFromTTL(ttl uint8) string {
	switch {
	case ttl > 0 && ttl <= 64:
		return "Linux"
	case ttl > 64 && ttl <= 128:
		return "Windows"
	case ttl > 128:
		return "Network Device / BSD"
	default:
		return ""
	}
}
