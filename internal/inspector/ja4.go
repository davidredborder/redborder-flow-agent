package inspector

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// JA4Fingerprint holds computed JA4 and JA4_r TLS client fingerprints.
type JA4Fingerprint struct {
	JA4  string // e.g. "t13d1516h2_8daaf6152771_e562703ab85f"
	JA4_r string // Raw signature representation
}

// ComputeJA4 extracts and calculates the JA4 fingerprint from a TLS ClientHello packet.
// JA4 format: [protocol][tls_version][sni_type][cipher_count][extension_count][alpn]_[sorted_ciphers_sha256_12]_[sorted_extensions+sigalgs_sha256_12]
func ComputeJA4(data []byte) *JA4Fingerprint {
	if !IsTLSHandshake(data) || len(data) < 44 {
		return nil
	}

	protocol := "t" // TCP
	tlsVersion := "00"
	sniType := "i"  // Default: IP or no SNI
	alpn := "00"    // Default: no ALPN

	// Parse TLS Version from ClientHello
	rawVer := binary.BigEndian.Uint16(data[9:11])
	switch rawVer {
	case 0x0304:
		tlsVersion = "13"
	case 0x0303:
		tlsVersion = "12"
	case 0x0302:
		tlsVersion = "11"
	case 0x0301:
		tlsVersion = "10"
	case 0x0300:
		tlsVersion = "s3"
	}

	// Session ID offset
	sidLen := int(data[43])
	offset := 44 + sidLen
	if len(data) < offset+2 {
		return nil
	}

	// Parse Cipher Suites
	cipherLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2
	if len(data) < offset+cipherLen+1 {
		return nil
	}

	var ciphers []uint16
	for i := 0; i+2 <= cipherLen; i += 2 {
		val := binary.BigEndian.Uint16(data[offset+i : offset+i+2])
		// Ignore GREASE ciphers (0x?a?a)
		if !isGREASE(val) {
			ciphers = append(ciphers, val)
		}
	}
	offset += cipherLen

	// Parse Compression Methods
	compLen := int(data[offset])
	offset += 1 + compLen
	if len(data) < offset+2 {
		return nil
	}

	// Parse Extensions
	extTotalLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2
	extEnd := offset + extTotalLen
	if extEnd > len(data) {
		extEnd = len(data)
	}

	var extensions []uint16
	var sigAlgs []uint16

	for offset+4 <= extEnd {
		extType := binary.BigEndian.Uint16(data[offset : offset+2])
		extDataLen := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		offset += 4

		if offset+extDataLen > extEnd {
			break
		}

		extData := data[offset : offset+extDataLen]

		// Filter GREASE extensions
		if !isGREASE(extType) {
			extensions = append(extensions, extType)
		}

		// 0x0000 = SNI
		if extType == 0x0000 && extDataLen >= 5 {
			sniType = "d" // Domain name present
		}

		// 0x002b = Supported Versions (true TLS version)
		if extType == 0x002b && extDataLen >= 2 {
			versLen := int(extData[0])
			for v := 1; v+2 <= 1+versLen && v+2 <= len(extData); v += 2 {
				sv := binary.BigEndian.Uint16(extData[v : v+2])
				if sv == 0x0304 {
					tlsVersion = "13"
					break
				}
			}
		}

		// 0x0010 = ALPN
		if extType == 0x0010 && extDataLen >= 4 {
			listLen := int(binary.BigEndian.Uint16(extData[0:2]))
			if listLen > 0 && listLen <= len(extData)-2 {
				protoLen := int(extData[2])
				if 3+protoLen <= len(extData) {
					firstProto := string(extData[3 : 3+protoLen])
					if strings.HasPrefix(firstProto, "h2") {
						alpn = "h2"
					} else if strings.HasPrefix(firstProto, "http/1.1") {
						alpn = "h1"
					} else if len(firstProto) >= 2 {
						alpn = string([]byte{firstProto[0], firstProto[len(firstProto)-1]})
					}
				}
			}
		}

		// 0x000d = Signature Algorithms
		if extType == 0x000d && extDataLen >= 2 {
			saLen := int(binary.BigEndian.Uint16(extData[0:2]))
			for sa := 2; sa+2 <= 2+saLen && sa+2 <= len(extData); sa += 2 {
				sigVal := binary.BigEndian.Uint16(extData[sa : sa+2])
				if !isGREASE(sigVal) {
					sigAlgs = append(sigAlgs, sigVal)
				}
			}
		}

		offset += extDataLen
	}

	cipherCount := fmt.Sprintf("%02d", len(ciphers))
	if len(ciphers) > 99 {
		cipherCount = "99"
	}

	extCount := fmt.Sprintf("%02d", len(extensions))
	if len(extensions) > 99 {
		extCount = "99"
	}

	partA := fmt.Sprintf("%s%s%s%s%s%s", protocol, tlsVersion, sniType, cipherCount, extCount, alpn)

	// Sort ciphers in ascending order for Part B
	sort.Slice(ciphers, func(i, j int) bool { return ciphers[i] < ciphers[j] })
	var cipherStrs []string
	for _, c := range ciphers {
		cipherStrs = append(cipherStrs, fmt.Sprintf("%04x", c))
	}
	cipherListStr := strings.Join(cipherStrs, ",")
	hB := sha256.Sum256([]byte(cipherListStr))
	partB := hex.EncodeToString(hB[:])[:12]

	// Sort extensions in ascending order, followed by signature algorithms for Part C
	sort.Slice(extensions, func(i, j int) bool { return extensions[i] < extensions[j] })
	var extStrs []string
	for _, e := range extensions {
		extStrs = append(extStrs, fmt.Sprintf("%04x", e))
	}
	extListStr := strings.Join(extStrs, ",")

	var sigStrs []string
	for _, s := range sigAlgs {
		sigStrs = append(sigStrs, fmt.Sprintf("%04x", s))
	}
	sigListStr := strings.Join(sigStrs, ",")

	combinedC := extListStr
	if len(sigStrs) > 0 {
		combinedC = fmt.Sprintf("%s_%s", extListStr, sigListStr)
	}
	hC := sha256.Sum256([]byte(combinedC))
	partC := hex.EncodeToString(hC[:])[:12]

	ja4 := fmt.Sprintf("%s_%s_%s", partA, partB, partC)
	raw := fmt.Sprintf("%s_%s_%s", partA, cipherListStr, combinedC)

	return &JA4Fingerprint{
		JA4:   ja4,
		JA4_r: raw,
	}
}

// isGREASE detects RFC 8701 GREASE values (0x0a0a, 0x1a1a, ... 0xfafa).
func isGREASE(val uint16) bool {
	return (val & 0x0f0f) == 0x0a0a && (val>>8) == (val&0xff)
}
