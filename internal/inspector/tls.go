package inspector

import (
	"encoding/binary"
	"strings"
)

// IsTLSHandshake verifies if the payload matches a TLS ClientHello.
func IsTLSHandshake(data []byte) bool {
	if len(data) < 9 {
		return false
	}
	// ContentType 22 (Handshake), Major Version 3, HandshakeType 1 (ClientHello)
	return data[0] == 0x16 && data[1] == 0x03 && data[5] == 0x01
}

// ExtractTLSDetails extracts SNI and human-readable TLS version string from TLS ClientHello.
func ExtractTLSDetails(data []byte) (sni string, tlsVersion string) {
	if !IsTLSHandshake(data) || len(data) < 44 {
		return "", ""
	}

	rawVer := binary.BigEndian.Uint16(data[9:11])
	switch rawVer {
	case 0x0304:
		tlsVersion = "TLS 1.3"
	case 0x0303:
		tlsVersion = "TLS 1.2"
	case 0x0302:
		tlsVersion = "TLS 1.1"
	case 0x0301:
		tlsVersion = "TLS 1.0"
	default:
		tlsVersion = "TLS"
	}

	// Skip Session ID
	sidLen := int(data[43])
	offset := 44 + sidLen
	if len(data) < offset+2 {
		return "", tlsVersion
	}

	// Skip Cipher Suites
	cipherLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2 + cipherLen
	if len(data) < offset+1 {
		return "", tlsVersion
	}

	// Skip Compression Methods
	compLen := int(data[offset])
	offset += 1 + compLen
	if len(data) < offset+2 {
		return "", tlsVersion
	}

	// Parse Extensions
	extTotalLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2
	extEnd := offset + extTotalLen
	if extEnd > len(data) {
		extEnd = len(data)
	}

	for offset+4 <= extEnd {
		extType := binary.BigEndian.Uint16(data[offset : offset+2])
		extDataLen := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		offset += 4

		if offset+extDataLen > extEnd {
			break
		}

		// Extension 0x0000 = server_name (SNI)
		if extType == 0x0000 && extDataLen >= 5 {
			extData := data[offset : offset+extDataLen]
			listLen := int(binary.BigEndian.Uint16(extData[0:2]))
			if listLen <= len(extData)-2 {
				nameType := extData[2]
				if nameType == 0x00 { // HostName
					nameLen := int(binary.BigEndian.Uint16(extData[3:5]))
					if 5+nameLen <= len(extData) {
						sni = strings.ToLower(string(extData[5 : 5+nameLen]))
					}
				}
			}
		}

		// Extension 0x002b = supported_versions (identifies true TLS 1.3)
		if extType == 0x002b && extDataLen >= 2 {
			extData := data[offset : offset+extDataLen]
			versLen := int(extData[0])
			for v := 1; v+2 <= 1+versLen && v+2 <= len(extData); v += 2 {
				sv := binary.BigEndian.Uint16(extData[v : v+2])
				if sv == 0x0304 {
					tlsVersion = "TLS 1.3"
					break
				}
			}
		}

		offset += extDataLen
	}

	return sni, tlsVersion
}

// ExtractTLSSNI is a helper returning only the SNI string.
func ExtractTLSSNI(data []byte) string {
	sni, _ := ExtractTLSDetails(data)
	return sni
}
