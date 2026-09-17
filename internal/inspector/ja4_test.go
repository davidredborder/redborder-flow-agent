package inspector

import (
	"fmt"
	"strings"
	"testing"
)

func TestComputeJA4(t *testing.T) {
	// Build valid TLS ClientHello programmatically to avoid any manual offset mistake
	// 1. Extensions
	// SNI: "example.com" (type 0x0000, 16 bytes payload)
	sniExt := []byte{
		0x00, 0x00, // type SNI
		0x00, 0x10, // ext len 16
		0x00, 0x0e, // list len 14
		0x00,       // host_name type
		0x00, 0x0b, // name len 11
		'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
	}

	// supported_versions: TLS 1.3 (0x0304) (type 0x002b)
	suppVersExt := []byte{
		0x00, 0x2b, // type supported_versions
		0x00, 0x03, // ext len 3
		0x02,       // vers list len 2
		0x03, 0x04, // TLS 1.3
	}

	// ALPN: "h2" (type 0x0010)
	alpnExt := []byte{
		0x00, 0x10, // type ALPN
		0x00, 0x05, // ext len 5
		0x00, 0x03, // alpn list len 3
		0x02,       // string len 2
		'h', '2',
	}

	exts := append(sniExt, suppVersExt...)
	exts = append(exts, alpnExt...)

	extsLen := len(exts)
	extsHeader := []byte{byte(extsLen >> 8), byte(extsLen & 0xff)}

	// 2. ClientHello Body
	var chBody []byte
	chBody = append(chBody, 0x03, 0x03) // client version 0303
	chBody = append(chBody, make([]byte, 32)...) // 32 bytes random
	chBody = append(chBody, 0x00) // session ID len = 0
	chBody = append(chBody, 0x00, 0x04, 0x13, 0x01, 0x13, 0x02) // ciphers len 4 (1301, 1302)
	chBody = append(chBody, 0x01, 0x00) // comp methods len 1 (00)
	chBody = append(chBody, extsHeader...)
	chBody = append(chBody, exts...)

	// 3. Handshake Header
	chLen := len(chBody)
	var hsHeader = []byte{
		0x01, // HandshakeType ClientHello
		byte((chLen >> 16) & 0xff),
		byte((chLen >> 8) & 0xff),
		byte(chLen & 0xff),
	}

	// 4. Record Header
	recBody := append(hsHeader, chBody...)
	recLen := len(recBody)
	var recHeader = []byte{
		0x16,       // ContentType Handshake
		0x03, 0x01, // Record Version 3.1
		byte(recLen >> 8),
		byte(recLen & 0xff),
	}

	packet := append(recHeader, recBody...)

	ja4 := ComputeJA4(packet)
	if ja4 == nil {
		t.Fatalf("expected non-nil JA4 fingerprint")
	}

	fmt.Printf("Computed JA4: %s\n", ja4.JA4)

	if !strings.HasPrefix(ja4.JA4, "t13d0203h2_") {
		t.Fatalf("expected JA4 starting with t13d0203h2_, got %s", ja4.JA4)
	}
}
