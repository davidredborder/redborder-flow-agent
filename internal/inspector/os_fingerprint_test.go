package inspector

import (
	"testing"
)

func TestDetectOSFromTCPSYN(t *testing.T) {
	// Linux SYN: TTL 64, Window 29200, Options: MSS (1460), SACK, TS, NOP, WScale (7)
	// Option bytes: 02 04 05 b4 (MSS 1460), 04 02 (SACK), 08 0a ... (TS), 01 (NOP), 03 03 07 (WS 7)
	linuxOpts := []byte{
		0x02, 0x04, 0x05, 0xb4,
		0x04, 0x02,
		0x08, 0x0a, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x01,
		0x03, 0x03, 0x07,
	}

	fpLinux := DetectOSFromTCPSYN(64, 29200, linuxOpts)
	if fpLinux.OS != "Linux" {
		t.Fatalf("expected Linux OS, got %s (signature: %s)", fpLinux.OS, fpLinux.Fingerprint)
	}

	// Windows SYN: TTL 128, Window 64240, Options: MSS (1460), NOP, WScale (8), NOP, NOP, SACK
	winOpts := []byte{
		0x02, 0x04, 0x05, 0xb4,
		0x01,
		0x03, 0x03, 0x08,
		0x01, 0x01,
		0x04, 0x02,
	}

	fpWin := DetectOSFromTCPSYN(128, 64240, winOpts)
	if fpWin.OS != "Windows" {
		t.Fatalf("expected Windows OS, got %s (signature: %s)", fpWin.OS, fpWin.Fingerprint)
	}
}
