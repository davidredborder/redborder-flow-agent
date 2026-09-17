package inspector

import (
	"net"
	"testing"
	"time"

	"github.com/redborder/redborder-flow-agent/internal/capture"
)

func TestExtractHTTPInfo(t *testing.T) {
	req := []byte("GET /api/v1/metrics?format=json HTTP/1.1\r\nHost: api.example.com\r\nUser-Agent: curl/7.68.0\r\nAccept: */*\r\n\r\n")
	host, uri := ExtractHTTPInfo(req)

	if host != "api.example.com" {
		t.Fatalf("expected host api.example.com, got %s", host)
	}
	if uri != "/api/v1/metrics?format=json" {
		t.Fatalf("expected URI /api/v1/metrics?format=json, got %s", uri)
	}
}

func TestExtractTLSSNI(t *testing.T) {
	// Synthesize a valid TLS ClientHello with SNI = "dashboard.redborder.com"
	sniName := "dashboard.redborder.com"
	sniBytes := []byte(sniName)

	var extData []byte
	// Extension 0x0000 (server_name)
	extData = append(extData, 0x00, byte(len(sniBytes)+3)) // list len
	extData = append(extData, 0x00)                        // type host_name
	extData = append(extData, 0x00, byte(len(sniBytes)))  // host len
	extData = append(extData, sniBytes...)

	var payload []byte
	// TLS Record Header: Type 22, Ver 0x0303, Len
	payload = append(payload, 0x16, 0x03, 0x03, 0x00, 0x00) // len patched later
	// Handshake: Type 1 (ClientHello), Len (3 bytes)
	payload = append(payload, 0x01, 0x00, 0x00, 0x00)
	payload = append(payload, 0x03, 0x03) // client ver
	payload = append(payload, make([]byte, 32)...) // random
	payload = append(payload, 0x00) // session ID len 0
	payload = append(payload, 0x00, 0x02, 0x13, 0x01) // cipher suites (1 suite)
	payload = append(payload, 0x01, 0x00) // comp methods (1 method)
	// Extensions length
	payload = append(payload, 0x00, byte(len(extData)+4))
	// Extension header
	payload = append(payload, 0x00, 0x00, 0x00, byte(len(extData)))
	payload = append(payload, extData...)

	sni := ExtractTLSSNI(payload)
	if sni != sniName {
		t.Fatalf("expected SNI %s, got %s", sniName, sni)
	}
}

func TestDNSCache(t *testing.T) {
	cache := NewDNSCache(100)
	ip := net.ParseIP("93.184.216.34")
	cache.Put(ip, "example.com", 1*time.Hour)

	found := cache.Lookup(ip)
	if found != "example.com" {
		t.Fatalf("expected domain example.com, got %s", found)
	}
}

func TestEvaluateTCPFlags(t *testing.T) {
	state := StateNone
	var isOpen bool

	// Step 1: SYN from client
	state, isOpen = EvaluateTCPFlags(capture.FlagSYN, true, state)
	if state != StateSYNSent || isOpen {
		t.Fatalf("expected StateSYNSent and false, got %v and %v", state, isOpen)
	}

	// Step 2: SYN-ACK from server
	state, isOpen = EvaluateTCPFlags(capture.FlagSYN|capture.FlagACK, false, state)
	if state != StateSYNReceived || !isOpen {
		t.Fatalf("expected StateSYNReceived and true, got %v and %v", state, isOpen)
	}

	// Step 3: ACK from client
	state, isOpen = EvaluateTCPFlags(capture.FlagACK, true, state)
	if state != StateEstablished || !isOpen {
		t.Fatalf("expected StateEstablished and true, got %v and %v", state, isOpen)
	}
}
