package stats

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStatsCollectorAndSnapshot(t *testing.T) {
	c := NewCollector()
	c.SetActiveFlowsFunc(func() int {
		return 42
	})

	c.IncPacketsCaptured(10, 15000)
	c.IncPacketsDropped()
	c.IncExportedFlows(5)
	c.IncExportErrors()
	c.IncFlowsDroppedTableFull()
	c.IncTCPHandshakes()
	c.IncOpenPorts()
	c.IncTLSClientHellos()
	c.IncDNSQueries()

	snap := c.GetSnapshot()

	if snap.PacketsCaptured != 10 {
		t.Errorf("expected 10 packets, got %d", snap.PacketsCaptured)
	}
	if snap.BytesCaptured != 15000 {
		t.Errorf("expected 15000 bytes, got %d", snap.BytesCaptured)
	}
	if snap.PacketsDropped != 1 {
		t.Errorf("expected 1 dropped packet, got %d", snap.PacketsDropped)
	}
	if snap.ActiveFlows != 42 {
		t.Errorf("expected 42 active flows, got %d", snap.ActiveFlows)
	}
	if snap.ExportedFlows != 5 {
		t.Errorf("expected 5 exported flows, got %d", snap.ExportedFlows)
	}
	if snap.ExportErrors != 1 {
		t.Errorf("expected 1 export error, got %d", snap.ExportErrors)
	}
	if snap.FlowsDroppedTableFull != 1 {
		t.Errorf("expected 1 flow dropped table full, got %d", snap.FlowsDroppedTableFull)
	}
	if snap.TCPHandshakes != 1 {
		t.Errorf("expected 1 tcp handshake, got %d", snap.TCPHandshakes)
	}
	if snap.OpenPortsDetected != 1 {
		t.Errorf("expected 1 open port detected, got %d", snap.OpenPortsDetected)
	}
	if snap.TLSClientHellos != 1 {
		t.Errorf("expected 1 tls client hello, got %d", snap.TLSClientHellos)
	}
	if snap.DNSQueriesDetected != 1 {
		t.Errorf("expected 1 dns query, got %d", snap.DNSQueriesDetected)
	}
	if snap.NumCPU <= 0 || snap.MaxProcs <= 0 {
		t.Errorf("invalid CPU stats: NumCPU=%d, MaxProcs=%d", snap.NumCPU, snap.MaxProcs)
	}
}

func TestStatsServerUnixAndHTTP(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "test-stats.sock")
	httpAddr := "127.0.0.1:0" // Pick free port

	c := NewCollector()
	c.IncPacketsCaptured(100, 50000)

	// Create listener first to get free port for HTTP
	httpLn, err := net.Listen("tcp", httpAddr)
	if err != nil {
		t.Fatalf("failed to listen on tcp: %v", err)
	}
	actualHTTPAddr := httpLn.Addr().String()
	_ = httpLn.Close()

	srv := NewServer(sockPath, actualHTTPAddr, c, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := srv.Start(ctx); err != nil {
		t.Fatalf("failed to start stats server: %v", err)
	}
	defer srv.Close()

	// Wait briefly for server startup
	time.Sleep(100 * time.Millisecond)

	// 1. Test UNIX Domain Socket
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("failed to connect to unix domain socket %s: %v", sockPath, err)
	}
	defer conn.Close()

	buf, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("failed to read from unix domain socket: %v", err)
	}

	var unixSnap Snapshot
	if err := json.Unmarshal(buf, &unixSnap); err != nil {
		t.Fatalf("failed to parse json from unix socket: %v, raw: %s", err, string(buf))
	}
	if unixSnap.PacketsCaptured != 100 || unixSnap.BytesCaptured != 50000 {
		t.Errorf("unexpected unix snap values: %+v", unixSnap)
	}

	// 2. Test HTTP /stats endpoint
	resp, err := http.Get("http://" + actualHTTPAddr + "/stats")
	if err != nil {
		t.Fatalf("failed to query http /stats: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", resp.StatusCode)
	}

	var httpSnap Snapshot
	if err := json.NewDecoder(resp.Body).Decode(&httpSnap); err != nil {
		t.Fatalf("failed to decode http json response: %v", err)
	}
	if httpSnap.PacketsCaptured != 100 {
		t.Errorf("expected 100 packets in http stats, got %d", httpSnap.PacketsCaptured)
	}

	// 3. Test HTTP /health endpoint
	healthResp, err := http.Get("http://" + actualHTTPAddr + "/health")
	if err != nil {
		t.Fatalf("failed to query http /health: %v", err)
	}
	defer healthResp.Body.Close()
	if healthResp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK for /health, got %d", healthResp.StatusCode)
	}

	// Ensure socket file gets cleaned up on Close()
	srv.Close()
	if _, err := os.Stat(sockPath); !os.IsNotExist(err) {
		t.Errorf("expected socket file %s to be deleted after Close()", sockPath)
	}
}

func TestClientFormattingAndQuery(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "test-client.sock")

	c := NewCollector()
	c.IncPacketsCaptured(500, 250000)
	c.IncPacketsDropped()
	c.IncExportedFlows(15)
	c.IncTCPHandshakes()
	c.IncOpenPorts()
	c.IncTLSClientHellos()
	c.IncDNSQueries()

	srv := NewServer(sockPath, "", c, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := srv.Start(ctx); err != nil {
		t.Fatalf("failed to start srv: %v", err)
	}
	defer srv.Close()

	time.Sleep(50 * time.Millisecond)

	snap, err := QuerySocket(sockPath)
	if err != nil {
		t.Fatalf("QuerySocket failed: %v", err)
	}

	if snap.PacketsCaptured != 500 {
		t.Errorf("expected 500 packets, got %d", snap.PacketsCaptured)
	}

	// Verify formatting helper doesn't crash
	PrintFormattedSnapshot(snap, sockPath)
}
