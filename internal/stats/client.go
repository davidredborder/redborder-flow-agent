package stats

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// QuerySocket connects to the local UNIX domain socket and reads a Snapshot.
func QuerySocket(socketPath string) (*Snapshot, error) {
	if socketPath == "" {
		socketPath = "/var/run/redborder-flow-agent.sock"
	}

	conn, err := net.DialTimeout("unix", socketPath, 2*time.Second)
	if err != nil {
		return nil, fmt.Errorf("could not connect to socket %s: %w\n(Is redborder-flow-agent running?)", socketPath, err)
	}
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	data, err := io.ReadAll(conn)
	if err != nil {
		return nil, fmt.Errorf("failed to read from socket %s: %w", socketPath, err)
	}

	var snap Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, fmt.Errorf("failed to parse stats JSON: %w (raw: %s)", err, string(data))
	}

	return &snap, nil
}

// formatBytes returns human-readable bytes representation (KB, MB, GB).
func formatBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

// formatDuration returns human-readable duration (e.g. 2h 15m 30s).
func formatDuration(sec int64) string {
	d := time.Duration(sec) * time.Second
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh %dm %ds", h, m, s)
	}
	if m > 0 {
		return fmt.Sprintf("%dm %ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}

// PrintFormattedSnapshot prints a clean ASCII summary table to stdout.
func PrintFormattedSnapshot(snap *Snapshot, socketPath string) {
	fmt.Println("================================================================================")
	fmt.Println("  redborder-flow-agent - Live Probe Statistics")
	fmt.Println("================================================================================")
	fmt.Printf("  Socket Path:           %s\n", socketPath)
	fmt.Printf("  Uptime:                %-22s Goroutines:           %d\n", formatDuration(snap.UptimeSec), snap.NumGoroutines)
	fmt.Printf("  CPU Cores (Procs):     %d / %-18d GC Cycles:            %d\n", snap.MaxProcs, snap.NumCPU, snap.GCNum)
	fmt.Printf("  Memory (Alloc / Sys):  %s / %s\n", formatBytes(snap.MemoryAllocBytes), formatBytes(snap.MemorySysBytes))
	fmt.Println("--------------------------------------------------------------------------------")
	fmt.Println("  PACKET & TRAFFIC METRICS")
	fmt.Printf("  Packets Captured:      %-22d Bytes Captured:       %s\n", snap.PacketsCaptured, formatBytes(snap.BytesCaptured))
	dropPct := 0.0
	if snap.PacketsCaptured+snap.PacketsDropped > 0 {
		dropPct = (float64(snap.PacketsDropped) / float64(snap.PacketsCaptured+snap.PacketsDropped)) * 100.0
	}
	fmt.Printf("  Packets Dropped:       %d (%.2f%%)\n", snap.PacketsDropped, dropPct)
	fmt.Println("--------------------------------------------------------------------------------")
	fmt.Println("  FLOW & PROTOCOL TELEMETRY")
	fmt.Printf("  Active Flows:          %-22d Flows Dropped (Full): %d\n", snap.ActiveFlows, snap.FlowsDroppedTableFull)
	fmt.Printf("  Exported Flows:        %-22d Export Errors:        %d\n", snap.ExportedFlows, snap.ExportErrors)
	fmt.Printf("  TCP Handshakes:        %-22d Open Ports Detected:  %d\n", snap.TCPHandshakes, snap.OpenPortsDetected)
	fmt.Printf("  TLS ClientHellos (JA4): %-21d DNS Queries Snooped:  %d\n", snap.TLSClientHellos, snap.DNSQueriesDetected)
	fmt.Println("================================================================================")
}

// RunTopConsole runs a live auto-refreshing terminal monitor.
func RunTopConsole(ctx context.Context, socketPath string) error {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	var lastPackets, lastBytes uint64
	var lastTime time.Time

	// Initial fetch
	snap, err := QuerySocket(socketPath)
	if err != nil {
		return err
	}
	lastPackets = snap.PacketsCaptured
	lastBytes = snap.BytesCaptured
	lastTime = time.Now()

	render := func(s *Snapshot) {
		now := time.Now()
		dt := now.Sub(lastTime).Seconds()
		if dt <= 0 {
			dt = 1
		}

		deltaPackets := s.PacketsCaptured - lastPackets
		deltaBytes := s.BytesCaptured - lastBytes

		pps := float64(deltaPackets) / dt
		mbps := (float64(deltaBytes) * 8.0) / (dt * 1000000.0)

		lastPackets = s.PacketsCaptured
		lastBytes = s.BytesCaptured
		lastTime = now

		// Clear screen & ANSI home
		fmt.Print("\033[H\033[2J")
		fmt.Println("================================================================================")
		fmt.Printf("  redborder-flow-agent [TOP CONSOLE] - %s\n", now.Format("2006-01-02 15:04:05"))
		fmt.Println("================================================================================")
		fmt.Printf("  Socket:                %-22s Uptime:               %s\n", socketPath, formatDuration(s.UptimeSec))
		fmt.Printf("  Active Flows:          %-22d Goroutines:           %d\n", s.ActiveFlows, s.NumGoroutines)
		fmt.Printf("  CPU Cores (Procs):     %d / %-18d Memory Alloc:         %s\n", s.MaxProcs, s.NumCPU, formatBytes(s.MemoryAllocBytes))
		fmt.Println("--------------------------------------------------------------------------------")
		fmt.Println("  LIVE THROUGHPUT & PACKET RATES")
		fmt.Printf("  Current Ingestion:     %10.1f pps       Bandwidth:          %8.2f Mbps\n", pps, mbps)
		fmt.Printf("  Total Packets:         %10d           Total Volume:       %s\n", s.PacketsCaptured, formatBytes(s.BytesCaptured))
		dropPct := 0.0
		if s.PacketsCaptured+s.PacketsDropped > 0 {
			dropPct = (float64(s.PacketsDropped) / float64(s.PacketsCaptured+s.PacketsDropped)) * 100.0
		}
		fmt.Printf("  Total Dropped:         %10d (%.2f%%)\n", s.PacketsDropped, dropPct)
		fmt.Println("--------------------------------------------------------------------------------")
		fmt.Println("  L4/L7 TELEMETRY & DISCOVERY STATS")
		fmt.Printf("  Active Flows:          %10d           Flows Dropped (Full): %d\n", s.ActiveFlows, s.FlowsDroppedTableFull)
		fmt.Printf("  Exported Flows:        %10d           Export Errors:        %d\n", s.ExportedFlows, s.ExportErrors)
		fmt.Printf("  TCP Handshakes:        %10d           Open Ports Active:    %d\n", s.TCPHandshakes, s.OpenPortsDetected)
		fmt.Printf("  TLS Handshakes (JA4):  %10d           DNS Queries:          %d\n", s.TLSClientHellos, s.DNSQueriesDetected)
		fmt.Println("================================================================================")
		fmt.Println("  [Ctrl+C to exit monitor]")
	}

	render(snap)

	for {
		select {
		case <-sigChan:
			fmt.Println("\nExiting top monitor.")
			return nil
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			s, err := QuerySocket(socketPath)
			if err != nil {
				fmt.Printf("\nError querying agent: %v\n", err)
				continue
			}
			render(s)
		}
	}
}
