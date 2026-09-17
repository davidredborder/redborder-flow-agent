package stats

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"runtime"
	"sync/atomic"
	"time"
)

// Snapshot represents a point-in-time metrics export payload.
type Snapshot struct {
	Timestamp          int64   `json:"timestamp"`
	UptimeSec          int64   `json:"uptime_sec"`
	PacketsCaptured    uint64  `json:"packets_captured"`
	BytesCaptured      uint64  `json:"bytes_captured"`
	PacketsDropped     uint64  `json:"packets_dropped"`
	ActiveFlows           int     `json:"active_flows"`
	ExportedFlows         uint64  `json:"exported_flows"`
	ExportErrors          uint64  `json:"export_errors"`
	FlowsDroppedTableFull uint64  `json:"flows_dropped_table_full"`
	TCPHandshakes         uint64  `json:"tcp_handshakes"`
	OpenPortsDetected     uint64  `json:"open_ports_detected"`
	TLSClientHellos       uint64  `json:"tls_client_hellos"`
	DNSQueriesDetected    uint64  `json:"dns_queries_detected"`
	NumCPU                int     `json:"num_cpu"`
	MaxProcs              int     `json:"max_procs"`
	NumGoroutines         int     `json:"num_goroutines"`
	MemoryAllocBytes      uint64  `json:"memory_alloc_bytes"`
	MemorySysBytes        uint64  `json:"memory_sys_bytes"`
	GCNum                 uint32  `json:"gc_num"`
}

// Collector provides thread-safe atomic metric counters.
type Collector struct {
	startTime             time.Time
	packetsCaptured       uint64
	bytesCaptured         uint64
	packetsDropped        uint64
	exportedFlows         uint64
	exportErrors          uint64
	flowsDroppedTableFull uint64
	tcpHandshakes         uint64
	openPortsDetected     uint64
	tlsClientHellos       uint64
	dnsQueriesDetected    uint64
	activeFlowsFn         func() int
}

// GlobalCollector is the default singleton instance.
var GlobalCollector = NewCollector()

// NewCollector creates an initialized metric collector.
func NewCollector() *Collector {
	return &Collector{
		startTime: time.Now(),
		activeFlowsFn: func() int { return 0 },
	}
}

func (c *Collector) SetActiveFlowsFunc(fn func() int) {
	c.activeFlowsFn = fn
}

func (c *Collector) IncPacketsCaptured(n uint64, bytes uint64) {
	atomic.AddUint64(&c.packetsCaptured, n)
	atomic.AddUint64(&c.bytesCaptured, bytes)
}

func (c *Collector) IncPacketsDropped() {
	atomic.AddUint64(&c.packetsDropped, 1)
}

func (c *Collector) IncExportedFlows(n uint64) {
	atomic.AddUint64(&c.exportedFlows, n)
}

func (c *Collector) IncExportErrors() {
	atomic.AddUint64(&c.exportErrors, 1)
}

func (c *Collector) IncFlowsDroppedTableFull() {
	atomic.AddUint64(&c.flowsDroppedTableFull, 1)
}

func (c *Collector) IncTCPHandshakes() {
	atomic.AddUint64(&c.tcpHandshakes, 1)
}

func (c *Collector) IncOpenPorts() {
	atomic.AddUint64(&c.openPortsDetected, 1)
}

func (c *Collector) IncTLSClientHellos() {
	atomic.AddUint64(&c.tlsClientHellos, 1)
}

func (c *Collector) IncDNSQueries() {
	atomic.AddUint64(&c.dnsQueriesDetected, 1)
}

func (c *Collector) GetSnapshot() Snapshot {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	now := time.Now()
	active := 0
	if c.activeFlowsFn != nil {
		active = c.activeFlowsFn()
	}

	return Snapshot{
		Timestamp:             now.Unix(),
		UptimeSec:             int64(now.Sub(c.startTime).Seconds()),
		PacketsCaptured:       atomic.LoadUint64(&c.packetsCaptured),
		BytesCaptured:         atomic.LoadUint64(&c.bytesCaptured),
		PacketsDropped:        atomic.LoadUint64(&c.packetsDropped),
		ActiveFlows:           active,
		ExportedFlows:         atomic.LoadUint64(&c.exportedFlows),
		ExportErrors:          atomic.LoadUint64(&c.exportErrors),
		FlowsDroppedTableFull: atomic.LoadUint64(&c.flowsDroppedTableFull),
		TCPHandshakes:         atomic.LoadUint64(&c.tcpHandshakes),
		OpenPortsDetected:     atomic.LoadUint64(&c.openPortsDetected),
		TLSClientHellos:       atomic.LoadUint64(&c.tlsClientHellos),
		DNSQueriesDetected:    atomic.LoadUint64(&c.dnsQueriesDetected),
		NumCPU:                runtime.NumCPU(),
		MaxProcs:              runtime.GOMAXPROCS(0),
		NumGoroutines:         runtime.NumGoroutine(),
		MemoryAllocBytes:      m.Alloc,
		MemorySysBytes:        m.Sys,
		GCNum:                 m.NumGC,
	}
}

// Server serves unix domain socket and HTTP stats for monitor integration.
type Server struct {
	socketPath string
	httpAddr   string
	collector  *Collector
	logger     *slog.Logger
	unixLn     net.Listener
	httpSrv    *http.Server
}

// NewServer creates a stats monitor server.
func NewServer(socketPath string, httpAddr string, collector *Collector, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	if collector == nil {
		collector = GlobalCollector
	}
	return &Server{
		socketPath: socketPath,
		httpAddr:   httpAddr,
		collector:  collector,
		logger:     logger,
	}
}

// Start launches unix domain socket listener and optional HTTP stats endpoint.
func (s *Server) Start(ctx context.Context) error {
	if s.socketPath != "" {
		_ = os.Remove(s.socketPath) // Clean up stale socket if present
		ln, err := net.Listen("unix", s.socketPath)
		if err != nil {
			return fmt.Errorf("failed to bind stats unix socket %s: %w", s.socketPath, err)
		}
		s.unixLn = ln
		_ = os.Chmod(s.socketPath, 0666) // Allow read access
		s.logger.Info("Stats UNIX socket server listening", "socket", s.socketPath)

		go s.serveUnix(ctx)
	}

	if s.httpAddr != "" {
		mux := http.NewServeMux()
		mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(s.collector.GetSnapshot())
		})
		mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		})

		s.httpSrv = &http.Server{
			Addr:    s.httpAddr,
			Handler: mux,
		}
		s.logger.Info("Stats HTTP server listening", "addr", s.httpAddr)

		go func() {
			if err := s.httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				s.logger.Error("Stats HTTP server error", "err", err)
			}
		}()
	}

	return nil
}

func (s *Server) serveUnix(ctx context.Context) {
	for {
		conn, err := s.unixLn.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				continue
			}
		}

		go func(c net.Conn) {
			defer c.Close()
			snap := s.collector.GetSnapshot()
			data, _ := json.Marshal(snap)
			data = append(data, '\n')
			_, _ = c.Write(data)
		}(conn)
	}
}

// Close terminates unix and HTTP listeners.
func (s *Server) Close() {
	if s.unixLn != nil {
		_ = s.unixLn.Close()
		if s.socketPath != "" {
			_ = os.Remove(s.socketPath)
		}
	}
	if s.httpSrv != nil {
		_ = s.httpSrv.Close()
	}
}
