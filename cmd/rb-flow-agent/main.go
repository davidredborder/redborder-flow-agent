package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/redborder/redborder-flow-agent/internal/capture"
	"github.com/redborder/redborder-flow-agent/internal/config"
	"github.com/redborder/redborder-flow-agent/internal/exporter"
	"github.com/redborder/redborder-flow-agent/internal/flow"
	"github.com/redborder/redborder-flow-agent/internal/inspector"
	"github.com/redborder/redborder-flow-agent/internal/stats"
	"github.com/redborder/redborder-flow-agent/internal/system"
)

var version = "1.0.0"

func main() {
	configPath := flag.String("config", "", "Path to YAML/JSON configuration file")
	ifaceFlag := flag.String("iface", "", "Network interface to capture (overrides config)")
	pcapFlag := flag.String("pcap", "", "Offline PCAP file to read for testing")
	exporterFlag := flag.String("exporter", "", "Exporter type: netflow5|netflow9|ipfix|sflow|kafka|stdout")
	flowModeFlag := flag.String("mode", "", "Flow mode: unidirectional|bidirectional (default: unidirectional)")
	inactiveTimeoutFlag := flag.Int("inactive-timeout", 0, "Inactive flow timeout in seconds (default: 15s)")
	activeTimeoutFlag := flag.Int("active-timeout", 0, "Active flow timeout in seconds (default: 60s)")
	targetFlag := flag.String("target", "", "Collector IP address")
	portFlag := flag.Int("port", 0, "Collector port")
	kafkaBrokersFlag := flag.String("kafka-brokers", "", "Comma-separated Kafka brokers (e.g. localhost:9092)")
	kafkaTopicFlag := flag.String("kafka-topic", "", "Kafka topic for JSON flow stream")
	sensorFlag := flag.String("sensor", "", "Default sensor name")
	sensorNameFlag := flag.String("sensor-name", "", "Default sensor name (alias)")
	sensorIPFlag := flag.String("sensor-ip", "", "Sensor probe IP address")
	tagFlag := flag.String("tag", "", "Primary metadata tag")
	tag2Flag := flag.String("tag2", "", "Secondary metadata tag")
	coresFlag := flag.Int("cores", 0, "Number of CPU cores / GOMAXPROCS to utilize (0 = all available)")
	cpuAffinityFlag := flag.String("cpu-affinity", "", "CPU core pinning list/range (e.g. 0-3 or 0,2,4)")
	statsSocketFlag := flag.String("stats-socket", "", "Unix domain socket path for statistics (e.g. /var/run/redborder-flow-agent.sock)")
	statsHTTPFlag := flag.String("stats-http", "", "HTTP address for statistics and healthcheck (e.g. :9100)")
	statsFlag := flag.Bool("stats", false, "Query and print a live statistics snapshot from the running agent socket and exit")
	topFlag := flag.Bool("top", false, "Run an interactive top-like terminal monitor connected to the stats socket")
	ja4SignaturesFlag := flag.String("ja4-signatures", "", "Path to JA4 signatures YAML/JSON file for bot & threat detection")
	debugFlag := flag.Bool("debug", false, "Enable verbose debug logs")
	versionFlag := flag.Bool("version", false, "Print version, nDPI compilation status and exit")

	flag.Usage = func() {
		ndpiEnabled, ndpiInfo := inspector.NDPIStatus()
		fmt.Fprintf(os.Stderr, "redborder-flow-agent - High-Performance Network Flow Exporter & Probe\n")
		fmt.Fprintf(os.Stderr, "Version:        %s\n", version)
		fmt.Fprintf(os.Stderr, "nDPI Support:   %s\n", ndpiInfo)
		fmt.Fprintf(os.Stderr, "nDPI Enabled:   %v\n\n", ndpiEnabled)
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nSupported Exporter Formats (-exporter):\n")
		fmt.Fprintf(os.Stderr, "  stdout    - Print formatted JSON flow records directly to standard output\n")
		fmt.Fprintf(os.Stderr, "  kafka     - Stream enriched JSON flow records directly to Apache Kafka\n")
		fmt.Fprintf(os.Stderr, "  ipfix     - IPFIX (RFC 7011) with MAC, VLAN, open port and website IEs\n")
		fmt.Fprintf(os.Stderr, "  netflow9  - NetFlow v9 template-based export\n")
		fmt.Fprintf(os.Stderr, "  netflow5  - Standards-compliant NetFlow v5 (IPv4)\n")
		fmt.Fprintf(os.Stderr, "  sflow     - sFlow v5 sampled headers and records\n")
	}

	flag.Parse()

	if *versionFlag {
		_, ndpiInfo := inspector.NDPIStatus()
		fmt.Printf("redborder-flow-agent version %s\n", version)
		fmt.Printf("nDPI Support: %s\n", ndpiInfo)
		os.Exit(0)
	}

	// Client Mode: Interactive Top Monitor
	if *topFlag {
		sockPath := *statsSocketFlag
		if sockPath == "" {
			sockPath = "/var/run/redborder-flow-agent.sock"
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		if err := stats.RunTopConsole(ctx, sockPath); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	// Client Mode: Stats Snapshot Table
	if *statsFlag {
		sockPath := *statsSocketFlag
		if sockPath == "" {
			sockPath = "/var/run/redborder-flow-agent.sock"
		}
		snap, err := stats.QuerySocket(sockPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		stats.PrintFormattedSnapshot(snap, sockPath)
		os.Exit(0)
	}

	logLevel := slog.LevelInfo
	if *debugFlag {
		logLevel = slog.LevelDebug
	}

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	// Apply CLI overrides
	if *ifaceFlag != "" {
		cfg.Capture.Interfaces = []string{*ifaceFlag}
	}
	if *pcapFlag != "" {
		cfg.Capture.PcapFile = *pcapFlag
	}
	if *exporterFlag != "" {
		cfg.Exporter.Type = *exporterFlag
	}

	// When exporting to stdout, direct system logs to stderr to keep stdout clean for jq/JSON piping
	logOutput := os.Stdout
	if cfg.Exporter.Type == "stdout" {
		logOutput = os.Stderr
	}
	logger := slog.New(slog.NewTextHandler(logOutput, &slog.HandlerOptions{Level: logLevel}))
	slog.SetDefault(logger)

	_, ndpiInfo := inspector.NDPIStatus()
	logger.Info("Starting redborder-flow-agent", "version", version, "ndpi", ndpiInfo)
	if *flowModeFlag != "" {
		cfg.Flow.Mode = *flowModeFlag
	}
	if *inactiveTimeoutFlag > 0 {
		cfg.Flow.InactiveTimeoutSec = *inactiveTimeoutFlag
	}
	if *activeTimeoutFlag > 0 {
		cfg.Flow.ActiveTimeoutSec = *activeTimeoutFlag
	}
	if *targetFlag != "" {
		cfg.Exporter.Target = *targetFlag
	}
	if *portFlag > 0 {
		cfg.Exporter.Port = *portFlag
	}
	if *kafkaBrokersFlag != "" {
		cfg.Kafka.Brokers = []string{*kafkaBrokersFlag}
	}
	if *kafkaTopicFlag != "" {
		cfg.Kafka.Topic = *kafkaTopicFlag
	}
	if *sensorFlag != "" {
		cfg.Sensor = *sensorFlag
	}
	if *sensorNameFlag != "" {
		cfg.SensorName = *sensorNameFlag
		cfg.Sensor = *sensorNameFlag
	}
	if *sensorIPFlag != "" {
		cfg.SensorIP = *sensorIPFlag
	}
	if *tagFlag != "" {
		cfg.Tag = *tagFlag
	}
	if *tag2Flag != "" {
		cfg.Tag2 = *tag2Flag
	}
	if *coresFlag > 0 {
		cfg.System.Cores = *coresFlag
	}
	if *cpuAffinityFlag != "" {
		cfg.System.CPUAffinity = *cpuAffinityFlag
	}
	if *statsSocketFlag != "" {
		cfg.Stats.SocketPath = *statsSocketFlag
		cfg.Stats.Enabled = true
	}
	if *statsHTTPFlag != "" {
		cfg.Stats.HTTPAddr = *statsHTTPFlag
		cfg.Stats.Enabled = true
	}

	if err := cfg.Validate(); err != nil {
		logger.Error("Invalid configuration", "err", err)
		os.Exit(1)
	}

	// Apply CPU Core Affinity Pinning if configured
	if cfg.System.CPUAffinity != "" {
		pinnedCPUs, err := system.SetCPUAffinity(cfg.System.CPUAffinity)
		if err != nil {
			logger.Warn("Failed to apply CPU core affinity mask", "affinity", cfg.System.CPUAffinity, "err", err)
		} else {
			logger.Info("Configured CPU core affinity pinning", "affinity", cfg.System.CPUAffinity, "pinned_cpus", pinnedCPUs)
		}
	}

	// Apply CPU Core Count (GOMAXPROCS)
	if cfg.System.Cores > 0 {
		prevProcs := runtime.GOMAXPROCS(cfg.System.Cores)
		logger.Info("Configured CPU core limitation", "requested_cores", cfg.System.Cores, "previous_max_procs", prevProcs, "active_max_procs", runtime.GOMAXPROCS(0))
	} else {
		logger.Info("Using all available CPU cores", "max_procs", runtime.GOMAXPROCS(0), "num_cpu", runtime.NumCPU())
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 1. Initialize Sensor Matcher
	sensorMatcher := flow.NewSensorMatcher(cfg)

	// 2. Initialize DNS Cache
	dnsCache := inspector.NewDNSCache(cfg.Analysis.DNSCacheSize)

	if *ja4SignaturesFlag != "" {
		cfg.Analysis.JA4SignaturesFile = *ja4SignaturesFlag
	}

	// 3. Initialize nDPI Classifier (CGO / libndpi if compiled with -tags ndpi)
	ndpiClassifier, err := inspector.NewNDPIClassifier()
	if err != nil {
		logger.Warn("nDPI classifier not initialized, using native L7 heuristics", "err", err)
	} else {
		defer ndpiClassifier.Close()
	}

	// Initialize JA4 Signature & Bot Classifier
	ja4Classifier := inspector.NewJA4Classifier(cfg.Analysis.JA4SignaturesFile, logger)

	// Initialize Sharded Flow Table
	flowTable := flow.NewShardedFlowTable(&cfg.Flow, &cfg.Analysis, sensorMatcher, dnsCache, ndpiClassifier, ja4Classifier, 65536, logger)

	// Initialize Statistics Monitor Server (Unix Socket & HTTP)
	stats.GlobalCollector.SetActiveFlowsFunc(flowTable.ActiveFlowsCount)
	var statsServer *stats.Server
	if cfg.Stats.Enabled && (cfg.Stats.SocketPath != "" || cfg.Stats.HTTPAddr != "") {
		statsServer = stats.NewServer(cfg.Stats.SocketPath, cfg.Stats.HTTPAddr, stats.GlobalCollector, logger)
		if err := statsServer.Start(ctx); err != nil {
			logger.Warn("Failed to start statistics monitor server", "err", err)
		} else {
			defer statsServer.Close()
		}
	}

	// Initialize Exporter
	exp, err := exporter.NewExporter(cfg)
	if err != nil {
		logger.Error("Failed to initialize exporter", "err", err)
		os.Exit(1)
	}

	// Initialize Multi-Interface Capture Engine
	capEngine, err := capture.NewEngine(&cfg.Capture, 65536, logger)
	if err != nil {
		logger.Error("Failed to initialize capture engine", "err", err)
		os.Exit(1)
	}

	// Start Background Flow Cleaner & Exporter
	go flowTable.StartCleaner(ctx)
	go func() {
		if err := exp.Start(ctx, flowTable.ExportChan()); err != nil {
			logger.Error("Exporter terminated with error", "err", err)
		}
	}()

	// Ingestion loop: Forward decoded packets from Capture -> Flow Table
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case p, ok := <-capEngine.PacketChan():
				if !ok {
					return
				}
				stats.GlobalCollector.IncPacketsCaptured(1, uint64(p.CaptureLen))
				flowTable.IngestPacket(p)
			}
		}
	}()

	// Start Packet Capture Engine
	if err := capEngine.Start(ctx); err != nil {
		logger.Error("Capture engine failed", "err", err)
		os.Exit(1)
	}

	var destinationInfo string
	if cfg.Exporter.Type == "kafka" {
		destinationInfo = fmt.Sprintf("Brokers: %v, Topic: %s", cfg.Kafka.Brokers, cfg.Kafka.Topic)
	} else if cfg.Exporter.Type == "stdout" {
		destinationInfo = "stdout (JSON lines)"
	} else {
		destinationInfo = fmt.Sprintf("Target: %s:%d", cfg.Exporter.Target, cfg.Exporter.Port)
	}

	logger.Info("redborder-flow-agent initialized and running",
		"interfaces", cfg.Capture.Interfaces,
		"exporter", cfg.Exporter.Type,
		"destination", destinationInfo,
	)

	// Periodic Heartbeat / Stats Logger
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				logger.Info("Flow agent statistics", "active_flows", flowTable.ActiveFlowsCount())
			}
		}
	}()

	// Signal Handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigChan
	logger.Info("Received signal, shutting down gracefully...", "signal", sig)

	cancel()                  // 1. Cancel background routines and timers immediately
	capEngine.Close()         // 2. Close capture sockets
	flowTable.FlushAndClose() // 3. Flush remaining flows and close export channel
	time.Sleep(100 * time.Millisecond)
	exp.Close() // 4. Close exporter socket
	logger.Info("redborder-flow-agent stopped successfully")
}
