package config

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config holds global configuration for rb-flow-agent.
type Config struct {
	Sensor           string            `yaml:"sensor" json:"sensor"`                       // Default sensor name (e.g. "sensor1")
	SensorName       string            `yaml:"sensor_name,omitempty" json:"sensor_name"`   // Explicit sensor name alias
	SensorIP         string            `yaml:"sensor_ip,omitempty" json:"sensor_ip"`       // Sensor reporting IP address (e.g. "192.168.1.1")
	Tag              string            `yaml:"tag,omitempty" json:"tag"`                   // Primary classification tag (e.g. "production")
	Tag2             string            `yaml:"tag2,omitempty" json:"tag2"`                 // Secondary classification tag (e.g. "datacenter-1")
	HomeNets         []string          `yaml:"home_nets,omitempty" json:"home_nets"`       // Subnets explicitly treated as local/home networks (in addition to RFC 1918)
	LocalNetworks    []string          `yaml:"local_networks,omitempty" json:"local_networks,omitempty"` // Alias for home_nets
	ExtraEnrichments map[string]string `yaml:"enrichments,omitempty" json:"enrichments"`   // Arbitrary key-value metadata enrichments
	Sensors          []SensorMapping   `yaml:"sensors,omitempty" json:"sensors"`           // Subnet-based sensor split rules
	System           SystemConfig      `yaml:"system" json:"system"`
	Capture          CaptureConfig     `yaml:"capture" json:"capture"`
	Analysis         AnalysisConfig    `yaml:"analysis" json:"analysis"`
	Flow             FlowConfig        `yaml:"flow" json:"flow"`
	Exporter         ExporterConfig    `yaml:"exporter" json:"exporter"`
	Kafka            KafkaConfig       `yaml:"kafka" json:"kafka"`
	Stats            StatsConfig       `yaml:"stats" json:"stats"`
}

// SensorMapping defines subnet-based sensor assignment rules.
// If src_ip matches any subnet, this sensor is assigned; if no match, dst_ip is checked.
type SensorMapping struct {
	Name             string            `yaml:"name" json:"name"`
	SensorName       string            `yaml:"sensor_name,omitempty" json:"sensor_name"`
	SensorIP         string            `yaml:"sensor_ip,omitempty" json:"sensor_ip"`
	Subnets          []string          `yaml:"subnets" json:"subnets"`
	Tag              string            `yaml:"tag,omitempty" json:"tag"`
	Tag2             string            `yaml:"tag2,omitempty" json:"tag2"`
	ExtraEnrichments map[string]string `yaml:"enrichments,omitempty" json:"enrichments"`
}

// CaptureConfig defines network interface capture parameters.
type CaptureConfig struct {
	Interfaces          []string `yaml:"interfaces" json:"interfaces"`
	Promiscuous         bool     `yaml:"promiscuous" json:"promiscuous"`
	SnapLen             int      `yaml:"snaplen" json:"snaplen"`
	WorkersPerInterface int      `yaml:"workers_per_interface" json:"workers_per_interface"`
	BufferSizeMB        int      `yaml:"buffer_size_mb" json:"buffer_size_mb"`
	PcapFile            string   `yaml:"pcap_file,omitempty" json:"pcap_file,omitempty"`
}

// AnalysisConfig configures L4/L7 protocol and metric inspection.
type AnalysisConfig struct {
	TrackOpenPorts     bool `yaml:"track_open_ports" json:"track_open_ports"`
	TrackTCPMetrics    bool `yaml:"track_tcp_metrics" json:"track_tcp_metrics"` // RTT latency, window size
	ExtractTLSSNI      bool `yaml:"extract_tls_sni" json:"extract_tls_sni"`
	ExtractTLSVersion  bool `yaml:"extract_tls_version" json:"extract_tls_version"`
	ExtractHTTPHost    bool `yaml:"extract_http_host" json:"extract_http_host"`
	ExtractHTTPDetails bool `yaml:"extract_http_details" json:"extract_http_details"` // HTTP method, status code, user agent
	ExtractDNSDomains  bool   `yaml:"extract_dns_domains" json:"extract_dns_domains"`
	DNSCacheSize       int    `yaml:"dns_cache_size" json:"dns_cache_size"`
	JA4SignaturesFile  string `yaml:"ja4_signatures_file,omitempty" json:"ja4_signatures_file,omitempty"`
}

// FlowConfig defines flow aggregation and expiration parameters.
type FlowConfig struct {
	Mode               string `yaml:"mode" json:"mode"` // "bidirectional" (biflow) or "unidirectional" (classic netflow)
	ActiveTimeoutSec   int    `yaml:"active_timeout_sec" json:"active_timeout_sec"`
	InactiveTimeoutSec int    `yaml:"inactive_timeout_sec" json:"inactive_timeout_sec"`
	MaxActiveFlows     int    `yaml:"max_active_flows" json:"max_active_flows"`
	Shards             int    `yaml:"shards" json:"shards"`
}

// ExporterConfig configures flow protocol export (NetFlow v5, v9, IPFIX, sFlow, Kafka, stdout).
type ExporterConfig struct {
	Type                string `yaml:"type" json:"type"` // "netflow5", "netflow9", "ipfix", "sflow", "kafka", "stdout"
	Target              string `yaml:"target" json:"target"`
	Port                int    `yaml:"port" json:"port"`
	EngineID            uint8  `yaml:"engine_id" json:"engine_id"`
	EngineType          uint8  `yaml:"engine_type" json:"engine_type"`
	SourceID            uint32 `yaml:"source_id" json:"source_id"`
	TemplateIntervalSec int    `yaml:"template_interval_sec" json:"template_interval_sec"`
	SFlowSamplingRate   uint32 `yaml:"sflow_sampling_rate" json:"sflow_sampling_rate"`
	RateLimitFPS        int    `yaml:"rate_limit_fps" json:"rate_limit_fps"`
}

// KafkaConfig defines Kafka broker and topic configurations.
type KafkaConfig struct {
	Brokers        []string `yaml:"brokers" json:"brokers"`
	Topic          string   `yaml:"topic" json:"topic"`                               // Unified flow & telemetry topic
	TelemetryTopic string   `yaml:"telemetry_topic,omitempty" json:"telemetry_topic"` // Optional separate topic
	BatchSize      int      `yaml:"batch_size" json:"batch_size"`
	Compression    string   `yaml:"compression" json:"compression"`                   // "gzip", "snappy", "lz4", "zstd", "none"
}

// SystemConfig defines process-level runtime configuration.
type SystemConfig struct {
	Cores       int    `yaml:"cores,omitempty" json:"cores,omitempty"`               // Max CPU cores / GOMAXPROCS (0 = all available)
	MaxProcs    int    `yaml:"max_procs,omitempty" json:"max_procs,omitempty"`         // Alias for cores
	CPUAffinity string `yaml:"cpu_affinity,omitempty" json:"cpu_affinity,omitempty"` // Core pinning list/ranges, e.g. "0-3" or "0,2,4"
}

// StatsConfig defines runtime statistics socket & server configuration.
type StatsConfig struct {
	Enabled    bool   `yaml:"enabled" json:"enabled"`
	SocketPath string `yaml:"socket_path" json:"socket_path"` // Unix domain socket path (e.g. "/var/run/rb-flow-agent.sock")
	HTTPAddr   string `yaml:"http_addr" json:"http_addr"`     // Optional HTTP listener for stats (e.g. "127.0.0.1:9100")
}

// DefaultConfig returns safe, high-performance defaults.
func DefaultConfig() *Config {
	return &Config{
		System: SystemConfig{
			Cores: 0, // 0 defaults to all available CPU cores
		},
		Stats: StatsConfig{
			Enabled:    true,
			SocketPath: "/var/run/redborder-flow-agent.sock",
			HTTPAddr:   "",
		},
		Capture: CaptureConfig{
			Interfaces:          []string{"eth0"},
			Promiscuous:         true,
			SnapLen:             1518,
			WorkersPerInterface: 2,
			BufferSizeMB:        16,
		},
		Analysis: AnalysisConfig{
			TrackOpenPorts:     true,
			TrackTCPMetrics:    true,
			ExtractTLSSNI:      true,
			ExtractTLSVersion:  true,
			ExtractHTTPHost:    true,
			ExtractHTTPDetails: true,
			ExtractDNSDomains:  true,
			DNSCacheSize:       50000,
		},
		Flow: FlowConfig{
			Mode:               "unidirectional",
			ActiveTimeoutSec:   60,
			InactiveTimeoutSec: 15,
			MaxActiveFlows:     500000,
			Shards:             64,
		},
		Exporter: ExporterConfig{
			Type:                "stdout",
			Target:              "127.0.0.1",
			Port:                2055,
			EngineID:            1,
			EngineType:          1,
			SourceID:            1001,
			TemplateIntervalSec: 30,
			SFlowSamplingRate:   1000,
			RateLimitFPS:        0,
		},
		Kafka: KafkaConfig{
			Brokers:     []string{"127.0.0.1:9092"},
			Topic:       "rb-flows",
			BatchSize:   100,
			Compression: "snappy",
		},
	}
}

// LoadConfig loads configuration from a YAML or JSON file.
func LoadConfig(filePath string) (*Config, error) {
	cfg := DefaultConfig()
	if filePath == "" {
		return cfg, nil
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %w", filePath, err)
	}

	if strings.HasSuffix(filePath, ".json") {
		if err := json.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("failed to parse JSON config: %w", err)
		}
	} else {
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("failed to parse YAML config: %w", err)
		}
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// Validate ensures all configuration fields contain sensible values.
func (c *Config) Validate() error {
	if c.System.Cores <= 0 && c.System.MaxProcs > 0 {
		c.System.Cores = c.System.MaxProcs
	}
	if c.System.Cores < 0 {
		c.System.Cores = 0
	}
	if len(c.Capture.Interfaces) == 0 && c.Capture.PcapFile == "" {
		return fmt.Errorf("at least one interface or pcap_file must be specified")
	}
	if c.Capture.SnapLen <= 0 {
		c.Capture.SnapLen = 1518
	}
	if c.Capture.WorkersPerInterface <= 0 {
		c.Capture.WorkersPerInterface = 1
	}

	c.Flow.Mode = strings.ToLower(c.Flow.Mode)
	if c.Flow.Mode != "unidirectional" && c.Flow.Mode != "bidirectional" {
		c.Flow.Mode = "bidirectional"
	}

	if c.Flow.ActiveTimeoutSec <= 0 {
		c.Flow.ActiveTimeoutSec = 60
	}
	if c.Flow.InactiveTimeoutSec <= 0 {
		c.Flow.InactiveTimeoutSec = 15
	}
	if c.Flow.MaxActiveFlows <= 0 {
		c.Flow.MaxActiveFlows = 100000
	}
	if c.Flow.Shards <= 0 {
		c.Flow.Shards = 64
	}
	if c.Analysis.DNSCacheSize <= 0 {
		c.Analysis.DNSCacheSize = 10000
	}

	validExporters := map[string]bool{
		"netflow5": true,
		"netflow9": true,
		"ipfix":    true,
		"sflow":    true,
		"kafka":    true,
		"stdout":   true,
	}
	c.Exporter.Type = strings.ToLower(c.Exporter.Type)
	if !validExporters[c.Exporter.Type] {
		return fmt.Errorf("invalid exporter type %q (must be netflow5, netflow9, ipfix, sflow, kafka, or stdout)", c.Exporter.Type)
	}

	if c.Exporter.Type == "kafka" {
		if len(c.Kafka.Brokers) == 0 {
			return fmt.Errorf("kafka brokers list cannot be empty when exporter type is kafka")
		}
		if c.Kafka.Topic == "" {
			c.Kafka.Topic = "rb-flows"
		}
	} else if c.Exporter.Type != "stdout" {
		if c.Exporter.Target == "" {
			return fmt.Errorf("exporter target cannot be empty")
		}
		if c.Exporter.Port <= 0 || c.Exporter.Port > 65535 {
			if c.Exporter.Type == "sflow" {
				c.Exporter.Port = 6343
			} else {
				c.Exporter.Port = 2055
			}
		}
	}

	// Validate sensor mappings and names
	if c.SensorName == "" && c.Sensor != "" {
		c.SensorName = c.Sensor
	} else if c.Sensor == "" && c.SensorName != "" {
		c.Sensor = c.SensorName
	}
	if c.Sensor == "" {
		c.Sensor = "default_sensor"
		c.SensorName = "default_sensor"
	}
	if c.SensorIP != "" {
		if ip := net.ParseIP(c.SensorIP); ip == nil {
			return fmt.Errorf("invalid global sensor_ip %q", c.SensorIP)
		}
	}

	if len(c.HomeNets) == 0 && len(c.LocalNetworks) > 0 {
		c.HomeNets = c.LocalNetworks
	}

	for _, subnet := range c.HomeNets {
		if _, _, err := net.ParseCIDR(subnet); err != nil {
			if ip := net.ParseIP(subnet); ip == nil {
				return fmt.Errorf("invalid subnet/IP %q in home_nets: %w", subnet, err)
			}
		}
	}

	for _, sm := range c.Sensors {
		sName := sm.Name
		if sName == "" {
			sName = sm.SensorName
		}
		if sName == "" {
			return fmt.Errorf("sensor mapping name cannot be empty")
		}
		if sm.SensorIP != "" {
			if ip := net.ParseIP(sm.SensorIP); ip == nil {
				return fmt.Errorf("invalid sensor_ip %q for sensor %q", sm.SensorIP, sName)
			}
		}
		for _, subnet := range sm.Subnets {
			if _, _, err := net.ParseCIDR(subnet); err != nil {
				// Also check if it's a plain IP
				if ip := net.ParseIP(subnet); ip == nil {
					return fmt.Errorf("invalid subnet/IP %q for sensor %q: %w", subnet, sName, err)
				}
			}
		}
	}

	return nil
}
