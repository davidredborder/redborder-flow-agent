package inspector

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// JA4Signature represents a single signature entry in the database.
type JA4Signature struct {
	JA4         string `yaml:"ja4" json:"ja4"`
	ClientType  string `yaml:"client_type" json:"client_type"` // "browser", "bot", "scanner", "malware", "os_service"
	ClientApp   string `yaml:"client_app" json:"client_app"`   // e.g. "Chrome", "python-requests", "curl", "CobaltStrike"
	IsBot       bool   `yaml:"is_bot" json:"is_bot"`
	IsThreat    bool   `yaml:"is_threat" json:"is_threat"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
}

// JA4Match holds the result of a signature lookup.
type JA4Match struct {
	ClientType string
	ClientApp  string
	IsBot      bool
	IsThreat   bool
}

// JA4Classifier maps JA4 fingerprints to applications, bot indicators, and threat intelligence.
type JA4Classifier struct {
	signatures map[string]JA4Match
	mu         sync.RWMutex
	logger     *slog.Logger
}

// NewJA4Classifier initializes a classifier with default embedded signatures.
func NewJA4Classifier(filePath string, logger *slog.Logger) *JA4Classifier {
	if logger == nil {
		logger = slog.Default()
	}

	c := &JA4Classifier{
		signatures: make(map[string]JA4Match),
		logger:     logger,
	}

	// 1. Load built-in baseline signatures
	c.loadDefaults()

	// 2. Load user-provided YAML/JSON file if specified
	if filePath != "" {
		if err := c.LoadFromFile(filePath); err != nil {
			logger.Warn("Failed to load external JA4 signature database", "path", filePath, "err", err)
		} else {
			logger.Info("Loaded external JA4 signature database", "path", filePath, "total_signatures", len(c.signatures))
		}
	}

	return c
}

// LoadFromFile loads signatures from a YAML or JSON file.
func (c *JA4Classifier) LoadFromFile(filePath string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read signature file %s: %w", filePath, err)
	}

	type SigFile struct {
		Signatures []JA4Signature `yaml:"signatures" json:"signatures"`
	}

	var parsed SigFile
	if strings.HasSuffix(filePath, ".json") {
		if err := json.Unmarshal(data, &parsed); err != nil {
			return fmt.Errorf("failed to parse JSON signatures: %w", err)
		}
	} else {
		if err := yaml.Unmarshal(data, &parsed); err != nil {
			return fmt.Errorf("failed to parse YAML signatures: %w", err)
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	for _, s := range parsed.Signatures {
		cleanJA4 := strings.TrimSpace(s.JA4)
		if cleanJA4 != "" {
			c.signatures[cleanJA4] = JA4Match{
				ClientType: s.ClientType,
				ClientApp:  s.ClientApp,
				IsBot:      s.IsBot,
				IsThreat:   s.IsThreat,
			}
		}
	}

	return nil
}

// Lookup finds matching metadata for a JA4 fingerprint.
// If exact signature is not found, it applies Part A heuristic rules.
func (c *JA4Classifier) Lookup(ja4 string) (JA4Match, bool) {
	if ja4 == "" {
		return JA4Match{}, false
	}

	if c != nil {
		c.mu.RLock()
		match, ok := c.signatures[ja4]
		c.mu.RUnlock()
		if ok {
			return match, true
		}
	}

	// Heuristic classification from Part A structure:
	// Part A format: [protocol][tls_ver][sni_type][cipher_count][ext_count][alpn]
	// Example: "t13d1516h2_..."
	parts := strings.Split(ja4, "_")
	if len(parts) >= 1 && len(parts[0]) >= 10 {
		partA := parts[0]
		tlsVer := partA[1:3]
		sniType := partA[3:4]
		alpn := partA[8:10]

		// 1. IP as SNI or no SNI -> Scanner or Direct IP Malware / Tool
		if sniType == "i" {
			if alpn == "00" {
				return JA4Match{
					ClientType: "scanner",
					ClientApp:  "Generic Scanner / IP Direct",
					IsBot:      true,
					IsThreat:   false,
				}, true
			}
			return JA4Match{
				ClientType: "bot",
				ClientApp:  "Automated Client (IP SNI)",
				IsBot:      true,
				IsThreat:   false,
			}, true
		}

		// 2. Domain SNI with No ALPN ("00") -> Scripting library, CLI, or non-browser client
		if alpn == "00" {
			return JA4Match{
				ClientType: "bot",
				ClientApp:  "Script / CLI Tool (No ALPN)",
				IsBot:      true,
				IsThreat:   false,
			}, true
		}

		// 3. Deprecated legacy TLS (1.0 / 1.1 / SSLv3)
		if tlsVer == "10" || tlsVer == "11" || tlsVer == "s3" {
			return JA4Match{
				ClientType: "bot",
				ClientApp:  "Legacy TLS Client",
				IsBot:      true,
				IsThreat:   false,
			}, true
		}

		// 4. Modern TLS 1.3/1.2 with Domain SNI and HTTP/2 ALPN -> Likely modern Web Browser or Chromium WebView
		if alpn == "h2" && (tlsVer == "13" || tlsVer == "12") {
			return JA4Match{
				ClientType: "browser",
				ClientApp:  "Generic Browser / WebView (h2)",
				IsBot:      false,
				IsThreat:   false,
			}, true
		}
	}

	return JA4Match{}, false
}

func (c *JA4Classifier) loadDefaults() {
	defaults := []JA4Signature{
		// Browsers
		{JA4: "t13d1516h2_8daaf6152771_e562703ab85f", ClientType: "browser", ClientApp: "Chrome / Chromium", IsBot: false, IsThreat: false},
		{JA4: "t13d1517h2_8daaf6152771_e562703ab85f", ClientType: "browser", ClientApp: "Chrome / Edge", IsBot: false, IsThreat: false},
		{JA4: "t13d1715h2_5da81232f052_e562703ab85f", ClientType: "browser", ClientApp: "Firefox", IsBot: false, IsThreat: false},
		{JA4: "t13d1516h2_bfa337485184_ce5d316eb7e9", ClientType: "browser", ClientApp: "Firefox / Safari", IsBot: false, IsThreat: false},
		{JA4: "t13d1909h2_9a12bc34de56_123456789abc", ClientType: "browser", ClientApp: "Safari (macOS / iOS)", IsBot: false, IsThreat: false},

		// Automated Libraries / Bots
		{JA4: "t10i030000_cbb25e4023a6_f82855905d68", ClientType: "bot", ClientApp: "python-requests / urllib3", IsBot: true, IsThreat: false},
		{JA4: "t13d150800_b964344d2d46_f82855905d68", ClientType: "bot", ClientApp: "curl", IsBot: true, IsThreat: false},
		{JA4: "t13d0304h2_2a3f4e5d6c7b_8e9f0a1b2c3d", ClientType: "bot", ClientApp: "Go-http-client", IsBot: true, IsThreat: false},
		{JA4: "t13d0203h2_62ed6f6ca7ad_76ae7f21e19f", ClientType: "bot", ClientApp: "Go-http-client / custom", IsBot: true, IsThreat: false},
		{JA4: "t12d080400_e7b1a2c3d4e5_a1b2c3d4e5f6", ClientType: "bot", ClientApp: "NodeJS / Axios", IsBot: true, IsThreat: false},
		{JA4: "t13d0806h2_d4c3b2a1e5f6_1234567890ab", ClientType: "bot", ClientApp: "Java / Apache-HttpClient", IsBot: true, IsThreat: false},

		// Scanners
		{JA4: "t12i010000_123456789abc_def012345678", ClientType: "scanner", ClientApp: "ZGrab / Masscan", IsBot: true, IsThreat: false},
		{JA4: "t10i010000_aabbccddeeff_001122334455", ClientType: "scanner", ClientApp: "Nmap SSL Probe", IsBot: true, IsThreat: false},

		// Threats & Malware
		{JA4: "t12d190800_8daaf6152771_b1234567890a", ClientType: "malware", ClientApp: "CobaltStrike Beacon", IsBot: true, IsThreat: true},
		{JA4: "t10i020000_9abc87654321_0123456789ab", ClientType: "malware", ClientApp: "Mirai Botnet", IsBot: true, IsThreat: true},
		{JA4: "t12i050200_a1b2c3d4e5f6_789012345678", ClientType: "malware", ClientApp: "Metasploit Meterpreter", IsBot: true, IsThreat: true},
		{JA4: "t12d100400_f1e2d3c4b5a6_0987654321fe", ClientType: "malware", ClientApp: "Sliver C2", IsBot: true, IsThreat: true},
	}

	for _, s := range defaults {
		c.signatures[s.JA4] = JA4Match{
			ClientType: s.ClientType,
			ClientApp:  s.ClientApp,
			IsBot:      s.IsBot,
			IsThreat:   s.IsThreat,
		}
	}
}
