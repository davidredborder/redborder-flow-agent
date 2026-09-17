package inspector

import (
	"os"
	"path/filepath"
	"testing"
)

func TestJA4Classifier(t *testing.T) {
	// 1. Test Default Signatures
	classifier := NewJA4Classifier("", nil)
	
	match, ok := classifier.Lookup("t13d1516h2_8daaf6152771_e562703ab85f")
	if !ok || match.ClientType != "browser" || match.IsBot {
		t.Fatalf("expected Chrome browser match, got %+v (ok=%v)", match, ok)
	}

	match, ok = classifier.Lookup("t10i030000_cbb25e4023a6_f82855905d68")
	if !ok || match.ClientType != "bot" || !match.IsBot || match.IsThreat {
		t.Fatalf("expected python bot match, got %+v (ok=%v)", match, ok)
	}

	match, ok = classifier.Lookup("t12d190800_8daaf6152771_b1234567890a")
	if !ok || match.ClientType != "malware" || !match.IsThreat || !match.IsBot {
		t.Fatalf("expected CobaltStrike malware match, got %+v (ok=%v)", match, ok)
	}

	// 2. Test External YAML file loading
	tmpDir := t.TempDir()
	yamlPath := filepath.Join(tmpDir, "signatures.yaml")
	yamlContent := `
signatures:
  - ja4: "t13d9999h2_abcdef123456_abcdef123456"
    client_type: "bot"
    client_app: "CustomScanner"
    is_bot: true
    is_threat: false
`
	if err := os.WriteFile(yamlPath, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("failed to write temp yaml: %v", err)
	}

	customClassifier := NewJA4Classifier(yamlPath, nil)
	match, ok = customClassifier.Lookup("t13d9999h2_abcdef123456_abcdef123456")
	if !ok || match.ClientApp != "CustomScanner" || !match.IsBot {
		t.Fatalf("expected CustomScanner match from YAML, got %+v (ok=%v)", match, ok)
	}

	// 3. Test Part A Heuristic Fallback (Unseen signatures)
	// Unseen Scanner without SNI or ALPN
	match, ok = classifier.Lookup("t12i010000_999999999999_888888888888")
	if !ok || match.ClientType != "scanner" || !match.IsBot {
		t.Fatalf("expected heuristic scanner match, got %+v", match)
	}

	// Unseen script without ALPN
	match, ok = classifier.Lookup("t13d080800_111111111111_222222222222")
	if !ok || match.ClientType != "bot" || !match.IsBot {
		t.Fatalf("expected heuristic bot match, got %+v", match)
	}
}
