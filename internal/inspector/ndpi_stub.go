//go:build !ndpi

package inspector

// NDPIStatus returns runtime compilation status and supported versions for nDPI.
func NDPIStatus() (enabled bool, details string) {
	return false, "Disabled (Pure-Go build, native HTTP/TLS/DNS inspection)"
}

// NewNDPIClassifier returns a pure-Go heuristic fallback when nDPI is not linked.
func NewNDPIClassifier() (NDPIClassifier, error) {
	return &stubNDPI{}, nil
}

type stubNDPI struct{}

func (s *stubNDPI) ProcessPacket(data []byte, ts int64) (string, uint16, string) {
	return "", 0, ""
}

func (s *stubNDPI) AllocFlow() NDPIFlow {
	return nil
}

func (s *stubNDPI) ProcessFlowPacket(flow NDPIFlow, ipData []byte, ts int64) (string, uint16, string) {
	return "", 0, ""
}

func (s *stubNDPI) FreeFlow(flow NDPIFlow) {}

func (s *stubNDPI) Close() {}

