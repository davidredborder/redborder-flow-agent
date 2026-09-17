package exporter

import (
	"context"
	"fmt"

	"github.com/redborder/redborder-flow-agent/internal/config"
	"github.com/redborder/redborder-flow-agent/internal/flow"
)

// Exporter represents a flow exporting backend.
type Exporter interface {
	Start(ctx context.Context, inChan <-chan *flow.Record) error
	Close() error
}

// NewExporter creates the configured flow exporter.
func NewExporter(cfg *config.Config) (Exporter, error) {
	switch cfg.Exporter.Type {
	case "netflow5":
		return NewNetFlowV5Exporter(&cfg.Exporter)
	case "netflow9":
		return NewNetFlowV9Exporter(&cfg.Exporter)
	case "ipfix":
		return NewIPFIXExporter(&cfg.Exporter)
	case "sflow":
		return NewSFlowExporter(&cfg.Exporter)
	case "kafka":
		return NewKafkaExporter(&cfg.Kafka)
	case "stdout":
		return NewStdoutExporter()
	default:
		return nil, fmt.Errorf("unsupported exporter type: %s", cfg.Exporter.Type)
	}
}
