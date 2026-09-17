package exporter

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/redborder/redborder-flow-agent/internal/flow"
)

// StdoutExporter prints formatted JSON flow records directly to standard output.
type StdoutExporter struct{}

// NewStdoutExporter creates a new stdout flow exporter.
func NewStdoutExporter() (*StdoutExporter, error) {
	return &StdoutExporter{}, nil
}

// Start listens for expired flow records and writes JSON lines to stdout.
func (e *StdoutExporter) Start(ctx context.Context, inChan <-chan *flow.Record) error {
	encoder := json.NewEncoder(os.Stdout)

	for {
		select {
		case <-ctx.Done():
			return nil
		case rec, ok := <-inChan:
			if !ok {
				return nil
			}
			jsonRec := formatJSONRecord(rec)
			if err := encoder.Encode(jsonRec); err != nil {
				fmt.Fprintf(os.Stderr, "Error encoding flow to stdout: %v\n", err)
			}
		}
	}
}

// Close is a no-op for stdout.
func (e *StdoutExporter) Close() error {
	return nil
}
