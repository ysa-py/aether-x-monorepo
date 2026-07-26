// Package telemetry consumes the supervisor's StreamTelemetry gRPC stream and
// persists events to the ClickHouse feature store. It is deliberately decoupled
// from the concrete ClickHouse driver via the Writer interface so it is unit-
// testable without a database.
package telemetry

import (
	"context"
	"errors"
	"log/slog"
	"time"

	telemetrypb "github.com/aether-x/control-plane/api/gen/go/aether/telemetry/v1"
)

// Event is the minimal ingester view of a telemetry event.
type Event struct {
	NodeID     string
	InstanceID string
	ProtocolID string
	ISP        telemetrypb.IspId
	ASN        uint32
	ASNOrg     string
	Kind       telemetrypb.EventKind
	TS         time.Time
	Success    bool
	RTTms      int32
	Throughput float64
}

// Writer persists a batch of events. Implementations MUST be safe for
// concurrent use and idempotent (the same event may arrive twice on reconnect).
type Writer interface {
	WriteBatch(ctx context.Context, events []Event) error
}

// Sink is the source of telemetry batches (the gRPC stream, abstracted for tests).
type Sink interface {
	Recv() (*telemetrypb.TelemetryBatch, error)
}

// Source opens a (re)connectable telemetry sink for a node.
type Source interface {
	Open(ctx context.Context, nodeID string) (Sink, error)
}

// Ingester continuously drains a telemetry source into the feature store,
// reconnecting with backoff on stream errors.
type Ingester struct {
	source Source
	writer Writer
	nodeID string
	flush  time.Duration
	log    *slog.Logger
}

// New constructs an Ingester.
func New(source Source, writer Writer, nodeID string, flush time.Duration, log *slog.Logger) *Ingester {
	if log == nil {
		log = slog.Default()
	}
	return &Ingester{source: source, writer: writer, nodeID: nodeID, flush: flush, log: log}
}

// Run blocks until ctx is cancelled, persisting batches and reconnecting.
func (in *Ingester) Run(ctx context.Context) error {
	backoff := 500 * time.Millisecond
	const maxBackoff = 30 * time.Second
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := in.drain(ctx)
		if err == nil {
			return nil
		}
		if errors.Is(err, context.Canceled) {
			return nil
		}
		in.log.Warn("telemetry stream ended; reconnecting", "err", err, "backoff", backoff)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

// drain opens one stream and processes it until error/EOF.
func (in *Ingester) drain(ctx context.Context) error {
	sink, err := in.source.Open(ctx, in.nodeID)
	if err != nil {
		return err
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		batch, err := sink.Recv()
		if err != nil {
			return err
		}
		events := toEvents(batch.GetEvents())
		if len(events) == 0 {
			continue
		}
		if werr := in.writer.WriteBatch(ctx, events); werr != nil {
			in.log.Error("clickhouse write failed", "err", werr, "n", len(events))
			// Do not kill the stream on a single bad batch; continue draining.
		}
	}
}

func toEvents(in []*telemetrypb.TelemetryEvent) []Event {
	out := make([]Event, 0, len(in))
	for _, e := range in {
		ts := time.UnixMilli(e.GetTsUnixMillis())
		out = append(out, Event{
			NodeID:     e.GetNodeId(),
			InstanceID: e.GetInstanceId(),
			ProtocolID: e.GetProtocolId(),
			ISP:        e.GetIsp(),
			ASN:        e.GetAsn(),
			ASNOrg:     e.GetAsnOrg(),
			Kind:       e.GetEvent(),
			TS:         ts,
			Success:    e.GetSuccess(),
			RTTms:      e.GetRttMs(),
			Throughput: e.GetThroughputBps(),
		})
	}
	return out
}
