package telemetry

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/google/uuid"

	telemetrypb "github.com/aether-x/control-plane/api/gen/go/aether/telemetry/v1"
	"github.com/aether-x/control-plane/internal/metrics"
)

// SchemaDDL creates the optimized, partitioned telemetry table. Partition by
// month, primary/sort key (isp, protocol, time) for the per-(ISP, protocol)
// queries the AI feature store runs.
const SchemaDDL = `
CREATE TABLE IF NOT EXISTS telemetry_events (
    event_time                    DateTime64(3, 'UTC'),
    node_id                       LowCardinality(String),
    instance_id                   String,
    isp_id                        LowCardinality(String),
    client_id                     UUID,
    protocol                      LowCardinality(String),
    latency_ms                    UInt16,
    packet_loss_rate              Float32,
    rst_injection_count           UInt16,
    throughput_bps                Float64,
    applied_fragmentation_pattern String
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(event_time)
ORDER BY (isp_id, node_id, protocol, event_time)
INDEX idx_time event_time TYPE minmax GRANULARITY 1;
`

// SchemaMigrations upgrades installations created before per-node scoring was
// available. Every statement is idempotent so it is safe at each startup.
var SchemaMigrations = []string{
    `ALTER TABLE telemetry_events ADD COLUMN IF NOT EXISTS node_id LowCardinality(String) DEFAULT ''`,
    `ALTER TABLE telemetry_events ADD COLUMN IF NOT EXISTS instance_id String DEFAULT ''`,
    `ALTER TABLE telemetry_events ADD COLUMN IF NOT EXISTS throughput_bps Float64 DEFAULT 0`,
}

const insertSQL = `INSERT INTO telemetry_events (
	event_time, node_id, instance_id, isp_id, client_id, protocol, latency_ms,
	packet_loss_rate, rst_injection_count, throughput_bps, applied_fragmentation_pattern
)`

// chRow is the columnar row mapped from a telemetry Event.
type chRow struct {
	EventTime     time.Time `json:"event_time"`
	NodeID        string    `json:"node_id"`
	InstanceID    string    `json:"instance_id"`
	IspID         string    `json:"isp_id"`
	ClientID      uuid.UUID `json:"client_id"`
	Protocol      string    `json:"protocol"`
	LatencyMs     uint16    `json:"latency_ms"`
	LossRate      float32   `json:"packet_loss_rate"`
	RstCount      uint16    `json:"rst_injection_count"`
	ThroughputBps float64   `json:"throughput_bps"`
	Fragmentation string    `json:"applied_fragmentation_pattern"`
}

// chSink is the persistence seam: tests use a fake; production uses the real
// clickhouse-go native connection.
type chSink interface {
	Insert(ctx context.Context, rows []chRow) error
}

// SchemaExecer runs DDL (the real clickhouse conn satisfies it).
type SchemaExecer interface {
	Exec(ctx context.Context, query string) error
}

// EnsureSchema applies the telemetry schema idempotently.
func EnsureSchema(ctx context.Context, e SchemaExecer) error {
	if e == nil {
		return errors.New("nil schema execer")
	}
	if err := e.Exec(ctx, SchemaDDL); err != nil {
		return err
	}
	for _, migration := range SchemaMigrations {
		if err := e.Exec(ctx, migration); err != nil {
			return err
		}
	}
	return nil
}

// eventToRow maps a telemetry.Event into the columnar schema.
func eventToRow(ev Event) chRow {
	rst := uint16(0)
	if ev.Kind == telemetrypb.EventKind_EVENT_TCP_RST_INJECTED {
		rst = 1
	}
	loss := float32(0)
	if !ev.Success {
		loss = 1
	}
	latency := int(ev.RTTms)
	if latency < 0 {
		latency = 0
	}
	return chRow{
		EventTime:     ev.TS,
		NodeID:        ev.NodeID,
		InstanceID:    ev.InstanceID,
		IspID:         ispName(ev.ISP),
		ClientID:      uuid.NewSHA1(uuid.NameSpaceDNS, []byte(ev.NodeID)),
		Protocol:      ev.ProtocolID,
		LatencyMs:     uint16(latency),
		LossRate:      loss,
		RstCount:      rst,
		ThroughputBps: ev.Throughput,
		Fragmentation: "",
	}
}

func ispName(isp telemetrypb.IspId) string {
	switch isp {
	case telemetrypb.IspId_ISP_ID_MCI:
		return "MCI"
	case telemetrypb.IspId_ISP_ID_IRANCELL:
		return "Irancell"
	case telemetrypb.IspId_ISP_ID_RIGHTEL:
		return "Rightel"
	case telemetrypb.IspId_ISP_ID_SHATEL:
		return "Shatel"
	case telemetrypb.IspId_ISP_ID_TCI:
		return "TCI"
	case telemetrypb.IspId_ISP_ID_ASIATECH:
		return "Asiatech"
	case telemetrypb.IspId_ISP_ID_RESALAT:
		return "Resalat"
	default:
		return "Other"
	}
}

// ---- real clickhouse-go sink ------------------------------------------------

type realSink struct {
	conn clickhouse.Conn
}

// NewClickHouseSink opens a native-protocol connection from a ClickHouse DSN.
func NewClickHouseSink(_ context.Context, dsn string) (*realSink, error) {
	opts, err := clickhouse.ParseDSN(dsn)
	if err != nil {
		return nil, err
	}
	opts.MaxOpenConns = 8
	opts.MaxIdleConns = 4
	opts.DialTimeout = 3 * time.Second
	conn, err := clickhouse.Open(opts)
	if err != nil {
		return nil, err
	}
	return &realSink{conn: conn}, nil
}

func (s *realSink) Insert(ctx context.Context, rows []chRow) error {
	if len(rows) == 0 {
		return nil
	}
	batch, err := s.conn.PrepareBatch(ctx, insertSQL)
	if err != nil {
		return err
	}
	for _, r := range rows {
		if err := batch.Append(
			r.EventTime,
			r.NodeID,
			r.InstanceID,
			r.IspID,
			r.ClientID,
			r.Protocol,
			r.LatencyMs,
			r.LossRate,
			r.RstCount,
			r.ThroughputBps,
			r.Fragmentation,
		); err != nil {
			return err
		}
	}
	return batch.Send()
}

func (s *realSink) Exec(ctx context.Context, query string) error {
	return s.conn.Exec(ctx, query)
}

func (s *realSink) Ping(ctx context.Context) error {
	return s.conn.Ping(ctx)
}

func (s *realSink) Close() error { return s.conn.Close() }

// ---- disk spool (fallback on connection drop) ------------------------------

// DiskSpool durably buffers failed batches as JSON lines so no telemetry is
// lost during a ClickHouse outage; it is drained (replayed) on reconnect.
type DiskSpool struct {
	path string
	mu   sync.Mutex
}

// NewDiskSpool creates (or opens) a spool file at path.
func NewDiskSpool(path string) (*DiskSpool, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	return &DiskSpool{path: path}, nil
}

// Append writes rows to the spool (best-effort: logs on FS failure).
func (d *DiskSpool) Append(rows []chRow) {
	if len(rows) == 0 {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	f, err := os.OpenFile(d.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, r := range rows {
		_ = enc.Encode(r)
	}
}

// DrainAll reads and clears the spool.
func (d *DiskSpool) DrainAll() []chRow {
	d.mu.Lock()
	defer d.mu.Unlock()
	data, err := os.ReadFile(d.path)
	if err != nil {
		return nil
	}
	var rows []chRow
	for _, line := range splitLines(data) {
		if len(line) == 0 {
			continue
		}
		var r chRow
		if json.Unmarshal(line, &r) == nil {
			rows = append(rows, r)
		}
	}
	_ = os.Truncate(d.path, 0)
	return rows
}

func splitLines(b []byte) [][]byte {
	var out [][]byte
	start := 0
	for i, c := range b {
		if c == '\n' {
			out = append(out, b[start:i])
			start = i + 1
		}
	}
	if start < len(b) {
		out = append(out, b[start:])
	}
	return out
}

// ---- batching writer --------------------------------------------------------

// ClickHouseWriter is a telemetry.Writer that batches events and persists them
// to ClickHouse via a background flusher, with exponential-backoff retry and a
// disk-spool fallback. It is safe for concurrent use (WriteBatch from the
// MultiWriter goroutine; flusher is a single background goroutine).
type ClickHouseWriter struct {
	sink      chSink
	spool     *DiskSpool
	incoming  chan Event
	flushSize int
	interval  time.Duration
	toRow     func(Event) chRow
	log       *slog.Logger
	inserted  atomic.Int64
	stop      chan struct{}
	done      chan struct{}
	closeOnce sync.Once
}

// ClickHouseWriterOptions configures the writer.
type ClickHouseWriterOptions struct {
	FlushSize     int
	FlushInterval time.Duration
	BufferCap     int
}

// DefaultClickHouseOptions matches the spec (5k events / 1000ms).
func DefaultClickHouseOptions() ClickHouseWriterOptions {
	return ClickHouseWriterOptions{
		FlushSize:     5000,
		FlushInterval: 1000 * time.Millisecond,
		BufferCap:     20000,
	}
}

// NewClickHouseWriter constructs and starts the writer. `spool` may be nil to
// disable disk fallback (e.g. in tests).
func NewClickHouseWriter(sink chSink, spool *DiskSpool, opts ClickHouseWriterOptions, log *slog.Logger) *ClickHouseWriter {
	if opts.FlushSize <= 0 {
		opts.FlushSize = 5000
	}
	if opts.FlushInterval <= 0 {
		opts.FlushInterval = 1000 * time.Millisecond
	}
	if opts.BufferCap <= 0 {
		opts.BufferCap = opts.FlushSize * 4
	}
	if log == nil {
		log = slog.Default()
	}
	w := &ClickHouseWriter{
		sink:      sink,
		spool:     spool,
		incoming:  make(chan Event, opts.BufferCap),
		flushSize: opts.FlushSize,
		interval:  opts.FlushInterval,
		toRow:     eventToRow,
		log:       log,
		stop:      make(chan struct{}),
		done:      make(chan struct{}),
	}
	go w.run()
	return w
}

// WriteBatch implements telemetry.Writer. It enqueues events (non-blocking); a
// full buffer overflows to the disk spool rather than blocking the hot path.
func (w *ClickHouseWriter) WriteBatch(_ context.Context, events []Event) error {
	for _, ev := range events {
		select {
		case w.incoming <- ev:
		default:
			if w.spool != nil {
				w.spool.Append([]chRow{w.toRow(ev)})
			}
		}
	}
	return nil
}

// Inserted returns the total number of rows successfully persisted (for tests).
func (w *ClickHouseWriter) Inserted() int64 { return w.inserted.Load() }

// Close drains remaining events and stops the flusher. It is safe to call
// repeatedly from independent shutdown paths.
func (w *ClickHouseWriter) Close() {
	w.closeOnce.Do(func() {
		close(w.stop)
		<-w.done
	})
}

func (w *ClickHouseWriter) run() {
	defer close(w.done)
	buf := make([]Event, 0, w.flushSize)
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	flush := func() {
		if len(buf) == 0 {
			return
		}
		rows := make([]chRow, len(buf))
		for i, ev := range buf {
			rows[i] = w.toRow(ev)
		}
		buf = buf[:0]
		w.persist(rows)
	}

	for {
		select {
		case ev := <-w.incoming:
			buf = append(buf, ev)
			if len(buf) >= w.flushSize {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-w.stop:
			// drain the channel (non-blocking) then flush the remainder.
			drained := true
			for drained {
				select {
				case ev := <-w.incoming:
					buf = append(buf, ev)
				default:
					drained = false
				}
			}
			flush()
			return
		}
	}
}

// persist inserts rows with exponential backoff; on persistent failure it
// spools to disk; on success it best-effort replays the spool.
func (w *ClickHouseWriter) persist(rows []chRow) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := time.Now()
	if err := withBackoff(ctx, func() error { return w.sink.Insert(ctx, rows) }); err != nil {
		w.log.Warn("clickhouse insert failed; spooling to disk", "err", err, "n", len(rows))
		if w.spool != nil {
			w.spool.Append(rows)
		}
		return
	}
	metrics.ClickHouseFlushLatency.Observe(time.Since(start).Seconds())
	w.inserted.Add(int64(len(rows)))
	w.replaySpool(ctx)
}

func (w *ClickHouseWriter) replaySpool(ctx context.Context) {
	if w.spool == nil {
		return
	}
	rows := w.spool.DrainAll()
	if len(rows) == 0 {
		return
	}
	if err := w.sink.Insert(ctx, rows); err != nil {
		// re-spool what we could not replay.
		w.spool.Append(rows)
		return
	}
	w.inserted.Add(int64(len(rows)))
}

// withBackoff retries fn with exponential backoff up to maxAttempts.
func withBackoff(ctx context.Context, fn func() error) error {
	const maxAttempts = 4
	var lastErr error
	delay := 100 * time.Millisecond
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if err := fn(); err != nil {
			lastErr = err
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return ctx.Err()
			}
			delay *= 2
			continue
		}
		return nil
	}
	return lastErr
}
