package telemetry

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	telemetrypb "github.com/aether-x/control-plane/api/gen/go/aether/telemetry/v1"
)

// fakeSink records inserted batches; optionally fails N times before succeeding.
type fakeSink struct {
	mu        sync.Mutex
	batches   [][]chRow
	inserted  int64
	failFirst int
	calls     int
	notify    chan struct{}
}

func newFakeSink() *fakeSink {
	return &fakeSink{notify: make(chan struct{}, 64)}
}

func (f *fakeSink) Insert(_ context.Context, rows []chRow) error {
	f.mu.Lock()
	f.calls++
	if f.failFirst > 0 {
		f.failFirst--
		f.mu.Unlock()
		return errors.New("boom")
	}
	f.batches = append(f.batches, rows)
	f.mu.Unlock()
	atomic.AddInt64(&f.inserted, int64(len(rows)))
	select {
	case f.notify <- struct{}{}:
	default:
	}
	return nil
}

type alwaysFailSink struct{}

func (alwaysFailSink) Insert(context.Context, []chRow) error { return errors.New("down") }

func sampleEvent(id string) Event {
	return Event{
		NodeID:     id,
		InstanceID: "inst",
		ProtocolID: "reality-vision",
		ISP:        telemetrypb.IspId_ISP_ID_MCI,
		Kind:       telemetrypb.EventKind_EVENT_CONNECT_SUCCESS,
		TS:         time.UnixMilli(1000),
		Success:    true,
		RTTms:      42,
	}
}

func newTestWriter(t *testing.T, sink chSink, spool *DiskSpool, flushSize int, interval time.Duration) *ClickHouseWriter {
	t.Helper()
	return NewClickHouseWriter(sink, spool, ClickHouseWriterOptions{
		FlushSize:     flushSize,
		FlushInterval: interval,
		BufferCap:     8192,
	}, nil)
}

func TestBatchingFlushesBySize(t *testing.T) {
	sink := newFakeSink()
	w := newTestWriter(t, sink, nil, 3, 5*time.Second)
	defer w.Close()

	if err := w.WriteBatch(context.Background(), []Event{
		sampleEvent("a"), sampleEvent("b"), sampleEvent("c"),
	}); err != nil {
		t.Fatalf("WriteBatch: %v", err)
	}
	<-sink.notify

	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.batches) != 1 || len(sink.batches[0]) != 3 {
		t.Fatalf("expected 1 batch of 3, got %+v", sink.batches)
	}
}

func TestBatchingFlushesByInterval(t *testing.T) {
	sink := newFakeSink()
	w := newTestWriter(t, sink, nil, 1000, 30*time.Millisecond)
	defer w.Close()

	if err := w.WriteBatch(context.Background(), []Event{sampleEvent("x"), sampleEvent("y")}); err != nil {
		t.Fatalf("WriteBatch: %v", err)
	}
	<-sink.notify
	if got := atomic.LoadInt64(&sink.inserted); got != 2 {
		t.Fatalf("expected 2 inserted, got %d", got)
	}
}

func TestRetryThenSucceeds(t *testing.T) {
	sink := newFakeSink()
	sink.failFirst = 2
	w := newTestWriter(t, sink, nil, 1, 5*time.Second)
	defer w.Close()

	if err := w.WriteBatch(context.Background(), []Event{sampleEvent("z")}); err != nil {
		t.Fatalf("WriteBatch: %v", err)
	}
	<-sink.notify
	if got := atomic.LoadInt64(&sink.inserted); got != 1 {
		t.Fatalf("expected 1 inserted after retries, got %d", got)
	}
}

func TestPersistentFailureSpoolsToDisk(t *testing.T) {
	dir := t.TempDir()
	spoolPath := filepath.Join(dir, "spool.jsonl")
	spool, err := NewDiskSpool(spoolPath)
	if err != nil {
		t.Fatalf("spool: %v", err)
	}
	w := newTestWriter(t, &alwaysFailSink{}, spool, 1, 5*time.Second)
	defer w.Close()

	if err := w.WriteBatch(context.Background(), []Event{sampleEvent("p")}); err != nil {
		t.Fatalf("WriteBatch: %v", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if info, e := os.Stat(spoolPath); e == nil && info.Size() > 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("expected spooled rows after persistent failure")
}

func TestDiskSpoolRoundTrip(t *testing.T) {
	dir := t.TempDir()
	spool, err := NewDiskSpool(filepath.Join(dir, "s.jsonl"))
	if err != nil {
		t.Fatalf("spool: %v", err)
	}
	rows := []chRow{
		{IspID: "MCI", Protocol: "x"},
		{IspID: "Irancell", Protocol: "y"},
	}
	spool.Append(rows)
	got := spool.DrainAll()
	if len(got) != 2 || got[0].IspID != "MCI" || got[1].IspID != "Irancell" {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
	if len(spool.DrainAll()) != 0 {
		t.Fatalf("spool not cleared after drain")
	}
}

type recordingExecer struct {
	query string
	calls int
}

func (r *recordingExecer) Exec(_ context.Context, q string) error {
	r.query = q
	r.calls++
	return nil
}

func TestEnsureSchemaRunsDDLAndMigrations(t *testing.T) {
	ex := &recordingExecer{}
	if err := EnsureSchema(context.Background(), ex); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}
	wantCalls := 1 + len(SchemaMigrations)
	if ex.query == "" || ex.calls != wantCalls {
		t.Fatalf("expected %d DDL calls, got calls=%d", wantCalls, ex.calls)
	}
}

func TestEventToRowMapping(t *testing.T) {
	ev := sampleEvent("node-1")
	ev.Kind = telemetrypb.EventKind_EVENT_TCP_RST_INJECTED
	ev.Success = false
	ev.RTTms = 200
	ev.Throughput = 12_345
	row := eventToRow(ev)
	if row.IspID != "MCI" || row.Protocol != "reality-vision" || row.NodeID != "node-1" {
		t.Fatalf("mapping wrong: %+v", row)
	}
	if row.RstCount != 1 || row.LossRate != 1 || row.LatencyMs != 200 || row.ThroughputBps != 12_345 {
		t.Fatalf("derived fields wrong: %+v", row)
	}
}

func TestClickHouseWriterCloseIsIdempotent(t *testing.T) {
	sink := newFakeSink()
	writer := newTestWriter(t, sink, nil, 100, time.Hour)
	writer.Close()
	writer.Close()
}

func TestThroughputNoRace(t *testing.T) {
	sink := newFakeSink()
	w := newTestWriter(t, sink, nil, 100, 10*time.Millisecond)
	defer w.Close()

	const goroutines = 8
	const perG = 200
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			batch := make([]Event, perG)
			for i := range batch {
				batch[i] = sampleEvent("n")
			}
			_ = w.WriteBatch(context.Background(), batch)
		}()
	}
	wg.Wait()

	total := int64(goroutines * perG)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt64(&sink.inserted) >= total {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("throughput: inserted %d < %d", atomic.LoadInt64(&sink.inserted), total)
}
