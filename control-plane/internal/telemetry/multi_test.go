package telemetry

import (
	"context"
	"errors"
	"testing"
)

type sinkWriter struct {
	count int
	err   error
}

func (s *sinkWriter) WriteBatch(_ context.Context, events []Event) error {
	s.count += len(events)
	return s.err
}

func TestMultiWriterFansOutAndIsolation(t *testing.T) {
	a := &sinkWriter{}
	b := &sinkWriter{}
	fail := &sinkWriter{err: errors.New("boom")}
	m := NewMultiWriter(a, b, fail)

	events := []Event{{NodeID: "n"}, {NodeID: "n"}}
	err := m.WriteBatch(context.Background(), events)

	if err == nil {
		t.Fatal("expected first error to surface")
	}
	if a.count != 2 || b.count != 2 {
		t.Fatalf("fan-out incomplete: a=%d b=%d", a.count, b.count)
	}
	// The failing writer must not stop the others; both a and b still got data.
}

func TestMultiWriterNoWritersIsNoop(t *testing.T) {
	m := NewMultiWriter()
	if err := m.WriteBatch(context.Background(), []Event{{}}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
