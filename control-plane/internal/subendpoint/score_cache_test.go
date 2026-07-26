package subendpoint

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/aether-x/control-plane/internal/telemetry"
)

type cacheReaderFixture struct {
	mu     sync.Mutex
	calls  int
	scores []telemetry.NodeScore
	err    error
}

func (r *cacheReaderFixture) ReadScores(context.Context, string) ([]telemetry.NodeScore, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	if r.err != nil {
		return nil, r.err
	}
	return append([]telemetry.NodeScore(nil), r.scores...), nil
}

func (r *cacheReaderFixture) Calls() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

type blockingScoreReader struct {
	started chan struct{}
	release chan struct{}
	mu      sync.Mutex
	calls   int
}

func (r *blockingScoreReader) ReadScores(ctx context.Context, _ string) ([]telemetry.NodeScore, error) {
	r.mu.Lock()
	r.calls++
	call := r.calls
	r.mu.Unlock()
	if call == 1 {
		close(r.started)
	}
	select {
	case <-r.release:
		return []telemetry.NodeScore{{NodeID: "node-1"}}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (r *blockingScoreReader) Calls() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

func TestCachingScoreReaderUsesFreshCache(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	backend := &cacheReaderFixture{scores: []telemetry.NodeScore{{NodeID: "node-1"}}}
	reader, err := NewCachingCatalogScoreReader(backend, ScoreCacheOptions{
		FreshTTL: time.Minute,
		MaxStale: 5 * time.Minute,
		Cooldown: time.Second,
		Now:      func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("new cache reader: %v", err)
	}
	first, err := reader.ReadScores(context.Background(), "MCI")
	if err != nil || len(first) != 1 {
		t.Fatalf("first read: scores=%+v err=%v", first, err)
	}
	second, err := reader.ReadScores(context.Background(), "MCI")
	if err != nil || len(second) != 1 || backend.Calls() != 1 {
		t.Fatalf("fresh cache did not suppress backend query: calls=%d scores=%+v err=%v", backend.Calls(), second, err)
	}
}

func TestCachingScoreReaderServesBoundedStaleDataDuringOutage(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	backend := &cacheReaderFixture{scores: []telemetry.NodeScore{{NodeID: "node-1"}}}
	reader, err := NewCachingCatalogScoreReader(backend, ScoreCacheOptions{
		FreshTTL: time.Second,
		MaxStale: time.Minute,
		Cooldown: 10 * time.Second,
		Now:      func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("new cache reader: %v", err)
	}
	if _, err := reader.ReadScores(context.Background(), "MCI"); err != nil {
		t.Fatalf("initial score read: %v", err)
	}
	backend.mu.Lock()
	backend.err = errors.New("clickhouse unavailable")
	backend.mu.Unlock()
	now = now.Add(2 * time.Second)

	stale, err := reader.ReadScores(context.Background(), "MCI")
	if err != nil || len(stale) != 1 {
		t.Fatalf("stale score fallback: scores=%+v err=%v", stale, err)
	}
	if backend.Calls() != 2 {
		t.Fatalf("expected one failed refresh, calls=%d", backend.Calls())
	}

	// Circuit is open; this call must reuse stale data without a new backend attempt.
	if _, err := reader.ReadScores(context.Background(), "MCI"); err != nil || backend.Calls() != 2 {
		t.Fatalf("circuit did not suppress repeated outage queries: calls=%d err=%v", backend.Calls(), err)
	}
}

func TestCachingScoreReaderCoalescesConcurrentRefreshes(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	backend := &blockingScoreReader{started: make(chan struct{}), release: make(chan struct{})}
	reader, err := NewCachingCatalogScoreReader(backend, ScoreCacheOptions{
		FreshTTL: time.Second,
		MaxStale: time.Minute,
		Cooldown: time.Second,
		Now:      func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("new cache reader: %v", err)
	}

	results := make(chan error, 2)
	go func() {
		_, readErr := reader.ReadScores(context.Background(), "MCI")
		results <- readErr
	}()
	<-backend.started
	go func() {
		_, readErr := reader.ReadScores(context.Background(), "MCI")
		results <- readErr
	}()

	// The second request must join the in-flight refresh rather than calling
	// ClickHouse a second time.
	time.Sleep(20 * time.Millisecond)
	if backend.Calls() != 1 {
		t.Fatalf("concurrent refresh created %d backend calls, want 1", backend.Calls())
	}
	close(backend.release)
	for range 2 {
		if readErr := <-results; readErr != nil {
			t.Fatalf("coalesced refresh failed: %v", readErr)
		}
	}
}

func TestCachingScoreReaderRejectsExpiredStaleDataWhenCircuitOpen(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	backend := &cacheReaderFixture{scores: []telemetry.NodeScore{{NodeID: "node-1"}}}
	reader, err := NewCachingCatalogScoreReader(backend, ScoreCacheOptions{
		FreshTTL: time.Second,
		MaxStale: 2 * time.Second,
		Cooldown: time.Minute,
		Now:      func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("new cache reader: %v", err)
	}
	if _, err := reader.ReadScores(context.Background(), "MCI"); err != nil {
		t.Fatalf("initial score read: %v", err)
	}
	backend.mu.Lock()
	backend.err = errors.New("clickhouse unavailable")
	backend.mu.Unlock()
	now = now.Add(3 * time.Second)
	if _, err := reader.ReadScores(context.Background(), "MCI"); err == nil {
		t.Fatal("expired stale data must not be used for failed refresh")
	}
	if _, err := reader.ReadScores(context.Background(), "MCI"); !errors.Is(err, ErrScoreCircuitOpen) {
		t.Fatalf("open circuit should report ErrScoreCircuitOpen, got %v", err)
	}
}
