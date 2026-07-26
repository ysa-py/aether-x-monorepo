package subendpoint

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/aether-x/control-plane/internal/telemetry"
)

// ErrScoreCircuitOpen indicates the underlying aggregate reader has recently
// failed. Callers may still receive a bounded stale score snapshot; otherwise
// they fall back to deterministic catalog order.
var ErrScoreCircuitOpen = errors.New("telemetry score circuit is open")

// ScoreCacheOptions bounds score freshness, stale reuse, and outage retry
// cadence. All values are intentionally short because network conditions in an
// adversarial environment change rapidly.
type ScoreCacheOptions struct {
	FreshTTL time.Duration
	MaxStale time.Duration
	Cooldown time.Duration
	Now      func() time.Time
}

// DefaultScoreCacheOptions preserves good scoring data for a short outage
// without allowing a ClickHouse failure to block every subscription request.
func DefaultScoreCacheOptions() ScoreCacheOptions {
	return ScoreCacheOptions{
		FreshTTL: 30 * time.Second,
		MaxStale: 5 * time.Minute,
		Cooldown: 15 * time.Second,
		Now:      time.Now,
	}
}

type scoreCacheEntry struct {
	scores  []telemetry.NodeScore
	fetched time.Time
}

type scoreRefresh struct {
	done   chan struct{}
	scores []telemetry.NodeScore
	err    error
}

// CachingCatalogScoreReader adds a per-ISP cache and a small circuit breaker to
// an aggregate score reader. It never manufactures scores; when no fresh or
// safe stale evidence exists it returns an error for the deterministic catalog
// layer to handle.
type CachingCatalogScoreReader struct {
	reader  CatalogScoreReader
	options ScoreCacheOptions

	mu        sync.Mutex
	entries   map[string]scoreCacheEntry
	inflight  map[string]*scoreRefresh
	openUntil time.Time
}

// NewCachingCatalogScoreReader wraps a real aggregate reader. Invalid options
// are normalized to the safe defaults so callers cannot accidentally create a
// zero-TTL retry storm.
func NewCachingCatalogScoreReader(
	reader CatalogScoreReader,
	options ScoreCacheOptions,
) (*CachingCatalogScoreReader, error) {
	if reader == nil {
		return nil, errors.New("catalog score reader is required")
	}
	defaults := DefaultScoreCacheOptions()
	if options.FreshTTL <= 0 {
		options.FreshTTL = defaults.FreshTTL
	}
	if options.MaxStale < options.FreshTTL {
		options.MaxStale = defaults.MaxStale
	}
	if options.Cooldown <= 0 {
		options.Cooldown = defaults.Cooldown
	}
	if options.Now == nil {
		options.Now = defaults.Now
	}
	return &CachingCatalogScoreReader{
		reader:   reader,
		options:  options,
		entries:  make(map[string]scoreCacheEntry),
		inflight: make(map[string]*scoreRefresh),
	}, nil
}

// ReadScores returns fresh aggregate evidence when available. During a reader
// failure it returns a copied stale snapshot inside MaxStale; after that it
// reports an error so callers retain the catalog's deterministic baseline.
// At most one refresh per ISP runs at once, preventing an expired cache from
// turning a burst of subscriptions into a ClickHouse query stampede.
func (r *CachingCatalogScoreReader) ReadScores(
	ctx context.Context,
	isp string,
) ([]telemetry.NodeScore, error) {
	now := r.options.Now().UTC()

	r.mu.Lock()
	entry, cached := r.entries[isp]
	if cached && now.Sub(entry.fetched) <= r.options.FreshTTL {
		scores := cloneScores(entry.scores)
		r.mu.Unlock()
		return scores, nil
	}
	if now.Before(r.openUntil) {
		if cached && now.Sub(entry.fetched) <= r.options.MaxStale {
			scores := cloneScores(entry.scores)
			r.mu.Unlock()
			return scores, nil
		}
		r.mu.Unlock()
		return nil, ErrScoreCircuitOpen
	}
	if refresh, refreshing := r.inflight[isp]; refreshing {
		if cached && now.Sub(entry.fetched) <= r.options.MaxStale {
			scores := cloneScores(entry.scores)
			r.mu.Unlock()
			return scores, nil
		}
		r.mu.Unlock()
		select {
		case <-refresh.done:
			return cloneScores(refresh.scores), refresh.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	refresh := &scoreRefresh{done: make(chan struct{})}
	r.inflight[isp] = refresh
	r.mu.Unlock()

	scores, err := r.reader.ReadScores(ctx, isp)
	r.mu.Lock()
	entry, cached = r.entries[isp]
	if err != nil {
		r.openUntil = now.Add(r.options.Cooldown)
		if cached && now.Sub(entry.fetched) <= r.options.MaxStale {
			refresh.scores = cloneScores(entry.scores)
			refresh.err = nil
		} else {
			refresh.err = err
		}
	} else {
		refresh.scores = cloneScores(scores)
		r.entries[isp] = scoreCacheEntry{scores: cloneScores(scores), fetched: now}
		r.openUntil = time.Time{}
	}
	delete(r.inflight, isp)
	close(refresh.done)
	result := cloneScores(refresh.scores)
	resultErr := refresh.err
	r.mu.Unlock()
	return result, resultErr
}

func cloneScores(scores []telemetry.NodeScore) []telemetry.NodeScore {
	return append([]telemetry.NodeScore(nil), scores...)
}

var _ CatalogScoreReader = (*CachingCatalogScoreReader)(nil)
