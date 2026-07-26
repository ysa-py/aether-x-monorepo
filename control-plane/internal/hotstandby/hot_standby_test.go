package hotstandby

import (
	"context"
	"testing"
	"time"
)

func TestEnsurePool(t *testing.T) {
	pool := New(3, 5)
	ctx := context.Background()
	added := pool.EnsurePool(ctx, []string{"eu-central", "tr-central", "us-east"}, []string{"xhttp", "grpc", "ws"})
	if added != 3 {
		t.Errorf("expected 3 added, got %d", added)
	}
	if pool.Count() != 3 {
		t.Error("count")
	}
	stats := pool.Stats()
	if stats.Handshaked != 3 {
		t.Error("handshaked")
	}
}

func TestMigrateToBest(t *testing.T) {
	pool := New(3, 5)
	pool.AddChannel("eu-central", "xhttp")
	// Make one faster
	for _, ch := range pool.channels {
		ch.RTTMs = 20
	}

	best, ok := pool.MigrateToBest()
	if !ok {
		t.Fatal("should migrate")
	}
	if !best.Handshaked {
		t.Error("should be handshaked for 0-RTT")
	}
	if pool.Stats().Migrations != 1 {
		t.Error("migrations")
	}
}

func TestRemoveStale(t *testing.T) {
	pool := New(1, 5)
	pool.AddChannel("eu", "ws")
	pool.AddChannel("us", "grpc")

	for _, ch := range pool.channels {
		ch.LastUsed = time.Now().Add(-2 * time.Hour)
	}

	removed := pool.RemoveStale(1 * time.Hour)
	if removed != 1 {
		t.Errorf("should remove 1 but keep minSize 1, got %d", removed)
	}
	if pool.Count() != 1 {
		t.Error("should keep min")
	}
}
