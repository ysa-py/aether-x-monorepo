package store

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestSessionManager_CreateAndGet(t *testing.T) {
	mem := NewMemSessionStore()
	mgr := NewSessionManager("localhost:6379", mem)

	ctx := context.Background()
	sess := &Session{
		ID:             "sess-001",
		UserID:         "user-001",
		SubscriptionID: "sub-001",
		NodeID:         "node-fra-01",
		Protocol:       "vless",
		Transport:      "xhttp",
		ClientIP:       "1.2.3.4",
		ISP:            "MCI",
		ConnID:         "conn-id-123",
	}

	if err := mgr.CreateSession(ctx, sess); err != nil {
		t.Fatalf("create failed: %v", err)
	}

	got, err := mgr.GetSession(ctx, "sess-001")
	if err != nil {
		t.Fatalf("get failed: %v", err)
	}
	if got.NodeID != "node-fra-01" {
		t.Errorf("expected node-fra-01, got %s", got.NodeID)
	}
	if !got.Active {
		t.Error("session should be active")
	}
}

func TestSessionManager_MigrationZeroDisconnection(t *testing.T) {
	mem := NewMemSessionStore()
	mgr := NewSessionManager("localhost:6379", mem)
	ctx := context.Background()

	sess := &Session{
		ID:     "sess-migrate",
		UserID: "user-001",
		NodeID: "node-fra-01",
		ConnID: "conn-preserving-cid",
	}
	mgr.CreateSession(ctx, sess)

	// Simulate QUIC CID migration: node changes but ConnID preserved, session stays active
	err := mgr.MigrateSession(ctx, "sess-migrate", "node-tr-01", "2.3.4.5")
	if err != nil {
		t.Fatalf("migrate failed: %v", err)
	}

	got, _ := mgr.GetSession(ctx, "sess-migrate")
	if got.NodeID != "node-tr-01" {
		t.Errorf("expected migrated to node-tr-01, got %s", got.NodeID)
	}
	if got.MigratedCount != 1 {
		t.Errorf("expected migrated count 1, got %d", got.MigratedCount)
	}
	if got.ConnID != "conn-preserving-cid" {
		t.Error("ConnID must be preserved across migration (zero disconnection)")
	}
	if !got.Active {
		t.Error("session must stay active after migration")
	}
}

func TestSessionManager_AutoFailover(t *testing.T) {
	mem := NewMemSessionStore()
	mgr := NewSessionManager("localhost:6379", mem)
	ctx := context.Background()

	// Create stale session (last seen 5 min ago)
	sess := &Session{
		ID:         "sess-stale",
		UserID:     "user-failover",
		NodeID:     "node-dead",
		Active:     true,
		LastSeenAt: time.Now().Add(-5 * time.Minute),
	}
	mem.SaveSession(ctx, sess)

	healthy := []string{"node-fra-01", "node-tr-01"}
	migrated, err := mgr.AutoFailover(ctx, "user-failover", healthy)
	if err != nil {
		t.Fatalf("auto failover failed: %v", err)
	}
	if migrated != 1 {
		t.Errorf("expected 1 migrated, got %d", migrated)
	}

	got, _ := mem.GetSession(ctx, "sess-stale")
	if got.NodeID == "node-dead" {
		t.Error("should have migrated away from dead node")
	}
}

func TestSessionManager_DeviceLimit(t *testing.T) {
	mem := NewMemSessionStore()
	mgr := NewSessionManager("localhost:6379", mem)
	ctx := context.Background()

	// Create 3 sessions for same user
	for i := 0; i < 3; i++ {
		s := &Session{
			ID:     string(rune('a' + i)),
			UserID: "user-limit",
			Active: true,
		}
		mem.SaveSession(ctx, s)
	}

	count, err := mgr.CountActive(ctx, "user-limit")
	if err != nil {
		t.Fatalf("count failed: %v", err)
	}
	if count != 3 {
		t.Errorf("expected 3 active, got %d", count)
	}
}

func TestSessionManager_Heartbeat(t *testing.T) {
	mem := NewMemSessionStore()
	mgr := NewSessionManager("localhost:6379", mem)
	ctx := context.Background()

	sess := &Session{ID: "sess-hb", UserID: "u1", NodeID: "n1"}
	mgr.CreateSession(ctx, sess)

	err := mgr.Heartbeat(ctx, "sess-hb", 1024, 2048)
	if err != nil {
		t.Fatalf("heartbeat failed: %v", err)
	}

	got, _ := mgr.GetSession(ctx, "sess-hb")
	if got.BytesUp != 1024 || got.BytesDown != 2048 {
		t.Errorf("bytes not updated: up=%d down=%d", got.BytesUp, got.BytesDown)
	}
}

func TestSessionManagerRejectsRegressiveHeartbeatCounters(t *testing.T) {
	mem := NewMemSessionStore()
	mgr := NewSessionManager("localhost:6379", mem)
	ctx := context.Background()
	if err := mgr.CreateSession(ctx, &Session{ID: "sess-counter", UserID: "u1", NodeID: "n1"}); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := mgr.Heartbeat(ctx, "sess-counter", 100, 200); err != nil {
		t.Fatalf("first heartbeat: %v", err)
	}
	if err := mgr.Heartbeat(ctx, "sess-counter", 99, 200); err == nil {
		t.Fatal("regressive byte counter must be rejected")
	}
}

func TestSessionManagerSerializesConcurrentMigrations(t *testing.T) {
	mem := NewMemSessionStore()
	mgr := NewSessionManager("localhost:6379", mem)
	ctx := context.Background()
	if err := mgr.CreateSession(ctx, &Session{
		ID:     "sess-concurrent",
		UserID: "u1",
		NodeID: "node-0",
		ConnID: "stable-quic-cid",
	}); err != nil {
		t.Fatalf("create: %v", err)
	}

	targets := []string{"node-1", "node-2", "node-3", "node-4"}
	var group sync.WaitGroup
	for _, target := range targets {
		group.Add(1)
		go func(target string) {
			defer group.Done()
			if err := mgr.MigrateSession(ctx, "sess-concurrent", target, ""); err != nil {
				t.Errorf("migrate to %s: %v", target, err)
			}
		}(target)
	}
	group.Wait()

	got, err := mgr.GetSession(ctx, "sess-concurrent")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.MigratedCount != len(targets) {
		t.Fatalf("migration count = %d, want %d", got.MigratedCount, len(targets))
	}
	if got.ConnID != "stable-quic-cid" || !got.Active {
		t.Fatalf("migration lost session continuity: %+v", got)
	}
}

func TestSelectFailoverNodeIsStableAndAvoidsCurrent(t *testing.T) {
	candidates := []string{"node-a", "node-b", "node-b", "node-c"}
	first, ok := selectFailoverNode("session-1", "node-a", candidates)
	if !ok || first == "" || first == "node-a" {
		t.Fatalf("unexpected failover choice: %q ok=%v", first, ok)
	}
	second, ok := selectFailoverNode("session-1", "node-a", candidates)
	if !ok || second != first {
		t.Fatalf("failover selection must be stable: first=%q second=%q", first, second)
	}
}
