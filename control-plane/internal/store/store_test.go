package store

import (
	"context"
	"testing"
	"time"

	"github.com/aether-x/control-plane/internal/model"
)

func TestMemStoreSubscriptionCRUD(t *testing.T) {
	s := NewMemStore()
	ctx := context.Background()

	sub := &model.Subscription{
		ID:         "test-1",
		UserID:     "user-1",
		PlanID:     "pro",
		BytesTotal: 10_000_000,
		BytesUsed:  1_000_000,
		ExpiresAt:  time.Now().Add(24 * time.Hour),
	}
	sub.SubToken = "tok-123"

	if err := s.Save(ctx, sub); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := s.ByToken(ctx, "tok-123")
	if err != nil {
		t.Fatalf("ByToken: %v", err)
	}
	if got.ID != "test-1" {
		t.Fatalf("got ID %s", got.ID)
	}

	got2, err := s.ByUserID(ctx, "user-1")
	if err != nil {
		t.Fatalf("ByUserID: %v", err)
	}
	if got2.ID != "test-1" {
		t.Fatalf("got ID %s", got2.ID)
	}

	if err := s.UpdateUsage(ctx, "test-1", 500_000); err != nil {
		t.Fatalf("UpdateUsage: %v", err)
	}
	got3, _ := s.ByToken(ctx, "tok-123")
	if got3.BytesUsed != 1_500_000 {
		t.Fatalf("bytes_used = %d, want 1500000", got3.BytesUsed)
	}

	// NotFound
	if _, err := s.ByToken(ctx, "nonexistent"); err == nil {
		t.Fatal("expected ErrNotFound")
	}
}

func TestMemStoreUser(t *testing.T) {
	s := NewMemStore()
	ctx := context.Background()

	u := &model.User{
		ID:    "u1",
		Email: "test@example.com",
		Role:  model.RoleUser,
	}
	s.mu.Lock()
	s.users[u.ID] = u
	s.mu.Unlock()

	got, err := s.UserByID(ctx, "u1")
	if err != nil {
		t.Fatalf("ByID: %v", err)
	}
	if got.Email != "test@example.com" {
		t.Fatalf("email %s", got.Email)
	}

	got2, err := s.ByEmail(ctx, "test@example.com")
	if err != nil {
		t.Fatalf("ByEmail: %v", err)
	}
	if got2.ID != "u1" {
		t.Fatalf("ID %s", got2.ID)
	}
}

func TestMemStoreNodes(t *testing.T) {
	s := NewMemStore()
	ctx := context.Background()
	s.SeedWithDemo()

	nodes, err := s.Active(ctx)
	if err != nil {
		t.Fatalf("Active: %v", err)
	}
	if len(nodes) == 0 {
		t.Fatal("expected at least 1 active node")
	}

	node, err := s.NodeByID(ctx, "node-fra-01")
	if err != nil {
		t.Fatalf("ByID: %v", err)
	}
	if !node.Healthy {
		t.Fatal("node should be healthy")
	}
}

func TestMemStoreSeedDemo(t *testing.T) {
	s := NewMemStore()
	s.SeedWithDemo()
	ctx := context.Background()

	sub, err := s.ByToken(ctx, "demo-token-aether-x-2026")
	if err != nil {
		t.Fatalf("ByToken demo: %v", err)
	}
	if sub.BytesTotal != 50_000_000_000 {
		t.Fatalf("bytes_total = %d", sub.BytesTotal)
	}
}
