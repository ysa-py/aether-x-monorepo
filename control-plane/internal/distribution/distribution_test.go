package distribution

import (
	"fmt"
	"testing"
	"time"
)

func newTestService() *Service {
	cfg := DefaultConfig()
	cfg.MaxN = 2
	cfg.WindowDays = 30
	cfg.NewIdentityAgeDays = 7
	cfg.DampenedN = 0
	svc := New(cfg)
	// Add 5 nodes.
	for i := 0; i < 5; i++ {
		svc.AddNode(Node{
			ID:        fmt.Sprintf("node-%d", i),
			Address:   fmt.Sprintf("10.0.0.%d:443", i),
			Protocol:  "vless-reality",
			CreatedAt: time.Now(),
		})
	}
	// Register an old identity.
	svc.RegisterIdentity("user-old", time.Now().Add(-30*24*time.Hour))
	// Register a new identity.
	svc.RegisterIdentity("user-new", time.Now().Add(-2*24*time.Hour))
	return svc
}

func TestRequestRationedNode_Success(t *testing.T) {
	svc := newTestService()
	node, err := svc.RequestRationedNode("user-old")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if node == nil {
		t.Fatal("expected a node, got nil")
	}
	if node.IsBurned {
		t.Fatal("allocated node should not be burned")
	}
}

func TestRequestRationedNode_CapEnforced(t *testing.T) {
	svc := newTestService()
	// Allocate up to the cap.
	for i := 0; i < 2; i++ {
		_, err := svc.RequestRationedNode("user-old")
		if err != nil {
			t.Fatalf("allocation %d failed: %v", i, err)
		}
	}
	// Third allocation must be rate-limited.
	_, err := svc.RequestRationedNode("user-old")
	if err != ErrRateLimited {
		t.Fatalf("expected ErrRateLimited, got: %v", err)
	}
}

func TestNewIdentityDampening(t *testing.T) {
	svc := newTestService()
	_, err := svc.RequestRationedNode("user-new")
	if err != ErrIdentityTooNew {
		t.Fatalf("expected ErrIdentityTooNew, got: %v", err)
	}
}

func TestReportBurned_TriggersRotation(t *testing.T) {
	svc := newTestService()
	err := svc.ReportBurned("node-0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	health := svc.GetPoolHealth()
	if health.BurnedNodes != 1 {
		t.Fatalf("expected 1 burned node, got %d", health.BurnedNodes)
	}
	if health.RotationPending != 1 {
		t.Fatalf("expected 1 rotation pending, got %d", health.RotationPending)
	}
	// Burned node is not allocated.
	_, err = svc.RequestRationedNode("user-old")
	if err != nil {
		t.Fatalf("should still allocate from non-burned nodes: %v", err)
	}
}

func TestReportBurned_UnknownNode(t *testing.T) {
	svc := newTestService()
	err := svc.ReportBurned("nonexistent")
	if err != ErrNodeNotFound {
		t.Fatalf("expected ErrNodeNotFound, got: %v", err)
	}
}

func TestUnknownIdentity(t *testing.T) {
	svc := newTestService()
	_, err := svc.RequestRationedNode("unknown-user")
	if err != ErrIdentityNotFound {
		t.Fatalf("expected ErrIdentityNotFound, got: %v", err)
	}
}

func TestPoolHealth(t *testing.T) {
	svc := newTestService()
	health := svc.GetPoolHealth()
	if health.TotalNodes != 5 {
		t.Fatalf("expected 5 total nodes, got %d", health.TotalNodes)
	}
	if health.AvailableNodes != 5 {
		t.Fatalf("expected 5 available nodes, got %d", health.AvailableNodes)
	}
}

func TestDrainRotationQueue(t *testing.T) {
	svc := newTestService()
	_ = svc.ReportBurned("node-0")
	_ = svc.ReportBurned("node-1")
	q := svc.DrainRotationQueue()
	if len(q) != 2 {
		t.Fatalf("expected 2 in rotation queue, got %d", len(q))
	}
	// Second drain is empty.
	q2 := svc.DrainRotationQueue()
	if len(q2) != 0 {
		t.Fatalf("expected empty rotation queue after drain, got %d", len(q2))
	}
}

func TestRollingWindow_NotCalendarMonth(t *testing.T) {
	// Property test: the N-per-identity cap holds across a ROLLING window,
	// not just a calendar month.
	cfg := DefaultConfig()
	cfg.MaxN = 2
	cfg.WindowDays = 30
	cfg.NewIdentityAgeDays = 0
	cfg.DampenedN = 2
	svc := New(cfg)
	for i := 0; i < 5; i++ {
		svc.AddNode(Node{
			ID:       fmt.Sprintf("node-%d", i),
			Address:  fmt.Sprintf("10.0.0.%d:443", i),
			Protocol: "vless",
		})
	}
	svc.RegisterIdentity("test-user", time.Now().Add(-365*24*time.Hour))

	// Manually inject an old allocation (31 days ago — outside window).
	svc.mu.Lock()
	svc.allocations = append(svc.allocations, Allocation{
		IdentityID:  "test-user",
		NodeID:      "node-old",
		AllocatedAt: time.Now().Add(-31 * 24 * time.Hour),
	})
	svc.mu.Unlock()

	// Should be able to allocate 2 within the window.
	for i := 0; i < 2; i++ {
		_, err := svc.RequestRationedNode("test-user")
		if err != nil {
			t.Fatalf("allocation %d failed: %v", i, err)
		}
	}
	// Third must be rate-limited.
	_, err := svc.RequestRationedNode("test-user")
	if err != ErrRateLimited {
		t.Fatalf("expected ErrRateLimited, got: %v", err)
	}
}

// fmt is needed for Sprintf.
var _ = fmt.Sprintf
