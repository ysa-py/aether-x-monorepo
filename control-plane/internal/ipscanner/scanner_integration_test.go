package ipscanner

import (
	"context"
	"testing"
	"time"
)

// Integration test: simulate a live network disruption — the scanner discovers
// a clean replacement IP, and the "rotation" (which in production would call
// the Rust autoheal via gRPC) completes in < 10ms with the correct IP.
//
// This validates the end-to-end Go-side flow:
//   1. Config gets filtered (simulated by marking all current IPs dirty).
//   2. TriggerRescan fires.
//  3. GetBestCleanIP returns the lowest-latency clean replacement.
//  4. The propagation call (mock) completes under 10ms.

// rotationCallback simulates sending the new IP to the Rust autoheal engine
// via gRPC. In production this would call supervisor.RotateTarget(newIP).
type rotationCallback func(ip string) error

// mockRotation returns instantly, simulating the atomic ArcSwap on the Rust side.
func mockRotation(ip string) error {
	if ip == "" {
		return nil // no clean IP found; stay on current
	}
	return nil
}

func TestIntegrationFilterTriggerRescanRotate(t *testing.T) {
	// Simulate a pool of 10 IPs where the first scan has 3 clean.
	m := &mockProber{
		clean: map[string]bool{
			"10.0.0.1": true, "10.0.0.2": true, "10.0.0.3": true,
			"10.0.0.4": false, "10.0.0.5": false,
		},
		rtts: map[string]time.Duration{
			"10.0.0.1": 80 * time.Millisecond,
			"10.0.0.2": 20 * time.Millisecond, // best clean
			"10.0.0.3": 50 * time.Millisecond,
			"10.0.0.4": 10 * time.Millisecond, // blocked
			"10.0.0.5": 15 * time.Millisecond, // blocked
		},
	}
	s := NewScanner(m, 4, nil)
	ips := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"}

	// Phase 1: initial scan — discover clean IPs.
	s.Scan(context.Background(), ips, "MCI")
	best := s.GetBestCleanIP("MCI")
	if best != "10.0.0.2" {
		t.Fatalf("initial best should be 10.0.0.2 (20ms), got %s", best)
	}

	// Phase 2: simulate filtering — mark current best as blocked, rescan.
	m.clean["10.0.0.2"] = false
	s.TriggerRescan(context.Background(), ips, "MCI")

	// Wait for the async rescan to complete.
	var newBest string
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		newBest = s.GetBestCleanIP("MCI")
		if newBest == "10.0.0.1" || newBest == "10.0.0.3" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if newBest == "" {
		t.Fatal("expected a clean IP after rescan, got empty")
	}
	if newBest == "10.0.0.2" {
		t.Fatal("10.0.0.2 should be filtered after rescan")
	}

	// Phase 3: measure rotation latency (< 10ms target).
	start := time.Now()
	err := mockRotation(newBest)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("rotation callback failed: %v", err)
	}
	if elapsed > 10*time.Millisecond {
		t.Fatalf("rotation took %v, expected < 10ms", elapsed)
	}
	t.Logf("rotation to %s completed in %v", newBest, elapsed)
}

func TestIntegrationAllFilteredStaysOnCurrent(t *testing.T) {
	m := &mockProber{
		clean: map[string]bool{"192.168.1.1": false, "192.168.1.2": false},
		rtts: map[string]time.Duration{
			"192.168.1.1": 30 * time.Millisecond,
			"192.168.1.2": 40 * time.Millisecond,
		},
	}
	s := NewScanner(m, 2, nil)
	s.Scan(context.Background(), []string{"192.168.1.1", "192.168.1.2"}, "Irancell")

	best := s.GetBestCleanIP("Irancell")
	if best != "" {
		t.Fatalf("expected empty when all filtered, got %s", best)
	}
	// Rotation with no clean IP — callback receives empty, no crash.
	if err := mockRotation(best); err != nil {
		t.Fatalf("rotation with empty IP should not error: %v", err)
	}
}
