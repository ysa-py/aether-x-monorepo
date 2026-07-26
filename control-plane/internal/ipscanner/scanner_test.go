package ipscanner

import (
	"context"
	"sync"
	"testing"
	"time"
)

type mockProber struct {
	clean map[string]bool
	rtts  map[string]time.Duration
}

func (m *mockProber) Probe(_ context.Context, ip string) (*IPProbe, error) {
	return &IPProbe{
		IP:       ip,
		RTT:      m.rtts[ip],
		Clean:    m.clean[ip],
		ProbedAt: time.Now(),
	}, nil
}

func TestScanAndGetBestCleanIP(t *testing.T) {
	m := &mockProber{
		clean: map[string]bool{"1.1.1.1": true, "1.1.1.2": true, "1.1.1.3": false, "1.1.1.4": true, "1.1.1.5": false},
		rtts: map[string]time.Duration{
			"1.1.1.1": 50 * time.Millisecond,
			"1.1.1.2": 30 * time.Millisecond, // lowest clean
			"1.1.1.3": 10 * time.Millisecond, // blocked
			"1.1.1.4": 80 * time.Millisecond,
			"1.1.1.5": 20 * time.Millisecond, // blocked
		},
	}
	s := NewScanner(m, 4, nil)
	ips := []string{"1.1.1.1", "1.1.1.2", "1.1.1.3", "1.1.1.4", "1.1.1.5"}
	s.Scan(context.Background(), ips, "MCI")

	best := s.GetBestCleanIP("MCI")
	if best != "1.1.1.2" {
		t.Fatalf("expected 1.1.1.2 (30ms, lowest clean), got %s", best)
	}

	results := s.Results("MCI")
	if len(results) != 5 {
		t.Fatalf("expected 5 results, got %d", len(results))
	}
}

func TestNoCleanIPs(t *testing.T) {
	m := &mockProber{
		clean: map[string]bool{"1.2.3.4": false},
		rtts:  map[string]time.Duration{"1.2.3.4": 100 * time.Millisecond},
	}
	s := NewScanner(m, 2, nil)
	s.Scan(context.Background(), []string{"1.2.3.4"}, "Irancell")
	if best := s.GetBestCleanIP("Irancell"); best != "" {
		t.Fatalf("expected empty (no clean IPs), got %s", best)
	}
}

func TestTriggerRescan(t *testing.T) {
	m := &mockProber{
		clean: map[string]bool{"10.0.0.1": true},
		rtts:  map[string]time.Duration{"10.0.0.1": 5 * time.Millisecond},
	}
	s := NewScanner(m, 2, nil)
	s.TriggerRescan(context.Background(), []string{"10.0.0.1"}, "TCI")

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if s.RescanCount() > 0 && s.GetBestCleanIP("TCI") == "10.0.0.1" {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("rescan did not complete")
}

func TestConcurrentAccess(t *testing.T) {
	m := &mockProber{
		clean: map[string]bool{"172.16.0.1": true, "172.16.0.2": true},
		rtts:  map[string]time.Duration{"172.16.0.1": 10 * time.Millisecond, "172.16.0.2": 20 * time.Millisecond},
	}
	s := NewScanner(m, 4, nil)
	ips := []string{"172.16.0.1", "172.16.0.2"}

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); s.Scan(context.Background(), ips, "Shatel") }()
		go func() { defer wg.Done(); _ = s.GetBestCleanIP("Shatel") }()
	}
	wg.Wait()
}

func TestExpandCIDR(t *testing.T) {
	ips, err := ExpandCIDR("192.168.1.0/30", 256)
	if err != nil {
		t.Fatalf("ExpandCIDR: %v", err)
	}
	if len(ips) < 2 {
		t.Fatalf("expected >=2 IPs from /30, got %d", len(ips))
	}
}
