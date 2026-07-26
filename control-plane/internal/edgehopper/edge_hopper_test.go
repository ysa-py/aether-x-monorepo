package edgehopper

import (
	"context"
	"testing"
	"time"
)

func TestDeployNew(t *testing.T) {
	h := New()
	ctx := context.Background()
	ep, err := h.DeployNew(ctx, ProviderCloudflare, "eu-central")
	if err != nil {
		t.Fatalf("deploy failed: %v", err)
	}
	if ep.URL == "" {
		t.Error("url empty")
	}
	if !ep.Healthy {
		t.Error("should be healthy")
	}
	if len(h.ListEndpoints()) != 1 {
		t.Error("should have 1 endpoint")
	}
}

func TestHandleDetectionWithin500ms(t *testing.T) {
	h := New()
	ctx := context.Background()
	ev := HopperEvent{
		Type:      "ip_drop",
		TargetIP:  "1.2.3.4",
		ISP:       "MCI",
		Timestamp: time.Now(),
	}
	ep, elapsed, err := h.HandleDetection(ctx, ev)
	if err != nil {
		t.Fatalf("handle detection failed: %v", err)
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("must be within 500ms, got %v", elapsed)
	}
	if ep == nil {
		t.Error("endpoint nil")
	}
	if h.Detections() != 1 {
		t.Error("detections count")
	}
	if h.Hops() != 1 {
		t.Error("hops count")
	}
}

func TestBestEndpoint(t *testing.T) {
	h := New()
	ctx := context.Background()
	h.DeployNew(ctx, ProviderCloudflare, "eu-central")
	ep2, _ := h.DeployNew(ctx, ProviderFastly, "tr-central")
	h.MarkHealthy(ep2.ID, true, 20) // faster

	best := h.BestEndpoint()
	if best == nil {
		t.Fatal("best nil")
	}
	if best.ID != ep2.ID {
		t.Errorf("expected fastest, got %s", best.ID)
	}
}

func TestPruneStale(t *testing.T) {
	h := New()
	ctx := context.Background()
	h.DeployNew(ctx, ProviderCloudflare, "eu")
	// Hack: make it old
	for _, ep := range h.endpoints {
		ep.CreatedAt = time.Now().Add(-2 * time.Hour)
	}
	removed := h.PruneStale(1 * time.Hour)
	if removed != 1 {
		t.Errorf("expected 1 removed, got %d", removed)
	}
	if len(h.ListEndpoints()) != 0 {
		t.Error("should be empty after prune")
	}
}

func TestStats(t *testing.T) {
	h := New()
	ctx := context.Background()
	h.DeployNew(ctx, ProviderCloudflare, "eu")
	h.DeployNew(ctx, ProviderAWSLambda, "us")
	stats := h.Stats()
	if stats.TotalEndpoints != 2 {
		t.Error("total")
	}
	if stats.Healthy != 2 {
		t.Error("healthy")
	}
}
