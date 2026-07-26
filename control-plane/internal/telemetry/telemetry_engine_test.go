package telemetry

import (
	"context"
	"testing"
	"time"
)

func TestTelemetryEngine_Tune(t *testing.T) {
	reader := &MockTelemetryReader{
		Snapshots: map[string]MetricsSnapshot{
			"node-fra-01": {RTTMs: 50, DropRate: 0.01, EntropyScore: 7.5, GeoDistanceKm: 100, Timestamp: time.Now()},
			"node-tr-01":  {RTTMs: 200, DropRate: 0.1, EntropyScore: 6.0, GeoDistanceKm: 500, Timestamp: time.Now()},
		},
	}
	engine := NewTelemetryEngine(reader)
	engine.RegisterCandidate("node-fra-01", "xhttp", 1.0)
	engine.RegisterCandidate("node-tr-01", "ws", 1.0)

	tuned, err := engine.TuneAll(context.Background())
	if err != nil {
		t.Fatalf("tune failed: %v", err)
	}
	if tuned != 2 {
		t.Errorf("expected 2 tuned, got %d", tuned)
	}

	weights := engine.GetWeights()
	if len(weights) != 2 {
		t.Fatalf("expected 2 weights")
	}
	// fra should be higher due to lower RTT and drop
	if weights[0].NodeID != "node-fra-01" {
		t.Errorf("expected fra-01 best, got %s", weights[0].NodeID)
	}
	if weights[0].TunedWeight <= weights[1].TunedWeight {
		t.Error("tuned weights should reflect metrics")
	}
}

func TestCalculateTunedWeight(t *testing.T) {
	engine := NewTelemetryEngine(&MockTelemetryReader{})
	base := 1.0

	good := MetricsSnapshot{RTTMs: 20, DropRate: 0.01, EntropyScore: 7.8, GeoDistanceKm: 100, Timestamp: time.Now()}
	bad := MetricsSnapshot{RTTMs: 500, DropRate: 0.5, EntropyScore: 4.0, GeoDistanceKm: 10000, Timestamp: time.Now().Add(-2 * time.Hour)}

	goodW := engine.calculateTunedWeight(base, good)
	badW := engine.calculateTunedWeight(base, bad)

	if goodW <= badW {
		t.Errorf("good should have higher weight: good=%f bad=%f", goodW, badW)
	}
}

func TestGetWeight(t *testing.T) {
	engine := NewTelemetryEngine(&MockTelemetryReader{})
	engine.RegisterCandidate("node-01", "xhttp", 1.0)
	w, ok := engine.GetWeight("node-01", "xhttp")
	if !ok {
		t.Fatal("should find")
	}
	if w.NodeID != "node-01" {
		t.Error("id mismatch")
	}
}

func TestStats(t *testing.T) {
	engine := NewTelemetryEngine(&MockTelemetryReader{})
	engine.RegisterCandidate("n1", "ws", 1.0)
	engine.RegisterCandidate("n2", "grpc", 1.0)
	stats := engine.Stats()
	if stats.Candidates != 2 {
		t.Error("candidates")
	}
}
