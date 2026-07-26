package telemetry

import (
	"testing"
	"time"
)

func TestNodeScoreAggregateClampsUnsafeValues(t *testing.T) {
	aggregate := nodeScoreAggregate{
		nodeID:        "catalog-node-1",
		protocol:      "vless",
		averageRTT:    -5,
		lossRate:      -1,
		rstCount:      1 << 20,
		throughputBps: -42,
		lastSeen:      time.Unix(1_700_000_000, 0),
	}
	score, ok := aggregate.toNodeScore("MCI")
	if !ok {
		t.Fatal("aggregate with node and protocol should produce a score")
	}
	if score.SuccessRate != 1 || score.AvgRTTMs != 0 || score.RSTCount != 65535 {
		t.Fatalf("unexpected clamped score: %+v", score)
	}
	if score.ThroughputBps != 0 {
		t.Fatalf("negative throughput must clamp to zero: %+v", score)
	}
}

func TestNodeScoreAggregateRejectsMissingIdentity(t *testing.T) {
	if _, ok := (nodeScoreAggregate{protocol: "vless"}).toNodeScore("MCI"); ok {
		t.Fatal("missing node ID must be rejected")
	}
	if _, ok := (nodeScoreAggregate{nodeID: "node"}).toNodeScore("MCI"); ok {
		t.Fatal("missing protocol must be rejected")
	}
}

func TestNodeScoreAggregatePreservesRealMeasurements(t *testing.T) {
	seen := time.Unix(1_700_000_000, 0).UTC()
	score, ok := (nodeScoreAggregate{
		nodeID:        "catalog-node-2",
		protocol:      "vless",
		averageRTT:    123.4,
		lossRate:      0.2,
		rstCount:      3,
		throughputBps: 250_000_000,
		lastSeen:      seen,
	}).toNodeScore("Irancell")
	if !ok {
		t.Fatal("complete aggregate should produce a score")
	}
	if score.NodeID != "catalog-node-2" || score.ISP != "Irancell" {
		t.Fatalf("unexpected score identity: %+v", score)
	}
	if score.SuccessRate < 0.799 || score.SuccessRate > 0.801 {
		t.Fatalf("unexpected success rate: %+v", score)
	}
	if score.AvgRTTMs != 123 || score.RSTCount != 3 || score.ThroughputBps != 250_000_000 {
		t.Fatalf("unexpected score metrics: %+v", score)
	}
	if !score.LastSeen.Equal(seen) {
		t.Fatalf("last seen = %v, want %v", score.LastSeen, seen)
	}
}
