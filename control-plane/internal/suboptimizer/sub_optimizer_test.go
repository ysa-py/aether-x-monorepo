package suboptimizer

import (
	"context"
	"testing"
	"time"
)

func TestOptimize(t *testing.T) {
	reader := &MockReader{
		Metrics: []NodeMetrics{
			{NodeID: "fra-01", Region: "eu-central", Protocol: "vless", Transport: "xhttp", RTTMs: 120, SuccessRate: 0.95, LastSeen: time.Now()},
			{NodeID: "tr-01", Region: "tr-central", Protocol: "vless", Transport: "ws", RTTMs: 80, SuccessRate: 0.88, LastSeen: time.Now()},
		},
	}
	opt := New(reader)
	nodes, err := opt.Optimize(context.Background(), "MCI", "eu-central", "sing-box")
	if err != nil {
		t.Fatalf("optimize failed: %v", err)
	}
	if len(nodes) != 2 {
		t.Errorf("expected 2, got %d", len(nodes))
	}
	if nodes[0].Weight <= 0 {
		t.Error("weight")
	}
}

func TestFilterByCore(t *testing.T) {
	nodes := []OptimizedNode{
		{NodeMetrics: NodeMetrics{NodeID: "1", Transport: "xhttp"}},
		{NodeMetrics: NodeMetrics{NodeID: "2", Transport: "ws"}},
	}
	filtered := filterByCore(nodes, "shadowrocket")
	if len(filtered) != 1 {
		t.Errorf("shadowrocket should filter xhttp, got %d", len(filtered))
	}
}
