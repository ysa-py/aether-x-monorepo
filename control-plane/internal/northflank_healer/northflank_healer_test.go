package northflank_healer

import (
	"context"
	"testing"
	"time"
)

func TestHealer_SevereDrop_IPMutation(t *testing.T) {
	client := &MockClient{}
	h := New(client)
	ctx := context.Background()

	alert := TelemetryAlert{
		NodeID:   "core-supervisor",
		DropRate: 0.6,
		RSTCount: 25,
		RTTMs:    100,
		Severity: "critical",
		Timestamp: time.Now(),
	}

	decision, err := h.HandleAlert(ctx, alert)
	if err != nil {
		t.Fatalf("handle failed: %v", err)
	}
	if decision.Action != ActionIPMutation {
		t.Errorf("expected IP mutation for severe, got %s", decision.Action)
	}
	if client.Mutations != 1 {
		t.Error("should mutate IP")
	}
}

func TestHealer_HighRTT_PortRotation(t *testing.T) {
	client := &MockClient{}
	h := New(client)
	ctx := context.Background()

	alert := TelemetryAlert{
		NodeID:   "node-01",
		DropRate: 0.1,
		RSTCount: 2,
		RTTMs:    600,
		Timestamp: time.Now(),
	}

	decision, err := h.HandleAlert(ctx, alert)
	if err != nil {
		t.Fatalf("handle failed: %v", err)
	}
	if decision.Action != ActionPortRotation {
		t.Errorf("expected port rotation for high RTT, got %s", decision.Action)
	}
	if client.Rotations != 1 {
		t.Error("rotation")
	}
}

func TestHealer_Cooldown(t *testing.T) {
	client := &MockClient{}
	h := New(client)
	ctx := context.Background()

	alert := TelemetryAlert{NodeID: "node-01", DropRate: 0.4, RSTCount: 15, Timestamp: time.Now()}
	h.HandleAlert(ctx, alert)

	_, err := h.HandleAlert(ctx, alert)
	if err == nil {
		t.Error("should be in cooldown")
	}
}
