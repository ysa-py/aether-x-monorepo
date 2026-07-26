// Package northflank_healer integrates Northflank REST/GraphQL API to auto-heal
// when ClickHouse telemetry reports severe drop rates or TCP RST injection.
package northflank_healer

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// HealerAction type
type ActionType string

const (
	ActionRedeploy      ActionType = "redeploy"
	ActionPortRotation  ActionType = "port-rotation"
	ActionIPMutation    ActionType = "ip-mutation"
	ActionScale         ActionType = "scale"
)

// TelemetryAlert from ClickHouse
type TelemetryAlert struct {
	NodeID      string
	DropRate    float64
	RSTCount    int
	RTTMs       uint16
	Timestamp   time.Time
	Severity    string // critical, warning
}

// HealerDecision
type HealerDecision struct {
	Action     ActionType
	NodeID     string
	Reason     string
	Timestamp  time.Time
	Executed   bool
}

// NorthflankAPIClient mock interface
type NorthflankAPIClient interface {
	RedeployService(ctx context.Context, serviceID string) error
	RotatePort(ctx context.Context, serviceID string, newPort int) error
	MutateIP(ctx context.Context, serviceID string) (newIP string, err error)
}

// Mock client for tests
type MockClient struct {
	Redeploys int
	Rotations int
	Mutations int
}

func (m *MockClient) RedeployService(ctx context.Context, serviceID string) error {
	m.Redeploys++
	return nil
}

func (m *MockClient) RotatePort(ctx context.Context, serviceID string, newPort int) error {
	m.Rotations++
	return nil
}

func (m *MockClient) MutateIP(ctx context.Context, serviceID string) (string, error) {
	m.Mutations++
	return fmt.Sprintf("10.0.0.%d", m.Mutations), nil
}

// Healer engine
type Healer struct {
	mu       sync.RWMutex
	client   NorthflankAPIClient
	decisions []HealerDecision
	cooldown  map[string]time.Time
	cooldownDur time.Duration
}

func New(client NorthflankAPIClient) *Healer {
	return &Healer{
		client:      client,
		cooldown:    make(map[string]time.Time),
		cooldownDur: 5 * time.Minute,
	}
}

// HandleAlert decides and executes healing action based on telemetry
func (h *Healer) HandleAlert(ctx context.Context, alert TelemetryAlert) (*HealerDecision, error) {
	// Cooldown check to avoid flapping
	h.mu.RLock()
	if last, ok := h.cooldown[alert.NodeID]; ok {
		if time.Since(last) < h.cooldownDur {
			h.mu.RUnlock()
			return nil, fmt.Errorf("cooldown active for %s", alert.NodeID)
		}
	}
	h.mu.RUnlock()

	var action ActionType
	var reason string

	switch {
	case alert.DropRate > 0.5 || alert.RSTCount > 20:
		action = ActionIPMutation
		reason = fmt.Sprintf("severe drop %.2f RST %d", alert.DropRate, alert.RSTCount)
	case alert.DropRate > 0.3 || alert.RSTCount > 10:
		action = ActionRedeploy
		reason = fmt.Sprintf("high drop %.2f RST %d", alert.DropRate, alert.RSTCount)
	case alert.RTTMs > 500:
		action = ActionPortRotation
		reason = fmt.Sprintf("high RTT %dms", alert.RTTMs)
	default:
		action = ActionRedeploy
		reason = "warning threshold"
	}

	decision := HealerDecision{
		Action:    action,
		NodeID:    alert.NodeID,
		Reason:    reason,
		Timestamp: time.Now(),
		Executed:  false,
	}

	// Execute via API client
	err := h.execute(ctx, &decision)
	if err != nil {
		return nil, err
	}

	decision.Executed = true
	h.mu.Lock()
	h.decisions = append(h.decisions, decision)
	h.cooldown[alert.NodeID] = time.Now()
	h.mu.Unlock()

	return &decision, nil
}

func (h *Healer) execute(ctx context.Context, d *HealerDecision) error {
	switch d.Action {
	case ActionRedeploy:
		return h.client.RedeployService(ctx, d.NodeID)
	case ActionPortRotation:
		newPort := 443
		if d.NodeID == "core-supervisor" {
			newPort = 8443
		}
		return h.client.RotatePort(ctx, d.NodeID, newPort)
	case ActionIPMutation:
		_, err := h.client.MutateIP(ctx, d.NodeID)
		return err
	case ActionScale:
		return h.client.RedeployService(ctx, d.NodeID)
	default:
		return fmt.Errorf("unknown action %s", d.Action)
	}
}

func (h *Healer) Decisions() []HealerDecision {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]HealerDecision, len(h.decisions))
	copy(out, h.decisions)
	return out
}

func (h *Healer) Stats() HealerStats {
	h.mu.RLock()
	defer h.mu.RUnlock()
	counts := make(map[ActionType]int)
	for _, d := range h.decisions {
		counts[d.Action]++
	}
	return HealerStats{
		Total:     len(h.decisions),
		ByAction:  counts,
		Cooldowns: len(h.cooldown),
	}
}

type HealerStats struct {
	Total     int
	ByAction  map[ActionType]int
	Cooldowns int
}
