package subendpoint

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aether-x/control-plane/internal/telemetry"
)

func TestDetectClientContext(t *testing.T) {
	tests := []struct {
		ua       string
		expected string // core
	}{
		{"sing-box/1.8.0", "sing-box"},
		{"Clash-Meta/1.0", "clash-meta"},
		{"NekoBox/1.2", "nekobox"},
		{"Shadowrocket/123", "shadowrocket"},
		{"v2rayNG/1.8", "xray-core"},
	}
	for _, tt := range tests {
		ctx := DetectClientContext(tt.ua, "1.2.3.4")
		if ctx.Core != tt.expected {
			t.Errorf("UA %q expected core %q got %q", tt.ua, tt.expected, ctx.Core)
		}
	}
}

func TestDetectClientContextDoesNotInventNetworkLocation(t *testing.T) {
	ctx := DetectClientContext("sing-box/1.11", "198.51.100.7")
	if ctx.ISP != "" || ctx.Region != "" || ctx.Country != "" {
		t.Fatalf("network location must be empty without a trusted resolver: %+v", ctx)
	}
}

func TestAdvisoryOptimizerNeverFabricatesSubscriptionEndpoints(t *testing.T) {
	reader := &telemetry.MockReader{
		Scores: []telemetry.NodeScore{
			{
				NodeID:      "telemetry-only-node",
				Region:      "eu-central",
				ISP:         "MCI",
				Protocol:    "vless",
				Transport:   "xhttp",
				SuccessRate: 0.95,
				AvgRTTMs:    120,
				LastSeen:    time.Now(),
			},
		},
	}
	service := NewDynamicOptimizerService(telemetry.NewOptimizer(reader))
	sub := &SubscriptionData{UserID: "subscriber-identity"}
	client := telemetry.ClientContext{ISP: "MCI", Region: "tehran", Core: "sing-box"}

	body, contentType, reason, err := service.BuildOptimizedSubscription(
		context.Background(), sub, client, "base64",
	)
	if !errors.Is(err, ErrNoCompatibleNodes) {
		t.Fatalf("advisory optimizer must fail closed, got %v", err)
	}
	if body != nil || contentType != "" {
		t.Fatalf("advisory optimizer emitted a subscription body: body=%q contentType=%q", body, contentType)
	}
	if reason == "" {
		t.Fatal("fail-closed response must explain that a verified catalog is required")
	}

	result, geoErr := service.BuildGeoRouted(context.Background(), sub, "sing-box/1.11", "198.51.100.7", "singbox")
	if !errors.Is(geoErr, ErrNoCompatibleNodes) || result != nil {
		t.Fatalf("geo-routed advisory path must not publish fake nodes: result=%+v err=%v", result, geoErr)
	}
}

func TestAdvisoryOptimizerFailsClosedWhenReaderIsUnavailable(t *testing.T) {
	service := NewDynamicOptimizerService(telemetry.NewOptimizer(&telemetry.MockReader{Err: errors.New("database unavailable")}))
	_, _, _, err := service.BuildOptimizedSubscription(
		context.Background(),
		&SubscriptionData{UserID: "subscriber"},
		telemetry.ClientContext{Core: "sing-box"},
		"base64",
	)
	if !errors.Is(err, ErrNoCompatibleNodes) {
		t.Fatalf("reader outage must fail closed to the verified catalog path, got %v", err)
	}
}
