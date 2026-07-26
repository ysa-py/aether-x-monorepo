package subendpoint

import (
	"context"
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

func TestOptimizedNodeConfig(t *testing.T) {
	ns := telemetry.NodeScore{
		NodeID:      "node-fra-01",
		Region:      "eu-central",
		Protocol:    "vless",
		Transport:   "xhttp",
		SuccessRate: 0.95,
	}
	cfg := OptimizedNodeConfig(ns, "user-uuid-123")
	if cfg.ID != "node-fra-01" {
		t.Errorf("expected ID node-fra-01, got %s", cfg.ID)
	}
	if cfg.Protocol != "vless" {
		t.Errorf("expected vless, got %s", cfg.Protocol)
	}
	if cfg.Transport != "xhttp" {
		t.Errorf("expected xhttp, got %s", cfg.Transport)
	}
}

func TestBuildOptimizedSubscription(t *testing.T) {
	reader := &telemetry.MockReader{
		Scores: []telemetry.NodeScore{
			{NodeID: "node-fra-01", Region: "eu-central", ISP: "MCI", Protocol: "vless", Transport: "xhttp", SuccessRate: 0.95, AvgRTTMs: 120, LastSeen: time.Now()},
			{NodeID: "node-tr-01", Region: "tr-central", ISP: "MCI", Protocol: "vless", Transport: "ws", SuccessRate: 0.88, AvgRTTMs: 80, LastSeen: time.Now()},
		},
	}
	opt := telemetry.NewOptimizer(reader)
	svc := NewDynamicOptimizerService(opt)

	sub := &SubscriptionData{
		SubID:     "sub-001",
		UserID:    "user-uuid-123",
		BytesUsed: 1024,
		BytesTotal: 10 * 1024 * 1024 * 1024,
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
		DisplayName: "Aether-X Test",
		SubURL: "https://example.com/sub/token",
	}

	clientCtx := telemetry.ClientContext{
		ISP:    "MCI",
		Region: "tehran",
		Core:   "sing-box",
	}

	body, ct, reason, err := svc.BuildOptimizedSubscription(context.Background(), sub, clientCtx, "base64")
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}
	if len(body) == 0 {
		t.Error("body empty")
	}
	if ct == "" {
		t.Error("content type empty")
	}
	if reason == "" {
		t.Error("reason empty")
	}
	// Body should be base64 encoded (default)
}

func TestBuildGeoRouted(t *testing.T) {
	reader := &telemetry.MockReader{
		Scores: []telemetry.NodeScore{
			{NodeID: "node-fra-01", Region: "eu-central", ISP: "MCI", Protocol: "vless", Transport: "xhttp", SuccessRate: 0.95, AvgRTTMs: 120, LastSeen: time.Now()},
		},
	}
	opt := telemetry.NewOptimizer(reader)
	svc := NewDynamicOptimizerService(opt)

	sub := &SubscriptionData{
		UserID:    "user-123",
		BytesUsed: 0,
		BytesTotal: 50 * 1024 * 1024 * 1024,
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
		SubURL: "https://example.com/sub/abc",
	}

	result, err := svc.BuildGeoRouted(context.Background(), sub, "sing-box/1.8", "1.2.3.4", "singbox")
	if err != nil {
		t.Fatalf("geo routed failed: %v", err)
	}
	if result.Nodes == 0 {
		t.Error("expected nodes >0")
	}
	if result.ContentType != "application/json; charset=utf-8" {
		t.Errorf("expected singbox json, got %s", result.ContentType)
	}
}

func TestClashAndSingboxFormats(t *testing.T) {
	reader := &telemetry.MockReader{
		Scores: []telemetry.NodeScore{
			{NodeID: "node-fra-01", Region: "eu-central", ISP: "MCI", Protocol: "vless", Transport: "ws", SuccessRate: 0.95, AvgRTTMs: 120, LastSeen: time.Now()},
		},
	}
	opt := telemetry.NewOptimizer(reader)
	svc := NewDynamicOptimizerService(opt)

	sub := &SubscriptionData{
		UserID:    "user-123",
		BytesUsed: 0,
		BytesTotal: 10 * 1024 * 1024 * 1024,
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
		SubURL: "https://example.com/sub/abc",
	}

	// sing-box format
	result, _ := svc.BuildGeoRouted(context.Background(), sub, "sing-box", "1.2.3.4", "singbox")
	if result.ContentType != "application/json; charset=utf-8" {
		t.Error("singbox should be json")
	}

	// clash format
	result2, _ := svc.BuildGeoRouted(context.Background(), sub, "clash-meta", "1.2.3.4", "clash")
	if result2.ContentType != "text/yaml; charset=utf-8" {
		t.Error("clash should be yaml")
	}
}
