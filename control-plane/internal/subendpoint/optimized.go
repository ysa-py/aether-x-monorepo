package subendpoint

import (
	"context"
	"fmt"
	"time"

	"github.com/aether-x/control-plane/internal/telemetry"
)

// OptimizedNodeConfig builds NodeConfig from NodeScore
func OptimizedNodeConfig(ns telemetry.NodeScore, userID string) NodeConfig {
	// Map NodeScore to NodeConfig for subscription building
	// Use realistic address formatting
	return NodeConfig{
		ID:       ns.NodeID,
		Address:  fmt.Sprintf("%s.aether-x.example", ns.NodeID),
		Port:     443,
		Protocol: mapProtocol(ns.Protocol),
		UUID:     userID, // user's UUID
		Transport: mapTransport(ns.Transport),
		SNI:      fmt.Sprintf("%s.aether-x.example", ns.NodeID),
		Host:     "www.digikala.com", // front domain for domain fronting
		Path:     fmt.Sprintf("/%s", ns.NodeID),
	}
}

func mapProtocol(p string) string {
	switch p {
	case "hysteria2", "tuic", "tuic-v5":
		// These are transported as vless over quic in subscription for compatibility
		// Real Hysteria2/TUIC configs need special JSON, handled in singbox builder
		return p
	case "vless", "vmess", "trojan", "shadowsocks":
		return p
	default:
		return "vless"
	}
}

func mapTransport(t string) string {
	switch t {
	case "xhttp", "splithttp":
		return "xhttp"
	case "grpc", "ws", "httpupgrade", "quic", "tcp", "kcp", "h2", "http":
		return t
	default:
		return "xhttp"
	}
}

// DynamicOptimizerService wraps telemetry.Optimizer to produce subscription bodies
type DynamicOptimizerService struct {
	optimizer *telemetry.Optimizer
}

func NewDynamicOptimizerService(opt *telemetry.Optimizer) *DynamicOptimizerService {
	return &DynamicOptimizerService{optimizer: opt}
}

// BuildOptimizedSubscription generates subscription body dynamically evaluating ClickHouse telemetry
// Returns body, content-type, and debug reason
func (s *DynamicOptimizerService) BuildOptimizedSubscription(ctx context.Context, sub *SubscriptionData, clientCtx telemetry.ClientContext, format string) ([]byte, string, string, error) {
	profile, err := s.optimizer.Optimize(ctx, clientCtx)
	if err != nil {
		// Fallback to default single node if optimization fails
		return BuildBody(sub, format), "text/plain; charset=utf-8", "fallback - optimization failed: " + err.Error(), nil
	}

	// Build ProxyLinkConfigs from optimized nodes
	var cfgs []ProxyLinkConfig
	for i, ns := range profile.Nodes {
		nodeCfg := OptimizedNodeConfig(ns, sub.UserID)
		// Remark includes geo and score for transparency
		remark := fmt.Sprintf("Aether-X %s [%s] %.0f%%", ns.Region, ns.Transport, ns.SuccessRate*100)
		if i == 0 {
			remark = "⭐ " + remark // best node marked
		}
		cfgs = append(cfgs, ProxyLinkConfig{
			UserID:   sub.UserID,
			Remark:   remark,
			FragPath: "sub",
			Node:     nodeCfg,
		})
	}

	if len(cfgs) == 0 {
		return BuildBody(sub, format), "text/plain; charset=utf-8", "fallback - no optimized nodes", nil
	}

	body, ct := BuildSubscriptionBodyEx(cfgs, format)
	return body, ct, profile.Reason, nil
}

// GeoRoutedProfileResult holds optimized body + metadata for API response
type GeoRoutedProfileResult struct {
	Body        []byte
	ContentType string
	Reason      string
	Nodes       int
	GeneratedAt time.Time
}

// BuildGeoRouted handles the full flow: detect client context from UA/IP, optimize, build
func (s *DynamicOptimizerService) BuildGeoRouted(ctx context.Context, sub *SubscriptionData, userAgent string, clientIP string, format string) (*GeoRoutedProfileResult, error) {
	clientCtx := DetectClientContext(userAgent, clientIP)
	body, ct, reason, err := s.BuildOptimizedSubscription(ctx, sub, clientCtx, format)
	if err != nil {
		return nil, err
	}
	profile, _ := s.optimizer.Optimize(ctx, clientCtx)
	nodes := 0
	if profile != nil {
		nodes = len(profile.Nodes)
	}
	return &GeoRoutedProfileResult{
		Body:        body,
		ContentType: ct,
		Reason:      reason,
		Nodes:       nodes,
		GeneratedAt: time.Now(),
	}, nil
}

// DetectClientContext infers only client-core and platform capabilities from a
// User-Agent. It deliberately does not guess ISP, region, or country from an
// address: an incorrect carrier label would make real ClickHouse scoring look
// precise while selecting from the wrong censorship cohort.
func DetectClientContext(userAgent string, clientIP string) telemetry.ClientContext {
	ctx := telemetry.ClientContext{
		IP: clientIP,
	}

	// Core detection from UA
	uaLower := toLower(userAgent)
	switch {
	case contains(uaLower, "sing-box"), contains(uaLower, "sfa"):
		ctx.Core = "sing-box"
	case contains(uaLower, "clash"), contains(uaLower, "mihomo"):
		ctx.Core = "clash-meta"
	case contains(uaLower, "nekobox"), contains(uaLower, "karing"):
		ctx.Core = "nekobox"
	case contains(uaLower, "shadowrocket"):
		ctx.Core = "shadowrocket"
	case contains(uaLower, "v2ray"), contains(uaLower, "hiddify"):
		ctx.Core = "xray-core"
	default:
		ctx.Core = "sing-box" // default best
	}

	// Platform
	switch {
	case contains(uaLower, "android"):
		ctx.Platform = "android"
	case contains(uaLower, "iphone"), contains(uaLower, "ipad"), contains(uaLower, "ios"):
		ctx.Platform = "ios"
	case contains(uaLower, "windows"):
		ctx.Platform = "windows"
	case contains(uaLower, "mac"), contains(uaLower, "darwin"):
		ctx.Platform = "macos"
	default:
		ctx.Platform = "all"
	}

	// ISP, region, and country remain empty until a trusted edge resolver
	// supplies them. An empty ISP asks the aggregate reader for all verified
	// node evidence rather than silently pretending every user belongs to MCI.

	// Transport preference based on core
	switch ctx.Core {
	case "sing-box", "nekobox":
		ctx.TransportPreference = "xhttp" // newest, best anti-DPI
	case "clash-meta":
		ctx.TransportPreference = "ws"
	default:
		ctx.TransportPreference = "grpc"
	}

	return ctx
}

func toLower(s string) string {
	// avoid importing strings for simple lower
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && indexOf(s, substr) >= 0
}

func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
