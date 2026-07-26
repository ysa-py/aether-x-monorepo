package subendpoint

import (
	"context"
	"time"

	"github.com/aether-x/control-plane/internal/telemetry"
)

// DynamicOptimizerService is retained as an advisory compatibility seam for
// callers that still construct telemetry.Optimizer directly. It deliberately
// cannot publish subscriptions: score records have no operator-verified
// address, credential, SNI, or client allow-list. Production publication is
// provided by TelemetryCatalogSubscriptionService, which can reorder only an
// already-verified catalog.
type DynamicOptimizerService struct {
	optimizer *telemetry.Optimizer
}

// NewDynamicOptimizerService creates an advisory-only optimizer. New
// production code must use NewTelemetryCatalogSubscriptionService with a
// ReloadingCatalogSubscriptionService instead.
func NewDynamicOptimizerService(opt *telemetry.Optimizer) *DynamicOptimizerService {
	return &DynamicOptimizerService{optimizer: opt}
}

// BuildOptimizedSubscription computes score evidence only long enough to
// confirm whether telemetry is available, then fails closed. NodeScore contains
// aggregate reachability data, not endpoint material, and must never be turned
// into a fabricated address or a placeholder subscription link.
func (s *DynamicOptimizerService) BuildOptimizedSubscription(
	ctx context.Context,
	sub *SubscriptionData,
	clientCtx telemetry.ClientContext,
	_ string,
) ([]byte, string, string, error) {
	if s == nil || s.optimizer == nil {
		return nil, "", "telemetry optimizer is unavailable; verified catalog required", ErrNoCompatibleNodes
	}
	if sub == nil || sub.UserID == "" {
		return nil, "", "subscription identity is required", ErrNoCompatibleNodes
	}
	if _, err := s.optimizer.Optimize(ctx, clientCtx); err != nil {
		return nil, "", "telemetry optimizer unavailable; verified catalog required", ErrNoCompatibleNodes
	}
	return nil, "", "telemetry scores are advisory; verified catalog required for endpoint publication", ErrNoCompatibleNodes
}

// GeoRoutedProfileResult holds a rendered verified-catalog body plus metadata.
type GeoRoutedProfileResult struct {
	Body        []byte
	ContentType string
	Reason      string
	Nodes       int
	GeneratedAt time.Time
}

// BuildGeoRouted is intentionally fail-closed for the advisory optimizer. A
// caller must use CatalogSubscriptionService or
// TelemetryCatalogSubscriptionService to publish standard client configs.
func (s *DynamicOptimizerService) BuildGeoRouted(
	ctx context.Context,
	sub *SubscriptionData,
	userAgent string,
	clientIP string,
	format string,
) (*GeoRoutedProfileResult, error) {
	clientCtx := DetectClientContext(userAgent, clientIP)
	_, _, _, err := s.BuildOptimizedSubscription(ctx, sub, clientCtx, format)
	if err != nil {
		return nil, err
	}
	return nil, ErrNoCompatibleNodes
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
		ctx.Core = "sing-box"
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
		ctx.TransportPreference = "xhttp"
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
