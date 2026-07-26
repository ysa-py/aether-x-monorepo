package subendpoint

import (
	"context"
	"math"
	"sort"
	"time"

	"github.com/aether-x/control-plane/internal/telemetry"
)

// CatalogScoreReader is intentionally narrow: it supplies aggregate node
// measurements only. It cannot create an endpoint, alter credentials, or
// bypass the verified catalog allow-list.
type CatalogScoreReader interface {
	ReadScores(ctx context.Context, isp string) ([]telemetry.NodeScore, error)
}

// TelemetryCatalogSubscriptionService adds a real aggregate-score overlay to
// the reloading verified catalog. On any reader error or empty result it serves
// the deterministic catalog order, preserving availability without inventing
// measurements.
type TelemetryCatalogSubscriptionService struct {
	catalog *ReloadingCatalogSubscriptionService
	reader  CatalogScoreReader
}

// NewTelemetryCatalogSubscriptionService constructs a scored standard-client
// publisher. Both dependencies are mandatory because scoring without a real
// catalog would recreate the fabricated-endpoint problem this package avoids.
func NewTelemetryCatalogSubscriptionService(
	catalog *ReloadingCatalogSubscriptionService,
	reader CatalogScoreReader,
) (*TelemetryCatalogSubscriptionService, error) {
	if catalog == nil || reader == nil {
		return nil, ErrNoCompatibleNodes
	}
	return &TelemetryCatalogSubscriptionService{catalog: catalog, reader: reader}, nil
}

// BuildGeoRouted publishes only verified catalog configs. Fresh ClickHouse
// score data may reorder those configs; it can never add a new node. A scoring
// failure intentionally retains the deterministic baseline order.
func (s *TelemetryCatalogSubscriptionService) BuildGeoRouted(
	ctx context.Context,
	sub *SubscriptionData,
	userAgent string,
	_ string,
	format string,
) (*GeoRoutedProfileResult, error) {
	return s.BuildGeoRoutedWithContext(
		ctx,
		sub,
		DetectClientContext(userAgent, ""),
		format,
	)
}

// BuildGeoRoutedWithContext uses attribution only when the API boundary has
// resolved it through a trusted proxy. It cannot add a non-catalog endpoint.
func (s *TelemetryCatalogSubscriptionService) BuildGeoRoutedWithContext(
	ctx context.Context,
	sub *SubscriptionData,
	client telemetry.ClientContext,
	format string,
) (*GeoRoutedProfileResult, error) {
	catalog := s.catalog.snapshotCatalog()
	if catalog == nil {
		return nil, ErrNoCompatibleNodes
	}
	configs, err := catalogConfigsFor(catalog, sub, client.Core)
	if err != nil {
		return nil, err
	}

	reason := "verified operator node catalog; deterministic baseline order"
	if scores, scoreErr := s.reader.ReadScores(ctx, client.ISP); scoreErr == nil && len(scores) > 0 {
		if scored := reorderVerifiedConfigs(configs, scores); scored > 0 {
			reason = "verified operator node catalog; reordered using aggregate ClickHouse reachability scores"
		}
	} else if scoreErr != nil {
		reason = "verified operator node catalog; telemetry score reader unavailable, using deterministic baseline order"
	}

	body, contentType := BuildSubscriptionBodyEx(configs, format)
	return &GeoRoutedProfileResult{
		Body:        body,
		ContentType: contentType,
		Reason:      reason,
		Nodes:       len(configs),
		GeneratedAt: time.Now().UTC(),
	}, nil
}

func reorderVerifiedConfigs(configs []ProxyLinkConfig, scores []telemetry.NodeScore) int {
	byNodeID := make(map[string]float64, len(scores))
	for _, score := range scores {
		if score.NodeID == "" {
			continue
		}
		candidate := aggregateScore(score)
		if current, exists := byNodeID[score.NodeID]; !exists || candidate > current {
			byNodeID[score.NodeID] = candidate
		}
	}

	scored := 0
	for _, config := range configs {
		if _, exists := byNodeID[config.Node.ID]; exists {
			scored++
		}
	}
	if scored == 0 {
		return 0
	}

	// Stable sorting leaves catalog order unchanged for ties and for nodes with
	// no current evidence. This is the deterministic floor during sparse data.
	sort.SliceStable(configs, func(left, right int) bool {
		leftScore, leftOK := byNodeID[configs[left].Node.ID]
		rightScore, rightOK := byNodeID[configs[right].Node.ID]
		if leftOK != rightOK {
			return leftOK
		}
		return leftScore > rightScore
	})
	return scored
}

func aggregateScore(score telemetry.NodeScore) float64 {
	success := clampScore(score.SuccessRate)
	rtt := 1 / (1 + float64(score.AvgRTTMs)/500)
	rst := math.Exp(-float64(score.RSTCount) * 0.1)
	throughput := 1.0
	if score.ThroughputBps > 0 {
		throughput += math.Min(score.ThroughputBps/1e9, 0.15)
	}
	return success * rtt * rst * throughput
}

func clampScore(value float64) float64 {
	if value <= 0 {
		return 0
	}
	if value >= 1 {
		return 1
	}
	return value
}

var _ interface {
	BuildGeoRouted(context.Context, *SubscriptionData, string, string, string) (*GeoRoutedProfileResult, error)
} = (*TelemetryCatalogSubscriptionService)(nil)
