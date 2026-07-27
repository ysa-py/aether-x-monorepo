// Package edgehopper implements automated ephemeral edge engine that deploys and cycles
// worker endpoints across public clouds (Cloudflare Workers, Fastly, AWS Lambda)
// within 500ms of detecting target IP drops or TCP RST anomalies.
package edgehopper

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// CloudProvider type
type CloudProvider string

const (
	ProviderCloudflare CloudProvider = "cloudflare-workers"
	ProviderFastly     CloudProvider = "fastly-compute"
	ProviderAWSLambda  CloudProvider = "aws-lambda"
	ProviderVercel     CloudProvider = "vercel-edge"
)

// WorkerEndpoint represents an ephemeral edge worker
type WorkerEndpoint struct {
	ID        string
	Provider  CloudProvider
	URL       string
	Region    string
	CreatedAt time.Time
	Healthy   bool
	RTTMs     uint16
	Requests  int64
}

// HopperEvent for detection
type HopperEvent struct {
	Type      string // "ip_drop", "rst_anomaly", "probe_fail"
	TargetIP  string
	ISP       string
	Timestamp time.Time
}

// EdgeHopper manages cycling worker endpoints
type EdgeHopper struct {
	mu               sync.RWMutex
	endpoints        map[string]*WorkerEndpoint
	providerCounters map[CloudProvider]int
	detections       int64
	hops             int64
	muDetections     sync.Mutex
}

func New() *EdgeHopper {
	return &EdgeHopper{
		endpoints:        make(map[string]*WorkerEndpoint),
		providerCounters: make(map[CloudProvider]int),
	}
}

// DeployNew deploys a new worker endpoint on a provider (mock, real would call cloud API)
func (h *EdgeHopper) DeployNew(ctx context.Context, provider CloudProvider, region string) (*WorkerEndpoint, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.providerCounters[provider]++
	count := h.providerCounters[provider]
	id := fmt.Sprintf("%s-%s-%d-%d", provider, region, count, time.Now().UnixNano()%10000)
	url := fmt.Sprintf("https://%s.aether-x.workers.dev", id)

	ep := &WorkerEndpoint{
		ID:        id,
		Provider:  provider,
		URL:       url,
		Region:    region,
		CreatedAt: time.Now(),
		Healthy:   true,
		RTTMs:     50,
		Requests:  0,
	}
	h.endpoints[id] = ep
	h.hops++
	return ep, nil
}

// HandleDetection reacts within 500ms to IP drop or RST anomaly by deploying new endpoint
func (h *EdgeHopper) HandleDetection(ctx context.Context, ev HopperEvent) (*WorkerEndpoint, time.Duration, error) {
	start := time.Now()

	h.muDetections.Lock()
	h.detections++
	h.muDetections.Unlock()

	// Choose provider based on event and ISP for geo routing
	var provider CloudProvider
	var region string
	switch ev.ISP {
	case "MCI":
		provider = ProviderCloudflare
		region = "eu-central"
	case "Irancell":
		provider = ProviderFastly
		region = "tr-central"
	default:
		provider = ProviderCloudflare
		region = "auto"
	}

	// Round-robin providers for resilience
	if h.hops%3 == 0 {
		provider = ProviderAWSLambda
		region = "us-east"
	}

	ep, err := h.DeployNew(ctx, provider, region)
	if err != nil {
		return nil, time.Since(start), err
	}

	elapsed := time.Since(start)
	// Verify <500ms guarantee
	if elapsed > 500*time.Millisecond {
		// In production, this would be a metric alert, not error
		// But we enforce budget
		return ep, elapsed, fmt.Errorf("hopping exceeded 500ms budget: %v", elapsed)
	}

	return ep, elapsed, nil
}

// MarkHealthy updates endpoint health
func (h *EdgeHopper) MarkHealthy(id string, healthy bool, rttMs uint16) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if ep, ok := h.endpoints[id]; ok {
		ep.Healthy = healthy
		ep.RTTMs = rttMs
	}
}

// BestEndpoint returns healthiest endpoint (lowest RTT)
func (h *EdgeHopper) BestEndpoint() *WorkerEndpoint {
	h.mu.RLock()
	defer h.mu.RUnlock()
	var best *WorkerEndpoint
	for _, ep := range h.endpoints {
		if !ep.Healthy {
			continue
		}
		if best == nil || ep.RTTMs < best.RTTMs {
			best = ep
		}
	}
	return best
}

// ListEndpoints returns all endpoints
func (h *EdgeHopper) ListEndpoints() []*WorkerEndpoint {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]*WorkerEndpoint, 0, len(h.endpoints))
	for _, ep := range h.endpoints {
		cp := *ep
		out = append(out, &cp)
	}
	return out
}

// PruneStale removes endpoints older than ttl
func (h *EdgeHopper) PruneStale(ttl time.Duration) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	cutoff := time.Now().Add(-ttl)
	removed := 0
	for id, ep := range h.endpoints {
		if ep.CreatedAt.Before(cutoff) {
			delete(h.endpoints, id)
			removed++
		}
	}
	return removed
}

func (h *EdgeHopper) Detections() int64 {
	h.muDetections.Lock()
	defer h.muDetections.Unlock()
	return h.detections
}

func (h *EdgeHopper) Hops() int64 {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.hops
}

// HopperStats for metrics
type HopperStats struct {
	TotalEndpoints int
	Healthy        int
	Detections     int64
	Hops           int64
}

func (h *EdgeHopper) Stats() HopperStats {
	h.mu.RLock()
	defer h.mu.RUnlock()
	healthy := 0
	for _, ep := range h.endpoints {
		if ep.Healthy {
			healthy++
		}
	}
	return HopperStats{
		TotalEndpoints: len(h.endpoints),
		Healthy:        healthy,
		Detections:     h.Detections(),
		Hops:           h.hops,
	}
}
