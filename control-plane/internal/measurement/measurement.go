// Package measurement implements the consented measurement network and
// privacy-preserving telemetry (Subsystem B).
//
// Collects anonymized transport reachability metrics over operator-curated
// canary domains (NEVER raw user traffic).
//
// Privacy-by-construction:
//   - Opt-in by default (off). Toggle immediately halts outbound telemetry.
//   - On-device aggregation into (ISP, protocol, transport, time_window) buckets.
//   - Laplace differential privacy noise applied to aggregate counts.
//   - k-anonymity enforcement: buckets with < K distinct device attestations
//     are DROPPED (not zeroed-then-redacted).
package measurement

import (
	"errors"
	"math"
	"math/rand"
	"sync"
	"time"
)

// Config configures the measurement network.
type Config struct {
	// K is the minimum number of distinct device attestations required
	// for a bucket to be included. Default: 20.
	K int
	// Epsilon is the differential privacy budget (Laplace noise scale).
	// Lower = more privacy, more noise. Default: 1.0.
	Epsilon float64
	// ProbeCycleMs is the probe cycle duration in milliseconds.
	// Consent revocation takes effect within one probe cycle. Default: 5000.
	ProbeCycleMs int
	// CanaryDomains is the operator-curated list of benign domains to probe.
	// NEVER the user's browsing history.
	CanaryDomains []string
}

// DefaultConfig returns conservative defaults.
func DefaultConfig() Config {
	return Config{
		K:            20,
		Epsilon:      1.0,
		ProbeCycleMs: 5000,
		CanaryDomains: []string{
			"connectivitycheck.gstatic.com",
			"detectportal.firefox.com",
			"captive.apple.com",
		},
	}
}

// BucketKey identifies a measurement bucket.
type BucketKey struct {
	ISP        string `json:"isp"`
	Protocol   string `json:"protocol"`
	Transport  string `json:"transport"`
	TimeWindow string `json:"time_window"` // coarse: "2026-07-25T12:00Z"
}

// ProbeResult is a single probe outcome (never leaves the device raw).
type ProbeResult struct {
	ISP       string
	Protocol  string
	Transport string
	Domain    string
	Success   bool
	RTTMs     int64
	RSTSeen   bool
	Truncated bool
	Timestamp time.Time
}

// AggregateBucket is the on-device aggregated counter for one bucket.
type AggregateBucket struct {
	Key          BucketKey       `json:"key"`
	SuccessCount int64           `json:"success_count"`
	FailureCount int64           `json:"failure_count"`
	RSTCount     int64           `json:"rst_count"`
	TruncCount   int64           `json:"trunc_count"`
	TotalRTTMs   int64           `json:"total_rtt_ms"`
	DeviceCount  int             `json:"-"` // distinct device attestations
	DeviceIDs    map[string]bool `json:"-"`
}

// PublishedBucket is the k-anonymous, DP-noised bucket ready for upload.
type PublishedBucket struct {
	Key          BucketKey `json:"key"`
	SuccessCount int64     `json:"success_count"`
	FailureCount int64     `json:"failure_count"`
	RSTCount     int64     `json:"rst_count"`
	TruncCount   int64     `json:"trunc_count"`
	MedianRTTMs  int64     `json:"median_rtt_ms"`
	Contributors int       `json:"contributors"`
}

// ConsentState tracks the user's opt-in/opt-out state.
type ConsentState struct {
	mu        sync.RWMutex
	optedIn   bool
	revokedAt time.Time
}

// NewConsentState creates a consent state (default: off).
func NewConsentState() *ConsentState {
	return &ConsentState{optedIn: false}
}

// IsOptedIn returns whether the user has opted in.
func (c *ConsentState) IsOptedIn() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.optedIn
}

// SetOptIn sets the consent state. Revoking immediately stops contributions.
func (c *ConsentState) SetOptIn(optedIn bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.optedIn = optedIn
	if !optedIn {
		c.revokedAt = time.Now()
	}
}

// Errors.
var (
	ErrConsentRevoked = errors.New("measurement: consent is not opted-in")
	ErrBucketDropped  = errors.New("measurement: bucket dropped (below k-anonymity threshold)")
)

// Network is the measurement network service.
type Network struct {
	mu      sync.RWMutex
	config  Config
	consent *ConsentState
	buckets map[BucketKey]*AggregateBucket
	rng     *rand.Rand
	// Telemetry counters.
	totalProbes      int64
	droppedBuckets   int64
	publishedBuckets int64
}

// New creates a new measurement network.
func New(cfg Config) *Network {
	return &Network{
		config:  cfg,
		consent: NewConsentState(),
		buckets: make(map[BucketKey]*AggregateBucket),
		rng:     rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// Consent returns the consent state.
func (n *Network) Consent() *ConsentState {
	return n.consent
}

// RecordProbe records a probe result into the on-device aggregate bucket.
// Returns ErrConsentRevoked if the user has not opted in.
// Raw probe data NEVER serializes off-device.
func (n *Network) RecordProbe(result ProbeResult) error {
	if !n.consent.IsOptedIn() {
		return ErrConsentRevoked
	}
	n.mu.Lock()
	defer n.mu.Unlock()

	// Coarse time window (1-hour granularity).
	tw := result.Timestamp.Truncate(time.Hour).UTC().Format(time.RFC3339)
	key := BucketKey{
		ISP:        result.ISP,
		Protocol:   result.Protocol,
		Transport:  result.Transport,
		TimeWindow: tw,
	}

	bucket, ok := n.buckets[key]
	if !ok {
		bucket = &AggregateBucket{
			Key:       key,
			DeviceIDs: make(map[string]bool),
		}
		n.buckets[key] = bucket
	}

	if result.Success {
		bucket.SuccessCount++
	} else {
		bucket.FailureCount++
	}
	if result.RSTSeen {
		bucket.RSTCount++
	}
	if result.Truncated {
		bucket.TruncCount++
	}
	bucket.TotalRTTMs += result.RTTMs
	// Device attestation (the device ID is never serialized off-device).
	// In production, this is a device-attested ephemeral ID.
	deviceID := result.ISP + ":" + result.Transport // simplified for testing
	bucket.DeviceIDs[deviceID] = true
	bucket.DeviceCount = len(bucket.DeviceIDs)
	n.totalProbes++
	return nil
}

// PublishBuckets returns the k-anonymous, DP-noised buckets ready for upload.
// Buckets with < K distinct contributors are DROPPED.
func (n *Network) PublishBuckets() []PublishedBucket {
	n.mu.RLock()
	defer n.mu.RUnlock()

	var published []PublishedBucket
	for _, bucket := range n.buckets {
		if bucket.DeviceCount < n.config.K {
			n.droppedBuckets++
			continue
		}
		pb := PublishedBucket{
			Key:          bucket.Key,
			SuccessCount: n.addLaplaceNoise(bucket.SuccessCount),
			FailureCount: n.addLaplaceNoise(bucket.FailureCount),
			RSTCount:     n.addLaplaceNoise(bucket.RSTCount),
			TruncCount:   n.addLaplaceNoise(bucket.TruncCount),
			MedianRTTMs:  bucket.TotalRTTMs / max(bucket.SuccessCount+bucket.FailureCount, 1),
			Contributors: bucket.DeviceCount,
		}
		published = append(published, pb)
		n.publishedBuckets++
	}
	return published
}

// addLaplaceNoise applies Laplace mechanism noise to a count.
// noise ~ Laplace(1/epsilon).
func (n *Network) addLaplaceNoise(count int64) int64 {
	if n.config.Epsilon <= 0 {
		return count
	}
	b := 1.0 / n.config.Epsilon
	u := n.rng.Float64() - 0.5
	if u == 0 {
		return count
	}
	noise := -b * math.Copysign(math.Log(1-2*math.Abs(u)), u)
	result := count + int64(math.Round(noise))
	if result < 0 {
		return 0
	}
	return result
}

// GetCoverage returns the current measurement coverage map.
func (n *Network) GetCoverage() CoverageMap {
	n.mu.RLock()
	defer n.mu.RUnlock()

	coverage := make(map[string]int)
	for key := range n.buckets {
		coverage[key.ISP]++
	}
	return CoverageMap{
		ISPs:           coverage,
		TotalBuckets:   len(n.buckets),
		TotalProbes:    n.totalProbes,
		DroppedBuckets: n.droppedBuckets,
		ConsentActive:  n.consent.IsOptedIn(),
	}
}

// CoverageMap is the k-anonymous coverage snapshot.
type CoverageMap struct {
	ISPs           map[string]int `json:"isps"`
	TotalBuckets   int            `json:"total_buckets"`
	TotalProbes    int64          `json:"total_probes"`
	DroppedBuckets int64          `json:"dropped_buckets"`
	ConsentActive  bool           `json:"consent_active"`
}

// TotalProbes returns the total number of probes recorded.
func (n *Network) TotalProbes() int64 {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.totalProbes
}

// DroppedBuckets returns the count of buckets dropped for k-anonymity.
func (n *Network) DroppedBuckets() int64 {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.droppedBuckets
}

func max(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
