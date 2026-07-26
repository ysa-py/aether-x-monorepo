// Package featurizer aggregates the raw telemetry stream into windowed,
// per-(ISP, protocol) feature points that serve as the AI feature store for
// the (offline) training pipeline.
//
// SCOPE (non-duplicate with the data plane): the Rust `LocalDecider` makes a
// REAL-TIME, per-node protocol-switch decision. This Go aggregator instead
// computes HISTORICAL/AGGREGATE statistics across events for AI *training* and
// for cross-ISP dashboards. The two share concepts (a "failure signature") but
// not code paths.
package featurizer

import (
	"sort"
	"sync"
	"time"

	telemetrypb "github.com/aether-x/control-plane/api/gen/go/aether/telemetry/v1"
	"github.com/aether-x/control-plane/internal/telemetry"
)

// FeaturePoint is one row of the AI feature store for a given (ISP, protocol).
type FeaturePoint struct {
	ISP         telemetrypb.IspId
	ASN         uint32
	ProtocolID  string
	SampleCount int
	SuccessRate float64 // [0,1]
	RstRate     float64 // fraction of windowed samples with TCP-RST injection
	TruncRate   float64 // TLS handshake truncation
	DnsRate     float64 // DNS anomaly
	MedianRTTms int32   // median RTT over the window, -1 if unknown
	UpdatedAt   time.Time
}

type sampleKey struct {
	isp      int32
	protocol string
}

type sample struct {
	ts      time.Time
	success bool
	rst     bool
	trunc   bool
	dns     bool
	rttMs   int32
}

// Aggregator keeps a rolling time-window of samples per (ISP, protocol) and can
// snapshot them as feature points. It is safe for concurrent use.
type Aggregator struct {
	mu      sync.Mutex
	window  time.Duration
	samples map[sampleKey][]sample
}

// New constructs an Aggregator that retains samples within `window`.
func New(window time.Duration) *Aggregator {
	return &Aggregator{window: window, samples: make(map[sampleKey][]sample)}
}

// Observe folds one telemetry event into the aggregator. Stale samples for the
// affected key are evicted relative to the event's timestamp.
func (a *Aggregator) Observe(ev telemetry.Event) {
	a.mu.Lock()
	defer a.mu.Unlock()

	k := sampleKey{isp: int32(ev.ISP), protocol: ev.ProtocolID}
	s := sample{
		ts:      ev.TS,
		success: ev.Success || ev.Kind == telemetrypb.EventKind_EVENT_CONNECT_SUCCESS,
		rst:     ev.Kind == telemetrypb.EventKind_EVENT_TCP_RST_INJECTED,
		trunc:   ev.Kind == telemetrypb.EventKind_EVENT_TLS_HANDSHAKE_TRUNCATION,
		dns:     ev.Kind == telemetrypb.EventKind_EVENT_DNS_HIJACK,
		rttMs:   ev.RTTms,
	}
	a.samples[k] = append(a.samples[k], s)
	a.evictLocked(k, ev.TS)
}

// evictLocked drops samples older than (now - window). Caller holds the lock.
func (a *Aggregator) evictLocked(k sampleKey, now time.Time) {
	cutoff := now.Add(-a.window)
	kept := a.samples[k][:0]
	for _, s := range a.samples[k] {
		if !s.ts.Before(cutoff) {
			kept = append(kept, s)
		}
	}
	a.samples[k] = kept
}

// Snapshot returns the current feature point for every active key.
func (a *Aggregator) Snapshot() []FeaturePoint {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]FeaturePoint, 0, len(a.samples))
	for k, ss := range a.samples {
		out = append(out, compute(k, ss))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ISP != out[j].ISP {
			return out[i].ISP < out[j].ISP
		}
		return out[i].ProtocolID < out[j].ProtocolID
	})
	return out
}

// Feature returns the feature point for a single (ISP, protocol), if present.
func (a *Aggregator) Feature(isp telemetrypb.IspId, protocol string) (FeaturePoint, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	k := sampleKey{isp: int32(isp), protocol: protocol}
	ss, ok := a.samples[k]
	if !ok {
		return FeaturePoint{}, false
	}
	return compute(k, ss), true
}

func compute(k sampleKey, ss []sample) FeaturePoint {
	if len(ss) == 0 {
		return FeaturePoint{ISP: telemetrypb.IspId(k.isp), ProtocolID: k.protocol}
	}
	n := len(ss)
	var success, rst, trunc, dns int
	rtts := make([]int32, 0, n)
	latest := ss[0].ts
	for _, s := range ss {
		if s.success {
			success++
		}
		if s.rst {
			rst++
		}
		if s.trunc {
			trunc++
		}
		if s.dns {
			dns++
		}
		if s.rttMs > 0 {
			rtts = append(rtts, s.rttMs)
		}
		if s.ts.After(latest) {
			latest = s.ts
		}
	}
	median := int32(-1)
	if len(rtts) > 0 {
		sort.Slice(rtts, func(i, j int) bool { return rtts[i] < rtts[j] })
		median = rtts[len(rtts)/2]
	}
	return FeaturePoint{
		ISP:         telemetrypb.IspId(k.isp),
		ProtocolID:  k.protocol,
		SampleCount: n,
		SuccessRate: float64(success) / float64(n),
		RstRate:     float64(rst) / float64(n),
		TruncRate:   float64(trunc) / float64(n),
		DnsRate:     float64(dns) / float64(n),
		MedianRTTms: median,
		UpdatedAt:   latest,
	}
}
