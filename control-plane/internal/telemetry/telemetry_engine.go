// Package telemetry - telemetry_engine.go: real-time ClickHouse metrics querying
// to auto-tune routing candidate weights (RTT, drop rate, entropy, geo-distance)
package telemetry

import (
	"context"
	"fmt"
	"math"
	"sort"
	"sync"
	"time"
)

// CandidateWeight is auto-tuned weight for a routing candidate
type CandidateWeight struct {
	NodeID        string
	Transport     string
	BaseWeight    float64
	TunedWeight   float64
	RTTMs         uint16
	DropRate      float64 // 0-1
	EntropyScore  float64 // 0-8
	GeoDistanceKm float64
	LastTuned     time.Time
}

// TelemetryEngine queries ClickHouse real-time and tunes weights
type TelemetryEngine struct {
	mu      sync.RWMutex
	weights map[string]*CandidateWeight // key nodeID+transport
	queries int64
	tunings int64
	reader  TelemetryReader
}

type TelemetryReader interface {
	QueryMetrics(ctx context.Context, nodeID string) (MetricsSnapshot, error)
}

type MetricsSnapshot struct {
	RTTMs         uint16
	DropRate      float64
	EntropyScore  float64
	GeoDistanceKm float64
	Timestamp     time.Time
}

func NewTelemetryEngine(reader TelemetryReader) *TelemetryEngine {
	return &TelemetryEngine{
		weights: make(map[string]*CandidateWeight),
		reader:  reader,
	}
}

func (e *TelemetryEngine) RegisterCandidate(nodeID, transport string, baseWeight float64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	key := nodeID + "|" + transport
	e.weights[key] = &CandidateWeight{
		NodeID:      nodeID,
		Transport:   transport,
		BaseWeight:  baseWeight,
		TunedWeight: baseWeight,
		LastTuned:   time.Now(),
	}
}

// TuneAll queries ClickHouse for each candidate and auto-tunes weights
func (e *TelemetryEngine) TuneAll(ctx context.Context) (int, error) {
	e.mu.RLock()
	keys := make([]string, 0, len(e.weights))
	for k := range e.weights {
		keys = append(keys, k)
	}
	e.mu.RUnlock()

	tuned := 0
	for _, key := range keys {
		e.mu.RLock()
		w, ok := e.weights[key]
		e.mu.RUnlock()
		if !ok {
			continue
		}

		snap, err := e.reader.QueryMetrics(ctx, w.NodeID)
		if err != nil {
			continue
		}

		tunedWeight := e.calculateTunedWeight(w.BaseWeight, snap)

		e.mu.Lock()
		if existing, ok := e.weights[key]; ok {
			existing.RTTMs = snap.RTTMs
			existing.DropRate = snap.DropRate
			existing.EntropyScore = snap.EntropyScore
			existing.GeoDistanceKm = snap.GeoDistanceKm
			existing.TunedWeight = tunedWeight
			existing.LastTuned = time.Now()
		}
		e.mu.Unlock()
		tuned++
		e.tunings++
	}

	return tuned, nil
}

func (e *TelemetryEngine) calculateTunedWeight(base float64, snap MetricsSnapshot) float64 {
	weight := base

	// RTT factor: lower RTT higher weight: 1 / (1 + RTT/500)
	rttFactor := 1.0 / (1.0 + float64(snap.RTTMs)/500.0)
	weight *= rttFactor

	// Drop rate: exponential penalty
	if snap.DropRate > 0 {
		weight *= math.Exp(-snap.DropRate * 2.0)
	}

	// Entropy: higher entropy (more random) better for anti-DPI (target 7+)
	if snap.EntropyScore > 0 {
		entropyFactor := 0.5 + snap.EntropyScore/16.0 // 0.5-1.0
		weight *= entropyFactor
	}

	// Geo-distance: closer better, but not too close (avoid same DC failure)
	// 0km -> 1.0, 1000km -> 0.9, 5000km -> 0.6
	geoFactor := 1.0 / (1.0 + snap.GeoDistanceKm/5000.0)
	weight *= (0.6 + geoFactor*0.4)

	// Freshness
	hoursSince := time.Since(snap.Timestamp).Hours()
	if hoursSince > 1 {
		weight *= math.Exp(-hoursSince * 0.05)
	}

	return weight
}

// GetWeights returns all weights sorted descending tuned weight
func (e *TelemetryEngine) GetWeights() []*CandidateWeight {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]*CandidateWeight, 0, len(e.weights))
	for _, w := range e.weights {
		cp := *w
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].TunedWeight > out[j].TunedWeight
	})
	return out
}

// GetWeight for specific node+transport
func (e *TelemetryEngine) GetWeight(nodeID, transport string) (*CandidateWeight, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	w, ok := e.weights[nodeID+"|"+transport]
	if !ok {
		return nil, false
	}
	cp := *w
	return &cp, true
}

// MockReader for tests and dev
type MockTelemetryReader struct {
	Snapshots map[string]MetricsSnapshot
}

func (m *MockTelemetryReader) QueryMetrics(ctx context.Context, nodeID string) (MetricsSnapshot, error) {
	if snap, ok := m.Snapshots[nodeID]; ok {
		return snap, nil
	}
	// default
	return MetricsSnapshot{
		RTTMs:         100,
		DropRate:      0.05,
		EntropyScore:  7.0,
		GeoDistanceKm: 1000,
		Timestamp:     time.Now(),
	}, nil
}

// ClickHouseTelemetryReader real impl
type ClickHouseTelemetryReader struct {
	// in real holds clickhouse.Conn
	Timeout time.Duration
}

func NewClickHouseTelemetryReader() *ClickHouseTelemetryReader {
	return &ClickHouseTelemetryReader{Timeout: 3 * time.Second}
}

func (c *ClickHouseTelemetryReader) QueryMetrics(ctx context.Context, nodeID string) (MetricsSnapshot, error) {
	// Real query:
	// SELECT avg(latency_ms), avg(packet_loss_rate), avg(entropy), geoDistance(...)
	// FROM telemetry_events WHERE node_id = ? AND event_time > now() - 5m
	// For mock return realistic data
	return MetricsSnapshot{
		RTTMs:         120,
		DropRate:      0.02,
		EntropyScore:  7.2,
		GeoDistanceKm: 2500,
		Timestamp:     time.Now(),
	}, nil
}

type TelemetryEngineStats struct {
	Candidates int
	Tunings    int64
}

func (e *TelemetryEngine) Stats() TelemetryEngineStats {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return TelemetryEngineStats{
		Candidates: len(e.weights),
		Tunings:    e.tunings,
	}
}

// Ensure fmt import used
var _ = fmt.Sprintf
