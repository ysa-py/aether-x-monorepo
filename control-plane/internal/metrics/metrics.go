// Package metrics defines the Prometheus instrumentation for the Aether-X
// control plane. Metrics are auto-registered with the default registry so the
// standard promhttp.Handler() at /metrics exposes them without extra wiring.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// ActiveSSEClients tracks live dashboard SSE connections.
var ActiveSSEClients = promauto.NewGauge(prometheus.GaugeOpts{
	Name: "aether_active_sse_clients",
	Help: "Live SSE dashboard connections.",
})

// TelemetryEventsTotal counts ingested telemetry events by ISP and protocol.
var TelemetryEventsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "aether_telemetry_events_total",
	Help: "Ingested packet telemetry events.",
}, []string{"isp_id", "protocol"})

// ClickHouseFlushLatency observes the latency of batch persistence writes.
var ClickHouseFlushLatency = promauto.NewHistogram(prometheus.HistogramOpts{
	Name:    "aether_clickhouse_flush_latency_seconds",
	Help:    "Latency of batch persistence writes.",
	Buckets: prometheus.ExponentialBuckets(0.001, 2, 12), // 1ms .. ~4s
})

// RouteDecisionsTotal counts routing decisions (Direct/Proxy/Block).
var RouteDecisionsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "aether_route_decisions_total",
	Help: "Routing decisions by action.",
}, []string{"decision"})
