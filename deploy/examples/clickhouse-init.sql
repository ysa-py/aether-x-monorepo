-- Aether-X telemetry table. The control plane also runs EnsureSchema() at
-- startup, so this is a convenience for self-hosted dev nodes.
CREATE TABLE IF NOT EXISTS telemetry_events (
    event_time                    DateTime64(3, 'UTC'),
    node_id                       LowCardinality(String),
    instance_id                   String,
    isp_id                        LowCardinality(String),
    client_id                     UUID,
    protocol                      LowCardinality(String),
    latency_ms                    UInt16,
    packet_loss_rate              Float32,
    rst_injection_count           UInt16,
    throughput_bps                Float64,
    applied_fragmentation_pattern String
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(event_time)
ORDER BY (isp_id, node_id, protocol, event_time);
