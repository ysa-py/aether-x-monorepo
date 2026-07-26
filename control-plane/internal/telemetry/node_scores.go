package telemetry

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
)

// DefaultNodeScoreWindow is deliberately short: stale reachability data must
// not influence an automatic subscription ordering.
const DefaultNodeScoreWindow = 10 * time.Minute

// ProductionNodeScoreReader reads aggregate, per-node reachability evidence
// from ClickHouse. It never synthesizes endpoint addresses; callers must join
// score NodeID values with the verified operator node catalog.
type ProductionNodeScoreReader struct {
	conn        clickhouse.Conn
	queryTimeout time.Duration
	window      time.Duration
	minSamples  uint64
}

// NewProductionNodeScoreReader opens a real ClickHouse connection for scoring.
// It intentionally returns an error instead of substituting fixture scores when
// a DSN is invalid or the database is unavailable.
func NewProductionNodeScoreReader(
	ctx context.Context,
	dsn string,
) (*ProductionNodeScoreReader, error) {
	if dsn == "" {
		return nil, errors.New("ClickHouse DSN is required for production node scoring")
	}
	opts, err := clickhouse.ParseDSN(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse ClickHouse DSN: %w", err)
	}
	opts.DialTimeout = 3 * time.Second
	opts.MaxOpenConns = 4
	opts.MaxIdleConns = 2
	conn, err := clickhouse.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("open ClickHouse score reader: %w", err)
	}
	pingCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := conn.Ping(pingCtx); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("ping ClickHouse score reader: %w", err)
	}
	return &ProductionNodeScoreReader{
		conn:         conn,
		queryTimeout: 3 * time.Second,
		window:       DefaultNodeScoreWindow,
		minSamples:   20,
	}, nil
}

// Close releases the ClickHouse score-reader connection.
func (r *ProductionNodeScoreReader) Close() error {
	if r == nil || r.conn == nil {
		return nil
	}
	return r.conn.Close()
}

// ReadScores implements NodeScoreReader using only aggregate telemetry from a
// bounded recent window. Empty results are valid evidence: the caller must
// retain a deterministic catalog order rather than inventing score data.
func (r *ProductionNodeScoreReader) ReadScores(
	ctx context.Context,
	isp string,
) ([]NodeScore, error) {
	if r == nil || r.conn == nil {
		return nil, errors.New("production node score reader is not initialized")
	}
	if r.window <= 0 || r.queryTimeout <= 0 || r.minSamples == 0 {
		return nil, errors.New("production node score reader has invalid bounds")
	}
	queryCtx, cancel := context.WithTimeout(ctx, r.queryTimeout)
	defer cancel()

	rows, err := r.conn.Query(
		queryCtx,
		nodeScoreSQL,
		int64(r.window / time.Second),
		isp,
		isp,
		r.minSamples,
	)
	if err != nil {
		return nil, fmt.Errorf("query aggregate node scores: %w", err)
	}
	defer rows.Close()

	scores := make([]NodeScore, 0)
	for rows.Next() {
		var aggregate nodeScoreAggregate
		if err := rows.Scan(
			&aggregate.nodeID,
			&aggregate.protocol,
			&aggregate.averageRTT,
			&aggregate.lossRate,
			&aggregate.rstCount,
			&aggregate.throughputBps,
			&aggregate.lastSeen,
		); err != nil {
			return nil, fmt.Errorf("scan aggregate node score: %w", err)
		}
		score, ok := aggregate.toNodeScore(isp)
		if ok {
			scores = append(scores, score)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate aggregate node scores: %w", err)
	}
	return scores, nil
}

const nodeScoreSQL = `
SELECT
    node_id,
    protocol,
    avg(latency_ms) AS average_rtt,
    avg(packet_loss_rate) AS loss_rate,
    sum(rst_injection_count) AS rst_count,
    avg(throughput_bps) AS throughput_bps,
    max(event_time) AS last_seen
FROM telemetry_events
WHERE event_time >= now() - toIntervalSecond(?)
  AND node_id != ''
  AND (isp_id = ? OR ? = '')
GROUP BY node_id, protocol
HAVING count() >= ?
ORDER BY loss_rate ASC, average_rtt ASC, rst_count ASC
`

type nodeScoreAggregate struct {
	nodeID        string
	protocol      string
	averageRTT    float64
	lossRate      float64
	rstCount      uint64
	throughputBps float64
	lastSeen      time.Time
}

func (a nodeScoreAggregate) toNodeScore(isp string) (NodeScore, bool) {
	if a.nodeID == "" || a.protocol == "" {
		return NodeScore{}, false
	}
	return NodeScore{
		NodeID:        a.nodeID,
		ISP:           isp,
		Protocol:      a.protocol,
		SuccessRate:   clampUnit(1 - a.lossRate),
		AvgRTTMs:      clampUint16(a.averageRTT),
		RSTCount:      clampUint16(float64(a.rstCount)),
		ThroughputBps: maxFloat(a.throughputBps, 0),
		LastSeen:      a.lastSeen.UTC(),
		CapacityLoad:  0,
	}, true
}

func clampUnit(value float64) float64 {
	if value <= 0 {
		return 0
	}
	if value >= 1 {
		return 1
	}
	return value
}

func clampUint16(value float64) uint16 {
	const maxUint16 = 1<<16 - 1
	if value <= 0 {
		return 0
	}
	if value >= maxUint16 {
		return maxUint16
	}
	return uint16(value + 0.5)
}

func maxFloat(left, right float64) float64 {
	if left > right {
		return left
	}
	return right
}

var _ NodeScoreReader = (*ProductionNodeScoreReader)(nil)
