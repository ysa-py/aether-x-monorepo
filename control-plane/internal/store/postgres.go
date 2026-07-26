package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aether-x/control-plane/internal/model"
)

// PgStore implements SubscriptionStore, NodeStore, and UserStore backed by
// PostgreSQL via pgx/v5 connection pool. All queries use prepared statements
// for safety and performance.
type PgStore struct {
	pool *pgxpool.Pool
}

var _ SessionStore = (*PgStore)(nil)

// NewPgStore creates a new PostgreSQL store from a connection string (DSN).
// The pool is configured with sensible defaults for a high-throughput
// subscription endpoint.
func NewPgStore(ctx context.Context, dsn string) (*PgStore, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse dsn: %w", err)
	}
	cfg.MaxConns = 20
	cfg.MinConns = 4
	cfg.MaxConnLifetime = time.Hour
	cfg.MaxConnIdleTime = 30 * time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connect postgres: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	return &PgStore{pool: pool}, nil
}

// Ping checks the PostgreSQL source of truth with the caller's readiness deadline.
func (s *PgStore) Ping(ctx context.Context) error {
	if s == nil || s.pool == nil {
		return errors.New("PostgreSQL store is not initialized")
	}
	return s.pool.Ping(ctx)
}

// Close releases the connection pool.
func (s *PgStore) Close() {
	if s.pool != nil {
		s.pool.Close()
	}
}

// Migrate runs the schema migration (idempotent).
func (s *PgStore) Migrate(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, SchemaSQL)
	return err
}

// --- SubscriptionStore ---

func (s *PgStore) ByToken(ctx context.Context, subToken string) (*model.Subscription, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT id, user_id, plan_id, bytes_total, bytes_used, expires_at, revoked, sub_token, created_at
		 FROM subscriptions WHERE sub_token = $1 AND revoked = false`, subToken)
	return scanSubscription(row)
}

func (s *PgStore) ByUserID(ctx context.Context, userID string) (*model.Subscription, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT id, user_id, plan_id, bytes_total, bytes_used, expires_at, revoked, sub_token, created_at
		 FROM subscriptions WHERE user_id = $1 AND revoked = false ORDER BY created_at DESC LIMIT 1`, userID)
	return scanSubscription(row)
}

func (s *PgStore) UpdateUsage(ctx context.Context, subID string, bytesDelta int64) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE subscriptions SET bytes_used = GREATEST(0, bytes_used + $1) WHERE id = $2`,
		bytesDelta, subID)
	if err != nil {
		return fmt.Errorf("update usage: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *PgStore) Save(ctx context.Context, sub *model.Subscription) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO subscriptions (id, user_id, plan_id, bytes_total, bytes_used, expires_at, revoked, sub_token, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		 ON CONFLICT (id) DO UPDATE SET
		   bytes_total = EXCLUDED.bytes_total,
		   bytes_used = EXCLUDED.bytes_used,
		   expires_at = EXCLUDED.expires_at,
		   revoked = EXCLUDED.revoked,
		   sub_token = EXCLUDED.sub_token`,
		sub.ID, sub.UserID, sub.PlanID, sub.BytesTotal, sub.BytesUsed,
		sub.ExpiresAt, sub.Revoked, sub.SubToken, sub.CreatedAt)
	return err
}

// --- SessionStore ---

func (s *PgStore) SaveSession(ctx context.Context, session *Session) error {
	if session == nil || session.ID == "" {
		return fmt.Errorf("session is required")
	}
	_, err := s.pool.Exec(ctx,
		`INSERT INTO sessions (
			id, user_id, subscription_id, node_id, protocol, transport, client_ip,
			isp, conn_id, started_at, last_seen_at, bytes_up, bytes_down, active, migrated_count
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15
		) ON CONFLICT (id) DO UPDATE SET
			user_id = EXCLUDED.user_id,
			subscription_id = EXCLUDED.subscription_id,
			node_id = EXCLUDED.node_id,
			protocol = EXCLUDED.protocol,
			transport = EXCLUDED.transport,
			client_ip = EXCLUDED.client_ip,
			isp = EXCLUDED.isp,
			conn_id = EXCLUDED.conn_id,
			last_seen_at = EXCLUDED.last_seen_at,
			bytes_up = EXCLUDED.bytes_up,
			bytes_down = EXCLUDED.bytes_down,
			active = EXCLUDED.active,
			migrated_count = EXCLUDED.migrated_count`,
		session.ID,
		session.UserID,
		session.SubscriptionID,
		session.NodeID,
		session.Protocol,
		session.Transport,
		session.ClientIP,
		session.ISP,
		session.ConnID,
		session.StartedAt,
		session.LastSeenAt,
		session.BytesUp,
		session.BytesDown,
		session.Active,
		session.MigratedCount,
	)
	if err != nil {
		return fmt.Errorf("save session: %w", err)
	}
	return nil
}

func (s *PgStore) GetSession(ctx context.Context, id string) (*Session, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT id, user_id, subscription_id, node_id, protocol, transport, client_ip,
			isp, conn_id, started_at, last_seen_at, bytes_up, bytes_down, active, migrated_count
		 FROM sessions WHERE id = $1`, id)
	return scanSession(row)
}

func (s *PgStore) DeleteSession(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *PgStore) ListActiveByUser(ctx context.Context, userID string) ([]*Session, error) {
	query := `SELECT id, user_id, subscription_id, node_id, protocol, transport, client_ip,
		isp, conn_id, started_at, last_seen_at, bytes_up, bytes_down, active, migrated_count
		FROM sessions WHERE active = true`
	args := []any{}
	if userID != "" {
		query += ` AND user_id = $1`
		args = append(args, userID)
	}
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list active sessions: %w", err)
	}
	defer rows.Close()

	sessions := make([]*Session, 0)
	for rows.Next() {
		session, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		sessions = append(sessions, session)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate active sessions: %w", err)
	}
	return sessions, nil
}

func (s *PgStore) UpdateBytes(ctx context.Context, id string, up, down int64) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE sessions SET bytes_up = $2, bytes_down = $3 WHERE id = $1`,
		id, up, down)
	if err != nil {
		return fmt.Errorf("update session bytes: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *PgStore) RecordMigration(ctx context.Context, id string, newNodeID string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE sessions SET node_id = $2, migrated_count = migrated_count + 1 WHERE id = $1`,
		id, newNodeID)
	if err != nil {
		return fmt.Errorf("record session migration: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// --- NodeStore ---

func (s *PgStore) Active(ctx context.Context) ([]model.Node, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, region, asn_org, capacity, supervisor_addr, healthy
		 FROM nodes WHERE healthy = true ORDER BY region`)
	if err != nil {
		return nil, fmt.Errorf("query nodes: %w", err)
	}
	defer rows.Close()

	var out []model.Node
	for rows.Next() {
		var n model.Node
		if err := rows.Scan(&n.ID, &n.Region, &n.ASNOrg, &n.Capacity, &n.SupervisorAddr, &n.Healthy); err != nil {
			return nil, fmt.Errorf("scan node: %w", err)
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func (s *PgStore) NodeByID(ctx context.Context, id string) (*model.Node, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT id, region, asn_org, capacity, supervisor_addr, healthy
		 FROM nodes WHERE id = $1`, id)
	var n model.Node
	err := row.Scan(&n.ID, &n.Region, &n.ASNOrg, &n.Capacity, &n.SupervisorAddr, &n.Healthy)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("scan node: %w", err)
	}
	return &n, nil
}

// --- UserStore ---

func (s *PgStore) UserByID(ctx context.Context, id string) (*model.User, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT id, email, role, reseller_id, created_at FROM users WHERE id = $1`, id)
	return scanUser(row)
}

func (s *PgStore) UserByEmail(ctx context.Context, email string) (*model.User, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT id, email, role, reseller_id, created_at FROM users WHERE email = $1`, email)
	return scanUser(row)
}

// --- Helpers ---

func scanSubscription(row pgx.Row) (*model.Subscription, error) {
	var sub model.Subscription
	err := row.Scan(
		&sub.ID, &sub.UserID, &sub.PlanID,
		&sub.BytesTotal, &sub.BytesUsed, &sub.ExpiresAt,
		&sub.Revoked, &sub.SubToken, &sub.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("scan subscription: %w", err)
	}
	return &sub, nil
}

func scanSession(row pgx.Row) (*Session, error) {
	var session Session
	err := row.Scan(
		&session.ID,
		&session.UserID,
		&session.SubscriptionID,
		&session.NodeID,
		&session.Protocol,
		&session.Transport,
		&session.ClientIP,
		&session.ISP,
		&session.ConnID,
		&session.StartedAt,
		&session.LastSeenAt,
		&session.BytesUp,
		&session.BytesDown,
		&session.Active,
		&session.MigratedCount,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("scan session: %w", err)
	}
	return &session, nil
}

func scanUser(row pgx.Row) (*model.User, error) {
	var u model.User
	var resellerID *string
	err := row.Scan(&u.ID, &u.Email, &u.Role, &resellerID, &u.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("scan user: %w", err)
	}
	u.ResellerID = resellerID
	return &u, nil
}

// SchemaSQL is the idempotent DDL for the Aether-X schema.
const SchemaSQL = `
CREATE TABLE IF NOT EXISTS users (
    id          TEXT PRIMARY KEY,
    email       TEXT UNIQUE NOT NULL,
    role        TEXT NOT NULL DEFAULT 'user',
    reseller_id TEXT REFERENCES users(id),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS subscriptions (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id),
    plan_id     TEXT NOT NULL DEFAULT 'free',
    bytes_total BIGINT NOT NULL DEFAULT 0,
    bytes_used  BIGINT NOT NULL DEFAULT 0,
    expires_at  TIMESTAMPTZ NOT NULL,
    revoked     BOOLEAN NOT NULL DEFAULT FALSE,
    sub_token   TEXT UNIQUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_subs_token ON subscriptions(sub_token) WHERE revoked = false;
CREATE INDEX IF NOT EXISTS idx_subs_user  ON subscriptions(user_id) WHERE revoked = false;

CREATE TABLE IF NOT EXISTS nodes (
    id             TEXT PRIMARY KEY,
    region         TEXT NOT NULL,
    asn_org        TEXT NOT NULL DEFAULT '',
    capacity       INT NOT NULL DEFAULT 1000,
    supervisor_addr TEXT NOT NULL DEFAULT '',
    healthy        BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE INDEX IF NOT EXISTS idx_nodes_healthy ON nodes(healthy) WHERE healthy = TRUE;

CREATE TABLE IF NOT EXISTS sessions (
    id              TEXT PRIMARY KEY,
    user_id         TEXT NOT NULL REFERENCES users(id),
    subscription_id TEXT NOT NULL DEFAULT '',
    node_id         TEXT NOT NULL DEFAULT '',
    protocol        TEXT NOT NULL DEFAULT '',
    transport       TEXT NOT NULL DEFAULT '',
    client_ip       TEXT NOT NULL DEFAULT '',
    isp             TEXT NOT NULL DEFAULT '',
    conn_id         TEXT NOT NULL DEFAULT '',
    started_at      TIMESTAMPTZ NOT NULL,
    last_seen_at    TIMESTAMPTZ NOT NULL,
    bytes_up        BIGINT NOT NULL DEFAULT 0 CHECK (bytes_up >= 0),
    bytes_down      BIGINT NOT NULL DEFAULT 0 CHECK (bytes_down >= 0),
    active          BOOLEAN NOT NULL DEFAULT TRUE,
    migrated_count  INT NOT NULL DEFAULT 0 CHECK (migrated_count >= 0)
);

CREATE INDEX IF NOT EXISTS idx_sessions_active_user ON sessions(user_id, last_seen_at) WHERE active = TRUE;
`
