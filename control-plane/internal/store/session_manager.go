// Package store - Enhanced session state management with Postgres/Redis and auto-failover
package store

import (
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// Session represents a client connection session with QUIC migration support
type Session struct {
	ID             string    `json:"id"`
	UserID         string    `json:"user_id"`
	SubscriptionID string    `json:"subscription_id"`
	NodeID         string    `json:"node_id"`
	Protocol       string    `json:"protocol"`  // vless, hysteria2, tuic, etc
	Transport      string    `json:"transport"` // xhttp, grpc, quic, etc
	ClientIP       string    `json:"client_ip"`
	ISP            string    `json:"isp"`
	ConnID         string    `json:"conn_id"` // QUIC Connection ID for migration
	StartedAt      time.Time `json:"started_at"`
	LastSeenAt     time.Time `json:"last_seen_at"`
	BytesUp        int64     `json:"bytes_up"`
	BytesDown      int64     `json:"bytes_down"`
	Active         bool      `json:"active"`
	MigratedCount  int       `json:"migrated_count"` // QUIC migration count
}

// SessionManager handles session state with Postgres as source of truth + Redis cache + auto-failover
type SessionManager struct {
	redis  *redis.Client
	pg     SessionStore // Postgres-backed store
	// Fixed lock striping serializes updates per session without an unbounded
	// lock map. This prevents concurrent heartbeat/migration writes from
	// resurrecting stale node state during a failover.
	stripes [64]sync.Mutex
}

type SessionStore interface {
	SaveSession(ctx context.Context, s *Session) error
	GetSession(ctx context.Context, id string) (*Session, error)
	DeleteSession(ctx context.Context, id string) error
	ListActiveByUser(ctx context.Context, userID string) ([]*Session, error)
	UpdateBytes(ctx context.Context, id string, up, down int64) error
	RecordMigration(ctx context.Context, id string, newNodeID string) error
}

// NewSessionManager creates manager with Redis + Postgres
func NewSessionManager(redisAddr string, pgStore SessionStore) *SessionManager {
	rdb := redis.NewClient(&redis.Options{
		Addr:         redisAddr,
		PoolSize:     20,
		MinIdleConns: 5,
		ReadTimeout:  100 * time.Millisecond,
		WriteTimeout: 100 * time.Millisecond,
	})
	return &SessionManager{redis: rdb, pg: pgStore}
}

// Close releases the Redis cache client. The durable PostgreSQL store is owned
// by the control-plane bootstrap and is closed separately after readiness and
// request handling have stopped.
func (m *SessionManager) Close() error {
	if m == nil || m.redis == nil {
		return nil
	}
	return m.redis.Close()
}

// RedisPing checks the cache dependency with the caller's readiness deadline.
func (m *SessionManager) RedisPing(ctx context.Context) error {
	if m == nil || m.redis == nil {
		return fmt.Errorf("Redis session cache is not initialized")
	}
	return m.redis.Ping(ctx).Err()
}

func (m *SessionManager) requireStore() error {
	if m == nil {
		return fmt.Errorf("session manager is not initialized")
	}
	if m.pg == nil {
		return fmt.Errorf("durable session store is not initialized")
	}
	return nil
}

func (m *SessionManager) sessionLock(id string) *sync.Mutex {
	hasher := fnv.New32a()
	_, _ = hasher.Write([]byte(id))
	return &m.stripes[int(hasher.Sum32())%len(m.stripes)]
}

// CreateSession stores session in both Redis (fast) and Postgres (durable)
func (m *SessionManager) CreateSession(ctx context.Context, s *Session) error {
	if err := m.requireStore(); err != nil {
		return err
	}
	if s == nil || strings.TrimSpace(s.ID) == "" || strings.TrimSpace(s.UserID) == "" {
		return fmt.Errorf("session ID and user ID are required")
	}
	lock := m.sessionLock(s.ID)
	lock.Lock()
	defer lock.Unlock()

	s.StartedAt = time.Now().UTC()
	s.LastSeenAt = s.StartedAt
	s.Active = true

	// Write to Postgres first (source of truth)
	if err := m.pg.SaveSession(ctx, s); err != nil {
		return fmt.Errorf("pg save: %w", err)
	}

	// Then cache in Redis when available (best effort).
	if m.redis != nil {
		data, _ := json.Marshal(s)
		_ = m.redis.Set(ctx, sessionKey(s.ID), data, 24*time.Hour).Err()
		_ = m.redis.SAdd(ctx, userSessionsKey(s.UserID), s.ID).Err()
		_ = m.redis.Expire(ctx, userSessionsKey(s.UserID), 24*time.Hour).Err()
	}

	return nil
}

// GetSession read-through: Redis -> Postgres
func (m *SessionManager) GetSession(ctx context.Context, id string) (*Session, error) {
	if err := m.requireStore(); err != nil {
		return nil, err
	}
	// Try Redis when the optional cache is configured.
	if m.redis != nil {
		if data, err := m.redis.Get(ctx, sessionKey(id)).Bytes(); err == nil {
			var s Session
			if json.Unmarshal(data, &s) == nil {
				return &s, nil
			}
		}
	}
	// Fallback to Postgres.
	s, err := m.pg.GetSession(ctx, id)
	if err != nil {
		return nil, err
	}
	// Populate Redis when available.
	if m.redis != nil {
		if data, err := json.Marshal(s); err == nil {
			_ = m.redis.Set(ctx, sessionKey(id), data, 24*time.Hour).Err()
		}
	}
	return s, nil
}

// Heartbeat updates last_seen and handles auto-failover detection
func (m *SessionManager) Heartbeat(ctx context.Context, id string, bytesUp, bytesDown int64) error {
	if err := m.requireStore(); err != nil {
		return err
	}
	if bytesUp < 0 || bytesDown < 0 {
		return fmt.Errorf("session byte counters must be non-negative")
	}
	lock := m.sessionLock(id)
	lock.Lock()
	defer lock.Unlock()

	s, err := m.GetSession(ctx, id)
	if err != nil {
		return err
	}
	if bytesUp < s.BytesUp || bytesDown < s.BytesDown {
		return fmt.Errorf("session byte counters may not decrease")
	}
	s.LastSeenAt = time.Now().UTC()
	s.BytesUp = bytesUp
	s.BytesDown = bytesDown

	// Update Postgres
	if err := m.pg.SaveSession(ctx, s); err != nil {
		return err
	}
	if err := m.pg.UpdateBytes(ctx, id, bytesUp, bytesDown); err != nil {
		// non-fatal
	}

	if m.redis != nil {
		data, _ := json.Marshal(s)
		_ = m.redis.Set(ctx, sessionKey(id), data, 24*time.Hour).Err()
	}
	return nil
}

// MigrateSession records a peer-supported native QUIC migration (TUIC / Hysteria2).
// It preserves control-plane session state after the transport peers have
// validated their own connection migration; it does not and cannot splice an
// arbitrary TCP stream between independent endpoints.
func (m *SessionManager) MigrateSession(ctx context.Context, id string, newNodeID string, newClientIP string) error {
	if err := m.requireStore(); err != nil {
		return err
	}
	newNodeID = strings.TrimSpace(newNodeID)
	if newNodeID == "" {
		return fmt.Errorf("migration target node is required")
	}
	lock := m.sessionLock(id)
	lock.Lock()
	defer lock.Unlock()

	s, err := m.GetSession(ctx, id)
	if err != nil {
		return err
	}
	if !s.Active {
		return fmt.Errorf("cannot migrate inactive session")
	}
	if !supportsNativeQUICMigration(s.Protocol) || strings.TrimSpace(s.ConnID) == "" {
		return fmt.Errorf("transparent migration requires a native QUIC session with a connection ID")
	}
	if s.NodeID == newNodeID {
		return nil
	}

	s.NodeID = newNodeID
	if strings.TrimSpace(newClientIP) != "" {
		s.ClientIP = newClientIP
	}
	s.MigratedCount++
	s.LastSeenAt = time.Now().UTC()

	// Record migration in Postgres for audit
	if err := m.pg.RecordMigration(ctx, id, newNodeID); err != nil {
		return err
	}
	if err := m.pg.SaveSession(ctx, s); err != nil {
		return err
	}

	// Update Redis when available.
	if m.redis != nil {
		data, _ := json.Marshal(s)
		_ = m.redis.Set(ctx, sessionKey(id), data, 24*time.Hour).Err()
	}

	// A caller may emit an aggregate migration event after this durable state
	// transition. No user payload or destination metadata is logged here.
	return nil
}

// CloseSession marks inactive and cleans Redis
func (m *SessionManager) CloseSession(ctx context.Context, id string) error {
	if err := m.requireStore(); err != nil {
		return err
	}
	lock := m.sessionLock(id)
	lock.Lock()
	defer lock.Unlock()

	s, err := m.GetSession(ctx, id)
	if err != nil {
		return err
	}
	s.Active = false
	if err := m.pg.SaveSession(ctx, s); err != nil {
		return err
	}
	if m.redis != nil {
		_ = m.redis.Del(ctx, sessionKey(id)).Err()
		if s.UserID != "" {
			_ = m.redis.SRem(ctx, userSessionsKey(s.UserID), id).Err()
		}
	}
	return m.pg.DeleteSession(ctx, id)
}

func supportsNativeQUICMigration(protocol string) bool {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "hysteria2", "tuic", "tuic-v5":
		return true
	default:
		return false
	}
}

// AutoFailover detects stale peer-migratable QUIC sessions and records a
// deterministic candidate transition. Stream/TCP sessions are deliberately not
// presented as transparently migrated: their application/proxy layer must
// reconnect using its own semantics.
func (m *SessionManager) AutoFailover(ctx context.Context, userID string, healthyNodeIDs []string) (int, error) {
	if err := m.requireStore(); err != nil {
		return 0, err
	}
	sessions, err := m.pg.ListActiveByUser(ctx, userID)
	if err != nil {
		return 0, err
	}

	migrated := 0
	cutoff := time.Now().Add(-2 * time.Minute)
	for _, s := range sessions {
		if !supportsNativeQUICMigration(s.Protocol) || strings.TrimSpace(s.ConnID) == "" {
			continue
		}
		if s.LastSeenAt.Before(cutoff) {
			newNode, found := selectFailoverNode(s.ID, s.NodeID, healthyNodeIDs)
			if found {
				if err := m.MigrateSession(ctx, s.ID, newNode, s.ClientIP); err == nil {
					migrated++
				}
			}
		}
	}
	return migrated, nil
}

// selectFailoverNode chooses a stable destination using rendezvous-style hashing.
// It avoids stampeding every stale session onto the first healthy node while
// remaining deterministic for retries with the same healthy set.
func selectFailoverNode(sessionID, currentNode string, candidates []string) (string, bool) {
	unique := make(map[string]struct{}, len(candidates))
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		if candidate != "" {
			unique[candidate] = struct{}{}
		}
	}
	nodes := make([]string, 0, len(unique))
	for node := range unique {
		if node != currentNode {
			nodes = append(nodes, node)
		}
	}
	if len(nodes) == 0 {
		return "", false
	}
	sort.Strings(nodes)
	best := nodes[0]
	bestScore := uint32(0)
	for _, node := range nodes {
		hasher := fnv.New32a()
		_, _ = hasher.Write([]byte(sessionID))
		_, _ = hasher.Write([]byte("|"))
		_, _ = hasher.Write([]byte(node))
		score := hasher.Sum32()
		if score > bestScore {
			best = node
			bestScore = score
		}
	}
	return best, true
}

// CountActive returns active session count for user (for device limiting)
func (m *SessionManager) CountActive(ctx context.Context, userID string) (int, error) {
	if err := m.requireStore(); err != nil {
		return 0, err
	}
	// Try Redis set count first when the cache is configured.
	if m.redis != nil {
		if cnt, err := m.redis.SCard(ctx, userSessionsKey(userID)).Result(); err == nil {
			return int(cnt), nil
		}
	}
	// Fallback to Postgres
	sessions, err := m.pg.ListActiveByUser(ctx, userID)
	if err != nil {
		return 0, err
	}
	return len(sessions), nil
}

func sessionKey(id string) string {
	return fmt.Sprintf("aether:session:%s", id)
}

func userSessionsKey(userID string) string {
	return fmt.Sprintf("aether:user_sessions:%s", userID)
}

// MemSessionStore in-memory for tests/dev
type MemSessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*Session
}

func NewMemSessionStore() *MemSessionStore {
	return &MemSessionStore{sessions: make(map[string]*Session)}
}

func (m *MemSessionStore) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.sessions)
}

func (m *MemSessionStore) SaveSession(ctx context.Context, s *Session) error {
	if s == nil || s.ID == "" {
		return fmt.Errorf("session is required")
	}
	cp := *s
	m.mu.Lock()
	m.sessions[s.ID] = &cp
	m.mu.Unlock()
	return nil
}

func (m *MemSessionStore) GetSession(ctx context.Context, id string) (*Session, error) {
	m.mu.RLock()
	s, ok := m.sessions[id]
	if !ok {
		m.mu.RUnlock()
		return nil, fmt.Errorf("session not found: %s", id)
	}
	cp := *s
	m.mu.RUnlock()
	return &cp, nil
}

func (m *MemSessionStore) DeleteSession(ctx context.Context, id string) error {
	m.mu.Lock()
	delete(m.sessions, id)
	m.mu.Unlock()
	return nil
}

func (m *MemSessionStore) ListActiveByUser(ctx context.Context, userID string) ([]*Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []*Session
	for _, s := range m.sessions {
		if s.UserID == userID && s.Active {
			cp := *s
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (m *MemSessionStore) UpdateBytes(ctx context.Context, id string, up, down int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	if !ok {
		return fmt.Errorf("not found")
	}
	s.BytesUp = up
	s.BytesDown = down
	return nil
}

func (m *MemSessionStore) RecordMigration(ctx context.Context, id string, newNodeID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	if !ok {
		return fmt.Errorf("not found")
	}
	s.NodeID = newNodeID
	s.MigratedCount++
	return nil
}
