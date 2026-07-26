// Package store provides the persistence layer for subscriptions, users, and
// nodes. It defines repository interfaces (matching model.Subscription /
// model.User) and a thread-safe in-memory implementation for development and
// testing. Production replaces the in-memory backend with PostgreSQL.
package store

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/aether-x/control-plane/internal/model"
)

// SubscriptionStore is the interface for subscription persistence.
type SubscriptionStore interface {
	ByToken(ctx context.Context, subToken string) (*model.Subscription, error)
	ByUserID(ctx context.Context, userID string) (*model.Subscription, error)
	UpdateUsage(ctx context.Context, subID string, bytesDelta int64) error
	Save(ctx context.Context, sub *model.Subscription) error
}

// NodeStore is the interface for node persistence.
type NodeStore interface {
	Active(ctx context.Context) ([]model.Node, error)
	NodeByID(ctx context.Context, id string) (*model.Node, error)
}

// UserStore is the interface for user persistence.
type UserStore interface {
	UserByID(ctx context.Context, id string) (*model.User, error)
	ByEmail(ctx context.Context, email string) (*model.User, error)
}

// MemStore is a thread-safe in-memory implementation of all store interfaces.
// Suitable for development, testing, and single-node deployments. Production
// uses the PostgreSQL implementation.
type MemStore struct {
	mu          sync.RWMutex
	subs        map[string]*model.Subscription // by ID
	subsByToken map[string]*model.Subscription // by SubToken
	subsByUser  map[string]*model.Subscription // by UserID
	users       map[string]*model.User
	nodes       map[string]*model.Node
}

// NewMemStore creates an empty in-memory store.
func NewMemStore() *MemStore {
	return &MemStore{
		subs:        make(map[string]*model.Subscription),
		subsByToken: make(map[string]*model.Subscription),
		subsByUser:  make(map[string]*model.Subscription),
		users:       make(map[string]*model.User),
		nodes:       make(map[string]*model.Node),
	}
}

// SeedWithDemo populates the store with a demo subscription + node. Useful for
// local development and integration tests.
func (s *MemStore) SeedWithDemo() {
	s.mu.Lock()
	defer s.mu.Unlock()

	sub := &model.Subscription{
		ID:         "sub-demo-001",
		UserID:     "user-demo",
		PlanID:     "pro",
		BytesTotal: 50_000_000_000,                      // 50 GB
		BytesUsed:  12_500_000_000,                      // 12.5 GB used (25%)
		ExpiresAt:  time.Now().Add(30 * 24 * time.Hour), // 30 days
		CreatedAt:  time.Now().Add(-2 * 24 * time.Hour),
	}
	sub.SubToken = "demo-token-aether-x-2026"
	s.subs[sub.ID] = sub
	s.subsByToken[sub.SubToken] = sub
	s.subsByUser[sub.UserID] = sub

	user := &model.User{
		ID:        "user-demo",
		Email:     "demo@aether-x.local",
		Role:      model.RoleUser,
		CreatedAt: time.Now().Add(-2 * 24 * time.Hour),
	}
	s.users[user.ID] = user

	node := model.Node{
		ID:             "node-fra-01",
		Region:         "eu-central",
		ASNOrg:         "Hetzner Online GmbH",
		Capacity:       1000,
		SupervisorAddr: "node-fra-01:7070",
		Healthy:        true,
	}
	s.nodes[node.ID] = &node
}

// --- SubscriptionStore ---

func (s *MemStore) ByToken(_ context.Context, subToken string) (*model.Subscription, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sub, ok := s.subsByToken[subToken]
	if !ok {
		return nil, ErrNotFound
	}
	cloned := *sub
	return &cloned, nil
}

func (s *MemStore) ByUserID(_ context.Context, userID string) (*model.Subscription, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sub, ok := s.subsByUser[userID]
	if !ok {
		return nil, ErrNotFound
	}
	cloned := *sub
	return &cloned, nil
}

func (s *MemStore) UpdateUsage(_ context.Context, subID string, bytesDelta int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sub, ok := s.subs[subID]
	if !ok {
		return ErrNotFound
	}
	sub.BytesUsed += bytesDelta
	if sub.BytesUsed < 0 {
		sub.BytesUsed = 0
	}
	return nil
}

func (s *MemStore) Save(_ context.Context, sub *model.Subscription) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.subs[sub.ID] = sub
	if sub.SubToken != "" {
		s.subsByToken[sub.SubToken] = sub
	}
	if sub.UserID != "" {
		s.subsByUser[sub.UserID] = sub
	}
	return nil
}

// --- UserStore ---

func (s *MemStore) UserByID(_ context.Context, id string) (*model.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[id]
	if !ok {
		return nil, ErrNotFound
	}
	cloned := *u
	return &cloned, nil
}

func (s *MemStore) ByEmail(_ context.Context, email string) (*model.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.users {
		if u.Email == email {
			cloned := *u
			return &cloned, nil
		}
	}
	return nil, ErrNotFound
}

// --- NodeStore ---

func (s *MemStore) Active(_ context.Context) ([]model.Node, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []model.Node
	for _, n := range s.nodes {
		if n.Healthy {
			out = append(out, *n)
		}
	}
	return out, nil
}

func (s *MemStore) NodeByID(_ context.Context, id string) (*model.Node, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n, ok := s.nodes[id]
	if !ok {
		return nil, ErrNotFound
	}
	cloned := *n
	return &cloned, nil
}

// ErrNotFound is returned when a record is not in the store.
var ErrNotFound = fmt.Errorf("record not found")
