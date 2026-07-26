// Package distribution implements anti-enumeration node/bridge distribution
// (Subsystem C).
//
// Two-tier pool model:
//   - Public tier: unchanged /v1/transports catalog (served openly).
//   - Rationed tier: held-back pool of egress nodes allocated per-identity,
//     rate-limited, rotated proactively.
//
// Allocation policy:
//   - Cap: N rationed-pool assignments per verified identity per rolling
//     30-day window (configurable; default N=2).
//   - New-identity dampening: identities younger than a configurable age
//     receive zero or minimal rationed-pool allocation.
//   - Burned IP rotation: ReportBurned signals trigger proactive rotation
//     scheduling for the rationed pool.
//
// Does NOT claim the rationed pool is unblockable. A sufficiently patient,
// well-resourced adversary running many sock-puppet identities can still
// eventually map part of it.
package distribution

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// Config configures the distribution service.
type Config struct {
	// MaxN is the maximum rationed-pool assignments per identity per
	// rolling window. Default: 2.
	MaxN int
	// WindowDays is the rolling window size in days. Default: 30.
	WindowDays int
	// NewIdentityAgeDays is the minimum identity age (days) to receive
	// full rationed-pool allocation. Identities younger than this get
	// dampened (0 or 1) allocations. Default: 7.
	NewIdentityAgeDays int
	// DampenedN is the allocation cap for new (dampened) identities.
	// Default: 0 (zero allocation).
	DampenedN int
}

// DefaultConfig returns conservative defaults.
func DefaultConfig() Config {
	return Config{
		MaxN:               2,
		WindowDays:         30,
		NewIdentityAgeDays: 7,
		DampenedN:          0,
	}
}

// Node represents a rationed-pool egress node.
type Node struct {
	ID        string    `json:"id"`
	Address   string    `json:"address"`
	Protocol  string    `json:"protocol"`
	IsBurned  bool      `json:"is_burned"`
	BurnedAt  time.Time `json:"burned_at,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// Allocation records one rationed-pool assignment to an identity.
type Allocation struct {
	IdentityID  string    `json:"identity_id"`
	NodeID      string    `json:"node_id"`
	AllocatedAt time.Time `json:"allocated_at"`
}

// PoolHealth reports the health of the rationed pool.
type PoolHealth struct {
	TotalNodes      int `json:"total_nodes"`
	AvailableNodes  int `json:"available_nodes"`
	BurnedNodes     int `json:"burned_nodes"`
	Allocations24h  int `json:"allocations_24h"`
	RotationPending int `json:"rotation_pending"`
}

// Errors.
var (
	ErrRateLimited      = errors.New("distribution: identity has reached allocation cap")
	ErrIdentityTooNew   = errors.New("distribution: identity is too new for rationed allocation")
	ErrNoAvailableNodes = errors.New("distribution: no available nodes in rationed pool")
	ErrNodeNotFound     = errors.New("distribution: node not found")
	ErrIdentityNotFound = errors.New("distribution: identity not found")
)

// Service is the anti-enumeration distribution service.
type Service struct {
	mu          sync.RWMutex
	config      Config
	nodes       map[string]*Node
	allocations []Allocation
	identities  map[string]time.Time // identity_id -> created_at
	rotationQ   []string             // node IDs pending rotation
}

// New creates a new distribution service.
func New(cfg Config) *Service {
	return &Service{
		config:     cfg,
		nodes:      make(map[string]*Node),
		identities: make(map[string]time.Time),
	}
}

// AddNode registers a node in the rationed pool.
func (s *Service) AddNode(node Node) {
	s.mu.Lock()
	defer s.mu.Unlock()
	node.IsBurned = false
	s.nodes[node.ID] = &node
}

// RegisterIdentity records when an identity was created (for dampening).
func (s *Service) RegisterIdentity(identityID string, createdAt time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.identities[identityID] = createdAt
}

// RequestRationedNode allocates a rationed-pool node to an identity.
// Enforces the N-per-identity per rolling window cap and new-identity dampening.
func (s *Service) RequestRationedNode(identityID string) (*Node, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	createdAt, known := s.identities[identityID]
	if !known {
		return nil, ErrIdentityNotFound
	}

	// Check new-identity dampening.
	identityAge := time.Since(createdAt)
	dampThreshold := time.Duration(s.config.NewIdentityAgeDays) * 24 * time.Hour
	effectiveN := s.config.MaxN
	if identityAge < dampThreshold {
		effectiveN = s.config.DampenedN
		if effectiveN <= 0 {
			return nil, ErrIdentityTooNew
		}
	}

	// Count allocations in the rolling window.
	windowStart := time.Now().Add(-time.Duration(s.config.WindowDays) * 24 * time.Hour)
	count := 0
	for _, a := range s.allocations {
		if a.IdentityID == identityID && a.AllocatedAt.After(windowStart) {
			count++
		}
	}
	if count >= effectiveN {
		return nil, ErrRateLimited
	}

	// Find an available (non-burned, unallocated) node.
	allocatedNodes := make(map[string]bool)
	for _, a := range s.allocations {
		if a.IdentityID == identityID && a.AllocatedAt.After(windowStart) {
			allocatedNodes[a.NodeID] = true
		}
	}
	for _, node := range s.nodes {
		if !node.IsBurned && !allocatedNodes[node.ID] {
			// Allocate.
			s.allocations = append(s.allocations, Allocation{
				IdentityID:  identityID,
				NodeID:      node.ID,
				AllocatedAt: time.Now(),
			})
			nodeCopy := *node
			return &nodeCopy, nil
		}
	}
	return nil, ErrNoAvailableNodes
}

// ReportBurned marks a node as burned and schedules proactive rotation.
// Does NOT touch the public-tier catalog.
func (s *Service) ReportBurned(nodeID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	node, ok := s.nodes[nodeID]
	if !ok {
		return ErrNodeNotFound
	}
	node.IsBurned = true
	node.BurnedAt = time.Now()
	s.rotationQ = append(s.rotationQ, nodeID)
	return nil
}

// GetPoolHealth returns the current rationed pool health.
func (s *Service) GetPoolHealth() PoolHealth {
	s.mu.RLock()
	defer s.mu.RUnlock()

	total := len(s.nodes)
	burned := 0
	for _, n := range s.nodes {
		if n.IsBurned {
			burned++
		}
	}
	windowStart := time.Now().Add(-24 * time.Hour)
	allocs24h := 0
	for _, a := range s.allocations {
		if a.AllocatedAt.After(windowStart) {
			allocs24h++
		}
	}
	return PoolHealth{
		TotalNodes:      total,
		AvailableNodes:  total - burned,
		BurnedNodes:     burned,
		Allocations24h:  allocs24h,
		RotationPending: len(s.rotationQ),
	}
}

// DrainRotationQueue returns and clears the pending rotation queue.
func (s *Service) DrainRotationQueue() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	q := s.rotationQ
	s.rotationQ = nil
	return q
}

// AllocationCount returns the number of allocations for an identity in the
// rolling window. Useful for testing.
func (s *Service) AllocationCount(identityID string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	windowStart := time.Now().Add(-time.Duration(s.config.WindowDays) * 24 * time.Hour)
	count := 0
	for _, a := range s.allocations {
		if a.IdentityID == identityID && a.AllocatedAt.After(windowStart) {
			count++
		}
	}
	return count
}

// String returns a human-readable summary.
func (s *Service) String() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return fmt.Sprintf("DistributionService{nodes=%d, allocs=%d, rotation_q=%d}",
		len(s.nodes), len(s.allocations), len(s.rotationQ))
}
