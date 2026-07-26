// Package mesh implements domestic P2P WebRTC DataChannel / WireGuard mesh topologies
// for multi-hop local routing during severe regional disconnects.
package mesh

import (
	"sync"
	"time"
)

// MeshNode is a domestic peer
type MeshNode struct {
	ID        string
	Region    string
	ISP       string
	IP        string
	Healthy   bool
	LastSeen  time.Time
	HopsAway  int // distance in mesh hops
	HasEgress bool // if this node has working international egress
}

// WebRTCDataChannel mock
type DataChannel struct {
	ID        string
	LocalID   string
	RemoteID  string
	Open      bool
	BytesSent int64
}

// MeshOrchestrator manages P2P mesh
type MeshOrchestrator struct {
	mu       sync.RWMutex
	nodes    map[string]*MeshNode
	channels map[string]*DataChannel
}

func New() *MeshOrchestrator {
	return &MeshOrchestrator{
		nodes:    make(map[string]*MeshNode),
		channels: make(map[string]*DataChannel),
	}
}

func (m *MeshOrchestrator) AddNode(node MeshNode) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := node
	n.LastSeen = time.Now()
	m.nodes[n.ID] = &n
}

func (m *MeshOrchestrator) RemoveNode(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.nodes, id)
	// also remove channels involving this node
	for cid, ch := range m.channels {
		if ch.LocalID == id || ch.RemoteID == id {
			delete(m.channels, cid)
		}
	}
}

func (m *MeshOrchestrator) MarkHealthy(id string, healthy bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if n, ok := m.nodes[id]; ok {
		n.Healthy = healthy
		n.LastSeen = time.Now()
	}
}

func (m *MeshOrchestrator) OpenChannel(localID, remoteID string) (*DataChannel, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	// both nodes must exist and be healthy
	local, ok1 := m.nodes[localID]
	remote, ok2 := m.nodes[remoteID]
	if !ok1 || !ok2 {
		return nil, ErrNodeNotFound
	}
	if !local.Healthy || !remote.Healthy {
		return nil, ErrNodeUnhealthy
	}

	id := localID + "->" + remoteID
	ch := &DataChannel{
		ID:       id,
		LocalID:  localID,
		RemoteID: remoteID,
		Open:     true,
	}
	m.channels[id] = ch
	return ch, nil
}

func (m *MeshOrchestrator) CloseChannel(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.channels, id)
}

// FindEgressPath finds multi-hop path to a node with HasEgress=true
// Uses BFS for shortest path
func (m *MeshOrchestrator) FindEgressPath(fromID string) ([]string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// BFS
	visited := make(map[string]bool)
	queue := [][]string{{fromID}}
	visited[fromID] = true

	for len(queue) > 0 {
		path := queue[0]
		queue = queue[1:]
		last := path[len(path)-1]

		node, ok := m.nodes[last]
		if !ok || !node.Healthy {
			continue
		}
		if node.HasEgress {
			return path, true
		}

		// find neighbors via channels
		for _, ch := range m.channels {
			var neighbor string
			if ch.LocalID == last {
				neighbor = ch.RemoteID
			} else if ch.RemoteID == last {
				neighbor = ch.LocalID
			} else {
				continue
			}
			if visited[neighbor] {
				continue
			}
			visited[neighbor] = true
			newPath := append(append([]string{}, path...), neighbor)
			queue = append(queue, newPath)
		}
	}
	return nil, false
}

func (m *MeshOrchestrator) Nodes() []*MeshNode {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*MeshNode, 0, len(m.nodes))
	for _, n := range m.nodes {
		cp := *n
		out = append(out, &cp)
	}
	return out
}

func (m *MeshOrchestrator) Channels() []*DataChannel {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*DataChannel, 0, len(m.channels))
	for _, ch := range m.channels {
		cp := *ch
		out = append(out, &cp)
	}
	return out
}

func (m *MeshOrchestrator) Stats() MeshStats {
	m.mu.RLock()
	defer m.mu.RUnlock()
	healthy := 0
	egress := 0
	for _, n := range m.nodes {
		if n.Healthy {
			healthy++
		}
		if n.HasEgress {
			egress++
		}
	}
	return MeshStats{
		TotalNodes:    len(m.nodes),
		HealthyNodes:  healthy,
		EgressNodes:   egress,
		TotalChannels: len(m.channels),
	}
}

type MeshStats struct {
	TotalNodes    int
	HealthyNodes  int
	EgressNodes   int
	TotalChannels int
}

var (
	ErrNodeNotFound  = fmtError("node not found")
	ErrNodeUnhealthy = fmtError("node unhealthy")
)

type fmtError string

func (e fmtError) Error() string { return string(e) }
