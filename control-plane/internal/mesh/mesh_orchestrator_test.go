package mesh

import "testing"

func TestAddAndFindEgress(t *testing.T) {
	m := New()
	m.AddNode(MeshNode{ID: "A", Region: "tehran", ISP: "MCI", Healthy: true, HasEgress: false})
	m.AddNode(MeshNode{ID: "B", Region: "tehran", ISP: "MCI", Healthy: true, HasEgress: false})
	m.AddNode(MeshNode{ID: "C", Region: "tehran", ISP: "MCI", Healthy: true, HasEgress: true})

	m.OpenChannel("A", "B")
	m.OpenChannel("B", "C")

	path, found := m.FindEgressPath("A")
	if !found {
		t.Fatal("should find egress path")
	}
	if len(path) != 3 {
		t.Errorf("expected path len 3, got %v", path)
	}
	if path[0] != "A" || path[2] != "C" {
		t.Errorf("unexpected path %v", path)
	}
}

func TestNoEgress(t *testing.T) {
	m := New()
	m.AddNode(MeshNode{ID: "A", Healthy: true, HasEgress: false})
	m.AddNode(MeshNode{ID: "B", Healthy: true, HasEgress: false})
	m.OpenChannel("A", "B")

	_, found := m.FindEgressPath("A")
	if found {
		t.Error("should not find egress")
	}
}

func TestRemoveNode(t *testing.T) {
	m := New()
	m.AddNode(MeshNode{ID: "A", Healthy: true})
	m.AddNode(MeshNode{ID: "B", Healthy: true})
	m.OpenChannel("A", "B")
	if len(m.Channels()) != 1 {
		t.Error("channel")
	}
	m.RemoveNode("A")
	if len(m.Nodes()) != 1 {
		t.Error("nodes")
	}
	if len(m.Channels()) != 0 {
		t.Error("channels should be removed")
	}
}

func TestStats(t *testing.T) {
	m := New()
	m.AddNode(MeshNode{ID: "A", Healthy: true, HasEgress: true})
	m.AddNode(MeshNode{ID: "B", Healthy: false, HasEgress: false})
	stats := m.Stats()
	if stats.TotalNodes != 2 || stats.HealthyNodes != 1 || stats.EgressNodes != 1 {
		t.Errorf("stats wrong %+v", stats)
	}
}
