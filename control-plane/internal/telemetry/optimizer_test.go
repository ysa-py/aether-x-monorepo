package telemetry

import (
	"context"
	"testing"
	"time"
)

func TestOptimizer_GeoRoutedSelection(t *testing.T) {
	reader := &MockReader{
		Scores: []NodeScore{
			{NodeID: "node-fra-01", Region: "eu-central", ISP: "MCI", Protocol: "vless", Transport: "xhttp", SuccessRate: 0.95, AvgRTTMs: 120, LastSeen: time.Now(), CapacityLoad: 0.4},
			{NodeID: "node-tr-01", Region: "tr-central", ISP: "MCI", Protocol: "vless", Transport: "ws", SuccessRate: 0.88, AvgRTTMs: 80, LastSeen: time.Now(), CapacityLoad: 0.6},
			{NodeID: "node-nl-01", Region: "eu-west", ISP: "MCI", Protocol: "trojan", Transport: "ws", SuccessRate: 0.85, AvgRTTMs: 130, LastSeen: time.Now(), CapacityLoad: 0.3},
		},
	}
	opt := NewOptimizer(reader)
	client := ClientContext{
		ISP:    "MCI",
		Region: "tehran",
		Core:   "sing-box",
	}
	profile, err := opt.Optimize(context.Background(), client)
	if err != nil {
		t.Fatalf("optimize failed: %v", err)
	}
	if len(profile.Nodes) == 0 {
		t.Fatalf("no nodes returned")
	}
	// Best node should be fra-01 due to high success + xhttp boost
	if profile.Nodes[0].NodeID != "node-fra-01" {
		t.Errorf("expected node-fra-01 best, got %s", profile.Nodes[0].NodeID)
	}
	if profile.Reason == "" {
		t.Error("reason empty")
	}
}

func TestOptimizer_CoreFiltering(t *testing.T) {
	reader := &MockReader{
		Scores: []NodeScore{
			{NodeID: "node-xhttp", Region: "eu-central", Protocol: "vless", Transport: "xhttp", SuccessRate: 0.95, AvgRTTMs: 100, LastSeen: time.Now()},
			{NodeID: "node-quic", Region: "eu-central", Protocol: "hysteria2", Transport: "quic", SuccessRate: 0.90, AvgRTTMs: 90, LastSeen: time.Now()},
			{NodeID: "node-ws", Region: "eu-central", Protocol: "vless", Transport: "ws", SuccessRate: 0.85, AvgRTTMs: 110, LastSeen: time.Now()},
		},
	}
	opt := NewOptimizer(reader)

	// shadowrocket should filter xhttp
	client := ClientContext{ISP: "MCI", Core: "shadowrocket"}
	profile, err := opt.Optimize(context.Background(), client)
	if err != nil {
		t.Fatalf("optimize failed: %v", err)
	}
	for _, n := range profile.Nodes {
		if n.Transport == "xhttp" {
			t.Error("shadowrocket should not get xhttp")
		}
	}

	// sing-box should get all including xhttp
	client2 := ClientContext{ISP: "MCI", Core: "sing-box"}
	profile2, err := opt.Optimize(context.Background(), client2)
	if err != nil {
		t.Fatalf("optimize failed: %v", err)
	}
	foundXHTTP := false
	for _, n := range profile2.Nodes {
		if n.Transport == "xhttp" {
			foundXHTTP = true
		}
	}
	if !foundXHTTP {
		t.Error("sing-box should get xhttp")
	}
}

func TestOptimizer_ZeroLossFailover(t *testing.T) {
	// Simulate DPI blocking a transport: success rate drops, optimizer should pick alternative
	reader := &MockReader{
		Scores: []NodeScore{
			{NodeID: "node-blocked", Region: "eu-central", ISP: "MCI", Protocol: "vless", Transport: "tcp", SuccessRate: 0.1, AvgRTTMs: 500, RSTCount: 10, LastSeen: time.Now()},
			{NodeID: "node-good", Region: "eu-central", ISP: "MCI", Protocol: "vless", Transport: "xhttp", SuccessRate: 0.95, AvgRTTMs: 100, LastSeen: time.Now()},
		},
	}
	opt := NewOptimizer(reader)
	client := ClientContext{ISP: "MCI", Core: "sing-box"}
	profile, err := opt.Optimize(context.Background(), client)
	if err != nil {
		t.Fatalf("optimize failed: %v", err)
	}
	if profile.Nodes[0].NodeID != "node-good" {
		t.Errorf("expected node-good to be selected over blocked, got %s", profile.Nodes[0].NodeID)
	}
}

func TestCompositeScore_GeoBoost(t *testing.T) {
	ns := NodeScore{Region: "eu-central", SuccessRate: 0.9, AvgRTTMs: 100, LastSeen: time.Now(), CapacityLoad: 0.2}
	client := ClientContext{Region: "eu-central"}
	scoreSame := compositeScore(ns, client)

	client2 := ClientContext{Region: "us-east"}
	scoreDiff := compositeScore(ns, client2)

	if scoreSame <= scoreDiff {
		t.Errorf("same region should boost score: same=%f diff=%f", scoreSame, scoreDiff)
	}
}

func TestClickHouseReader_Mock(t *testing.T) {
	reader := NewClickHouseReader()
	scores, err := reader.ReadScores(context.Background(), "MCI")
	if err != nil {
		t.Fatalf("reader failed: %v", err)
	}
	if len(scores) == 0 {
		t.Error("expected scores from mock reader")
	}
	// Should contain hysteria2 and tuic for zero-disconnection testing
	hasHysteria := false
	hasTuic := false
	for _, s := range scores {
		if s.Protocol == "hysteria2" {
			hasHysteria = true
		}
		if s.Protocol == "tuic" {
			hasTuic = true
		}
	}
	if !hasHysteria {
		t.Error("should contain hysteria2 node for QUIC migration")
	}
	if !hasTuic {
		t.Error("should contain tuic node for QUIC migration")
	}
}
