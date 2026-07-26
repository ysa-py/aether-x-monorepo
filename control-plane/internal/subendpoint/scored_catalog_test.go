package subendpoint

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aether-x/control-plane/internal/telemetry"
)

type scoreReaderFixture struct {
	scores []telemetry.NodeScore
	err    error
}

func (r scoreReaderFixture) ReadScores(context.Context, string) ([]telemetry.NodeScore, error) {
	if r.err != nil {
		return nil, r.err
	}
	return r.scores, nil
}

type capturingScoreReader struct {
	isp    string
	scores []telemetry.NodeScore
}

func (r *capturingScoreReader) ReadScores(_ context.Context, isp string) ([]telemetry.NodeScore, error) {
	r.isp = isp
	return r.scores, nil
}

func twoNodeCatalogService(t *testing.T) *ReloadingCatalogSubscriptionService {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "catalog.json")
	first := testCatalogNode()
	first.ID = "catalog-node-a-slow"
	first.Address = "203.0.113.42"
	second := testCatalogNode()
	second.ID = "catalog-node-z-fast"
	second.Address = "203.0.113.43"
	document := CatalogDocument{Version: "v1", Nodes: []CatalogNode{first, second}}
	writeCatalogDocument(t, path, document)
	service, err := NewReloadingCatalogSubscriptionService(path, time.Second)
	if err != nil {
		t.Fatalf("new reloading catalog service: %v", err)
	}
	return service
}

func writeCatalogDocument(t *testing.T, path string, document CatalogDocument) {
	t.Helper()
	contents, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("marshal catalog document: %v", err)
	}
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatalf("write catalog document: %v", err)
	}
}

func decodeSubscriptionBody(t *testing.T, body []byte) string {
	t.Helper()
	decoded, err := base64.StdEncoding.DecodeString(string(body))
	if err != nil {
		t.Fatalf("decode subscription body: %v", err)
	}
	return string(decoded)
}

func TestTelemetryCatalogReordersOnlyVerifiedNodes(t *testing.T) {
	catalog := twoNodeCatalogService(t)
	service, err := NewTelemetryCatalogSubscriptionService(catalog, scoreReaderFixture{
		scores: []telemetry.NodeScore{
			{NodeID: "catalog-node-a-slow", SuccessRate: 0.3, AvgRTTMs: 900, RSTCount: 8},
			{NodeID: "catalog-node-z-fast", SuccessRate: 0.98, AvgRTTMs: 80, RSTCount: 0, ThroughputBps: 300_000_000},
			{NodeID: "not-in-catalog", SuccessRate: 1, AvgRTTMs: 1},
		},
	})
	if err != nil {
		t.Fatalf("new telemetry catalog service: %v", err)
	}

	result, err := service.BuildGeoRouted(
		context.Background(),
		&SubscriptionData{UserID: "subscriber"},
		"sing-box/1.11",
		"",
		"base64",
	)
	if err != nil {
		t.Fatalf("build scored subscription: %v", err)
	}
	body := decodeSubscriptionBody(t, result.Body)
	fast := strings.Index(body, "203.0.113.43:443")
	slow := strings.Index(body, "203.0.113.42:443")
	if fast < 0 || slow < 0 || fast >= slow {
		t.Fatalf("verified nodes were not ordered by real score: %q", body)
	}
	if strings.Contains(body, "not-in-catalog") {
		t.Fatalf("score-only node leaked into subscription: %q", body)
	}
}

func TestTelemetryCatalogUsesTrustedClientContextForScoreQuery(t *testing.T) {
	catalog := twoNodeCatalogService(t)
	reader := &capturingScoreReader{}
	service, err := NewTelemetryCatalogSubscriptionService(catalog, reader)
	if err != nil {
		t.Fatalf("new telemetry catalog service: %v", err)
	}
	_, err = service.BuildGeoRoutedWithContext(
		context.Background(),
		&SubscriptionData{UserID: "subscriber"},
		telemetry.ClientContext{Core: "sing-box", ISP: "Irancell"},
		"base64",
	)
	if err != nil {
		t.Fatalf("build trusted-context subscription: %v", err)
	}
	if reader.isp != "Irancell" {
		t.Fatalf("trusted ISP context was not forwarded to score reader: %q", reader.isp)
	}
}

func TestTelemetryCatalogFallsBackToDeterministicOrderOnReaderFailure(t *testing.T) {
	catalog := twoNodeCatalogService(t)
	service, err := NewTelemetryCatalogSubscriptionService(
		catalog,
		scoreReaderFixture{err: errors.New("database unavailable")},
	)
	if err != nil {
		t.Fatalf("new telemetry catalog service: %v", err)
	}
	result, err := service.BuildGeoRouted(
		context.Background(),
		&SubscriptionData{UserID: "subscriber"},
		"sing-box/1.11",
		"",
		"base64",
	)
	if err != nil {
		t.Fatalf("build baseline subscription: %v", err)
	}
	body := decodeSubscriptionBody(t, result.Body)
	first := strings.Index(body, "203.0.113.43:443")
	second := strings.Index(body, "203.0.113.42:443")
	if first < 0 || second < 0 || second >= first {
		t.Fatalf("baseline catalog sort order was not retained: %q", body)
	}
	if !strings.Contains(result.Reason, "deterministic baseline") {
		t.Fatalf("fallback reason does not disclose baseline order: %q", result.Reason)
	}
}
