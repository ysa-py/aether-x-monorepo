package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	telemetrypb "github.com/aether-x/control-plane/api/gen/go/aether/telemetry/v1"
	"github.com/aether-x/control-plane/internal/featurizer"
)

// --- fakes ---

type fakeSup struct {
	health  HealthInfo
	hErr    error
	cores   []CoreInfo
	cErr    error
	switchM bool
	sErr    error
	effRev  uint64
	aErr    error
}

func (f *fakeSup) Health(context.Context) (HealthInfo, error)    { return f.health, f.hErr }
func (f *fakeSup) ListCores(context.Context) ([]CoreInfo, error) { return f.cores, f.cErr }
func (f *fakeSup) SwitchProtocol(context.Context, string, string, uint32) (bool, error) {
	return f.switchM, f.sErr
}
func (f *fakeSup) ApplyFallbackChain(context.Context, string, []string, uint64) (uint64, error) {
	return f.effRev, f.aErr
}

type fakeFeat struct{ pts []featurizer.FeaturePoint }

func (f *fakeFeat) Snapshot() []featurizer.FeaturePoint { return f.pts }

// --- Subsystem fakes ---

type fakeTraining struct {
	status      map[string]any
	promoted    bool
	promoteErr  error
	rollbackErr error
}

func (f *fakeTraining) GetStatus() map[string]any { return f.status }
func (f *fakeTraining) PromoteModel(modelID string) (bool, error) {
	return f.promoted, f.promoteErr
}
func (f *fakeTraining) RollbackModel(modelID string) error { return f.rollbackErr }

type fakeMeasurement struct {
	coverage map[string]any
}

func (f *fakeMeasurement) GetCoverage() map[string]any { return f.coverage }

type fakeDistribution struct {
	health map[string]any
}

func (f *fakeDistribution) GetPoolHealth() map[string]any { return f.health }

type fakeTransparency struct {
	sth map[string]any
}

func (f *fakeTransparency) GetSignedTreeHead() map[string]any { return f.sth }

// --- helpers ---

func call(t *testing.T, s *Server, method string, params any) rpcResponse {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	var resp rpcResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v (body=%s)", err, rec.Body.String())
	}
	return resp
}

func callTool(t *testing.T, s *Server, name string, args map[string]any) CallResult {
	t.Helper()
	resp := call(t, s, "tools/call", map[string]any{"name": name, "arguments": args})
	b, _ := json.Marshal(resp.Result)
	var cr CallResult
	_ = json.Unmarshal(b, &cr)
	return cr
}

// --- tests ---

func TestInitialize(t *testing.T) {
	s := New(&fakeSup{}, &fakeFeat{})
	resp := call(t, s, "initialize", map[string]any{})
	if resp.Error != nil {
		t.Fatalf("initialize errored: %+v", resp.Error)
	}
	m, ok := resp.Result.(map[string]any)
	if !ok || m["protocolVersion"] != ProtocolVersion {
		t.Fatalf("bad initialize result: %+v", resp.Result)
	}
}

func TestToolsListExposesAllTools(t *testing.T) {
	s := New(&fakeSup{}, &fakeFeat{})
	resp := call(t, s, "tools/list", map[string]any{})
	m := resp.Result.(map[string]any)
	tools := m["tools"].([]any)
	want := []string{
		"list_cores", "get_node_health", "switch_protocol",
		"analyze_traffic", "apply_ai_recommendation",
		"get_training_pipeline_status", "promote_model_canary",
		"rollback_model", "get_measurement_coverage",
		"get_distribution_pool_health", "get_transparency_log_head",
	}
	got := map[string]bool{}
	for _, t := range tools {
		got[t.(map[string]any)["name"].(string)] = true
	}
	for _, w := range want {
		if !got[w] {
			t.Fatalf("missing tool %q in catalog: %+v", w, got)
		}
	}
}

func TestListCoresTool(t *testing.T) {
	s := New(&fakeSup{cores: []CoreInfo{{InstanceID: "i1", ProtocolID: "reality-vision", Status: "RUNNING"}}}, &fakeFeat{})
	cr := callTool(t, s, "list_cores", nil)
	if cr.IsError {
		t.Fatalf("unexpected error: %+v", cr)
	}
	if cr.Content[0].Text == "" {
		t.Fatal("empty text")
	}
}

func TestListCoresEmptyIsFriendly(t *testing.T) {
	s := New(&fakeSup{cores: nil}, &fakeFeat{})
	cr := callTool(t, s, "list_cores", nil)
	if cr.IsError {
		t.Fatalf("empty cores should be success, not error")
	}
}

func TestListCoresBackendError(t *testing.T) {
	s := New(&fakeSup{cErr: errors.New("boom")}, &fakeFeat{})
	cr := callTool(t, s, "list_cores", nil)
	if !cr.IsError {
		t.Fatalf("expected error result")
	}
}

func TestSwitchProtocolRequiresArgs(t *testing.T) {
	s := New(&fakeSup{switchM: true}, &fakeFeat{})
	if cr := callTool(t, s, "switch_protocol", map[string]any{"instance_id": "i1"}); !cr.IsError {
		t.Fatal("missing protocol_id must error")
	}
	cr := callTool(t, s, "switch_protocol", map[string]any{"instance_id": "i1", "protocol_id": "hysteria2"})
	if cr.IsError {
		t.Fatalf("valid call errored: %+v", cr)
	}
}

func TestAnalyzeTrafficFilters(t *testing.T) {
	pts := []featurizer.FeaturePoint{
		{ISP: telemetrypb.IspId_ISP_ID_MCI, ProtocolID: "reality-vision", SampleCount: 5, SuccessRate: 0.2, RstRate: 0.8},
		{ISP: telemetrypb.IspId_ISP_ID_MCI, ProtocolID: "hysteria2", SampleCount: 5, SuccessRate: 1.0},
	}
	s := New(&fakeSup{}, &fakeFeat{pts: pts})
	cr := callTool(t, s, "analyze_traffic", map[string]any{"protocol_id": "hysteria2"})
	if cr.IsError {
		t.Fatalf("unexpected error: %+v", cr)
	}
	// The filtered result must contain hysteria2 and not reality-vision.
	if !contains(cr.Content[0].Text, "hysteria2") || contains(cr.Content[0].Text, "reality-vision") {
		t.Fatalf("filter failed: %s", cr.Content[0].Text)
	}
}

func TestApplyRecommendationValidatesChain(t *testing.T) {
	s := New(&fakeSup{effRev: 7}, &fakeFeat{})
	// Missing chain -> error.
	if cr := callTool(t, s, "apply_ai_recommendation", map[string]any{"instance_id": "i1"}); !cr.IsError {
		t.Fatal("missing chain must error")
	}
	cr := callTool(t, s, "apply_ai_recommendation", map[string]any{
		"instance_id":    "i1",
		"fallback_chain": []any{"hysteria2", "tuic-v5"},
		"revision":       float64(7),
	})
	if cr.IsError {
		t.Fatalf("valid call errored: %+v", cr)
	}
}

func TestResourceReadNodeStatus(t *testing.T) {
	s := New(&fakeSup{health: HealthInfo{Serving: true, Version: "0.1"}, cores: []CoreInfo{{InstanceID: "i1"}}}, &fakeFeat{})
	resp := call(t, s, "resources/read", map[string]any{"uri": "aether://node/status"})
	if resp.Error != nil {
		t.Fatalf("resource read errored: %+v", resp.Error)
	}
}

func TestResourceReadUnknownURI(t *testing.T) {
	s := New(&fakeSup{}, &fakeFeat{})
	resp := call(t, s, "resources/read", map[string]any{"uri": "aether://bogus"})
	if resp.Error == nil {
		t.Fatal("unknown uri must error")
	}
}

func TestPromptGetDiagnose(t *testing.T) {
	s := New(&fakeSup{}, &fakeFeat{pts: []featurizer.FeaturePoint{{ProtocolID: "x"}}})
	resp := call(t, s, "prompts/get", map[string]any{"name": "diagnose_isp_failures", "arguments": map[string]any{"isp": "MCI"}})
	if resp.Error != nil {
		t.Fatalf("prompt get errored: %+v", resp.Error)
	}
}

func TestMethodNotFound(t *testing.T) {
	s := New(&fakeSup{}, &fakeFeat{})
	resp := call(t, s, "nope", map[string]any{})
	if resp.Error == nil || resp.Error.Code != codeMethodNotFound {
		t.Fatalf("expected method-not-found, got %+v", resp.Error)
	}
}

func TestRejectsNonPost(t *testing.T) {
	s := New(&fakeSup{}, &fakeFeat{})
	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rec.Code)
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (haystack == needle || indexOf(haystack, needle) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func (f *fakeSup) Route(_ context.Context, domain, _ string) (string, error) {
	if domain != "" && domain[0:1] >= "a" {
		return "PROXY", nil
	}
	return "DIRECT", nil
}

// --- Subsystem tool tests ---

func TestGetTrainingPipelineStatus(t *testing.T) {
	s := New(&fakeSup{}, &fakeFeat{})
	s.SetTrainingPipeline(&fakeTraining{
		status: map[string]any{"models": 3, "shadow_mode": true},
	})
	cr := callTool(t, s, "get_training_pipeline_status", nil)
	if cr.IsError {
		t.Fatalf("unexpected error: %+v", cr)
	}
	if !contains(cr.Content[0].Text, "models") {
		t.Fatalf("expected status JSON, got: %s", cr.Content[0].Text)
	}
}

func TestGetTrainingPipelineStatus_NotConfigured(t *testing.T) {
	s := New(&fakeSup{}, &fakeFeat{})
	cr := callTool(t, s, "get_training_pipeline_status", nil)
	if !cr.IsError {
		t.Fatal("expected error when training pipeline not configured")
	}
}

func TestPromoteModelCanary(t *testing.T) {
	s := New(&fakeSup{}, &fakeFeat{})
	s.SetTrainingPipeline(&fakeTraining{promoted: true})
	cr := callTool(t, s, "promote_model_canary", map[string]any{"model_id": "censorship_classifier"})
	if cr.IsError {
		t.Fatalf("unexpected error: %+v", cr)
	}
	if !contains(cr.Content[0].Text, "promoted") {
		t.Fatalf("expected promotion message, got: %s", cr.Content[0].Text)
	}
}

func TestPromoteModelCanary_RequiresModelID(t *testing.T) {
	s := New(&fakeSup{}, &fakeFeat{})
	s.SetTrainingPipeline(&fakeTraining{})
	cr := callTool(t, s, "promote_model_canary", map[string]any{})
	if !cr.IsError {
		t.Fatal("expected error when model_id is missing")
	}
}

func TestRollbackModel(t *testing.T) {
	s := New(&fakeSup{}, &fakeFeat{})
	s.SetTrainingPipeline(&fakeTraining{})
	cr := callTool(t, s, "rollback_model", map[string]any{"model_id": "censorship_classifier"})
	if cr.IsError {
		t.Fatalf("unexpected error: %+v", cr)
	}
	if !contains(cr.Content[0].Text, "rolled back") {
		t.Fatalf("expected rollback message, got: %s", cr.Content[0].Text)
	}
}

func TestGetMeasurementCoverage(t *testing.T) {
	s := New(&fakeSup{}, &fakeFeat{})
	s.SetMeasurement(&fakeMeasurement{
		coverage: map[string]any{"total_buckets": 5, "consent_active": true},
	})
	cr := callTool(t, s, "get_measurement_coverage", nil)
	if cr.IsError {
		t.Fatalf("unexpected error: %+v", cr)
	}
}

func TestGetMeasurementCoverage_NotConfigured(t *testing.T) {
	s := New(&fakeSup{}, &fakeFeat{})
	cr := callTool(t, s, "get_measurement_coverage", nil)
	if !cr.IsError {
		t.Fatal("expected error when measurement not configured")
	}
}

func TestGetDistributionPoolHealth(t *testing.T) {
	s := New(&fakeSup{}, &fakeFeat{})
	s.SetDistribution(&fakeDistribution{
		health: map[string]any{"total_nodes": 10, "available": 8},
	})
	cr := callTool(t, s, "get_distribution_pool_health", nil)
	if cr.IsError {
		t.Fatalf("unexpected error: %+v", cr)
	}
}

func TestGetDistributionPoolHealth_NotConfigured(t *testing.T) {
	s := New(&fakeSup{}, &fakeFeat{})
	cr := callTool(t, s, "get_distribution_pool_health", nil)
	if !cr.IsError {
		t.Fatal("expected error when distribution not configured")
	}
}

func TestGetTransparencyLogHead(t *testing.T) {
	s := New(&fakeSup{}, &fakeFeat{})
	s.SetTransparency(&fakeTransparency{
		sth: map[string]any{"tree_size": 42, "timestamp": 1700000000},
	})
	cr := callTool(t, s, "get_transparency_log_head", nil)
	if cr.IsError {
		t.Fatalf("unexpected error: %+v", cr)
	}
}

func TestGetTransparencyLogHead_NotConfigured(t *testing.T) {
	s := New(&fakeSup{}, &fakeFeat{})
	cr := callTool(t, s, "get_transparency_log_head", nil)
	if !cr.IsError {
		t.Fatal("expected error when transparency not configured")
	}
}
