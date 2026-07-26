package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	supervisorpb "github.com/aether-x/control-plane/api/gen/go/aether/supervisor/v1"
	"github.com/aether-x/control-plane/internal/grpcclient/grpctest"
	"github.com/aether-x/control-plane/internal/mcp"
	"github.com/aether-x/control-plane/internal/mcpbridge"
)

// cannedSupervisor is a CoreSupervisorServiceServer returning fixed data for
// the MCP-over-HTTP E2E test.
type cannedSupervisor struct {
	supervisorpb.UnimplementedCoreSupervisorServiceServer
}

func (cannedSupervisor) ListCores(_ context.Context, _ *supervisorpb.ListCoresRequest) (*supervisorpb.ListCoresResponse, error) {
	return &supervisorpb.ListCoresResponse{
		Instances: []*supervisorpb.CoreInstance{
			{InstanceId: "edge-1", ProtocolId: "reality-vision", Status: supervisorpb.CoreStatus_CORE_STATUS_RUNNING},
		},
	}, nil
}

func (cannedSupervisor) HealthCheck(_ context.Context, _ *supervisorpb.HealthCheckRequest) (*supervisorpb.HealthCheckResponse, error) {
	return &supervisorpb.HealthCheckResponse{
		Status: supervisorpb.HealthCheckResponse_SERVING_STATUS_SERVING, Version: "e2e-9.9",
	}, nil
}

func (cannedSupervisor) HotSwapProtocol(_ context.Context, r *supervisorpb.HotSwapProtocolRequest) (*supervisorpb.HotSwapProtocolResponse, error) {
	return &supervisorpb.HotSwapProtocolResponse{
		InstanceId: r.GetInstanceId(), MigratedSessions: true,
	}, nil
}

func (cannedSupervisor) ApplyPolicy(_ context.Context, r *supervisorpb.ApplyPolicyRequest) (*supervisorpb.ApplyPolicyResponse, error) {
	return &supervisorpb.ApplyPolicyResponse{Applied: true, EffectiveRevision: r.GetPolicy().GetRevision()}, nil
}

func (cannedSupervisor) Route(_ context.Context, r *supervisorpb.RouteRequest) (*supervisorpb.RouteResponse, error) {
	act := supervisorpb.RouteAction_ROUTE_ACTION_PROXY
	if strings.Contains(r.GetDomain(), "ir") || r.GetIp() == "78.38.5.5" {
		act = supervisorpb.RouteAction_ROUTE_ACTION_DIRECT
	}
	return &supervisorpb.RouteResponse{Action: act, Domain: r.GetDomain(), Ip: r.GetIp()}, nil
}

// mcpServer builds a real MCP server backed by a REAL gRPC supervisor (bufconn)
// via the mcpbridge adapter.
func mcpServer(t *testing.T) http.Handler {
	t.Helper()
	client := grpctest.NewClient(t, cannedSupervisor{})
	return mcp.New(mcpbridge.NewSupervisor(client), nil)
}

// mcpCall issues one JSON-RPC request to the mounted /mcp endpoint and returns
// the parsed response.
func mcpCall(t *testing.T, s *Server, method string, params any) map[string]any {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	s.Router().ServeHTTP(rec, req)
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode MCP response: %v (body=%s)", err, rec.Body.String())
	}
	return out
}

func TestMCPE2EInitializeOverHTTP(t *testing.T) {
	s := &Server{MCP: mcpServer(t), Build: "test"}
	resp := mcpCall(t, s, "initialize", map[string]any{})
	if resp["error"] != nil {
		t.Fatalf("initialize errored: %v", resp)
	}
	res := resp["result"].(map[string]any)
	if res["protocolVersion"] != mcp.ProtocolVersion {
		t.Fatalf("unexpected protocolVersion: %v", res["protocolVersion"])
	}
}

func TestMCPE2EListCoresThroughRealGRPC(t *testing.T) {
	s := &Server{MCP: mcpServer(t)}
	resp := mcpCall(t, s, "tools/call", map[string]any{"name": "list_cores", "arguments": map[string]any{}})
	res := resp["result"].(map[string]any)
	if res["isError"] == true {
		t.Fatalf("list_cores errored over real gRPC: %v", resp)
	}
	content := res["content"].([]any)[0].(map[string]any)
	text := content["text"].(string)
	if !containsStr(text, "edge-1") {
		t.Fatalf("expected edge-1 in tool output, got: %s", text)
	}
}

func TestMCPE2ESwitchProtocolRoundTrip(t *testing.T) {
	s := &Server{MCP: mcpServer(t)}
	resp := mcpCall(t, s, "tools/call", map[string]any{
		"name":      "switch_protocol",
		"arguments": map[string]any{"instance_id": "edge-1", "protocol_id": "hysteria2", "drain_ms": 200},
	})
	res := resp["result"].(map[string]any)
	if res["isError"] == true {
		t.Fatalf("switch_protocol errored: %v", resp)
	}
	text := res["content"].([]any)[0].(map[string]any)["text"].(string)
	if !containsStr(text, "switched edge-1 -> hysteria2") {
		t.Fatalf("unexpected switch result: %s", text)
	}
}

func containsStr(haystack, needle string) bool {
	return len(haystack) >= len(needle) && indexOfStr(haystack, needle) >= 0
}

func indexOfStr(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func TestMCPE2ERouteDestinationThroughRealGRPC(t *testing.T) {
	s := &Server{MCP: mcpServer(t)}
	resp := mcpCall(t, s, "tools/call", map[string]any{
		"name":      "route_destination",
		"arguments": map[string]any{"domain": "bank.mellat.ir", "ip": "78.38.5.5"},
	})
	res := resp["result"].(map[string]any)
	if res["isError"] == true {
		t.Fatalf("route_destination errored: %v", resp)
	}
	text := res["content"].([]any)[0].(map[string]any)["text"].(string)
	if !containsStr(text, "DIRECT") {
		t.Fatalf("expected DIRECT for ir domain, got: %s", text)
	}
}
