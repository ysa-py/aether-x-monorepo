package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/aether-x/control-plane/internal/featurizer"
)

// CoreInfo is the MCP view of one supervised core instance.
type CoreInfo struct {
	InstanceID string `json:"instance_id"`
	ProtocolID string `json:"protocol_id"`
	Status     string `json:"status"`
	Restarts   uint32 `json:"restart_count"`
}

// HealthInfo is the MCP view of supervisor health.
type HealthInfo struct {
	Serving bool   `json:"serving"`
	Version string `json:"version"`
}

// SupervisorClient is the subset of the supervisor gRPC client the MCP server
// needs. main.go adapts the real client to this interface.
type SupervisorClient interface {
	Health(context.Context) (HealthInfo, error)
	ListCores(context.Context) ([]CoreInfo, error)
	SwitchProtocol(ctx context.Context, instance, protocol string, drainMs uint32) (migrated bool, err error)
	ApplyFallbackChain(ctx context.Context, instance string, chain []string, revision uint64) (effective uint64, err error)
	Route(ctx context.Context, domain, ip string) (action string, err error)
}

// FeatureClient exposes the live featurizer snapshot.
type FeatureClient interface {
	Snapshot() []featurizer.FeaturePoint
}

// TrainingPipelineClient exposes AI training pipeline status (Subsystem A).
type TrainingPipelineClient interface {
	GetStatus() map[string]any
	PromoteModel(modelID string) (bool, error)
	RollbackModel(modelID string) error
}

// MeasurementClient exposes measurement coverage (Subsystem B).
type MeasurementClient interface {
	GetCoverage() map[string]any
}

// DistributionClient exposes distribution pool health (Subsystem C).
type DistributionClient interface {
	GetPoolHealth() map[string]any
}

// TransparencyClient exposes transparency log head (Subsystem D).
type TransparencyClient interface {
	GetSignedTreeHead() map[string]any
}

// Server is the embedded MCP server. It is safe for concurrent use.
type Server struct {
	sup          SupervisorClient
	feat         FeatureClient
	training     TrainingPipelineClient
	measurement  MeasurementClient
	distribution DistributionClient
	transparency TransparencyClient
}

// New constructs an MCP Server. Both deps are required at operation time; a nil
// dep makes the relevant tools return a clear "not configured" error rather than
// crash, so the server is always mountable.
func New(sup SupervisorClient, feat FeatureClient) *Server {
	return &Server{sup: sup, feat: feat}
}

// SetTrainingPipeline sets the training pipeline client (Subsystem A).
func (s *Server) SetTrainingPipeline(c TrainingPipelineClient) {
	s.training = c
}

// SetMeasurement sets the measurement client (Subsystem B).
func (s *Server) SetMeasurement(c MeasurementClient) {
	s.measurement = c
}

// SetDistribution sets the distribution client (Subsystem C).
func (s *Server) SetDistribution(c DistributionClient) {
	s.distribution = c
}

// SetTransparency sets the transparency client (Subsystem D).
func (s *Server) SetTransparency(c TransparencyClient) {
	s.transparency = c
}

// ServeHTTP implements http.Handler. It speaks a single JSON-RPC 2.0 request
// per POST (batch not required by typical MCP HTTP clients).
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req rpcRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusOK, errorResp(nil, codeParseError, "parse error: "+err.Error()))
		return
	}
	if req.JSONRPC != "2.0" {
		writeJSON(w, http.StatusOK, errorResp(req.ID, codeInvalidRequest, "jsonrpc must be \"2.0\""))
		return
	}
	resp := s.dispatch(r.Context(), &req)
	// Notifications (no id) get no response per JSON-RPC.
	if req.ID == nil && resp != nil {
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) dispatch(ctx context.Context, req *rpcRequest) *rpcResponse {
	switch req.Method {
	case "initialize":
		return resultResp(req.ID, map[string]any{
			"protocolVersion": ProtocolVersion,
			"serverInfo":      map[string]string{"name": "aether-control", "version": "0.1.0"},
			"capabilities": map[string]any{
				"tools":     map[string]any{},
				"resources": map[string]any{},
				"prompts":   map[string]any{},
			},
		})
	case "tools/list":
		return resultResp(req.ID, map[string]any{"tools": toolCatalog()})
	case "tools/call":
		return s.handleToolCall(ctx, req)
	case "resources/list":
		return resultResp(req.ID, map[string]any{"resources": resourceCatalog()})
	case "resources/read":
		return s.handleResourceRead(req)
	case "prompts/list":
		return resultResp(req.ID, map[string]any{"prompts": promptCatalog()})
	case "prompts/get":
		return s.handlePromptGet(req)
	default:
		return errorResp(req.ID, codeMethodNotFound, "method not found: "+req.Method)
	}
}

// ---- catalogs -------------------------------------------------------------

func toolCatalog() []Tool {
	obj := func(props map[string]any) map[string]any {
		return map[string]any{"type": "object", "properties": props}
	}
	str := func(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }
	num := func(desc string) map[string]any { return map[string]any{"type": "integer", "description": desc} }
	return []Tool{
		{Name: "list_cores", Description: "List all supervised proxy cores and their status.", InputSchema: obj(nil)},
		{Name: "get_node_health", Description: "Probe the Core Supervisor health/readiness.", InputSchema: obj(nil)},
		{Name: "switch_protocol", Description: "Hot-swap a core's active protocol (drain where supported).",
			InputSchema: obj(map[string]any{"instance_id": str("core instance id"), "protocol_id": str("target protocol, e.g. hysteria2"), "drain_ms": num("drain timeout in ms (0 = hard cut)")})},
		{Name: "analyze_traffic", Description: "Return windowed per-(ISP, protocol) traffic/censorship feature stats.", InputSchema: obj(map[string]any{"protocol_id": str("optional filter")})},
		{Name: "apply_ai_recommendation", Description: "Push a fallback-chain policy to a core.",
			InputSchema: obj(map[string]any{"instance_id": str("core instance id"), "fallback_chain": map[string]any{"type": "array", "items": map[string]any{"type": "string"}}, "revision": num("monotonic policy revision")})},
		{Name: "route_destination", Description: "Resolve the Direct/Proxy/Block routing action for a destination (domain and/or IP).",
			InputSchema: obj(map[string]any{"domain": str("destination domain"), "ip": str("destination IP, e.g. 78.38.5.5")})},
		{Name: "get_training_pipeline_status", Description: "Get the AI training pipeline status (models, shadow mode, promotions).",
			InputSchema: obj(nil)},
		{Name: "promote_model_canary", Description: "Promote a shadow-mode model to production (requires shadow mode eligibility).",
			InputSchema: obj(map[string]any{"model_id": str("model identifier")})},
		{Name: "rollback_model", Description: "Roll back a promoted model to FSM-only (< 5s).",
			InputSchema: obj(map[string]any{"model_id": str("model identifier")})},
		{Name: "get_measurement_coverage", Description: "Get the k-anonymous measurement coverage map (never raw contributions).",
			InputSchema: obj(nil)},
		{Name: "get_distribution_pool_health", Description: "Get the rationed-pool distribution health.",
			InputSchema: obj(nil)},
		{Name: "get_transparency_log_head", Description: "Get the current signed tree head from the transparency log.",
			InputSchema: obj(nil)},
	}
}

func resourceCatalog() []Resource {
	return []Resource{
		{URI: "aether://node/status", Name: "node-status", Description: "Live supervisor health + core list.", MimeType: "application/json"},
		{URI: "aether://traffic/features", Name: "traffic-features", Description: "Live per-(ISP, protocol) feature points.", MimeType: "application/json"},
	}
}

func promptCatalog() []Prompt {
	return []Prompt{
		{Name: "diagnose_isp_failures", Description: "Build a diagnostic prompt for why users on a given ISP are failing.",
			Arguments: []PromptArgument{{Name: "isp", Description: "ISP name (e.g. MCI, Irancell)", Required: true}}},
		{Name: "protocol_switch_recommendation", Description: "Recommend a protocol switch for an instance from current telemetry.",
			Arguments: []PromptArgument{{Name: "instance_id", Description: "core instance id", Required: true}}},
	}
}

// ---- helpers --------------------------------------------------------------

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func resultResp(id any, result any) *rpcResponse {
	return &rpcResponse{JSONRPC: "2.0", ID: id, Result: result}
}

func errorResp(id any, code int, msg string) *rpcResponse {
	return &rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: msg}}
}

func mustJSON(v any) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Sprintf("<marshal error: %v>", err)
	}
	return string(b)
}
