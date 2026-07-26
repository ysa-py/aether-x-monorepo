package mcp

import (
	"context"
	"encoding/json"
	"fmt"
)

// tools/call params.
type toolCallParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments,omitempty"`
}

func (s *Server) handleToolCall(ctx context.Context, req *rpcRequest) *rpcResponse {
	var p toolCallParams
	if err := json.Unmarshal(req.Params, &p); err != nil {
		return errorResp(req.ID, codeInvalidParams, "invalid tools/call params: "+err.Error())
	}

	var res CallResult
	switch p.Name {
	case "list_cores":
		res = s.toolListCores(ctx)
	case "get_node_health":
		res = s.toolHealth(ctx)
	case "switch_protocol":
		res = s.toolSwitch(ctx, p.Arguments)
	case "analyze_traffic":
		res = s.toolAnalyzeTraffic(p.Arguments)
	case "apply_ai_recommendation":
		res = s.toolApplyRecommendation(ctx, p.Arguments)
	case "route_destination":
		res = s.toolRouteDestination(ctx, p.Arguments)
	case "get_training_pipeline_status":
		res = s.toolGetTrainingPipelineStatus()
	case "promote_model_canary":
		res = s.toolPromoteModelCanary(p.Arguments)
	case "rollback_model":
		res = s.toolRollbackModel(p.Arguments)
	case "get_measurement_coverage":
		res = s.toolGetMeasurementCoverage()
	case "get_distribution_pool_health":
		res = s.toolGetDistributionPoolHealth()
	case "get_transparency_log_head":
		res = s.toolGetTransparencyLogHead()
	default:
		return errorResp(req.ID, codeMethodNotFound, "unknown tool: "+p.Name)
	}
	return resultResp(req.ID, res)
}

func (s *Server) toolListCores(ctx context.Context) CallResult {
	if s.sup == nil {
		return ErrorResult("supervisor not configured")
	}
	cores, err := s.sup.ListCores(ctx)
	if err != nil {
		return ErrorResult("list_cores failed: " + err.Error())
	}
	if len(cores) == 0 {
		return TextResult("No supervised cores currently running.")
	}
	return TextResult(mustJSON(cores))
}

func (s *Server) toolHealth(ctx context.Context) CallResult {
	if s.sup == nil {
		return ErrorResult("supervisor not configured")
	}
	h, err := s.sup.Health(ctx)
	if err != nil {
		return ErrorResult("health probe failed: " + err.Error())
	}
	return TextResult(mustJSON(h))
}

func (s *Server) toolSwitch(ctx context.Context, args map[string]any) CallResult {
	if s.sup == nil {
		return ErrorResult("supervisor not configured")
	}
	instance, ok1 := args["instance_id"].(string)
	protocol, ok2 := args["protocol_id"].(string)
	if !ok1 || !ok2 || instance == "" || protocol == "" {
		return ErrorResult("switch_protocol requires instance_id and protocol_id")
	}
	drainMs := uint32(0)
	if v, ok := args["drain_ms"].(float64); ok {
		drainMs = uint32(v)
	}
	migrated, err := s.sup.SwitchProtocol(ctx, instance, protocol, drainMs)
	if err != nil {
		return ErrorResult("switch_protocol failed: " + err.Error())
	}
	msg := fmt.Sprintf("switched %s -> %s", instance, protocol)
	if migrated {
		msg += " (sessions drained/migrated)"
	} else {
		msg += " (hard cut)"
	}
	return TextResult(msg)
}

func (s *Server) toolAnalyzeTraffic(args map[string]any) CallResult {
	if s.feat == nil {
		return ErrorResult("featurizer not configured")
	}
	pts := s.feat.Snapshot()
	if protoFilter, ok := args["protocol_id"].(string); ok && protoFilter != "" {
		filtered := pts[:0]
		for _, p := range pts {
			if p.ProtocolID == protoFilter {
				filtered = append(filtered, p)
			}
		}
		pts = filtered
	}
	if len(pts) == 0 {
		return TextResult("No traffic feature points in the current window.")
	}
	return TextResult(mustJSON(pts))
}

func (s *Server) toolApplyRecommendation(ctx context.Context, args map[string]any) CallResult {
	if s.sup == nil {
		return ErrorResult("supervisor not configured")
	}
	instance, ok := args["instance_id"].(string)
	if !ok || instance == "" {
		return ErrorResult("apply_ai_recommendation requires instance_id")
	}
	var chain []string
	if raw, ok := args["fallback_chain"].([]any); ok {
		for _, c := range raw {
			if str, ok := c.(string); ok {
				chain = append(chain, str)
			}
		}
	}
	if len(chain) == 0 {
		return ErrorResult("apply_ai_recommendation requires a non-empty fallback_chain")
	}
	revision := uint64(0)
	if v, ok := args["revision"].(float64); ok {
		revision = uint64(v)
	}
	eff, err := s.sup.ApplyFallbackChain(ctx, instance, chain, revision)
	if err != nil {
		return ErrorResult("apply_ai_recommendation failed: " + err.Error())
	}
	return TextResult(fmt.Sprintf("policy applied to %s; effective revision=%d", instance, eff))
}

func (s *Server) toolRouteDestination(ctx context.Context, args map[string]any) CallResult {
	if s.sup == nil {
		return ErrorResult("supervisor not configured")
	}
	domain, _ := args["domain"].(string)
	ip, _ := args["ip"].(string)
	action, err := s.sup.Route(ctx, domain, ip)
	if err != nil {
		return ErrorResult("route_destination failed: " + err.Error())
	}
	return TextResult(fmt.Sprintf("destination domain=%q ip=%q -> %s", domain, ip, action))
}

func (s *Server) toolGetTrainingPipelineStatus() CallResult {
	if s.training == nil {
		return ErrorResult("training pipeline not configured")
	}
	return TextResult(mustJSON(s.training.GetStatus()))
}

func (s *Server) toolPromoteModelCanary(args map[string]any) CallResult {
	if s.training == nil {
		return ErrorResult("training pipeline not configured")
	}
	modelID, ok := args["model_id"].(string)
	if !ok || modelID == "" {
		return ErrorResult("promote_model_canary requires model_id")
	}
	promoted, err := s.training.PromoteModel(modelID)
	if err != nil {
		return ErrorResult("promote_model_canary failed: " + err.Error())
	}
	if promoted {
		return TextResult(fmt.Sprintf("model %s promoted successfully", modelID))
	}
	return TextResult(fmt.Sprintf("model %s not eligible for promotion (shadow mode requirements not met)", modelID))
}

func (s *Server) toolRollbackModel(args map[string]any) CallResult {
	if s.training == nil {
		return ErrorResult("training pipeline not configured")
	}
	modelID, ok := args["model_id"].(string)
	if !ok || modelID == "" {
		return ErrorResult("rollback_model requires model_id")
	}
	err := s.training.RollbackModel(modelID)
	if err != nil {
		return ErrorResult("rollback_model failed: " + err.Error())
	}
	return TextResult(fmt.Sprintf("model %s rolled back to FSM-only", modelID))
}

func (s *Server) toolGetMeasurementCoverage() CallResult {
	if s.measurement == nil {
		return ErrorResult("measurement network not configured")
	}
	return TextResult(mustJSON(s.measurement.GetCoverage()))
}

func (s *Server) toolGetDistributionPoolHealth() CallResult {
	if s.distribution == nil {
		return ErrorResult("distribution service not configured")
	}
	return TextResult(mustJSON(s.distribution.GetPoolHealth()))
}

func (s *Server) toolGetTransparencyLogHead() CallResult {
	if s.transparency == nil {
		return ErrorResult("transparency log not configured")
	}
	return TextResult(mustJSON(s.transparency.GetSignedTreeHead()))
}

// ---- resources/read -------------------------------------------------------

type resourceReadParams struct {
	URI string `json:"uri"`
}

func (s *Server) handleResourceRead(req *rpcRequest) *rpcResponse {
	var p resourceReadParams
	if err := json.Unmarshal(req.Params, &p); err != nil || p.URI == "" {
		return errorResp(req.ID, codeInvalidParams, "resources/read requires {uri}")
	}
	var text string
	switch p.URI {
	case "aether://node/status":
		text = s.resourceNodeStatus(req.ID != nil) // always compute; context via method below
	case "aether://traffic/features":
		text = s.resourceTrafficFeatures()
	default:
		return errorResp(req.ID, codeInvalidParams, "unknown resource uri: "+p.URI)
	}
	contents := map[string]any{
		"contents": []map[string]any{
			{"uri": p.URI, "mimeType": "application/json", "text": text},
		},
	}
	return resultResp(req.ID, contents)
}

// resourceNodeStatus returns health + cores as JSON text.
func (s *Server) resourceNodeStatus(_ bool) string {
	if s.sup == nil {
		return mustJSON(map[string]string{"error": "supervisor not configured"})
	}
	ctx := context.Background()
	h, err := s.sup.Health(ctx)
	cores, cerr := s.sup.ListCores(ctx)
	doc := map[string]any{"health": h}
	if err != nil {
		doc["health_error"] = err.Error()
	}
	if cerr != nil {
		doc["cores_error"] = cerr.Error()
	} else {
		doc["cores"] = cores
	}
	return mustJSON(doc)
}

func (s *Server) resourceTrafficFeatures() string {
	if s.feat == nil {
		return mustJSON(map[string]string{"error": "featurizer not configured"})
	}
	return mustJSON(s.feat.Snapshot())
}

// ---- prompts/get ----------------------------------------------------------

type promptGetParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments,omitempty"`
}

func (s *Server) handlePromptGet(req *rpcRequest) *rpcResponse {
	var p promptGetParams
	if err := json.Unmarshal(req.Params, &p); err != nil || p.Name == "" {
		return errorResp(req.ID, codeInvalidParams, "prompts/get requires {name}")
	}
	var text string
	switch p.Name {
	case "diagnose_isp_failures":
		isp, _ := p.Arguments["isp"].(string)
		text = s.promptDiagnoseISP(isp)
	case "protocol_switch_recommendation":
		inst, _ := p.Arguments["instance_id"].(string)
		text = s.promptProtocolSwitch(inst)
	default:
		return errorResp(req.ID, codeMethodNotFound, "unknown prompt: "+p.Name)
	}
	result := map[string]any{
		"messages": []map[string]any{
			{"role": "user", "content": map[string]any{"type": "text", "text": text}},
		},
	}
	return resultResp(req.ID, result)
}

func (s *Server) promptDiagnoseISP(isp string) string {
	snapshot := "n/a"
	if s.feat != nil {
		snapshot = mustJSON(s.feat.Snapshot())
	}
	ispLine := isp
	if ispLine == "" {
		ispLine = "<unspecified ISP>"
	}
	return fmt.Sprintf(
		"Diagnose why users on ISP %s are failing to connect. "+
			"Analyze the windowed per-(ISP, protocol) telemetry below and recommend the best "+
			"protocol + fragmentation strategy. Telemetry feature points:\n%s", ispLine, snapshot)
}

func (s *Server) promptProtocolSwitch(instance string) string {
	inst := instance
	if inst == "" {
		inst = "<unspecified instance>"
	}
	features := "n/a"
	if s.feat != nil {
		features = mustJSON(s.feat.Snapshot())
	}
	return fmt.Sprintf(
		"Given the current traffic features for instance %s below, recommend whether to keep the "+
			"active protocol or switch, and to what. If switching, provide the full fallback chain. "+
			"Features:\n%s", inst, features)
}
