// Package mcpbridge adapts the live control-plane components (the supervisor
// gRPC client and the featurizer) to the small interfaces the MCP server
// consumes (mcp.SupervisorClient / mcp.FeatureClient). Keeping these adapters
// here — rather than inline in main — makes them reusable and unit-testable.
package mcpbridge

import (
	"context"

	supervisorpb "github.com/aether-x/control-plane/api/gen/go/aether/supervisor/v1"
	"github.com/aether-x/control-plane/internal/grpcclient"
	"github.com/aether-x/control-plane/internal/mcp"
)

// SupervisorBridge adapts a grpcclient.Client to mcp.SupervisorClient.
type SupervisorBridge struct {
	c *grpcclient.Client
}

// NewSupervisor wraps a supervisor gRPC client as an MCP SupervisorClient.
func NewSupervisor(c *grpcclient.Client) mcp.SupervisorClient {
	return SupervisorBridge{c: c}
}

// Health maps the supervisor HealthCheck to the MCP view.
func (b SupervisorBridge) Health(ctx context.Context) (mcp.HealthInfo, error) {
	h, err := b.c.Health(ctx)
	if err != nil {
		return mcp.HealthInfo{}, err
	}
	return mcp.HealthInfo{
		Serving: h.GetStatus() == supervisorpb.HealthCheckResponse_SERVING_STATUS_SERVING,
		Version: h.GetVersion(),
	}, nil
}

// ListCores maps the supervisor ListCores to the MCP view.
func (b SupervisorBridge) ListCores(ctx context.Context) ([]mcp.CoreInfo, error) {
	resp, err := b.c.ListCores(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]mcp.CoreInfo, 0, len(resp.GetInstances()))
	for _, c := range resp.GetInstances() {
		out = append(out, mcp.CoreInfo{
			InstanceID: c.GetInstanceId(),
			ProtocolID: c.GetProtocolId(),
			Status:     c.GetStatus().String(),
			Restarts:   c.GetRestartCount(),
		})
	}
	return out, nil
}

// SwitchProtocol maps to the supervisor HotSwap RPC.
func (b SupervisorBridge) SwitchProtocol(
	ctx context.Context, instance, protocol string, drainMs uint32,
) (bool, error) {
	resp, err := b.c.HotSwap(ctx, instance, protocol, drainMs)
	if err != nil {
		return false, err
	}
	return resp.GetMigratedSessions(), nil
}

// ApplyFallbackChain maps to the supervisor ApplyPolicy RPC.
func (b SupervisorBridge) ApplyFallbackChain(
	ctx context.Context, instance string, chain []string, revision uint64,
) (uint64, error) {
	resp, err := b.c.ApplyPolicy(ctx, instance, &supervisorpb.Policy{
		FallbackChain: chain,
		Revision:      revision,
	})
	if err != nil {
		return 0, err
	}
	return resp.GetEffectiveRevision(), nil
}

// Route queries the data-plane routing engine for a destination's action.
func (b SupervisorBridge) Route(ctx context.Context, domain, ip string) (string, error) {
	resp, err := b.c.Route(ctx, domain, ip)
	if err != nil {
		return "", err
	}
	switch resp.GetAction() {
	case supervisorpb.RouteAction_ROUTE_ACTION_DIRECT:
		return "DIRECT", nil
	case supervisorpb.RouteAction_ROUTE_ACTION_PROXY:
		return "PROXY", nil
	case supervisorpb.RouteAction_ROUTE_ACTION_BLOCK:
		return "BLOCK", nil
	default:
		return "UNSPECIFIED", nil
	}
}
