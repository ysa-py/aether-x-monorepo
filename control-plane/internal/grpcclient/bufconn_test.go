package grpcclient_test

import (
	"context"
	"strings"
	"testing"

	supervisorpb "github.com/aether-x/control-plane/api/gen/go/aether/supervisor/v1"
	"github.com/aether-x/control-plane/internal/grpcclient/grpctest"
)

// fakeSupervisorServer is a canned CoreSupervisorServiceServer used to exercise
// the REAL gRPC client over an in-memory transport.
type fakeSupervisorServer struct {
	supervisorpb.UnimplementedCoreSupervisorServiceServer
	hotSwapMigrated bool
}

func (f *fakeSupervisorServer) ListCores(
	_ context.Context, _ *supervisorpb.ListCoresRequest,
) (*supervisorpb.ListCoresResponse, error) {
	return &supervisorpb.ListCoresResponse{
		Instances: []*supervisorpb.CoreInstance{
			{InstanceId: "i1", ProtocolId: "reality-vision", Status: supervisorpb.CoreStatus_CORE_STATUS_RUNNING},
			{InstanceId: "i2", ProtocolId: "hysteria2", Status: supervisorpb.CoreStatus_CORE_STATUS_DEGRADED, RestartCount: 2},
		},
	}, nil
}

func (f *fakeSupervisorServer) HealthCheck(
	_ context.Context, _ *supervisorpb.HealthCheckRequest,
) (*supervisorpb.HealthCheckResponse, error) {
	return &supervisorpb.HealthCheckResponse{
		Status:  supervisorpb.HealthCheckResponse_SERVING_STATUS_SERVING,
		Version: "test-1.0",
	}, nil
}

func (f *fakeSupervisorServer) HotSwapProtocol(
	_ context.Context, req *supervisorpb.HotSwapProtocolRequest,
) (*supervisorpb.HotSwapProtocolResponse, error) {
	return &supervisorpb.HotSwapProtocolResponse{
		InstanceId:       req.GetInstanceId(),
		Status:           supervisorpb.CoreStatus_CORE_STATUS_RUNNING,
		MigratedSessions: f.hotSwapMigrated,
	}, nil
}

func (f *fakeSupervisorServer) ApplyPolicy(
	_ context.Context, req *supervisorpb.ApplyPolicyRequest,
) (*supervisorpb.ApplyPolicyResponse, error) {
	return &supervisorpb.ApplyPolicyResponse{
		Applied:           true,
		EffectiveRevision: req.GetPolicy().GetRevision(),
	}, nil
}

func (f *fakeSupervisorServer) Route(_ context.Context, req *supervisorpb.RouteRequest) (*supervisorpb.RouteResponse, error) {
	act := supervisorpb.RouteAction_ROUTE_ACTION_PROXY
	if strings.Contains(req.GetDomain(), "ir") || req.GetIp() == "78.38.5.5" {
		act = supervisorpb.RouteAction_ROUTE_ACTION_DIRECT
	}
	return &supervisorpb.RouteResponse{Action: act, Domain: req.GetDomain(), Ip: req.GetIp()}, nil
}

// TestE2EListCoresAndHealth proves the client decodes real server responses.
func TestE2EListCoresAndHealth(t *testing.T) {
	c := grpctest.NewClient(t, &fakeSupervisorServer{})

	resp, err := c.ListCores(t.Context())
	if err != nil {
		t.Fatalf("ListCores: %v", err)
	}
	if got := len(resp.GetInstances()); got != 2 {
		t.Fatalf("expected 2 cores, got %d", got)
	}
	if resp.GetInstances()[0].GetInstanceId() != "i1" {
		t.Fatalf("unexpected instance: %+v", resp.GetInstances()[0])
	}

	h, err := c.Health(t.Context())
	if err != nil {
		t.Fatalf("Health: %v", err)
	}
	if h.GetStatus() != supervisorpb.HealthCheckResponse_SERVING_STATUS_SERVING {
		t.Fatalf("expected SERVING, got %v", h.GetStatus())
	}
	if h.GetVersion() != "test-1.0" {
		t.Fatalf("unexpected version %q", h.GetVersion())
	}
}

// TestE2EHotSwapAndApplyPolicy proves mutating RPCs round-trip correctly.
func TestE2EHotSwapAndApplyPolicy(t *testing.T) {
	c := grpctest.NewClient(t, &fakeSupervisorServer{hotSwapMigrated: true})

	hs, err := c.HotSwap(t.Context(), "i1", "hysteria2", 250)
	if err != nil {
		t.Fatalf("HotSwap: %v", err)
	}
	if !hs.GetMigratedSessions() {
		t.Fatal("expected migrated sessions")
	}

	ap, err := c.ApplyPolicy(t.Context(), "i1", &supervisorpb.Policy{
		FallbackChain: []string{"hysteria2", "tuic-v5"},
		Revision:      7,
	})
	if err != nil {
		t.Fatalf("ApplyPolicy: %v", err)
	}
	if !ap.GetApplied() || ap.GetEffectiveRevision() != 7 {
		t.Fatalf("unexpected ApplyPolicy response: %+v", ap)
	}
}

func TestE2ERoute(t *testing.T) {
	c := grpctest.NewClient(t, &fakeSupervisorServer{})
	r, err := c.Route(t.Context(), "bank.mellat.ir", "")
	if err != nil {
		t.Fatalf("Route: %v", err)
	}
	if r.GetAction() != supervisorpb.RouteAction_ROUTE_ACTION_DIRECT {
		t.Fatalf("expected DIRECT for ir domain, got %v", r.GetAction())
	}
	r2, _ := c.Route(t.Context(), "youtube.com", "142.250.0.1")
	if r2.GetAction() != supervisorpb.RouteAction_ROUTE_ACTION_PROXY {
		t.Fatalf("expected PROXY, got %v", r2.GetAction())
	}
}
