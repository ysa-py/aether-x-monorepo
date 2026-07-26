package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	supervisorpb "github.com/aether-x/control-plane/api/gen/go/aether/supervisor/v1"
	"github.com/aether-x/control-plane/internal/grpcclient/grpctest"
)

func TestRouteEndpointE2E(t *testing.T) {
	client := grpctest.NewClient(t, cannedSupervisor{})
	s := &Server{Route: client.Route}

	// Iranian domain + IP -> DIRECT.
	req := httptest.NewRequest(http.MethodGet, "/v1/route?domain=bank.mellat.ir&ip=78.38.5.5", nil)
	rec := httptest.NewRecorder()
	s.Router().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["action"] != "DIRECT" {
		t.Fatalf("expected DIRECT, got %v", body["action"])
	}

	// Foreign domain -> PROXY.
	req2 := httptest.NewRequest(http.MethodGet, "/v1/route?domain=youtube.com", nil)
	rec2 := httptest.NewRecorder()
	s.Router().ServeHTTP(rec2, req2)
	var body2 map[string]any
	_ = json.Unmarshal(rec2.Body.Bytes(), &body2)
	if body2["action"] != "PROXY" {
		t.Fatalf("expected PROXY, got %v", body2["action"])
	}
}

func TestRouteEndpointDisabledWhenBridgeDown(t *testing.T) {
	s := &Server{} // no Route configured
	req := httptest.NewRequest(http.MethodGet, "/v1/route?domain=x", nil)
	rec := httptest.NewRecorder()
	s.Router().ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rec.Code)
	}
}

func TestRouteEndpointSanitizesUpstreamFailure(t *testing.T) {
	const sensitiveDetail = "dial tcp 10.10.4.7:7070 with token=super-secret"
	server := &Server{
		Route: func(context.Context, string, string) (*supervisorpb.RouteResponse, error) {
			return nil, errors.New(sensitiveDetail)
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/route?domain=example.invalid", nil)
	recorder := httptest.NewRecorder()
	server.Router().ServeHTTP(recorder, req)
	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadGateway)
	}
	if strings.Contains(recorder.Body.String(), sensitiveDetail) {
		t.Fatalf("upstream detail leaked to client: %q", recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "routing service unavailable") {
		t.Fatalf("missing sanitized routing error: %q", recorder.Body.String())
	}
}
