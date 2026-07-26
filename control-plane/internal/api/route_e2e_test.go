package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

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
