package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	supervisorpb "github.com/aether-x/control-plane/api/gen/go/aether/supervisor/v1"
)

func readySupervisor() (*supervisorpb.ListCoresResponse, error) {
	return &supervisorpb.ListCoresResponse{}, nil
}

func TestReadyzRejectsUnreadyDependency(t *testing.T) {
	server := &Server{
		SupervisorCores: readySupervisor,
		ReadyChecks: []ReadinessCheck{
			{
				Name: "postgres",
				Check: func(context.Context) error {
					return errors.New("unavailable")
				},
			},
		},
	}
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	recorder := httptest.NewRecorder()
	server.Router().ServeHTTP(recorder, req)
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusServiceUnavailable)
	}
	if got := recorder.Body.String(); got == "" || !containsString(got, "postgres") {
		t.Fatalf("dependency name missing from readiness response: %q", got)
	}
}

func TestReadyzAcceptsAllDependencies(t *testing.T) {
	server := &Server{
		SupervisorCores: readySupervisor,
		ReadyChecks: []ReadinessCheck{
			{Name: "postgres", Check: func(context.Context) error { return nil }},
			{Name: "redis", Check: func(context.Context) error { return nil }},
			{Name: "clickhouse", Check: func(context.Context) error { return nil }},
		},
	}
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	recorder := httptest.NewRecorder()
	server.Router().ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
}

func containsString(value, fragment string) bool {
	for index := 0; index+len(fragment) <= len(value); index++ {
		if value[index:index+len(fragment)] == fragment {
			return true
		}
	}
	return false
}
