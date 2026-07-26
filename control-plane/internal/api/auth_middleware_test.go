package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aether-x/control-plane/internal/auth"
	"github.com/aether-x/control-plane/internal/model"
)

func mintAPITestToken(t *testing.T, issuer *auth.Issuer, role model.Role) string {
	t.Helper()
	token, err := issuer.Mint(model.User{ID: string(role) + "-id", Role: role})
	if err != nil {
		t.Fatalf("mint token: %v", err)
	}
	return token
}

func TestAPIBearerAuthenticationAndAdminRBAC(t *testing.T) {
	issuer := auth.New([]byte("01234567890123456789012345678901"), time.Hour)
	server := &Server{Issuer: issuer, Build: "auth-test"}

	noToken := httptest.NewRequest(http.MethodGet, "/v1/transports", nil)
	noTokenRecorder := httptest.NewRecorder()
	server.Router().ServeHTTP(noTokenRecorder, noToken)
	if noTokenRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("missing token status = %d, want %d", noTokenRecorder.Code, http.StatusUnauthorized)
	}

	userToken := mintAPITestToken(t, issuer, model.RoleUser)
	userRequest := httptest.NewRequest(http.MethodGet, "/v1/transports", nil)
	userRequest.Header.Set("Authorization", "Bearer "+userToken)
	userRecorder := httptest.NewRecorder()
	server.Router().ServeHTTP(userRecorder, userRequest)
	if userRecorder.Code != http.StatusForbidden {
		t.Fatalf("user admin-route status = %d, want %d", userRecorder.Code, http.StatusForbidden)
	}

	adminToken := mintAPITestToken(t, issuer, model.RoleAdmin)
	adminRequest := httptest.NewRequest(http.MethodGet, "/v1/transports", nil)
	adminRequest.Header.Set("Authorization", "Bearer "+adminToken)
	adminRecorder := httptest.NewRecorder()
	server.Router().ServeHTTP(adminRecorder, adminRequest)
	if adminRecorder.Code != http.StatusOK {
		t.Fatalf("admin route status = %d, want %d; body=%s", adminRecorder.Code, http.StatusOK, adminRecorder.Body.String())
	}
}

func TestAPIBearerAuthenticationRejectsMalformedCredentials(t *testing.T) {
	issuer := auth.New([]byte("01234567890123456789012345678901"), time.Hour)
	server := &Server{Issuer: issuer, Build: "auth-test"}

	request := httptest.NewRequest(http.MethodGet, "/v1/route", nil)
	request.Header.Set("Authorization", "Basic not-a-bearer-token")
	recorder := httptest.NewRecorder()
	server.Router().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("malformed token status = %d, want %d", recorder.Code, http.StatusUnauthorized)
	}
}
