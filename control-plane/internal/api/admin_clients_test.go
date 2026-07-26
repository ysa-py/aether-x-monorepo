package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aether-x/control-plane/internal/clientengine"
)

// --- POST /v1/admin/clients/draft + confirm + GET drafts (Part 2 §6) ---

func draftTestServer(t *testing.T) *Server {
	t.Helper()
	engine := clientengine.Default()
	return &Server{
		Build:        "client-draft-test",
		ClientEngine: &clientEngineAdapter{engine: engine},
		ClientDrafts: clientengine.NewDraftRegistry(engine),
	}
}

func TestAdminDraftClient_HappyPath(t *testing.T) {
	srv := draftTestServer(t)
	body := `{"docs_url":"https://github.com/acme/NovaVPN"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/clients/draft", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	srv.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Status string `json:"status"`
		Draft  struct {
			Name   string `json:"name"`
			Status string `json:"status"`
		} `json:"draft"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Status != "drafted" {
		t.Errorf("status = %q, want drafted", resp.Status)
	}
	if resp.Draft.Name != "NovaVPN" {
		t.Errorf("draft name = %q, want NovaVPN", resp.Draft.Name)
	}
	if resp.Draft.Status != clientengine.StatusDraftPending {
		t.Errorf("draft status = %q, want pending-review", resp.Draft.Status)
	}
}

func TestAdminDraftClient_InvalidURL(t *testing.T) {
	srv := draftTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/clients/draft", bytes.NewBufferString(`{"docs_url":"not-a-url"}`))
	rec := httptest.NewRecorder()
	srv.Router().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestAdminConfirmClient_GateThenServed(t *testing.T) {
	srv := draftTestServer(t)

	// Draft first.
	draftReq := httptest.NewRequest(http.MethodPost, "/v1/admin/clients/draft", bytes.NewBufferString(`{"docs_url":"https://github.com/acme/NovaVPN"}`))
	srv.Router().ServeHTTP(httptest.NewRecorder(), draftReq)

	// Confirm.
	confirmReq := httptest.NewRequest(http.MethodPost, "/v1/admin/clients/confirm", bytes.NewBufferString(`{"name":"NovaVPN"}`))
	rec := httptest.NewRecorder()
	srv.Router().ServeHTTP(rec, confirmReq)
	if rec.Code != http.StatusOK {
		t.Fatalf("confirm status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	// Now the confirmed client must appear in the served /v1/sub/clients list.
	clientsReq := httptest.NewRequest(http.MethodGet, "/v1/sub/clients?platform=all", nil)
	clientsReq.Header.Set("User-Agent", "Mozilla/5.0")
	rec2 := httptest.NewRecorder()
	srv.Router().ServeHTTP(rec2, clientsReq)
	if rec2.Code != http.StatusOK {
		t.Fatalf("sub/clients status = %d", rec2.Code)
	}
	if !bytes.Contains(rec2.Body.Bytes(), []byte("NovaVPN")) {
		t.Error("confirmed client must be served to subscribers after confirm")
	}
}

func TestAdminConfirmClient_NotFound(t *testing.T) {
	srv := draftTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/clients/confirm", bytes.NewBufferString(`{"name":"ghost"}`))
	rec := httptest.NewRecorder()
	srv.Router().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestAdminListDrafts(t *testing.T) {
	srv := draftTestServer(t)
	_ = srv.Router() // ensure router builds
	d1 := httptest.NewRequest(http.MethodPost, "/v1/admin/clients/draft", bytes.NewBufferString(`{"docs_url":"https://github.com/x/AlphaVPN"}`))
	srv.Router().ServeHTTP(httptest.NewRecorder(), d1)

	req := httptest.NewRequest(http.MethodGet, "/v1/admin/clients/drafts", nil)
	rec := httptest.NewRecorder()
	srv.Router().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte("AlphaVPN")) {
		t.Error("drafts list should contain AlphaVPN")
	}
}

func TestAdminClientDrafts_Unconfigured(t *testing.T) {
	srv := &Server{Build: "t"} // ClientDrafts nil
	for _, tc := range []struct {
		method, path string
		body         string
		want         int
	}{
		{http.MethodPost, "/v1/admin/clients/draft", `{"docs_url":"x"}`, http.StatusServiceUnavailable},
		{http.MethodPost, "/v1/admin/clients/confirm", `{"name":"x"}`, http.StatusServiceUnavailable},
	} {
		req := httptest.NewRequest(tc.method, tc.path, bytes.NewBufferString(tc.body))
		rec := httptest.NewRecorder()
		srv.Router().ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Errorf("%s %s: status = %d, want %d", tc.method, tc.path, rec.Code, tc.want)
		}
	}
}
