package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aether-x/control-plane/internal/clientengine"
	"github.com/aether-x/control-plane/internal/store"
)

// PNG magic header — every valid PNG starts with these 8 bytes.
var pngMagic = []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}

// qrTestServer wires a real MemStore with a seeded subscription + the QR route.
func qrTestServer(t *testing.T) *Server {
	t.Helper()
	mem := store.NewMemStore()
	mem.SeedWithDemo()
	return &Server{
		SubStore:     &subStoreAdapter{store: mem},
		ClientEngine: &clientEngineAdapter{engine: clientengine.Default()},
		Build:        "qr-test",
	}
}

func TestServeSubscriptionQR_ValidToken(t *testing.T) {
	srv := qrTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/sub/demo-token-aether-x-2026/qr.png", nil)
	req.Host = "panel.aether-x.example"
	rec := httptest.NewRecorder()
	srv.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "image/png" {
		t.Errorf("content-type = %q, want image/png", ct)
	}
	// PNG magic bytes prove it is a real PNG, not an error page.
	body := rec.Body.Bytes()
	if !bytes.HasPrefix(body, pngMagic) {
		t.Errorf("body does not start with PNG magic; first bytes: % x", body[:min(8, len(body))])
	}
	// Credential-bearing image must never be cached by shared caches.
	if cc := rec.Header().Get("Cache-Control"); cc != "private, no-store" {
		t.Errorf("cache-control = %q, want 'private, no-store'", cc)
	}
}

func TestServeSubscriptionQR_InvalidToken(t *testing.T) {
	srv := qrTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/sub/does-not-exist/qr.png", nil)
	rec := httptest.NewRecorder()
	srv.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 for unknown token", rec.Code)
	}
}

func TestServeSubscriptionQR_StoreNotConfigured(t *testing.T) {
	srv := &Server{Build: "qr-test"} // SubStore == nil

	req := httptest.NewRequest(http.MethodGet, "/sub/any/qr.png", nil)
	rec := httptest.NewRecorder()
	srv.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 when store not configured", rec.Code)
	}
}

// min is provided by the existing e2e_integration_test.go in this package.

// The onboarding HTML page (browser visitors) must render the server-side QR
// via /sub/{token}/qr.png (Part 2 §7) — not a third-party API, not "coming soon".
func TestOnboardingHTMLReferencesServerQR(t *testing.T) {
	srv := qrTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/sub/demo-token-aether-x-2026", nil)
	req.Host = "panel.aether-x.example"
	req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120")
	req.Header.Set("Accept", "text/html")
	rec := httptest.NewRecorder()
	srv.Router().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	if !bytes.Contains([]byte(body), []byte("/qr.png")) {
		t.Error("onboarding HTML should reference the server-side /qr.png endpoint")
	}
	if bytes.Contains([]byte(body), []byte("به‌زودی")) {
		t.Error("onboarding HTML should no longer show the 'coming soon' QR placeholder")
	}
}
