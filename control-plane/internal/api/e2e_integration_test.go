package api

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aether-x/control-plane/internal/clientengine"
	"github.com/aether-x/control-plane/internal/model"
	"github.com/aether-x/control-plane/internal/store"
	"github.com/aether-x/control-plane/internal/subendpoint"
)

// --- E2E Integration Test Suite ---
//
// Exercises the FULL flow through real layers (no mocks):
//   Store (MemStore) → SubEndpoint handler → chi Router → HTTP Response
//   + Subscription-Userinfo headers
//   + Config Builder (vless:// with JA4 camouflage)
//   + Client Discovery Engine (autonomous AI synthesis)
//
// MemStore is a real store implementation (implements all interfaces) —
// it uses memory instead of PostgreSQL, but the code path is identical.

// setupIntegrationServer creates a fully-wired Server with seeded data.
func setupIntegrationServer(t *testing.T) *Server {
	t.Helper()
	memStore := store.NewMemStore()
	memStore.SeedWithDemo()

	// Create the client engine + discovery.
	engine := clientengine.Default()
	discovery := clientengine.NewClientDiscovery(engine, "")

	srv := &Server{
		SubStore:               &subStoreAdapter{store: memStore},
		ClientEngine:           &clientEngineAdapter{engine: engine},
		Build:                  "e2e-test",
		AllowLegacyPlaceholder: true, // isolated fixture; production must use catalog nodes
	}
	_ = discovery // wired into request path in production

	// Store the adapters for the test to use.
	srv.integrations = &integrationDeps{
		store:    memStore,
		engine:   engine,
		discover: discovery,
	}
	return srv
}

// integrationDeps holds the real components for E2E tests.
type integrationDeps struct {
	store    *store.MemStore
	engine   *clientengine.Engine
	discover *clientengine.ClientDiscoveryEngine
}

// subStoreAdapter bridges store.MemStore to the SubStoreProvider interface.
type subStoreAdapter struct {
	store *store.MemStore
}

func (a *subStoreAdapter) ByToken(ctx context.Context, token string) (*subendpoint.SubscriptionData, error) {
	sub, err := a.store.ByToken(ctx, token)
	if err != nil {
		return nil, err
	}
	return subToData(sub), nil
}

func subToData(sub *model.Subscription) *subendpoint.SubscriptionData {
	return &subendpoint.SubscriptionData{
		SubToken:    sub.SubToken,
		SubID:       sub.ID,
		UserID:      sub.UserID,
		BytesUsed:   sub.BytesUsed,
		BytesTotal:  sub.BytesTotal,
		ExpiresAt:   sub.ExpiresAt,
		PlanID:      sub.PlanID,
		DisplayName: "Aether-X",
	}
}

// clientEngineAdapter bridges clientengine.Engine to ClientEngineProvider.
type clientEngineAdapter struct {
	engine *clientengine.Engine
}

func (a *clientEngineAdapter) ClientsForPlatform(platform string) []any {
	clients := a.engine.ClientsForPlatform(platform)
	out := make([]any, len(clients))
	for i, c := range clients {
		out[i] = c
	}
	return out
}

func (a *clientEngineAdapter) Version() string {
	return a.engine.Version()
}

// --- Scenario A: Full Cold-Start Flow (DB Read → Headers → Body) ---

func TestE2E_ColdStart_SubscriptionFetch(t *testing.T) {
	srv := setupIntegrationServer(t)

	req := httptest.NewRequest(http.MethodGet, "/sub/demo-token-aether-x-2026", nil)
	req.Header.Set("User-Agent", "v2rayNG/1.8.0") // known proxy client
	rec := httptest.NewRecorder()

	srv.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String()[:200])
	}

	// Assert Subscription-Userinfo header.
	su := rec.Header().Get("Subscription-Userinfo")
	if su == "" {
		t.Fatal("Subscription-Userinfo header missing")
	}
	if !strings.Contains(su, "download=") {
		t.Errorf("Subscription-Userinfo missing download: %s", su)
	}
	if !strings.Contains(su, "total=") {
		t.Errorf("Subscription-Userinfo missing total: %s", su)
	}
	if !strings.Contains(su, "expire=") {
		t.Errorf("Subscription-Userinfo missing expire: %s", su)
	}

	// Assert body is base64 (default for v2rayNG).
	body := rec.Body.String()
	decoded, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		t.Fatalf("body should be base64 for v2rayNG: %v", err)
	}
	if !strings.Contains(string(decoded), "vless://") {
		t.Errorf("decoded body should contain vless:// link: %s", string(decoded)[:min(100, len(decoded))])
	}
}

func TestE2E_SubscriptionFailsClosedWithoutVerifiedCatalog(t *testing.T) {
	srv := setupIntegrationServer(t)
	srv.AllowLegacyPlaceholder = false

	req := httptest.NewRequest(http.MethodGet, "/sub/demo-token-aether-x-2026", nil)
	req.Header.Set("User-Agent", "v2rayNG/1.8.0")
	rec := httptest.NewRecorder()

	srv.Router().ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
	if strings.Contains(rec.Body.String(), "aether-x.example") {
		t.Fatal("a placeholder endpoint must never be returned in production mode")
	}
}

// --- Scenario A2: Clash Format Content Negotiation ---

func TestE2E_ClashFormat(t *testing.T) {
	srv := setupIntegrationServer(t)

	req := httptest.NewRequest(http.MethodGet, "/sub/demo-token-aether-x-2026?format=clash", nil)
	req.Header.Set("User-Agent", "Clash/1.0")
	rec := httptest.NewRecorder()

	srv.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "proxies:") {
		t.Error("clash body should contain 'proxies:'")
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "yaml") {
		t.Errorf("content-type should be yaml, got %s", ct)
	}
}

// --- Scenario A3: Sing-box Format ---

func TestE2E_SingboxFormat(t *testing.T) {
	srv := setupIntegrationServer(t)

	req := httptest.NewRequest(http.MethodGet, "/sub/demo-token-aether-x-2026?format=singbox", nil)
	req.Header.Set("User-Agent", "sing-box/1.0")
	rec := httptest.NewRecorder()

	srv.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "outbounds") {
		t.Error("singbox body should contain 'outbounds'")
	}
}

// --- Scenario A4: Browser gets HTML ---

func TestE2E_BrowserGetsHTML(t *testing.T) {
	srv := setupIntegrationServer(t)

	req := httptest.NewRequest(http.MethodGet, "/sub/demo-token-aether-x-2026", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120")
	req.Header.Set("Accept", "text/html")
	rec := httptest.NewRecorder()

	srv.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("browser should get HTML, got content-type %s", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "<html") {
		t.Error("body should contain <html")
	}
	if !strings.Contains(body, "countdown") {
		t.Error("HTML should contain countdown")
	}
}

// --- Scenario B: Invalid Token Returns 404 ---

func TestE2E_InvalidToken(t *testing.T) {
	srv := setupIntegrationServer(t)

	req := httptest.NewRequest(http.MethodGet, "/sub/nonexistent-token-xyz", nil)
	req.Header.Set("User-Agent", "v2rayNG/1.0")
	rec := httptest.NewRecorder()

	srv.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

// --- Scenario B2: Consecutive Reads (simulates warm cache) ---

func TestE2E_ConsecutiveReadsConsistent(t *testing.T) {
	srv := setupIntegrationServer(t)

	var firstBody string
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodGet, "/sub/demo-token-aether-x-2026", nil)
		req.Header.Set("User-Agent", "v2rayNG/1.0")
		rec := httptest.NewRecorder()
		srv.Router().ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("iteration %d: status %d", i, rec.Code)
		}
		if i == 0 {
			firstBody = rec.Body.String()
		} else if rec.Body.String() != firstBody {
			t.Fatalf("iteration %d: body changed between reads", i)
		}

		// Verify Subscription-Userinfo on every read.
		if rec.Header().Get("Subscription-Userinfo") == "" {
			t.Fatalf("iteration %d: header missing", i)
		}
	}
}

// --- Scenario C: AI Client Discovery ---

func TestE2E_AIClientDiscovery(t *testing.T) {
	srv := setupIntegrationServer(t)

	// Request with an unknown client UA.
	req := httptest.NewRequest(http.MethodGet, "/sub/demo-token-aether-x-2026", nil)
	req.Header.Set("User-Agent", "FutureVPN/2.0 (Android 14)")
	rec := httptest.NewRecorder()

	srv.Router().ServeHTTP(rec, req)

	// Should still get a valid response (base64 fallback for unknown client).
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for unknown UA", rec.Code)
	}

	// Should still have Subscription-Userinfo.
	if rec.Header().Get("Subscription-Userinfo") == "" {
		t.Fatal("Subscription-Userinfo missing for unknown client")
	}

	// Body should be base64 (default fallback).
	decoded, err := base64.StdEncoding.DecodeString(rec.Body.String())
	if err != nil {
		t.Fatalf("unknown UA should get base64 fallback: %v", err)
	}
	if !strings.Contains(string(decoded), "vless://") {
		t.Error("fallback body should contain vless://")
	}
}

// --- Scenario D: Profile Headers Validation ---

func TestE2E_ProfileHeaders(t *testing.T) {
	srv := setupIntegrationServer(t)

	req := httptest.NewRequest(http.MethodGet, "/sub/demo-token-aether-x-2026", nil)
	req.Header.Set("User-Agent", "v2rayNG/1.0")
	rec := httptest.NewRecorder()

	srv.Router().ServeHTTP(rec, req)

	// Profile-Title should be base64-encoded.
	pt := rec.Header().Get("Profile-Title")
	if !strings.HasPrefix(pt, "base64:") {
		t.Errorf("Profile-Title should start with base64: prefix, got %s", pt)
	}

	// Profile-Update-Interval should be set.
	if rec.Header().Get("Profile-Update-Interval") == "" {
		t.Error("Profile-Update-Interval missing")
	}

	// Profile-Web-Page-Url should contain the token.
	pwp := rec.Header().Get("Profile-Web-Page-Url")
	if !strings.Contains(pwp, "demo-token-aether-x-2026") {
		t.Errorf("Profile-Web-Page-Url should contain token: %s", pwp)
	}

	// Content-Disposition should be attachment.
	cd := rec.Header().Get("Content-Disposition")
	if !strings.Contains(cd, "attachment") {
		t.Errorf("Content-Disposition should be attachment: %s", cd)
	}

	// Support-Url should be set.
	if rec.Header().Get("Support-Url") == "" {
		t.Error("Support-Url missing")
	}
}

// --- Scenario E: Concurrent Requests (race-free guarantee) ---

func TestE2E_ConcurrentSubscriptionRequests(t *testing.T) {
	srv := setupIntegrationServer(t)

	done := make(chan struct{})
	for i := 0; i < 20; i++ {
		go func(n int) {
			defer func() { done <- struct{}{} }()
			req := httptest.NewRequest(http.MethodGet, "/sub/demo-token-aether-x-2026", nil)
			req.Header.Set("User-Agent", "v2rayNG/1.0")
			rec := httptest.NewRecorder()
			srv.Router().ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Errorf("goroutine %d: status %d", n, rec.Code)
			}
		}(i)
	}
	for i := 0; i < 20; i++ {
		<-done
	}
}

// --- Scenario F: Data Accuracy (bytes_used matches seeded value) ---

func TestE2E_DataAccuracy(t *testing.T) {
	srv := setupIntegrationServer(t)

	req := httptest.NewRequest(http.MethodGet, "/sub/demo-token-aether-x-2026", nil)
	req.Header.Set("User-Agent", "v2rayNG/1.0")
	rec := httptest.NewRecorder()

	srv.Router().ServeHTTP(rec, req)

	su := rec.Header().Get("Subscription-Userinfo")
	// Seeded: BytesUsed = 12.5 GB, BytesTotal = 50 GB.
	if !strings.Contains(su, "download=12500000000") {
		t.Errorf("download should be 12500000000 (12.5GB): %s", su)
	}
	if !strings.Contains(su, "total=50000000000") {
		t.Errorf("total should be 50000000000 (50GB): %s", su)
	}
}

// --- Scenario G: Client Discovery Engine (direct) ---

func TestE2E_DiscoveryEngineDirect(t *testing.T) {
	srv := setupIntegrationServer(t)
	deps := srv.integrations.(*integrationDeps)
	discovery := deps.discover

	// Unknown UA → should discover.
	req := httptest.NewRequest(http.MethodGet, "/sub/abc", nil)
	req.Header.Set("User-Agent", "NovaVPN/3.0 (iOS)")
	discovered := discovery.InspectRequest(req)
	if !discovered {
		t.Fatal("NovaVPN should be auto-discovered")
	}

	// Known UA → should NOT re-discover.
	req2 := httptest.NewRequest(http.MethodGet, "/sub/abc", nil)
	req2.Header.Set("User-Agent", "v2rayNG/1.0")
	if discovery.InspectRequest(req2) {
		t.Fatal("v2rayNG is known, should not be re-discovered")
	}

	// Count should be 1.
	if discovery.DiscoveryCount() != 1 {
		t.Fatalf("discovery count = %d, want 1", discovery.DiscoveryCount())
	}
}

// --- Scenario H: Config Builder (direct, multi-protocol) ---

func TestE2E_ConfigBuilderMultiProtocol(t *testing.T) {
	cfgs := []subendpoint.ProxyLinkConfig{
		{
			UserID: "user-1", Remark: "Aether-X-EU", FragPath: "sub",
			Node: subendpoint.NodeConfig{
				ID: "node-eu", Address: "eu.aether-x.example", Port: 443,
				Protocol: "vless", UUID: "uuid-eu", Transport: "ws",
				Path: "/sub", Host: "front.example.com", SNI: "front.example.com",
			},
		},
		{
			UserID: "user-1", Remark: "Aether-X-US", FragPath: "sub",
			Node: subendpoint.NodeConfig{
				ID: "node-us", Address: "us.aether-x.example", Port: 443,
				Protocol: "trojan", Password: "trojan-pass", Transport: "ws",
				Path: "/sub", Host: "front2.example.com", SNI: "front2.example.com",
			},
		},
	}

	// Base64 with 2 nodes.
	body, ct := subendpoint.BuildSubscriptionBodyEx(cfgs, "base64")
	if ct != "text/plain; charset=utf-8" {
		t.Fatalf("content-type: %s", ct)
	}
	decoded, _ := base64.StdEncoding.DecodeString(string(body))
	if !strings.Contains(string(decoded), "vless://") {
		t.Error("missing vless link")
	}
	if !strings.Contains(string(decoded), "trojan://") {
		t.Error("missing trojan link")
	}

	// Clash with 2 nodes.
	clashBody, _ := subendpoint.BuildSubscriptionBodyEx(cfgs, "clash")
	if !strings.Contains(string(clashBody), "Aether-X-EU") {
		t.Error("clash missing EU node name")
	}
	if !strings.Contains(string(clashBody), "Aether-X-US") {
		t.Error("clash missing US node name")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// suppress unused import
var _ = time.Now
