package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aether-x/control-plane/internal/auth"
	"github.com/aether-x/control-plane/internal/model"
	"github.com/aether-x/control-plane/internal/store"
)

// newMeServer builds a Server wired with a real MemStore (satisfies
// MeStoreProvider directly) and the given issuer (may be nil for token-only
// auth scenarios).
func newMeServer(t *testing.T, issuer *auth.Issuer, seed func(*store.MemStore)) *Server {
	t.Helper()
	mem := store.NewMemStore()
	if seed != nil {
		seed(mem)
	}
	return &Server{
		MeStore: mem,
		Issuer:  issuer,
		Build:   "me-test",
	}
}

func seedLiveSub(mem *store.MemStore) {
	sub := &model.Subscription{
		ID:         "sub-pro-001",
		UserID:     "user-pro",
		PlanID:     "pro",
		BytesTotal: 50_000_000_000,
		BytesUsed:  12_500_000_000, // 25%
		ExpiresAt:  time.Now().Add(30 * 24 * time.Hour),
	}
	sub.SubToken = "tok-pro-live-001"
	_ = mem.Save(context.Background(), sub)
}

func seedEnterpriseSub(mem *store.MemStore) {
	sub := &model.Subscription{
		ID:         "sub-ent-002",
		UserID:     "user-ent",
		PlanID:     "enterprise",
		BytesTotal: 1_000_000_000_000_000,
		BytesUsed:  1_000_000_000,
		ExpiresAt:  time.Now().Add(365 * 24 * time.Hour),
	}
	sub.SubToken = "tok-ent-002"
	_ = mem.Save(context.Background(), sub)
}

func seedExpiredSub(mem *store.MemStore) {
	sub := &model.Subscription{
		ID:         "sub-exp-003",
		UserID:     "user-exp",
		PlanID:     "pro",
		BytesTotal: 10_000_000_000,
		BytesUsed:  1_000_000_000,
		ExpiresAt:  time.Now().Add(-48 * time.Hour), // already past
	}
	sub.SubToken = "tok-exp-003"
	_ = mem.Save(context.Background(), sub)
}

// --- Scenario 1: token query param returns live status with all required fields ---

func TestMe_TokenQueryParam_LiveStatus(t *testing.T) {
	srv := newMeServer(t, nil, seedLiveSub)

	req := httptest.NewRequest(http.MethodGet, "/v1/me/subscription?token=tok-pro-live-001", nil)
	rec := httptest.NewRecorder()
	srv.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	var resp MySubscriptionResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// Required fields from spec §8.
	if resp.BytesUsed != 12_500_000_000 {
		t.Errorf("bytes_used = %d, want 12500000000", resp.BytesUsed)
	}
	if resp.BytesTotal != 50_000_000_000 {
		t.Errorf("bytes_total = %d, want 50000000000", resp.BytesTotal)
	}
	if resp.ExpiresAt == "" {
		t.Error("expires_at must be set (RFC3339)")
	}
	if _, err := time.Parse(time.RFC3339, resp.ExpiresAt); err != nil {
		t.Errorf("expires_at not RFC3339: %v", err)
	}
	if resp.PlanType != "pro" {
		t.Errorf("plan_type = %q, want pro", resp.PlanType)
	}
	if !resp.IsLive {
		t.Error("is_live should be true for a fresh pro sub")
	}
	if resp.IsExpired {
		t.Error("is_expired should be false")
	}
	if resp.UsagePercent < 24.9 || resp.UsagePercent > 25.1 {
		t.Errorf("usage_percent = %.2f, want ~25", resp.UsagePercent)
	}
	if resp.DaysRemaining < 28 || resp.DaysRemaining > 31 {
		t.Errorf("days_remaining = %d, want ~30", resp.DaysRemaining)
	}
	if !strings.Contains(resp.SubURL, "/sub/tok-pro-live-001") {
		t.Errorf("sub_url missing token: %s", resp.SubURL)
	}
}

// --- Scenario 2: Bearer subtoken ---

func TestMe_BearerSubtoken(t *testing.T) {
	srv := newMeServer(t, nil, seedLiveSub)

	req := httptest.NewRequest(http.MethodGet, "/v1/me/subscription", nil)
	req.Header.Set("Authorization", "Bearer tok-pro-live-001")
	rec := httptest.NewRecorder()
	srv.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var resp MySubscriptionResponse
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if resp.SubscriptionID != "sub-pro-001" {
		t.Errorf("subscription_id = %q", resp.SubscriptionID)
	}
}

// --- Scenario 3: Bearer JWT resolves by user id ---

func TestMe_BearerJWT(t *testing.T) {
	issuer := auth.New([]byte("test-secret-32-bytes-xxxxxxxxxxxx"), time.Hour)
	srv := newMeServer(t, issuer, seedLiveSub)

	// Mint a JWT for the demo user.
	tok, err := issuer.Mint(model.User{ID: "user-pro", Role: model.RoleUser})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/me/subscription", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	srv.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp MySubscriptionResponse
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if resp.UserID != "user-pro" {
		t.Errorf("user_id = %q, want user-pro", resp.UserID)
	}
}

// --- Scenario 4: no credential → 401 ---

func TestMe_NoCredential_Unauthorized(t *testing.T) {
	srv := newMeServer(t, nil, seedLiveSub)

	req := httptest.NewRequest(http.MethodGet, "/v1/me/subscription", nil)
	rec := httptest.NewRecorder()
	srv.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

// --- Scenario 5: unknown token → 404 ---

func TestMe_UnknownToken_NotFound(t *testing.T) {
	srv := newMeServer(t, nil, seedLiveSub)

	req := httptest.NewRequest(http.MethodGet, "/v1/me/subscription?token=does-not-exist", nil)
	rec := httptest.NewRecorder()
	srv.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

// --- Scenario 6: expired subscription → is_live false, is_expired true ---

func TestMe_ExpiredSubscription(t *testing.T) {
	srv := newMeServer(t, nil, seedExpiredSub)

	req := httptest.NewRequest(http.MethodGet, "/v1/me/subscription?token=tok-exp-003", nil)
	rec := httptest.NewRecorder()
	srv.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var resp MySubscriptionResponse
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if resp.IsLive {
		t.Error("is_live should be false for expired sub")
	}
	if !resp.IsExpired {
		t.Error("is_expired should be true")
	}
	if resp.DaysRemaining != 0 {
		t.Errorf("days_remaining = %d, want 0", resp.DaysRemaining)
	}
}

// --- Scenario 7: enterprise plan tier ---

func TestMe_EnterprisePlan(t *testing.T) {
	srv := newMeServer(t, nil, seedEnterpriseSub)

	req := httptest.NewRequest(http.MethodGet, "/v1/me/subscription?token=tok-ent-002", nil)
	rec := httptest.NewRecorder()
	srv.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var resp MySubscriptionResponse
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if resp.PlanType != "enterprise" {
		t.Errorf("plan_type = %q, want enterprise", resp.PlanType)
	}
	if resp.PlanName != "Enterprise" {
		t.Errorf("plan_name = %q, want Enterprise", resp.PlanName)
	}
	if resp.BytesTotal != 1_000_000_000_000_000 {
		t.Errorf("enterprise bytes_total = %d", resp.BytesTotal)
	}
}

// --- Scenario 8: planTier unit coverage for free/unknown ---

func TestPlanTier(t *testing.T) {
	cases := []struct {
		in, wantSlug, wantName string
	}{
		{"free", "free", "Free"},
		{"trial", "free", "Free"},
		{"ENTERPRISE", "enterprise", "Enterprise"},
		{"", "pro", "Pro"},
		{"pro", "pro", "Pro"},
		{"plus", "pro", "Pro"},
		{"custom-tier", "custom-tier", "custom-tier"},
	}
	for _, c := range cases {
		slug, name := planTier(c.in)
		if slug != c.wantSlug || name != c.wantName {
			t.Errorf("planTier(%q) = (%q,%q), want (%q,%q)", c.in, slug, name, c.wantSlug, c.wantName)
		}
	}
}

// --- Scenario 9: concurrent reads (race detector guard) ---

func TestMe_ConcurrentReads(t *testing.T) {
	srv := newMeServer(t, nil, seedLiveSub)

	done := make(chan struct{})
	for i := 0; i < 30; i++ {
		go func(n int) {
			defer func() { done <- struct{}{} }()
			req := httptest.NewRequest(http.MethodGet, "/v1/me/subscription?token=tok-pro-live-001", nil)
			rec := httptest.NewRecorder()
			srv.Router().ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Errorf("goroutine %d: status %d", n, rec.Code)
			}
		}(i)
	}
	for i := 0; i < 30; i++ {
		<-done
	}
}
