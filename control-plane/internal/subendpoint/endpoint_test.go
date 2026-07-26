package subendpoint

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestWantsHTML(t *testing.T) {
	tests := []struct {
		ua     string
		accept string
		want   bool
	}{
		{"Mozilla/5.0 Chrome", "text/html", true},
		{"sing-box/1.0", "text/html", false}, // known client → never HTML
		{"v2rayNG/1.0", "*/*", false},
		{"curl/8.0", "*/*", false}, // no text/html
		{"Hiddify/1.0", "text/html", false},
	}
	for _, tt := range tests {
		req := httptest.NewRequest(http.MethodGet, "/sub/abc", nil)
		req.Header.Set("User-Agent", tt.ua)
		req.Header.Set("Accept", tt.accept)
		if got := WantsHTML(req); got != tt.want {
			t.Errorf("WantsHTML(ua=%q) = %v, want %v", tt.ua, got, tt.want)
		}
	}
}

func TestNegotiateFormat(t *testing.T) {
	tests := []struct {
		ua, query, want string
	}{
		{"", "", "base64"},
		{"Clash/1.0", "", "clash"},
		{"mihomo/1.0", "", "clash"},
		{"FlClash/1.0", "", "clash"},
		{"sing-box/1.0", "", "singbox"},
		{"NekoBox/1.0", "", "singbox"},
		{"v2rayNG/1.0", "", "base64"},
		{"", "format=clash", "clash"}, // query override
		{"", "format=singbox", "singbox"},
	}
	for _, tt := range tests {
		req := httptest.NewRequest(http.MethodGet, "/sub/abc?"+tt.query, nil)
		req.Header.Set("User-Agent", tt.ua)
		if got := NegotiateFormat(req); got != tt.want {
			t.Errorf("NegotiateFormat(ua=%q q=%q) = %s, want %s", tt.ua, tt.query, got, tt.want)
		}
	}
}

func TestApplySubscriptionHeaders(t *testing.T) {
	w := httptest.NewRecorder()
	sub := &SubscriptionData{
		SubToken:    "abc123",
		BytesUsed:   1_000_000_000,
		BytesTotal:  10_000_000_000,
		ExpiresAt:   time.Unix(2_000_000_000, 0),
		SubURL:      "https://panel.example/sub/abc123",
		DisplayName: "Aether-X Pro",
	}
	ApplySubscriptionHeaders(w, sub)

	// Critical header: Subscription-Userinfo
	su := w.Header().Get("Subscription-Userinfo")
	if su == "" {
		t.Fatal("Subscription-Userinfo header missing")
	}
	if !contains(su, "download=1000000000") {
		t.Errorf("Subscription-Userinfo missing download: %s", su)
	}
	if !contains(su, "total=10000000000") {
		t.Errorf("Subscription-Userinfo missing total: %s", su)
	}
	if !contains(su, "expire=2000000000") {
		t.Errorf("Subscription-Userinfo missing expire: %s", su)
	}

	// Profile-Title must be valid base64
	pt := w.Header().Get("Profile-Title")
	if pt == "" || !contains(pt, "base64:") {
		t.Errorf("Profile-Title invalid: %s", pt)
	}

	// Content-Disposition
	cd := w.Header().Get("Content-Disposition")
	if cd == "" {
		t.Error("Content-Disposition missing")
	}

	// Profile-Web-Page-Url
	pwp := w.Header().Get("Profile-Web-Page-Url")
	if pwp != sub.SubURL {
		t.Errorf("Profile-Web-Page-Url = %s, want %s", pwp, sub.SubURL)
	}
}

func TestBuildBody(t *testing.T) {
	sub := &SubscriptionData{UserID: "test-user-001"}

	// base64 format
	body, ct := BuildBody(sub, "base64")
	if ct != "text/plain; charset=utf-8" {
		t.Errorf("base64 content-type: %s", ct)
	}
	if len(body) == 0 {
		t.Error("base64 body empty")
	}

	// clash format
	body, ct = BuildBody(sub, "clash")
	if ct != "text/yaml; charset=utf-8" {
		t.Errorf("clash content-type: %s", ct)
	}
	if !contains(string(body), "proxies:") {
		t.Error("clash body missing proxies section")
	}

	// singbox format
	body, ct = BuildBody(sub, "singbox")
	if ct != "application/json; charset=utf-8" {
		t.Errorf("singbox content-type: %s", ct)
	}
	if !contains(string(body), "outbounds") {
		t.Error("singbox body missing outbounds")
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || indexOfStr(s, sub) >= 0)
}

func indexOfStr(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
