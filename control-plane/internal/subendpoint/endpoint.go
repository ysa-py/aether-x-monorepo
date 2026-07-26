// Package subendpoint implements the public GET /sub/{subToken} endpoint —
// the single URL that serves both proxy clients (subscription config) and
// browsers (HTML onboarding page). Content-negotiated via User-Agent.
//
// This is the highest-leverage component: the Subscription-Userinfo header
// makes expiry/usage appear automatically inside every compliant client app
// — present and future — with zero per-client code.
package subendpoint

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// SubscriptionData is what the handler needs to build a response. It mirrors
// the fields from model.Subscription + the antiforgery Claims.
type SubscriptionData struct {
	SubToken    string
	SubID       string
	UserID      string
	BytesUsed   int64
	BytesTotal  int64
	ExpiresAt   time.Time
	PlanID      string
	SubURL      string // full subscription URL for this token
	DisplayName string // for Profile-Title header
}

// SubscriptionStore is the lookup interface. In production this is a Postgres
// repository; tests use a mock.
type SubscriptionStore interface {
	ByToken(ctx context.Context, token string) (*SubscriptionData, error)
}

// --- Content negotiation (§5.1) ---

var knownClientUA = regexp.MustCompile(`(?i)(clash|mihomo|v2ray|hiddify|shadowrocket|nekobox|sing-box|sfa|karing|streisand|happ)`)

// WantsHTML returns true when a human browser is viewing the link.
// A known proxy client UA always wins — never show a proxy app an HTML page.
func WantsHTML(r *http.Request) bool {
	if knownClientUA.MatchString(r.UserAgent()) {
		return false
	}
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

// NegotiateFormat picks the subscription body format based on UA or ?format=.
func NegotiateFormat(r *http.Request) string {
	if f := r.URL.Query().Get("format"); f != "" {
		return f
	}
	ua := strings.ToLower(r.UserAgent())
	switch {
	case strings.Contains(ua, "clash"), strings.Contains(ua, "mihomo"), strings.Contains(ua, "flclash"):
		return "clash"
	case strings.Contains(ua, "sing-box"), strings.Contains(ua, "sfa"),
		strings.Contains(ua, "nekobox"), strings.Contains(ua, "karing"):
		return "singbox"
	default:
		return "base64"
	}
}

// --- Standard response headers (§5.2) ---

// ApplySubscriptionHeaders sets the de-facto standard headers that make
// expiry/usage appear automatically inside every compliant client.
func ApplySubscriptionHeaders(w http.ResponseWriter, sub *SubscriptionData) {
	info := fmt.Sprintf("upload=0; download=%d; total=%d; expire=%d",
		sub.BytesUsed, sub.BytesTotal, sub.ExpiresAt.Unix())
	w.Header().Set("Subscription-Userinfo", info)
	w.Header().Set("Profile-Update-Interval", "6")
	title := sub.DisplayName
	if title == "" {
		title = "Aether-X"
	}
	w.Header().Set("Profile-Title", "base64:"+base64.StdEncoding.EncodeToString([]byte(title)))
	w.Header().Set("Profile-Web-Page-Url", sub.SubURL)
	w.Header().Set("Support-Url", "https://t.me/aetherx_support")
	w.Header().Set("Content-Disposition", `attachment; filename="aether-x"`)
}
