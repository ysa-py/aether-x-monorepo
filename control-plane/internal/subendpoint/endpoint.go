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

// --- Body builders ---

// BuildBody generates the legacy fixture body for the requested format.
//
// It intentionally contains an example endpoint and is retained only for
// isolated tests/local fixtures. Production handlers must use
// CatalogSubscriptionService, which renders validated operator nodes instead.
func BuildBody(sub *SubscriptionData, format string) (body []byte, contentType string) {
	switch format {
	case "clash":
		return buildClashYAML(sub), "text/yaml; charset=utf-8"
	case "singbox":
		return buildSingboxJSON(sub), "application/json; charset=utf-8"
	default:
		return buildBase64Links(sub), "text/plain; charset=utf-8"
	}
}

func buildBase64Links(sub *SubscriptionData) []byte {
	// Placeholder proxy link. In production: assemble from real node config.
	link := fmt.Sprintf("vless://%s@aether-x.example:443?encryption=none&security=tls&type=ws&path=%%2Fsub&host=aether-x.example&sni=aether-x.example#Aether-X", sub.UserID)
	encoded := base64.StdEncoding.EncodeToString([]byte(link))
	return []byte(encoded)
}

func buildClashYAML(sub *SubscriptionData) []byte {
	yaml := fmt.Sprintf(`port: 7890
socks-port: 7891
mode: rule
proxies:
  - name: "Aether-X"
    type: vless
    server: aether-x.example
    port: 443
    uuid: %s
    network: ws
    tls: true
    udp: true
    ws-opts:
      path: /sub
      headers:
        Host: aether-x.example
proxy-groups:
  - name: "Aether-X"
    type: select
    proxies: ["Aether-X"]
rules:
  - MATCH,Aether-X
`, sub.UserID)
	return []byte(yaml)
}

func buildSingboxJSON(sub *SubscriptionData) []byte {
	jsonStr := fmt.Sprintf(`{
  "log": {"level": "warn"},
  "outbounds": [
    {
      "type": "vless",
      "tag": "Aether-X",
      "server": "aether-x.example",
      "server_port": 443,
      "uuid": "%s",
      "transport": {"type": "ws", "path": "/sub"},
      "tls": {"enabled": true, "server_name": "aether-x.example"}
    }
  ]
}`, sub.UserID)
	return []byte(jsonStr)
}
