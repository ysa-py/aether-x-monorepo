package api

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/aether-x/control-plane/internal/subendpoint"
)

// mountSubscriberOnboarding wires the public GET /sub/{subToken} endpoint.
// Deliberately outside /v1 (no auth middleware) — the token IS the credential.
func (s *Server) mountSubscriberOnboarding(r chiRouter) {
	r.Get("/sub/{subToken}/qr.png", s.serveSubscriptionQR)
	r.Get("/sub/{subToken}", s.serveSubscription)
}

// serveSubscription is the content-negotiated subscription endpoint (§5).
// Enhanced: dynamically evaluates ClickHouse telemetry if DynamicSubs is configured,
// returning geo-routed optimized profiles compatible with sing-box, xray-core, clash-meta, shadowrocket, nekobox.
func (s *Server) serveSubscription(w http.ResponseWriter, r *http.Request) {
	subToken := chiURLParam(r, "subToken")
	if subToken == "" {
		http.NotFound(w, r)
		return
	}

	// Look up the subscription. If no store is configured, return a 503.
	if s.SubStore == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "subscription store not configured",
		})
		return
	}

	sub, err := s.SubStore.ByToken(r.Context(), subToken)
	if err != nil || sub == nil {
		http.NotFound(w, r)
		return
	}

	// Ensure SubURL is populated for headers.
	if sub.SubURL == "" {
		sub.SubURL = fmt.Sprintf("https://%s/sub/%s", r.Host, subToken)
	}

	// Content negotiation
	if subendpoint.WantsHTML(r) {
		s.renderOnboardingPage(w, r, sub)
		return
	}

	format := subendpoint.NegotiateFormat(r)

	// If a verified catalog provider is available, render a standard-client
	// subscription using only its trusted network context when configured.
	if s.DynamicSubs != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		result, renderErr := s.buildDynamicSubscription(ctx, sub, r, format)
		if renderErr != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{
				"error": "verified subscription nodes are unavailable",
			})
			return
		}
		subendpoint.ApplySubscriptionHeaders(w, sub)
		w.Header().Set("Content-Type", result.ContentType)
		w.Header().Set("X-Aether-Optimized", "true")
		w.Header().Set("X-Aether-Nodes", fmt.Sprintf("%d", result.Nodes))
		w.Header().Set("X-Aether-Reason", result.Reason)
		w.Write(result.Body)
		return
	}

	writeJSON(w, http.StatusServiceUnavailable, map[string]string{
		"error": "verified subscription node catalog is not configured",
	})
}

// renderOnboardingPage serves a minimal HTML page for browser visitors.
// In production, this redirects to the Next.js subscriber panel
// (/s/{subToken}). Here it renders a compact standalone HTML page so the
// endpoint is fully functional without the frontend.
func (s *Server) renderOnboardingPage(w http.ResponseWriter, r *http.Request, sub *subendpoint.SubscriptionData) {
	pct := 0.0
	if sub.BytesTotal > 0 {
		pct = float64(sub.BytesUsed) / float64(sub.BytesTotal) * 100
	}
	remaining := sub.BytesTotal - sub.BytesUsed
	if remaining < 0 {
		remaining = 0
	}
	color := "cyan"
	if pct >= 85 {
		color = "#ff3860"
	} else if pct >= 60 {
		color = "#ffb800"
	}

	title := sub.DisplayName
	if title == "" {
		title = "Aether-X"
	}

	html := buildOnboardingHTML(title, color, pct,
		formatBytes(sub.BytesUsed), formatBytes(sub.BytesTotal),
		buildCountdownHTML(sub.ExpiresAt, color), sub.SubURL)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write([]byte(html))
}

func buildCountdownHTML(expiresAt time.Time, color string) string {
	diff := time.Until(expiresAt)
	if diff < 0 {
		diff = 0
	}
	d := int(diff.Hours()) / 24
	h := int(diff.Hours()) % 24
	m := int(diff.Minutes()) % 60
	box := func(num int, label string) string {
		return fmt.Sprintf(`<div class="cd-box"><div class="cd-num" style="color:%s">%02d</div><div class="cd-lbl">%s</div></div>`, color, num, label)
	}
	return box(d, "روز") + box(h, "ساعت") + box(m, "دقیقه")
}

func formatBytes(b int64) string {
	if b == 0 {
		return "0 B"
	}
	const k = 1024
	sizes := []string{"B", "KB", "MB", "GB", "TB"}
	i := 0
	for v := b; v >= k && i < len(sizes)-1; v /= k {
		i++
	}
	return fmt.Sprintf("%.1f %s", float64(b)/float64(int64(1)<<uint(i*10)), sizes[i])
}

// chiURLParam extracts a URL parameter using chi (or a fallback for tests).
func chiURLParam(r *http.Request, key string) string {
	// Try chi's URLParam
	if v := r.PathValue(key); v != "" {
		return v
	}
	// Fallback: parse from path manually
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) >= 2 && parts[0] == "sub" {
		return parts[1]
	}
	return ""
}

// Compile-time assertion that the unused import is referenced.
var _ = context.Background
var _ = base64.StdEncoding

// SubStoreProvider is the minimal interface for subscription lookup.
type SubStoreProvider interface {
	ByToken(ctx context.Context, token string) (*subendpoint.SubscriptionData, error)
}

func buildOnboardingHTML(title, color string, pct float64, usedStr, totalStr, countdown, subURL string) string {
	dashUsed := pct * 3.14
	dashRemain := (100 - pct) * 3.14
	return "<!DOCTYPE html>\n" +
		"<html lang=\"fa\" dir=\"rtl\">\n" +
		"<head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n" +
		"<title>" + title + "</title>\n" +
		"<style>\n" +
		"  body{margin:0;background:#0B1220;color:#e2e8f0;font-family:system-ui,sans-serif;display:flex;justify-content:center;padding:2rem 1rem}\n" +
		"  .card{max-width:420px;width:100%;background:rgba(20,28,40,.8);border:1px solid rgba(56,72,96,.5);border-radius:1rem;padding:1.5rem;backdrop-filter:blur(12px)}\n" +
		"  h1{font-size:1.5rem;margin:0 0 1rem;background:linear-gradient(90deg,#22D3EE,#8B5CF6,#EC4899);-webkit-background-clip:text;-webkit-text-fill-color:transparent}\n" +
		"  .ring{width:120px;height:120px;margin:1rem auto;position:relative}\n" +
		"  .pct{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;font-size:1.5rem;font-weight:700;color:" + color + "}\n" +
		"  .info{display:flex;justify-content:space-between;margin:.5rem 0;font-size:.875rem;color:#94a3b8}\n" +
		"  .countdown{display:flex;gap:.5rem;justify-content:center;margin:1rem 0}\n" +
		"  .cd-box{text-align:center;min-width:60px}\n" +
		"  .cd-num{font-size:1.5rem;font-weight:700;color:" + color + "}\n" +
		"  .cd-lbl{font-size:.75rem;color:#64748b}\n" +
		"  .btn{display:block;width:100%;padding:.75rem;margin:.25rem 0;border-radius:.5rem;border:1px solid rgba(56,72,96,.5);background:rgba(14,18,28,.6);color:#e2e8f0;text-decoration:none;text-align:center;font-size:.875rem;transition:all .2s}\n" +
		"  .btn:hover{border-color:#22D3EE;background:rgba(34,211,238,.1)}\n" +
		"  .btn-primary{background:linear-gradient(90deg,rgba(34,211,238,.2),rgba(236,72,153,.2))}\n" +
		"  .qr{text-align:center;margin:1rem 0}\n" +
		"</style></head>\n" +
		"<body><div class=\"card\">\n" +
		"  <h1>" + title + "</h1>\n" +
		"  <div class=\"ring\">\n" +
		"    <svg width=\"120\" height=\"120\" viewBox=\"0 0 120 120\">\n" +
		"      <circle cx=\"60\" cy=\"60\" r=\"50\" fill=\"none\" stroke=\"rgba(56,72,96,.3)\" stroke-width=\"8\"/>\n" +
		"      <circle cx=\"60\" cy=\"60\" r=\"50\" fill=\"none\" stroke=\"" + color + "\" stroke-width=\"8\"\n" +
		"        stroke-dasharray=\"" + fmt.Sprintf("%.0f %.0f", dashUsed, dashRemain) + "\" stroke-linecap=\"round\"\n" +
		"        transform=\"rotate(-90 60 60)\" style=\"transition:stroke-dasharray .5s\"/>\n" +
		"    </svg>\n" +
		"    <div class=\"pct\">" + fmt.Sprintf("%.0f%%", pct) + "</div>\n" +
		"  </div>\n" +
		"  <div class=\"info\"><span>حجم مصرف‌شده</span><span>" + usedStr + " / " + totalStr + "</span></div>\n" +
		"  <div class=\"countdown\">" + countdown + "</div>\n" +
		"  <div class=\"qr\"><img src=\"" + subURL + "/qr.png\" alt=\"QR\" width=\"180\" height=\"180\" style=\"border-radius:12px\"/></div>\n" +
		"  <a class=\"btn btn-primary\" href=\"" + subURL + "\">➕ افزودن به اپ (خودکار)</a>\n" +
		"  <a class=\"btn\" href=\"" + subURL + "?format=clash\">Clash / Mihomo</a>\n" +
		"  <a class=\"btn\" href=\"" + subURL + "?format=singbox\">Sing-box / NekoBox</a>\n" +
		"  <a class=\"btn\" href=\"" + subURL + "?format=base64\">v2rayNG / Hiddify</a>\n" +
		"  <a class=\"btn\" href=\"javascript:void(0)\" onclick=\"navigator.clipboard.writeText('" + subURL + "')\">📋 کپی لینک</a>\n" +
		"</div></body></html>"
}
