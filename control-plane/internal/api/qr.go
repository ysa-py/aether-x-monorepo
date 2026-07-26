package api

import (
	"net/http"

	qrcode "github.com/skip2/go-qrcode"
)

// serveSubscriptionQR renders the subscription URL as a QR PNG, generated fully
// in-process (Part 2 §7). This is the security-critical path: a third-party QR
// API would leak every subscriber's token on every panel view, so the QR is
// rendered server-side and the PNG itself encodes the credential — hence the
// `private, no-store` cache directive.
//
// Mounted at GET /sub/{subToken}/qr.png, alongside the /sub/{subToken}
// onboarding handler. A valid token resolves through SubStore; an unknown token
// returns 404 (no information leak).
func (s *Server) serveSubscriptionQR(w http.ResponseWriter, r *http.Request) {
	subToken := chiURLParam(r, "subToken")
	if subToken == "" {
		http.NotFound(w, r)
		return
	}
	if s.SubStore == nil {
		http.Error(w, "subscription store not configured", http.StatusServiceUnavailable)
		return
	}
	sub, err := s.SubStore.ByToken(r.Context(), subToken)
	if err != nil || sub == nil {
		http.NotFound(w, r)
		return
	}

	scheme := "https"
	if isLocalhostHost(r.Host) {
		scheme = "http"
	}
	subURL := scheme + "://" + r.Host + "/sub/" + subToken

	png, err := qrcode.Encode(subURL, qrcode.Medium, 512)
	if err != nil {
		http.Error(w, "qr generation failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "image/png")
	// The PNG encodes the credential itself — never cache it anywhere shared.
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Write(png)
}

// isLocalhostHost reports whether the Host header points at a loopback address
// (used to pick http vs https for the encoded URL in dev).
func isLocalhostHost(host string) bool {
	return host == "localhost" || host == "127.0.0.1" ||
		len(host) > 10 && host[:10] == "127.0.0.1:" ||
		len(host) > 10 && host[:10] == "localhost:"
}
