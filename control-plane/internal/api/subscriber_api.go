package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

// SubscriberInfo is the response for GET /v1/sub/me.
type SubscriberInfo struct {
	SubscriptionID string       `json:"subscription_id"`
	BytesUsed      int64        `json:"bytes_used"`
	BytesTotal     int64        `json:"bytes_total"`
	ExpiresUnix    int64        `json:"expires_unix"`
	DaysRemaining  int          `json:"days_remaining"`
	IsExpired      bool         `json:"is_expired"`
	UsagePercent   float64      `json:"usage_percent"`
	Devices        []DeviceInfo `json:"devices"`
	MirrorURLs     []string     `json:"mirror_urls"`
	SubURL         string       `json:"sub_url"`
}

// DeviceInfo describes an active device session.
type DeviceInfo struct {
	DeviceID    string `json:"device_id"`
	Fingerprint string `json:"fingerprint"`
	Platform    string `json:"platform"`
	LastSeen    string `json:"last_seen"`
}

// SubscriberDataProvider abstracts how subscriber data is fetched.
// In production this calls the antiforgery service + device registry.
type SubscriberDataProvider interface {
	GetSubscriber(ctx context.Context) (*SubscriberInfo, error)
	RevokeDevice(ctx context.Context, deviceID string) error
}

// subscriberMe handles GET /v1/sub/me.
func (s *Server) subscriberMe(w http.ResponseWriter, r *http.Request) {
	if s.Subscriber == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "subscriber service not configured"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	info, err := s.Subscriber.GetSubscriber(ctx)
	if err != nil {
		writeDependencyFailure(w, "subscriber service unavailable")
		return
	}
	writeJSON(w, http.StatusOK, info)
}

// subscriberRevoke handles POST /v1/sub/revoke-device.
func (s *Server) subscriberRevoke(w http.ResponseWriter, r *http.Request) {
	if s.Subscriber == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "subscriber service not configured"})
		return
	}
	var req struct {
		DeviceID string `json:"device_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if req.DeviceID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "device_id required"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	if err := s.Subscriber.RevokeDevice(ctx, req.DeviceID); err != nil {
		writeDependencyFailure(w, "device revocation service unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

// subscriberClients handles GET /v1/sub/clients?platform=ios.
func (s *Server) subscriberClients(w http.ResponseWriter, r *http.Request) {
	if s.ClientEngine == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "client engine not configured"})
		return
	}
	platform := r.URL.Query().Get("platform")
	if platform == "" {
		platform = detectPlatform(r.UserAgent())
	}
	clients := s.ClientEngine.ClientsForPlatform(platform)
	writeJSON(w, http.StatusOK, map[string]any{
		"version":  s.ClientEngine.Version(),
		"platform": platform,
		"clients":  clients,
	})
}

func detectPlatform(ua string) string {
	ua = toLower(ua)
	switch {
	case contains(ua, "iphone"), contains(ua, "ipad"), contains(ua, "ios"):
		return "ios"
	case contains(ua, "android"):
		return "android"
	case contains(ua, "mac"):
		return "macos"
	case contains(ua, "win"):
		return "windows"
	case contains(ua, "linux"):
		return "linux"
	default:
		return "all"
	}
}

func toLower(s string) string {
	out := make([]byte, len(s))
	for i := range s {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		out[i] = c
	}
	return string(out)
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func (s *Server) mountSubscriberPortal(r chiRouter) {
	if s.Subscriber == nil && s.ClientEngine == nil {
		r.Get("/sub/*", func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "subscriber portal not configured"})
		})
		return
	}
	r.Get("/sub/me", s.subscriberMe)
	r.Post("/sub/revoke-device", s.subscriberRevoke)
	r.Get("/sub/clients", s.subscriberClients)
}

// ClientEngineProvider is the minimal interface the API needs from clientengine.Engine.
type ClientEngineProvider interface {
	ClientsForPlatform(platform string) []any
	Version() string
}
