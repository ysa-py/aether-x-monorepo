package api

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/aether-x/control-plane/internal/model"
)

// MeStoreProvider is the persistence interface backing the authenticated
// "/me" family of endpoints. It resolves the caller's live subscription either
// by authenticated user ID (JWT subject) or by the opaque subscription token
// (Bearer fallback / ?token=). Both store.MemStore and store.PgStore satisfy it.
type MeStoreProvider interface {
	ByUserID(ctx context.Context, userID string) (*model.Subscription, error)
	ByToken(ctx context.Context, token string) (*model.Subscription, error)
}

// MySubscriptionResponse is the JSON payload for GET /v1/me/subscription.
// It is the authoritative, server-verified status surfaced to the subscriber
// panel: quota, expiry, plan tier, and liveness flags. Client-reported values
// are never trusted — every field is derived from the signed store record.
type MySubscriptionResponse struct {
	SubscriptionID string       `json:"subscription_id"`
	UserID         string       `json:"user_id"`
	BytesUsed      int64        `json:"bytes_used"`
	BytesTotal     int64        `json:"bytes_total"`
	BytesRemaining int64        `json:"bytes_remaining"`
	ExpiresAt      string       `json:"expires_at"` // RFC3339
	ExpiresUnix    int64        `json:"expires_unix"`
	DaysRemaining  int          `json:"days_remaining"`
	UsagePercent   float64      `json:"usage_percent"`
	PlanType       string       `json:"plan_type"` // free | pro | enterprise
	PlanName       string       `json:"plan_name"` // localized-ish display label
	IsLive         bool         `json:"is_live"`   // healthy & usable right now
	IsExpired      bool         `json:"is_expired"`
	IsQuotaExhaust bool         `json:"is_quota_exhausted"`
	IsRevoked      bool         `json:"is_revoked"`
	Devices        []DeviceInfo `json:"devices"`
	MirrorURLs     []string     `json:"mirror_urls"`
	SubURL         string       `json:"sub_url"`
}

// mountMe wires the authenticated subscriber-self endpoints. These sit under
// the /v1 group but perform their OWN credential resolution (JWT subject OR
// subscription token), so the token IS the credential — no separate session.
func (s *Server) mountMe(r chiRouter) {
	if s.MeStore == nil {
		r.Get("/me/*", func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{
				"error": "me store not configured",
			})
		})
		return
	}
	r.Get("/me/subscription", s.meSubscription)
}

// meSubscription handles GET /v1/me/subscription.
//
// Authentication precedence:
//  1. Authorization: Bearer <jwt>   → resolve by JWT subject (user id)
//  2. Authorization: Bearer <subtoken> → resolve by opaque token
//  3. ?token=<subtoken>             → resolve by opaque token (deep-link)
//
// A bearer string is first attempted as a JWT; if the issuer is unset or the
// parse fails it is treated as a raw subscription token. This lets the same
// endpoint serve both the signed-in dashboard (JWT) and a one-tap deep link
// (?token=) opened directly on a subscriber's device.
func (s *Server) meSubscription(w http.ResponseWriter, r *http.Request) {
	if s.MeStore == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "me store not configured",
		})
		return
	}

	userID, subToken := s.extractMeCredential(r)
	if userID == "" && subToken == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error": "authentication required: provide a Bearer JWT, Bearer subtoken, or ?token=",
		})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	var (
		sub *model.Subscription
		err error
	)
	switch {
	case userID != "":
		sub, err = s.MeStore.ByUserID(ctx, userID)
	default:
		sub, err = s.MeStore.ByToken(ctx, subToken)
	}
	if err != nil || sub == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{
			"error": "subscription not found",
		})
		return
	}

	resp := buildMySubscriptionResponse(sub, r.Host)
	writeJSON(w, http.StatusOK, resp)
}

// extractMeCredential pulls the caller identity from the request, applying the
// precedence documented on meSubscription. Returns (userID, subToken) with at
// most one populated.
func (s *Server) extractMeCredential(r *http.Request) (userID, subToken string) {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		tok := strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
		if tok != "" {
			if s.Issuer != nil {
				if claims, perr := s.Issuer.Parse(tok); perr == nil && claims != nil && claims.UID != "" {
					return claims.UID, ""
				}
			}
			// Not a valid JWT (or no issuer configured): treat as opaque token.
			return "", tok
		}
	}
	if t := strings.TrimSpace(r.URL.Query().Get("token")); t != "" {
		return "", t
	}
	return "", ""
}

// buildMySubscriptionResponse projects a stored subscription into the
// server-verified subscriber-facing payload. Pure function — easy to unit test.
func buildMySubscriptionResponse(sub *model.Subscription, host string) MySubscriptionResponse {
	now := time.Now()
	bytesRemaining, secsRemaining := sub.Remaining(now)
	expired := sub.Expired(now)
	quotaExhaust := sub.BytesTotal > 0 && sub.BytesUsed >= sub.BytesTotal

	var pct float64
	if sub.BytesTotal > 0 {
		pct = float64(sub.BytesUsed) / float64(sub.BytesTotal) * 100
		if pct > 100 {
			pct = 100
		}
	}

	planType, planName := planTier(sub.PlanID)

	subURL := ""
	if sub.SubToken != "" {
		scheme := "https"
		if strings.HasPrefix(host, "localhost") || strings.HasPrefix(host, "127.0.0.1") {
			scheme = "http"
		}
		subURL = scheme + "://" + host + "/sub/" + sub.SubToken
	}

	return MySubscriptionResponse{
		SubscriptionID: sub.ID,
		UserID:         sub.UserID,
		BytesUsed:      sub.BytesUsed,
		BytesTotal:     sub.BytesTotal,
		BytesRemaining: bytesRemaining,
		ExpiresAt:      sub.ExpiresAt.UTC().Format(time.RFC3339),
		ExpiresUnix:    sub.ExpiresAt.Unix(),
		DaysRemaining:  daysFromSeconds(secsRemaining),
		UsagePercent:   pct,
		PlanType:       planType,
		PlanName:       planName,
		IsLive:         !expired,
		IsExpired:      expired,
		IsQuotaExhaust: quotaExhaust,
		IsRevoked:      sub.Revoked,
		Devices:        []DeviceInfo{},
		MirrorURLs:     []string{},
		SubURL:         subURL,
	}
}

// planTier maps a stored plan id to (type slug, display name). Unknown ids fall
// back to "pro" semantics so legacy data still renders a sane tier.
func planTier(planID string) (slug, name string) {
	switch strings.ToLower(strings.TrimSpace(planID)) {
	case "free", "trial":
		return "free", "Free"
	case "enterprise", "ultimate":
		return "enterprise", "Enterprise"
	case "", "pro", "standard", "plus":
		return "pro", "Pro"
	default:
		return planID, planID
	}
}

func daysFromSeconds(secs int64) int {
	if secs <= 0 {
		return 0
	}
	return int(secs / 86400)
}
