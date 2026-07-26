package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	antiforgerypb "github.com/aether-x/control-plane/api/gen/go/aether/antiforgery/v1"
)

// mountSubscriptions wires the /v1/subscriptions endpoints that proxy to the
// Rust anti-forgery core (issue/verify signed tokens, audit-log roots). The
// control plane never touches the crypto directly.
func (s *Server) mountSubscriptions(r chiRouter) {
	if s.Antiforgery == nil {
		// Degraded mode: surface a clear 503 so clients know the bridge is down.
		notConfigured := func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{
				"error": "anti-forgery service not configured",
			})
		}
		r.Get("/subscriptions/*", notConfigured)
		r.Post("/subscriptions/*", notConfigured)
		return
	}
	r.Post("/subscriptions/issue", s.issueSubscription)
	r.Post("/subscriptions/verify", s.verifySubscription)
	r.Get("/subscriptions/audit-root", s.auditRoot)
}

// chiRouter is the minimal subset of chi.Router we use, kept as an interface so
// `api` does not depend on chi for this unit-tested file.
type chiRouter interface {
	Post(pattern string, h http.HandlerFunc)
	Get(pattern string, h http.HandlerFunc)
}

type issueReq struct {
	SubscriptionID string `json:"subscription_id"`
	UserID         string `json:"user_id"`
	BytesTotal     int64  `json:"bytes_total"`
	BytesUsed      int64  `json:"bytes_used"`
	ExpiresUnix    int64  `json:"expires_unix"`
}

func (s *Server) issueSubscription(w http.ResponseWriter, r *http.Request) {
	var req issueReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if req.SubscriptionID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "subscription_id is required"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	resp, err := s.Antiforgery.IssueToken(ctx, &antiforgerypb.IssueTokenRequest{
		SubscriptionId: req.SubscriptionID,
		UserId:         req.UserID,
		BytesTotal:     req.BytesTotal,
		BytesUsed:      req.BytesUsed,
		ExpiresUnix:    req.ExpiresUnix,
	})
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"token":         resp.GetToken(),
		"audit_seq":     resp.GetAuditSeq(),
		"audit_hash":    hex.EncodeToString(resp.GetAuditHash()),
		"verifying_key": hex.EncodeToString(resp.GetVerifyingKey()),
	})
}

type verifyReq struct {
	Token   string `json:"token"`
	NowUnix int64  `json:"now_unix"`
}

func (s *Server) verifySubscription(w http.ResponseWriter, r *http.Request) {
	var req verifyReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if req.Token == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "token is required"})
		return
	}
	if req.NowUnix == 0 {
		req.NowUnix = time.Now().Unix()
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	resp, err := s.Antiforgery.VerifyToken(ctx, &antiforgerypb.VerifyTokenRequest{
		Token:   req.Token,
		NowUnix: req.NowUnix,
	})
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) auditRoot(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	resp, err := s.Antiforgery.AuditRoot(ctx, &antiforgerypb.AuditRootRequest{})
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"merkle_root": hex.EncodeToString(resp.GetMerkleRoot()),
		"chain_root":  hex.EncodeToString(resp.GetChainRoot()),
		"count":       resp.GetCount(),
	})
}
