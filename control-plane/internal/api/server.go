// Package api exposes the control-plane HTTP surface: versioned REST under
// /v1, a health probe, and the mount point for the embedded MCP server
// (/mcp). The MCP server itself lands in package mcp (phase 1); here we only
// reserve the route and wire auth.
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	antiforgerypb "github.com/aether-x/control-plane/api/gen/go/aether/antiforgery/v1"
	supervisorpb "github.com/aether-x/control-plane/api/gen/go/aether/supervisor/v1"
	"github.com/aether-x/control-plane/internal/auth"
	"github.com/aether-x/control-plane/internal/model"
	"github.com/aether-x/control-plane/internal/store"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// ReadinessCheck describes one required runtime dependency. Check functions
// must honor the supplied context and never mutate the data plane.
type ReadinessCheck struct {
	Name  string
	Check func(context.Context) error
}

// Server holds API dependencies.
type Server struct {
	SupervisorCores func() (*supervisorpb.ListCoresResponse, error) // wrap of grpcclient.ListCores
	ReadyChecks     []ReadinessCheck
	Issuer          *auth.Issuer
	// AllowUnauthenticatedDevelopment is an explicit local-only escape hatch.
	// It must never be enabled in a public deployment.
	AllowUnauthenticatedDevelopment bool
	Build                           string
	// MCP is the embedded Model Context Protocol handler (tools/resources/prompts).
	// When nil, GET /mcp returns a not-implemented placeholder so the panel is
	// always runnable.
	MCP http.Handler
	// Antiforgery is the anti-forgery gRPC client (Rust bridge). When nil, the
	// /v1/subscriptions endpoints return 503.
	Antiforgery antiforgerypb.AntiForgeryServiceClient
	// Route proxies to the supervisor Route RPC (data-plane routing decision).
	// When nil, GET /v1/route returns 503.
	Route func(ctx context.Context, domain, ip string) (*supervisorpb.RouteResponse, error)
	// NewSubscriber returns a telemetry stream subscription (SSE hub).
	NewSubscriber func() (<-chan []byte, func())
	// NetworkContextResolver may attach ISP/region/country only after a trusted
	// ingress boundary authenticated those headers. A nil resolver preserves a
	// capability-only context with no fabricated network attribution.
	NetworkContextResolver ClientNetworkContextResolver
	// DynamicSubs is the verified subscription renderer. Production wiring uses
	// an operator-managed node catalog; a simulated telemetry optimizer must not
	// manufacture a destination address for this interface.
	DynamicSubs DynamicSubProvider
	// Sessions exposes durable/cache-backed migration state to privileged
	// operational endpoints. It is nil only in isolated API fixtures.
	Sessions *store.SessionManager

	Subscriber   SubscriberDataProvider
	ClientEngine ClientEngineProvider

	// ClientDrafts backs the AI-assisted client-registry workflow (Part 2 §6).
	ClientDrafts clientDraftsProvider

	// SubStore looks up subscriptions by token.
	SubStore SubStoreProvider

	// MeStore backs the authenticated /v1/me/* endpoints (live subscription
	// status resolved by JWT subject or subscription token).
	MeStore MeStoreProvider

	// integrations holds real components for E2E tests (type-asserted by tests).
	integrations any
}

// Router returns the configured HTTP router.
func (s *Server) Router() http.Handler {
	r := chi.NewRouter()
	r.Use(corsMiddleware)
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)

	r.Get("/healthz", s.healthz)
	r.Method("GET", "/metrics", promhttp.Handler())
	r.Get("/readyz", s.readyz)
	s.mountSubscriberOnboarding(r)

	r.Route("/v1", func(r chi.Router) {
		r.Use(s.authMiddleware)
		r.Get("/cores", s.adminOnly(s.listCores)) // privileged observability
		r.Get("/admin/sessions/stats", s.adminOnly(s.sessionStats))
		s.mountSubscriptions(r)
		s.mountDynamicSubscription(r)
		s.mountSubscriberPortal(r)
		s.mountMe(r)
		s.mountAdmin(r)
		r.Get("/route", s.routeDestination)
		r.Get("/telemetry/stream", s.telemetryStream)
		r.Get("/openapi.json", s.openapiJSONHandler)
		r.Get("/openapi.yaml", s.openapiYAMLHandler)
		// TODO(phase-1): /v1/users, /v1/nodes, /v1/policies
	})

	// MCP server (embedded, not a sidecar). Mounted under /mcp per the spec.
	if s.MCP != nil {
		r.Group(func(r chi.Router) {
			r.Use(s.authMiddleware)
			r.Use(s.requireRoleMiddleware(model.RoleAdmin))
			r.Mount("/mcp", s.MCP)
		})
	} else {
		r.Get("/mcp", s.mcpPlaceholder)
	}

	return r
}

func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "build": s.Build})
}

func (s *Server) readyz(w http.ResponseWriter, r *http.Request) {
	if s.SupervisorCores == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "no-supervisor"})
		return
	}
	ctx, cancel := withTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if _, err := s.SupervisorCores(); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"status": "supervisor-unreachable",
		})
		return
	}
	for _, check := range s.ReadyChecks {
		if check.Check == nil {
			continue
		}
		if err := check.Check(ctx); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{
				"status":     "dependency-unready",
				"dependency": check.Name,
			})
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func writeDependencyFailure(w http.ResponseWriter, publicMessage string) {
	writeJSON(w, http.StatusBadGateway, map[string]string{"error": publicMessage})
}

func (s *Server) listCores(w http.ResponseWriter, r *http.Request) {
	if s.SupervisorCores == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "no-supervisor"})
		return
	}
	resp, err := s.SupervisorCores()
	if err != nil {
		writeDependencyFailure(w, "supervisor service unavailable")
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) sessionStats(w http.ResponseWriter, r *http.Request) {
	if s.Sessions == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "session manager not configured"})
		return
	}
	ctx, cancel := withTimeout(r.Context(), 2*time.Second)
	defer cancel()
	writeJSON(w, http.StatusOK, s.Sessions.SessionStats(ctx))
}

func (s *Server) mcpPlaceholder(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusNotImplemented, map[string]string{
		"error": "MCP server not implemented in phase 0; see ARCHITECTURE.md §5.2",
	})
}

type claimsContextKey struct{}

// ClaimsFromContext returns validated JWT claims installed by authMiddleware.
func ClaimsFromContext(ctx context.Context) (*auth.Claims, bool) {
	claims, ok := ctx.Value(claimsContextKey{}).(*auth.Claims)
	return claims, ok && claims != nil
}

// authMiddleware validates bearer JWTs for every /v1 and MCP request. A nil
// issuer is retained only for isolated unit fixtures; real control-plane
// construction always supplies one. Local development must opt in explicitly.
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.AllowUnauthenticatedDevelopment || s.Issuer == nil {
			next.ServeHTTP(w, r)
			return
		}
		value := strings.TrimSpace(r.Header.Get("Authorization"))
		const prefix = "Bearer "
		if !strings.HasPrefix(value, prefix) || len(strings.TrimSpace(strings.TrimPrefix(value, prefix))) == 0 {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "bearer token required"})
			return
		}
		claims, err := s.Issuer.Parse(strings.TrimSpace(strings.TrimPrefix(value, prefix)))
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid or expired bearer token"})
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), claimsContextKey{}, claims)))
	})
}

func (s *Server) requireRoleMiddleware(minimum model.Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if s.AllowUnauthenticatedDevelopment || s.Issuer == nil {
				next.ServeHTTP(w, r)
				return
			}
			claims, ok := ClaimsFromContext(r.Context())
			if !ok {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "bearer token required"})
				return
			}
			if err := auth.Authorize(claims, minimum); err != nil {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "insufficient role"})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func (s *Server) adminOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.requireRoleMiddleware(model.RoleAdmin)(next).ServeHTTP(w, r)
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// withTimeout isolates the context import so tests don't need the dep inline.
func withTimeout(parent context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, d)
}
