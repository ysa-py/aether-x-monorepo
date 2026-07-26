package api

import (
	"context"
	"net/http"
	"time"

	supervisorpb "github.com/aether-x/control-plane/api/gen/go/aether/supervisor/v1"

	"github.com/aether-x/control-plane/internal/metrics"
)

// routeDestination handles GET /v1/route?domain=...&ip=... and proxies to the
// supervisor's data-plane routing engine. Lets the frontend (or any REST
// client) query how a destination would be routed before connecting.
func (s *Server) routeDestination(w http.ResponseWriter, r *http.Request) {
	if s.Route == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "routing service not configured",
		})
		return
	}
	domain := r.URL.Query().Get("domain")
	ip := r.URL.Query().Get("ip")

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	resp, err := s.Route(ctx, domain, ip)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	action := routeActionString(resp.GetAction())
	metrics.RouteDecisionsTotal.WithLabelValues(action).Inc()
	writeJSON(w, http.StatusOK, map[string]any{
		"action": action,
		"domain": resp.GetDomain(),
		"ip":     resp.GetIp(),
	})
}

// routeActionString maps the proto enum to the human-readable action.
func routeActionString(a supervisorpb.RouteAction) string {
	switch a {
	case supervisorpb.RouteAction_ROUTE_ACTION_DIRECT:
		return "DIRECT"
	case supervisorpb.RouteAction_ROUTE_ACTION_PROXY:
		return "PROXY"
	case supervisorpb.RouteAction_ROUTE_ACTION_BLOCK:
		return "BLOCK"
	default:
		return "UNSPECIFIED"
	}
}
