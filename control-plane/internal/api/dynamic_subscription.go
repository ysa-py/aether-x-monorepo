package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/aether-x/control-plane/internal/subendpoint"
	"github.com/aether-x/control-plane/internal/telemetry"
)

// DynamicSubProvider renders a standard-client subscription from verified
// operator data. A future telemetry optimizer may implement this interface only
// after its score reader is real and independently validated.
type DynamicSubProvider interface {
	BuildGeoRouted(
		ctx context.Context,
		sub *subendpoint.SubscriptionData,
		userAgent string,
		clientIP string,
		format string,
	) (*subendpoint.GeoRoutedProfileResult, error)
}

// ContextAwareDynamicSubProvider accepts a verified client network context from
// the API boundary. Catalog-backed providers implement it; legacy providers
// remain compatible through DynamicSubProvider's capability-only method.
type ContextAwareDynamicSubProvider interface {
	BuildGeoRoutedWithContext(
		ctx context.Context,
		sub *subendpoint.SubscriptionData,
		client telemetry.ClientContext,
		format string,
	) (*subendpoint.GeoRoutedProfileResult, error)
}

func (s *Server) resolveClientContext(request *http.Request) telemetry.ClientContext {
	if s.NetworkContextResolver != nil {
		return s.NetworkContextResolver.Resolve(request)
	}
	return subendpoint.DetectClientContext(request.UserAgent(), request.RemoteAddr)
}

func (s *Server) buildDynamicSubscription(
	ctx context.Context,
	sub *subendpoint.SubscriptionData,
	request *http.Request,
	format string,
) (*subendpoint.GeoRoutedProfileResult, error) {
	if provider, ok := s.DynamicSubs.(ContextAwareDynamicSubProvider); ok {
		return provider.BuildGeoRoutedWithContext(ctx, sub, s.resolveClientContext(request), format)
	}
	return s.DynamicSubs.BuildGeoRouted(ctx, sub, request.UserAgent(), request.RemoteAddr, format)
}

// mountDynamicSubscription wires the catalog-backed /v1/subscriptions endpoint.
func (s *Server) mountDynamicSubscription(r chiRouter) {
	if s.DynamicSubs == nil {
		return
	}
	r.Get("/subscriptions/optimized", s.optimizedSubscription)
}

func (s *Server) optimizedSubscription(w http.ResponseWriter, r *http.Request) {
	if s.DynamicSubs == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "dynamic optimizer not configured"})
		return
	}
	token := r.URL.Query().Get("token")
	if token == "" {
		token = r.Header.Get("X-Subscription-Token")
	}
	if token == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "token required (?token= or X-Subscription-Token header)"})
		return
	}
	if s.SubStore == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "subscription store not configured"})
		return
	}
	sub, err := s.SubStore.ByToken(r.Context(), token)
	if err != nil || sub == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "subscription not found"})
		return
	}

	format := r.URL.Query().Get("format")
	if format == "" {
		format = subendpoint.NegotiateFormat(r)
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	result, err := s.buildDynamicSubscription(ctx, sub, r, format)
	if err != nil {
		status := http.StatusInternalServerError
		message := "subscription rendering failed"
		if errors.Is(err, subendpoint.ErrNoCompatibleNodes) {
			status = http.StatusServiceUnavailable
			message = "verified subscription nodes are unavailable"
		}
		writeJSON(w, status, map[string]string{"error": message})
		return
	}

	// Headers for client compatibility
	subendpoint.ApplySubscriptionHeaders(w, sub)
	w.Header().Set("Content-Type", result.ContentType)
	w.Header().Set("X-Aether-Optimized", "true")
	w.Header().Set("X-Aether-Reason", result.Reason)
	w.Header().Set("X-Aether-Nodes", toString(result.Nodes))
	w.Header().Set("X-Aether-Generated-At", result.GeneratedAt.Format(time.RFC3339))
	w.Write(result.Body)
}

func toString(i int) string {
	return fmt.Sprintf("%d", i)
}
