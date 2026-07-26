package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/aether-x/control-plane/internal/metrics"
)

// corsMiddleware enables cross-origin dashboard access (the Next.js dev server
// runs on a different origin). Permissive in dev; tighten in production.
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// telemetryStream is the SSE endpoint /v1/telemetry/stream. It subscribes to
// the broadcaster hub and pushes live telemetry to the client, with a 15s
// keep-alive ping. Slow clients are dropped by the broadcaster (never block).
func (s *Server) telemetryStream(w http.ResponseWriter, r *http.Request) {
	if s.NewSubscriber == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "telemetry stream not configured",
		})
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "streaming unsupported"})
		return
	}

	ch, unsub := s.NewSubscriber()
	metrics.ActiveSSEClients.Inc()
	defer func() {
		metrics.ActiveSSEClients.Dec()
		unsub()
	}()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache, no-transform")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	// Initial open event so clients can flip their connection state.
	fmt.Fprint(w, "event: open\ndata: {}\n\n")
	flusher.Flush()

	ping := time.NewTicker(15 * time.Second)
	defer ping.Stop()

	for {
		select {
		case payload, ok := <-ch:
			if !ok {
				return
			}
			w.Write([]byte("data: "))
			w.Write(payload)
			w.Write([]byte("\n\n"))
			flusher.Flush()
		case <-ping.C:
			// SSE comment line as a keep-alive.
			w.Write([]byte(": ping\n\n"))
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}
