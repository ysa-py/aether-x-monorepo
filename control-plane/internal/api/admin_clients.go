package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/aether-x/control-plane/internal/clientengine"
)

// ClientDrafts backs the AI-assisted client-registry workflow (Part 2 §6).
// Admin drafts a candidate from a docs URL; only confirmed drafts are promoted
// into the served client engine.
type clientDraftsProvider interface {
	DraftFromURLAndStore(docsURL string) (*clientengine.DiscoveredClient, error)
	Confirm(name string) (*clientengine.DiscoveredClient, error)
	Drafts() []clientengine.DiscoveredClient
}

// adminDraftClient handles POST /v1/admin/clients/draft.
func (s *Server) adminDraftClient(w http.ResponseWriter, r *http.Request) {
	if s.ClientDrafts == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "client draft registry not configured"})
		return
	}
	var req struct {
		DocsURL string `json:"docs_url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	draft, err := s.ClientDrafts.DraftFromURLAndStore(req.DocsURL)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "client draft rejected"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "drafted",
		"draft":  draft,
	})
}

// adminConfirmClient handles POST /v1/admin/clients/confirm.
func (s *Server) adminConfirmClient(w http.ResponseWriter, r *http.Request) {
	if s.ClientDrafts == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "client draft registry not configured"})
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if req.Name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name is required"})
		return
	}
	confirmed, err := s.ClientDrafts.Confirm(req.Name)
	if err != nil {
		if errors.Is(err, clientengine.ErrDraftNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "draft not found"})
			return
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "client confirmation rejected"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "confirmed",
		"client": confirmed,
	})
}

// adminListDrafts handles GET /v1/admin/clients/drafts.
func (s *Server) adminListDrafts(w http.ResponseWriter, r *http.Request) {
	if s.ClientDrafts == nil {
		writeJSON(w, http.StatusOK, map[string]any{"drafts": []any{}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"drafts": s.ClientDrafts.Drafts()})
}

// mountAdminClients wires the AI-assisted client-registry surface.
func (s *Server) mountAdminClients(r chiRouter) {
	r.Post("/admin/clients/draft", s.adminOnly(s.adminDraftClient))
	r.Post("/admin/clients/confirm", s.adminOnly(s.adminConfirmClient))
	r.Get("/admin/clients/drafts", s.adminOnly(s.adminListDrafts))
}
