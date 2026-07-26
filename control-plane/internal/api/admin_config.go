package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/aether-x/control-plane/internal/subendpoint"
	"github.com/aether-x/control-plane/internal/transport"
)

// TransportsResponse is the payload for GET /v1/transports — the catalog the
// admin config-builder panel renders. Data-driven: adding a transport entry to
// the registry surfaces it here with zero code changes.
type TransportsResponse struct {
	Version    string                `json:"version"`
	Protocols  []transport.Protocol  `json:"protocols"`
	Transports []transport.Transport `json:"transports"`
}

// transportsHandler handles GET /v1/transports.
func (s *Server) transportsHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, TransportsResponse{
		Version:    "1.0",
		Protocols:  transport.Protocols(),
		Transports: transport.Catalog(),
	})
}

// BuildConfigRequest is the body for POST /v1/admin/build-config. The admin
// selects protocol + transport + params; the server returns the authoritative
// generated configs (share link + Clash + sing-box + base64).
type BuildConfigRequest struct {
	Protocol    string `json:"protocol"`
	Transport   string `json:"transport"`
	Address     string `json:"address"`
	Port        int    `json:"port"`
	UUID        string `json:"uuid"`
	Password    string `json:"password"`
	Path        string `json:"path"`
	Host        string `json:"host"`
	SNI         string `json:"sni"`
	ALPN        string `json:"alpn"`
	Remark      string `json:"remark"`
	ServiceName string `json:"service_name"`
	Mode        string `json:"mode"`
	HeaderType  string `json:"header_type"`
	Seed        string `json:"seed"`
}

// BuildConfigResponse is the result of building a config server-side.
type BuildConfigResponse struct {
	ShareLink string `json:"share_link"`
	Clash     string `json:"clash"`
	Singbox   string `json:"singbox"`
	Base64    string `json:"base64"`
	Protocol  string `json:"protocol"`
	Transport string `json:"transport"`
}

// buildConfigHandler handles POST /v1/admin/build-config.
func (s *Server) buildConfigHandler(w http.ResponseWriter, r *http.Request) {
	var req BuildConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}

	// Validate protocol + transport against the catalog.
	if !validProtocol(req.Protocol) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported protocol: " + req.Protocol})
		return
	}
	if !transport.IsValid(req.Transport) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported transport: " + req.Transport})
		return
	}
	if req.Address == "" || req.Port <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "address and a valid port are required"})
		return
	}

	remark := strings.TrimSpace(req.Remark)
	if remark == "" {
		remark = "Aether-X-" + req.Protocol
	}

	node := subendpoint.NodeConfig{
		Address:     req.Address,
		Port:        req.Port,
		Protocol:    req.Protocol,
		UUID:        req.UUID,
		Password:    req.Password,
		Transport:   req.Transport,
		Path:        req.Path,
		Host:        req.Host,
		SNI:         req.SNI,
		ALPN:        req.ALPN,
		ServiceName: req.ServiceName,
		Mode:        req.Mode,
		HeaderType:  req.HeaderType,
		Seed:        req.Seed,
	}
	cfg := subendpoint.ProxyLinkConfig{Remark: remark, FragPath: "sub", Node: node}

	shareLink := subendpoint.BuildProxyLink(cfg)
	clashBody, _ := subendpoint.BuildSubscriptionBodyEx([]subendpoint.ProxyLinkConfig{cfg}, "clash")
	singboxBody, _ := subendpoint.BuildSubscriptionBodyEx([]subendpoint.ProxyLinkConfig{cfg}, "singbox")
	base64Body, _ := subendpoint.BuildSubscriptionBodyEx([]subendpoint.ProxyLinkConfig{cfg}, "base64")

	writeJSON(w, http.StatusOK, BuildConfigResponse{
		ShareLink: shareLink,
		Clash:     string(clashBody),
		Singbox:   string(singboxBody),
		Base64:    string(base64Body),
		Protocol:  req.Protocol,
		Transport: req.Transport,
	})
}

// transportProfilesHandler handles GET /v1/transport-profiles — the schema-driven
// transport profile catalog (Part 2 §5.2) the admin form generator consumes.
func (s *Server) transportProfilesHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"version":  "1.0",
		"profiles": transport.Profiles(),
	})
}

func validProtocol(p string) bool {
	for _, pr := range transport.Protocols() {
		if pr.ID == p {
			return true
		}
	}
	return false
}

// mountAdmin wires the admin config-builder surface.
func (s *Server) mountAdmin(r chiRouter) {
	r.Get("/transports", s.adminOnly(s.transportsHandler))
	r.Get("/transport-profiles", s.adminOnly(s.transportProfilesHandler))
	s.mountAdminClients(r)
	r.Post("/admin/build-config", s.adminOnly(s.buildConfigHandler))
}
