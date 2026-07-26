package api

import (
	_ "embed"
	"encoding/json"
	"net/http"

	"gopkg.in/yaml.v3"
)

// openapiYAML is the canonical OpenAPI 3.1 document (source of truth), embedded
// at build time so the binary is self-describing.
//
//go:embed openapi.yaml
var openapiYAML []byte

// openapiYAMLHandler serves the raw YAML document.
func (s *Server) openapiYAMLHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(openapiYAML)
}

// openapiJSONHandler serves the same document as JSON (parsed once at init).
func (s *Server) openapiJSONHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(openapiJSON())
}

// cachedJSON memoizes the YAML→JSON conversion.
var openapiJSON = func() []byte {
	var node any
	if err := yaml.Unmarshal(openapiYAML, &node); err != nil {
		// The embedded spec is validated in CI; fall back to {} on the
		// impossible parse error.
		return []byte("{}")
	}
	b, err := json.Marshal(node)
	if err != nil {
		return []byte("{}")
	}
	return b
}
