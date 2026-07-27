package transport

import (
	"encoding/json"

	"github.com/aether-x/control-plane/internal/model"
)

// Profiles returns the schema-driven transport profiles the admin panel builds
// configs from (Part 2 §5.2). It maps the data-driven transport catalog onto
// the two axes the real binaries expose: streamSettings.network and
// streamSettings.security. Each profile carries a JSON Schema snippet the admin
// form is generated from — schema-driven, not one hand-built form per transport.
//
// Adding a transport here changes the admin form schema only. It does not
// configure a running core or prove a subscriber can parse the generated
// output. Each core/version/profile combination needs an external-core parser
// and authorized end-to-end test before publication. Deprecated entries are
// retained (never deleted) so an existing schema capability is not silently
// removed.
func Profiles() []model.TransportProfile {
	return append(xrayProfiles(), singboxProfiles()...)
}

// schema builds a compact JSON Schema object for a profile's required fields.
func schema(network, security string, extra []string) json.RawMessage {
	props := map[string]any{
		"address":  map[string]any{"type": "string"},
		"port":     map[string]any{"type": "integer", "minimum": 1, "maximum": 65535},
		"uuid":     map[string]any{"type": "string"},
		"network":  map[string]any{"type": "string", "const": network},
		"security": map[string]any{"type": "string", "const": security},
	}
	for _, e := range extra {
		props[e] = map[string]any{"type": "string"}
	}
	obj := map[string]any{
		"type":       "object",
		"properties": props,
		"required":   []string{"address", "port", "network", "security"},
	}
	b, _ := json.Marshal(obj)
	return b
}

// xrayProfiles covers CoreKind "xray": tcp, ws, httpupgrade, grpc, mkcp,
// splithttp (= XHTTP, newest). Security axis: none / tls / reality.
func xrayProfiles() []model.TransportProfile {
	type spec struct {
		network string
		name    string
		newest  bool
		legacy  bool
		extra   []string
	}
	specs := []spec{
		{"splithttp", "XHTTP (SplitHTTP)", true, false, []string{"mode", "path", "host", "extra"}},
		{"httpupgrade", "HTTPUpgrade", true, false, []string{"path", "host"}},
		{"grpc", "gRPC", false, false, []string{"serviceName"}},
		{"ws", "WebSocket", false, false, []string{"path", "host"}},
		{"mkcp", "mKCP", false, false, []string{"headerType"}},
		{"tcp", "TCP (raw)", false, false, nil},
	}
	var out []model.TransportProfile
	for _, sp := range specs {
		for _, sec := range []string{"reality", "tls", "none"} {
			out = append(out, model.TransportProfile{
				ID:           "xray-" + sp.network + "-" + sec,
				DisplayName:  "Xray · " + sp.name + " · " + sec,
				CoreKind:     "xray",
				Network:      sp.network,
				Security:     sec,
				ConfigSchema: schema(sp.network, sec, sp.extra),
				Deprecated:   sp.legacy,
				Newest:       sp.newest,
			})
		}
	}
	return out
}

// singboxProfiles covers CoreKind "sing-box": ws, http, grpc, httpupgrade, quic.
func singboxProfiles() []model.TransportProfile {
	type spec struct {
		network string
		name    string
		newest  bool
		extra   []string
	}
	specs := []spec{
		{"httpupgrade", "HTTPUpgrade", true, []string{"path", "host"}},
		{"quic", "QUIC", true, []string{"host"}},
		{"grpc", "gRPC", false, []string{"service_name"}},
		{"http", "HTTP/2", false, []string{"path", "host"}},
		{"ws", "WebSocket", false, []string{"path", "host"}},
	}
	var out []model.TransportProfile
	for _, sp := range specs {
		for _, sec := range []string{"tls", "none"} {
			out = append(out, model.TransportProfile{
				ID:           "singbox-" + sp.network + "-" + sec,
				DisplayName:  "sing-box · " + sp.name + " · " + sec,
				CoreKind:     "sing-box",
				Network:      sp.network,
				Security:     sec,
				ConfigSchema: schema(sp.network, sec, sp.extra),
				Newest:       sp.newest,
			})
		}
	}
	return out
}
