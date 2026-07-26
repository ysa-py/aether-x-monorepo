package subendpoint

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// NodeConfig holds the per-protocol connection parameters for a proxy node.
// In production this comes from the node registry; here it's a clean struct
// that config builders consume.
type NodeConfig struct {
	ID         string `json:"id"`
	Address    string `json:"address"` // IP or domain
	Port       int    `json:"port"`
	Protocol   string `json:"protocol"` // "vless", "vmess", "trojan", "shadowsocks"
	UUID       string `json:"uuid"` // user UUID for vless/vmess
	Password   string `json:"password,omitempty"` // for trojan/shadowsocks
	Encryption string `json:"encryption,omitempty"` // "none" for vless
	Transport  string `json:"transport"` // tcp, kcp, ws, h2, grpc, httpupgrade, xhttp, quic, ...
	Path       string `json:"path,omitempty"` // WebSocket / HTTP path
	Host       string `json:"host,omitempty"` // WebSocket Host header / front domain
	SNI        string `json:"sni,omitempty"` // TLS SNI
	ALPN       string `json:"alpn,omitempty"` // TLS ALPN (h2, http/1.1)
	Insecure   bool   `json:"insecure,omitempty"` // skip TLS verify (dev only)

	// Transport-specific knobs (all optional; zero-value ⇒ sensible default):
	ServiceName   string `json:"service_name,omitempty"` // gRPC serviceName
	// xhttp mode (packet-up/stream-up/stream-one); kcp uses HeaderType.
	Mode          string `json:"mode,omitempty"`
	HeaderType    string `json:"header_type,omitempty"` // kcp obfs / tcp(raw) http header
	Seed          string `json:"seed,omitempty"` // kcp / xhttp seed
	GRPCMultiMode bool   `json:"grpc_multi_mode,omitempty"` // gRPC gun multi-mode
	Extra         string `json:"extra,omitempty"` // xhttp extra headers path
}

// ProxyLinkConfig binds a subscriber's identity to a node's protocol params.
type ProxyLinkConfig struct {
	UserID   string
	Remark   string // display name in client
	FragPath string // anti-DPI fragmentation path segment
	Node     NodeConfig
}

// BuildProxyLink generates a standard share link (vless://, vmess://,
// trojan://, ss://) for the given config. This is the core URI that every
// proxy client on earth can import via paste or QR scan.
func BuildProxyLink(cfg ProxyLinkConfig) string {
	switch cfg.Node.Protocol {
	case "vless":
		return buildVlessLink(cfg)
	case "vmess":
		return buildVmessLink(cfg)
	case "trojan":
		return buildTrojanLink(cfg)
	case "shadowsocks":
		return buildSSLink(cfg)
	default:
		return buildVlessLink(cfg) // safe default
	}
}

// transportShareType maps a catalog Transport ID to the Xray/V2Ray wire "type"
// value used inside share links. e.g. h2→http, raw→tcp.
func transportShareType(t string) string {
	switch t {
	case "", "tcp", "raw":
		return "tcp"
	case "h2":
		return "http" // Xray represents HTTP/2 as "http"
	default:
		return t // ws, kcp, grpc, httpupgrade, xhttp, quic, http, meek
	}
}

// shareTransportParams returns the transport "type" plus any transport-specific
// query params for a vless/trojan share link. Pure mapping, no side effects.
func shareTransportParams(n NodeConfig) (string, url.Values) {
	extra := url.Values{}
	switch n.Transport {
	case "", "tcp", "raw":
		if n.Transport == "raw" && n.HeaderType != "" {
			extra.Set("headerType", n.HeaderType)
		}
	case "kcp":
		extra.Set("headerType", ifEmpty(n.HeaderType, "none"))
		if n.Seed != "" {
			extra.Set("seed", n.Seed)
		}
	case "ws":
		extra.Set("path", ifEmpty(n.Path, "/"+n.ID))
		extra.Set("host", ifEmpty(n.Host, n.SNI))
	case "http", "h2":
		extra.Set("path", ifEmpty(n.Path, "/"+n.ID))
		extra.Set("host", ifEmpty(n.Host, n.SNI))
	case "grpc":
		extra.Set("serviceName", ifEmpty(n.ServiceName, "GunService"))
		if n.GRPCMultiMode {
			extra.Set("mode", "gun")
		}
	case "httpupgrade":
		extra.Set("path", ifEmpty(n.Path, "/"+n.ID))
		extra.Set("host", ifEmpty(n.Host, n.SNI))
	case "xhttp":
		extra.Set("path", ifEmpty(n.Path, "/"+n.ID))
		extra.Set("host", ifEmpty(n.Host, n.SNI))
		extra.Set("mode", ifEmpty(n.Mode, "auto"))
		if n.Extra != "" {
			extra.Set("extra", n.Extra)
		}
	case "quic":
		extra.Set("host", ifEmpty(n.Host, n.SNI))
		if n.Seed != "" {
			extra.Set("key", n.Seed)
		}
	case "meek":
		extra.Set("path", ifEmpty(n.Path, "/"+n.ID))
		extra.Set("host", ifEmpty(n.Host, n.SNI))
	default:
		extra.Set("path", ifEmpty(n.Path, "/"+n.ID))
		extra.Set("host", ifEmpty(n.Host, n.SNI))
	}
	return transportShareType(n.Transport), extra
}

func buildVlessLink(cfg ProxyLinkConfig) string {
	n := cfg.Node
	params := url.Values{}
	params.Set("encryption", ifEmpty(n.Encryption, "none"))
	ttype, textra := shareTransportParams(n)
	params.Set("type", ttype)
	params.Set("security", "tls")
	for k := range textra {
		params.Set(k, textra.Get(k))
	}
	// Path/host defaults only when the transport actually uses them.
	if needsPathHost(n.Transport) {
		if params.Get("path") == "" {
			params.Set("path", "/"+ifEmpty(cfg.FragPath, "sub"))
		}
		if params.Get("host") == "" {
			params.Set("host", ifEmpty(n.Host, n.SNI))
		}
	}
	params.Set("sni", ifEmpty(n.SNI, n.Address))
	params.Set("fp", "chrome") // JA4 fingerprint camouflage
	if n.ALPN != "" {
		params.Set("alpn", n.ALPN)
	}
	return fmt.Sprintf("vless://%s@%s:%d?%s#%s",
		n.UUID, n.Address, n.Port, params.Encode(), url.QueryEscape(cfg.Remark))
}

func buildVmessLink(cfg ProxyLinkConfig) string {
	n := cfg.Node
	ttype, _ := shareTransportParams(n)
	obj := map[string]any{
		"v":    "2",
		"ps":   cfg.Remark,
		"add":  n.Address,
		"port": fmt.Sprintf("%d", n.Port),
		"id":   n.UUID,
		"aid":  "0",
		"scy":  "auto",
		"net":  ttype,
		"type": "none",
		"host": ifEmpty(n.Host, n.SNI),
		"path": ifEmpty(n.Path, "/"+cfg.FragPath),
		"tls":  "tls",
		"sni":  ifEmpty(n.SNI, n.Address),
	}
	// vmess transport-specific fields
	switch n.Transport {
	case "grpc":
		obj["path"] = ifEmpty(n.ServiceName, "GunService")
	case "kcp":
		obj["type"] = ifEmpty(n.HeaderType, "none") // vmess uses "type" for kcp header
	case "xhttp":
		obj["host"] = ifEmpty(n.Host, n.SNI)
	}
	b, _ := json.Marshal(obj)
	return "vmess://" + base64.StdEncoding.EncodeToString(b)
}

func buildTrojanLink(cfg ProxyLinkConfig) string {
	n := cfg.Node
	params := url.Values{}
	ttype, textra := shareTransportParams(n)
	params.Set("type", ttype)
	params.Set("security", "tls")
	for k := range textra {
		params.Set(k, textra.Get(k))
	}
	if needsPathHost(n.Transport) {
		if params.Get("path") == "" {
			params.Set("path", "/"+ifEmpty(cfg.FragPath, "sub"))
		}
		if params.Get("host") == "" {
			params.Set("host", ifEmpty(n.Host, n.SNI))
		}
	}
	params.Set("sni", ifEmpty(n.SNI, n.Address))
	params.Set("host", ifEmpty(n.Host, n.SNI))
	params.Set("fp", "chrome")
	return fmt.Sprintf("trojan://%s@%s:%d?%s#%s",
		n.Password, n.Address, n.Port, params.Encode(), url.QueryEscape(cfg.Remark))
}

func buildSSLink(cfg ProxyLinkConfig) string {
	n := cfg.Node
	userinfo := base64.RawURLEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:" + n.Password))
	return fmt.Sprintf("ss://%s@%s:%d#%s", userinfo, n.Address, n.Port, url.QueryEscape(cfg.Remark))
}

// needsPathHost reports whether a transport uses an HTTP/WS path + host.
func needsPathHost(t string) bool {
	switch t {
	case "ws", "http", "h2", "httpupgrade", "xhttp", "meek":
		return true
	default:
		return false
	}
}

// BuildSubscriptionBodyEx generates the full subscription body from one or
// more node configs. This is the enhanced version of BuildBody that uses
// real node data instead of placeholders.
func BuildSubscriptionBodyEx(cfgs []ProxyLinkConfig, format string) ([]byte, string) {
	switch format {
	case "clash":
		return buildClashFromNodes(cfgs), "text/yaml; charset=utf-8"
	case "singbox":
		return buildSingboxFromNodes(cfgs), "application/json; charset=utf-8"
	default:
		return buildBase64FromNodes(cfgs), "text/plain; charset=utf-8"
	}
}

func buildBase64FromNodes(cfgs []ProxyLinkConfig) []byte {
	var links []string
	for _, c := range cfgs {
		links = append(links, BuildProxyLink(c))
	}
	joined := strings.Join(links, "\n")
	return []byte(base64.StdEncoding.EncodeToString([]byte(joined)))
}

// clashNetwork maps a transport id to the Clash "network:" value.
func clashNetwork(t string) string {
	switch t {
	case "h2":
		return "h2"
	case "", "tcp", "raw":
		return "tcp"
	default:
		return t // ws, grpc, kcp, http, httpupgrade, xhttp, quic
	}
}

func buildClashFromNodes(cfgs []ProxyLinkConfig) []byte {
	var sb strings.Builder
	sb.WriteString("port: 7890\nsocks-port: 7891\nmode: rule\n\nproxies:\n")
	var names []string
	for i, c := range cfgs {
		name := c.Remark
		if name == "" {
			name = fmt.Sprintf("Aether-X-%d", i+1)
		}
		names = append(names, name)
		writeClashProxy(&sb, name, c)
	}
	sb.WriteString("\nproxy-groups:\n")
	sb.WriteString("  - name: Aether-X\n    type: select\n    proxies:\n")
	for _, n := range names {
		sb.WriteString(fmt.Sprintf("      - %q\n", n))
	}
	sb.WriteString("\nrules:\n  - MATCH,Aether-X\n")
	return []byte(sb.String())
}

// writeClashProxy emits one Clash proxy entry with transport-correct options.
func writeClashProxy(sb *strings.Builder, name string, c ProxyLinkConfig) {
	n := c.Node
	sb.WriteString(fmt.Sprintf("  - name: %q\n", name))
	sb.WriteString(fmt.Sprintf("    type: %s\n", n.Protocol))
	sb.WriteString(fmt.Sprintf("    server: %s\n", n.Address))
	sb.WriteString(fmt.Sprintf("    port: %d\n", n.Port))
	if n.Protocol == "vless" || n.Protocol == "vmess" {
		sb.WriteString(fmt.Sprintf("    uuid: %s\n", n.UUID))
	}
	if n.Protocol == "vless" {
		sb.WriteString("    flow: xtls-rprx-vision\n")
	}
	if n.Protocol == "trojan" {
		sb.WriteString(fmt.Sprintf("    password: %s\n", n.Password))
	}
	sb.WriteString(fmt.Sprintf("    network: %s\n", clashNetwork(n.Transport)))
	sb.WriteString("    tls: true\n")
	sb.WriteString(fmt.Sprintf("    server-name: %s\n", ifEmpty(n.SNI, n.Address)))
	sb.WriteString("    udp: true\n")

	writeClashTransport(sb, n)
}

// writeClashTransport writes the transport-specific *-opts block.
func writeClashTransport(sb *strings.Builder, n NodeConfig) {
	path := ifEmpty(n.Path, "/sub")
	host := ifEmpty(n.Host, n.SNI)
	switch n.Transport {
	case "ws":
		sb.WriteString("    ws-opts:\n")
		sb.WriteString(fmt.Sprintf("      path: %q\n", path))
		sb.WriteString("      headers:\n")
		sb.WriteString(fmt.Sprintf("        Host: %q\n", host))
	case "grpc":
		sb.WriteString("    grpc-opts:\n")
		sb.WriteString(fmt.Sprintf("      grpc-service-name: %q\n", ifEmpty(n.ServiceName, "GunService")))
	case "h2":
		sb.WriteString("    h2-opts:\n")
		sb.WriteString(fmt.Sprintf("      host:\n        - %q\n", host))
		sb.WriteString(fmt.Sprintf("      path: %q\n", path))
	case "http":
		sb.WriteString("    http-opts:\n")
		sb.WriteString(fmt.Sprintf("      path:\n        - %q\n", path))
		sb.WriteString(fmt.Sprintf("      headers:\n        Host:\n          - %q\n", host))
	case "kcp":
		sb.WriteString("    kcp-opts:\n")
		sb.WriteString(fmt.Sprintf("      header-type: %s\n", ifEmpty(n.HeaderType, "none")))
	case "httpupgrade":
		sb.WriteString("    httpupgrade-opts:\n")
		sb.WriteString(fmt.Sprintf("      host: %q\n", host))
		sb.WriteString(fmt.Sprintf("      path: %q\n", path))
	case "xhttp":
		// Mihomo/Clash.Meta xhttp opts
		sb.WriteString("    xhttp-opts:\n")
		sb.WriteString(fmt.Sprintf("      host: %q\n", host))
		sb.WriteString(fmt.Sprintf("      path: %q\n", path))
		sb.WriteString(fmt.Sprintf("      mode: %s\n", ifEmpty(n.Mode, "auto")))
	case "quic":
		sb.WriteString("    quic-opts:\n")
		sb.WriteString(fmt.Sprintf("      host: %q\n", host))
	default:
		// tcp / raw / meek / unknown: no opts block needed
	}
}

func buildSingboxFromNodes(cfgs []ProxyLinkConfig) []byte {
	type outbound struct {
		Type       string         `json:"type"`
		Tag        string         `json:"tag"`
		Server     string         `json:"server"`
		ServerPort int            `json:"server_port"`
		UUID       string         `json:"uuid,omitempty"`
		Password   string         `json:"password,omitempty"`
		Flow       string         `json:"flow,omitempty"`
		Transport  map[string]any `json:"transport,omitempty"`
		TLS        map[string]any `json:"tls,omitempty"`
	}
	var outbounds []outbound
	for i, c := range cfgs {
		n := c.Node
		tag := c.Remark
		if tag == "" {
			tag = fmt.Sprintf("Aether-X-%d", i+1)
		}
		ob := outbound{
			Type:       n.Protocol,
			Tag:        tag,
			Server:     n.Address,
			ServerPort: n.Port,
			Transport:  singboxTransport(n),
			TLS:        singboxTLS(n),
		}
		if n.Protocol == "vless" || n.Protocol == "vmess" {
			ob.UUID = n.UUID
		}
		if n.Protocol == "vless" {
			ob.Flow = "xtls-rprx-vision"
		}
		if n.Protocol == "trojan" {
			ob.Password = n.Password
		}
		outbounds = append(outbounds, ob)
	}
	result := map[string]any{
		"log":       map[string]string{"level": "warn"},
		"outbounds": outbounds,
	}
	b, _ := json.MarshalIndent(result, "", "  ")
	return b
}

// singboxTransport returns the sing-box transport object for a node.
func singboxTransport(n NodeConfig) map[string]any {
	path := ifEmpty(n.Path, "/sub")
	host := ifEmpty(n.Host, n.SNI)
	switch n.Transport {
	case "ws":
		return map[string]any{
			"type": "ws", "path": path,
			"headers": map[string]string{"Host": host},
		}
	case "grpc":
		return map[string]any{"type": "grpc", "service_name": ifEmpty(n.ServiceName, "GunService")}
	case "http", "h2":
		return map[string]any{"type": "http", "path": path, "host": []string{host}}
	case "httpupgrade":
		return map[string]any{"type": "httpupgrade", "path": path, "host": host}
	case "xhttp":
		return map[string]any{"type": "xhttp", "path": path, "host": host, "mode": ifEmpty(n.Mode, "auto")}
	case "quic":
		return map[string]any{"type": "quic"}
	case "kcp":
		// sing-box has no mkcp transport for vless; keep type for clarity.
		return map[string]any{"type": "kcp", "header_type": ifEmpty(n.HeaderType, "none")}
	default:
		// tcp / raw / meek / unknown: no transport object (raw stream).
		return nil
	}
}

func singboxTLS(n NodeConfig) map[string]any {
	tls := map[string]any{
		"enabled":     true,
		"server_name": ifEmpty(n.SNI, n.Address),
	}
	if n.ALPN != "" {
		tls["alpn"] = []string{n.ALPN}
	} else {
		tls["alpn"] = []string{"h2", "http/1.1"}
	}
	if n.Insecure {
		tls["insecure"] = true
	}
	if n.Transport == "xhttp" {
		tls["utls"] = map[string]any{"enabled": true, "fingerprint": "chrome"}
	}
	return tls
}

func ifEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
