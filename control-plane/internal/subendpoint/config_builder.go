package subendpoint

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/aether-x/control-plane/internal/transport"
)

// NodeConfig holds the per-protocol connection parameters for a proxy node.
// In production this comes from the node registry; here it's a clean struct
// that config builders consume.
type NodeConfig struct {
	ID       string `json:"id"`
	Address  string `json:"address"` // IP or domain
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`           // vless, vmess, trojan, shadowsocks, hysteria2, tuic
	UUID     string `json:"uuid"`               // user UUID for vless/vmess/tuic
	Password string `json:"password,omitempty"` // for trojan/shadowsocks/hysteria2/tuic
	// Encryption is VLESS's encryption field or the Shadowsocks cipher/method.
	Encryption string `json:"encryption,omitempty"`
	Transport  string `json:"transport"`          // tcp, kcp, ws, h2, grpc, httpupgrade, xhttp, quic, ...
	Path       string `json:"path,omitempty"`     // WebSocket / HTTP path
	Host       string `json:"host,omitempty"`     // WebSocket Host header / front domain
	SNI        string `json:"sni,omitempty"`      // TLS SNI
	ALPN       string `json:"alpn,omitempty"`     // TLS ALPN (h2, http/1.1)
	Insecure   bool   `json:"insecure,omitempty"` // skip TLS verify (dev only)

	// Transport-specific knobs (all optional; zero-value ⇒ sensible default):
	ServiceName string `json:"service_name,omitempty"` // gRPC serviceName
	// xhttp mode (packet-up/stream-up/stream-one); kcp uses HeaderType.
	Mode          string `json:"mode,omitempty"`
	HeaderType    string `json:"header_type,omitempty"`     // kcp obfs / tcp(raw) http header
	Seed          string `json:"seed,omitempty"`            // kcp / xhttp seed
	GRPCMultiMode bool   `json:"grpc_multi_mode,omitempty"` // gRPC gun multi-mode
	Extra         string `json:"extra,omitempty"`           // xhttp extra headers path
	// Flow is optional VLESS flow control (for example xtls-rprx-vision).
	// It is emitted only when the reviewed node catalog explicitly sets it.
	Flow string `json:"flow,omitempty"`
	// Native QUIC protocol settings. Hysteria2 requires reviewed bandwidth
	// values; TUIC uses congestion control and UDP relay mode.
	UpMbps            int    `json:"up_mbps,omitempty"`
	DownMbps          int    `json:"down_mbps,omitempty"`
	CongestionControl string `json:"congestion_control,omitempty"`
	UDPRelayMode      string `json:"udp_relay_mode,omitempty"`
}

// ProxyLinkConfig binds a subscriber's identity to a node's protocol params.
type ProxyLinkConfig struct {
	UserID   string
	Remark   string // display name in client
	FragPath string // anti-DPI fragmentation path segment
	Node     NodeConfig
}

// ValidateNodeConfig rejects node material that this repository cannot render
// faithfully for a standard client. It is shared by the catalog admission path
// and the admin preview endpoint so an administrator cannot be shown a config
// that production would later reject.
func ValidateNodeConfig(node NodeConfig) error {
	if !supportedProtocol(node.Protocol) {
		return fmt.Errorf("unsupported protocol %q", node.Protocol)
	}
	if !transport.IsValid(node.Transport) {
		return fmt.Errorf("unsupported transport %q", node.Transport)
	}
	if !validPublishedHost(node.Address) {
		return fmt.Errorf("invalid or placeholder address")
	}
	if node.Port < 1 || node.Port > 65535 {
		return fmt.Errorf("invalid port")
	}
	if node.Insecure {
		return fmt.Errorf("insecure TLS is not publishable")
	}
	if node.SNI != "" && !validPublishedHost(node.SNI) {
		return fmt.Errorf("invalid or placeholder SNI")
	}
	if node.Host != "" && !validPublishedHost(node.Host) {
		return fmt.Errorf("invalid or placeholder host")
	}
	if (node.Protocol == "vless" || node.Protocol == "vmess" || node.Protocol == "tuic") && strings.TrimSpace(node.UUID) == "" {
		return fmt.Errorf("protocol %q requires a UUID", node.Protocol)
	}
	if (node.Protocol == "trojan" || node.Protocol == "shadowsocks" || node.Protocol == "hysteria2" || node.Protocol == "tuic") && strings.TrimSpace(node.Password) == "" {
		return fmt.Errorf("protocol %q requires a password", node.Protocol)
	}
	if isNativeQUICProtocol(node.Protocol) {
		if node.Transport != "quic" {
			return fmt.Errorf("protocol %q requires transport quic", node.Protocol)
		}
		if node.Protocol == "hysteria2" && (node.UpMbps <= 0 || node.DownMbps <= 0) {
			return fmt.Errorf("hysteria2 requires positive up_mbps and down_mbps")
		}
	}
	if node.Flow != "" && node.Protocol != "vless" {
		return fmt.Errorf("flow is supported only for vless")
	}
	if node.Protocol == "shadowsocks" && node.Transport != "tcp" && node.Transport != "raw" {
		return fmt.Errorf("unsupported Shadowsocks transport %q without a plugin renderer", node.Transport)
	}
	return nil
}

// BuildProxyLink generates a standard share link (vless://, vmess://,
// trojan://, ss://, hysteria2://, tuic://) for the given config. This is the
// core URI that a compatible standard client can import via paste or QR scan.
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
	case "hysteria2":
		return buildHysteria2Link(cfg)
	case "tuic":
		return buildTuicLink(cfg)
	default:
		// Never relabel an unknown protocol as VLESS. A syntactically valid
		// link for the wrong protocol is worse than an explicit empty result;
		// verified catalog validation prevents this branch in production.
		return ""
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
	if n.Flow != "" {
		params.Set("flow", n.Flow)
	}
	params.Set("fp", "chrome")
	if n.ALPN != "" {
		params.Set("alpn", n.ALPN)
	}
	return fmt.Sprintf("vless://%s@%s:%d?%s#%s",
		url.User(n.UUID).String(), n.Address, n.Port, params.Encode(), url.QueryEscape(cfg.Remark))
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
		url.User(n.Password).String(), n.Address, n.Port, params.Encode(), url.QueryEscape(cfg.Remark))
}

func shadowsocksMethod(n NodeConfig) string {
	return ifEmpty(n.Encryption, "chacha20-ietf-poly1305")
}

func buildSSLink(cfg ProxyLinkConfig) string {
	n := cfg.Node
	userinfo := base64.RawURLEncoding.EncodeToString([]byte(shadowsocksMethod(n) + ":" + n.Password))
	return fmt.Sprintf("ss://%s@%s:%d#%s", userinfo, n.Address, n.Port, url.QueryEscape(cfg.Remark))
}

func nativeQUICParams(n NodeConfig) url.Values {
	params := url.Values{}
	params.Set("sni", ifEmpty(n.SNI, n.Address))
	if n.ALPN != "" {
		params.Set("alpn", n.ALPN)
	}
	return params
}

func buildHysteria2Link(cfg ProxyLinkConfig) string {
	n := cfg.Node
	params := nativeQUICParams(n)
	params.Set("upmbps", fmt.Sprintf("%d", n.UpMbps))
	params.Set("downmbps", fmt.Sprintf("%d", n.DownMbps))
	return fmt.Sprintf("hysteria2://%s@%s:%d?%s#%s",
		url.User(n.Password).String(), n.Address, n.Port, params.Encode(), url.QueryEscape(cfg.Remark))
}

func buildTuicLink(cfg ProxyLinkConfig) string {
	n := cfg.Node
	params := nativeQUICParams(n)
	params.Set("congestion_control", ifEmpty(n.CongestionControl, "bbr"))
	params.Set("udp_relay_mode", ifEmpty(n.UDPRelayMode, "native"))
	return fmt.Sprintf("tuic://%s@%s:%d?%s#%s",
		url.UserPassword(n.UUID, n.Password).String(), n.Address, n.Port, params.Encode(), url.QueryEscape(cfg.Remark))
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
// more node configs. This is the renderer used by the verified catalog path;
// it uses real operator-provided node data rather than placeholders.
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
		if link := BuildProxyLink(c); link != "" {
			links = append(links, link)
		}
	}
	joined := strings.Join(links, "\n")
	return []byte(base64.StdEncoding.EncodeToString([]byte(joined)))
}

// clashProtocol maps the internal protocol identifier to Clash/Mihomo's
// published type name. In particular, the standard Shadowsocks type is `ss`.
func clashProtocol(protocol string) string {
	if protocol == "shadowsocks" {
		return "ss"
	}
	return protocol
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
	if n.Protocol == "hysteria2" || n.Protocol == "tuic" {
		writeClashNativeQUICProxy(sb, n)
		return
	}

	sb.WriteString(fmt.Sprintf("    type: %q\n", clashProtocol(n.Protocol)))
	sb.WriteString(fmt.Sprintf("    server: %q\n", n.Address))
	sb.WriteString(fmt.Sprintf("    port: %d\n", n.Port))
	if n.Protocol == "vless" || n.Protocol == "vmess" {
		sb.WriteString(fmt.Sprintf("    uuid: %q\n", n.UUID))
	}
	if n.Protocol == "vless" && n.Flow != "" {
		sb.WriteString(fmt.Sprintf("    flow: %q\n", n.Flow))
	}
	if n.Protocol == "trojan" {
		sb.WriteString(fmt.Sprintf("    password: %q\n", n.Password))
	}
	if n.Protocol == "shadowsocks" {
		sb.WriteString(fmt.Sprintf("    cipher: %q\n", shadowsocksMethod(n)))
		sb.WriteString(fmt.Sprintf("    password: %q\n", n.Password))
	}
	sb.WriteString(fmt.Sprintf("    network: %q\n", clashNetwork(n.Transport)))
	sb.WriteString("    tls: true\n")
	sb.WriteString(fmt.Sprintf("    server-name: %q\n", ifEmpty(n.SNI, n.Address)))
	sb.WriteString("    udp: true\n")

	writeClashTransport(sb, n)
}

// writeClashNativeQUICProxy emits native Hysteria2/TUIC fields. These are
// protocol outbounds, not a VLESS/Trojan stream transport, so they must not
// inherit stream-only `network` or `tls` keys.
func writeClashNativeQUICProxy(sb *strings.Builder, n NodeConfig) {
	sb.WriteString(fmt.Sprintf("    type: %q\n", n.Protocol))
	sb.WriteString(fmt.Sprintf("    server: %q\n", n.Address))
	sb.WriteString(fmt.Sprintf("    port: %d\n", n.Port))
	sb.WriteString(fmt.Sprintf("    sni: %q\n", ifEmpty(n.SNI, n.Address)))
	sb.WriteString("    skip-cert-verify: false\n")
	sb.WriteString("    udp: true\n")
	switch n.Protocol {
	case "hysteria2":
		sb.WriteString(fmt.Sprintf("    password: %q\n", n.Password))
		sb.WriteString(fmt.Sprintf("    up: %d\n", n.UpMbps))
		sb.WriteString(fmt.Sprintf("    down: %d\n", n.DownMbps))
	case "tuic":
		sb.WriteString(fmt.Sprintf("    uuid: %q\n", n.UUID))
		sb.WriteString(fmt.Sprintf("    password: %q\n", n.Password))
		sb.WriteString(fmt.Sprintf("    congestion-controller: %q\n", ifEmpty(n.CongestionControl, "bbr")))
		sb.WriteString(fmt.Sprintf("    udp-relay-mode: %q\n", ifEmpty(n.UDPRelayMode, "native")))
	}
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
		sb.WriteString(fmt.Sprintf("      header-type: %q\n", ifEmpty(n.HeaderType, "none")))
	case "httpupgrade":
		sb.WriteString("    httpupgrade-opts:\n")
		sb.WriteString(fmt.Sprintf("      host: %q\n", host))
		sb.WriteString(fmt.Sprintf("      path: %q\n", path))
	case "xhttp":
		// Mihomo/Clash.Meta xhttp opts
		sb.WriteString("    xhttp-opts:\n")
		sb.WriteString(fmt.Sprintf("      host: %q\n", host))
		sb.WriteString(fmt.Sprintf("      path: %q\n", path))
		sb.WriteString(fmt.Sprintf("      mode: %q\n", ifEmpty(n.Mode, "auto")))
	case "quic":
		sb.WriteString("    quic-opts:\n")
		sb.WriteString(fmt.Sprintf("      host: %q\n", host))
	default:
		// tcp / raw / meek / unknown: no opts block needed
	}
}

func buildSingboxFromNodes(cfgs []ProxyLinkConfig) []byte {
	type outbound struct {
		Type              string         `json:"type"`
		Tag               string         `json:"tag"`
		Server            string         `json:"server"`
		ServerPort        int            `json:"server_port"`
		UUID              string         `json:"uuid,omitempty"`
		Password          string         `json:"password,omitempty"`
		Method            string         `json:"method,omitempty"`
		Flow              string         `json:"flow,omitempty"`
		UpMbps            int            `json:"up_mbps,omitempty"`
		DownMbps          int            `json:"down_mbps,omitempty"`
		CongestionControl string         `json:"congestion_control,omitempty"`
		UDPRelayMode      string         `json:"udp_relay_mode,omitempty"`
		Transport         map[string]any `json:"transport,omitempty"`
		TLS               map[string]any `json:"tls,omitempty"`
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
		if n.Protocol == "vless" || n.Protocol == "vmess" || n.Protocol == "tuic" {
			ob.UUID = n.UUID
		}
		if n.Protocol == "vless" && n.Flow != "" {
			ob.Flow = n.Flow
		}
		if n.Protocol == "trojan" || n.Protocol == "shadowsocks" || n.Protocol == "hysteria2" || n.Protocol == "tuic" {
			ob.Password = n.Password
		}
		if n.Protocol == "shadowsocks" {
			ob.Method = shadowsocksMethod(n)
		}
		if n.Protocol == "hysteria2" {
			ob.UpMbps = n.UpMbps
			ob.DownMbps = n.DownMbps
		}
		if n.Protocol == "tuic" {
			ob.CongestionControl = ifEmpty(n.CongestionControl, "bbr")
			ob.UDPRelayMode = ifEmpty(n.UDPRelayMode, "native")
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
	// Hysteria2 and TUIC are native QUIC outbounds in sing-box. Their QUIC
	// parameters live on the outbound itself, not in a VLESS-style transport.
	if n.Protocol == "hysteria2" || n.Protocol == "tuic" {
		return nil
	}
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
	} else if n.Protocol == "hysteria2" || n.Protocol == "tuic" {
		// Native QUIC clients negotiate HTTP/3 by default; stream transports
		// retain the TLS-over-TCP ALPN default below.
		tls["alpn"] = []string{"h3"}
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
