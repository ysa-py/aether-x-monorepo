// Package transport defines the Transport Network catalog for Aether-X.
//
// It is the single source of truth for every transport a proxy node can speak:
// legacy TCP, mKCP, WebSocket, HTTP/2, gRPC, HTTPUpgrade, the modern xhttp
// (SplitHTTP) and QUIC. The catalog is intentionally data-driven — every entry
// is a plain struct returned from Catalog(), so a brand-new transport shipping
// years from now is supported by adding ONE entry (zero code changes, zero
// recompilation of the protocol core). The admin config-builder panel consumes
// this catalog to render its UI.
package transport

import "sort"

// Family groups transports by their wire characteristics.
type Family string

const (
	FamilyStream    Family = "stream"    // tcp / raw — byte stream
	FamilyUDP       Family = "udp"       // kcp / quic — datagram-based
	FamilyWebSocket Family = "websocket" // ws / httpupgrade
	FamilyHTTP      Family = "http"      // h2 / http / xhttp
	FamilyGRPC      Family = "grpc"      // grpc
)

// Transport describes one Transport Network option.
type Transport struct {
	ID           string   `json:"id"`         // canonical id: "xhttp", "ws", "grpc"...
	Name         string   `json:"name"`       // English display name
	NameFA       string   `json:"name_fa"`    // Persian display name
	Family       Family   `json:"family"`     // routing family
	NeedsPath    bool     `json:"needs_path"` // uses an HTTP/WS path
	NeedsHost    bool     `json:"needs_host"` // uses a Host header / SNI front
	NeedsMode    bool     `json:"needs_mode"` // exposes a sub-mode selector
	Modes        []string `json:"modes,omitempty"`
	NeedsService bool     `json:"needs_service"` // gRPC serviceName
	Description  string   `json:"description"`
	Legacy       bool     `json:"legacy"` // classic / older transport
	Newest       bool     `json:"newest"` // cutting-edge anti-DPI transport
}

// Catalog returns every supported transport, sorted: newest first, then by id.
// This is the exhaustive registry — old AND new transports, including xhttp.
func Catalog() []Transport {
	all := builtin()
	sort.SliceStable(all, func(i, j int) bool {
		if all[i].Newest != all[j].Newest {
			return all[i].Newest // newest (true) first
		}
		return all[i].ID < all[j].ID
	})
	return all
}

// ByID looks up a transport by canonical id. Returns ok=false if unknown.
func ByID(id string) (Transport, bool) {
	for _, t := range Catalog() {
		if t.ID == id {
			return t, true
		}
	}
	return Transport{}, false
}

// IDs returns just the canonical ids (handy for validation / UI dropdowns).
func IDs() []string {
	all := Catalog()
	out := make([]string, 0, len(all))
	for _, t := range all {
		out = append(out, t.ID)
	}
	return out
}

// IsValid reports whether id is a known transport.
func IsValid(id string) bool {
	_, ok := ByID(id)
	return ok
}

// Protocol is a supported inbound protocol (pairs with a transport).
type Protocol struct {
	ID     string `json:"id"` // vless | vmess | trojan | shadowsocks
	Name   string `json:"name"`
	NameFA string `json:"name_fa"`
}

// Protocols returns the supported inbound protocols.
func Protocols() []Protocol {
	return []Protocol{
		{ID: "vless", Name: "VLESS", NameFA: "VLESS (واقعیت)"},
		{ID: "vmess", Name: "VMess", NameFA: "VMess"},
		{ID: "trojan", Name: "Trojan", NameFA: "تروجان"},
		{ID: "shadowsocks", Name: "Shadowsocks", NameFA: "شادوساکس"},
	}
}

// builtin is the canonical, hand-curated registry. Add a transport here (or in
// the loaded JSON overlay) to support it everywhere with zero protocol-core
// changes. Covers everything requested: tcp, kcp, ws, httpupgrade, xhttp, h2,
// grpc, quic, and the legacy http/meek transports.
func builtin() []Transport {
	return []Transport{
		{
			ID: "xhttp", Name: "XHTTP (SplitHTTP)", NameFA: "XHTTP (جدیدترین)",
			Family: FamilyHTTP, NeedsPath: true, NeedsHost: true, NeedsMode: true,
			Modes:       []string{"packet-up", "stream-up", "stream-one"},
			Description: "Newest Xray transport; multiplexed HTTP with packet-up / stream-up / stream-one modes — strongest anti-DPI in Iran.",
			Newest:      true,
		},
		{
			ID: "httpupgrade", Name: "HTTPUpgrade", NameFA: "ارتقاء HTTP",
			Family: FamilyWebSocket, NeedsPath: true, NeedsHost: true,
			Description: "HTTP Upgrade handshake reused as a persistent stream — lower overhead than raw WebSocket.",
			Newest:      true,
		},
		{
			ID: "quic", Name: "QUIC", NameFA: "QUIC",
			Family: FamilyUDP, NeedsHost: true,
			Description: "UDP-based, TLS 1.3 encrypted, fast handover — needs a stable UDP path.",
			Newest:      true,
		},
		{
			ID: "grpc", Name: "gRPC", NameFA: "gRPC",
			Family: FamilyGRPC, NeedsService: true,
			Description: "Multiplexed HTTP/2 gRPC streams; great DPI resistance via serviceName camouflage.",
		},
		{
			ID: "h2", Name: "HTTP/2", NameFA: "HTTP/2",
			Family: FamilyHTTP, NeedsPath: true, NeedsHost: true,
			Description: "HTTP/2 h2 transport with path + host fronting.",
		},
		{
			ID: "ws", Name: "WebSocket", NameFA: "وب‌سوکت",
			Family: FamilyWebSocket, NeedsPath: true, NeedsHost: true,
			Description: "Classic WebSocket; universally supported by every client.",
		},
		{
			ID: "kcp", Name: "mKCP", NameFA: "mKCP",
			Family: FamilyUDP, NeedsMode: true,
			Modes:       []string{"none", "srtp", "utp", "wechat-video", "dtls", "wireguard"},
			Description: "UDP mKCP with pluggable header obfuscation; tolerates packet loss well.",
		},
		{
			ID: "http", Name: "HTTP/1.1", NameFA: "HTTP/1.1",
			Family: FamilyHTTP, NeedsPath: true, NeedsHost: true,
			Description: "Legacy HTTP/1.1 transport (often combined with obfs).",
			Legacy:      true,
		},
		{
			ID: "tcp", Name: "TCP (raw)", NameFA: "TCP خام",
			Family:      FamilyStream,
			Description: "Raw TCP stream — the baseline transport, no extra framing.",
		},
		{
			ID: "raw", Name: "Raw (tcp + header)", NameFA: "خام (TCP + سرآیند)",
			Family: FamilyStream, NeedsMode: true,
			Modes:       []string{"none", "http"},
			Description: "Xray 'raw' stream with optional HTTP header obfuscation. Alias of tcp.",
			Legacy:      true,
		},
		{
			ID: "meek", Name: "Meek", NameFA: "Meek",
			Family: FamilyHTTP, NeedsPath: true, NeedsHost: true,
			Description: "Tor-style meek transport over front-domain HTTPS.",
			Legacy:      true,
		},
	}
}
