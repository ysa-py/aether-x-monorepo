package subendpoint

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func testConfig() ProxyLinkConfig {
	return ProxyLinkConfig{
		UserID:   "user-001",
		Remark:   "Aether-X",
		FragPath: "sub",
		Node: NodeConfig{
			ID:        "node-1",
			Address:   "node.aether-x.example",
			Port:      443,
			Protocol:  "vless",
			UUID:      "aaa-bbb-ccc-ddd",
			Transport: "ws",
			Path:      "/sub",
			Host:      "front.example.com",
			SNI:       "front.example.com",
		},
	}
}

func TestBuildVlessLink(t *testing.T) {
	link := BuildProxyLink(testConfig())
	if !strings.HasPrefix(link, "vless://") {
		t.Fatalf("expected vless:// prefix, got %s", link[:20])
	}
	if !strings.Contains(link, "aaa-bbb-ccc-ddd") {
		t.Fatal("UUID not in link")
	}
	if !strings.Contains(link, "security=tls") {
		t.Fatal("TLS not in link")
	}
	if !strings.Contains(link, "Aether-X") {
		t.Fatal("remark not in link")
	}
}

func TestBuildVmessLink(t *testing.T) {
	cfg := testConfig()
	cfg.Node.Protocol = "vmess"
	link := BuildProxyLink(cfg)
	if !strings.HasPrefix(link, "vmess://") {
		t.Fatalf("expected vmess:// prefix")
	}
	b64 := strings.TrimPrefix(link, "vmess://")
	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("vmess base64 decode: %v", err)
	}
	if !strings.Contains(string(decoded), "node.aether-x.example") {
		t.Fatal("address not in vmess JSON")
	}
}

func TestBuildTrojanLink(t *testing.T) {
	cfg := testConfig()
	cfg.Node.Protocol = "trojan"
	cfg.Node.Password = "trojan-pass"
	link := BuildProxyLink(cfg)
	if !strings.HasPrefix(link, "trojan://") {
		t.Fatalf("expected trojan:// prefix")
	}
	if !strings.Contains(link, "trojan-pass") {
		t.Fatal("password not in link")
	}
}

func TestBuildSubscriptionBodyExBase64(t *testing.T) {
	cfgs := []ProxyLinkConfig{testConfig()}
	body, ct := BuildSubscriptionBodyEx(cfgs, "base64")
	if ct != "text/plain; charset=utf-8" {
		t.Fatalf("content-type: %s", ct)
	}
	decoded, err := base64.StdEncoding.DecodeString(string(body))
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	if !strings.Contains(string(decoded), "vless://") {
		t.Fatal("vless link not in decoded body")
	}
}

func TestBuildSubscriptionBodyExClash(t *testing.T) {
	cfgs := []ProxyLinkConfig{testConfig()}
	body, ct := BuildSubscriptionBodyEx(cfgs, "clash")
	if !strings.Contains(string(body), "proxies:") {
		t.Fatal("clash body missing proxies")
	}
	if !strings.Contains(string(body), "Aether-X") {
		t.Fatal("clash body missing name")
	}
	if ct != "text/yaml; charset=utf-8" {
		t.Fatalf("content-type: %s", ct)
	}
}

func TestBuildSubscriptionBodyExSingbox(t *testing.T) {
	cfgs := []ProxyLinkConfig{testConfig()}
	body, ct := BuildSubscriptionBodyEx(cfgs, "singbox")
	if !strings.Contains(string(body), "outbounds") {
		t.Fatal("singbox body missing outbounds")
	}
	if !strings.Contains(string(body), "vless") {
		t.Fatal("singbox body missing protocol")
	}
	if ct != "application/json; charset=utf-8" {
		t.Fatalf("content-type: %s", ct)
	}
}

func TestMultipleNodesBase64(t *testing.T) {
	cfg2 := testConfig()
	cfg2.Node.Address = "node2.example.com"
	cfgs := []ProxyLinkConfig{testConfig(), cfg2}
	body, _ := BuildSubscriptionBodyEx(cfgs, "base64")
	decoded, _ := base64.StdEncoding.DecodeString(string(body))
	lines := strings.Split(string(decoded), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 links, got %d", len(lines))
	}
}

// --- Transport Network coverage (tcp, kcp, ws, h2, grpc, httpupgrade, xhttp, quic) ---

func TestShareLinkPerTransportType(t *testing.T) {
	cases := []struct {
		transport string
		wantType  string // expected type= in share link
	}{
		{"tcp", "tcp"},
		{"raw", "tcp"},
		{"kcp", "kcp"},
		{"ws", "ws"},
		{"h2", "http"},
		{"http", "http"},
		{"grpc", "grpc"},
		{"httpupgrade", "httpupgrade"},
		{"xhttp", "xhttp"},
		{"quic", "quic"},
	}
	for _, c := range cases {
		cfg := testConfig()
		cfg.Node.Transport = c.transport
		link := BuildProxyLink(cfg)
		want := "type=" + c.wantType
		if !strings.Contains(link, want) {
			t.Errorf("transport %q: link missing %q\n  %s", c.transport, want, link)
		}
	}
}

func TestXHTTPShareLinkHasMode(t *testing.T) {
	cfg := testConfig()
	cfg.Node.Transport = "xhttp"
	cfg.Node.Mode = "stream-one"
	link := BuildProxyLink(cfg)
	if !strings.Contains(link, "mode=stream-one") {
		t.Errorf("xhttp link missing mode=stream-one: %s", link)
	}
	if !strings.Contains(link, "type=xhttp") {
		t.Errorf("xhttp link missing type=xhttp: %s", link)
	}
}

func TestGRPCShareLinkHasServiceName(t *testing.T) {
	cfg := testConfig()
	cfg.Node.Transport = "grpc"
	cfg.Node.ServiceName = "AetherGun"
	link := BuildProxyLink(cfg)
	if !strings.Contains(link, "serviceName=AetherGun") {
		t.Errorf("grpc link missing serviceName: %s", link)
	}
	if !strings.Contains(link, "type=grpc") {
		t.Errorf("grpc link missing type=grpc: %s", link)
	}
}

func TestKCPShareLinkHasHeaderType(t *testing.T) {
	cfg := testConfig()
	cfg.Node.Transport = "kcp"
	cfg.Node.HeaderType = "wechat-video"
	link := BuildProxyLink(cfg)
	if !strings.Contains(link, "headerType=wechat-video") {
		t.Errorf("kcp link missing headerType: %s", link)
	}
	if !strings.Contains(link, "type=kcp") {
		t.Errorf("kcp link missing type=kcp: %s", link)
	}
}

func TestClashEmitPerTransport(t *testing.T) {
	transports := []string{"tcp", "ws", "grpc", "h2", "kcp", "httpupgrade", "xhttp", "quic"}
	for _, tr := range transports {
		cfg := testConfig()
		cfg.Node.Transport = tr
		body := buildClashFromNodes([]ProxyLinkConfig{cfg})
		s := string(body)
		if !strings.Contains(s, "network: ") {
			t.Errorf("transport %q: clash missing network", tr)
		}
		// Each transport must produce a deterministic, non-empty opts block where applicable.
		switch tr {
		case "ws":
			if !strings.Contains(s, "ws-opts:") {
				t.Errorf("ws clash missing ws-opts")
			}
		case "grpc":
			if !strings.Contains(s, "grpc-opts:") {
				t.Errorf("grpc clash missing grpc-opts")
			}
		case "xhttp":
			if !strings.Contains(s, "xhttp-opts:") {
				t.Errorf("xhttp clash missing xhttp-opts")
			}
		case "kcp":
			if !strings.Contains(s, "kcp-opts:") {
				t.Errorf("kcp clash missing kcp-opts")
			}
		}
	}
}

func TestSingboxEmitPerTransport(t *testing.T) {
	for _, tr := range []string{"ws", "grpc", "h2", "httpupgrade", "xhttp", "kcp", "tcp"} {
		cfg := testConfig()
		cfg.Node.Transport = tr
		body := buildSingboxFromNodes([]ProxyLinkConfig{cfg})
		if !json.Valid(body) {
			t.Errorf("transport %q: sing-box JSON invalid", tr)
		}
		if tr == "xhttp" && !strings.Contains(string(body), "\"type\": \"xhttp\"") {
			t.Errorf("xhttp singbox missing transport type")
		}
	}
}

func TestShadowsocksRendererPreservesConfiguredCipherAcrossClientFormats(t *testing.T) {
	cfg := testConfig()
	cfg.Node.Protocol = "shadowsocks"
	cfg.Node.Transport = "tcp"
	cfg.Node.Password = "p@ss word"
	cfg.Node.Encryption = "aes-128-gcm"

	link := BuildProxyLink(cfg)
	if !strings.HasPrefix(link, "ss://") {
		t.Fatalf("expected ss:// prefix, got %q", link)
	}
	encodedUserinfo := strings.Split(strings.TrimPrefix(link, "ss://"), "@")[0]
	userinfo, err := base64.RawURLEncoding.DecodeString(encodedUserinfo)
	if err != nil {
		t.Fatalf("decode Shadowsocks userinfo: %v", err)
	}
	if got, want := string(userinfo), "aes-128-gcm:p@ss word"; got != want {
		t.Fatalf("Shadowsocks userinfo = %q, want %q", got, want)
	}

	clash := string(buildClashFromNodes([]ProxyLinkConfig{cfg}))
	for _, required := range []string{
		`type: "ss"`,
		`cipher: "aes-128-gcm"`,
		`password: "p@ss word"`,
	} {
		if !strings.Contains(clash, required) {
			t.Errorf("Clash config missing %q:\n%s", required, clash)
		}
	}
	var clashDocument struct {
		Proxies []struct {
			Type     string `yaml:"type"`
			Cipher   string `yaml:"cipher"`
			Password string `yaml:"password"`
		} `yaml:"proxies"`
	}
	if err := yaml.Unmarshal([]byte(clash), &clashDocument); err != nil {
		t.Fatalf("decode Clash YAML: %v", err)
	}
	if len(clashDocument.Proxies) != 1 {
		t.Fatalf("Clash proxies = %d, want 1", len(clashDocument.Proxies))
	}
	clashProxy := clashDocument.Proxies[0]
	if clashProxy.Type != "ss" || clashProxy.Cipher != "aes-128-gcm" || clashProxy.Password != "p@ss word" {
		t.Fatalf("Clash Shadowsocks proxy = %+v", clashProxy)
	}

	var singbox struct {
		Outbounds []struct {
			Type     string `json:"type"`
			Method   string `json:"method"`
			Password string `json:"password"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal(buildSingboxFromNodes([]ProxyLinkConfig{cfg}), &singbox); err != nil {
		t.Fatalf("decode sing-box config: %v", err)
	}
	if len(singbox.Outbounds) != 1 {
		t.Fatalf("sing-box outbounds = %d, want 1", len(singbox.Outbounds))
	}
	outbound := singbox.Outbounds[0]
	if outbound.Type != "shadowsocks" || outbound.Method != "aes-128-gcm" || outbound.Password != "p@ss word" {
		t.Fatalf("sing-box Shadowsocks outbound = %+v", outbound)
	}
}

func TestVlessFlowIsExplicitAndConsistent(t *testing.T) {
	cfg := testConfig()

	if link := BuildProxyLink(cfg); strings.Contains(link, "flow=") {
		t.Fatalf("VLESS link injected an unconfigured flow: %s", link)
	}
	if clash := string(buildClashFromNodes([]ProxyLinkConfig{cfg})); strings.Contains(clash, "flow:") {
		t.Fatalf("Clash config injected an unconfigured flow:\n%s", clash)
	}
	if singbox := string(buildSingboxFromNodes([]ProxyLinkConfig{cfg})); strings.Contains(singbox, `"flow"`) {
		t.Fatalf("sing-box config injected an unconfigured flow:\n%s", singbox)
	}

	cfg.Node.Flow = "xtls-rprx-vision"
	if link := BuildProxyLink(cfg); !strings.Contains(link, "flow=xtls-rprx-vision") {
		t.Fatalf("VLESS link omitted configured flow: %s", link)
	}
	if clash := string(buildClashFromNodes([]ProxyLinkConfig{cfg})); !strings.Contains(clash, `flow: "xtls-rprx-vision"`) {
		t.Fatalf("Clash config omitted configured flow:\n%s", clash)
	}
	if singbox := string(buildSingboxFromNodes([]ProxyLinkConfig{cfg})); !strings.Contains(singbox, `"flow": "xtls-rprx-vision"`) {
		t.Fatalf("sing-box config omitted configured flow:\n%s", singbox)
	}
}

func TestBuildProxyLinkRejectsUnknownProtocol(t *testing.T) {
	cfg := testConfig()
	cfg.Node.Protocol = "unsupported"
	if link := BuildProxyLink(cfg); link != "" {
		t.Fatalf("unknown protocol produced a fabricated link: %q", link)
	}
}

func nativeQUICConfig(protocol string) ProxyLinkConfig {
	cfg := testConfig()
	cfg.Node.Protocol = protocol
	cfg.Node.Address = "198.51.100.42"
	cfg.Node.Transport = "quic"
	cfg.Node.Password = "native-quic-password"
	cfg.Node.SNI = "native.example.com"
	cfg.Node.Host = ""
	if protocol == "hysteria2" {
		cfg.Node.UpMbps = 100
		cfg.Node.DownMbps = 200
	} else {
		cfg.Node.UUID = "tuic-uuid"
		cfg.Node.CongestionControl = "bbr"
		cfg.Node.UDPRelayMode = "native"
	}
	return cfg
}

func TestNativeQUICRenderersProduceProtocolSpecificStandardConfigs(t *testing.T) {
	cases := []struct {
		protocol      string
		sharePrefix   string
		clashRequired []string
		jsonRequired  []string
	}{
		{
			protocol:      "hysteria2",
			sharePrefix:   "hysteria2://",
			clashRequired: []string{`type: "hysteria2"`, `up: 100`, `down: 200`},
			jsonRequired:  []string{`"type": "hysteria2"`, `"up_mbps": 100`, `"down_mbps": 200`},
		},
		{
			protocol:      "tuic",
			sharePrefix:   "tuic://",
			clashRequired: []string{`type: "tuic"`, `congestion-controller: "bbr"`, `udp-relay-mode: "native"`},
			jsonRequired:  []string{`"type": "tuic"`, `"congestion_control": "bbr"`, `"udp_relay_mode": "native"`},
		},
	}

	for _, tc := range cases {
		t.Run(tc.protocol, func(t *testing.T) {
			cfg := nativeQUICConfig(tc.protocol)
			if err := ValidateNodeConfig(cfg.Node); err != nil {
				t.Fatalf("ValidateNodeConfig: %v", err)
			}
			if link := BuildProxyLink(cfg); !strings.HasPrefix(link, tc.sharePrefix) {
				t.Fatalf("share link = %q, want prefix %q", link, tc.sharePrefix)
			}

			clash := buildClashFromNodes([]ProxyLinkConfig{cfg})
			var clashDocument struct {
				Proxies []map[string]any `yaml:"proxies"`
			}
			if err := yaml.Unmarshal(clash, &clashDocument); err != nil {
				t.Fatalf("decode Clash YAML: %v", err)
			}
			if len(clashDocument.Proxies) != 1 {
				t.Fatalf("Clash proxies = %d, want 1", len(clashDocument.Proxies))
			}
			for _, required := range tc.clashRequired {
				if !strings.Contains(string(clash), required) {
					t.Errorf("Clash output missing %q:\n%s", required, clash)
				}
			}

			singbox := buildSingboxFromNodes([]ProxyLinkConfig{cfg})
			if !json.Valid(singbox) {
				t.Fatalf("invalid sing-box JSON: %s", singbox)
			}
			for _, required := range tc.jsonRequired {
				if !strings.Contains(string(singbox), required) {
					t.Errorf("sing-box output missing %q:\n%s", required, singbox)
				}
			}
		})
	}
}

func TestNativeQUICValidationRejectsIncompleteOrIncorrectTransport(t *testing.T) {
	hysteria := nativeQUICConfig("hysteria2")
	hysteria.Node.UpMbps = 0
	if err := ValidateNodeConfig(hysteria.Node); err == nil {
		t.Fatal("Hysteria2 without reviewed bandwidth must be rejected")
	}

	tuic := nativeQUICConfig("tuic")
	tuic.Node.Transport = "ws"
	if err := ValidateNodeConfig(tuic.Node); err == nil {
		t.Fatal("TUIC without QUIC transport must be rejected")
	}
}
