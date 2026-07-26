package subendpoint

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
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
