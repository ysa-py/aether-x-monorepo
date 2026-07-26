package subendpoint

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

func testCatalogNode() CatalogNode {
	return CatalogNode{
		NodeConfig: NodeConfig{
			ID:        "fra-verified-1",
			Address:   "203.0.113.42", // TEST-NET address used only in a unit fixture
			Port:      443,
			Protocol:  "vless",
			UUID:      "operator-provisioned-credential",
			Transport: "ws",
			Path:      "/edge",
			Host:      "cdn.operator.test",
			SNI:       "cdn.operator.test",
		},
		Enabled:     true,
		ClientCores: []string{"sing-box", "nekobox"},
	}
}

func TestNodeCatalogRejectsPlaceholderOrInsecureEndpoint(t *testing.T) {
	node := testCatalogNode()
	node.Address = "node.aether-x.example"
	_, err := NewNodeCatalog(CatalogDocument{Version: "v1", Nodes: []CatalogNode{node}})
	if err == nil {
		t.Fatal("placeholder address must be rejected")
	}

	node = testCatalogNode()
	node.Insecure = true
	_, err = NewNodeCatalog(CatalogDocument{Version: "v1", Nodes: []CatalogNode{node}})
	if err == nil {
		t.Fatal("insecure TLS publication must be rejected")
	}
}

func TestNodeCatalogRespectsClientAllowList(t *testing.T) {
	catalog, err := NewNodeCatalog(CatalogDocument{
		Version: "v1",
		Nodes:   []CatalogNode{testCatalogNode()},
	})
	if err != nil {
		t.Fatalf("NewNodeCatalog: %v", err)
	}
	if _, err := catalog.Resolve("fra-verified-1", "sing-box"); err != nil {
		t.Fatalf("sing-box should receive its allow-listed node: %v", err)
	}
	if _, err := catalog.Resolve("fra-verified-1", "shadowrocket"); !errors.Is(err, ErrNoCompatibleNodes) {
		t.Fatalf("shadowrocket must not receive a non-allow-listed node: %v", err)
	}
}

func TestCatalogSubscriptionUsesOnlyVerifiedOperatorEndpoint(t *testing.T) {
	catalog, err := NewNodeCatalog(CatalogDocument{
		Version: "2026.07.26",
		Nodes:   []CatalogNode{testCatalogNode()},
	})
	if err != nil {
		t.Fatalf("NewNodeCatalog: %v", err)
	}
	service, err := NewCatalogSubscriptionService(catalog)
	if err != nil {
		t.Fatalf("NewCatalogSubscriptionService: %v", err)
	}

	result, err := service.BuildGeoRouted(context.Background(), &SubscriptionData{
		UserID:    "subscriber-identity",
		ExpiresAt: time.Now().Add(time.Hour),
	}, "sing-box/1.11", "", "base64")
	if err != nil {
		t.Fatalf("BuildGeoRouted: %v", err)
	}
	decoded, err := base64.StdEncoding.DecodeString(string(result.Body))
	if err != nil {
		t.Fatalf("subscription must be base64 links: %v", err)
	}
	body := string(decoded)
	if !strings.Contains(body, "203.0.113.42:443") {
		t.Fatalf("catalog endpoint missing from subscription: %q", body)
	}
	if strings.Contains(body, "aether-x.example") {
		t.Fatalf("placeholder endpoint leaked into subscription: %q", body)
	}
	if result.Nodes != 1 {
		t.Fatalf("node count = %d, want 1", result.Nodes)
	}
}

func TestCatalogSubscriptionRejectsClientWithoutVerifiedNode(t *testing.T) {
	catalog, err := NewNodeCatalog(CatalogDocument{
		Version: "v1",
		Nodes:   []CatalogNode{testCatalogNode()},
	})
	if err != nil {
		t.Fatalf("NewNodeCatalog: %v", err)
	}
	service, err := NewCatalogSubscriptionService(catalog)
	if err != nil {
		t.Fatalf("NewCatalogSubscriptionService: %v", err)
	}
	_, err = service.BuildGeoRouted(
		context.Background(),
		&SubscriptionData{UserID: "subscriber"},
		"Shadowrocket/2",
		"",
		"base64",
	)
	if !errors.Is(err, ErrNoCompatibleNodes) {
		t.Fatalf("expected no verified node error, got %v", err)
	}
}

func TestNodeCatalogRejectsUnrenderableProtocolOptions(t *testing.T) {
	node := testCatalogNode()
	node.Protocol = "shadowsocks"
	node.Password = "operator-password"
	node.UUID = ""
	node.Transport = "ws"
	if _, err := NewNodeCatalog(CatalogDocument{Version: "v1", Nodes: []CatalogNode{node}}); err == nil {
		t.Fatal("Shadowsocks plugin transport must be rejected when no plugin renderer exists")
	}

	node = testCatalogNode()
	node.Protocol = "trojan"
	node.Password = "operator-password"
	node.UUID = ""
	node.Flow = "xtls-rprx-vision"
	if _, err := NewNodeCatalog(CatalogDocument{Version: "v1", Nodes: []CatalogNode{node}}); err == nil {
		t.Fatal("non-VLESS flow must be rejected")
	}
}

func TestCatalogRenderGateRejectsMissingRendererAndSafelyQuotesCredentials(t *testing.T) {
	unrenderable := testCatalogNode()
	unrenderable.Protocol = "unsupported"
	if err := validateNodeRenderability(unrenderable); err == nil {
		t.Fatal("render gate must reject a node with no standard-client renderer")
	}

	node := testCatalogNode()
	node.Protocol = "trojan"
	node.UUID = ""
	node.Password = `pass: "quoted" # YAML-looking but valid credential`
	if _, err := NewNodeCatalog(CatalogDocument{Version: "v1", Nodes: []CatalogNode{node}}); err != nil {
		t.Fatalf("quoted credential must render into valid standard-client formats: %v", err)
	}
}

func TestNativeQUICCatalogRequiresCompatibleExplicitClientCores(t *testing.T) {
	node := testCatalogNode()
	node.Protocol = "hysteria2"
	node.Transport = "quic"
	node.UUID = ""
	node.Password = "hy2-password"
	node.UpMbps = 100
	node.DownMbps = 200
	node.ClientCores = nil
	if _, err := NewNodeCatalog(CatalogDocument{Version: "v1", Nodes: []CatalogNode{node}}); err == nil {
		t.Fatal("native QUIC node without explicit compatible cores must be rejected")
	}

	node.ClientCores = []string{"xray-core"}
	if _, err := NewNodeCatalog(CatalogDocument{Version: "v1", Nodes: []CatalogNode{node}}); err == nil {
		t.Fatal("native QUIC node must not be advertised to xray-core")
	}

	node.ClientCores = []string{"sing-box", "clash-meta", "nekobox"}
	if _, err := NewNodeCatalog(CatalogDocument{Version: "v1", Nodes: []CatalogNode{node}}); err != nil {
		t.Fatalf("compatible native QUIC node should pass the render gate: %v", err)
	}
}
