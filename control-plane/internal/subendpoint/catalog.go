package subendpoint

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/aether-x/control-plane/internal/telemetry"
	"github.com/aether-x/control-plane/internal/transport"
	"gopkg.in/yaml.v3"
)

// ErrNoCompatibleNodes means the operator has not supplied a verified node for
// the requesting standard client. Returning this error is intentional: the
// service must not substitute an attractive-but-fictional endpoint.
var ErrNoCompatibleNodes = errors.New("no verified catalog nodes are compatible with this client")

// CatalogDocument is the operator-managed, versioned source of real published
// node connection parameters. It is loaded from a read-only JSON file, never
// inferred from telemetry node IDs or made up from a placeholder domain.
type CatalogDocument struct {
	Version string        `json:"version"`
	Nodes   []CatalogNode `json:"nodes"`
}

// CatalogNode combines a real endpoint with its publication policy.
//
// ClientCores is optional; an empty list means all supported standard clients
// may receive the node. It is an allow-list, not a hint.
type CatalogNode struct {
	NodeConfig
	Enabled     bool     `json:"enabled"`
	ClientCores []string `json:"client_cores,omitempty"`
}

// NodeCatalog contains only validated, enabled endpoint material. Its map is
// immutable after construction, so subscription reads do not need a database
// round trip or a mutable global config.
type NodeCatalog struct {
	version string
	nodes   map[string]CatalogNode
}

// LoadNodeCatalog reads and validates an operator-provided catalog. Unknown
// JSON fields are rejected so a spelling mistake cannot silently publish a
// node with a zero-value address or credential.
func LoadNodeCatalog(path string) (*NodeCatalog, error) {
	contents, _, err := readCatalogFileSnapshot(path)
	if err != nil {
		return nil, err
	}
	return decodeNodeCatalog(contents)
}

// decodeNodeCatalog validates exactly the bytes that were fingerprinted for a
// reload. This prevents a file replacement between a separate fingerprint read
// and parser read from associating a valid catalog with the wrong fingerprint.
func decodeNodeCatalog(contents []byte) (*NodeCatalog, error) {
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var document CatalogDocument
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("decode node catalog: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("node catalog must contain exactly one JSON document")
	}
	return NewNodeCatalog(document)
}

// NewNodeCatalog validates an already-decoded document. This is useful for
// tests and for future database-backed implementations that retain the same
// publication rules.
func NewNodeCatalog(document CatalogDocument) (*NodeCatalog, error) {
	if strings.TrimSpace(document.Version) == "" {
		return nil, errors.New("node catalog version is required")
	}
	if len(document.Nodes) == 0 {
		return nil, errors.New("node catalog must contain at least one node")
	}

	catalog := &NodeCatalog{
		version: document.Version,
		nodes:   make(map[string]CatalogNode, len(document.Nodes)),
	}
	for _, node := range document.Nodes {
		if err := validateCatalogNode(node); err != nil {
			return nil, err
		}
		if _, exists := catalog.nodes[node.ID]; exists {
			return nil, fmt.Errorf("node catalog contains duplicate id %q", node.ID)
		}
		catalog.nodes[node.ID] = cloneCatalogNode(node)
	}
	return catalog, nil
}

// Version returns the operator-declared catalog version.
func (c *NodeCatalog) Version() string {
	if c == nil {
		return ""
	}
	return c.version
}

// Resolve returns a copy of a verified node only when it is enabled and
// compatible with the requested standard client core.
func (c *NodeCatalog) Resolve(nodeID, clientCore string) (NodeConfig, error) {
	if c == nil {
		return NodeConfig{}, ErrNoCompatibleNodes
	}
	node, found := c.nodes[nodeID]
	if !found || !node.Enabled || !allowsClientCore(node.ClientCores, clientCore) {
		return NodeConfig{}, ErrNoCompatibleNodes
	}
	return cloneNodeConfig(node.NodeConfig), nil
}

// BuildGeoRouted implements api.DynamicSubProvider using only verified catalog
// nodes. It deliberately does not fabricate health scores: the order is a
// stable catalog order until a real telemetry reader is wired.
type CatalogSubscriptionService struct {
	catalog *NodeCatalog
}

// NewCatalogSubscriptionService creates a standard-client subscription source
// from a validated operator catalog.
func NewCatalogSubscriptionService(catalog *NodeCatalog) (*CatalogSubscriptionService, error) {
	if catalog == nil || len(catalog.nodes) == 0 {
		return nil, errors.New("verified node catalog is required")
	}
	return &CatalogSubscriptionService{catalog: catalog}, nil
}

// BuildGeoRouted emits base64 links, Clash YAML, or sing-box JSON for real
// catalog entries only. `clientIP` is intentionally ignored: this baseline is
// deterministic and privacy-preserving until the telemetry optimizer has a
// real ClickHouse score reader.
func (s *CatalogSubscriptionService) BuildGeoRouted(
	_ context.Context,
	sub *SubscriptionData,
	userAgent string,
	_ string,
	format string,
) (*GeoRoutedProfileResult, error) {
	return buildCatalogSubscription(
		s.catalog,
		sub,
		DetectClientContext(userAgent, ""),
		format,
	)
}

// BuildGeoRoutedWithContext accepts only an API-resolved context. The catalog
// renderer uses its client-core capability and never trusts raw request headers.
func (s *CatalogSubscriptionService) BuildGeoRoutedWithContext(
	_ context.Context,
	sub *SubscriptionData,
	client telemetry.ClientContext,
	format string,
) (*GeoRoutedProfileResult, error) {
	return buildCatalogSubscription(s.catalog, sub, client, format)
}

func buildCatalogSubscription(
	catalog *NodeCatalog,
	sub *SubscriptionData,
	client telemetry.ClientContext,
	format string,
) (*GeoRoutedProfileResult, error) {
	if catalog == nil {
		return nil, ErrNoCompatibleNodes
	}
	if sub == nil {
		return nil, errors.New("subscription data is required")
	}
	configs, err := catalogConfigsFor(catalog, sub, client.Core)
	if err != nil {
		return nil, err
	}
	body, contentType := BuildSubscriptionBodyEx(configs, format)
	return &GeoRoutedProfileResult{
		Body:        body,
		ContentType: contentType,
		Reason: "verified operator node catalog; telemetry ordering is disabled " +
			"until a real score reader is configured",
		Nodes:       len(configs),
		GeneratedAt: nowUTC(),
	}, nil
}

func catalogConfigsFor(
	catalog *NodeCatalog,
	sub *SubscriptionData,
	clientCore string,
) ([]ProxyLinkConfig, error) {
	ids := make([]string, 0, len(catalog.nodes))
	for id := range catalog.nodes {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	configs := make([]ProxyLinkConfig, 0, len(ids))
	for _, id := range ids {
		node, err := catalog.Resolve(id, clientCore)
		if err != nil {
			continue
		}
		identity, err := applySubscriptionIdentity(node, sub)
		if err != nil {
			return nil, fmt.Errorf("catalog node %q: %w", id, err)
		}
		configs = append(configs, ProxyLinkConfig{
			UserID:   sub.UserID,
			Remark:   "Aether-X " + id,
			FragPath: "sub",
			Node:     identity,
		})
	}
	if len(configs) == 0 {
		return nil, ErrNoCompatibleNodes
	}
	return configs, nil
}

func validateCatalogNode(node CatalogNode) error {
	if strings.TrimSpace(node.ID) == "" {
		return errors.New("catalog node id is required")
	}
	if err := ValidateNodeConfig(node.NodeConfig); err != nil {
		return fmt.Errorf("catalog node %q: %w", node.ID, err)
	}
	if isNativeQUICProtocol(node.Protocol) && len(node.ClientCores) == 0 {
		return fmt.Errorf("catalog node %q requires an explicit compatible client allow-list for protocol %q", node.ID, node.Protocol)
	}
	for _, core := range node.ClientCores {
		if !knownClientCore(core) {
			return fmt.Errorf("catalog node %q names unsupported client core %q", node.ID, core)
		}
		if !coreSupportsProtocol(core, node.Protocol) {
			return fmt.Errorf("catalog node %q protocol %q is not supported by client core %q", node.ID, node.Protocol, core)
		}
	}
	return validateNodeRenderability(node)
}

func validateNodeRenderability(node CatalogNode) error {
	config := ProxyLinkConfig{
		Remark: "catalog-validation",
		Node:   node.NodeConfig,
	}
	if link := BuildProxyLink(config); link == "" {
		return fmt.Errorf("catalog node %q could not render a standard share link", node.ID)
	}

	var clash struct {
		Proxies []struct {
			Type string `yaml:"type"`
		} `yaml:"proxies"`
	}
	if err := yaml.Unmarshal(buildClashFromNodes([]ProxyLinkConfig{config}), &clash); err != nil {
		return fmt.Errorf("catalog node %q renders invalid Clash YAML: %w", node.ID, err)
	}
	if len(clash.Proxies) != 1 {
		return fmt.Errorf("catalog node %q renders %d Clash proxies, want 1", node.ID, len(clash.Proxies))
	}
	if clash.Proxies[0].Type != clashProtocol(node.Protocol) {
		return fmt.Errorf("catalog node %q renders Clash type %q, want %q", node.ID, clash.Proxies[0].Type, clashProtocol(node.Protocol))
	}

	var singbox struct {
		Outbounds []struct {
			Type string `json:"type"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal(buildSingboxFromNodes([]ProxyLinkConfig{config}), &singbox); err != nil {
		return fmt.Errorf("catalog node %q renders invalid sing-box JSON: %w", node.ID, err)
	}
	if len(singbox.Outbounds) != 1 {
		return fmt.Errorf("catalog node %q renders %d sing-box outbounds, want 1", node.ID, len(singbox.Outbounds))
	}
	if singbox.Outbounds[0].Type != node.Protocol {
		return fmt.Errorf("catalog node %q renders sing-box type %q, want %q", node.ID, singbox.Outbounds[0].Type, node.Protocol)
	}
	return nil
}

func applySubscriptionIdentity(node NodeConfig, sub *SubscriptionData) (NodeConfig, error) {
	if sub == nil || strings.TrimSpace(sub.UserID) == "" {
		return NodeConfig{}, errors.New("subscription user identity is required")
	}
	// Catalog credentials are explicit and validated. A future identity service
	// can replace this copy with a per-subscription credential without changing
	// the client config renderer.
	return node, nil
}

func supportedProtocol(protocol string) bool {
	for _, candidate := range transport.Protocols() {
		if candidate.ID == protocol {
			return true
		}
	}
	return false
}

func isNativeQUICProtocol(protocol string) bool {
	return protocol == "hysteria2" || protocol == "tuic"
}

// coreSupportsProtocol keeps native QUIC protocols away from clients whose
// standard import schema cannot represent them. Stream protocols remain
// catalog-driven because their compatibility is expressed by transport fields.
func coreSupportsProtocol(core, protocol string) bool {
	if !isNativeQUICProtocol(protocol) {
		return true
	}
	switch core {
	case "sing-box", "clash-meta", "nekobox":
		return true
	default:
		return false
	}
}

func knownClientCore(core string) bool {
	switch core {
	case "sing-box", "xray-core", "clash-meta", "shadowrocket", "nekobox":
		return true
	default:
		return false
	}
}

func allowsClientCore(allowed []string, clientCore string) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, core := range allowed {
		if core == clientCore {
			return true
		}
	}
	return false
}

func validPublishedHost(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || strings.ContainsAny(value, " \t\r\n/@") {
		return false
	}
	if strings.HasSuffix(strings.ToLower(value), ".example") || value == "localhost" {
		return false
	}
	if net.ParseIP(value) != nil {
		return true
	}
	if len(value) > 253 || !strings.Contains(value, ".") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, character := range label {
			isLower := character >= 'a' && character <= 'z'
			isUpper := character >= 'A' && character <= 'Z'
			isDigit := character >= '0' && character <= '9'
			if !isLower && !isUpper && !isDigit && character != '-' {
				return false
			}
		}
	}
	return true
}

func cloneCatalogNode(node CatalogNode) CatalogNode {
	return CatalogNode{
		NodeConfig:  cloneNodeConfig(node.NodeConfig),
		Enabled:     node.Enabled,
		ClientCores: append([]string(nil), node.ClientCores...),
	}
}

func cloneNodeConfig(node NodeConfig) NodeConfig {
	return node
}

func nowUTC() time.Time {
	return time.Now().UTC()
}

// Compile-time assertion: the catalog service remains compatible with the
// existing geo-routed endpoint contract without importing the API package.
var _ interface {
	BuildGeoRouted(context.Context, *SubscriptionData, string, string, string) (*GeoRoutedProfileResult, error)
} = (*CatalogSubscriptionService)(nil)
