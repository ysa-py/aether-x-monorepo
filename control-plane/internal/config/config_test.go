package config

import (
	"strings"
	"testing"
	"time"
)

func TestValidateSupervisorTransportAllowsLoopbackDevelopment(t *testing.T) {
	cfg := Config{SupervisorAddr: "127.0.0.1:7070"}
	if err := validateSupervisorTransport(cfg); err != nil {
		t.Fatalf("loopback plaintext should be allowed for development: %v", err)
	}
}

func TestValidateSupervisorTransportRejectsPlaintextServiceAddress(t *testing.T) {
	cfg := Config{SupervisorAddr: "core-supervisor:7070"}
	err := validateSupervisorTransport(cfg)
	if err == nil {
		t.Fatal("non-loopback plaintext supervisor address must be rejected")
	}
	if !strings.Contains(err.Error(), "AETHER_MTLS_ENABLED=true") {
		t.Fatalf("error %q should explain the mTLS remedy", err)
	}
}

func TestValidateSupervisorTransportRequiresAllMTLSPaths(t *testing.T) {
	cfg := Config{
		SupervisorAddr: "core-supervisor:7070",
		MTLSEnabled:    true,
		SupervisorCert: "/secrets/control-plane.crt",
		SupervisorKey:  "/secrets/control-plane.key",
	}
	if err := validateSupervisorTransport(cfg); err == nil {
		t.Fatal("mTLS configuration missing CA must be rejected")
	}

	cfg.SupervisorCA = "/secrets/ca.crt"
	if err := validateSupervisorTransport(cfg); err != nil {
		t.Fatalf("complete mTLS configuration should pass static validation: %v", err)
	}
}

func TestValidateAntiforgeryTransportRequiresMTLSOutsideLoopback(t *testing.T) {
	cfg := Config{AntiforgeryAddr: "antiforgery-server:7071"}
	if err := validateAntiforgeryTransport(cfg); err == nil {
		t.Fatal("non-loopback plaintext anti-forgery address must be rejected")
	}

	cfg.AntiforgeryMTLSEnabled = true
	cfg.AntiforgeryCert = "/secrets/control-plane.crt"
	cfg.AntiforgeryKey = "/secrets/control-plane.key"
	cfg.AntiforgeryCA = "/secrets/ca.crt"
	if err := validateAntiforgeryTransport(cfg); err != nil {
		t.Fatalf("complete anti-forgery mTLS configuration should pass static validation: %v", err)
	}
}

func TestValidateSubscriptionDeliveryRequiresVerifiedCatalogPath(t *testing.T) {
	if err := validateSubscriptionDelivery(Config{SubscriptionDelivery: true}); err == nil {
		t.Fatal("enabled subscription delivery must require a verified catalog path")
	}
	if err := validateSubscriptionDelivery(Config{
		SubscriptionDelivery:      true,
		NodeCatalogFile:           "/run/aether/catalog.json",
		NodeCatalogReloadInterval: time.Second,
	}); err != nil {
		t.Fatalf("catalog-backed subscription delivery should validate: %v", err)
	}
	if err := validateSubscriptionDelivery(Config{
		SubscriptionDelivery:      true,
		NodeCatalogFile:           "/run/aether/catalog.json",
		NodeCatalogReloadInterval: 500 * time.Millisecond,
	}); err == nil {
		t.Fatal("sub-second catalog polling must be rejected")
	}
	if err := validateSubscriptionDelivery(Config{TelemetryScoring: true}); err == nil {
		t.Fatal("telemetry scoring without subscription delivery must be rejected")
	}
	if err := validateSubscriptionDelivery(Config{
		SubscriptionDelivery:      true,
		NodeCatalogFile:           "/run/aether/catalog.json",
		NodeCatalogReloadInterval: time.Second,
		TelemetryScoring:          true,
	}); err == nil {
		t.Fatal("telemetry scoring without a ClickHouse DSN must be rejected")
	}
}

func TestParseJWTPreviousKeys(t *testing.T) {
	keys, err := parseJWTPreviousKeys("old-a:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa, old-b:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	if err != nil {
		t.Fatalf("parse previous keys: %v", err)
	}
	if string(keys["old-a"]) != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" || string(keys["old-b"]) != "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" {
		t.Fatalf("unexpected previous keys: %#v", keys)
	}
	if _, err := parseJWTPreviousKeys("broken-entry"); err == nil {
		t.Fatal("malformed previous key entry must be rejected")
	}
}

func TestGetenvCSVTrimsAndDropsEmptyValues(t *testing.T) {
	t.Setenv("AETHER_TRUSTED_PROXY_CIDRS", " 127.0.0.0/8, ,10.0.0.0/8 ")
	values := getenvCSV("AETHER_TRUSTED_PROXY_CIDRS")
	if len(values) != 2 || values[0] != "127.0.0.0/8" || values[1] != "10.0.0.0/8" {
		t.Fatalf("unexpected CSV values: %#v", values)
	}
}

func TestIsLoopbackEndpoint(t *testing.T) {
	for _, address := range []string{"127.0.0.1:7070", "[::1]:7070", "localhost:7070"} {
		if !isLoopbackEndpoint(address) {
			t.Errorf("%q should be recognized as loopback", address)
		}
	}
	for _, address := range []string{"core-supervisor:7070", "10.0.0.4:7070", "not-a-socket"} {
		if isLoopbackEndpoint(address) {
			t.Errorf("%q must not be recognized as loopback", address)
		}
	}
}

func TestHTTPAddrUsesExplicitAddressThenValidatedPortFallback(t *testing.T) {
	t.Setenv("AETHER_HTTP_ADDR", "127.0.0.1:9090")
	t.Setenv("AETHER_PORT", "8081")
	if got := httpAddrFromEnv(); got != "127.0.0.1:9090" {
		t.Fatalf("explicit address = %q, want 127.0.0.1:9090", got)
	}

	t.Setenv("AETHER_HTTP_ADDR", "")
	t.Setenv("AETHER_PORT", "8081")
	if got := httpAddrFromEnv(); got != "0.0.0.0:8081" {
		t.Fatalf("port fallback = %q, want 0.0.0.0:8081", got)
	}

	t.Setenv("AETHER_PORT", "not-a-port")
	if got := httpAddrFromEnv(); got != "0.0.0.0:8080" {
		t.Fatalf("invalid port fallback = %q, want default", got)
	}
}
