// Package config holds the control-plane configuration, sourced from
// environment variables (12-factor friendly) with safe development defaults.
package config

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the resolved control-plane configuration.
type Config struct {
	HTTPAddr                  string            // public REST/MCP listener
	SupervisorAddr            string            // Rust data-plane gRPC address
	PostgresDSN               string            // source of truth DB
	ClickHouseDSN             string            // telemetry / feature store
	RedisAddr                 string            // sessions + rate limiting
	JWTSecret                 []byte            // active signing key for access tokens
	JWTKeyID                  string            // active JWT key ID used in kid header
	JWTPreviousKeys           map[string][]byte // verification-only rotating JWT keys
	MTLSEnabled               bool              // require mTLS to the supervisor
	SupervisorCert            string            // client cert PEM path (mTLS)
	SupervisorKey             string            // client key PEM path (mTLS)
	SupervisorCA              string            // supervisor server CA PEM path
	SupervisorServerName      string            // optional TLS SNI / certificate name
	AntiforgeryAddr           string            // Rust anti-forgery gRPC address
	AntiforgeryMTLSEnabled    bool              // require mTLS to the anti-forgery service
	AntiforgeryCert           string            // client cert PEM path (mTLS)
	AntiforgeryKey            string            // client key PEM path (mTLS)
	AntiforgeryCA             string            // anti-forgery server CA PEM path
	AntiforgeryServerName     string            // optional TLS SNI / certificate name
	NodeCatalogFile           string            // validated standard-client node catalog JSON path
	NodeCatalogReloadInterval time.Duration     // safe poll interval for catalog hot reload
	SubscriptionDelivery      bool              // publish verified standard-client subscriptions
	TelemetryScoring          bool              // reorder verified nodes using real ClickHouse aggregates
	TrustedProxyCIDRs         []string          // ingress CIDRs allowed to assert network headers
	Development               bool              // explicit local-only auth bypass
	TelemetryFlush            time.Duration     // how often the ingester commits to ClickHouse
}

// FromEnv reads configuration from the process environment.
func FromEnv() (Config, error) {
	c := Config{
		HTTPAddr:                  httpAddrFromEnv(),
		JWTKeyID:                  getenv("AETHER_JWT_KEY_ID", "active"),
		SupervisorAddr:            getenv("AETHER_SUPERVISOR_ADDR", "127.0.0.1:7070"),
		PostgresDSN:               getenv("AETHER_POSTGRES_DSN", "postgres://aether:aether@localhost:5432/aether?sslmode=disable"),
		ClickHouseDSN:             getenv("AETHER_CLICKHOUSE_DSN", "clickhouse://aether:aether@localhost:9000/aether"),
		RedisAddr:                 getenv("AETHER_REDIS_ADDR", "localhost:6379"),
		TelemetryFlush:            getenvDuration("AETHER_TELEMETRY_FLUSH", 500*time.Millisecond),
		MTLSEnabled:               getenvBool("AETHER_MTLS_ENABLED", false),
		SupervisorCert:            os.Getenv("AETHER_SUPERVISOR_CERT"),
		SupervisorKey:             os.Getenv("AETHER_SUPERVISOR_KEY"),
		SupervisorCA:              os.Getenv("AETHER_SUPERVISOR_CA"),
		SupervisorServerName:      os.Getenv("AETHER_SUPERVISOR_SERVER_NAME"),
		AntiforgeryAddr:           getenv("AETHER_ANTIFORGERY_ADDR", "127.0.0.1:7071"),
		AntiforgeryMTLSEnabled:    getenvBool("AETHER_ANTIFORGERY_MTLS_ENABLED", getenvBool("AETHER_MTLS_ENABLED", false)),
		AntiforgeryCert:           os.Getenv("AETHER_ANTIFORGERY_CERT"),
		AntiforgeryKey:            os.Getenv("AETHER_ANTIFORGERY_KEY"),
		AntiforgeryCA:             os.Getenv("AETHER_ANTIFORGERY_CA"),
		AntiforgeryServerName:     os.Getenv("AETHER_ANTIFORGERY_SERVER_NAME"),
		NodeCatalogFile:           os.Getenv("AETHER_NODE_CATALOG_FILE"),
		NodeCatalogReloadInterval: getenvDuration("AETHER_NODE_CATALOG_RELOAD_INTERVAL", 30*time.Second),
		SubscriptionDelivery:      getenvBool("AETHER_ENABLE_DYNAMIC_SUBS", false),
		TelemetryScoring:          getenvBool("AETHER_ENABLE_TELEMETRY_SCORING", false),
		TrustedProxyCIDRs:         getenvCSV("AETHER_TRUSTED_PROXY_CIDRS"),
		Development:               getenvBool("AETHER_DEV", false),
	}
	secret := os.Getenv("AETHER_JWT_SECRET")
	if len(secret) < 32 && !c.Development {
		return Config{}, fmt.Errorf("AETHER_JWT_SECRET must be >=32 bytes (or set AETHER_DEV=true)")
	}
	previousKeys, err := parseJWTPreviousKeys(os.Getenv("AETHER_JWT_PREVIOUS_KEYS"))
	if err != nil {
		return Config{}, err
	}
	c.JWTSecret = []byte(secret)
	c.JWTPreviousKeys = previousKeys
	if err := validateSupervisorTransport(c); err != nil {
		return Config{}, err
	}
	if err := validateAntiforgeryTransport(c); err != nil {
		return Config{}, err
	}
	if err := validateSubscriptionDelivery(c); err != nil {
		return Config{}, err
	}
	return c, nil
}

// validateSupervisorTransport prevents an accidental plaintext control-plane
// deployment. The Rust supervisor independently enforces the same server-side
// rule, so a misconfigured side fails closed rather than silently downgrading.
func validateSupervisorTransport(c Config) error {
	if c.MTLSEnabled {
		required := []struct {
			name  string
			value string
		}{
			{name: "AETHER_SUPERVISOR_CERT", value: c.SupervisorCert},
			{name: "AETHER_SUPERVISOR_KEY", value: c.SupervisorKey},
			{name: "AETHER_SUPERVISOR_CA", value: c.SupervisorCA},
		}
		for _, item := range required {
			if item.value == "" {
				return fmt.Errorf("%s is required when AETHER_MTLS_ENABLED=true", item.name)
			}
		}
		return nil
	}
	if !isLoopbackEndpoint(c.SupervisorAddr) {
		return fmt.Errorf("plaintext AETHER_SUPERVISOR_ADDR %q is not loopback; set AETHER_MTLS_ENABLED=true", c.SupervisorAddr)
	}
	return nil
}

func validateAntiforgeryTransport(c Config) error {
	if c.AntiforgeryMTLSEnabled {
		required := []struct {
			name  string
			value string
		}{
			{name: "AETHER_ANTIFORGERY_CERT", value: c.AntiforgeryCert},
			{name: "AETHER_ANTIFORGERY_KEY", value: c.AntiforgeryKey},
			{name: "AETHER_ANTIFORGERY_CA", value: c.AntiforgeryCA},
		}
		for _, item := range required {
			if item.value == "" {
				return fmt.Errorf("%s is required when AETHER_ANTIFORGERY_MTLS_ENABLED=true", item.name)
			}
		}
		return nil
	}
	if !isLoopbackEndpoint(c.AntiforgeryAddr) {
		return fmt.Errorf("plaintext AETHER_ANTIFORGERY_ADDR %q is not loopback; set AETHER_ANTIFORGERY_MTLS_ENABLED=true", c.AntiforgeryAddr)
	}
	return nil
}

func validateSubscriptionDelivery(c Config) error {
	if !c.SubscriptionDelivery {
		if c.TelemetryScoring {
			return fmt.Errorf("AETHER_ENABLE_TELEMETRY_SCORING requires AETHER_ENABLE_DYNAMIC_SUBS=true")
		}
		return nil
	}
	if c.NodeCatalogFile == "" {
		return fmt.Errorf("AETHER_NODE_CATALOG_FILE is required when AETHER_ENABLE_DYNAMIC_SUBS=true")
	}
	if c.NodeCatalogReloadInterval < time.Second {
		return fmt.Errorf("AETHER_NODE_CATALOG_RELOAD_INTERVAL must be at least 1s when subscription delivery is enabled")
	}
	if c.TelemetryScoring && c.ClickHouseDSN == "" {
		return fmt.Errorf("AETHER_CLICKHOUSE_DSN is required when AETHER_ENABLE_TELEMETRY_SCORING=true")
	}
	return nil
}

func isLoopbackEndpoint(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// httpAddrFromEnv gives the explicit socket address precedence. AETHER_PORT is
// a deployment-friendly fallback for platforms that inject a port separately;
// malformed or out-of-range values fail safe to the documented default.
func httpAddrFromEnv() string {
	if value, exists := os.LookupEnv("AETHER_HTTP_ADDR"); exists && strings.TrimSpace(value) != "" {
		return value
	}
	port, err := strconv.Atoi(getenv("AETHER_PORT", "8080"))
	if err != nil || port < 1 || port > 65535 {
		return "0.0.0.0:8080"
	}
	return net.JoinHostPort("0.0.0.0", strconv.Itoa(port))
}

func getenv(k, def string) string {
	if v, ok := os.LookupEnv(k); ok {
		return v
	}
	return def
}

func getenvBool(k string, def bool) bool {
	if v, ok := os.LookupEnv(k); ok {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return def
		}
		return b
	}
	return def
}

func getenvDuration(k string, def time.Duration) time.Duration {
	if v, ok := os.LookupEnv(k); ok {
		d, err := time.ParseDuration(v)
		if err != nil {
			return def
		}
		return d
	}
	return def
}

func getenvCSV(k string) []string {
	value := os.Getenv(k)
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

// parseJWTPreviousKeys parses verification-only keys as `kid:secret` pairs.
// Active signing material remains exclusively in AETHER_JWT_SECRET.
func parseJWTPreviousKeys(value string) (map[string][]byte, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	keys := make(map[string][]byte)
	for _, item := range strings.Split(value, ",") {
		keyID, secret, ok := strings.Cut(strings.TrimSpace(item), ":")
		keyID = strings.TrimSpace(keyID)
		secret = strings.TrimSpace(secret)
		if !ok || keyID == "" || secret == "" {
			return nil, fmt.Errorf("AETHER_JWT_PREVIOUS_KEYS entries must use kid:secret")
		}
		if _, exists := keys[keyID]; exists {
			return nil, fmt.Errorf("AETHER_JWT_PREVIOUS_KEYS contains duplicate key ID %q", keyID)
		}
		keys[keyID] = []byte(secret)
	}
	return keys, nil
}
