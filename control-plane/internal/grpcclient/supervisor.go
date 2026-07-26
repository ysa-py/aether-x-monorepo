// Package grpcclient is the control-plane's typed client for the Rust
// Core Supervisor (data plane). All cross-plane calls go through here so we
// have one place for mTLS, retries, and metrics.
package grpcclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	supervisorpb "github.com/aether-x/control-plane/api/gen/go/aether/supervisor/v1"
)

// Client wraps the generated supervisor gRPC client.
type Client struct {
	pb   supervisorpb.CoreSupervisorServiceClient
	conn *grpc.ClientConn
}

// New dials the supervisor with mTLS when configured, else insecure (dev only).
func New(ctx context.Context, addr string, tlsCfg TLSConfig) (*Client, error) {
	var creds credentials.TransportCredentials
	if tlsCfg.Enabled {
		tc, err := buildTLS(tlsCfg)
		if err != nil {
			return nil, fmt.Errorf("mTLS dial: %w", err)
		}
		creds = credentials.NewTLS(tc)
	} else {
		if !isLoopbackEndpoint(addr) {
			return nil, fmt.Errorf("refusing plaintext supervisor dial to non-loopback address %q", addr)
		}
		// Insecure is retained only for a local development supervisor.
		creds = insecure.NewCredentials()
	}

	// grpc.NewClient is non-blocking; the first RPC will establish the conn.
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("grpc dial %s: %w", addr, err)
	}
	return &Client{
		pb:   supervisorpb.NewCoreSupervisorServiceClient(conn),
		conn: conn,
	}, nil
}

// TLSConfig carries the mTLS material paths.
type TLSConfig struct {
	Enabled    bool
	Cert       string // client cert PEM path
	Key        string // client key PEM path
	CA         string // supervisor server CA PEM path
	ServerName string // optional certificate DNS name / SNI override
}

func buildTLS(c TLSConfig) (*tls.Config, error) {
	if c.Cert == "" || c.Key == "" || c.CA == "" {
		return nil, errors.New("client certificate, key, and supervisor CA paths are all required for mTLS")
	}
	cert, err := tls.LoadX509KeyPair(c.Cert, c.Key)
	if err != nil {
		return nil, fmt.Errorf("load client keypair: %w", err)
	}
	caPEM, err := os.ReadFile(c.CA)
	if err != nil {
		return nil, fmt.Errorf("read supervisor CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("invalid supervisor CA PEM")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ServerName:   c.ServerName,
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h2"},
	}, nil
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

// Close releases the underlying connection.
func (c *Client) Close() error { return c.conn.Close() }

// Health probes the supervisor.
func (c *Client) Health(ctx context.Context) (*supervisorpb.HealthCheckResponse, error) {
	return c.pb.HealthCheck(ctx, &supervisorpb.HealthCheckRequest{})
}

// StartCore starts a supervised core.
func (c *Client) StartCore(ctx context.Context, cfg *supervisorpb.CoreConfig) (*supervisorpb.StartCoreResponse, error) {
	return c.pb.StartCore(ctx, &supervisorpb.StartCoreRequest{Config: cfg})
}

// ListCores returns all supervised instances.
func (c *Client) ListCores(ctx context.Context) (*supervisorpb.ListCoresResponse, error) {
	return c.pb.ListCores(ctx, &supervisorpb.ListCoresRequest{})
}

// ApplyPolicy pushes a fallback/AI policy to an instance.
func (c *Client) ApplyPolicy(ctx context.Context, instance string, p *supervisorpb.Policy) (*supervisorpb.ApplyPolicyResponse, error) {
	return c.pb.ApplyPolicy(ctx, &supervisorpb.ApplyPolicyRequest{InstanceId: instance, Policy: p})
}

// HotSwap switches a core's active protocol, draining where supported.
func (c *Client) HotSwap(ctx context.Context, instance, protocolID string, drainMs uint32) (*supervisorpb.HotSwapProtocolResponse, error) {
	return c.pb.HotSwapProtocol(ctx, &supervisorpb.HotSwapProtocolRequest{
		InstanceId:     instance,
		NewProtocol:    &supervisorpb.ProtocolSpec{ProtocolId: protocolID},
		DrainTimeoutMs: drainMs,
	})
}

// StreamTelemetry opens the server-streaming telemetry channel. The returned
// stream is consumed by the telemetry ingester.
func (c *Client) StreamTelemetry(ctx context.Context, nodeID string) (supervisorpb.CoreSupervisorService_StreamTelemetryClient, error) {
	return c.pb.StreamTelemetry(ctx, &supervisorpb.StreamTelemetryRequest{NodeId: nodeID})
}

// rpcTimeout is a sane default for unary calls.
const rpcTimeout = 5 * time.Second

// NewFromConn builds a Client from an existing gRPC connection. Useful for
// tests with custom dialers (e.g. bufconn) or bespoke connection wiring.
func NewFromConn(conn *grpc.ClientConn) *Client {
	return &Client{
		pb:   supervisorpb.NewCoreSupervisorServiceClient(conn),
		conn: conn,
	}
}

// Route asks the supervisor's data-plane routing engine for the Direct/Proxy/Block
// action for a destination (domain and/or IP string; "" to omit).
func (c *Client) Route(ctx context.Context, domain, ip string) (*supervisorpb.RouteResponse, error) {
	return c.pb.Route(ctx, &supervisorpb.RouteRequest{Domain: domain, Ip: ip})
}
