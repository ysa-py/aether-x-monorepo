// Package antiforgeryclient is the control-plane's typed client for the Rust
// anti-forgery gRPC service. The control plane NEVER reimplements the crypto —
// it calls this bridge.
package antiforgeryclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/aether-x/control-plane/api/gen/go/aether/antiforgery/v1"
)

// Client wraps the generated anti-forgery gRPC client.
type Client struct {
	pb   pb.AntiForgeryServiceClient
	conn *grpc.ClientConn
}

// TLSConfig contains the mutually authenticated transport material for the
// anti-forgery service. Paths are loaded only when Enabled is true.
type TLSConfig struct {
	Enabled    bool
	Cert       string // client certificate PEM path
	Key        string // client key PEM path
	CA         string // anti-forgery server CA PEM path
	ServerName string // optional certificate DNS name / SNI override
}

// New dials the anti-forgery server. Plaintext is limited to a loopback dev
// listener; all inter-service deployments must use mutual TLS.
func New(_ context.Context, addr string, tlsCfg TLSConfig) (*Client, error) {
	var creds credentials.TransportCredentials
	if tlsCfg.Enabled {
		tc, err := buildTLS(tlsCfg)
		if err != nil {
			return nil, fmt.Errorf("anti-forgery mTLS dial: %w", err)
		}
		creds = credentials.NewTLS(tc)
	} else {
		if !isLoopbackEndpoint(addr) {
			return nil, fmt.Errorf("refusing plaintext anti-forgery dial to non-loopback address %q", addr)
		}
		creds = insecure.NewCredentials()
	}
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("anti-forgery dial %s: %w", addr, err)
	}
	return &Client{pb: pb.NewAntiForgeryServiceClient(conn), conn: conn}, nil
}

func buildTLS(c TLSConfig) (*tls.Config, error) {
	if c.Cert == "" || c.Key == "" || c.CA == "" {
		return nil, errors.New("client certificate, key, and anti-forgery CA paths are all required for mTLS")
	}
	certificate, err := tls.LoadX509KeyPair(c.Cert, c.Key)
	if err != nil {
		return nil, fmt.Errorf("load client keypair: %w", err)
	}
	caPEM, err := os.ReadFile(c.CA)
	if err != nil {
		return nil, fmt.Errorf("read anti-forgery CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("invalid anti-forgery CA PEM")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{certificate},
		RootCAs:      roots,
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

// Issue signs a subscription token and records it in the audit log.
func (c *Client) Issue(
	ctx context.Context, subscriptionID, userID string,
	bytesTotal, bytesUsed, expiresUnix int64,
) (*pb.IssueTokenResponse, error) {
	return c.pb.IssueToken(ctx, &pb.IssueTokenRequest{
		SubscriptionId: subscriptionID,
		UserId:         userID,
		BytesTotal:     bytesTotal,
		BytesUsed:      bytesUsed,
		ExpiresUnix:    expiresUnix,
	})
}

// Verify checks a token's signature and expiry/quota against nowUnix.
func (c *Client) Verify(ctx context.Context, token string, nowUnix int64) (*pb.VerifyTokenResponse, error) {
	return c.pb.VerifyToken(ctx, &pb.VerifyTokenRequest{Token: token, NowUnix: nowUnix})
}

// AuditRoot returns the current audit-log commitments.
func (c *Client) AuditRoot(ctx context.Context) (*pb.AuditRootResponse, error) {
	return c.pb.AuditRoot(ctx, &pb.AuditRootRequest{})
}

// Close releases the underlying connection.
func (c *Client) Close() error { return c.conn.Close() }

// Raw returns the underlying generated gRPC client, for cases (like the API
// layer) that want the proto-typed interface directly.
func (c *Client) Raw() pb.AntiForgeryServiceClient { return c.pb }
