// Package grpctest provides an in-memory (bufconn) gRPC test harness for the
// Core Supervisor service, so multiple test packages can spin up a real gRPC
// transport against a canned server without duplicating the dialer boilerplate.
package grpctest

import (
	"context"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	supervisorpb "github.com/aether-x/control-plane/api/gen/go/aether/supervisor/v1"
	"github.com/aether-x/control-plane/internal/grpcclient"
)

// NewClient registers `srv` on an in-memory gRPC server and returns a real
// grpcclient.Client wired to it. The server and connection are cleaned up
// automatically when the test ends.
func NewClient(t testing.TB, srv supervisorpb.CoreSupervisorServiceServer) *grpcclient.Client {
	t.Helper()
	const bufSize = 1024 * 1024
	lis := bufconn.Listen(bufSize)
	s := grpc.NewServer()
	supervisorpb.RegisterCoreSupervisorServiceServer(s, srv)

	errCh := make(chan error, 1)
	go func() { errCh <- s.Serve(lis) }()
	t.Cleanup(s.Stop)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := grpc.DialContext(ctx, "bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return lis.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial bufconn: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return grpcclient.NewFromConn(conn)
}
