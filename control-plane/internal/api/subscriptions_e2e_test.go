package api

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	antiforgerypb "github.com/aether-x/control-plane/api/gen/go/aether/antiforgery/v1"
)

// fakeAntiforgeryServer is a canned AntiForgeryServiceServer used to exercise
// the REAL /v1/subscriptions handlers over a real (bufconn) gRPC transport.
type fakeAntiforgeryServer struct {
	antiforgerypb.UnimplementedAntiForgeryServiceServer
}

func (fakeAntiforgeryServer) IssueToken(
	_ context.Context, req *antiforgerypb.IssueTokenRequest,
) (*antiforgerypb.IssueTokenResponse, error) {
	hash := make([]byte, 32)
	for i := range hash {
		hash[i] = byte(i)
	}
	vk := make([]byte, 32)
	for i := range vk {
		vk[i] = 0xff - byte(i)
	}
	return &antiforgerypb.IssueTokenResponse{
		Token:        "tok-" + req.GetSubscriptionId(),
		AuditSeq:     7,
		AuditHash:    hash,
		VerifyingKey: vk,
	}, nil
}

func (fakeAntiforgeryServer) VerifyToken(
	_ context.Context, req *antiforgerypb.VerifyTokenRequest,
) (*antiforgerypb.VerifyTokenResponse, error) {
	valid := len(req.GetToken()) > 4 && req.GetToken()[:4] == "tok-"
	resp := &antiforgerypb.VerifyTokenResponse{
		SignatureValid: valid,
		Expired:        false,
		QuotaExhausted: false,
		IsLive:         valid,
	}
	if valid {
		resp.Claims = &antiforgerypb.Claims{SubscriptionId: "sub-x", BytesTotal: 100, ExpiresUnix: 2_000_000_000}
	}
	return resp, nil
}

func (fakeAntiforgeryServer) AuditRoot(
	_ context.Context, _ *antiforgerypb.AuditRootRequest,
) (*antiforgerypb.AuditRootResponse, error) {
	mr := make([]byte, 32)
	mr[0] = 0x01
	cr := make([]byte, 32)
	cr[0] = 0x02
	return &antiforgerypb.AuditRootResponse{
		MerkleRoot: mr,
		ChainRoot:  cr,
		Count:      42,
	}, nil
}

// newAntiforgeryServer builds a bufconn-backed AntiForgeryServiceClient wired
// to a fake server.
func newAntiforgeryServer(t *testing.T) antiforgerypb.AntiForgeryServiceClient {
	t.Helper()
	lis := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer()
	antiforgerypb.RegisterAntiForgeryServiceServer(srv, fakeAntiforgeryServer{})
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := grpc.DialContext(ctx, "bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return antiforgerypb.NewAntiForgeryServiceClient(conn)
}

// doJSON issues a request against the api router and returns the status + body.
func doJSON(t *testing.T, s *Server, method, path string, body any) (int, map[string]any) {
	t.Helper()
	var rdr *bytes.Buffer
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		rdr = bytes.NewBuffer(b)
	} else {
		rdr = &bytes.Buffer{}
	}
	req := httptest.NewRequest(method, path, rdr)
	rec := httptest.NewRecorder()
	s.Router().ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func TestSubscriptionsIssueE2E(t *testing.T) {
	s := &Server{Antiforgery: newAntiforgeryServer(t), Build: "test"}
	code, body := doJSON(t, s, http.MethodPost, "/v1/subscriptions/issue", map[string]any{
		"subscription_id": "sub-1",
		"user_id":         "u-1",
		"bytes_total":     1_000_000_000,
		"bytes_used":      0,
		"expires_unix":    2_000_000_000,
	})
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %v", code, body)
	}
	if body["token"] != "tok-sub-1" {
		t.Fatalf("unexpected token: %v", body["token"])
	}
	if body["audit_seq"] != float64(7) {
		t.Fatalf("unexpected audit_seq: %v", body["audit_seq"])
	}
	// audit_hash and verifying_key must be hex-encoded 32-byte strings.
	if h, ok := body["audit_hash"].(string); !ok || len(h) != 64 {
		t.Fatalf("bad audit_hash: %v", body["audit_hash"])
	}
	if _, err := hex.DecodeString(body["audit_hash"].(string)); err != nil {
		t.Fatalf("audit_hash not hex: %v", err)
	}
}

func TestSubscriptionsIssueRejectsMissingID(t *testing.T) {
	s := &Server{Antiforgery: newAntiforgeryServer(t)}
	code, _ := doJSON(t, s, http.MethodPost, "/v1/subscriptions/issue", map[string]any{
		"user_id": "u-1",
	})
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing subscription_id, got %d", code)
	}
}

func TestSubscriptionsVerifyE2E(t *testing.T) {
	s := &Server{Antiforgery: newAntiforgeryServer(t)}
	// A valid (canned) token verifies as live.
	code, body := doJSON(t, s, http.MethodPost, "/v1/subscriptions/verify", map[string]any{
		"token":    "tok-sub-1",
		"now_unix": 1_000,
	})
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %v", code, body)
	}
	if body["signature_valid"] != true {
		t.Fatalf("expected signature_valid=true: %v", body)
	}
	if body["is_live"] != true {
		t.Fatalf("expected is_live=true: %v", body)
	}
}

func TestSubscriptionsAuditRootE2E(t *testing.T) {
	s := &Server{Antiforgery: newAntiforgeryServer(t)}
	code, body := doJSON(t, s, http.MethodGet, "/v1/subscriptions/audit-root", nil)
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %v", code, body)
	}
	if body["count"] != float64(42) {
		t.Fatalf("unexpected count: %v", body["count"])
	}
	if h, ok := body["merkle_root"].(string); !ok || len(h) != 64 {
		t.Fatalf("bad merkle_root: %v", body["merkle_root"])
	}
}

func TestSubscriptionsDisabledWhenBridgeDown(t *testing.T) {
	// No Antiforgery client configured -> degraded 503.
	s := &Server{}
	code, _ := doJSON(t, s, http.MethodPost, "/v1/subscriptions/issue", map[string]any{
		"subscription_id": "sub-1",
	})
	if code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when bridge down, got %d", code)
	}
}
