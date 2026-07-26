package antiforgeryclient

import "testing"

func TestLoopbackEndpointClassification(t *testing.T) {
	for _, address := range []string{"127.0.0.1:7071", "[::1]:7071", "localhost:7071"} {
		if !isLoopbackEndpoint(address) {
			t.Errorf("%q should be loopback", address)
		}
	}
	for _, address := range []string{"antiforgery-server:7071", "192.0.2.5:7071", "invalid"} {
		if isLoopbackEndpoint(address) {
			t.Errorf("%q must not be treated as loopback", address)
		}
	}
}

func TestNewRejectsRemotePlaintextBeforeDial(t *testing.T) {
	client, err := New(t.Context(), "antiforgery-server:7071", TLSConfig{})
	if err == nil {
		if client != nil {
			_ = client.Close()
		}
		t.Fatal("remote plaintext client construction must fail")
	}
}

func TestBuildTLSRejectsMissingMaterial(t *testing.T) {
	if _, err := buildTLS(TLSConfig{}); err == nil {
		t.Fatal("missing mTLS material must be rejected")
	}
}
