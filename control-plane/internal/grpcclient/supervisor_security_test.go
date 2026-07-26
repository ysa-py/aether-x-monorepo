package grpcclient

import "testing"

func TestLoopbackEndpointClassification(t *testing.T) {
	for _, address := range []string{"127.0.0.1:7070", "[::1]:7070", "localhost:7070"} {
		if !isLoopbackEndpoint(address) {
			t.Errorf("%q should be loopback", address)
		}
	}
	for _, address := range []string{"core-supervisor:7070", "192.0.2.1:7070", "invalid"} {
		if isLoopbackEndpoint(address) {
			t.Errorf("%q must not be treated as loopback", address)
		}
	}
}

func TestNewRejectsRemotePlaintextBeforeDial(t *testing.T) {
	client, err := New(t.Context(), "core-supervisor:7070", TLSConfig{})
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
