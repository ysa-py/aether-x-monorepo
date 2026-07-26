package transport

import (
	"testing"
)

func TestCatalogComplete(t *testing.T) {
	got := Catalog()
	// Must include every transport the subscriber/admin spec requires.
	required := []string{"xhttp", "httpupgrade", "h2", "ws", "grpc", "kcp", "tcp", "quic", "http", "raw", "meek"}
	have := map[string]bool{}
	for _, c := range got {
		have[c.ID] = true
	}
	for _, id := range required {
		if !have[id] {
			t.Errorf("catalog missing required transport %q", id)
		}
	}
	if len(got) < len(required) {
		t.Errorf("catalog has only %d entries, want >= %d", len(got), len(required))
	}
}

func TestCatalogNewestFirst(t *testing.T) {
	got := Catalog()
	if len(got) == 0 {
		t.Fatal("empty catalog")
	}
	// xhttp must surface as a "newest" entry.
	first := got[0]
	if !first.Newest {
		t.Errorf("expected newest transport first, got %q (newest=%v)", first.ID, first.Newest)
	}
	xhttp, ok := ByID("xhttp")
	if !ok {
		t.Fatal("xhttp not found")
	}
	if !xhttp.Newest {
		t.Error("xhttp should be flagged newest")
	}
	if xhttp.Family != FamilyHTTP {
		t.Errorf("xhttp family = %q, want http", xhttp.Family)
	}
	if len(xhttp.Modes) < 3 {
		t.Errorf("xhttp should advertise >=3 modes, got %v", xhttp.Modes)
	}
}

func TestByID(t *testing.T) {
	if _, ok := ByID("nope"); ok {
		t.Error("unknown id should not resolve")
	}
	ws, ok := ByID("ws")
	if !ok {
		t.Fatal("ws not found")
	}
	if !ws.NeedsPath || !ws.NeedsHost {
		t.Error("ws needs path + host")
	}
}

func TestIsValidAndIDs(t *testing.T) {
	for _, id := range IDs() {
		if !IsValid(id) {
			t.Errorf("IsValid(%q) = false", id)
		}
	}
	if IsValid("does-not-exist") {
		t.Error("IsValid should be false for unknown")
	}
}

func TestProtocols(t *testing.T) {
	ps := Protocols()
	want := map[string]bool{"vless": true, "vmess": true, "trojan": true, "shadowsocks": true}
	seen := map[string]bool{}
	for _, p := range ps {
		seen[p.ID] = true
	}
	for k := range want {
		if !seen[k] {
			t.Errorf("missing protocol %q", k)
		}
	}
}
