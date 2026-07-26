package clientengine

import (
	"strings"
	"testing"
)

func TestDraftFromURL_ExtractsNameAndPlatform(t *testing.T) {
	cases := []struct {
		url      string
		wantName string
		wantPlat string
	}{
		{"https://github.com/acme/NovaVPN", "NovaVPN", "all"},
		{"https://play.google.com/store/apps/details?id=com.nova.vpn", "Details", "android"}, // last segment, android host
		{"https://novavpn.app", "Novavpn", "all"},
		{"https://apps.apple.com/us/app/kevinvpn/id123", "Id123", "ios"},
	}
	for _, c := range cases {
		d, err := DraftFromURL(c.url)
		if err != nil {
			t.Errorf("%s: unexpected err %v", c.url, err)
			continue
		}
		if d.Name != c.wantName {
			t.Errorf("%s: name = %q, want %q", c.url, d.Name, c.wantName)
		}
		if d.Platform != c.wantPlat {
			t.Errorf("%s: platform = %q, want %q", c.url, d.Platform, c.wantPlat)
		}
		if d.Status != StatusDraftPending {
			t.Errorf("%s: status = %q, want %q", c.url, d.Status, StatusDraftPending)
		}
		if d.URI != "" {
			t.Errorf("%s: draft must not guess a URI (got %q)", c.url, d.URI)
		}
		if !strings.Contains(d.Note, "verify") {
			t.Errorf("%s: note should mention verification", c.url)
		}
	}
}

func TestDraftFromURL_Invalid(t *testing.T) {
	for _, bad := range []string{"", "not-a-url", "ftp://", "http://"} {
		if _, err := DraftFromURL(bad); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
}

func TestDraftRegistry_ConfirmGate(t *testing.T) {
	engine := Default()
	reg := NewDraftRegistry(engine)

	// Draft is pending and NOT in the served engine.
	draft, err := reg.DraftFromURLAndStore("https://github.com/acme/NovaVPN")
	if err != nil {
		t.Fatalf("draft: %v", err)
	}
	if draft.Status != StatusDraftPending {
		t.Fatalf("status = %q, want pending", draft.Status)
	}
	if isServed(engine, "NovaVPN") {
		t.Fatal("pending draft must NOT be served to subscribers yet")
	}

	// Unknown confirm → error.
	if _, err := reg.Confirm("ghost"); err != ErrDraftNotFound {
		t.Errorf("confirm unknown: err = %v, want ErrDraftNotFound", err)
	}

	// Confirm promotes into the served engine.
	confirmed, err := reg.Confirm("NovaVPN")
	if err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if confirmed.Status != StatusConfirmed {
		t.Errorf("status = %q, want confirmed", confirmed.Status)
	}
	if !isServed(engine, "NovaVPN") {
		t.Error("confirmed draft must be served to subscribers")
	}

	// Confirm again is idempotent (no duplicate in served list).
	if _, err := reg.Confirm("NovaVPN"); err != nil {
		t.Fatalf("second confirm: %v", err)
	}
	count := 0
	engine.mu.RLock()
	for _, c := range engine.scheme.Clients {
		if c.Name == "NovaVPN" {
			count++
		}
	}
	engine.mu.RUnlock()
	if count != 1 {
		t.Errorf("confirmed client duplicated: %d occurrences", count)
	}
}

func TestDraftRegistry_DraftsList(t *testing.T) {
	reg := NewDraftRegistry(Default())
	_, _ = reg.DraftFromURLAndStore("https://github.com/x/AlphaVPN")
	_, _ = reg.DraftFromURLAndStore("https://github.com/y/BetaVPN")
	if got := len(reg.Drafts()); got != 2 {
		t.Errorf("drafts count = %d, want 2", got)
	}
}

func isServed(e *Engine, name string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, c := range e.scheme.Clients {
		if c.Name == name {
			return true
		}
	}
	return false
}
