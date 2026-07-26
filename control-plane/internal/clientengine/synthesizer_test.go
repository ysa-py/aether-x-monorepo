package clientengine

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSynthesizeFromKnownUA(t *testing.T) {
	e := Default()
	d := NewClientDiscovery(e, "")

	req := httptest.NewRequest(http.MethodGet, "/sub/abc", nil)
	req.Header.Set("User-Agent", "v2rayNG/1.8.0")
	discovered := d.InspectRequest(req)
	if discovered {
		t.Fatal("v2rayNG should be known, not discovered")
	}
}

func TestSynthesizeFromUnknownUA(t *testing.T) {
	e := Default()
	d := NewClientDiscovery(e, "")

	req := httptest.NewRequest(http.MethodGet, "/sub/abc", nil)
	req.Header.Set("User-Agent", "FutureVPN/2.0 (Android 14)")
	discovered := d.InspectRequest(req)
	if !discovered {
		t.Fatal("FutureVPN should be discovered")
	}
	if d.DiscoveryCount() != 1 {
		t.Fatalf("count = %d, want 1", d.DiscoveryCount())
	}
}

func TestSynthesizeSkipsBrowsers(t *testing.T) {
	e := Default()
	d := NewClientDiscovery(e, "")

	req := httptest.NewRequest(http.MethodGet, "/sub/abc", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
	discovered := d.InspectRequest(req)
	if discovered {
		t.Fatal("Mozilla should be skipped")
	}
}

func TestSynthesizeSkipsEmpty(t *testing.T) {
	e := Default()
	d := NewClientDiscovery(e, "")

	req := httptest.NewRequest(http.MethodGet, "/sub/abc", nil)
	// No User-Agent header
	discovered := d.InspectRequest(req)
	if discovered {
		t.Fatal("empty UA should be skipped")
	}
}

func TestSynthesizePreventsDuplicates(t *testing.T) {
	e := Default()
	d := NewClientDiscovery(e, "")

	req1 := httptest.NewRequest(http.MethodGet, "/sub/abc", nil)
	req1.Header.Set("User-Agent", "NovaProxy/1.0 (iOS)")
	req2 := httptest.NewRequest(http.MethodGet, "/sub/abc", nil)
	req2.Header.Set("User-Agent", "NovaProxy/1.0 (iOS)")

	if !d.InspectRequest(req1) {
		t.Fatal("first should discover")
	}
	if d.InspectRequest(req2) {
		t.Fatal("second should NOT re-discover")
	}
}

func TestValidateSchemeRejectsInjection(t *testing.T) {
	bad := &DiscoveredClient{
		ClientScheme: ClientScheme{
			Name: "Test",
			URI:  "javascript:alert({{evil}})",
		},
	}
	if err := ValidateScheme(bad); err == nil {
		t.Fatal("should reject javascript: scheme")
	}

	bad2 := &DiscoveredClient{
		ClientScheme: ClientScheme{
			Name: "Test",
			URI:  "test://{{UNKNOWN_VAR}}",
		},
	}
	if err := ValidateScheme(bad2); err == nil {
		t.Fatal("should reject unknown template var")
	}
}

func TestValidateSchemeAcceptsValid(t *testing.T) {
	good := &DiscoveredClient{
		ClientScheme: ClientScheme{
			Name: "ValidClient",
			URI:  "valid://import?url={{SUB_URL_ENCODED}}&name={{REMARK}}",
		},
	}
	if err := ValidateScheme(good); err != nil {
		t.Fatalf("should accept valid: %v", err)
	}

	emptyURI := &DiscoveredClient{
		ClientScheme: ClientScheme{Name: "NoScheme", URI: ""},
	}
	if err := ValidateScheme(emptyURI); err != nil {
		t.Fatalf("empty URI should be valid (QR fallback): %v", err)
	}
}

func TestPlatformDetection(t *testing.T) {
	tests := map[string]string{
		"App/1.0 (Android)": "android",
		"App/1.0 (iPhone)":  "ios",
		"App/1.0 (Windows)": "windows",
		"App/1.0 (Mac)":     "macos",
		"App/1.0 (Linux)":   "linux",
		"App/1.0":           "all",
	}
	for ua, want := range tests {
		if got := detectPlatformFromUA(ua); got != want {
			t.Errorf("platform(%s) = %s, want %s", ua, got, want)
		}
	}
}

func TestExtractAppName(t *testing.T) {
	if got := extractAppName("NovaProxy/1.0"); got != "NovaProxy" {
		t.Fatalf("got %s", got)
	}
	if got := extractAppName("Mozilla/5.0"); got != "" {
		t.Fatalf("Mozilla should be filtered, got %s", got)
	}
}
