package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTrustedNetworkContextAcceptsOnlyTrustedIngress(t *testing.T) {
	resolver, err := NewTrustedNetworkContextResolver([]string{"127.0.0.0/8"})
	if err != nil {
		t.Fatalf("new resolver: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/sub/token", nil)
	req.RemoteAddr = "127.0.0.1:443"
	req.Header.Set("User-Agent", "sing-box/1.11")
	req.Header.Set(HeaderISP, "MCI")
	req.Header.Set(HeaderRegion, "Tehran-1")
	req.Header.Set(HeaderCountry, "ir")

	context := resolver.Resolve(req)
	if context.ISP != "MCI" || context.Region != "tehran-1" || context.Country != "IR" {
		t.Fatalf("trusted network context was not normalized: %+v", context)
	}
	if context.Core != "sing-box" {
		t.Fatalf("client capability detection lost: %+v", context)
	}
}

func TestTrustedNetworkContextRejectsSpoofedHeadersFromClient(t *testing.T) {
	resolver, err := NewTrustedNetworkContextResolver([]string{"127.0.0.0/8"})
	if err != nil {
		t.Fatalf("new resolver: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/sub/token", nil)
	req.RemoteAddr = "198.51.100.7:444"
	req.Header.Set("User-Agent", "sing-box/1.11")
	req.Header.Set(HeaderISP, "MCI")
	req.Header.Set(HeaderRegion, "tehran")
	req.Header.Set(HeaderCountry, "IR")

	context := resolver.Resolve(req)
	if context.ISP != "" || context.Region != "" || context.Country != "" {
		t.Fatalf("untrusted client headers must not affect routing context: %+v", context)
	}
}

func TestTrustedNetworkContextDropsInvalidTrustedHeaders(t *testing.T) {
	resolver, err := NewTrustedNetworkContextResolver([]string{"127.0.0.0/8"})
	if err != nil {
		t.Fatalf("new resolver: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/sub/token", nil)
	req.RemoteAddr = "127.0.0.1:443"
	req.Header.Set(HeaderISP, "fabricated-carrier")
	req.Header.Set(HeaderRegion, "tehran;drop")
	req.Header.Set(HeaderCountry, "Iran")

	context := resolver.Resolve(req)
	if context.ISP != "" || context.Region != "" || context.Country != "" {
		t.Fatalf("invalid trusted headers must be ignored: %+v", context)
	}
}

func TestTrustedNetworkContextRejectsInvalidCIDR(t *testing.T) {
	if _, err := NewTrustedNetworkContextResolver([]string{"not-a-cidr"}); err == nil {
		t.Fatal("invalid trusted proxy CIDR must be rejected")
	}
}
