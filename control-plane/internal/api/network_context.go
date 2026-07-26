package api

import (
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/aether-x/control-plane/internal/subendpoint"
	"github.com/aether-x/control-plane/internal/telemetry"
)

const (
	// HeaderISP is accepted only from a configured trusted proxy network.
	HeaderISP = "X-Aether-ISP"
	// HeaderRegion is an operator-defined region label supplied by a trusted edge.
	HeaderRegion = "X-Aether-Region"
	// HeaderCountry is a two-letter country code supplied by a trusted edge.
	HeaderCountry = "X-Aether-Country"
)

// ClientNetworkContextResolver produces an optional trusted network hint for
// subscription ordering. It must never trust arbitrary client-supplied headers.
type ClientNetworkContextResolver interface {
	Resolve(*http.Request) telemetry.ClientContext
}

// TrustedNetworkContextResolver accepts normalized ISP/region/country headers
// only when the TCP peer belongs to a configured operator-controlled proxy CIDR.
// User-Agent capability detection remains available for every client.
type TrustedNetworkContextResolver struct {
	trusted []*net.IPNet
}

// NewTrustedNetworkContextResolver parses operator-controlled ingress CIDRs.
func NewTrustedNetworkContextResolver(cidrs []string) (*TrustedNetworkContextResolver, error) {
	trusted := make([]*net.IPNet, 0, len(cidrs))
	for _, raw := range cidrs {
		value := strings.TrimSpace(raw)
		if value == "" {
			continue
		}
		_, network, err := net.ParseCIDR(value)
		if err != nil {
			return nil, fmt.Errorf("invalid trusted proxy CIDR %q: %w", value, err)
		}
		trusted = append(trusted, network)
	}
	if len(trusted) == 0 {
		return nil, fmt.Errorf("at least one trusted proxy CIDR is required")
	}
	return &TrustedNetworkContextResolver{trusted: trusted}, nil
}

// Resolve returns a capability context for every request, adding network
// attribution only for a trusted proxy peer with valid normalized headers.
func (r *TrustedNetworkContextResolver) Resolve(request *http.Request) telemetry.ClientContext {
	context := subendpoint.DetectClientContext(request.UserAgent(), request.RemoteAddr)
	if r == nil || !r.isTrustedPeer(request.RemoteAddr) {
		return context
	}
	if isp := normalizeISP(request.Header.Get(HeaderISP)); isp != "" {
		context.ISP = isp
	}
	if region := normalizeRegion(request.Header.Get(HeaderRegion)); region != "" {
		context.Region = region
	}
	if country := normalizeCountry(request.Header.Get(HeaderCountry)); country != "" {
		context.Country = country
	}
	return context
}

func (r *TrustedNetworkContextResolver) isTrustedPeer(remoteAddress string) bool {
	host, _, err := net.SplitHostPort(remoteAddress)
	if err != nil {
		return false
	}
	peer := net.ParseIP(host)
	if peer == nil {
		return false
	}
	for _, network := range r.trusted {
		if network.Contains(peer) {
			return true
		}
	}
	return false
}

func normalizeISP(value string) string {
	switch strings.TrimSpace(value) {
	case "MCI", "Irancell", "Rightel", "Shatel", "TCI", "Asiatech", "Resalat", "Other":
		return strings.TrimSpace(value)
	default:
		return ""
	}
}

func normalizeRegion(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" || len(value) > 63 {
		return ""
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z') && !(character >= '0' && character <= '9') && character != '-' {
			return ""
		}
	}
	return value
}

func normalizeCountry(value string) string {
	value = strings.ToUpper(strings.TrimSpace(value))
	if len(value) != 2 {
		return ""
	}
	for _, character := range value {
		if character < 'A' || character > 'Z' {
			return ""
		}
	}
	return value
}
