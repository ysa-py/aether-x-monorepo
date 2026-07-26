// Package model defines the control-plane domain types: users, subscriptions,
// and nodes. Quota and expiry values here are SOURCE-OF-TRUTH; the user-facing
// panel must never trust client-reported values — they are delivered
// cryptographically signed (see package antiforgery, planned in phase 1).
package model

import (
	"encoding/json"
	"time"
)

// Role is the RBAC role embedded in a JWT.
type Role string

const (
	RoleAdmin    Role = "admin"
	RoleReseller Role = "reseller"
	RoleUser     Role = "user"
)

// User is an authenticated identity on the platform.
type User struct {
	ID         string
	Email      string
	Role       Role
	ResellerID *string // nil for direct/admin users
	CreatedAt  time.Time
}

// Subscription is a purchased plan bound to a user.
type Subscription struct {
	ID         string
	UserID     string
	PlanID     string
	BytesTotal int64     // quota, bytes
	BytesUsed  int64     // consumed, bytes (server-verified)
	ExpiresAt  time.Time // server-verified expiry
	Revoked    bool
	SubToken   string // opaque lookup key for GET /sub/{token}
	CreatedAt  time.Time
}

// Remaining returns (bytes remaining, seconds remaining).
func (s *Subscription) Remaining(now time.Time) (int64, int64) {
	remaining := s.BytesTotal - s.BytesUsed
	if remaining < 0 {
		remaining = 0
	}
	secs := int64(time.Until(s.ExpiresAt).Seconds())
	if secs < 0 {
		secs = 0
	}
	return remaining, secs
}

// Expired reports whether the subscription has passed its expiry or quota.
func (s *Subscription) Expired(now time.Time) bool {
	if s.Revoked {
		return true
	}
	_, secs := s.Remaining(now)
	if secs == 0 {
		return true
	}
	return s.BytesUsed >= s.BytesTotal
}

// Plan defines a subscription tier.
type Plan struct {
	ID              string
	DisplayName     map[string]string
	DeviceLimit     int
	PriorityRouting bool
	DedicatedNodes  []string
	SLAHours        *int
}

// Node is a deployed data-plane instance.
type Node struct {
	ID             string
	Region         string
	ASNOrg         string // e.g. "Mobile Communication Company of Iran"
	Capacity       int    // max concurrent users
	SupervisorAddr string // gRPC address of its Rust supervisor
	Healthy        bool
}

// TransportProfile describes a schema-driven proxy transport the admin can
// build configs from (Part 2 §5.2). Network + Security mirror the axes the
// real binaries (xray-core / sing-box) expose; ConfigSchema is the JSON Schema
// the admin form is generated from. Deprecated transports are marked, never
// deleted — they leave the default picker but stay selectable (never lose a
// capability).
type TransportProfile struct {
	ID           string          `json:"id"`
	DisplayName  string          `json:"display_name"`
	CoreKind     string          `json:"core_kind"` // "xray" | "sing-box"
	Network      string          `json:"network"`   // tcp|ws|httpupgrade|grpc|mkcp|splithttp (xray); ws|http|grpc|httpupgrade|quic (sing-box)
	Security     string          `json:"security"`  // none | tls | reality
	ConfigSchema json.RawMessage `json:"config_schema"`
	Deprecated   bool            `json:"deprecated"`
	Newest       bool            `json:"newest"`
}
