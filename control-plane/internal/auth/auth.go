// Package auth implements JWT issuance/validation and role-based access
// control. Tokens are HS256 (symmetric) for now; phase 1 will move to
// Ed25519 asymmetric signing to match the anti-forgery core.
package auth

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/aether-x/control-plane/internal/model"
)

const defaultKeyID = "default"

// Claims is the JWT payload.
type Claims struct {
	UID  string     `json:"uid"`
	Role model.Role `json:"role"`
	jwt.RegisteredClaims
}

// Issuer mints and validates access tokens. It keeps a bounded keyring so an
// operator can introduce a new signing key without invalidating every current
// control-plane session at once.
type Issuer struct {
	activeKeyID string
	keys        map[string][]byte
	ttl         time.Duration
}

// New constructs a single-key issuer. Existing callers retain the stable
// `default` key identifier while newly minted tokens include that `kid` header.
func New(secret []byte, ttl time.Duration) *Issuer {
	issuer, err := NewKeyring(defaultKeyID, secret, nil, ttl)
	if err != nil {
		// A nil/empty secret is surfaced later by Parse/Mint as an explicit
		// configuration error. This preserves the established constructor shape.
		return &Issuer{ttl: normalizedTTL(ttl)}
	}
	return issuer
}

// NewKeyring constructs an issuer with one active signing key and zero or more
// previous verification-only keys. Previous key IDs must be distinct and must
// not replace the active key.
func NewKeyring(
	activeKeyID string,
	activeSecret []byte,
	previous map[string][]byte,
	ttl time.Duration,
) (*Issuer, error) {
	activeKeyID = normalizeKeyID(activeKeyID)
	if activeKeyID == "" {
		return nil, errors.New("active JWT key ID is required")
	}
	if len(activeSecret) < 32 {
		return nil, errors.New("active JWT signing key must be at least 32 bytes")
	}
	keys := map[string][]byte{activeKeyID: cloneSecret(activeSecret)}
	for keyID, secret := range previous {
		keyID = normalizeKeyID(keyID)
		if keyID == "" || keyID == activeKeyID {
			return nil, errors.New("previous JWT key ID is invalid or duplicates the active key")
		}
		if len(secret) < 32 {
			return nil, fmt.Errorf("previous JWT key %q must be at least 32 bytes", keyID)
		}
		if _, exists := keys[keyID]; exists {
			return nil, fmt.Errorf("duplicate JWT key ID %q", keyID)
		}
		keys[keyID] = cloneSecret(secret)
	}
	return &Issuer{activeKeyID: activeKeyID, keys: keys, ttl: normalizedTTL(ttl)}, nil
}

// Mint issues a short-lived access token for u using the active key.
func (i *Issuer) Mint(u model.User) (string, error) {
	if i == nil || i.activeKeyID == "" || len(i.keys[i.activeKeyID]) == 0 {
		return "", errors.New("JWT issuer is not configured")
	}
	if !knownRole(u.Role) || u.ID == "" {
		return "", errors.New("JWT user identity or role is invalid")
	}
	now := time.Now()
	claims := Claims{
		UID:  u.ID,
		Role: u.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   u.ID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(i.ttl)),
			Issuer:    "aether-x",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token.Header["kid"] = i.activeKeyID
	return token.SignedString(i.keys[i.activeKeyID])
}

// Parse validates a token and returns its claims. `kid` tokens verify only
// against their named key. Legacy tokens without `kid` are tried against the
// active key then prior keys, allowing a controlled two-phase rotation from
// releases that predate key identifiers.
func (i *Issuer) Parse(tokenString string) (*Claims, error) {
	if i == nil || len(i.keys) == 0 {
		return nil, errors.New("JWT issuer is not configured")
	}
	keyIDs, err := i.candidateKeyIDs(tokenString)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, keyID := range keyIDs {
		claims, err := parseWithKey(tokenString, i.keys[keyID])
		if err == nil {
			return claims, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("JWT verification key is unavailable")
	}
	return nil, lastErr
}

func (i *Issuer) candidateKeyIDs(tokenString string) ([]string, error) {
	unverifiedClaims := &Claims{}
	parser := jwt.NewParser(jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
	token, _, err := parser.ParseUnverified(tokenString, unverifiedClaims)
	if err != nil {
		return nil, err
	}
	keyID, _ := token.Header["kid"].(string)
	keyID = normalizeKeyID(keyID)
	if keyID != "" {
		if _, exists := i.keys[keyID]; !exists {
			return nil, errors.New("JWT key ID is unknown")
		}
		return []string{keyID}, nil
	}

	keyIDs := make([]string, 0, len(i.keys))
	keyIDs = append(keyIDs, i.activeKeyID)
	for candidate := range i.keys {
		if candidate != i.activeKeyID {
			keyIDs = append(keyIDs, candidate)
		}
	}
	if len(keyIDs) > 1 {
		sort.Strings(keyIDs[1:])
	}
	return keyIDs, nil
}

func parseWithKey(tokenString string, key []byte) (*Claims, error) {
	if len(key) == 0 {
		return nil, errors.New("JWT verification key is empty")
	}
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(
		tokenString,
		claims,
		func(token *jwt.Token) (any, error) {
			if token.Method.Alg() != jwt.SigningMethodHS256.Alg() {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return key, nil
		},
		jwt.WithIssuer("aether-x"),
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
	)
	if err != nil {
		return nil, err
	}
	if !token.Valid || claims.UID == "" || claims.Subject != claims.UID {
		return nil, errors.New("JWT claims are invalid")
	}
	if !knownRole(claims.Role) {
		return nil, errors.New("JWT role is invalid")
	}
	return claims, nil
}

func normalizedTTL(ttl time.Duration) time.Duration {
	if ttl <= 0 {
		return 15 * time.Minute
	}
	return ttl
}

func normalizeKeyID(value string) string {
	if len(value) == 0 || len(value) > 64 {
		return ""
	}
	for _, character := range value {
		isLower := character >= 'a' && character <= 'z'
		isUpper := character >= 'A' && character <= 'Z'
		isDigit := character >= '0' && character <= '9'
		if !isLower && !isUpper && !isDigit && character != '-' && character != '_' {
			return ""
		}
	}
	return value
}

func cloneSecret(secret []byte) []byte {
	return append([]byte(nil), secret...)
}

// ErrForbidden indicates an RBAC denial.
var ErrForbidden = errors.New("forbidden")

// Authorize returns nil if claims.Role is at-or-above min.
func Authorize(claims *Claims, min model.Role) error {
	if claims == nil || !knownRole(min) {
		return ErrForbidden
	}
	level := map[model.Role]int{
		model.RoleUser:     0,
		model.RoleReseller: 1,
		model.RoleAdmin:    2,
	}
	actual, known := level[claims.Role]
	if !known || actual < level[min] {
		return ErrForbidden
	}
	return nil
}

func knownRole(role model.Role) bool {
	switch role {
	case model.RoleUser, model.RoleReseller, model.RoleAdmin:
		return true
	default:
		return false
	}
}
