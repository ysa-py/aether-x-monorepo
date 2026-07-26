package auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/aether-x/control-plane/internal/model"
)

func TestParsePinsHS256AndValidatesClaims(t *testing.T) {
	issuer := New([]byte("01234567890123456789012345678901"), time.Hour)
	valid, err := issuer.Mint(model.User{ID: "user-1", Role: model.RoleUser})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	claims, err := issuer.Parse(valid)
	if err != nil || claims.UID != "user-1" {
		t.Fatalf("valid token parse failed: claims=%+v err=%v", claims, err)
	}

	wrongAlgorithm := jwt.NewWithClaims(jwt.SigningMethodHS384, Claims{
		UID:  "user-1",
		Role: model.RoleUser,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user-1",
			Issuer:    "aether-x",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	})
	wrongAlgorithmString, err := wrongAlgorithm.SignedString([]byte("01234567890123456789012345678901"))
	if err != nil {
		t.Fatalf("sign HS384 fixture: %v", err)
	}
	if _, err := issuer.Parse(wrongAlgorithmString); err == nil {
		t.Fatal("HS384 token must be rejected")
	}
}

func TestKeyringRotationAcceptsPreviousAndMintsActiveKid(t *testing.T) {
	legacySecret := []byte("11111111111111111111111111111111")
	legacyIssuer := New(legacySecret, time.Hour)
	legacyToken, err := legacyIssuer.Mint(model.User{ID: "user-1", Role: model.RoleUser})
	if err != nil {
		t.Fatalf("mint legacy token: %v", err)
	}

	rotated, err := NewKeyring(
		"2026-07",
		[]byte("22222222222222222222222222222222"),
		map[string][]byte{defaultKeyID: legacySecret},
		time.Hour,
	)
	if err != nil {
		t.Fatalf("new rotating keyring: %v", err)
	}
	if _, err := rotated.Parse(legacyToken); err != nil {
		t.Fatalf("legacy token should remain valid during rotation: %v", err)
	}

	activeToken, err := rotated.Mint(model.User{ID: "user-2", Role: model.RoleAdmin})
	if err != nil {
		t.Fatalf("mint active token: %v", err)
	}
	if _, err := rotated.Parse(activeToken); err != nil {
		t.Fatalf("active token parse failed: %v", err)
	}
	if _, err := legacyIssuer.Parse(activeToken); err == nil {
		t.Fatal("previous issuer must not validate the new active key token")
	}
}

func TestAuthorizeRejectsUnknownRole(t *testing.T) {
	claims := &Claims{Role: model.Role("unknown")}
	if err := Authorize(claims, model.RoleUser); err != ErrForbidden {
		t.Fatalf("unknown role authorize error = %v, want ErrForbidden", err)
	}
}
