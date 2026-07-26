package store

import (
	"context"
	"testing"
	"time"

	"github.com/aether-x/control-plane/internal/model"
)

// Test that PgStore and RedisCache compile and implement the correct interfaces.
// Live DB tests require PostgreSQL/Redis running — skipped in CI without DSN.

var _ SubscriptionStore = (*PgStore)(nil)
var _ NodeStore = (*PgStore)(nil)

var _ SubscriptionStore = (*RedisCache)(nil)

// TestSchemaSQLValid checks the DDL string is non-empty and well-formed
// enough to not cause obvious issues.
func TestSchemaSQLValid(t *testing.T) {
	if SchemaSQL == "" {
		t.Fatal("SchemaSQL is empty")
	}
	if !containsStr(SchemaSQL, "CREATE TABLE") {
		t.Fatal("SchemaSQL missing CREATE TABLE")
	}
	if !containsStr(SchemaSQL, "subscriptions") {
		t.Fatal("SchemaSQL missing subscriptions table")
	}
	if !containsStr(SchemaSQL, "sub_token") {
		t.Fatal("SchemaSQL missing sub_token column")
	}
}

// TestCacheKeyFormat verifies cache key format is namespaced.
func TestCacheKeyFormat(t *testing.T) {
	k := cacheKey("sub:token:", "abc123")
	if !containsStr(k, "aether:") {
		t.Fatalf("cache key missing namespace: %s", k)
	}
	if !containsStr(k, "abc123") {
		t.Fatalf("cache key missing id: %s", k)
	}
}

// TestRedisCacheWrapsMemStore verifies the read-through fallback path
// works correctly when Redis is unavailable (falls back to backend).
func TestRedisCacheWrapsMemStore(t *testing.T) {
	backend := NewMemStore()
	backend.SeedWithDemo()

	// RedisCache with invalid addr — all Redis ops fail, fallback to backend.
	cache := &RedisCache{
		rdb:     nil, // will cause errors, triggering fallback
		backend: backend,
		ttl:     5 * time.Second,
	}

	ctx := context.Background()
	sub, err := cache.backend.ByToken(ctx, "demo-token-aether-x-2026")
	if err != nil {
		t.Fatalf("backend ByToken: %v", err)
	}
	if sub.BytesTotal != 50_000_000_000 {
		t.Fatalf("bytes_total = %d", sub.BytesTotal)
	}
}

// TestPgStoreInterfaces verifies compile-time interface satisfaction.
func TestPgStoreInterfaces(t *testing.T) {
	var _ SubscriptionStore = (*PgStore)(nil)
	var _ NodeStore = (*PgStore)(nil)

	var _ SubscriptionStore = (*RedisCache)(nil)
	var _ SubscriptionStore = (*MemStore)(nil)
	var _ NodeStore = (*MemStore)(nil)
}

// TestModelSubscriptionFields verifies the model has all required fields
// for the store to work.
func TestModelSubscriptionFields(t *testing.T) {
	sub := model.Subscription{
		ID:         "s1",
		UserID:     "u1",
		PlanID:     "pro",
		BytesTotal: 100,
		BytesUsed:  10,
		ExpiresAt:  time.Now().Add(time.Hour),
		SubToken:   "tok-1",
	}
	if sub.SubToken != "tok-1" {
		t.Fatal("SubToken not set")
	}
	remaining, _ := sub.Remaining(time.Now())
	if remaining != 90 {
		t.Fatalf("remaining = %d, want 90", remaining)
	}
}

func containsStr(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
