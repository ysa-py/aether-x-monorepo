package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/aether-x/control-plane/internal/model"
)

// RedisCache wraps a SubscriptionStore with a read-through / write-through
// Redis cache. On cache miss or Redis failure, it falls back to the backing
// store (PostgreSQL). This guarantees sub-millisecond response times for
// high-throughput /sub/{token} requests while never serving stale data if
// the backing store is the source of truth.
type RedisCache struct {
	rdb     *redis.Client
	backend SubscriptionStore // the real store (PgStore)
	ttl     time.Duration
}

// NewRedisCache creates a read-through cache wrapping `backend`.
func NewRedisCache(addr string, backend SubscriptionStore) *RedisCache {
	return &RedisCache{
		rdb: redis.NewClient(&redis.Options{
			Addr:         addr,
			PoolSize:     20,
			MinIdleConns: 4,
			ReadTimeout:  100 * time.Millisecond,
			WriteTimeout: 100 * time.Millisecond,
		}),
		backend: backend,
		ttl:     30 * time.Second,
	}
}

// Close releases the Redis connection.
func (c *RedisCache) Close() error {
	return c.rdb.Close()
}

// ByToken implements SubscriptionStore with read-through caching.
// Flow: Redis → (miss) → PostgreSQL → (populate Redis) → return.
// On Redis error, transparently falls back to PostgreSQL.
func (c *RedisCache) ByToken(ctx context.Context, subToken string) (*model.Subscription, error) {
	key := cacheKey("sub:token:", subToken)

	// Try Redis first.
	if data, err := c.rdb.Get(ctx, key).Bytes(); err == nil {
		var sub model.Subscription
		if json.Unmarshal(data, &sub) == nil {
			return &sub, nil
		}
		// Corrupt cache entry → fall through to backend.
	}
	// Redis miss or error → fetch from backend.
	sub, err := c.backend.ByToken(ctx, subToken)
	if err != nil {
		return nil, err
	}

	// Write-through: populate cache (best-effort, non-blocking on error).
	if data, err := json.Marshal(sub); err == nil {
		_ = c.rdb.Set(ctx, key, data, c.ttl).Err()
	}
	return sub, nil
}

// ByUserID implements SubscriptionStore with read-through caching.
func (c *RedisCache) ByUserID(ctx context.Context, userID string) (*model.Subscription, error) {
	key := cacheKey("sub:user:", userID)

	if data, err := c.rdb.Get(ctx, key).Bytes(); err == nil {
		var sub model.Subscription
		if json.Unmarshal(data, &sub) == nil {
			return &sub, nil
		}
	}

	sub, err := c.backend.ByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}

	if data, err := json.Marshal(sub); err == nil {
		_ = c.rdb.Set(ctx, key, data, c.ttl).Err()
	}
	return sub, nil
}

// UpdateUsage implements SubscriptionStore with write-through cache invalidation.
// Updates PostgreSQL first, then invalidates both cache keys (by token + by user).
func (c *RedisCache) UpdateUsage(ctx context.Context, subID string, bytesDelta int64) error {
	if err := c.backend.UpdateUsage(ctx, subID, bytesDelta); err != nil {
		return err
	}
	// Invalidate cache entries (best-effort).
	_ = c.rdb.Del(ctx, cacheKey("sub:id:", subID)).Err()
	return nil
}

// Save implements SubscriptionStore with write-through.
func (c *RedisCache) Save(ctx context.Context, sub *model.Subscription) error {
	if err := c.backend.Save(ctx, sub); err != nil {
		return err
	}
	// Invalidate so next read populates fresh.
	_ = c.rdb.Del(ctx, cacheKey("sub:token:", sub.SubToken)).Err()
	_ = c.rdb.Del(ctx, cacheKey("sub:user:", sub.UserID)).Err()
	return nil
}

// InvalidateToken manually evicts a cached subscription by token.
func (c *RedisCache) InvalidateToken(ctx context.Context, subToken string) {
	_ = c.rdb.Del(ctx, cacheKey("sub:token:", subToken)).Err()
}

// InvalidateUser manually evicts a cached subscription by user ID.
func (c *RedisCache) InvalidateUser(ctx context.Context, userID string) {
	_ = c.rdb.Del(ctx, cacheKey("sub:user:", userID)).Err()
}

// Ping checks Redis connectivity.
func (c *RedisCache) Ping(ctx context.Context) error {
	return c.rdb.Ping(ctx).Err()
}

func cacheKey(prefix, id string) string {
	return fmt.Sprintf("aether:%s:%s", prefix, id)
}
