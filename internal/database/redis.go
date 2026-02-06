package database

import (
	"context"
	"fmt"
	"time"

	"github.com/hostedid/hostedid/internal/config"
	"github.com/redis/go-redis/v9"
)

// Redis wraps the Redis client
type Redis struct {
	*redis.Client
}

// NewRedis creates a new Redis connection
func NewRedis(cfg config.RedisConfig) (*Redis, error) {
	client := redis.NewClient(&redis.Options{
		Addr:         cfg.Addr(),
		Password:     cfg.Password,
		DB:           cfg.DB,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
		PoolSize:     100,
		MinIdleConns: 10,
	})

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to ping Redis: %w", err)
	}

	return &Redis{Client: client}, nil
}

// HealthCheck verifies the Redis connection is healthy
func (r *Redis) HealthCheck(ctx context.Context) error {
	return r.Ping(ctx).Err()
}

// SetWithTTL sets a key with an expiration time
func (r *Redis) SetWithTTL(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	return r.Set(ctx, key, value, ttl).Err()
}

// GetString retrieves a string value
func (r *Redis) GetString(ctx context.Context, key string) (string, error) {
	return r.Get(ctx, key).Result()
}

// Delete removes a key
func (r *Redis) Delete(ctx context.Context, keys ...string) error {
	return r.Del(ctx, keys...).Err()
}

// Exists checks if keys exist
func (r *Redis) Exists(ctx context.Context, keys ...string) (int64, error) {
	return r.Client.Exists(ctx, keys...).Result()
}

// Incr increments a key's value
func (r *Redis) Incr(ctx context.Context, key string) (int64, error) {
	return r.Client.Incr(ctx, key).Result()
}

// Expire sets a TTL on an existing key
func (r *Redis) Expire(ctx context.Context, key string, ttl time.Duration) error {
	return r.Client.Expire(ctx, key, ttl).Err()
}

// Publish publishes a message to a channel
func (r *Redis) Publish(ctx context.Context, channel string, message interface{}) error {
	return r.Client.Publish(ctx, channel, message).Err()
}

// Subscribe subscribes to channels
func (r *Redis) Subscribe(ctx context.Context, channels ...string) *redis.PubSub {
	return r.Client.Subscribe(ctx, channels...)
}
