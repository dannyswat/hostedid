package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// RateLimitConfig holds configuration for a specific rate limit
type RateLimitConfig struct {
	Limit  int
	Window time.Duration
	KeyFn  func(*http.Request) string
}

// RateLimit creates a rate limiting middleware
func (m *Middleware) RateLimit(cfg RateLimitConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !m.cfg.Security.RateLimiting.Enabled {
				next.ServeHTTP(w, r)
				return
			}

			ctx := r.Context()
			key := fmt.Sprintf("ratelimit:%s", cfg.KeyFn(r))

			// Get current count
			count, err := m.rdb.Incr(ctx, key)
			if err != nil {
				m.log.Error().Err(err).Msg("failed to increment rate limit counter")
				next.ServeHTTP(w, r)
				return
			}

			// Set expiry on first request
			if count == 1 {
				m.rdb.Expire(ctx, key, cfg.Window)
			}

			// Get TTL for reset header
			ttl, _ := m.rdb.Client.TTL(ctx, key).Result()
			resetTime := time.Now().Add(ttl).Unix()

			// Set rate limit headers
			w.Header().Set("X-RateLimit-Limit", strconv.Itoa(cfg.Limit))
			w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(max(0, cfg.Limit-int(count))))
			w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(resetTime, 10))

			// Check if limit exceeded
			if int(count) > cfg.Limit {
				w.Header().Set("Retry-After", strconv.FormatInt(int64(ttl.Seconds()), 10))
				http.Error(w, `{"error":"rate_limit_exceeded","message":"Too many requests. Please try again later."}`, http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// IPKey returns the client IP address as the rate limit key
func IPKey(r *http.Request) string {
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		return forwarded
	}
	return r.RemoteAddr
}

// UserKey returns the user ID from context as the rate limit key
func UserKey(ctx context.Context) string {
	if userID, ok := ctx.Value("user_id").(string); ok {
		return userID
	}
	return "anonymous"
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
