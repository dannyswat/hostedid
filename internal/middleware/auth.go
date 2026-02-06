package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/hostedid/hostedid/internal/auth"
)

// Context keys for authenticated user data
const (
	UserIDKey   contextKey = "user_id"
	DeviceIDKey contextKey = "device_id"
	EmailKey    contextKey = "email"
)

// Auth creates an authentication middleware that validates JWT tokens
func (m *Middleware) Auth(tokenSvc *auth.TokenService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var tokenString string

			// 1. Try Authorization header first
			authHeader := r.Header.Get("Authorization")
			if authHeader != "" {
				parts := strings.SplitN(authHeader, " ", 2)
				if len(parts) == 2 && strings.EqualFold(parts[0], "bearer") {
					tokenString = parts[1]
				}
			}

			// 2. Fall back to cookie
			if tokenString == "" {
				if cookie, err := r.Cookie("hostedid_access_token"); err == nil && cookie.Value != "" {
					tokenString = cookie.Value
				}
			}

			if tokenString == "" {
				http.Error(w, `{"error":{"code":"unauthorized","message":"Authentication required"}}`, http.StatusUnauthorized)
				return
			}

			// Validate the token
			claims, err := tokenSvc.ValidateAccessToken(tokenString)
			if err != nil {
				m.log.Debug().Err(err).Msg("token validation failed")
				http.Error(w, `{"error":{"code":"token_expired","message":"The access token is invalid or expired"}}`, http.StatusUnauthorized)
				return
			}

			// Add user info to context
			ctx := r.Context()
			ctx = context.WithValue(ctx, UserIDKey, claims.Subject)
			ctx = context.WithValue(ctx, DeviceIDKey, claims.DeviceID)
			ctx = context.WithValue(ctx, EmailKey, claims.Email)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
