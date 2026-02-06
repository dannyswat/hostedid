package router

import (
	"net/http"
	"time"

	"github.com/hostedid/hostedid/internal/auth"
	"github.com/hostedid/hostedid/internal/handler"
	"github.com/hostedid/hostedid/internal/logger"
	"github.com/hostedid/hostedid/internal/middleware"
)

// New creates and configures the HTTP router
func New(h *handler.Handler, mw *middleware.Middleware, log *logger.Logger, tokenSvc *auth.TokenService) http.Handler {
	mux := http.NewServeMux()

	// Health check endpoints (no auth required)
	mux.HandleFunc("GET /health", h.Health)
	mux.HandleFunc("GET /ready", h.Ready)

	// API v1 routes
	mux.HandleFunc("GET /api/v1/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"message":"HostedID API v1","version":"0.1.0"}`))
	})

	// Public authentication routes (rate limited)
	loginRateLimit := mw.RateLimit(middleware.RateLimitConfig{
		Limit:  5,
		Window: 15 * time.Minute,
		KeyFn:  middleware.IPKey,
	})
	registerRateLimit := mw.RateLimit(middleware.RateLimitConfig{
		Limit:  3,
		Window: 1 * time.Hour,
		KeyFn:  middleware.IPKey,
	})
	refreshRateLimit := mw.RateLimit(middleware.RateLimitConfig{
		Limit:  10,
		Window: 1 * time.Minute,
		KeyFn:  middleware.IPKey,
	})

	mux.Handle("POST /api/v1/auth/register", registerRateLimit(http.HandlerFunc(h.Register)))
	mux.Handle("POST /api/v1/auth/login", loginRateLimit(http.HandlerFunc(h.Login)))
	mux.Handle("POST /api/v1/auth/token/refresh", refreshRateLimit(http.HandlerFunc(h.RefreshToken)))

	// Password reset routes (public, rate limited)
	passwordResetRateLimit := mw.RateLimit(middleware.RateLimitConfig{
		Limit:  3,
		Window: 1 * time.Hour,
		KeyFn:  middleware.IPKey,
	})
	mux.Handle("POST /api/v1/auth/password/reset-request", passwordResetRateLimit(http.HandlerFunc(h.PasswordResetRequest)))
	mux.Handle("POST /api/v1/auth/password/reset-complete", passwordResetRateLimit(http.HandlerFunc(h.PasswordResetComplete)))

	// Protected routes (require auth)
	authMw := mw.Auth(tokenSvc)

	// Auth routes requiring authentication
	mux.Handle("POST /api/v1/auth/logout", authMw(http.HandlerFunc(h.Logout)))
	mux.Handle("POST /api/v1/auth/logout/all", authMw(http.HandlerFunc(h.LogoutAll)))

	// Password change (authenticated, rate limited)
	mux.Handle("POST /api/v1/auth/password/change", authMw(http.HandlerFunc(h.ChangePassword)))

	// User routes requiring authentication
	mux.Handle("GET /api/v1/users/me", authMw(http.HandlerFunc(h.GetCurrentUser)))

	// Admin routes (require auth)
	// TODO: Add admin role check middleware when roles are implemented
	adminRateLimit := mw.RateLimit(middleware.RateLimitConfig{
		Limit:  10,
		Window: 1 * time.Minute,
		KeyFn:  middleware.IPKey,
	})
	mux.Handle("POST /api/v1/admin/users/{id}/unlock", authMw(adminRateLimit(http.HandlerFunc(h.AdminUnlockAccount))))
	mux.Handle("GET /api/v1/admin/keys", authMw(http.HandlerFunc(h.AdminListKeys)))
	mux.Handle("POST /api/v1/admin/keys/rotate", authMw(adminRateLimit(http.HandlerFunc(h.AdminRotateKey))))
	mux.Handle("GET /api/v1/admin/keys/{id}", authMw(http.HandlerFunc(h.AdminGetKeyInfo)))

	// TODO: Add MFA routes
	// MFA routes (authenticated - for setup and management)
	mfaRateLimit := mw.RateLimit(middleware.RateLimitConfig{
		Limit:  10,
		Window: 1 * time.Minute,
		KeyFn:  middleware.IPKey,
	})
	mux.Handle("GET /api/v1/mfa/methods", authMw(http.HandlerFunc(h.GetMFAMethods)))
	mux.Handle("POST /api/v1/mfa/totp/setup", authMw(mfaRateLimit(http.HandlerFunc(h.TOTPSetup))))
	mux.Handle("POST /api/v1/mfa/totp/verify", authMw(mfaRateLimit(http.HandlerFunc(h.TOTPVerify))))
	mux.Handle("POST /api/v1/mfa/webauthn/register/begin", authMw(http.HandlerFunc(h.WebAuthnRegisterBegin)))
	mux.Handle("POST /api/v1/mfa/webauthn/register/complete", authMw(http.HandlerFunc(h.WebAuthnRegisterComplete)))
	mux.Handle("POST /api/v1/mfa/backup-codes/generate", authMw(mfaRateLimit(http.HandlerFunc(h.BackupCodesGenerate))))
	mux.Handle("DELETE /api/v1/mfa/{method}", authMw(http.HandlerFunc(h.DeleteMFAMethod)))

	// MFA verification routes (public - used during login flow with MFA token)
	mfaVerifyRateLimit := mw.RateLimit(middleware.RateLimitConfig{
		Limit:  5,
		Window: 5 * time.Minute,
		KeyFn:  middleware.IPKey,
	})
	mux.Handle("POST /api/v1/mfa/verify", mfaVerifyRateLimit(http.HandlerFunc(h.MFAVerify)))
	mux.Handle("POST /api/v1/mfa/webauthn/authenticate/begin", mfaVerifyRateLimit(http.HandlerFunc(h.WebAuthnAuthenticateBegin)))
	mux.Handle("POST /api/v1/mfa/webauthn/authenticate/complete", mfaVerifyRateLimit(http.HandlerFunc(h.WebAuthnAuthenticateComplete)))

	// Device routes (authenticated)
	mux.Handle("GET /api/v1/devices", authMw(http.HandlerFunc(h.ListDevices)))
	mux.Handle("GET /api/v1/devices/current", authMw(http.HandlerFunc(h.GetCurrentDevice)))
	mux.Handle("GET /api/v1/devices/{id}", authMw(http.HandlerFunc(h.GetDevice)))
	mux.Handle("POST /api/v1/devices/trust", authMw(http.HandlerFunc(h.TrustDevice)))
	mux.Handle("POST /api/v1/devices/untrust", authMw(http.HandlerFunc(h.UntrustDevice)))
	mux.Handle("PATCH /api/v1/devices/{id}", authMw(http.HandlerFunc(h.UpdateDevice)))
	mux.Handle("DELETE /api/v1/devices/{id}", authMw(http.HandlerFunc(h.DeleteDevice)))
	mux.Handle("POST /api/v1/devices/{id}/logout", authMw(http.HandlerFunc(h.LogoutDevice)))

	// Backward-compatible device routes (used by frontend authService)
	mux.Handle("GET /api/v1/users/me/devices", authMw(http.HandlerFunc(h.ListDevices)))
	mux.Handle("DELETE /api/v1/users/me/devices/{id}", authMw(http.HandlerFunc(h.DeleteDevice)))
	mux.Handle("POST /api/v1/users/me/devices/revoke-all", authMw(http.HandlerFunc(h.RevokeAllOtherDevices)))

	// Session management routes (authenticated)
	mux.Handle("GET /api/v1/sessions", authMw(http.HandlerFunc(h.GetUserSessions)))
	mux.Handle("GET /api/v1/sessions/{id}", authMw(http.HandlerFunc(h.GetDeviceSession)))
	mux.Handle("POST /api/v1/sessions/{id}/revoke", authMw(http.HandlerFunc(h.RevokeDeviceSession)))
	mux.Handle("POST /api/v1/sessions/revoke-others", authMw(http.HandlerFunc(h.RevokeAllOtherSessions)))

	// Back-channel logout routes
	mux.Handle("POST /api/v1/auth/logout/backchannel", authMw(http.HandlerFunc(h.BackChannelLogout)))
	mux.Handle("POST /api/v1/auth/logout/validate-token", http.HandlerFunc(h.ValidateLogoutToken))

	// Apply middleware stack
	var handler http.Handler = mux

	// CORS (configure allowed origins based on environment)
	handler = mw.CORS([]string{"http://localhost:3000", "http://localhost:5173"})(handler)

	// Security headers
	handler = mw.SecurityHeaders(handler)

	// Request logging
	handler = mw.Logger(handler)

	// Timing
	handler = mw.Timing(handler)

	// Request ID
	handler = mw.RequestID(handler)

	// Panic recovery (outermost)
	handler = mw.Recover(handler)

	return handler
}
