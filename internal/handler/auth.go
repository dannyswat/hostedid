package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/hostedid/hostedid/internal/middleware"
	"github.com/hostedid/hostedid/internal/service"
)

// JSON helper functions

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]interface{}{
		"error": map[string]interface{}{
			"code":    code,
			"message": message,
		},
	})
}

func writeErrorWithDetails(w http.ResponseWriter, r *http.Request, status int, code, message string, details map[string]interface{}) {
	resp := map[string]interface{}{
		"error": map[string]interface{}{
			"code":    code,
			"message": message,
		},
	}
	if details != nil {
		resp["error"].(map[string]interface{})["details"] = details
	}
	if reqID := r.Header.Get("X-Request-ID"); reqID != "" {
		resp["error"].(map[string]interface{})["request_id"] = reqID
	}
	writeJSON(w, status, resp)
}

func readJSON(r *http.Request, v interface{}) error {
	if r.Body == nil {
		return errors.New("request body is empty")
	}
	defer r.Body.Close()

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	return decoder.Decode(v)
}

// getClientIP extracts the client IP address from the request
func getClientIP(r *http.Request) string {
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		return forwarded
	}
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		return realIP
	}
	return r.RemoteAddr
}

// --- Cookie helpers ---

// setTokenCookies sets access token, ID token, and refresh token as HTTP cookies.
// Access + ID tokens are shared across all subdomains; refresh token is host-only.
func (h *Handler) setTokenCookies(w http.ResponseWriter, accessToken, idToken, refreshToken string, accessTTL, refreshTTL time.Duration) {
	sameSite := http.SameSiteLaxMode
	switch strings.ToLower(h.cfg.Cookie.SameSite) {
	case "strict":
		sameSite = http.SameSiteStrictMode
	case "none":
		sameSite = http.SameSiteNoneMode
	}

	// Subdomain-shared domain (e.g. ".example.com")
	sharedDomain := h.cfg.Cookie.Domain
	if sharedDomain != "" && !strings.HasPrefix(sharedDomain, ".") {
		sharedDomain = "." + sharedDomain
	}

	// Access token cookie — shared across subdomains
	http.SetCookie(w, &http.Cookie{
		Name:     "hostedid_access_token",
		Value:    accessToken,
		Path:     "/",
		Domain:   sharedDomain,
		MaxAge:   int(accessTTL.Seconds()),
		HttpOnly: true,
		Secure:   h.cfg.Cookie.Secure,
		SameSite: sameSite,
	})

	// ID token cookie — shared across subdomains
	if idToken != "" {
		http.SetCookie(w, &http.Cookie{
			Name:     "hostedid_id_token",
			Value:    idToken,
			Path:     "/",
			Domain:   sharedDomain,
			MaxAge:   int(accessTTL.Seconds()),
			HttpOnly: false, // ID token may be read by client JS
			Secure:   h.cfg.Cookie.Secure,
			SameSite: sameSite,
		})
	}

	// Refresh token cookie — locked to current host (no Domain attribute)
	http.SetCookie(w, &http.Cookie{
		Name:     "hostedid_refresh_token",
		Value:    refreshToken,
		Path:     "/api/v1/auth/token",
		Domain:   "",
		MaxAge:   int(refreshTTL.Seconds()),
		HttpOnly: true,
		Secure:   h.cfg.Cookie.Secure,
		SameSite: sameSite,
	})
}

// clearTokenCookies removes all auth cookies
func (h *Handler) clearTokenCookies(w http.ResponseWriter) {
	sharedDomain := h.cfg.Cookie.Domain
	if sharedDomain != "" && !strings.HasPrefix(sharedDomain, ".") {
		sharedDomain = "." + sharedDomain
	}

	for _, name := range []string{"hostedid_access_token", "hostedid_id_token"} {
		http.SetCookie(w, &http.Cookie{
			Name:     name,
			Value:    "",
			Path:     "/",
			Domain:   sharedDomain,
			MaxAge:   -1,
			HttpOnly: true,
			Secure:   h.cfg.Cookie.Secure,
			SameSite: http.SameSiteLaxMode,
		})
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "hostedid_refresh_token",
		Value:    "",
		Path:     "/api/v1/auth/token",
		Domain:   "",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   h.cfg.Cookie.Secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// isAllowedReturnURL validates that a return URL is safe to redirect to.
// It must be an absolute HTTP(S) URL whose host matches the cookie domain
// or is in the allowed return URL list.
func (h *Handler) isAllowedReturnURL(rawURL string) bool {
	if rawURL == "" {
		return false
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}

	// Must be http or https
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return false
	}

	// Check against configured domain (any subdomain)
	cookieDomain := h.cfg.Cookie.Domain
	if cookieDomain != "" {
		host := parsed.Hostname()
		if host == cookieDomain || strings.HasSuffix(host, "."+cookieDomain) {
			return true
		}
	}

	// Check against allowed return URL prefixes
	for _, allowed := range h.cfg.Cookie.AllowedReturnURLs {
		if strings.HasPrefix(rawURL, allowed) {
			return true
		}
	}

	return false
}

// --- Registration Handler ---

type registerRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Profile  *struct {
		DisplayName string `json:"displayName,omitempty"`
		Locale      string `json:"locale,omitempty"`
		Timezone    string `json:"timezone,omitempty"`
	} `json:"profile,omitempty"`
}

// Register handles user registration
func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "validation_error", "Invalid request body")
		return
	}

	if req.Email == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "validation_error", "Email and password are required")
		return
	}

	svcReq := service.RegisterRequest{
		Email:    req.Email,
		Password: req.Password,
	}
	if req.Profile != nil {
		svcReq.DisplayName = req.Profile.DisplayName
		svcReq.Locale = req.Profile.Locale
		svcReq.Timezone = req.Profile.Timezone
	}

	resp, err := h.authSvc.Register(r.Context(), svcReq)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrEmailAlreadyExists):
			writeError(w, http.StatusConflict, "email_exists", "An account with this email already exists")
		case errors.Is(err, service.ErrPasswordTooWeak):
			writeError(w, http.StatusBadRequest, "password_too_weak", err.Error())
		default:
			h.log.Error().Err(err).Msg("registration failed")
			writeError(w, http.StatusInternalServerError, "internal_error", "Registration failed")
		}
		return
	}

	writeJSON(w, http.StatusCreated, resp)
}

// --- Login Handler ---

type loginRequest struct {
	Email             string `json:"email"`
	Password          string `json:"password"`
	DeviceFingerprint string `json:"deviceFingerprint,omitempty"`
	RememberDevice    bool   `json:"rememberDevice,omitempty"`
	ReturnURL         string `json:"returnUrl,omitempty"`
}

// Login handles user authentication
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "validation_error", "Invalid request body")
		return
	}

	if req.Email == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "validation_error", "Email and password are required")
		return
	}

	// Validate return_url if provided
	returnURL := req.ReturnURL
	if returnURL != "" && !h.isAllowedReturnURL(returnURL) {
		returnURL = "" // silently discard invalid return URLs
	}

	svcReq := service.LoginRequest{
		Email:             req.Email,
		Password:          req.Password,
		DeviceFingerprint: req.DeviceFingerprint,
		UserAgent:         r.UserAgent(),
		IPAddress:         getClientIP(r),
	}

	resp, err := h.authSvc.Login(r.Context(), svcReq)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrMFARequired):
			// MFA is required - populate the challenge with available methods
			if resp != nil && resp.MFAChallenge != nil {
				mfaToken := h.mfaSvc.CreateMFAToken(resp.MFAChallenge.Status) // Will be overridden below
				// Get the actual user ID from a fresh lookup
				user, uErr := h.authSvc.GetUserByEmail(r.Context(), req.Email)
				if uErr == nil {
					mfaToken = h.mfaSvc.CreateMFAToken(user.ID)
					available, preferred, _ := h.mfaSvc.GetAvailableMethods(r.Context(), user.ID)
					mfaResp := map[string]interface{}{
						"status":           "mfa_required",
						"mfaToken":         mfaToken,
						"availableMethods": available,
						"preferredMethod":  preferred,
					}
					if returnURL != "" {
						mfaResp["returnUrl"] = returnURL
					}
					writeJSON(w, http.StatusOK, mfaResp)
					return
				}
			}
			writeError(w, http.StatusForbidden, "mfa_required", "Multi-factor authentication is required.")
		case errors.Is(err, service.ErrInvalidCredentials):
			writeError(w, http.StatusUnauthorized, "invalid_credentials", "The email or password is incorrect.")
		case errors.Is(err, service.ErrAccountLocked):
			writeError(w, http.StatusForbidden, "account_locked", "Your account has been temporarily locked due to too many failed login attempts.")
		case errors.Is(err, service.ErrAccountNotActive):
			writeError(w, http.StatusForbidden, "account_inactive", "Your account is not active.")
		default:
			h.log.Error().Err(err).Msg("login failed")
			writeError(w, http.StatusInternalServerError, "internal_error", "Login failed")
		}
		return
	}

	// Set tokens as cookies
	h.setTokenCookies(w,
		resp.Success.AccessToken,
		resp.Success.IDToken,
		resp.Success.RefreshToken,
		h.cfg.Security.Tokens.AccessTokenTTL,
		h.cfg.Security.Tokens.RefreshTokenTTL,
	)

	// Build response (still include tokens in body for API clients)
	loginResp := map[string]interface{}{
		"accessToken":  resp.Success.AccessToken,
		"refreshToken": resp.Success.RefreshToken,
		"idToken":      resp.Success.IDToken,
		"tokenType":    resp.Success.TokenType,
		"expiresIn":    resp.Success.ExpiresIn,
		"deviceId":     resp.Success.DeviceID,
	}
	if returnURL != "" {
		loginResp["returnUrl"] = returnURL
	}

	writeJSON(w, http.StatusOK, loginResp)
}

// --- Logout Handler ---

// Logout handles user logout (current session)
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	userID, _ := r.Context().Value(middleware.UserIDKey).(string)
	deviceID, _ := r.Context().Value(middleware.DeviceIDKey).(string)

	if userID == "" {
		writeError(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
		return
	}

	if err := h.authSvc.Logout(r.Context(), userID, deviceID, getClientIP(r), r.UserAgent()); err != nil {
		h.log.Error().Err(err).Msg("logout failed")
		writeError(w, http.StatusInternalServerError, "internal_error", "Logout failed")
		return
	}

	h.clearTokenCookies(w)
	writeJSON(w, http.StatusOK, map[string]string{"message": "logged out successfully"})
}

// LogoutAll handles logging out all sessions
func (h *Handler) LogoutAll(w http.ResponseWriter, r *http.Request) {
	userID, _ := r.Context().Value(middleware.UserIDKey).(string)

	if userID == "" {
		writeError(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
		return
	}

	if err := h.authSvc.LogoutAll(r.Context(), userID, getClientIP(r), r.UserAgent()); err != nil {
		h.log.Error().Err(err).Msg("logout all failed")
		writeError(w, http.StatusInternalServerError, "internal_error", "Logout failed")
		return
	}

	h.clearTokenCookies(w)
	writeJSON(w, http.StatusOK, map[string]string{"message": "all sessions logged out successfully"})
}

// --- Token Refresh Handler ---

type refreshTokenRequest struct {
	RefreshToken string `json:"refreshToken"`
}

// RefreshToken handles token refresh
func (h *Handler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	var req refreshTokenRequest
	_ = readJSON(r, &req) // body may be empty when using cookie-based refresh

	// Fall back to cookie if no refresh token in body
	refreshToken := req.RefreshToken
	if refreshToken == "" {
		if cookie, err := r.Cookie("hostedid_refresh_token"); err == nil {
			refreshToken = cookie.Value
		}
	}

	if refreshToken == "" {
		writeError(w, http.StatusBadRequest, "validation_error", "Refresh token is required")
		return
	}

	resp, err := h.authSvc.RefreshTokens(r.Context(), refreshToken)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrInvalidToken):
			h.clearTokenCookies(w)
			writeError(w, http.StatusUnauthorized, "token_expired", "The refresh token is invalid or expired.")
		case errors.Is(err, service.ErrTokenRevoked):
			h.clearTokenCookies(w)
			writeError(w, http.StatusUnauthorized, "token_revoked", "The refresh token has been revoked.")
		default:
			h.log.Error().Err(err).Msg("token refresh failed")
			writeError(w, http.StatusInternalServerError, "internal_error", "Token refresh failed")
		}
		return
	}

	// Set refreshed tokens as cookies
	h.setTokenCookies(w,
		resp.AccessToken,
		resp.IDToken,
		resp.RefreshToken,
		h.cfg.Security.Tokens.AccessTokenTTL,
		h.cfg.Security.Tokens.RefreshTokenTTL,
	)

	writeJSON(w, http.StatusOK, resp)
}

// --- Password Reset Request Handler ---

type passwordResetRequestPayload struct {
	Email string `json:"email"`
}

// PasswordResetRequest handles initiating a password reset
func (h *Handler) PasswordResetRequest(w http.ResponseWriter, r *http.Request) {
	var req passwordResetRequestPayload
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "validation_error", "Invalid request body")
		return
	}

	if req.Email == "" {
		writeError(w, http.StatusBadRequest, "validation_error", "Email is required")
		return
	}

	resp, err := h.authSvc.RequestPasswordReset(r.Context(), req.Email, getClientIP(r), r.UserAgent())
	if err != nil {
		h.log.Error().Err(err).Msg("password reset request failed")
		writeError(w, http.StatusInternalServerError, "internal_error", "Failed to process request")
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

// --- Password Reset Complete Handler ---

type passwordResetCompletePayload struct {
	Token       string `json:"token"`
	NewPassword string `json:"newPassword"`
}

// PasswordResetComplete handles completing a password reset
func (h *Handler) PasswordResetComplete(w http.ResponseWriter, r *http.Request) {
	var req passwordResetCompletePayload
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "validation_error", "Invalid request body")
		return
	}

	if req.Token == "" || req.NewPassword == "" {
		writeError(w, http.StatusBadRequest, "validation_error", "Token and new password are required")
		return
	}

	err := h.authSvc.CompletePasswordReset(r.Context(), req.Token, req.NewPassword, getClientIP(r), r.UserAgent())
	if err != nil {
		switch {
		case errors.Is(err, service.ErrInvalidToken):
			writeError(w, http.StatusBadRequest, "invalid_token", "The reset token is invalid.")
		case errors.Is(err, service.ErrResetTokenExpired):
			writeError(w, http.StatusBadRequest, "token_expired", "The reset token has expired. Please request a new one.")
		case errors.Is(err, service.ErrResetTokenUsed):
			writeError(w, http.StatusBadRequest, "token_used", "This reset token has already been used.")
		case errors.Is(err, service.ErrPasswordTooWeak):
			writeError(w, http.StatusBadRequest, "password_too_weak", err.Error())
		default:
			h.log.Error().Err(err).Msg("password reset completion failed")
			writeError(w, http.StatusInternalServerError, "internal_error", "Failed to reset password")
		}
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "Password has been reset successfully. Please log in with your new password."})
}

// --- Change Password Handler ---

type changePasswordPayload struct {
	CurrentPassword         string `json:"currentPassword"`
	NewPassword             string `json:"newPassword"`
	InvalidateOtherSessions bool   `json:"invalidateOtherSessions,omitempty"`
}

// ChangePassword handles authenticated password change
func (h *Handler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	userID, _ := r.Context().Value(middleware.UserIDKey).(string)
	if userID == "" {
		writeError(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
		return
	}

	var req changePasswordPayload
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "validation_error", "Invalid request body")
		return
	}

	if req.CurrentPassword == "" || req.NewPassword == "" {
		writeError(w, http.StatusBadRequest, "validation_error", "Current password and new password are required")
		return
	}

	svcReq := service.ChangePasswordRequest{
		UserID:                  userID,
		CurrentPassword:         req.CurrentPassword,
		NewPassword:             req.NewPassword,
		InvalidateOtherSessions: req.InvalidateOtherSessions,
		IPAddress:               getClientIP(r),
		UserAgent:               r.UserAgent(),
	}

	err := h.authSvc.ChangePassword(r.Context(), svcReq)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrInvalidCredentials):
			writeError(w, http.StatusUnauthorized, "invalid_password", "The current password is incorrect.")
		case errors.Is(err, service.ErrSamePassword):
			writeError(w, http.StatusBadRequest, "same_password", "New password must be different from the current password.")
		case errors.Is(err, service.ErrPasswordTooWeak):
			writeError(w, http.StatusBadRequest, "password_too_weak", err.Error())
		default:
			h.log.Error().Err(err).Msg("password change failed")
			writeError(w, http.StatusInternalServerError, "internal_error", "Failed to change password")
		}
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "Password changed successfully."})
}

// GetCurrentUser returns the authenticated user's data
func (h *Handler) GetCurrentUser(w http.ResponseWriter, r *http.Request) {
	userID, _ := r.Context().Value(middleware.UserIDKey).(string)

	if userID == "" {
		writeError(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
		return
	}

	userWithProfile, err := h.authSvc.GetCurrentUser(r.Context(), userID)
	if err != nil {
		h.log.Error().Err(err).Str("user_id", userID).Msg("failed to get current user")
		writeError(w, http.StatusInternalServerError, "internal_error", "Failed to get user data")
		return
	}

	// Build the response matching frontend expectations
	resp := map[string]interface{}{
		"id":            userWithProfile.ID,
		"email":         userWithProfile.Email,
		"emailVerified": userWithProfile.EmailVerified,
		"status":        userWithProfile.Status,
		"createdAt":     userWithProfile.CreatedAt,
	}

	if userWithProfile.Profile != nil {
		resp["profile"] = userWithProfile.Profile
	}

	writeJSON(w, http.StatusOK, resp)
}
