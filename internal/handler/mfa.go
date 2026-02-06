package handler

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/hostedid/hostedid/internal/middleware"
	"github.com/hostedid/hostedid/internal/model"
	"github.com/hostedid/hostedid/internal/service"
)

// --- MFA Status ---

// GetMFAMethods returns the authenticated user's MFA enrollment status
func (h *Handler) GetMFAMethods(w http.ResponseWriter, r *http.Request) {
	userID, _ := r.Context().Value(middleware.UserIDKey).(string)
	if userID == "" {
		writeError(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
		return
	}

	status, err := h.mfaSvc.GetMFAStatus(r.Context(), userID)
	if err != nil {
		h.log.Error().Err(err).Msg("failed to get MFA status")
		writeError(w, http.StatusInternalServerError, "internal_error", "Failed to get MFA methods")
		return
	}

	writeJSON(w, http.StatusOK, status)
}

// --- TOTP Setup ---

// TOTPSetup initiates TOTP enrollment for the authenticated user
func (h *Handler) TOTPSetup(w http.ResponseWriter, r *http.Request) {
	userID, _ := r.Context().Value(middleware.UserIDKey).(string)
	if userID == "" {
		writeError(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
		return
	}

	resp, err := h.mfaSvc.SetupTOTP(r.Context(), userID)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrMFAAlreadyEnrolled):
			writeError(w, http.StatusConflict, "mfa_already_enrolled", "TOTP is already set up for this account")
		default:
			h.log.Error().Err(err).Msg("TOTP setup failed")
			writeError(w, http.StatusInternalServerError, "internal_error", "Failed to set up TOTP")
		}
		return
	}

	h.logAudit(r, userID, "mfa.totp_setup", "mfa", userID)
	writeJSON(w, http.StatusOK, resp)
}

// --- TOTP Verify (Setup confirmation) ---

type totpVerifyRequest struct {
	Code string `json:"code"`
}

// TOTPVerify verifies a TOTP code during setup or for MFA challenge
func (h *Handler) TOTPVerify(w http.ResponseWriter, r *http.Request) {
	userID, _ := r.Context().Value(middleware.UserIDKey).(string)
	if userID == "" {
		writeError(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
		return
	}

	var req totpVerifyRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "validation_error", "Invalid request body")
		return
	}

	if req.Code == "" {
		writeError(w, http.StatusBadRequest, "validation_error", "Code is required")
		return
	}

	err := h.mfaSvc.VerifyTOTPSetup(r.Context(), userID, req.Code)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrMFANotEnrolled):
			writeError(w, http.StatusBadRequest, "mfa_not_enrolled", "TOTP is not set up. Please initiate setup first.")
		case errors.Is(err, service.ErrMFAInvalidCode):
			writeError(w, http.StatusBadRequest, "invalid_code", "The verification code is incorrect. Please try again.")
		default:
			h.log.Error().Err(err).Msg("TOTP verification failed")
			writeError(w, http.StatusInternalServerError, "internal_error", "Failed to verify TOTP code")
		}
		return
	}

	h.logAudit(r, userID, "mfa.totp_verified", "mfa", userID)
	writeJSON(w, http.StatusOK, map[string]string{"message": "TOTP has been successfully set up."})
}

// --- MFA Verify (Login challenge) ---

type mfaVerifyRequest struct {
	MFAToken   string `json:"mfaToken"`
	Method     string `json:"method"`
	Code       string `json:"code,omitempty"`
	SessionKey string `json:"sessionKey,omitempty"` // for WebAuthn
	ReturnURL  string `json:"returnUrl,omitempty"`
}

// MFAVerify handles MFA verification during the login flow
func (h *Handler) MFAVerify(w http.ResponseWriter, r *http.Request) {
	var req mfaVerifyRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "validation_error", "Invalid request body")
		return
	}

	if req.MFAToken == "" {
		writeError(w, http.StatusBadRequest, "validation_error", "MFA token is required")
		return
	}

	// Validate the MFA token
	userID, err := h.mfaSvc.ValidateMFAToken(req.MFAToken)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrMFAInvalidToken):
			writeError(w, http.StatusUnauthorized, "invalid_mfa_token", "The MFA token is invalid.")
		case errors.Is(err, service.ErrMFASessionExpired):
			writeError(w, http.StatusUnauthorized, "mfa_session_expired", "The MFA session has expired. Please log in again.")
		default:
			writeError(w, http.StatusInternalServerError, "internal_error", "MFA verification failed")
		}
		return
	}

	// Verify based on method
	method := model.MFAMethodType(req.Method)
	switch method {
	case model.MFAMethodTOTP:
		if req.Code == "" {
			writeError(w, http.StatusBadRequest, "validation_error", "Code is required for TOTP verification")
			return
		}
		err = h.mfaSvc.VerifyTOTP(r.Context(), userID, req.Code)

	case model.MFAMethodBackupCode:
		if req.Code == "" {
			writeError(w, http.StatusBadRequest, "validation_error", "Backup code is required")
			return
		}
		err = h.mfaSvc.VerifyBackupCode(r.Context(), userID, req.Code)

	case model.MFAMethodWebAuthn:
		// WebAuthn is handled via the begin/complete ceremony endpoints
		writeError(w, http.StatusBadRequest, "validation_error", "WebAuthn verification should use the /webauthn/authenticate endpoints")
		return

	default:
		writeError(w, http.StatusBadRequest, "validation_error", "Unsupported MFA method")
		return
	}

	if err != nil {
		switch {
		case errors.Is(err, service.ErrMFAInvalidCode):
			writeError(w, http.StatusBadRequest, "invalid_code", "The verification code is incorrect.")
		case errors.Is(err, service.ErrMFANoBackupCodes):
			writeError(w, http.StatusBadRequest, "no_backup_codes", "No backup codes remaining. Please contact support.")
		case errors.Is(err, service.ErrMFANotEnrolled):
			writeError(w, http.StatusBadRequest, "mfa_not_enrolled", "This MFA method is not enrolled.")
		default:
			h.log.Error().Err(err).Msg("MFA verification failed")
			writeError(w, http.StatusInternalServerError, "internal_error", "MFA verification failed")
		}
		return
	}

	// MFA verified! Consume the token and complete the login
	userID, err = h.mfaSvc.ConsumeMFAToken(req.MFAToken)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_mfa_token", "The MFA token is invalid.")
		return
	}

	// Complete login by issuing tokens
	resp, err := h.authSvc.CompleteMFALogin(r.Context(), userID, getClientIP(r), r.UserAgent())
	if err != nil {
		h.log.Error().Err(err).Msg("failed to complete MFA login")
		writeError(w, http.StatusInternalServerError, "internal_error", "Failed to complete login")
		return
	}

	// Set tokens as cookies
	h.setTokenCookies(w,
		resp.AccessToken,
		resp.IDToken,
		resp.RefreshToken,
		h.cfg.Security.Tokens.AccessTokenTTL,
		h.cfg.Security.Tokens.RefreshTokenTTL,
	)

	h.logAudit(r, userID, "mfa.verified", "mfa", userID)

	// Build response with optional returnUrl
	mfaResp := map[string]interface{}{
		"accessToken":  resp.AccessToken,
		"refreshToken": resp.RefreshToken,
		"idToken":      resp.IDToken,
		"tokenType":    resp.TokenType,
		"expiresIn":    resp.ExpiresIn,
		"deviceId":     resp.DeviceID,
	}
	if req.ReturnURL != "" && h.isAllowedReturnURL(req.ReturnURL) {
		mfaResp["returnUrl"] = req.ReturnURL
	}

	writeJSON(w, http.StatusOK, mfaResp)
}

// --- WebAuthn Registration ---

// WebAuthnRegisterBegin starts the WebAuthn registration ceremony
func (h *Handler) WebAuthnRegisterBegin(w http.ResponseWriter, r *http.Request) {
	userID, _ := r.Context().Value(middleware.UserIDKey).(string)
	if userID == "" {
		writeError(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
		return
	}

	resp, err := h.mfaSvc.BeginWebAuthnRegistration(r.Context(), userID)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrWebAuthnUnsupported):
			writeError(w, http.StatusNotImplemented, "webauthn_unsupported", "WebAuthn is not configured on this server")
		default:
			h.log.Error().Err(err).Msg("WebAuthn registration begin failed")
			writeError(w, http.StatusInternalServerError, "internal_error", "Failed to start WebAuthn registration")
		}
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

// WebAuthnRegisterComplete completes the WebAuthn registration ceremony
func (h *Handler) WebAuthnRegisterComplete(w http.ResponseWriter, r *http.Request) {
	userID, _ := r.Context().Value(middleware.UserIDKey).(string)
	if userID == "" {
		writeError(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
		return
	}

	// Read the raw body for credential parsing
	var body struct {
		SessionKey     string          `json:"sessionKey"`
		CredentialName string          `json:"credentialName"`
		Credential     json.RawMessage `json:"credential"`
	}
	if err := readJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "validation_error", "Invalid request body")
		return
	}

	if body.SessionKey == "" {
		writeError(w, http.StatusBadRequest, "validation_error", "Session key is required")
		return
	}

	if body.Credential == nil {
		writeError(w, http.StatusBadRequest, "validation_error", "Credential data is required")
		return
	}

	// Parse the credential creation response from the credential JSON
	credReader := bytes.NewReader(body.Credential)
	parsed, err := protocol.ParseCredentialCreationResponseBody(credReader)
	if err != nil {
		h.log.Error().Err(err).Msg("failed to parse WebAuthn credential")
		writeError(w, http.StatusBadRequest, "validation_error", "Failed to parse WebAuthn response")
		return
	}

	credName := body.CredentialName
	if credName == "" {
		credName = "Security Key"
	}

	err = h.mfaSvc.CompleteWebAuthnRegistration(r.Context(), userID, body.SessionKey, credName, *parsed)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrMFASessionExpired):
			writeError(w, http.StatusBadRequest, "session_expired", "WebAuthn session has expired. Please try again.")
		default:
			h.log.Error().Err(err).Msg("WebAuthn registration complete failed")
			writeError(w, http.StatusInternalServerError, "internal_error", "Failed to complete WebAuthn registration")
		}
		return
	}

	h.logAudit(r, userID, "mfa.webauthn_registered", "mfa", userID)
	writeJSON(w, http.StatusOK, map[string]string{"message": "WebAuthn credential registered successfully."})
}

// --- WebAuthn Authentication ---

// WebAuthnAuthenticateBegin starts the WebAuthn authentication ceremony
func (h *Handler) WebAuthnAuthenticateBegin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		MFAToken string `json:"mfaToken"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "validation_error", "Invalid request body")
		return
	}

	if req.MFAToken == "" {
		writeError(w, http.StatusBadRequest, "validation_error", "MFA token is required")
		return
	}

	userID, err := h.mfaSvc.ValidateMFAToken(req.MFAToken)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_mfa_token", "The MFA token is invalid or expired.")
		return
	}

	resp, err := h.mfaSvc.BeginWebAuthnAuthentication(r.Context(), userID)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrMFANotEnrolled):
			writeError(w, http.StatusBadRequest, "mfa_not_enrolled", "No WebAuthn credentials found.")
		case errors.Is(err, service.ErrWebAuthnUnsupported):
			writeError(w, http.StatusNotImplemented, "webauthn_unsupported", "WebAuthn is not configured on this server")
		default:
			h.log.Error().Err(err).Msg("WebAuthn authentication begin failed")
			writeError(w, http.StatusInternalServerError, "internal_error", "Failed to start WebAuthn authentication")
		}
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

// WebAuthnAuthenticateComplete completes the WebAuthn authentication ceremony
func (h *Handler) WebAuthnAuthenticateComplete(w http.ResponseWriter, r *http.Request) {
	var body struct {
		MFAToken   string          `json:"mfaToken"`
		SessionKey string          `json:"sessionKey"`
		Credential json.RawMessage `json:"credential"`
		ReturnURL  string          `json:"returnUrl,omitempty"`
	}
	if err := readJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "validation_error", "Invalid request body")
		return
	}

	if body.MFAToken == "" || body.SessionKey == "" {
		writeError(w, http.StatusBadRequest, "validation_error", "MFA token and session key are required")
		return
	}

	userID, err := h.mfaSvc.ValidateMFAToken(body.MFAToken)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_mfa_token", "The MFA token is invalid or expired.")
		return
	}

	if body.Credential == nil {
		writeError(w, http.StatusBadRequest, "validation_error", "Credential data is required")
		return
	}

	// Parse the assertion response from the credential JSON
	credReader := bytes.NewReader(body.Credential)
	parsed, err := protocol.ParseCredentialRequestResponseBody(credReader)
	if err != nil {
		writeError(w, http.StatusBadRequest, "validation_error", "Failed to parse WebAuthn response")
		return
	}

	err = h.mfaSvc.CompleteWebAuthnAuthentication(r.Context(), userID, body.SessionKey, *parsed)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrMFASessionExpired):
			writeError(w, http.StatusBadRequest, "session_expired", "WebAuthn session has expired. Please try again.")
		default:
			h.log.Error().Err(err).Msg("WebAuthn authentication failed")
			writeError(w, http.StatusBadRequest, "webauthn_failed", "WebAuthn authentication failed")
		}
		return
	}

	// MFA verified! Complete login
	userID, err = h.mfaSvc.ConsumeMFAToken(body.MFAToken)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_mfa_token", "The MFA token is invalid.")
		return
	}

	resp, err := h.authSvc.CompleteMFALogin(r.Context(), userID, getClientIP(r), r.UserAgent())
	if err != nil {
		h.log.Error().Err(err).Msg("failed to complete MFA login")
		writeError(w, http.StatusInternalServerError, "internal_error", "Failed to complete login")
		return
	}

	// Set tokens as cookies
	h.setTokenCookies(w,
		resp.AccessToken,
		resp.IDToken,
		resp.RefreshToken,
		h.cfg.Security.Tokens.AccessTokenTTL,
		h.cfg.Security.Tokens.RefreshTokenTTL,
	)

	h.logAudit(r, userID, "mfa.webauthn_verified", "mfa", userID)

	// Build response with optional returnUrl
	webauthnResp := map[string]interface{}{
		"accessToken":  resp.AccessToken,
		"refreshToken": resp.RefreshToken,
		"idToken":      resp.IDToken,
		"tokenType":    resp.TokenType,
		"expiresIn":    resp.ExpiresIn,
		"deviceId":     resp.DeviceID,
	}
	if body.ReturnURL != "" && h.isAllowedReturnURL(body.ReturnURL) {
		webauthnResp["returnUrl"] = body.ReturnURL
	}

	writeJSON(w, http.StatusOK, webauthnResp)
}

// --- Backup Codes ---

// BackupCodesGenerate generates a new set of backup codes
func (h *Handler) BackupCodesGenerate(w http.ResponseWriter, r *http.Request) {
	userID, _ := r.Context().Value(middleware.UserIDKey).(string)
	if userID == "" {
		writeError(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
		return
	}

	resp, err := h.mfaSvc.GenerateBackupCodes(r.Context(), userID)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrMFANotEnrolled):
			writeError(w, http.StatusBadRequest, "mfa_not_enrolled", "You must enroll in an MFA method before generating backup codes.")
		default:
			h.log.Error().Err(err).Msg("backup code generation failed")
			writeError(w, http.StatusInternalServerError, "internal_error", "Failed to generate backup codes")
		}
		return
	}

	h.logAudit(r, userID, "mfa.backup_codes_generated", "mfa", userID)
	writeJSON(w, http.StatusOK, resp)
}

// --- Delete MFA Method ---

// DeleteMFAMethod removes an MFA method for the authenticated user
func (h *Handler) DeleteMFAMethod(w http.ResponseWriter, r *http.Request) {
	userID, _ := r.Context().Value(middleware.UserIDKey).(string)
	if userID == "" {
		writeError(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
		return
	}

	methodStr := r.PathValue("method")
	method := model.MFAMethodType(methodStr)

	switch method {
	case model.MFAMethodTOTP, model.MFAMethodWebAuthn:
		// valid
	default:
		writeError(w, http.StatusBadRequest, "validation_error", "Invalid MFA method. Use 'totp' or 'webauthn'.")
		return
	}

	err := h.mfaSvc.DisableMFAMethod(r.Context(), userID, method)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrMFANotEnrolled):
			writeError(w, http.StatusNotFound, "mfa_not_enrolled", "This MFA method is not enrolled.")
		default:
			h.log.Error().Err(err).Msg("failed to delete MFA method")
			writeError(w, http.StatusInternalServerError, "internal_error", "Failed to delete MFA method")
		}
		return
	}

	h.logAudit(r, userID, "mfa.method_disabled", "mfa", userID)
	writeJSON(w, http.StatusOK, map[string]string{"message": "MFA method has been removed."})
}

// --- Helpers ---

// logAudit is a helper for MFA handler audit logging
func (h *Handler) logAudit(r *http.Request, userID, action, resourceType, resourceID string) {
	h.authSvc.LogAudit(r.Context(), userID, action, resourceType, resourceID, getClientIP(r), r.UserAgent(), nil)
}
