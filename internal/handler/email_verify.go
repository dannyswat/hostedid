package handler

import (
	"errors"
	"net/http"

	"github.com/hostedid/hostedid/internal/service"
)

// VerifyEmail handles POST /api/v1/auth/email/verify
// Verifies the user's email using the OTP code.
func (h *Handler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID string `json:"userId"`
		Code   string `json:"code"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}

	if req.UserID == "" || req.Code == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "userId and code are required")
		return
	}

	if h.emailVerifySvc == nil {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Email verification is not configured")
		return
	}

	err := h.emailVerifySvc.VerifyOTP(r.Context(), req.UserID, req.Code)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrInvalidOTP):
			writeError(w, http.StatusBadRequest, "invalid_otp", "Invalid or expired verification code")
		case errors.Is(err, service.ErrVerificationDisabled):
			writeError(w, http.StatusBadRequest, "verification_disabled", "Email verification is not enabled")
		case errors.Is(err, service.ErrEmailAlreadyVerified):
			writeError(w, http.StatusConflict, "already_verified", "Email is already verified")
		default:
			h.log.Error().Err(err).Str("user_id", req.UserID).Msg("email verification failed")
			writeError(w, http.StatusInternalServerError, "internal_error", "Failed to verify email")
		}
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message":       "Email verified successfully",
		"emailVerified": true,
	})
}

// ResendVerificationOTP handles POST /api/v1/auth/email/resend
// Resends the verification OTP to the user's email.
func (h *Handler) ResendVerificationOTP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID string `json:"userId"`
		Email  string `json:"email"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}

	if req.UserID == "" || req.Email == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "userId and email are required")
		return
	}

	if h.emailVerifySvc == nil {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "Email verification is not configured")
		return
	}

	err := h.emailVerifySvc.SendVerificationOTP(r.Context(), req.UserID, req.Email)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrTooManyResendAttempts):
			writeError(w, http.StatusTooManyRequests, "too_many_requests", "Please wait before requesting a new code")
		case errors.Is(err, service.ErrVerificationDisabled):
			writeError(w, http.StatusBadRequest, "verification_disabled", "Email verification is not enabled")
		default:
			h.log.Error().Err(err).Str("user_id", req.UserID).Msg("resend verification OTP failed")
			writeError(w, http.StatusInternalServerError, "internal_error", "Failed to resend verification code")
		}
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Verification code sent",
	})
}
