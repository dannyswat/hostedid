package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/hostedid/hostedid/internal/middleware"
	"github.com/hostedid/hostedid/internal/service"
)

// --- Session Handlers ---

// GetUserSessions returns all sessions for the authenticated user
func (h *Handler) GetUserSessions(w http.ResponseWriter, r *http.Request) {
	userID, _ := r.Context().Value(middleware.UserIDKey).(string)
	deviceID, _ := r.Context().Value(middleware.DeviceIDKey).(string)

	if userID == "" {
		writeError(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
		return
	}

	summary, err := h.sessionSvc.GetUserSessions(r.Context(), userID, deviceID)
	if err != nil {
		h.log.Error().Err(err).Msg("failed to get user sessions")
		writeError(w, http.StatusInternalServerError, "internal_error", "Failed to get sessions")
		return
	}

	writeJSON(w, http.StatusOK, summary)
}

// GetDeviceSession returns the session info for a specific device
func (h *Handler) GetDeviceSession(w http.ResponseWriter, r *http.Request) {
	userID, _ := r.Context().Value(middleware.UserIDKey).(string)
	deviceID := r.PathValue("id")

	if userID == "" {
		writeError(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
		return
	}

	if deviceID == "" {
		writeError(w, http.StatusBadRequest, "validation_error", "Device ID is required")
		return
	}

	session, err := h.sessionSvc.GetSessionByDevice(r.Context(), userID, deviceID)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrSessionNotFound):
			writeError(w, http.StatusNotFound, "not_found", "Session not found")
		case errors.Is(err, service.ErrDeviceNotOwned):
			writeError(w, http.StatusForbidden, "forbidden", "Device does not belong to you")
		default:
			h.log.Error().Err(err).Msg("failed to get device session")
			writeError(w, http.StatusInternalServerError, "internal_error", "Failed to get session")
		}
		return
	}

	writeJSON(w, http.StatusOK, session)
}

// RevokeDeviceSession revokes the session for a specific device
func (h *Handler) RevokeDeviceSession(w http.ResponseWriter, r *http.Request) {
	userID, _ := r.Context().Value(middleware.UserIDKey).(string)
	deviceID := r.PathValue("id")

	if userID == "" {
		writeError(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
		return
	}

	if deviceID == "" {
		writeError(w, http.StatusBadRequest, "validation_error", "Device ID is required")
		return
	}

	var body struct {
		Reason string `json:"reason"`
	}
	if r.Body != nil {
		json.NewDecoder(r.Body).Decode(&body)
	}
	if body.Reason == "" {
		body.Reason = "user_initiated"
	}

	err := h.sessionSvc.RevokeDeviceSession(r.Context(), userID, deviceID, body.Reason, getClientIP(r), r.UserAgent())
	if err != nil {
		switch {
		case errors.Is(err, service.ErrSessionNotFound):
			writeError(w, http.StatusNotFound, "not_found", "Session not found")
		case errors.Is(err, service.ErrDeviceNotOwned):
			writeError(w, http.StatusForbidden, "forbidden", "Device does not belong to you")
		default:
			h.log.Error().Err(err).Msg("failed to revoke device session")
			writeError(w, http.StatusInternalServerError, "internal_error", "Failed to revoke session")
		}
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "Session revoked successfully"})
}

// RevokeAllOtherSessions revokes all sessions except the current device
func (h *Handler) RevokeAllOtherSessions(w http.ResponseWriter, r *http.Request) {
	userID, _ := r.Context().Value(middleware.UserIDKey).(string)
	deviceID, _ := r.Context().Value(middleware.DeviceIDKey).(string)

	if userID == "" {
		writeError(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
		return
	}

	count, err := h.sessionSvc.RevokeAllSessions(r.Context(), userID, deviceID, "user_revoke_all", getClientIP(r), r.UserAgent())
	if err != nil {
		h.log.Error().Err(err).Msg("failed to revoke all sessions")
		writeError(w, http.StatusInternalServerError, "internal_error", "Failed to revoke sessions")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message":      "All other sessions revoked successfully",
		"revokedCount": count,
	})
}

// --- Back-Channel Logout Handler ---

// BackChannelLogout handles OIDC back-channel logout requests
func (h *Handler) BackChannelLogout(w http.ResponseWriter, r *http.Request) {
	userID, _ := r.Context().Value(middleware.UserIDKey).(string)

	if userID == "" {
		writeError(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
		return
	}

	var req struct {
		DeviceID string `json:"deviceId"`
		Reason   string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "validation_error", "Invalid request body")
		return
	}

	resp, err := h.backChannelSvc.TriggerLogout(r.Context(), service.BackChannelLogoutRequest{
		UserID:    userID,
		DeviceID:  req.DeviceID,
		Reason:    req.Reason,
		IPAddress: getClientIP(r),
		UserAgent: r.UserAgent(),
	})
	if err != nil {
		h.log.Error().Err(err).Msg("failed to trigger back-channel logout")
		writeError(w, http.StatusInternalServerError, "internal_error", "Failed to process back-channel logout")
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

// ValidateLogoutToken validates an OIDC logout token
// This endpoint is for relying parties to validate tokens they receive
func (h *Handler) ValidateLogoutToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		LogoutToken string `json:"logoutToken"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "validation_error", "Invalid request body")
		return
	}

	if req.LogoutToken == "" {
		writeError(w, http.StatusBadRequest, "validation_error", "Logout token is required")
		return
	}

	claims, err := h.backChannelSvc.ValidateLogoutToken(req.LogoutToken)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_token", "Invalid or expired logout token")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"valid":    true,
		"userId":   claims.Subject,
		"deviceId": claims.DeviceID,
		"events":   claims.Events,
		"issuedAt": claims.IssuedAt,
	})
}
