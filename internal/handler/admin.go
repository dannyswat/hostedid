package handler

import (
	"net/http"

	"github.com/hostedid/hostedid/internal/middleware"
)

// AdminUnlockAccount handles POST /api/v1/admin/users/{id}/unlock
func (h *Handler) AdminUnlockAccount(w http.ResponseWriter, r *http.Request) {
	targetUserID := r.PathValue("id")
	if targetUserID == "" {
		writeError(w, http.StatusBadRequest, "MISSING_USER_ID", "User ID is required")
		return
	}

	// Get admin user from auth context
	adminUserID, ok := r.Context().Value(middleware.UserIDKey).(string)
	if !ok || adminUserID == "" {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	ipAddress := r.RemoteAddr
	userAgent := r.UserAgent()

	if err := h.authSvc.AdminUnlockAccount(r.Context(), targetUserID, adminUserID, ipAddress, userAgent); err != nil {
		h.log.Error().Err(err).Str("target_user_id", targetUserID).Msg("failed to unlock account")
		writeError(w, http.StatusInternalServerError, "UNLOCK_FAILED", "Failed to unlock account")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Account unlocked successfully",
		"user_id": targetUserID,
	})
}

// AdminListKeys handles GET /api/v1/admin/keys
func (h *Handler) AdminListKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := h.keySvc.ListKeys(r.Context())
	if err != nil {
		h.log.Error().Err(err).Msg("failed to list signing keys")
		writeError(w, http.StatusInternalServerError, "LIST_KEYS_FAILED", "Failed to list signing keys")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"keys":      keys,
		"activeKey": h.keySvc.GetActiveKeyID(),
	})
}

// AdminRotateKey handles POST /api/v1/admin/keys/rotate
func (h *Handler) AdminRotateKey(w http.ResponseWriter, r *http.Request) {
	algorithm := h.cfg.Security.Tokens.SigningAlgorithm
	if algorithm == "" {
		algorithm = "hybrid"
	}

	keyInfo, err := h.keySvc.RotateKey(r.Context(), algorithm)
	if err != nil {
		h.log.Error().Err(err).Msg("failed to rotate signing key")
		writeError(w, http.StatusInternalServerError, "ROTATE_KEY_FAILED", "Failed to rotate signing key")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Key rotated successfully",
		"key":     keyInfo,
	})
}

// AdminGetKeyInfo handles GET /api/v1/admin/keys/{id}
func (h *Handler) AdminGetKeyInfo(w http.ResponseWriter, r *http.Request) {
	keyID := r.PathValue("id")
	if keyID == "" {
		writeError(w, http.StatusBadRequest, "MISSING_KEY_ID", "Key ID is required")
		return
	}

	// Use ListKeys and find the one we want
	keys, err := h.keySvc.ListKeys(r.Context())
	if err != nil {
		h.log.Error().Err(err).Msg("failed to get key info")
		writeError(w, http.StatusInternalServerError, "GET_KEY_FAILED", "Failed to get key info")
		return
	}

	for _, k := range keys {
		if k.ID == keyID {
			writeJSON(w, http.StatusOK, k)
			return
		}
	}

	writeError(w, http.StatusNotFound, "KEY_NOT_FOUND", "Signing key not found")
}
