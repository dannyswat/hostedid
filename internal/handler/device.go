package handler

import (
	"errors"
	"net/http"
	"time"

	"github.com/hostedid/hostedid/internal/middleware"
	"github.com/hostedid/hostedid/internal/service"
)

// --- List Devices ---

// ListDevices returns all devices for the authenticated user
func (h *Handler) ListDevices(w http.ResponseWriter, r *http.Request) {
	userID, _ := r.Context().Value(middleware.UserIDKey).(string)
	deviceID, _ := r.Context().Value(middleware.DeviceIDKey).(string)

	if userID == "" {
		writeError(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
		return
	}

	devices, err := h.deviceSvc.ListUserDevices(r.Context(), userID, deviceID)
	if err != nil {
		h.log.Error().Err(err).Msg("failed to list devices")
		writeError(w, http.StatusInternalServerError, "internal_error", "Failed to list devices")
		return
	}

	writeJSON(w, http.StatusOK, devices)
}

// --- Get Device ---

// GetDevice returns a specific device
func (h *Handler) GetDevice(w http.ResponseWriter, r *http.Request) {
	userID, _ := r.Context().Value(middleware.UserIDKey).(string)
	if userID == "" {
		writeError(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
		return
	}

	deviceID := r.PathValue("id")
	if deviceID == "" {
		writeError(w, http.StatusBadRequest, "validation_error", "Device ID is required")
		return
	}

	device, err := h.deviceSvc.GetDevice(r.Context(), userID, deviceID)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrDeviceNotFound):
			writeError(w, http.StatusNotFound, "not_found", "Device not found")
		case errors.Is(err, service.ErrDeviceNotOwned):
			writeError(w, http.StatusForbidden, "forbidden", "Device does not belong to you")
		default:
			h.log.Error().Err(err).Msg("failed to get device")
			writeError(w, http.StatusInternalServerError, "internal_error", "Failed to get device")
		}
		return
	}

	writeJSON(w, http.StatusOK, device)
}

// --- Get Current Device ---

// GetCurrentDevice returns the user's current device
func (h *Handler) GetCurrentDevice(w http.ResponseWriter, r *http.Request) {
	userID, _ := r.Context().Value(middleware.UserIDKey).(string)
	deviceID, _ := r.Context().Value(middleware.DeviceIDKey).(string)

	if userID == "" {
		writeError(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
		return
	}

	if deviceID == "" {
		writeError(w, http.StatusBadRequest, "validation_error", "No device ID in current session")
		return
	}

	device, err := h.deviceSvc.GetCurrentDevice(r.Context(), userID, deviceID)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrDeviceNotFound):
			writeError(w, http.StatusNotFound, "not_found", "Current device not found")
		default:
			h.log.Error().Err(err).Msg("failed to get current device")
			writeError(w, http.StatusInternalServerError, "internal_error", "Failed to get current device")
		}
		return
	}

	writeJSON(w, http.StatusOK, device)
}

// --- Trust Device ---

type trustDeviceRequest struct {
	DeviceID string `json:"deviceId"`
	Duration *int   `json:"durationDays,omitempty"` // days
}

// TrustDevice marks a device as trusted
func (h *Handler) TrustDevice(w http.ResponseWriter, r *http.Request) {
	userID, _ := r.Context().Value(middleware.UserIDKey).(string)
	if userID == "" {
		writeError(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
		return
	}

	var req trustDeviceRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "validation_error", "Invalid request body")
		return
	}

	if req.DeviceID == "" {
		writeError(w, http.StatusBadRequest, "validation_error", "Device ID is required")
		return
	}

	svcReq := service.TrustDeviceRequest{
		DeviceID:  req.DeviceID,
		UserID:    userID,
		IPAddress: getClientIP(r),
		UserAgent: r.UserAgent(),
	}

	if req.Duration != nil && *req.Duration > 0 {
		d := time.Duration(*req.Duration) * 24 * time.Hour
		svcReq.Duration = &d
	}

	device, err := h.deviceSvc.TrustDevice(r.Context(), svcReq)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrDeviceNotFound):
			writeError(w, http.StatusNotFound, "not_found", "Device not found")
		case errors.Is(err, service.ErrDeviceNotOwned):
			writeError(w, http.StatusForbidden, "forbidden", "Device does not belong to you")
		default:
			h.log.Error().Err(err).Msg("failed to trust device")
			writeError(w, http.StatusInternalServerError, "internal_error", "Failed to trust device")
		}
		return
	}

	writeJSON(w, http.StatusOK, device)
}

// --- Untrust Device ---

type untrustDeviceRequest struct {
	DeviceID string `json:"deviceId"`
}

// UntrustDevice removes trust from a device
func (h *Handler) UntrustDevice(w http.ResponseWriter, r *http.Request) {
	userID, _ := r.Context().Value(middleware.UserIDKey).(string)
	if userID == "" {
		writeError(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
		return
	}

	var req untrustDeviceRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "validation_error", "Invalid request body")
		return
	}

	if req.DeviceID == "" {
		writeError(w, http.StatusBadRequest, "validation_error", "Device ID is required")
		return
	}

	device, err := h.deviceSvc.UntrustDevice(r.Context(), userID, req.DeviceID, getClientIP(r), r.UserAgent())
	if err != nil {
		switch {
		case errors.Is(err, service.ErrDeviceNotFound):
			writeError(w, http.StatusNotFound, "not_found", "Device not found")
		case errors.Is(err, service.ErrDeviceNotOwned):
			writeError(w, http.StatusForbidden, "forbidden", "Device does not belong to you")
		default:
			h.log.Error().Err(err).Msg("failed to untrust device")
			writeError(w, http.StatusInternalServerError, "internal_error", "Failed to untrust device")
		}
		return
	}

	writeJSON(w, http.StatusOK, device)
}

// --- Update Device ---

type updateDeviceRequest struct {
	Name string `json:"name"`
}

// UpdateDevice updates a device (e.g., rename)
func (h *Handler) UpdateDevice(w http.ResponseWriter, r *http.Request) {
	userID, _ := r.Context().Value(middleware.UserIDKey).(string)
	if userID == "" {
		writeError(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
		return
	}

	deviceID := r.PathValue("id")
	if deviceID == "" {
		writeError(w, http.StatusBadRequest, "validation_error", "Device ID is required")
		return
	}

	var req updateDeviceRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "validation_error", "Invalid request body")
		return
	}

	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "validation_error", "Device name is required")
		return
	}

	if len(req.Name) > 100 {
		writeError(w, http.StatusBadRequest, "validation_error", "Device name must be 100 characters or less")
		return
	}

	svcReq := service.RenameDeviceRequest{
		DeviceID:  deviceID,
		UserID:    userID,
		Name:      req.Name,
		IPAddress: getClientIP(r),
		UserAgent: r.UserAgent(),
	}

	device, err := h.deviceSvc.RenameDevice(r.Context(), svcReq)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrDeviceNotFound):
			writeError(w, http.StatusNotFound, "not_found", "Device not found")
		case errors.Is(err, service.ErrDeviceNotOwned):
			writeError(w, http.StatusForbidden, "forbidden", "Device does not belong to you")
		default:
			h.log.Error().Err(err).Msg("failed to update device")
			writeError(w, http.StatusInternalServerError, "internal_error", "Failed to update device")
		}
		return
	}

	writeJSON(w, http.StatusOK, device)
}

// --- Delete Device ---

// DeleteDevice removes a device and revokes its session
func (h *Handler) DeleteDevice(w http.ResponseWriter, r *http.Request) {
	userID, _ := r.Context().Value(middleware.UserIDKey).(string)
	if userID == "" {
		writeError(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
		return
	}

	deviceID := r.PathValue("id")
	if deviceID == "" {
		writeError(w, http.StatusBadRequest, "validation_error", "Device ID is required")
		return
	}

	err := h.deviceSvc.RemoveDevice(r.Context(), userID, deviceID, getClientIP(r), r.UserAgent())
	if err != nil {
		switch {
		case errors.Is(err, service.ErrDeviceNotFound):
			writeError(w, http.StatusNotFound, "not_found", "Device not found")
		case errors.Is(err, service.ErrDeviceNotOwned):
			writeError(w, http.StatusForbidden, "forbidden", "Device does not belong to you")
		default:
			h.log.Error().Err(err).Msg("failed to delete device")
			writeError(w, http.StatusInternalServerError, "internal_error", "Failed to delete device")
		}
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "Device removed successfully"})
}

// --- Logout Device ---

// LogoutDevice ends a device's session but keeps the device record
func (h *Handler) LogoutDevice(w http.ResponseWriter, r *http.Request) {
	userID, _ := r.Context().Value(middleware.UserIDKey).(string)
	if userID == "" {
		writeError(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
		return
	}

	deviceID := r.PathValue("id")
	if deviceID == "" {
		writeError(w, http.StatusBadRequest, "validation_error", "Device ID is required")
		return
	}

	err := h.deviceSvc.LogoutDevice(r.Context(), userID, deviceID, getClientIP(r), r.UserAgent())
	if err != nil {
		switch {
		case errors.Is(err, service.ErrDeviceNotFound):
			writeError(w, http.StatusNotFound, "not_found", "Device not found")
		case errors.Is(err, service.ErrDeviceNotOwned):
			writeError(w, http.StatusForbidden, "forbidden", "Device does not belong to you")
		default:
			h.log.Error().Err(err).Msg("failed to logout device")
			writeError(w, http.StatusInternalServerError, "internal_error", "Failed to logout device")
		}
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "Device session ended successfully"})
}

// --- Revoke All Other Devices ---

// RevokeAllOtherDevices removes all devices except the current one
func (h *Handler) RevokeAllOtherDevices(w http.ResponseWriter, r *http.Request) {
	userID, _ := r.Context().Value(middleware.UserIDKey).(string)
	deviceID, _ := r.Context().Value(middleware.DeviceIDKey).(string)

	if userID == "" {
		writeError(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
		return
	}

	// Get all devices for user
	devices, err := h.deviceSvc.ListUserDevices(r.Context(), userID, deviceID)
	if err != nil {
		h.log.Error().Err(err).Msg("failed to list devices for revoke all")
		writeError(w, http.StatusInternalServerError, "internal_error", "Failed to revoke devices")
		return
	}

	// Remove all devices except current
	for _, d := range devices {
		if d.ID == deviceID {
			continue
		}
		if err := h.deviceSvc.RemoveDevice(r.Context(), userID, d.ID, getClientIP(r), r.UserAgent()); err != nil {
			h.log.Error().Err(err).Str("device_id", d.ID).Msg("failed to remove device during revoke all")
		}
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "All other devices have been signed out"})
}
