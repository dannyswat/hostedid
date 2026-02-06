package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hostedid/hostedid/internal/config"
	"github.com/hostedid/hostedid/internal/logger"
	"github.com/hostedid/hostedid/internal/model"
	"github.com/hostedid/hostedid/internal/repository"
)

// Device service errors
var (
	ErrDeviceNotFound       = errors.New("device not found")
	ErrDeviceNotOwned       = errors.New("device does not belong to user")
	ErrDeviceAlreadyTrusted = errors.New("device is already trusted")
	ErrMaxDevicesReached    = errors.New("maximum number of devices reached")
)

const (
	// MaxDevicesPerUser is the maximum number of devices allowed per user
	MaxDevicesPerUser = 50
	// DefaultTrustDuration is the default trust duration for a device (90 days)
	DefaultTrustDuration = 90 * 24 * time.Hour
)

// DeviceService handles device management business logic
type DeviceService struct {
	deviceRepo *repository.DeviceRepository
	tokenRepo  *repository.TokenRepository
	auditRepo  *repository.AuditRepository
	cfg        *config.Config
	log        *logger.Logger
}

// NewDeviceService creates a new DeviceService
func NewDeviceService(
	deviceRepo *repository.DeviceRepository,
	tokenRepo *repository.TokenRepository,
	auditRepo *repository.AuditRepository,
	cfg *config.Config,
	log *logger.Logger,
) *DeviceService {
	return &DeviceService{
		deviceRepo: deviceRepo,
		tokenRepo:  tokenRepo,
		auditRepo:  auditRepo,
		cfg:        cfg,
		log:        log.WithComponent("device_service"),
	}
}

// DeviceResponse represents a device in API responses
type DeviceResponse struct {
	ID              string          `json:"id"`
	DeviceID        string          `json:"deviceId"`
	DeviceName      string          `json:"deviceName"`
	DeviceType      string          `json:"deviceType"`
	Name            string          `json:"name"`
	FingerprintHash string          `json:"fingerprintHash"`
	FirstSeen       time.Time       `json:"firstSeen"`
	LastActivity    time.Time       `json:"lastActivity"`
	LastActiveAt    time.Time       `json:"lastActiveAt"`
	CurrentIP       string          `json:"currentIp"`
	IPAddress       string          `json:"ipAddress"`
	CurrentLocation *string         `json:"currentLocation,omitempty"`
	Location        *string         `json:"location,omitempty"`
	Browser         string          `json:"browser"`
	OS              string          `json:"os"`
	IsTrusted       bool            `json:"isTrusted"`
	TrustExpiresAt  *time.Time      `json:"trustExpiresAt,omitempty"`
	Session         SessionResponse `json:"session"`
	IsCurrentDevice bool            `json:"isCurrentDevice"`
	IsCurrent       bool            `json:"isCurrent"`
}

// SessionResponse represents session info within a device
type SessionResponse struct {
	IsActive    bool       `json:"isActive"`
	StartedAt   *time.Time `json:"startedAt,omitempty"`
	ExpiresAt   *time.Time `json:"expiresAt,omitempty"`
	LastRefresh *time.Time `json:"lastRefresh,omitempty"`
}

// FingerprintData represents the data collected from the client for fingerprinting
type FingerprintData struct {
	UserAgent           string `json:"userAgent"`
	ScreenResolution    string `json:"screenResolution"`
	Timezone            string `json:"timezone"`
	Language            string `json:"language"`
	Platform            string `json:"platform"`
	WebGLRenderer       string `json:"webglRenderer"`
	CanvasHash          string `json:"canvasHash"`
	ColorDepth          int    `json:"colorDepth"`
	HardwareConcurrency int    `json:"hardwareConcurrency"`
	TouchSupport        bool   `json:"touchSupport"`
}

// GenerateFingerprint creates a stable hash from fingerprint components
func GenerateFingerprint(data *FingerprintData) string {
	// Build a stable string from the most stable components
	components := []string{
		data.UserAgent,
		data.ScreenResolution,
		data.Timezone,
		data.Language,
		data.Platform,
		data.WebGLRenderer,
		data.CanvasHash,
		fmt.Sprintf("%d", data.ColorDepth),
		fmt.Sprintf("%d", data.HardwareConcurrency),
		fmt.Sprintf("%t", data.TouchSupport),
	}

	input := strings.Join(components, "|")
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:])
}

// ValidateFingerprint checks if the provided fingerprint data is valid
func ValidateFingerprint(data *FingerprintData) bool {
	// At minimum, we need a user agent
	if data.UserAgent == "" {
		return false
	}
	return true
}

// RecognizeDevice attempts to find an existing device by fingerprint
func (s *DeviceService) RecognizeDevice(ctx context.Context, userID, fingerprintHash string) (*model.Device, error) {
	device, err := s.deviceRepo.GetByUserAndFingerprint(ctx, userID, fingerprintHash)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, nil // Not found is not an error - it's a new device
		}
		return nil, fmt.Errorf("failed to look up device: %w", err)
	}
	return device, nil
}

// ListUserDevices returns all devices for a user
func (s *DeviceService) ListUserDevices(ctx context.Context, userID, currentDeviceID string) ([]DeviceResponse, error) {
	devices, err := s.deviceRepo.GetByUserID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to list devices: %w", err)
	}

	responses := make([]DeviceResponse, 0, len(devices))
	for _, d := range devices {
		responses = append(responses, s.toDeviceResponse(&d, currentDeviceID))
	}
	return responses, nil
}

// GetDevice returns a specific device by ID, verifying ownership
func (s *DeviceService) GetDevice(ctx context.Context, userID, deviceID string) (*DeviceResponse, error) {
	device, err := s.deviceRepo.GetByID(ctx, deviceID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrDeviceNotFound
		}
		return nil, fmt.Errorf("failed to get device: %w", err)
	}

	if device.UserID != userID {
		return nil, ErrDeviceNotOwned
	}

	resp := s.toDeviceResponse(device, "")
	return &resp, nil
}

// GetCurrentDevice returns the user's current device
func (s *DeviceService) GetCurrentDevice(ctx context.Context, userID, deviceID string) (*DeviceResponse, error) {
	device, err := s.deviceRepo.GetByID(ctx, deviceID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrDeviceNotFound
		}
		return nil, fmt.Errorf("failed to get device: %w", err)
	}

	if device.UserID != userID {
		return nil, ErrDeviceNotOwned
	}

	resp := s.toDeviceResponse(device, deviceID)
	return &resp, nil
}

// TrustDeviceRequest represents a request to trust a device
type TrustDeviceRequest struct {
	DeviceID  string
	UserID    string
	Duration  *time.Duration // nil = use default duration
	IPAddress string
	UserAgent string
}

// TrustDevice marks a device as trusted
func (s *DeviceService) TrustDevice(ctx context.Context, req TrustDeviceRequest) (*DeviceResponse, error) {
	device, err := s.deviceRepo.GetByID(ctx, req.DeviceID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrDeviceNotFound
		}
		return nil, fmt.Errorf("failed to get device: %w", err)
	}

	if device.UserID != req.UserID {
		return nil, ErrDeviceNotOwned
	}

	duration := DefaultTrustDuration
	if req.Duration != nil {
		duration = *req.Duration
	}

	trustExpiry := time.Now().Add(duration)

	if err := s.deviceRepo.UpdateTrust(ctx, req.DeviceID, true, &trustExpiry); err != nil {
		return nil, fmt.Errorf("failed to trust device: %w", err)
	}

	// Audit log
	s.logAudit(ctx, req.UserID, "device.trusted", "device", req.DeviceID, req.IPAddress, req.UserAgent, map[string]interface{}{
		"device_id":        req.DeviceID,
		"trust_expires_at": trustExpiry,
	})

	s.log.Info().Str("user_id", req.UserID).Str("device_id", req.DeviceID).Msg("device trusted")

	// Reload device to return updated state
	device, err = s.deviceRepo.GetByID(ctx, req.DeviceID)
	if err != nil {
		return nil, fmt.Errorf("failed to reload device: %w", err)
	}
	resp := s.toDeviceResponse(device, "")
	return &resp, nil
}

// UntrustDevice removes trust from a device
func (s *DeviceService) UntrustDevice(ctx context.Context, userID, deviceID, ipAddress, userAgent string) (*DeviceResponse, error) {
	device, err := s.deviceRepo.GetByID(ctx, deviceID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrDeviceNotFound
		}
		return nil, fmt.Errorf("failed to get device: %w", err)
	}

	if device.UserID != userID {
		return nil, ErrDeviceNotOwned
	}

	if err := s.deviceRepo.UpdateTrust(ctx, deviceID, false, nil); err != nil {
		return nil, fmt.Errorf("failed to untrust device: %w", err)
	}

	// Audit log
	s.logAudit(ctx, userID, "device.untrusted", "device", deviceID, ipAddress, userAgent, map[string]interface{}{
		"device_id": deviceID,
	})

	s.log.Info().Str("user_id", userID).Str("device_id", deviceID).Msg("device untrusted")

	// Reload device
	device, err = s.deviceRepo.GetByID(ctx, deviceID)
	if err != nil {
		return nil, fmt.Errorf("failed to reload device: %w", err)
	}
	resp := s.toDeviceResponse(device, "")
	return &resp, nil
}

// RenameDeviceRequest represents a request to rename a device
type RenameDeviceRequest struct {
	DeviceID  string
	UserID    string
	Name      string
	IPAddress string
	UserAgent string
}

// RenameDevice updates a device's name
func (s *DeviceService) RenameDevice(ctx context.Context, req RenameDeviceRequest) (*DeviceResponse, error) {
	device, err := s.deviceRepo.GetByID(ctx, req.DeviceID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrDeviceNotFound
		}
		return nil, fmt.Errorf("failed to get device: %w", err)
	}

	if device.UserID != req.UserID {
		return nil, ErrDeviceNotOwned
	}

	if err := s.deviceRepo.UpdateName(ctx, req.DeviceID, req.Name); err != nil {
		return nil, fmt.Errorf("failed to rename device: %w", err)
	}

	// Audit log
	s.logAudit(ctx, req.UserID, "device.renamed", "device", req.DeviceID, req.IPAddress, req.UserAgent, map[string]interface{}{
		"device_id": req.DeviceID,
		"new_name":  req.Name,
	})

	// Reload device
	device, err = s.deviceRepo.GetByID(ctx, req.DeviceID)
	if err != nil {
		return nil, fmt.Errorf("failed to reload device: %w", err)
	}
	resp := s.toDeviceResponse(device, "")
	return &resp, nil
}

// RemoveDevice removes a device and revokes its session and tokens
func (s *DeviceService) RemoveDevice(ctx context.Context, userID, deviceID, ipAddress, userAgent string) error {
	device, err := s.deviceRepo.GetByID(ctx, deviceID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return ErrDeviceNotFound
		}
		return fmt.Errorf("failed to get device: %w", err)
	}

	if device.UserID != userID {
		return ErrDeviceNotOwned
	}

	// Revoke all refresh tokens for this device
	if err := s.tokenRepo.RevokeRefreshTokenByDeviceID(ctx, deviceID); err != nil {
		s.log.Error().Err(err).Str("device_id", deviceID).Msg("failed to revoke device tokens")
	}

	// Delete the device record
	if err := s.deviceRepo.Delete(ctx, deviceID); err != nil {
		return fmt.Errorf("failed to delete device: %w", err)
	}

	// Audit log
	s.logAudit(ctx, userID, "device.removed", "device", deviceID, ipAddress, userAgent, map[string]interface{}{
		"device_id": deviceID,
	})

	s.log.Info().Str("user_id", userID).Str("device_id", deviceID).Msg("device removed")

	return nil
}

// LogoutDevice ends a device's session but keeps the device record
func (s *DeviceService) LogoutDevice(ctx context.Context, userID, deviceID, ipAddress, userAgent string) error {
	device, err := s.deviceRepo.GetByID(ctx, deviceID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return ErrDeviceNotFound
		}
		return fmt.Errorf("failed to get device: %w", err)
	}

	if device.UserID != userID {
		return ErrDeviceNotOwned
	}

	// Deactivate the session
	if err := s.deviceRepo.UpdateSession(ctx, deviceID, false, nil, nil, nil); err != nil {
		return fmt.Errorf("failed to deactivate session: %w", err)
	}

	// Revoke refresh tokens for this device
	if err := s.tokenRepo.RevokeRefreshTokenByDeviceID(ctx, deviceID); err != nil {
		s.log.Error().Err(err).Str("device_id", deviceID).Msg("failed to revoke device tokens")
	}

	// Audit log
	s.logAudit(ctx, userID, "device.logout", "device", deviceID, ipAddress, userAgent, map[string]interface{}{
		"device_id": deviceID,
	})

	s.log.Info().Str("user_id", userID).Str("device_id", deviceID).Msg("device logged out")

	return nil
}

// IsDeviceTrusted checks if a device is currently trusted
func (s *DeviceService) IsDeviceTrusted(ctx context.Context, deviceID string) (bool, error) {
	device, err := s.deviceRepo.GetByID(ctx, deviceID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return false, nil
		}
		return false, fmt.Errorf("failed to get device: %w", err)
	}

	if !device.IsTrusted {
		return false, nil
	}

	// Check if trust has expired
	if device.TrustExpiresAt != nil && time.Now().After(*device.TrustExpiresAt) {
		// Trust has expired, update the record
		if err := s.deviceRepo.UpdateTrust(ctx, deviceID, false, nil); err != nil {
			s.log.Error().Err(err).Str("device_id", deviceID).Msg("failed to expire device trust")
		}
		return false, nil
	}

	return true, nil
}

// toDeviceResponse converts a model.Device to DeviceResponse
func (s *DeviceService) toDeviceResponse(d *model.Device, currentDeviceID string) DeviceResponse {
	name := "Unknown Device"
	if d.Name != nil {
		name = *d.Name
	}

	ip := ""
	if d.CurrentIP != nil {
		ip = *d.CurrentIP
	}

	browser, os, deviceType := parseUserAgentDetails(d.UserAgent)
	isCurrent := currentDeviceID != "" && d.ID == currentDeviceID

	return DeviceResponse{
		ID:              d.ID,
		DeviceID:        d.ID,
		DeviceName:      name,
		DeviceType:      deviceType,
		Name:            name,
		FingerprintHash: d.FingerprintHash,
		FirstSeen:       d.FirstSeen,
		LastActivity:    d.LastActivity,
		LastActiveAt:    d.LastActivity,
		CurrentIP:       ip,
		IPAddress:       ip,
		CurrentLocation: d.CurrentLocation,
		Location:        d.CurrentLocation,
		Browser:         browser,
		OS:              os,
		IsTrusted:       d.IsTrusted,
		TrustExpiresAt:  d.TrustExpiresAt,
		Session: SessionResponse{
			IsActive:    d.SessionActive,
			StartedAt:   d.SessionStartedAt,
			ExpiresAt:   d.SessionExpiresAt,
			LastRefresh: &d.LastActivity,
		},
		IsCurrentDevice: isCurrent,
		IsCurrent:       isCurrent,
	}
}

// parseUserAgentDetails extracts browser, OS, and device type from user agent
func parseUserAgentDetails(ua *string) (browser string, os string, deviceType string) {
	if ua == nil || *ua == "" {
		return "Unknown", "Unknown", "unknown"
	}

	uaLower := strings.ToLower(*ua)

	// Detect browser
	switch {
	case strings.Contains(uaLower, "firefox"):
		browser = "Firefox"
	case strings.Contains(uaLower, "edg"):
		browser = "Edge"
	case strings.Contains(uaLower, "opr") || strings.Contains(uaLower, "opera"):
		browser = "Opera"
	case strings.Contains(uaLower, "chrome") || strings.Contains(uaLower, "chromium"):
		browser = "Chrome"
	case strings.Contains(uaLower, "safari"):
		browser = "Safari"
	default:
		browser = "Unknown"
	}

	// Detect OS
	switch {
	case strings.Contains(uaLower, "iphone"):
		os = "iOS"
		deviceType = "mobile"
	case strings.Contains(uaLower, "ipad"):
		os = "iPadOS"
		deviceType = "tablet"
	case strings.Contains(uaLower, "android"):
		if strings.Contains(uaLower, "mobile") {
			os = "Android"
			deviceType = "mobile"
		} else {
			os = "Android"
			deviceType = "tablet"
		}
	case strings.Contains(uaLower, "windows"):
		os = "Windows"
		deviceType = "desktop"
	case strings.Contains(uaLower, "macintosh") || strings.Contains(uaLower, "mac os"):
		os = "macOS"
		deviceType = "desktop"
	case strings.Contains(uaLower, "linux"):
		os = "Linux"
		deviceType = "desktop"
	case strings.Contains(uaLower, "cros"):
		os = "ChromeOS"
		deviceType = "desktop"
	default:
		os = "Unknown"
		deviceType = "unknown"
	}

	return browser, os, deviceType
}

// logAudit creates an audit log entry
func (s *DeviceService) logAudit(ctx context.Context, userID, action, resourceType, resourceID, ipAddress, userAgent string, metadata map[string]interface{}) {
	auditLog := &model.AuditLog{
		ID:           generateID("aud"),
		UserID:       &userID,
		Action:       action,
		ResourceType: &resourceType,
		ResourceID:   &resourceID,
		IPAddress:    &ipAddress,
		UserAgent:    &userAgent,
		Metadata:     metadata,
		CreatedAt:    time.Now(),
	}

	if err := s.auditRepo.Create(ctx, auditLog); err != nil {
		s.log.Error().Err(err).Str("action", action).Msg("failed to create audit log")
	}
}
