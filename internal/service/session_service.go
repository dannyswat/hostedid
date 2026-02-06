package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/hostedid/hostedid/internal/config"
	"github.com/hostedid/hostedid/internal/database"
	"github.com/hostedid/hostedid/internal/logger"
	"github.com/hostedid/hostedid/internal/model"
	"github.com/hostedid/hostedid/internal/repository"
)

// Session service errors
var (
	ErrSessionNotFound = errors.New("session not found")
	ErrSessionExpired  = errors.New("session has expired")
)

// Redis channels for back-channel logout
const (
	LogoutChannel     = "hostedid:logout"
	LogoutAllChannel  = "hostedid:logout:all"
	SessionExpChannel = "hostedid:session:expired"
)

// LogoutEvent represents a logout event published to Redis
type LogoutEvent struct {
	Type      string `json:"type"`      // "device", "user", "backchannel"
	UserID    string `json:"userId"`    // User being logged out
	DeviceID  string `json:"deviceId"`  // Specific device (empty for all-device logout)
	SessionID string `json:"sessionId"` // Session ID if applicable
	Reason    string `json:"reason"`    // Reason for logout
	Timestamp int64  `json:"timestamp"` // Unix timestamp
	TokenJTI  string `json:"tokenJti"`  // JWT ID of the logout token
}

// SessionInfo represents detailed session information
type SessionInfo struct {
	DeviceID     string     `json:"deviceId"`
	DeviceName   string     `json:"deviceName"`
	DeviceType   string     `json:"deviceType"`
	Browser      string     `json:"browser"`
	OS           string     `json:"os"`
	IPAddress    string     `json:"ipAddress"`
	Location     *string    `json:"location,omitempty"`
	IsActive     bool       `json:"isActive"`
	IsCurrent    bool       `json:"isCurrent"`
	IsTrusted    bool       `json:"isTrusted"`
	StartedAt    *time.Time `json:"startedAt,omitempty"`
	ExpiresAt    *time.Time `json:"expiresAt,omitempty"`
	LastActivity time.Time  `json:"lastActivity"`
	FirstSeen    time.Time  `json:"firstSeen"`
	CreatedAt    time.Time  `json:"createdAt"`
}

// SessionSummary represents a summary of user sessions
type SessionSummary struct {
	TotalDevices   int           `json:"totalDevices"`
	ActiveSessions int           `json:"activeSessions"`
	TrustedDevices int           `json:"trustedDevices"`
	Sessions       []SessionInfo `json:"sessions"`
}

// SessionService handles session tracking and back-channel logout
type SessionService struct {
	deviceRepo *repository.DeviceRepository
	tokenRepo  *repository.TokenRepository
	auditRepo  *repository.AuditRepository
	rdb        *database.Redis
	cfg        *config.Config
	log        *logger.Logger
}

// NewSessionService creates a new SessionService
func NewSessionService(
	deviceRepo *repository.DeviceRepository,
	tokenRepo *repository.TokenRepository,
	auditRepo *repository.AuditRepository,
	rdb *database.Redis,
	cfg *config.Config,
	log *logger.Logger,
) *SessionService {
	return &SessionService{
		deviceRepo: deviceRepo,
		tokenRepo:  tokenRepo,
		auditRepo:  auditRepo,
		rdb:        rdb,
		cfg:        cfg,
		log:        log.WithComponent("session_service"),
	}
}

// GetUserSessions returns all sessions for a user with detailed metadata
func (s *SessionService) GetUserSessions(ctx context.Context, userID, currentDeviceID string) (*SessionSummary, error) {
	devices, err := s.deviceRepo.GetByUserID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user devices: %w", err)
	}

	summary := &SessionSummary{
		TotalDevices: len(devices),
		Sessions:     make([]SessionInfo, 0, len(devices)),
	}

	for _, d := range devices {
		browser, os, deviceType := parseUserAgentDetails(d.UserAgent)

		name := "Unknown Device"
		if d.Name != nil {
			name = *d.Name
		}

		ip := ""
		if d.CurrentIP != nil {
			ip = *d.CurrentIP
		}

		isCurrent := currentDeviceID != "" && d.ID == currentDeviceID

		info := SessionInfo{
			DeviceID:     d.ID,
			DeviceName:   name,
			DeviceType:   deviceType,
			Browser:      browser,
			OS:           os,
			IPAddress:    ip,
			Location:     d.CurrentLocation,
			IsActive:     d.SessionActive,
			IsCurrent:    isCurrent,
			IsTrusted:    d.IsTrusted,
			StartedAt:    d.SessionStartedAt,
			ExpiresAt:    d.SessionExpiresAt,
			LastActivity: d.LastActivity,
			FirstSeen:    d.FirstSeen,
			CreatedAt:    d.CreatedAt,
		}

		if d.SessionActive {
			summary.ActiveSessions++
		}
		if d.IsTrusted {
			summary.TrustedDevices++
		}

		summary.Sessions = append(summary.Sessions, info)
	}

	return summary, nil
}

// GetSessionByDevice returns session info for a specific device
func (s *SessionService) GetSessionByDevice(ctx context.Context, userID, deviceID string) (*SessionInfo, error) {
	device, err := s.deviceRepo.GetByID(ctx, deviceID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrSessionNotFound
		}
		return nil, fmt.Errorf("failed to get device: %w", err)
	}

	if device.UserID != userID {
		return nil, ErrDeviceNotOwned
	}

	browser, os, deviceType := parseUserAgentDetails(device.UserAgent)

	name := "Unknown Device"
	if device.Name != nil {
		name = *device.Name
	}

	ip := ""
	if device.CurrentIP != nil {
		ip = *device.CurrentIP
	}

	return &SessionInfo{
		DeviceID:     device.ID,
		DeviceName:   name,
		DeviceType:   deviceType,
		Browser:      browser,
		OS:           os,
		IPAddress:    ip,
		Location:     device.CurrentLocation,
		IsActive:     device.SessionActive,
		IsCurrent:    false,
		IsTrusted:    device.IsTrusted,
		StartedAt:    device.SessionStartedAt,
		ExpiresAt:    device.SessionExpiresAt,
		LastActivity: device.LastActivity,
		FirstSeen:    device.FirstSeen,
		CreatedAt:    device.CreatedAt,
	}, nil
}

// UpdateSessionActivity updates the last activity and IP for a device session
func (s *SessionService) UpdateSessionActivity(ctx context.Context, deviceID, ipAddress string) error {
	device, err := s.deviceRepo.GetByID(ctx, deviceID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil // silently ignore unknown devices
		}
		return fmt.Errorf("failed to get device: %w", err)
	}

	if !device.SessionActive {
		return nil // no active session to update
	}

	// Check if session has expired
	if device.SessionExpiresAt != nil && time.Now().After(*device.SessionExpiresAt) {
		// Session expired, deactivate it
		if err := s.deviceRepo.UpdateSession(ctx, deviceID, false, nil, nil, nil); err != nil {
			s.log.Error().Err(err).Str("device_id", deviceID).Msg("failed to deactivate expired session")
		}
		return ErrSessionExpired
	}

	// Update last activity and IP
	now := time.Now()
	if err := s.deviceRepo.UpdateSession(ctx, deviceID, true, device.SessionStartedAt, device.SessionExpiresAt, &ipAddress); err != nil {
		return fmt.Errorf("failed to update session activity: %w", err)
	}

	// Also update last_activity directly
	if err := s.deviceRepo.UpdateLastActivity(ctx, deviceID, now); err != nil {
		s.log.Error().Err(err).Str("device_id", deviceID).Msg("failed to update last activity")
	}

	return nil
}

// RevokeDeviceSession revokes the session for a specific device and publishes an event
func (s *SessionService) RevokeDeviceSession(ctx context.Context, userID, deviceID, reason, ipAddress, userAgent string) error {
	device, err := s.deviceRepo.GetByID(ctx, deviceID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return ErrSessionNotFound
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

	// Revoke refresh tokens
	if err := s.tokenRepo.RevokeRefreshTokenByDeviceID(ctx, deviceID); err != nil {
		s.log.Error().Err(err).Str("device_id", deviceID).Msg("failed to revoke device tokens")
	}

	// Publish logout event to Redis
	event := LogoutEvent{
		Type:      "device",
		UserID:    userID,
		DeviceID:  deviceID,
		Reason:    reason,
		Timestamp: time.Now().Unix(),
	}
	s.publishLogoutEvent(ctx, event)

	// Audit log
	s.logAudit(ctx, userID, model.AuditActionSessionRevoked, "device", deviceID, ipAddress, userAgent, map[string]interface{}{
		"device_id": deviceID,
		"reason":    reason,
	})

	s.log.Info().Str("user_id", userID).Str("device_id", deviceID).Str("reason", reason).Msg("device session revoked")

	return nil
}

// RevokeAllSessions revokes all sessions for a user and publishes events
func (s *SessionService) RevokeAllSessions(ctx context.Context, userID, excludeDeviceID, reason, ipAddress, userAgent string) (int, error) {
	devices, err := s.deviceRepo.GetByUserID(ctx, userID)
	if err != nil {
		return 0, fmt.Errorf("failed to get user devices: %w", err)
	}

	revokedCount := 0
	for _, d := range devices {
		if d.ID == excludeDeviceID {
			continue
		}
		if !d.SessionActive {
			continue
		}

		// Deactivate session
		if err := s.deviceRepo.UpdateSession(ctx, d.ID, false, nil, nil, nil); err != nil {
			s.log.Error().Err(err).Str("device_id", d.ID).Msg("failed to deactivate session")
			continue
		}

		// Revoke refresh tokens
		if err := s.tokenRepo.RevokeRefreshTokenByDeviceID(ctx, d.ID); err != nil {
			s.log.Error().Err(err).Str("device_id", d.ID).Msg("failed to revoke device tokens")
		}

		// Publish per-device logout event
		event := LogoutEvent{
			Type:      "device",
			UserID:    userID,
			DeviceID:  d.ID,
			Reason:    reason,
			Timestamp: time.Now().Unix(),
		}
		s.publishLogoutEvent(ctx, event)

		revokedCount++
	}

	// Also publish a user-level logout event
	event := LogoutEvent{
		Type:      "user",
		UserID:    userID,
		Reason:    reason,
		Timestamp: time.Now().Unix(),
	}
	s.publishLogoutEvent(ctx, event)

	// Audit log
	s.logAudit(ctx, userID, model.AuditActionSessionRevokedAll, "user", userID, ipAddress, userAgent, map[string]interface{}{
		"revoked_count":   revokedCount,
		"excluded_device": excludeDeviceID,
		"reason":          reason,
	})

	s.log.Info().Str("user_id", userID).Int("revoked", revokedCount).Msg("all sessions revoked")

	return revokedCount, nil
}

// PublishBackChannelLogout publishes a back-channel logout event for OIDC clients
func (s *SessionService) PublishBackChannelLogout(ctx context.Context, userID, deviceID, tokenJTI string) error {
	event := LogoutEvent{
		Type:      "backchannel",
		UserID:    userID,
		DeviceID:  deviceID,
		TokenJTI:  tokenJTI,
		Reason:    "backchannel_logout",
		Timestamp: time.Now().Unix(),
	}

	return s.publishLogoutEvent(ctx, event)
}

// SubscribeToLogoutEvents returns a channel that receives logout events
// This is used by application servers subscribing to back-channel logout
func (s *SessionService) SubscribeToLogoutEvents(ctx context.Context) (<-chan LogoutEvent, func(), error) {
	pubsub := s.rdb.Subscribe(ctx, LogoutChannel, LogoutAllChannel)

	eventCh := make(chan LogoutEvent, 100)

	go func() {
		defer close(eventCh)
		ch := pubsub.Channel()
		for msg := range ch {
			var event LogoutEvent
			if err := json.Unmarshal([]byte(msg.Payload), &event); err != nil {
				s.log.Error().Err(err).Msg("failed to unmarshal logout event")
				continue
			}
			select {
			case eventCh <- event:
			default:
				s.log.Warn().Msg("logout event channel full, dropping event")
			}
		}
	}()

	cleanup := func() {
		pubsub.Close()
	}

	return eventCh, cleanup, nil
}

// CheckExpiredSessions checks for expired sessions and deactivates them
func (s *SessionService) CheckExpiredSessions(ctx context.Context) (int, error) {
	// This could be called periodically by a background worker
	// For now, we check per-user on access
	return 0, nil
}

// publishLogoutEvent publishes a logout event to the Redis pub/sub channel
func (s *SessionService) publishLogoutEvent(ctx context.Context, event LogoutEvent) error {
	data, err := json.Marshal(event)
	if err != nil {
		s.log.Error().Err(err).Msg("failed to marshal logout event")
		return fmt.Errorf("failed to marshal logout event: %w", err)
	}

	channel := LogoutChannel
	if event.Type == "user" {
		channel = LogoutAllChannel
	}

	if err := s.rdb.Publish(ctx, channel, string(data)); err != nil {
		s.log.Error().Err(err).Str("channel", channel).Msg("failed to publish logout event")
		return fmt.Errorf("failed to publish logout event: %w", err)
	}

	s.log.Debug().
		Str("type", event.Type).
		Str("user_id", event.UserID).
		Str("device_id", event.DeviceID).
		Str("channel", channel).
		Msg("logout event published")

	return nil
}

// logAudit creates an audit log entry
func (s *SessionService) logAudit(ctx context.Context, userID, action, resourceType, resourceID, ipAddress, userAgent string, metadata map[string]interface{}) {
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
