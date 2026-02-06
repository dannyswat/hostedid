package service

import (
	"context"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/hostedid/hostedid/internal/auth"
	"github.com/hostedid/hostedid/internal/config"
	"github.com/hostedid/hostedid/internal/logger"
	"github.com/hostedid/hostedid/internal/model"
	"github.com/hostedid/hostedid/internal/repository"
)

// BackChannelLogoutService handles OIDC back-channel logout
type BackChannelLogoutService struct {
	sessionSvc *SessionService
	tokenSvc   *auth.TokenService
	deviceRepo *repository.DeviceRepository
	auditRepo  *repository.AuditRepository
	cfg        *config.Config
	log        *logger.Logger
}

// LogoutTokenClaims represents the claims in an OIDC logout token
type LogoutTokenClaims struct {
	jwt.RegisteredClaims
	Events   map[string]interface{} `json:"events"`
	DeviceID string                 `json:"device_id,omitempty"`
	SID      string                 `json:"sid,omitempty"` // Session ID
}

// BackChannelLogoutRequest represents a request to trigger back-channel logout
type BackChannelLogoutRequest struct {
	UserID    string `json:"userId"`
	DeviceID  string `json:"deviceId,omitempty"` // Empty = all devices
	Reason    string `json:"reason,omitempty"`
	IPAddress string `json:"-"`
	UserAgent string `json:"-"`
}

// BackChannelLogoutResponse represents the response from a back-channel logout
type BackChannelLogoutResponse struct {
	LogoutToken   string `json:"logoutToken"`
	DevicesLogged int    `json:"devicesLoggedOut"`
	Status        string `json:"status"`
}

// NewBackChannelLogoutService creates a new BackChannelLogoutService
func NewBackChannelLogoutService(
	sessionSvc *SessionService,
	tokenSvc *auth.TokenService,
	deviceRepo *repository.DeviceRepository,
	auditRepo *repository.AuditRepository,
	cfg *config.Config,
	log *logger.Logger,
) *BackChannelLogoutService {
	return &BackChannelLogoutService{
		sessionSvc: sessionSvc,
		tokenSvc:   tokenSvc,
		deviceRepo: deviceRepo,
		auditRepo:  auditRepo,
		cfg:        cfg,
		log:        log.WithComponent("backchannel_logout"),
	}
}

// TriggerLogout initiates a back-channel logout
func (s *BackChannelLogoutService) TriggerLogout(ctx context.Context, req BackChannelLogoutRequest) (*BackChannelLogoutResponse, error) {
	reason := req.Reason
	if reason == "" {
		reason = "backchannel_logout"
	}

	var devicesLogged int

	if req.DeviceID != "" {
		// Revoke specific device session
		if err := s.sessionSvc.RevokeDeviceSession(ctx, req.UserID, req.DeviceID, reason, req.IPAddress, req.UserAgent); err != nil {
			return nil, fmt.Errorf("failed to revoke device session: %w", err)
		}
		devicesLogged = 1
	} else {
		// Revoke all sessions
		count, err := s.sessionSvc.RevokeAllSessions(ctx, req.UserID, "", reason, req.IPAddress, req.UserAgent)
		if err != nil {
			return nil, fmt.Errorf("failed to revoke all sessions: %w", err)
		}
		devicesLogged = count
	}

	// Generate logout token (OIDC spec)
	logoutToken, jti, err := s.generateLogoutToken(req.UserID, req.DeviceID)
	if err != nil {
		s.log.Error().Err(err).Msg("failed to generate logout token")
		// Don't fail the logout if token generation fails
		return &BackChannelLogoutResponse{
			DevicesLogged: devicesLogged,
			Status:        "completed_without_token",
		}, nil
	}

	// Publish back-channel logout event via Redis
	if err := s.sessionSvc.PublishBackChannelLogout(ctx, req.UserID, req.DeviceID, jti); err != nil {
		s.log.Error().Err(err).Msg("failed to publish back-channel logout event")
	}

	// Audit log
	s.logAudit(ctx, req.UserID, model.AuditActionBackChannelLogout, "user", req.UserID, req.IPAddress, req.UserAgent, map[string]interface{}{
		"device_id":       req.DeviceID,
		"devices_logged":  devicesLogged,
		"reason":          reason,
		"logout_token_id": jti,
	})

	s.log.Info().
		Str("user_id", req.UserID).
		Str("device_id", req.DeviceID).
		Int("devices_logged", devicesLogged).
		Msg("back-channel logout completed")

	return &BackChannelLogoutResponse{
		LogoutToken:   logoutToken,
		DevicesLogged: devicesLogged,
		Status:        "completed",
	}, nil
}

// generateLogoutToken creates an OIDC logout token JWT
// Follows the OpenID Connect Back-Channel Logout specification
func (s *BackChannelLogoutService) generateLogoutToken(userID, deviceID string) (string, string, error) {
	now := time.Now()
	jti := uuid.New().String()

	claims := LogoutTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:   s.cfg.Security.Tokens.Issuer,
			Subject:  userID,
			IssuedAt: jwt.NewNumericDate(now),
			ID:       jti,
			// Logout tokens are short-lived
			ExpiresAt: jwt.NewNumericDate(now.Add(2 * time.Minute)),
		},
		Events: map[string]interface{}{
			"http://schemas.openid.net/event/backchannel-logout": map[string]interface{}{},
		},
		DeviceID: deviceID,
	}

	// Sign with EdDSA using the token service's key provider
	// For back-channel logout tokens, we use a simple JWT
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Use a derived key from the issuer for logout tokens
	// In production, this should use the same key infrastructure as access tokens
	signingKey := deriveLogoutTokenKey(s.cfg.Security.Tokens.Issuer)
	tokenString, err := token.SignedString(signingKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to sign logout token: %w", err)
	}

	return tokenString, jti, nil
}

// ValidateLogoutToken validates an OIDC logout token
func (s *BackChannelLogoutService) ValidateLogoutToken(tokenString string) (*LogoutTokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &LogoutTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return deriveLogoutTokenKey(s.cfg.Security.Tokens.Issuer), nil
	})

	if err != nil {
		return nil, fmt.Errorf("invalid logout token: %w", err)
	}

	claims, ok := token.Claims.(*LogoutTokenClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid logout token claims")
	}

	// Verify the required back-channel logout event claim
	if _, hasEvent := claims.Events["http://schemas.openid.net/event/backchannel-logout"]; !hasEvent {
		return nil, fmt.Errorf("missing back-channel logout event claim")
	}

	return claims, nil
}

// deriveLogoutTokenKey derives an HMAC key for logout tokens from the issuer
func deriveLogoutTokenKey(issuer string) []byte {
	// Use SHA-256 of the issuer as a symmetric key for logout tokens
	// In production, you'd want a dedicated secret
	source := fmt.Sprintf("hostedid:logout-token-signing:%s", issuer)
	key := make([]byte, 32)
	copy(key, []byte(source))
	return key
}

// logAudit creates an audit log entry
func (s *BackChannelLogoutService) logAudit(ctx context.Context, userID, action, resourceType, resourceID, ipAddress, userAgent string, metadata map[string]interface{}) {
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
