package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/hostedid/hostedid/internal/auth"
	"github.com/hostedid/hostedid/internal/config"
	"github.com/hostedid/hostedid/internal/logger"
	"github.com/hostedid/hostedid/internal/model"
	"github.com/hostedid/hostedid/internal/repository"
)

// Common service errors
var (
	ErrInvalidCredentials   = errors.New("invalid email or password")
	ErrAccountLocked        = errors.New("account is temporarily locked")
	ErrAccountNotActive     = errors.New("account is not active")
	ErrEmailAlreadyExists   = errors.New("email already registered")
	ErrPasswordTooWeak      = errors.New("password does not meet requirements")
	ErrInvalidToken         = errors.New("invalid or expired token")
	ErrTokenRevoked         = errors.New("token has been revoked")
	ErrResetTokenExpired    = errors.New("password reset token has expired")
	ErrResetTokenUsed       = errors.New("password reset token has already been used")
	ErrSamePassword         = errors.New("new password must be different from current password")
	ErrTooManyResetAttempts = errors.New("too many password reset requests")
	ErrMFARequired          = errors.New("MFA verification required")
)

// AuthService handles authentication business logic
type AuthService struct {
	userRepo          *repository.UserRepository
	tokenRepo         *repository.TokenRepository
	deviceRepo        *repository.DeviceRepository
	auditRepo         *repository.AuditRepository
	passwordResetRepo *repository.PasswordResetRepository
	mfaRepo           *repository.MFARepository
	tokenSvc          *auth.TokenService
	argonParams       *auth.Argon2Params
	cfg               *config.Config
	log               *logger.Logger
}

// NewAuthService creates a new AuthService
func NewAuthService(
	userRepo *repository.UserRepository,
	tokenRepo *repository.TokenRepository,
	deviceRepo *repository.DeviceRepository,
	auditRepo *repository.AuditRepository,
	passwordResetRepo *repository.PasswordResetRepository,
	mfaRepo *repository.MFARepository,
	tokenSvc *auth.TokenService,
	cfg *config.Config,
	log *logger.Logger,
) *AuthService {
	return &AuthService{
		userRepo:          userRepo,
		tokenRepo:         tokenRepo,
		deviceRepo:        deviceRepo,
		auditRepo:         auditRepo,
		passwordResetRepo: passwordResetRepo,
		mfaRepo:           mfaRepo,
		tokenSvc:          tokenSvc,
		argonParams: auth.NewParams(
			cfg.Security.Password.Argon2Memory,
			cfg.Security.Password.Argon2Iterations,
			cfg.Security.Password.Argon2Parallelism,
		),
		cfg: cfg,
		log: log.WithComponent("auth_service"),
	}
}

// RegisterRequest contains the data for registering a new user
type RegisterRequest struct {
	Email       string
	Password    string
	DisplayName string
	Locale      string
	Timezone    string
}

// RegisterResponse contains the response from a registration
type RegisterResponse struct {
	UserID             string    `json:"userId"`
	Email              string    `json:"email"`
	Status             string    `json:"status"`
	VerificationSentAt time.Time `json:"verificationSentAt"`
}

// Register creates a new user account
func (s *AuthService) Register(ctx context.Context, req RegisterRequest) (*RegisterResponse, error) {
	// Validate email format
	if !isValidEmail(req.Email) {
		return nil, fmt.Errorf("invalid email format")
	}

	// Normalize email
	email := strings.ToLower(strings.TrimSpace(req.Email))

	// Check email uniqueness
	exists, err := s.userRepo.ExistsByEmail(ctx, email)
	if err != nil {
		return nil, fmt.Errorf("failed to check email: %w", err)
	}
	if exists {
		return nil, ErrEmailAlreadyExists
	}

	// Validate password
	if err := auth.ValidatePassword(req.Password, s.cfg.Security.Password.MinLength); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrPasswordTooWeak, err.Error())
	}

	// Hash password
	passwordHash, err := auth.HashPassword(req.Password, s.argonParams)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Generate user ID
	now := time.Now()
	userID := generateID("usr")

	// Create user
	user := &model.User{
		ID:            userID,
		Email:         email,
		EmailVerified: false,
		PasswordHash:  passwordHash,
		Status:        model.UserStatusPendingVerification,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	if err := s.userRepo.Create(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Create user profile
	profile := &model.UserProfile{
		UserID:    userID,
		Locale:    defaultString(req.Locale, "en-US"),
		Timezone:  defaultString(req.Timezone, "UTC"),
		Metadata:  map[string]interface{}{},
		CreatedAt: now,
		UpdatedAt: now,
	}
	if req.DisplayName != "" {
		profile.DisplayName = &req.DisplayName
	}

	if err := s.userRepo.CreateProfile(ctx, profile); err != nil {
		s.log.Error().Err(err).Str("user_id", userID).Msg("failed to create user profile")
		// Don't fail registration if profile creation fails
	}

	s.log.Info().Str("user_id", userID).Str("email", email).Msg("user registered")

	return &RegisterResponse{
		UserID:             userID,
		Email:              email,
		Status:             string(model.UserStatusPendingVerification),
		VerificationSentAt: now,
	}, nil
}

// LoginRequest contains the data for logging in
type LoginRequest struct {
	Email             string
	Password          string
	DeviceFingerprint string
	UserAgent         string
	IPAddress         string
}

// LoginResponse contains the response from a login
type LoginResponse struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	IDToken      string `json:"idToken"`
	TokenType    string `json:"tokenType"`
	ExpiresIn    int    `json:"expiresIn"`
	DeviceID     string `json:"deviceId"`
}

// MFAChallengeResponse is returned when MFA is required during login
type MFAChallengeResponse struct {
	Status           string                `json:"status"`
	MFAToken         string                `json:"mfaToken"`
	AvailableMethods []model.MFAMethodType `json:"availableMethods"`
	PreferredMethod  *model.MFAMethodType  `json:"preferredMethod,omitempty"`
}

// LoginResult wraps either a successful login or an MFA challenge
type LoginResult struct {
	// Success is set when login is complete (no MFA required or MFA already passed)
	Success *LoginResponse `json:"success,omitempty"`
	// MFAChallenge is set when MFA verification is required
	MFAChallenge *MFAChallengeResponse `json:"mfaChallenge,omitempty"`
}

// Login authenticates a user and returns tokens or an MFA challenge
func (s *AuthService) Login(ctx context.Context, req LoginRequest) (*LoginResult, error) {
	email := strings.ToLower(strings.TrimSpace(req.Email))

	// Get user by email
	user, err := s.userRepo.GetByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Check if account is locked
	if user.IsLocked() {
		s.logAudit(ctx, user.ID, model.AuditActionLoginFailed, "user", user.ID, req.IPAddress, req.UserAgent, map[string]interface{}{
			"reason": "account_locked",
		})
		return nil, ErrAccountLocked
	}

	// Verify password
	match, err := auth.VerifyPassword(req.Password, user.PasswordHash)
	if err != nil {
		return nil, fmt.Errorf("failed to verify password: %w", err)
	}
	if !match {
		// Increment failed attempts
		attempts, _ := s.userRepo.IncrementFailedAttempts(ctx, user.ID)
		s.handleFailedLogin(ctx, user.ID, attempts)
		s.logAudit(ctx, user.ID, model.AuditActionLoginFailed, "user", user.ID, req.IPAddress, req.UserAgent, map[string]interface{}{
			"reason":          "invalid_password",
			"failed_attempts": attempts,
		})
		return nil, ErrInvalidCredentials
	}

	// Check if account status allows login
	if user.Status != model.UserStatusActive && user.Status != model.UserStatusPendingVerification {
		return nil, ErrAccountNotActive
	}

	// Reset failed attempts on successful login
	if err := s.userRepo.ResetFailedAttempts(ctx, user.ID); err != nil {
		s.log.Error().Err(err).Str("user_id", user.ID).Msg("failed to reset failed attempts")
	}

	// Check if user has MFA enabled
	if s.mfaRepo != nil {
		hasMFA, err := s.mfaRepo.HasAnyMethod(ctx, user.ID)
		if err != nil {
			s.log.Error().Err(err).Str("user_id", user.ID).Msg("failed to check MFA status")
		}
		if hasMFA {
			// MFA is required - return a challenge instead of tokens
			s.logAudit(ctx, user.ID, model.AuditActionLogin, "user", user.ID, req.IPAddress, req.UserAgent, map[string]interface{}{
				"mfa_required": true,
			})
			return &LoginResult{
				MFAChallenge: &MFAChallengeResponse{
					Status: "mfa_required",
				},
			}, ErrMFARequired
		}
	}

	// Handle device
	deviceID, err := s.handleDevice(ctx, user.ID, req)
	if err != nil {
		return nil, fmt.Errorf("failed to handle device: %w", err)
	}

	// Generate tokens
	tokenPair, refreshTokenHash, err := s.tokenSvc.GenerateTokenPair(user.ID, user.Email, deviceID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	// Store refresh token
	now := time.Now()
	refreshToken := &model.RefreshToken{
		ID:        generateID("rt"),
		UserID:    user.ID,
		TokenHash: refreshTokenHash,
		DeviceID:  deviceID,
		ExpiresAt: now.Add(s.tokenSvc.GetRefreshTokenTTL()),
		CreatedAt: now,
	}

	if err := s.tokenRepo.CreateRefreshToken(ctx, refreshToken); err != nil {
		return nil, fmt.Errorf("failed to store refresh token: %w", err)
	}

	// Audit log
	s.logAudit(ctx, user.ID, model.AuditActionLogin, "user", user.ID, req.IPAddress, req.UserAgent, map[string]interface{}{
		"device_id": deviceID,
	})

	s.log.Info().Str("user_id", user.ID).Str("device_id", deviceID).Msg("user logged in")

	return &LoginResult{
		Success: &LoginResponse{
			AccessToken:  tokenPair.AccessToken,
			RefreshToken: tokenPair.RefreshToken,
			IDToken:      tokenPair.IDToken,
			TokenType:    tokenPair.TokenType,
			ExpiresIn:    tokenPair.ExpiresIn,
			DeviceID:     deviceID,
		},
	}, nil
}

// RefreshTokens refreshes an access token using a refresh token
func (s *AuthService) RefreshTokens(ctx context.Context, refreshTokenRaw string) (*LoginResponse, error) {
	// Hash the provided token
	tokenHash := auth.HashToken(refreshTokenRaw)

	// Look up the stored token
	storedToken, err := s.tokenRepo.GetRefreshTokenByHash(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrInvalidToken
		}
		return nil, fmt.Errorf("failed to get refresh token: %w", err)
	}

	// Validate the token
	if storedToken.IsRevoked() {
		return nil, ErrTokenRevoked
	}
	if storedToken.IsExpired() {
		return nil, ErrInvalidToken
	}

	// Get the user
	user, err := s.userRepo.GetByID(ctx, storedToken.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Revoke the old refresh token (token rotation)
	if err := s.tokenRepo.RevokeRefreshToken(ctx, storedToken.ID); err != nil {
		s.log.Error().Err(err).Msg("failed to revoke old refresh token")
	}

	// Generate new tokens
	tokenPair, newRefreshHash, err := s.tokenSvc.GenerateTokenPair(user.ID, user.Email, storedToken.DeviceID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	// Store the new refresh token
	now := time.Now()
	newRefreshToken := &model.RefreshToken{
		ID:        generateID("rt"),
		UserID:    user.ID,
		TokenHash: newRefreshHash,
		DeviceID:  storedToken.DeviceID,
		ExpiresAt: now.Add(s.tokenSvc.GetRefreshTokenTTL()),
		CreatedAt: now,
	}

	if err := s.tokenRepo.CreateRefreshToken(ctx, newRefreshToken); err != nil {
		return nil, fmt.Errorf("failed to store refresh token: %w", err)
	}

	return &LoginResponse{
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
		IDToken:      tokenPair.IDToken,
		TokenType:    tokenPair.TokenType,
		ExpiresIn:    tokenPair.ExpiresIn,
		DeviceID:     storedToken.DeviceID,
	}, nil
}

// Logout revokes the user's session and tokens for a given device
func (s *AuthService) Logout(ctx context.Context, userID, deviceID, ipAddress, userAgent string) error {
	// Revoke refresh tokens for the device
	if err := s.tokenRepo.RevokeRefreshTokenByDeviceID(ctx, deviceID); err != nil {
		s.log.Error().Err(err).Str("device_id", deviceID).Msg("failed to revoke device refresh tokens")
	}

	// Deactivate device session
	if err := s.deviceRepo.UpdateSession(ctx, deviceID, false, nil, nil, nil); err != nil {
		s.log.Error().Err(err).Str("device_id", deviceID).Msg("failed to deactivate device session")
	}

	// Audit log
	s.logAudit(ctx, userID, model.AuditActionLogout, "user", userID, ipAddress, userAgent, map[string]interface{}{
		"device_id": deviceID,
	})

	return nil
}

// LogoutAll revokes all sessions and tokens for a user
func (s *AuthService) LogoutAll(ctx context.Context, userID, ipAddress, userAgent string) error {
	// Revoke all refresh tokens
	if err := s.tokenRepo.RevokeAllUserRefreshTokens(ctx, userID); err != nil {
		s.log.Error().Err(err).Str("user_id", userID).Msg("failed to revoke all refresh tokens")
	}

	// Deactivate all device sessions
	if err := s.deviceRepo.DeactivateAllUserSessions(ctx, userID); err != nil {
		s.log.Error().Err(err).Str("user_id", userID).Msg("failed to deactivate all sessions")
	}

	// Audit log
	s.logAudit(ctx, userID, model.AuditActionLogout, "user", userID, ipAddress, userAgent, map[string]interface{}{
		"scope": "all_sessions",
	})

	return nil
}

// GetCurrentUser returns the user with their profile
func (s *AuthService) GetCurrentUser(ctx context.Context, userID string) (*model.UserWithProfile, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	profile, err := s.userRepo.GetProfile(ctx, userID)
	if err != nil {
		s.log.Error().Err(err).Str("user_id", userID).Msg("failed to get user profile")
	}

	return &model.UserWithProfile{
		User:    *user,
		Profile: profile,
	}, nil
}

// GetUserByEmail returns a user by email
func (s *AuthService) GetUserByEmail(ctx context.Context, email string) (*model.User, error) {
	normalizedEmail := strings.ToLower(strings.TrimSpace(email))
	return s.userRepo.GetByEmail(ctx, normalizedEmail)
}

// ValidateAccessToken validates an access token and returns the claims
func (s *AuthService) ValidateAccessToken(tokenString string) (*auth.TokenClaims, error) {
	return s.tokenSvc.ValidateAccessToken(tokenString)
}

// CompleteMFALogin issues tokens after successful MFA verification
func (s *AuthService) CompleteMFALogin(ctx context.Context, userID, ipAddress, userAgent string) (*LoginResponse, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Handle device
	deviceReq := LoginRequest{
		UserAgent: userAgent,
		IPAddress: ipAddress,
	}
	deviceID, err := s.handleDevice(ctx, userID, deviceReq)
	if err != nil {
		return nil, fmt.Errorf("failed to handle device: %w", err)
	}

	// Generate tokens
	tokenPair, refreshTokenHash, err := s.tokenSvc.GenerateTokenPair(user.ID, user.Email, deviceID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	// Store refresh token
	now := time.Now()
	refreshToken := &model.RefreshToken{
		ID:        generateID("rt"),
		UserID:    user.ID,
		TokenHash: refreshTokenHash,
		DeviceID:  deviceID,
		ExpiresAt: now.Add(s.tokenSvc.GetRefreshTokenTTL()),
		CreatedAt: now,
	}

	if err := s.tokenRepo.CreateRefreshToken(ctx, refreshToken); err != nil {
		return nil, fmt.Errorf("failed to store refresh token: %w", err)
	}

	// Audit log
	s.logAudit(ctx, user.ID, model.AuditActionLogin, "user", user.ID, ipAddress, userAgent, map[string]interface{}{
		"device_id":    deviceID,
		"mfa_verified": true,
	})

	s.log.Info().Str("user_id", user.ID).Str("device_id", deviceID).Msg("user logged in (MFA verified)")

	return &LoginResponse{
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
		IDToken:      tokenPair.IDToken,
		TokenType:    tokenPair.TokenType,
		ExpiresIn:    tokenPair.ExpiresIn,
		DeviceID:     deviceID,
	}, nil
}

// LogAudit is a public wrapper around logAudit for use by handlers
func (s *AuthService) LogAudit(ctx context.Context, userID, action, resourceType, resourceID, ipAddress, userAgent string, metadata map[string]interface{}) {
	s.logAudit(ctx, userID, action, resourceType, resourceID, ipAddress, userAgent, metadata)
}

// --- Password Reset ---

// PasswordResetResponse contains the response from a password reset request
type PasswordResetResponse struct {
	Message string `json:"message"`
}

// RequestPasswordReset initiates a password reset flow
// Always returns success to prevent email enumeration
func (s *AuthService) RequestPasswordReset(ctx context.Context, email, ipAddress, userAgent string) (*PasswordResetResponse, error) {
	normalizedEmail := strings.ToLower(strings.TrimSpace(email))

	// Always return the same response to prevent email enumeration
	successResp := &PasswordResetResponse{
		Message: "If an account with that email exists, a password reset link has been sent.",
	}

	// Look up user - if not found, return success anyway
	user, err := s.userRepo.GetByEmail(ctx, normalizedEmail)
	if err != nil {
		s.log.Debug().Str("email", normalizedEmail).Msg("password reset requested for non-existent email")
		return successResp, nil
	}

	// Rate limit: max 3 reset requests per hour per user
	recentCount, err := s.passwordResetRepo.CountRecentByUserID(ctx, user.ID, time.Now().Add(-1*time.Hour))
	if err != nil {
		s.log.Error().Err(err).Str("user_id", user.ID).Msg("failed to count recent reset tokens")
		return nil, fmt.Errorf("failed to process request: %w", err)
	}
	if recentCount >= 3 {
		s.log.Warn().Str("user_id", user.ID).Int("count", recentCount).Msg("too many password reset requests")
		// Still return success to prevent enumeration
		return successResp, nil
	}

	// Invalidate any existing unused tokens
	if err := s.passwordResetRepo.InvalidateAllForUser(ctx, user.ID); err != nil {
		s.log.Error().Err(err).Msg("failed to invalidate existing reset tokens")
	}

	// Generate secure reset token (32 bytes)
	tokenRaw, err := generateSecureToken(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate reset token: %w", err)
	}

	tokenHash := auth.HashToken(tokenRaw)
	now := time.Now()

	resetToken := &model.PasswordResetToken{
		ID:        generateID("prt"),
		UserID:    user.ID,
		TokenHash: tokenHash,
		ExpiresAt: now.Add(1 * time.Hour), // 1 hour expiry per spec
		CreatedAt: now,
	}

	if err := s.passwordResetRepo.Create(ctx, resetToken); err != nil {
		return nil, fmt.Errorf("failed to store reset token: %w", err)
	}

	// Audit log
	s.logAudit(ctx, user.ID, model.AuditActionPasswordResetRequest, "user", user.ID, ipAddress, userAgent, map[string]interface{}{
		"token_id": resetToken.ID,
	})

	// TODO: Send reset email with token
	// For now, log the token in development mode
	s.log.Info().
		Str("user_id", user.ID).
		Str("email", normalizedEmail).
		Str("reset_token", tokenRaw).
		Msg("password reset token generated (email sending not implemented)")

	return successResp, nil
}

// CompletePasswordReset completes a password reset using the token
func (s *AuthService) CompletePasswordReset(ctx context.Context, tokenRaw, newPassword, ipAddress, userAgent string) error {
	// Hash the provided token to look it up
	tokenHash := auth.HashToken(tokenRaw)

	// Look up the stored token
	storedToken, err := s.passwordResetRepo.GetByTokenHash(ctx, tokenHash)
	if err != nil {
		return ErrInvalidToken
	}

	// Check if token is already used
	if storedToken.IsUsed() {
		return ErrResetTokenUsed
	}

	// Check if token is expired
	if storedToken.IsExpired() {
		return ErrResetTokenExpired
	}

	// Validate the new password
	if err := auth.ValidatePassword(newPassword, s.cfg.Security.Password.MinLength); err != nil {
		return fmt.Errorf("%w: %s", ErrPasswordTooWeak, err.Error())
	}

	// Hash the new password
	passwordHash, err := auth.HashPassword(newPassword, s.argonParams)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Update the password
	if err := s.userRepo.UpdatePasswordHash(ctx, storedToken.UserID, passwordHash); err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	// Mark the reset token as used
	if err := s.passwordResetRepo.MarkUsed(ctx, storedToken.ID); err != nil {
		s.log.Error().Err(err).Msg("failed to mark reset token as used")
	}

	// Invalidate all other reset tokens for this user
	if err := s.passwordResetRepo.InvalidateAllForUser(ctx, storedToken.UserID); err != nil {
		s.log.Error().Err(err).Msg("failed to invalidate other reset tokens")
	}

	// Revoke all refresh tokens (invalidate all sessions) per spec
	if err := s.tokenRepo.RevokeAllUserRefreshTokens(ctx, storedToken.UserID); err != nil {
		s.log.Error().Err(err).Msg("failed to revoke all refresh tokens after password reset")
	}

	// Deactivate all device sessions
	if err := s.deviceRepo.DeactivateAllUserSessions(ctx, storedToken.UserID); err != nil {
		s.log.Error().Err(err).Msg("failed to deactivate all sessions after password reset")
	}

	// Reset failed attempts and unlock account
	if err := s.userRepo.ResetFailedAttempts(ctx, storedToken.UserID); err != nil {
		s.log.Error().Err(err).Msg("failed to reset failed attempts after password reset")
	}

	// If the account was locked, reactivate it
	if err := s.userRepo.UpdateStatus(ctx, storedToken.UserID, model.UserStatusActive); err != nil {
		s.log.Error().Err(err).Msg("failed to reactivate account after password reset")
	}

	// Audit log
	s.logAudit(ctx, storedToken.UserID, model.AuditActionPasswordReset, "user", storedToken.UserID, ipAddress, userAgent, nil)

	s.log.Info().Str("user_id", storedToken.UserID).Msg("password reset completed")

	return nil
}

// --- Change Password ---

// ChangePasswordRequest contains the data for changing a password
type ChangePasswordRequest struct {
	UserID                  string
	CurrentPassword         string
	NewPassword             string
	InvalidateOtherSessions bool
	IPAddress               string
	UserAgent               string
}

// ChangePassword changes a user's password (requires authentication)
func (s *AuthService) ChangePassword(ctx context.Context, req ChangePasswordRequest) error {
	// Get the user
	user, err := s.userRepo.GetByID(ctx, req.UserID)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}

	// Verify current password
	match, err := auth.VerifyPassword(req.CurrentPassword, user.PasswordHash)
	if err != nil {
		return fmt.Errorf("failed to verify password: %w", err)
	}
	if !match {
		s.logAudit(ctx, req.UserID, model.AuditActionPasswordChange, "user", req.UserID, req.IPAddress, req.UserAgent, map[string]interface{}{
			"status": "failed",
			"reason": "invalid_current_password",
		})
		return ErrInvalidCredentials
	}

	// Check new password isn't the same as current
	sameAsOld, err := auth.VerifyPassword(req.NewPassword, user.PasswordHash)
	if err != nil {
		return fmt.Errorf("failed to verify password: %w", err)
	}
	if sameAsOld {
		return ErrSamePassword
	}

	// Validate the new password
	if err := auth.ValidatePassword(req.NewPassword, s.cfg.Security.Password.MinLength); err != nil {
		return fmt.Errorf("%w: %s", ErrPasswordTooWeak, err.Error())
	}

	// Hash the new password
	passwordHash, err := auth.HashPassword(req.NewPassword, s.argonParams)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Update the password
	if err := s.userRepo.UpdatePasswordHash(ctx, req.UserID, passwordHash); err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	// Optionally invalidate other sessions
	if req.InvalidateOtherSessions {
		if err := s.tokenRepo.RevokeAllUserRefreshTokens(ctx, req.UserID); err != nil {
			s.log.Error().Err(err).Msg("failed to revoke other sessions after password change")
		}
		if err := s.deviceRepo.DeactivateAllUserSessions(ctx, req.UserID); err != nil {
			s.log.Error().Err(err).Msg("failed to deactivate other sessions after password change")
		}
	}

	// Audit log
	s.logAudit(ctx, req.UserID, model.AuditActionPasswordChange, "user", req.UserID, req.IPAddress, req.UserAgent, map[string]interface{}{
		"status":                     "success",
		"invalidated_other_sessions": req.InvalidateOtherSessions,
	})

	s.log.Info().Str("user_id", req.UserID).Bool("invalidated_sessions", req.InvalidateOtherSessions).Msg("password changed")

	return nil
}

// handleDevice creates or updates the device record for a login
func (s *AuthService) handleDevice(ctx context.Context, userID string, req LoginRequest) (string, error) {
	now := time.Now()

	// Generate fingerprint hash (use device fingerprint if provided, otherwise hash UA + IP)
	fingerprintInput := req.DeviceFingerprint
	if fingerprintInput == "" {
		fingerprintInput = req.UserAgent + req.IPAddress
	}
	fingerprintHash := hashFingerprint(fingerprintInput)

	// Try to find existing device
	device, err := s.deviceRepo.GetByUserAndFingerprint(ctx, userID, fingerprintHash)
	if err != nil && !errors.Is(err, repository.ErrNotFound) {
		return "", fmt.Errorf("failed to look up device: %w", err)
	}

	sessionExpiry := now.Add(s.tokenSvc.GetRefreshTokenTTL())
	ip := cleanIP(req.IPAddress)

	if device != nil {
		// Update existing device session
		if err := s.deviceRepo.UpdateSession(ctx, device.ID, true, &now, &sessionExpiry, &ip); err != nil {
			return "", fmt.Errorf("failed to update device session: %w", err)
		}
		return device.ID, nil
	}

	// Create new device
	deviceID := generateID("dev")
	deviceName := parseDeviceName(req.UserAgent)
	newDevice := &model.Device{
		ID:               deviceID,
		UserID:           userID,
		FingerprintHash:  fingerprintHash,
		Name:             &deviceName,
		UserAgent:        &req.UserAgent,
		SessionActive:    true,
		SessionStartedAt: &now,
		SessionExpiresAt: &sessionExpiry,
		CurrentIP:        &ip,
		LastActivity:     now,
		FirstSeen:        now,
		CreatedAt:        now,
		UpdatedAt:        now,
	}

	if err := s.deviceRepo.Create(ctx, newDevice); err != nil {
		return "", fmt.Errorf("failed to create device: %w", err)
	}

	return deviceID, nil
}

// AdminUnlockAccount unlocks a user account and resets failed attempts.
// This is an admin operation.
func (s *AuthService) AdminUnlockAccount(ctx context.Context, targetUserID, adminUserID, ipAddress, userAgent string) error {
	// Verify the target user exists
	user, err := s.userRepo.GetByID(ctx, targetUserID)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	// Reset failed attempts and clear lock
	if err := s.userRepo.ResetFailedAttempts(ctx, user.ID); err != nil {
		return fmt.Errorf("failed to reset failed attempts: %w", err)
	}

	// Set status back to active
	if err := s.userRepo.UpdateStatus(ctx, user.ID, model.UserStatusActive); err != nil {
		return fmt.Errorf("failed to update status: %w", err)
	}

	// Audit log
	s.logAudit(ctx, adminUserID, model.AuditActionAccountUnlock, "user", targetUserID, ipAddress, userAgent, map[string]interface{}{
		"target_user_id": targetUserID,
		"admin_user_id":  adminUserID,
	})

	s.log.Info().Str("target_user_id", targetUserID).Str("admin_user_id", adminUserID).Msg("account unlocked by admin")
	return nil
}

// handleFailedLogin manages progressive account lockout
func (s *AuthService) handleFailedLogin(ctx context.Context, userID string, attempts int) {
	var lockDuration time.Duration

	switch {
	case attempts >= 20:
		// Permanent lock - require manual unlock
		lockDuration = 24 * 365 * time.Hour // effectively permanent
		s.userRepo.LockUntil(ctx, userID, time.Now().Add(lockDuration))
	case attempts >= 15:
		lockDuration = 2 * time.Hour
		s.userRepo.LockUntil(ctx, userID, time.Now().Add(lockDuration))
	case attempts >= 10:
		lockDuration = 30 * time.Minute
		s.userRepo.LockUntil(ctx, userID, time.Now().Add(lockDuration))
	case attempts >= 5:
		lockDuration = 5 * time.Minute
		s.userRepo.LockUntil(ctx, userID, time.Now().Add(lockDuration))
	}

	if lockDuration > 0 {
		s.log.Warn().
			Str("user_id", userID).
			Int("attempts", attempts).
			Dur("lock_duration", lockDuration).
			Msg("account locked due to failed attempts")
	}
}

// logAudit creates an audit log entry
func (s *AuthService) logAudit(ctx context.Context, userID, action, resourceType, resourceID, ipAddress, userAgent string, metadata map[string]interface{}) {
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

// Helper functions

func generateID(prefix string) string {
	id := uuid.New().String()
	// Remove hyphens and take first 26 chars to fit varchar(32) with prefix
	clean := strings.ReplaceAll(id, "-", "")
	if len(prefix) > 0 {
		return prefix + "_" + clean[:min(26, len(clean))]
	}
	return clean
}

func generateSecureToken(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate secure token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func defaultString(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func isValidEmail(email string) bool {
	if len(email) < 3 || len(email) > 255 {
		return false
	}
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return false
	}
	if len(parts[0]) == 0 || len(parts[1]) == 0 {
		return false
	}
	// Check domain has at least one dot
	if !strings.Contains(parts[1], ".") {
		return false
	}
	return true
}

func hashFingerprint(input string) string {
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:])
}

func cleanIP(ip string) string {
	// Strip port if present
	host, _, err := net.SplitHostPort(ip)
	if err != nil {
		return ip
	}
	return host
}

func parseDeviceName(userAgent string) string {
	if userAgent == "" {
		return "Unknown Device"
	}

	ua := strings.ToLower(userAgent)

	// Simple browser/OS detection
	browser := "Browser"
	switch {
	case strings.Contains(ua, "firefox"):
		browser = "Firefox"
	case strings.Contains(ua, "edg"):
		browser = "Edge"
	case strings.Contains(ua, "chrome"):
		browser = "Chrome"
	case strings.Contains(ua, "safari"):
		browser = "Safari"
	}

	os := "Unknown"
	switch {
	case strings.Contains(ua, "windows"):
		os = "Windows"
	case strings.Contains(ua, "macintosh") || strings.Contains(ua, "mac os"):
		os = "Mac"
	case strings.Contains(ua, "linux"):
		os = "Linux"
	case strings.Contains(ua, "iphone"):
		os = "iPhone"
	case strings.Contains(ua, "android"):
		os = "Android"
	}

	return browser + " on " + os
}
