package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/hostedid/hostedid/internal/config"
	"github.com/hostedid/hostedid/internal/database"
	"github.com/hostedid/hostedid/internal/email"
	"github.com/hostedid/hostedid/internal/logger"
	"github.com/hostedid/hostedid/internal/model"
	"github.com/hostedid/hostedid/internal/repository"
)

// Email verification errors
var (
	ErrVerificationDisabled  = errors.New("email verification is not enabled")
	ErrInvalidOTP            = errors.New("invalid or expired verification code")
	ErrTooManyResendAttempts = errors.New("too many resend attempts, please wait")
	ErrEmailAlreadyVerified  = errors.New("email is already verified")
)

const (
	otpRedisPrefix       = "email_otp:"
	resendCooldownPrefix = "email_resend:"
	otpAttemptsPrefix    = "email_otp_attempts:"
	maxOTPAttempts       = 5
)

// EmailVerificationService handles email verification via OTP.
type EmailVerificationService struct {
	rdb      *database.Redis
	userRepo *repository.UserRepository
	sender   email.Sender
	cfg      *config.Config
	log      *logger.Logger
}

// NewEmailVerificationService creates a new EmailVerificationService.
func NewEmailVerificationService(
	rdb *database.Redis,
	userRepo *repository.UserRepository,
	sender email.Sender,
	cfg *config.Config,
	log *logger.Logger,
) *EmailVerificationService {
	return &EmailVerificationService{
		rdb:      rdb,
		userRepo: userRepo,
		sender:   sender,
		cfg:      cfg,
		log:      log.WithComponent("email_verification"),
	}
}

// IsEnabled returns whether email verification is enabled in the config.
func (s *EmailVerificationService) IsEnabled() bool {
	return s.cfg.EmailVerification.Enabled
}

// SendVerificationOTP generates an OTP and sends it to the user's email.
func (s *EmailVerificationService) SendVerificationOTP(ctx context.Context, userID, userEmail string) error {
	if !s.IsEnabled() {
		return ErrVerificationDisabled
	}

	// Check resend cooldown
	cooldownKey := resendCooldownPrefix + userID
	exists, err := s.rdb.Exists(ctx, cooldownKey)
	if err != nil {
		return fmt.Errorf("failed to check resend cooldown: %w", err)
	}
	if exists > 0 {
		return ErrTooManyResendAttempts
	}

	// Generate OTP
	otp, err := s.generateOTP()
	if err != nil {
		return fmt.Errorf("failed to generate OTP: %w", err)
	}

	// Hash OTP before storing (defense in depth)
	hashedOTP := hashOTP(otp)

	// Store hashed OTP in Redis with TTL
	otpKey := otpRedisPrefix + userID
	ttl := s.cfg.EmailVerification.OTPTTL
	if ttl == 0 {
		ttl = 10 * time.Minute
	}
	if err := s.rdb.SetWithTTL(ctx, otpKey, hashedOTP, ttl); err != nil {
		return fmt.Errorf("failed to store OTP: %w", err)
	}

	// Reset attempt counter
	attemptsKey := otpAttemptsPrefix + userID
	_ = s.rdb.Delete(ctx, attemptsKey)

	// Set resend cooldown
	cooldown := s.cfg.EmailVerification.ResendCooldown
	if cooldown == 0 {
		cooldown = 60 * time.Second
	}
	if err := s.rdb.SetWithTTL(ctx, cooldownKey, "1", cooldown); err != nil {
		s.log.Warn().Err(err).Str("user_id", userID).Msg("failed to set resend cooldown")
	}

	// Build and send email
	ttlMinutes := int(ttl.Minutes())
	if ttlMinutes < 1 {
		ttlMinutes = 1
	}
	appName := s.cfg.Email.AppName
	if appName == "" {
		appName = "HostedID"
	}

	msg := email.Message{
		To:       userEmail,
		Subject:  fmt.Sprintf("Your %s verification code: %s", appName, otp),
		HTMLBody: email.VerificationEmailHTML(otp, appName, ttlMinutes),
		TextBody: email.VerificationEmailText(otp, appName, ttlMinutes),
	}

	if err := s.sender.Send(ctx, msg); err != nil {
		// Clean up OTP on send failure so user can retry immediately
		_ = s.rdb.Delete(ctx, otpKey)
		_ = s.rdb.Delete(ctx, cooldownKey)
		return fmt.Errorf("failed to send verification email: %w", err)
	}

	s.log.Info().Str("user_id", userID).Str("email", userEmail).Msg("verification OTP sent")
	return nil
}

// VerifyOTP verifies the submitted OTP for the given user.
// On success, it marks the user's email as verified and activates the account.
func (s *EmailVerificationService) VerifyOTP(ctx context.Context, userID string, code string) error {
	if !s.IsEnabled() {
		return ErrVerificationDisabled
	}

	// Check attempt counter (brute-force protection)
	attemptsKey := otpAttemptsPrefix + userID
	attempts, err := s.rdb.Incr(ctx, attemptsKey)
	if err != nil {
		return fmt.Errorf("failed to track OTP attempts: %w", err)
	}
	// Set expiry on first attempt
	if attempts == 1 {
		_ = s.rdb.Expire(ctx, attemptsKey, 15*time.Minute)
	}
	if attempts > int64(maxOTPAttempts) {
		return ErrInvalidOTP
	}

	// Get stored OTP hash
	otpKey := otpRedisPrefix + userID
	storedHash, err := s.rdb.GetString(ctx, otpKey)
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return ErrInvalidOTP
		}
		return fmt.Errorf("failed to get OTP: %w", err)
	}

	// Compare hashes
	submittedHash := hashOTP(code)
	if storedHash != submittedHash {
		return ErrInvalidOTP
	}

	// OTP is valid — clean up Redis
	_ = s.rdb.Delete(ctx, otpKey, attemptsKey, resendCooldownPrefix+userID)

	// Update user: mark email as verified, set status to active
	if err := s.userRepo.VerifyEmail(ctx, userID); err != nil {
		return fmt.Errorf("failed to verify email: %w", err)
	}
	if err := s.userRepo.UpdateStatus(ctx, userID, model.UserStatusActive); err != nil {
		return fmt.Errorf("failed to activate user: %w", err)
	}

	s.log.Info().Str("user_id", userID).Msg("email verified successfully")
	return nil
}

// generateOTP creates a cryptographically random numeric OTP.
func (s *EmailVerificationService) generateOTP() (string, error) {
	length := s.cfg.EmailVerification.OTPLength
	if length == 0 {
		length = 6
	}

	// Calculate upper bound: 10^length
	upper := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(length)), nil)

	n, err := rand.Int(rand.Reader, upper)
	if err != nil {
		return "", err
	}

	// Pad with leading zeros
	format := fmt.Sprintf("%%0%dd", length)
	return fmt.Sprintf(format, n), nil
}

// hashOTP hashes an OTP using SHA-256 for secure storage.
func hashOTP(otp string) string {
	h := sha256.Sum256([]byte(otp))
	return hex.EncodeToString(h[:])
}
