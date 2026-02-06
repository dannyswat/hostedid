package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	qrcode "github.com/skip2/go-qrcode"

	"github.com/hostedid/hostedid/internal/config"
	"github.com/hostedid/hostedid/internal/logger"
	"github.com/hostedid/hostedid/internal/model"
	"github.com/hostedid/hostedid/internal/repository"
)

// MFA service errors
var (
	ErrMFAAlreadyEnrolled  = errors.New("MFA method already enrolled")
	ErrMFANotEnrolled      = errors.New("MFA method not enrolled")
	ErrMFAInvalidCode      = errors.New("invalid MFA code")
	ErrMFAInvalidToken     = errors.New("invalid or expired MFA token")
	ErrMFASessionExpired   = errors.New("MFA session expired")
	ErrMFANoBackupCodes    = errors.New("no backup codes remaining")
	ErrMFASetupIncomplete  = errors.New("MFA setup not verified")
	ErrWebAuthnUnsupported = errors.New("WebAuthn is not configured")
)

const (
	backupCodeCount  = 10
	backupCodeLength = 8 // characters per code
	mfaTokenTTL      = 5 * time.Minute
)

// MFAService handles multi-factor authentication logic
type MFAService struct {
	mfaRepo  *repository.MFARepository
	userRepo *repository.UserRepository
	webauthn *webauthn.WebAuthn
	cfg      *config.Config
	log      *logger.Logger
	// In-memory store for temporary MFA tokens and WebAuthn sessions
	// In production, use Redis for this
	mfaTokens        map[string]*mfaTokenEntry
	webauthnSessions map[string]*webauthnSessionEntry
}

type mfaTokenEntry struct {
	UserID    string
	ExpiresAt time.Time
}

type webauthnSessionEntry struct {
	UserID      string
	SessionData *webauthn.SessionData
	Type        string // "registration" or "authentication"
	ExpiresAt   time.Time
}

// NewMFAService creates a new MFAService
func NewMFAService(
	mfaRepo *repository.MFARepository,
	userRepo *repository.UserRepository,
	cfg *config.Config,
	log *logger.Logger,
) (*MFAService, error) {
	svc := &MFAService{
		mfaRepo:          mfaRepo,
		userRepo:         userRepo,
		cfg:              cfg,
		log:              log.WithComponent("mfa_service"),
		mfaTokens:        make(map[string]*mfaTokenEntry),
		webauthnSessions: make(map[string]*webauthnSessionEntry),
	}

	// Initialize WebAuthn if configured
	if cfg.MFA.WebAuthn.RPID != "" {
		wconfig := &webauthn.Config{
			RPID:                  cfg.MFA.WebAuthn.RPID,
			RPDisplayName:         cfg.MFA.WebAuthn.RPName,
			RPOrigins:             cfg.MFA.WebAuthn.RPOrigins,
			AttestationPreference: protocol.PreferNoAttestation,
			AuthenticatorSelection: protocol.AuthenticatorSelection{
				UserVerification: protocol.VerificationPreferred,
			},
		}

		var err error
		svc.webauthn, err = webauthn.New(wconfig)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize WebAuthn: %w", err)
		}
	}

	return svc, nil
}

// --- TOTP Methods ---

// SetupTOTP generates a TOTP secret and QR code for a user
func (s *MFAService) SetupTOTP(ctx context.Context, userID string) (*model.MFASetupResponse, error) {
	// Check if TOTP is already enrolled
	_, err := s.mfaRepo.GetMethodByUserAndType(ctx, userID, model.MFAMethodTOTP)
	if err == nil {
		return nil, ErrMFAAlreadyEnrolled
	}
	if !errors.Is(err, repository.ErrNotFound) {
		return nil, fmt.Errorf("failed to check TOTP enrollment: %w", err)
	}

	// Get user for account name
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	issuer := s.cfg.MFA.TOTP.Issuer
	if issuer == "" {
		issuer = "HostedID"
	}

	// Generate TOTP key
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: user.Email,
		Period:      uint(s.cfg.MFA.TOTP.Period),
		Digits:      otp.Digits(s.cfg.MFA.TOTP.Digits),
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to generate TOTP key: %w", err)
	}

	// Generate QR code as base64 PNG
	qrPNG, err := qrcode.Encode(key.URL(), qrcode.Medium, 256)
	if err != nil {
		return nil, fmt.Errorf("failed to generate QR code: %w", err)
	}
	qrBase64 := base64.StdEncoding.EncodeToString(qrPNG)

	// Store the secret temporarily - it will be confirmed on verification
	now := time.Now()
	method := &model.MFAMethod{
		ID:        generateID("mfa"),
		UserID:    userID,
		Method:    model.MFAMethodTOTP,
		Secret:    []byte(key.Secret()),
		IsPrimary: false,
		CreatedAt: now,
	}

	if err := s.mfaRepo.CreateMethod(ctx, method); err != nil {
		return nil, fmt.Errorf("failed to store TOTP method: %w", err)
	}

	s.log.Info().Str("user_id", userID).Msg("TOTP setup initiated")

	return &model.MFASetupResponse{
		Secret:    key.Secret(),
		QRCode:    qrBase64,
		Issuer:    issuer,
		AccountID: user.Email,
	}, nil
}

// VerifyTOTPSetup verifies the initial TOTP code during setup and activates the method
func (s *MFAService) VerifyTOTPSetup(ctx context.Context, userID, code string) error {
	method, err := s.mfaRepo.GetMethodByUserAndType(ctx, userID, model.MFAMethodTOTP)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return ErrMFANotEnrolled
		}
		return fmt.Errorf("failed to get TOTP method: %w", err)
	}

	// Validate the TOTP code
	valid := totp.Validate(code, string(method.Secret))
	if !valid {
		return ErrMFAInvalidCode
	}

	// Mark as primary if it's the first MFA method
	methods, err := s.mfaRepo.GetMethodsByUser(ctx, userID)
	if err == nil && len(methods) == 1 {
		if err := s.mfaRepo.SetPrimaryMethod(ctx, userID, model.MFAMethodTOTP); err != nil {
			s.log.Error().Err(err).Msg("failed to set TOTP as primary")
		}
	}

	// Update last used
	if err := s.mfaRepo.UpdateMethodLastUsed(ctx, method.ID); err != nil {
		s.log.Error().Err(err).Msg("failed to update TOTP last used")
	}

	s.log.Info().Str("user_id", userID).Msg("TOTP setup verified and activated")
	return nil
}

// VerifyTOTP validates a TOTP code for authentication
func (s *MFAService) VerifyTOTP(ctx context.Context, userID, code string) error {
	method, err := s.mfaRepo.GetMethodByUserAndType(ctx, userID, model.MFAMethodTOTP)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return ErrMFANotEnrolled
		}
		return fmt.Errorf("failed to get TOTP method: %w", err)
	}

	valid := totp.Validate(code, string(method.Secret))
	if !valid {
		return ErrMFAInvalidCode
	}

	if err := s.mfaRepo.UpdateMethodLastUsed(ctx, method.ID); err != nil {
		s.log.Error().Err(err).Msg("failed to update TOTP last used")
	}

	return nil
}

// --- WebAuthn Methods ---

// webauthnUser implements the webauthn.User interface
type webauthnUser struct {
	id          []byte
	name        string
	displayName string
	credentials []webauthn.Credential
}

func (u *webauthnUser) WebAuthnID() []byte                         { return u.id }
func (u *webauthnUser) WebAuthnName() string                       { return u.name }
func (u *webauthnUser) WebAuthnDisplayName() string                { return u.displayName }
func (u *webauthnUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

// BeginWebAuthnRegistration starts the WebAuthn registration ceremony
func (s *MFAService) BeginWebAuthnRegistration(ctx context.Context, userID string) (interface{}, error) {
	if s.webauthn == nil {
		return nil, ErrWebAuthnUnsupported
	}

	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Get existing WebAuthn credentials
	existingCreds, err := s.getWebAuthnCredentials(ctx, userID)
	if err != nil {
		return nil, err
	}

	displayName := user.Email
	profile, _ := s.userRepo.GetProfile(ctx, userID)
	if profile != nil && profile.DisplayName != nil {
		displayName = *profile.DisplayName
	}

	wUser := &webauthnUser{
		id:          []byte(userID),
		name:        user.Email,
		displayName: displayName,
		credentials: existingCreds,
	}

	creation, session, err := s.webauthn.BeginRegistration(wUser)
	if err != nil {
		return nil, fmt.Errorf("failed to begin WebAuthn registration: %w", err)
	}

	// Store session data
	sessionKey := generateSessionKey()
	s.webauthnSessions[sessionKey] = &webauthnSessionEntry{
		UserID:      userID,
		SessionData: session,
		Type:        "registration",
		ExpiresAt:   time.Now().Add(5 * time.Minute),
	}

	return map[string]interface{}{
		"publicKey":  creation,
		"sessionKey": sessionKey,
	}, nil
}

// CompleteWebAuthnRegistration completes the WebAuthn registration ceremony
func (s *MFAService) CompleteWebAuthnRegistration(ctx context.Context, userID, sessionKey, credentialName string, body protocol.ParsedCredentialCreationData) error {
	if s.webauthn == nil {
		return ErrWebAuthnUnsupported
	}

	sessionEntry, ok := s.webauthnSessions[sessionKey]
	if !ok || sessionEntry.UserID != userID || time.Now().After(sessionEntry.ExpiresAt) {
		return ErrMFASessionExpired
	}
	defer delete(s.webauthnSessions, sessionKey)

	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}

	existingCreds, err := s.getWebAuthnCredentials(ctx, userID)
	if err != nil {
		return err
	}

	displayName := user.Email
	profile, _ := s.userRepo.GetProfile(ctx, userID)
	if profile != nil && profile.DisplayName != nil {
		displayName = *profile.DisplayName
	}

	wUser := &webauthnUser{
		id:          []byte(userID),
		name:        user.Email,
		displayName: displayName,
		credentials: existingCreds,
	}

	credential, err := s.webauthn.CreateCredential(wUser, *sessionEntry.SessionData, &body)
	if err != nil {
		return fmt.Errorf("WebAuthn registration failed: %w", err)
	}

	// Store credential in the database
	credInfo := model.WebAuthnCredentialInfo{
		ID:        base64.RawURLEncoding.EncodeToString(credential.ID),
		Name:      credentialName,
		CreatedAt: time.Now(),
	}

	// Build credential data (existing creds + new one)
	type webauthnCredData struct {
		Credentials []webauthn.Credential          `json:"credentials"`
		CredInfos   []model.WebAuthnCredentialInfo `json:"credInfos"`
	}

	var existingData webauthnCredData
	method, err := s.mfaRepo.GetMethodByUserAndType(ctx, userID, model.MFAMethodWebAuthn)
	if err == nil && method.CredentialData != nil {
		json.Unmarshal(method.CredentialData, &existingData)
	}

	existingData.Credentials = append(existingData.Credentials, *credential)
	existingData.CredInfos = append(existingData.CredInfos, credInfo)

	credDataJSON, err := json.Marshal(existingData)
	if err != nil {
		return fmt.Errorf("failed to marshal credential data: %w", err)
	}

	if method != nil {
		// Update existing method
		if err := s.mfaRepo.UpdateMethodCredentialData(ctx, method.ID, credDataJSON); err != nil {
			return fmt.Errorf("failed to update WebAuthn credentials: %w", err)
		}
	} else {
		// Create new method
		now := time.Now()
		newMethod := &model.MFAMethod{
			ID:             generateID("mfa"),
			UserID:         userID,
			Method:         model.MFAMethodWebAuthn,
			CredentialData: credDataJSON,
			IsPrimary:      false,
			CreatedAt:      now,
		}
		if err := s.mfaRepo.CreateMethod(ctx, newMethod); err != nil {
			return fmt.Errorf("failed to create WebAuthn method: %w", err)
		}

		// Set as primary if first MFA method
		methods, err := s.mfaRepo.GetMethodsByUser(ctx, userID)
		if err == nil && len(methods) == 1 {
			s.mfaRepo.SetPrimaryMethod(ctx, userID, model.MFAMethodWebAuthn)
		}
	}

	s.log.Info().Str("user_id", userID).Str("credential_name", credentialName).Msg("WebAuthn credential registered")
	return nil
}

// BeginWebAuthnAuthentication starts the WebAuthn authentication ceremony
func (s *MFAService) BeginWebAuthnAuthentication(ctx context.Context, userID string) (interface{}, error) {
	if s.webauthn == nil {
		return nil, ErrWebAuthnUnsupported
	}

	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	creds, err := s.getWebAuthnCredentials(ctx, userID)
	if err != nil {
		return nil, err
	}
	if len(creds) == 0 {
		return nil, ErrMFANotEnrolled
	}

	displayName := user.Email
	profile, _ := s.userRepo.GetProfile(ctx, userID)
	if profile != nil && profile.DisplayName != nil {
		displayName = *profile.DisplayName
	}

	wUser := &webauthnUser{
		id:          []byte(userID),
		name:        user.Email,
		displayName: displayName,
		credentials: creds,
	}

	assertion, session, err := s.webauthn.BeginLogin(wUser)
	if err != nil {
		return nil, fmt.Errorf("failed to begin WebAuthn authentication: %w", err)
	}

	sessionKey := generateSessionKey()
	s.webauthnSessions[sessionKey] = &webauthnSessionEntry{
		UserID:      userID,
		SessionData: session,
		Type:        "authentication",
		ExpiresAt:   time.Now().Add(5 * time.Minute),
	}

	return map[string]interface{}{
		"publicKey":  assertion,
		"sessionKey": sessionKey,
	}, nil
}

// CompleteWebAuthnAuthentication completes the WebAuthn authentication ceremony
func (s *MFAService) CompleteWebAuthnAuthentication(ctx context.Context, userID, sessionKey string, body protocol.ParsedCredentialAssertionData) error {
	if s.webauthn == nil {
		return ErrWebAuthnUnsupported
	}

	sessionEntry, ok := s.webauthnSessions[sessionKey]
	if !ok || sessionEntry.UserID != userID || time.Now().After(sessionEntry.ExpiresAt) {
		return ErrMFASessionExpired
	}
	defer delete(s.webauthnSessions, sessionKey)

	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}

	creds, err := s.getWebAuthnCredentials(ctx, userID)
	if err != nil {
		return err
	}

	displayName := user.Email
	profile, _ := s.userRepo.GetProfile(ctx, userID)
	if profile != nil && profile.DisplayName != nil {
		displayName = *profile.DisplayName
	}

	wUser := &webauthnUser{
		id:          []byte(userID),
		name:        user.Email,
		displayName: displayName,
		credentials: creds,
	}

	_, err = s.webauthn.ValidateLogin(wUser, *sessionEntry.SessionData, &body)
	if err != nil {
		return fmt.Errorf("WebAuthn authentication failed: %w", err)
	}

	// Update last used
	method, mErr := s.mfaRepo.GetMethodByUserAndType(ctx, userID, model.MFAMethodWebAuthn)
	if mErr == nil {
		s.mfaRepo.UpdateMethodLastUsed(ctx, method.ID)
	}

	s.log.Info().Str("user_id", userID).Msg("WebAuthn authentication successful")
	return nil
}

// getWebAuthnCredentials retrieves stored WebAuthn credentials for a user
func (s *MFAService) getWebAuthnCredentials(ctx context.Context, userID string) ([]webauthn.Credential, error) {
	method, err := s.mfaRepo.GetMethodByUserAndType(ctx, userID, model.MFAMethodWebAuthn)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get WebAuthn method: %w", err)
	}

	if method.CredentialData == nil {
		return nil, nil
	}

	type webauthnCredData struct {
		Credentials []webauthn.Credential `json:"credentials"`
	}
	var data webauthnCredData
	if err := json.Unmarshal(method.CredentialData, &data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal WebAuthn credentials: %w", err)
	}

	return data.Credentials, nil
}

// --- Backup Codes ---

// GenerateBackupCodes generates a new set of backup codes for a user
func (s *MFAService) GenerateBackupCodes(ctx context.Context, userID string) (*model.BackupCodesResponse, error) {
	// Verify user has at least one MFA method enrolled
	hasMFA, err := s.mfaRepo.HasAnyMethod(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to check MFA methods: %w", err)
	}
	if !hasMFA {
		return nil, ErrMFANotEnrolled
	}

	// Delete existing backup codes
	if err := s.mfaRepo.DeleteAllBackupCodes(ctx, userID); err != nil {
		s.log.Error().Err(err).Msg("failed to delete existing backup codes")
	}

	// Generate new codes
	now := time.Now()
	plainCodes := make([]string, backupCodeCount)
	dbCodes := make([]*model.BackupCode, backupCodeCount)

	for i := 0; i < backupCodeCount; i++ {
		code := generateBackupCode()
		plainCodes[i] = code

		hash := sha256.Sum256([]byte(normalizeBackupCode(code)))
		dbCodes[i] = &model.BackupCode{
			ID:        generateID("bkp"),
			UserID:    userID,
			CodeHash:  hex.EncodeToString(hash[:]),
			CreatedAt: now,
		}
	}

	if err := s.mfaRepo.CreateBackupCodes(ctx, dbCodes); err != nil {
		return nil, fmt.Errorf("failed to store backup codes: %w", err)
	}

	s.log.Info().Str("user_id", userID).Int("count", backupCodeCount).Msg("backup codes generated")

	return &model.BackupCodesResponse{
		Codes: plainCodes,
		Count: backupCodeCount,
	}, nil
}

// VerifyBackupCode validates and consumes a backup code
func (s *MFAService) VerifyBackupCode(ctx context.Context, userID, code string) error {
	codes, err := s.mfaRepo.GetUnusedBackupCodes(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get backup codes: %w", err)
	}
	if len(codes) == 0 {
		return ErrMFANoBackupCodes
	}

	normalizedCode := normalizeBackupCode(code)
	inputHash := sha256.Sum256([]byte(normalizedCode))
	inputHashStr := hex.EncodeToString(inputHash[:])

	for _, c := range codes {
		if subtle.ConstantTimeCompare([]byte(c.CodeHash), []byte(inputHashStr)) == 1 {
			// Mark the code as used
			if err := s.mfaRepo.MarkBackupCodeUsed(ctx, c.ID); err != nil {
				return fmt.Errorf("failed to mark backup code as used: %w", err)
			}
			s.log.Info().Str("user_id", userID).Msg("backup code used")
			return nil
		}
	}

	return ErrMFAInvalidCode
}

// --- MFA Status & Methods ---

// GetMFAStatus returns the user's MFA configuration
func (s *MFAService) GetMFAStatus(ctx context.Context, userID string) (*model.MFAStatusResponse, error) {
	methods, err := s.mfaRepo.GetMethodsByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get MFA methods: %w", err)
	}

	backupCount, err := s.mfaRepo.CountUnusedBackupCodes(ctx, userID)
	if err != nil {
		s.log.Error().Err(err).Msg("failed to count backup codes")
	}

	resp := &model.MFAStatusResponse{
		MFAEnabled:           len(methods) > 0,
		EnrolledMethods:      make([]model.MFAMethodInfo, 0, len(methods)),
		BackupCodesRemaining: backupCount,
	}

	for _, m := range methods {
		info := model.MFAMethodInfo{
			Method:    m.Method,
			IsPrimary: m.IsPrimary,
			LastUsed:  m.LastUsed,
			CreatedAt: m.CreatedAt,
		}

		if m.IsPrimary {
			method := m.Method
			resp.PreferredMethod = &method
		}

		// For WebAuthn, include credential info
		if m.Method == model.MFAMethodWebAuthn && m.CredentialData != nil {
			type webauthnCredData struct {
				CredInfos []model.WebAuthnCredentialInfo `json:"credInfos"`
			}
			var data webauthnCredData
			if err := json.Unmarshal(m.CredentialData, &data); err == nil {
				info.Credentials = data.CredInfos
			}
		}

		resp.EnrolledMethods = append(resp.EnrolledMethods, info)
	}

	return resp, nil
}

// DisableMFAMethod removes an MFA method for a user
func (s *MFAService) DisableMFAMethod(ctx context.Context, userID string, method model.MFAMethodType) error {
	if err := s.mfaRepo.DeleteMethod(ctx, userID, method); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return ErrMFANotEnrolled
		}
		return fmt.Errorf("failed to delete MFA method: %w", err)
	}

	// If no methods remain, delete backup codes too
	hasMFA, err := s.mfaRepo.HasAnyMethod(ctx, userID)
	if err == nil && !hasMFA {
		s.mfaRepo.DeleteAllBackupCodes(ctx, userID)
	}

	s.log.Info().Str("user_id", userID).Str("method", string(method)).Msg("MFA method disabled")
	return nil
}

// --- MFA Token Management ---

// CreateMFAToken creates a temporary MFA token for the login flow
func (s *MFAService) CreateMFAToken(userID string) string {
	token := generateSessionKey()
	s.mfaTokens[token] = &mfaTokenEntry{
		UserID:    userID,
		ExpiresAt: time.Now().Add(mfaTokenTTL),
	}
	return token
}

// ValidateMFAToken validates an MFA token and returns the associated user ID
func (s *MFAService) ValidateMFAToken(token string) (string, error) {
	entry, ok := s.mfaTokens[token]
	if !ok {
		return "", ErrMFAInvalidToken
	}
	if time.Now().After(entry.ExpiresAt) {
		delete(s.mfaTokens, token)
		return "", ErrMFASessionExpired
	}
	return entry.UserID, nil
}

// ConsumeMFAToken validates and removes an MFA token
func (s *MFAService) ConsumeMFAToken(token string) (string, error) {
	userID, err := s.ValidateMFAToken(token)
	if err != nil {
		return "", err
	}
	delete(s.mfaTokens, token)
	return userID, nil
}

// GetAvailableMethods returns the MFA methods available for a user
func (s *MFAService) GetAvailableMethods(ctx context.Context, userID string) ([]model.MFAMethodType, *model.MFAMethodType, error) {
	methods, err := s.mfaRepo.GetMethodsByUser(ctx, userID)
	if err != nil {
		return nil, nil, err
	}

	available := make([]model.MFAMethodType, 0, len(methods)+1)
	var preferred *model.MFAMethodType

	for _, m := range methods {
		available = append(available, m.Method)
		if m.IsPrimary {
			method := m.Method
			preferred = &method
		}
	}

	// Check if backup codes are available
	count, err := s.mfaRepo.CountUnusedBackupCodes(ctx, userID)
	if err == nil && count > 0 {
		available = append(available, model.MFAMethodBackupCode)
	}

	return available, preferred, nil
}

// HasMFA checks if a user has any MFA method enrolled
func (s *MFAService) HasMFA(ctx context.Context, userID string) (bool, error) {
	return s.mfaRepo.HasAnyMethod(ctx, userID)
}

// --- Helper functions ---

func generateBackupCode() string {
	const charset = "0123456789abcdefghjkmnpqrstuvwxyz" // no i, l, o to avoid confusion
	b := make([]byte, backupCodeLength)
	if _, err := rand.Read(b); err != nil {
		panic("failed to generate random bytes for backup code")
	}
	code := make([]byte, backupCodeLength)
	for i := range code {
		code[i] = charset[int(b[i])%len(charset)]
	}
	// Format as xxxx-xxxx
	return string(code[:4]) + "-" + string(code[4:])
}

func normalizeBackupCode(code string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(code), "-", ""))
}

func generateSessionKey() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("failed to generate random bytes for session key")
	}
	return hex.EncodeToString(b)
}
