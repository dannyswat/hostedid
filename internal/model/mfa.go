package model

import (
	"encoding/json"
	"time"
)

// MFAMethodType represents a type of MFA method
type MFAMethodType string

const (
	MFAMethodTOTP       MFAMethodType = "totp"
	MFAMethodWebAuthn   MFAMethodType = "webauthn"
	MFAMethodBackupCode MFAMethodType = "backup_code"
)

// MFAMethod represents an enrolled MFA method for a user
type MFAMethod struct {
	ID             string          `json:"id"`
	UserID         string          `json:"userId"`
	Method         MFAMethodType   `json:"method"`
	Secret         []byte          `json:"-"` // encrypted TOTP secret, never expose
	CredentialData json.RawMessage `json:"credentialData,omitempty"`
	IsPrimary      bool            `json:"isPrimary"`
	LastUsed       *time.Time      `json:"lastUsed,omitempty"`
	CreatedAt      time.Time       `json:"createdAt"`
}

// BackupCode represents a one-time-use backup code
type BackupCode struct {
	ID        string     `json:"id"`
	UserID    string     `json:"userId"`
	CodeHash  string     `json:"-"` // hashed code, never expose
	UsedAt    *time.Time `json:"usedAt,omitempty"`
	CreatedAt time.Time  `json:"createdAt"`
}

// IsUsed checks if the backup code has already been used
func (b *BackupCode) IsUsed() bool {
	return b.UsedAt != nil
}

// MFASetupResponse is returned when setting up TOTP
type MFASetupResponse struct {
	Secret    string `json:"secret"`
	QRCode    string `json:"qrCode"` // base64-encoded PNG
	Issuer    string `json:"issuer"`
	AccountID string `json:"accountId"`
}

// MFAVerifyRequest represents a request to verify an MFA code
type MFAVerifyRequest struct {
	Method   MFAMethodType `json:"method"`
	Code     string        `json:"code,omitempty"` // for TOTP and backup codes
	MFAToken string        `json:"mfaToken"`       // temporary token from login
}

// MFAMethodInfo provides information about an enrolled method (for listing)
type MFAMethodInfo struct {
	Method    MFAMethodType `json:"method"`
	IsPrimary bool          `json:"isPrimary"`
	LastUsed  *time.Time    `json:"lastUsed,omitempty"`
	CreatedAt time.Time     `json:"createdAt"`
	// WebAuthn-specific
	Credentials []WebAuthnCredentialInfo `json:"credentials,omitempty"`
}

// WebAuthnCredentialInfo provides info about a WebAuthn credential
type WebAuthnCredentialInfo struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"createdAt"`
}

// MFAStatusResponse returns the user's MFA configuration
type MFAStatusResponse struct {
	MFAEnabled           bool            `json:"mfaEnabled"`
	PreferredMethod      *MFAMethodType  `json:"preferredMethod,omitempty"`
	EnrolledMethods      []MFAMethodInfo `json:"enrolledMethods"`
	BackupCodesRemaining int             `json:"backupCodesRemaining"`
}

// MFAChallengeResponse is returned when MFA is required during login
type MFAChallengeResponse struct {
	Status           string          `json:"status"` // "mfa_required"
	MFAToken         string          `json:"mfaToken"`
	AvailableMethods []MFAMethodType `json:"availableMethods"`
	PreferredMethod  *MFAMethodType  `json:"preferredMethod,omitempty"`
}

// BackupCodesResponse is returned when generating backup codes
type BackupCodesResponse struct {
	Codes []string `json:"codes"`
	Count int      `json:"count"`
}

// WebAuthnSessionData stores WebAuthn ceremony state temporarily
type WebAuthnSessionData struct {
	UserID      string          `json:"userId"`
	SessionData json.RawMessage `json:"sessionData"`
	Type        string          `json:"type"` // "registration" or "authentication"
	ExpiresAt   time.Time       `json:"expiresAt"`
}
