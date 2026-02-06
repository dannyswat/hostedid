package model

import (
	"time"
)

// Device represents a user's device with embedded session state
type Device struct {
	ID               string     `json:"id"`
	UserID           string     `json:"userId"`
	FingerprintHash  string     `json:"fingerprintHash"`
	Name             *string    `json:"name,omitempty"`
	UserAgent        *string    `json:"userAgent,omitempty"`
	IsTrusted        bool       `json:"isTrusted"`
	TrustExpiresAt   *time.Time `json:"trustExpiresAt,omitempty"`
	CurrentIP        *string    `json:"currentIp,omitempty"`
	CurrentLocation  *string    `json:"currentLocation,omitempty"`
	SessionActive    bool       `json:"sessionActive"`
	SessionStartedAt *time.Time `json:"sessionStartedAt,omitempty"`
	SessionExpiresAt *time.Time `json:"sessionExpiresAt,omitempty"`
	LastActivity     time.Time  `json:"lastActivity"`
	FirstSeen        time.Time  `json:"firstSeen"`
	CreatedAt        time.Time  `json:"createdAt"`
	UpdatedAt        time.Time  `json:"updatedAt"`
}

// RefreshToken represents a stored refresh token
type RefreshToken struct {
	ID        string     `json:"id"`
	UserID    string     `json:"userId"`
	TokenHash string     `json:"-"`
	DeviceID  string     `json:"deviceId"`
	ExpiresAt time.Time  `json:"expiresAt"`
	RevokedAt *time.Time `json:"revokedAt,omitempty"`
	CreatedAt time.Time  `json:"createdAt"`
}

// IsExpired checks if the refresh token has expired
func (t *RefreshToken) IsExpired() bool {
	return time.Now().After(t.ExpiresAt)
}

// IsRevoked checks if the refresh token has been revoked
func (t *RefreshToken) IsRevoked() bool {
	return t.RevokedAt != nil
}

// PasswordResetToken represents a password reset token
type PasswordResetToken struct {
	ID        string     `json:"id"`
	UserID    string     `json:"userId"`
	TokenHash string     `json:"-"`
	ExpiresAt time.Time  `json:"expiresAt"`
	UsedAt    *time.Time `json:"usedAt,omitempty"`
	CreatedAt time.Time  `json:"createdAt"`
}

// IsExpired checks if the password reset token has expired
func (t *PasswordResetToken) IsExpired() bool {
	return time.Now().After(t.ExpiresAt)
}

// IsUsed checks if the password reset token has been used
func (t *PasswordResetToken) IsUsed() bool {
	return t.UsedAt != nil
}
