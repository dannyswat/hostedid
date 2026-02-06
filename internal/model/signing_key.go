package model

import "time"

// SigningKey represents a signing key stored in the database.
type SigningKey struct {
	ID            string     `json:"id"`
	Algorithm     string     `json:"algorithm"`
	PublicKey     []byte     `json:"-"`
	PrivateKeyEnc []byte     `json:"-"`
	IsActive      bool       `json:"isActive"`
	ExpiresAt     *time.Time `json:"expiresAt,omitempty"`
	CreatedAt     time.Time  `json:"createdAt"`
	RotatedAt     *time.Time `json:"rotatedAt,omitempty"`
}

// SigningKeyInfo is the public view of a signing key (no private material).
type SigningKeyInfo struct {
	ID        string     `json:"id"`
	Algorithm string     `json:"algorithm"`
	IsActive  bool       `json:"isActive"`
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
	CreatedAt time.Time  `json:"createdAt"`
	RotatedAt *time.Time `json:"rotatedAt,omitempty"`
}

// ToInfo converts a SigningKey to its public-safe representation.
func (k *SigningKey) ToInfo() *SigningKeyInfo {
	return &SigningKeyInfo{
		ID:        k.ID,
		Algorithm: k.Algorithm,
		IsActive:  k.IsActive,
		ExpiresAt: k.ExpiresAt,
		CreatedAt: k.CreatedAt,
		RotatedAt: k.RotatedAt,
	}
}
