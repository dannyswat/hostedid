package model

import (
	"time"
)

// UserStatus represents the status of a user account
type UserStatus string

const (
	UserStatusPendingVerification UserStatus = "pending_verification"
	UserStatusActive              UserStatus = "active"
	UserStatusLocked              UserStatus = "locked"
	UserStatusDisabled            UserStatus = "disabled"
)

// User represents the core user entity
type User struct {
	ID             string     `json:"id"`
	Email          string     `json:"email"`
	EmailVerified  bool       `json:"emailVerified"`
	PasswordHash   string     `json:"-"` // never expose password hash
	Status         UserStatus `json:"status"`
	FailedAttempts int        `json:"-"`
	LockedUntil    *time.Time `json:"-"`
	CreatedAt      time.Time  `json:"createdAt"`
	UpdatedAt      time.Time  `json:"updatedAt"`
	DeletedAt      *time.Time `json:"-"`
}

// UserProfile represents extended user profile data
type UserProfile struct {
	UserID      string                 `json:"userId"`
	DisplayName *string                `json:"displayName,omitempty"`
	AvatarURL   *string                `json:"avatarUrl,omitempty"`
	Locale      string                 `json:"locale"`
	Timezone    string                 `json:"timezone"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt   time.Time              `json:"createdAt"`
	UpdatedAt   time.Time              `json:"updatedAt"`
}

// UserWithProfile combines User and UserProfile
type UserWithProfile struct {
	User    `json:"user"`
	Profile *UserProfile `json:"profile,omitempty"`
}

// IsLocked checks if the user account is currently locked
func (u *User) IsLocked() bool {
	if u.LockedUntil == nil {
		return false
	}
	return time.Now().Before(*u.LockedUntil)
}

// IsActive checks if the user account is active
func (u *User) IsActive() bool {
	return u.Status == UserStatusActive
}
