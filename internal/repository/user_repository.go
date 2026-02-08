package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/hostedid/hostedid/internal/database"
	"github.com/hostedid/hostedid/internal/model"
)

// UserRepository handles user data persistence
type UserRepository struct {
	db *database.Postgres
}

// NewUserRepository creates a new UserRepository
func NewUserRepository(db *database.Postgres) *UserRepository {
	return &UserRepository{db: db}
}

// Create inserts a new user into the database
func (r *UserRepository) Create(ctx context.Context, user *model.User) error {
	query := `
		INSERT INTO users (id, email, email_verified, password_hash, status, failed_attempts, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`
	_, err := r.db.ExecContext(ctx, query,
		user.ID,
		user.Email,
		user.EmailVerified,
		user.PasswordHash,
		user.Status,
		user.FailedAttempts,
		user.CreatedAt,
		user.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}
	return nil
}

// GetByID retrieves a user by ID (excludes soft-deleted)
func (r *UserRepository) GetByID(ctx context.Context, id string) (*model.User, error) {
	query := `
		SELECT id, email, email_verified, password_hash, status,
		       failed_attempts, locked_until, created_at, updated_at
		FROM users
		WHERE id = $1 AND deleted_at IS NULL
	`
	return r.scanUser(r.db.QueryRowContext(ctx, query, id))
}

// GetByEmail retrieves a user by email (excludes soft-deleted)
func (r *UserRepository) GetByEmail(ctx context.Context, email string) (*model.User, error) {
	query := `
		SELECT id, email, email_verified, password_hash, status,
		       failed_attempts, locked_until, created_at, updated_at
		FROM users
		WHERE email = $1 AND deleted_at IS NULL
	`
	return r.scanUser(r.db.QueryRowContext(ctx, query, email))
}

// ExistsByEmail checks if a user with the given email exists
func (r *UserRepository) ExistsByEmail(ctx context.Context, email string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM users WHERE email = $1 AND deleted_at IS NULL)`
	var exists bool
	err := r.db.QueryRowContext(ctx, query, email).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check email existence: %w", err)
	}
	return exists, nil
}

// UpdateStatus updates the user's status
func (r *UserRepository) UpdateStatus(ctx context.Context, id string, status model.UserStatus) error {
	query := `UPDATE users SET status = $1 WHERE id = $2 AND deleted_at IS NULL`
	result, err := r.db.ExecContext(ctx, query, status, id)
	if err != nil {
		return fmt.Errorf("failed to update user status: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// UpdatePasswordHash updates the user's password hash
func (r *UserRepository) UpdatePasswordHash(ctx context.Context, id string, hash string) error {
	query := `UPDATE users SET password_hash = $1 WHERE id = $2 AND deleted_at IS NULL`
	result, err := r.db.ExecContext(ctx, query, hash, id)
	if err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// VerifyEmail marks the user's email as verified
func (r *UserRepository) VerifyEmail(ctx context.Context, id string) error {
	query := `UPDATE users SET email_verified = true, updated_at = $1 WHERE id = $2 AND deleted_at IS NULL`
	result, err := r.db.ExecContext(ctx, query, time.Now(), id)
	if err != nil {
		return fmt.Errorf("failed to verify email: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// IncrementFailedAttempts increments the failed login attempts counter
func (r *UserRepository) IncrementFailedAttempts(ctx context.Context, id string) (int, error) {
	query := `
		UPDATE users
		SET failed_attempts = failed_attempts + 1
		WHERE id = $1 AND deleted_at IS NULL
		RETURNING failed_attempts
	`
	var attempts int
	err := r.db.QueryRowContext(ctx, query, id).Scan(&attempts)
	if err != nil {
		return 0, fmt.Errorf("failed to increment failed attempts: %w", err)
	}
	return attempts, nil
}

// ResetFailedAttempts resets the failed login attempts counter
func (r *UserRepository) ResetFailedAttempts(ctx context.Context, id string) error {
	query := `UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to reset failed attempts: %w", err)
	}
	return nil
}

// LockUntil locks the user account until the specified time
func (r *UserRepository) LockUntil(ctx context.Context, id string, until time.Time) error {
	query := `UPDATE users SET locked_until = $1, status = $2 WHERE id = $3`
	_, err := r.db.ExecContext(ctx, query, until, model.UserStatusLocked, id)
	if err != nil {
		return fmt.Errorf("failed to lock user: %w", err)
	}
	return nil
}

// scanUser scans a single user row
func (r *UserRepository) scanUser(row *sql.Row) (*model.User, error) {
	var user model.User
	err := row.Scan(
		&user.ID,
		&user.Email,
		&user.EmailVerified,
		&user.PasswordHash,
		&user.Status,
		&user.FailedAttempts,
		&user.LockedUntil,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to scan user: %w", err)
	}
	return &user, nil
}

// CreateProfile creates a user profile
func (r *UserRepository) CreateProfile(ctx context.Context, profile *model.UserProfile) error {
	metadataJSON, err := json.Marshal(profile.Metadata)
	if err != nil {
		metadataJSON = []byte("{}")
	}

	query := `
		INSERT INTO user_profiles (user_id, display_name, avatar_url, locale, timezone, metadata, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`
	_, err = r.db.ExecContext(ctx, query,
		profile.UserID,
		profile.DisplayName,
		profile.AvatarURL,
		profile.Locale,
		profile.Timezone,
		metadataJSON,
		profile.CreatedAt,
		profile.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create user profile: %w", err)
	}
	return nil
}

// GetProfile retrieves a user profile by user ID
func (r *UserRepository) GetProfile(ctx context.Context, userID string) (*model.UserProfile, error) {
	query := `
		SELECT user_id, display_name, avatar_url, locale, timezone, metadata, created_at, updated_at
		FROM user_profiles
		WHERE user_id = $1
	`
	var profile model.UserProfile
	var metadataJSON []byte
	err := r.db.QueryRowContext(ctx, query, userID).Scan(
		&profile.UserID,
		&profile.DisplayName,
		&profile.AvatarURL,
		&profile.Locale,
		&profile.Timezone,
		&metadataJSON,
		&profile.CreatedAt,
		&profile.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil // Profile is optional
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user profile: %w", err)
	}

	if len(metadataJSON) > 0 {
		json.Unmarshal(metadataJSON, &profile.Metadata)
	}

	return &profile, nil
}
