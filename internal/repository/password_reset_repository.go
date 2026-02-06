package repository

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/hostedid/hostedid/internal/database"
	"github.com/hostedid/hostedid/internal/model"
)

// PasswordResetRepository handles password reset token persistence
type PasswordResetRepository struct {
	db *database.Postgres
}

// NewPasswordResetRepository creates a new PasswordResetRepository
func NewPasswordResetRepository(db *database.Postgres) *PasswordResetRepository {
	return &PasswordResetRepository{db: db}
}

// Create stores a new password reset token
func (r *PasswordResetRepository) Create(ctx context.Context, token *model.PasswordResetToken) error {
	query := `
		INSERT INTO password_reset_tokens (id, user_id, token_hash, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5)
	`
	_, err := r.db.ExecContext(ctx, query,
		token.ID,
		token.UserID,
		token.TokenHash,
		token.ExpiresAt,
		token.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create password reset token: %w", err)
	}
	return nil
}

// GetByTokenHash retrieves a password reset token by its hash
func (r *PasswordResetRepository) GetByTokenHash(ctx context.Context, tokenHash string) (*model.PasswordResetToken, error) {
	query := `
		SELECT id, user_id, token_hash, expires_at, used_at, created_at
		FROM password_reset_tokens
		WHERE token_hash = $1
	`
	var token model.PasswordResetToken
	err := r.db.QueryRowContext(ctx, query, tokenHash).Scan(
		&token.ID,
		&token.UserID,
		&token.TokenHash,
		&token.ExpiresAt,
		&token.UsedAt,
		&token.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get password reset token: %w", err)
	}
	return &token, nil
}

// MarkUsed marks a password reset token as used
func (r *PasswordResetRepository) MarkUsed(ctx context.Context, id string) error {
	query := `UPDATE password_reset_tokens SET used_at = $1 WHERE id = $2`
	_, err := r.db.ExecContext(ctx, query, time.Now(), id)
	if err != nil {
		return fmt.Errorf("failed to mark password reset token as used: %w", err)
	}
	return nil
}

// InvalidateAllForUser invalidates all unused password reset tokens for a user
func (r *PasswordResetRepository) InvalidateAllForUser(ctx context.Context, userID string) error {
	query := `UPDATE password_reset_tokens SET used_at = $1 WHERE user_id = $2 AND used_at IS NULL`
	_, err := r.db.ExecContext(ctx, query, time.Now(), userID)
	if err != nil {
		return fmt.Errorf("failed to invalidate password reset tokens: %w", err)
	}
	return nil
}

// CleanupExpired removes expired password reset tokens
func (r *PasswordResetRepository) CleanupExpired(ctx context.Context) (int64, error) {
	query := `DELETE FROM password_reset_tokens WHERE expires_at < $1`
	result, err := r.db.ExecContext(ctx, query, time.Now())
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup expired password reset tokens: %w", err)
	}
	return result.RowsAffected()
}

// CountRecentByUserID counts recent password reset tokens for rate limiting
func (r *PasswordResetRepository) CountRecentByUserID(ctx context.Context, userID string, since time.Time) (int, error) {
	query := `SELECT COUNT(*) FROM password_reset_tokens WHERE user_id = $1 AND created_at > $2`
	var count int
	err := r.db.QueryRowContext(ctx, query, userID, since).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count recent password reset tokens: %w", err)
	}
	return count, nil
}
