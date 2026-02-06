package repository

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/hostedid/hostedid/internal/database"
	"github.com/hostedid/hostedid/internal/model"
)

// TokenRepository handles token persistence
type TokenRepository struct {
	db *database.Postgres
}

// NewTokenRepository creates a new TokenRepository
func NewTokenRepository(db *database.Postgres) *TokenRepository {
	return &TokenRepository{db: db}
}

// CreateRefreshToken stores a new refresh token
func (r *TokenRepository) CreateRefreshToken(ctx context.Context, token *model.RefreshToken) error {
	query := `
		INSERT INTO refresh_tokens (id, user_id, token_hash, device_id, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`
	_, err := r.db.ExecContext(ctx, query,
		token.ID,
		token.UserID,
		token.TokenHash,
		token.DeviceID,
		token.ExpiresAt,
		token.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create refresh token: %w", err)
	}
	return nil
}

// GetRefreshTokenByHash retrieves a refresh token by its hash
func (r *TokenRepository) GetRefreshTokenByHash(ctx context.Context, tokenHash string) (*model.RefreshToken, error) {
	query := `
		SELECT id, user_id, token_hash, device_id, expires_at, revoked_at, created_at
		FROM refresh_tokens
		WHERE token_hash = $1
	`
	var token model.RefreshToken
	err := r.db.QueryRowContext(ctx, query, tokenHash).Scan(
		&token.ID,
		&token.UserID,
		&token.TokenHash,
		&token.DeviceID,
		&token.ExpiresAt,
		&token.RevokedAt,
		&token.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get refresh token: %w", err)
	}
	return &token, nil
}

// RevokeRefreshToken revokes a refresh token
func (r *TokenRepository) RevokeRefreshToken(ctx context.Context, id string) error {
	query := `UPDATE refresh_tokens SET revoked_at = $1 WHERE id = $2`
	_, err := r.db.ExecContext(ctx, query, time.Now(), id)
	if err != nil {
		return fmt.Errorf("failed to revoke refresh token: %w", err)
	}
	return nil
}

// RevokeAllUserRefreshTokens revokes all refresh tokens for a user
func (r *TokenRepository) RevokeAllUserRefreshTokens(ctx context.Context, userID string) error {
	query := `UPDATE refresh_tokens SET revoked_at = $1 WHERE user_id = $2 AND revoked_at IS NULL`
	_, err := r.db.ExecContext(ctx, query, time.Now(), userID)
	if err != nil {
		return fmt.Errorf("failed to revoke all refresh tokens: %w", err)
	}
	return nil
}

// RevokeRefreshTokenByDeviceID revokes all refresh tokens for a specific device
func (r *TokenRepository) RevokeRefreshTokenByDeviceID(ctx context.Context, deviceID string) error {
	query := `UPDATE refresh_tokens SET revoked_at = $1 WHERE device_id = $2 AND revoked_at IS NULL`
	_, err := r.db.ExecContext(ctx, query, time.Now(), deviceID)
	if err != nil {
		return fmt.Errorf("failed to revoke device refresh tokens: %w", err)
	}
	return nil
}

// CleanupExpiredTokens removes expired refresh tokens
func (r *TokenRepository) CleanupExpiredTokens(ctx context.Context) (int64, error) {
	query := `DELETE FROM refresh_tokens WHERE expires_at < $1`
	result, err := r.db.ExecContext(ctx, query, time.Now())
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup expired tokens: %w", err)
	}
	return result.RowsAffected()
}
