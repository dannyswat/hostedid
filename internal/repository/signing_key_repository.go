package repository

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/hostedid/hostedid/internal/database"
	"github.com/hostedid/hostedid/internal/model"
)

// SigningKeyRepository handles signing key persistence.
type SigningKeyRepository struct {
	db *database.Postgres
}

// NewSigningKeyRepository creates a new SigningKeyRepository.
func NewSigningKeyRepository(db *database.Postgres) *SigningKeyRepository {
	return &SigningKeyRepository{db: db}
}

// Create stores a new signing key.
func (r *SigningKeyRepository) Create(ctx context.Context, key *model.SigningKey) error {
	query := `
		INSERT INTO signing_keys (id, algorithm, public_key, private_key_enc, is_active, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`
	_, err := r.db.ExecContext(ctx, query,
		key.ID,
		key.Algorithm,
		key.PublicKey,
		key.PrivateKeyEnc,
		key.IsActive,
		key.ExpiresAt,
		key.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create signing key: %w", err)
	}
	return nil
}

// GetActive retrieves the currently active signing key for a given algorithm.
func (r *SigningKeyRepository) GetActive(ctx context.Context, algorithm string) (*model.SigningKey, error) {
	query := `
		SELECT id, algorithm, public_key, private_key_enc, is_active, expires_at, created_at, rotated_at
		FROM signing_keys
		WHERE algorithm = $1 AND is_active = TRUE
		ORDER BY created_at DESC
		LIMIT 1
	`
	return r.scanKey(r.db.QueryRowContext(ctx, query, algorithm))
}

// GetByID retrieves a signing key by ID.
func (r *SigningKeyRepository) GetByID(ctx context.Context, id string) (*model.SigningKey, error) {
	query := `
		SELECT id, algorithm, public_key, private_key_enc, is_active, expires_at, created_at, rotated_at
		FROM signing_keys
		WHERE id = $1
	`
	return r.scanKey(r.db.QueryRowContext(ctx, query, id))
}

// ListAll lists all signing keys (public info only).
func (r *SigningKeyRepository) ListAll(ctx context.Context) ([]*model.SigningKey, error) {
	query := `
		SELECT id, algorithm, public_key, private_key_enc, is_active, expires_at, created_at, rotated_at
		FROM signing_keys
		ORDER BY created_at DESC
	`
	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list signing keys: %w", err)
	}
	defer rows.Close()

	var keys []*model.SigningKey
	for rows.Next() {
		var key model.SigningKey
		if err := rows.Scan(
			&key.ID, &key.Algorithm, &key.PublicKey, &key.PrivateKeyEnc,
			&key.IsActive, &key.ExpiresAt, &key.CreatedAt, &key.RotatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan signing key: %w", err)
		}
		keys = append(keys, &key)
	}
	return keys, rows.Err()
}

// ListAllVerificationKeys returns all active or recently-expired keys
// that are still valid for token verification (within 1 year of creation per spec).
func (r *SigningKeyRepository) ListAllVerificationKeys(ctx context.Context, algorithm string) ([]*model.SigningKey, error) {
	query := `
		SELECT id, algorithm, public_key, private_key_enc, is_active, expires_at, created_at, rotated_at
		FROM signing_keys
		WHERE algorithm = $1 AND created_at > $2
		ORDER BY created_at DESC
	`
	verificationCutoff := time.Now().Add(-365 * 24 * time.Hour) // keys valid for verification 1 year
	rows, err := r.db.QueryContext(ctx, query, algorithm, verificationCutoff)
	if err != nil {
		return nil, fmt.Errorf("failed to list verification keys: %w", err)
	}
	defer rows.Close()

	var keys []*model.SigningKey
	for rows.Next() {
		var key model.SigningKey
		if err := rows.Scan(
			&key.ID, &key.Algorithm, &key.PublicKey, &key.PrivateKeyEnc,
			&key.IsActive, &key.ExpiresAt, &key.CreatedAt, &key.RotatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan signing key: %w", err)
		}
		keys = append(keys, &key)
	}
	return keys, rows.Err()
}

// Deactivate marks a signing key as inactive and sets its rotated_at time.
func (r *SigningKeyRepository) Deactivate(ctx context.Context, id string) error {
	query := `UPDATE signing_keys SET is_active = FALSE, rotated_at = $1 WHERE id = $2`
	result, err := r.db.ExecContext(ctx, query, time.Now(), id)
	if err != nil {
		return fmt.Errorf("failed to deactivate signing key: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// DeactivateAllForAlgorithm deactivates all keys of a given algorithm.
func (r *SigningKeyRepository) DeactivateAllForAlgorithm(ctx context.Context, algorithm string) error {
	query := `UPDATE signing_keys SET is_active = FALSE, rotated_at = $1 WHERE algorithm = $2 AND is_active = TRUE`
	_, err := r.db.ExecContext(ctx, query, time.Now(), algorithm)
	if err != nil {
		return fmt.Errorf("failed to deactivate signing keys: %w", err)
	}
	return nil
}

// DeleteExpired removes keys older than the verification window.
func (r *SigningKeyRepository) DeleteExpired(ctx context.Context, maxAge time.Duration) (int64, error) {
	cutoff := time.Now().Add(-maxAge)
	query := `DELETE FROM signing_keys WHERE is_active = FALSE AND created_at < $1`
	result, err := r.db.ExecContext(ctx, query, cutoff)
	if err != nil {
		return 0, fmt.Errorf("failed to delete expired keys: %w", err)
	}
	return result.RowsAffected()
}

func (r *SigningKeyRepository) scanKey(row *sql.Row) (*model.SigningKey, error) {
	var key model.SigningKey
	err := row.Scan(
		&key.ID, &key.Algorithm, &key.PublicKey, &key.PrivateKeyEnc,
		&key.IsActive, &key.ExpiresAt, &key.CreatedAt, &key.RotatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to scan signing key: %w", err)
	}
	return &key, nil
}
