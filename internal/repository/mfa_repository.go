package repository

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/hostedid/hostedid/internal/database"
	"github.com/hostedid/hostedid/internal/model"
)

// MFARepository handles MFA data persistence
type MFARepository struct {
	db *database.Postgres
}

// NewMFARepository creates a new MFARepository
func NewMFARepository(db *database.Postgres) *MFARepository {
	return &MFARepository{db: db}
}

// --- MFA Methods ---

// CreateMethod inserts a new MFA method for a user
func (r *MFARepository) CreateMethod(ctx context.Context, method *model.MFAMethod) error {
	query := `
		INSERT INTO mfa_methods (id, user_id, method, secret, credential_data, is_primary, last_used, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`
	_, err := r.db.ExecContext(ctx, query,
		method.ID,
		method.UserID,
		method.Method,
		method.Secret,
		method.CredentialData,
		method.IsPrimary,
		method.LastUsed,
		method.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create MFA method: %w", err)
	}
	return nil
}

// GetMethodByUserAndType retrieves a specific MFA method for a user
func (r *MFARepository) GetMethodByUserAndType(ctx context.Context, userID string, method model.MFAMethodType) (*model.MFAMethod, error) {
	query := `
		SELECT id, user_id, method, secret, credential_data, is_primary, last_used, created_at
		FROM mfa_methods
		WHERE user_id = $1 AND method = $2
	`
	var m model.MFAMethod
	err := r.db.QueryRowContext(ctx, query, userID, method).Scan(
		&m.ID,
		&m.UserID,
		&m.Method,
		&m.Secret,
		&m.CredentialData,
		&m.IsPrimary,
		&m.LastUsed,
		&m.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get MFA method: %w", err)
	}
	return &m, nil
}

// GetMethodsByUser retrieves all MFA methods for a user
func (r *MFARepository) GetMethodsByUser(ctx context.Context, userID string) ([]*model.MFAMethod, error) {
	query := `
		SELECT id, user_id, method, secret, credential_data, is_primary, last_used, created_at
		FROM mfa_methods
		WHERE user_id = $1
		ORDER BY created_at ASC
	`
	rows, err := r.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to query MFA methods: %w", err)
	}
	defer rows.Close()

	var methods []*model.MFAMethod
	for rows.Next() {
		var m model.MFAMethod
		if err := rows.Scan(
			&m.ID,
			&m.UserID,
			&m.Method,
			&m.Secret,
			&m.CredentialData,
			&m.IsPrimary,
			&m.LastUsed,
			&m.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan MFA method: %w", err)
		}
		methods = append(methods, &m)
	}
	return methods, rows.Err()
}

// UpdateMethodLastUsed updates the last_used timestamp for an MFA method
func (r *MFARepository) UpdateMethodLastUsed(ctx context.Context, id string) error {
	query := `UPDATE mfa_methods SET last_used = $1 WHERE id = $2`
	_, err := r.db.ExecContext(ctx, query, time.Now(), id)
	if err != nil {
		return fmt.Errorf("failed to update MFA method last_used: %w", err)
	}
	return nil
}

// UpdateMethodCredentialData updates the credential_data for an MFA method (WebAuthn)
func (r *MFARepository) UpdateMethodCredentialData(ctx context.Context, id string, data []byte) error {
	query := `UPDATE mfa_methods SET credential_data = $1 WHERE id = $2`
	_, err := r.db.ExecContext(ctx, query, data, id)
	if err != nil {
		return fmt.Errorf("failed to update MFA credential data: %w", err)
	}
	return nil
}

// DeleteMethod removes an MFA method
func (r *MFARepository) DeleteMethod(ctx context.Context, userID string, method model.MFAMethodType) error {
	query := `DELETE FROM mfa_methods WHERE user_id = $1 AND method = $2`
	result, err := r.db.ExecContext(ctx, query, userID, method)
	if err != nil {
		return fmt.Errorf("failed to delete MFA method: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// SetPrimaryMethod sets an MFA method as primary and unsets others
func (r *MFARepository) SetPrimaryMethod(ctx context.Context, userID string, method model.MFAMethodType) error {
	// Unset all as primary
	query := `UPDATE mfa_methods SET is_primary = FALSE WHERE user_id = $1`
	if _, err := r.db.ExecContext(ctx, query, userID); err != nil {
		return fmt.Errorf("failed to unset primary methods: %w", err)
	}

	// Set the target as primary
	query = `UPDATE mfa_methods SET is_primary = TRUE WHERE user_id = $1 AND method = $2`
	result, err := r.db.ExecContext(ctx, query, userID, method)
	if err != nil {
		return fmt.Errorf("failed to set primary method: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// HasAnyMethod checks if a user has any MFA method enrolled
func (r *MFARepository) HasAnyMethod(ctx context.Context, userID string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM mfa_methods WHERE user_id = $1)`
	var exists bool
	err := r.db.QueryRowContext(ctx, query, userID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check MFA methods: %w", err)
	}
	return exists, nil
}

// --- Backup Codes ---

// CreateBackupCodes inserts a batch of backup codes
func (r *MFARepository) CreateBackupCodes(ctx context.Context, codes []*model.BackupCode) error {
	tx, err := r.db.BeginTx(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	query := `INSERT INTO backup_codes (id, user_id, code_hash, created_at) VALUES ($1, $2, $3, $4)`
	for _, code := range codes {
		if _, err := tx.ExecContext(ctx, query, code.ID, code.UserID, code.CodeHash, code.CreatedAt); err != nil {
			return fmt.Errorf("failed to insert backup code: %w", err)
		}
	}

	return tx.Commit()
}

// GetUnusedBackupCodes retrieves all unused backup codes for a user
func (r *MFARepository) GetUnusedBackupCodes(ctx context.Context, userID string) ([]*model.BackupCode, error) {
	query := `
		SELECT id, user_id, code_hash, used_at, created_at
		FROM backup_codes
		WHERE user_id = $1 AND used_at IS NULL
		ORDER BY created_at ASC
	`
	rows, err := r.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to query backup codes: %w", err)
	}
	defer rows.Close()

	var codes []*model.BackupCode
	for rows.Next() {
		var c model.BackupCode
		if err := rows.Scan(&c.ID, &c.UserID, &c.CodeHash, &c.UsedAt, &c.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan backup code: %w", err)
		}
		codes = append(codes, &c)
	}
	return codes, rows.Err()
}

// CountUnusedBackupCodes returns the count of remaining unused backup codes
func (r *MFARepository) CountUnusedBackupCodes(ctx context.Context, userID string) (int, error) {
	query := `SELECT COUNT(*) FROM backup_codes WHERE user_id = $1 AND used_at IS NULL`
	var count int
	if err := r.db.QueryRowContext(ctx, query, userID).Scan(&count); err != nil {
		return 0, fmt.Errorf("failed to count backup codes: %w", err)
	}
	return count, nil
}

// MarkBackupCodeUsed marks a backup code as used
func (r *MFARepository) MarkBackupCodeUsed(ctx context.Context, id string) error {
	query := `UPDATE backup_codes SET used_at = $1 WHERE id = $2`
	_, err := r.db.ExecContext(ctx, query, time.Now(), id)
	if err != nil {
		return fmt.Errorf("failed to mark backup code as used: %w", err)
	}
	return nil
}

// DeleteAllBackupCodes removes all backup codes for a user (used before regeneration)
func (r *MFARepository) DeleteAllBackupCodes(ctx context.Context, userID string) error {
	query := `DELETE FROM backup_codes WHERE user_id = $1`
	_, err := r.db.ExecContext(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("failed to delete backup codes: %w", err)
	}
	return nil
}
