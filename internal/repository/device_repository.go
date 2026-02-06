package repository

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/hostedid/hostedid/internal/database"
	"github.com/hostedid/hostedid/internal/model"
)

// DeviceRepository handles device data persistence
type DeviceRepository struct {
	db *database.Postgres
}

// NewDeviceRepository creates a new DeviceRepository
func NewDeviceRepository(db *database.Postgres) *DeviceRepository {
	return &DeviceRepository{db: db}
}

// Create inserts a new device
func (r *DeviceRepository) Create(ctx context.Context, device *model.Device) error {
	query := `
		INSERT INTO devices (id, user_id, fingerprint_hash, name, user_agent, is_trusted,
		    current_ip, session_active, session_started_at, session_expires_at,
		    last_activity, first_seen, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
	`
	_, err := r.db.ExecContext(ctx, query,
		device.ID,
		device.UserID,
		device.FingerprintHash,
		device.Name,
		device.UserAgent,
		device.IsTrusted,
		device.CurrentIP,
		device.SessionActive,
		device.SessionStartedAt,
		device.SessionExpiresAt,
		device.LastActivity,
		device.FirstSeen,
		device.CreatedAt,
		device.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create device: %w", err)
	}
	return nil
}

// GetByID retrieves a device by ID
func (r *DeviceRepository) GetByID(ctx context.Context, id string) (*model.Device, error) {
	query := `
		SELECT id, user_id, fingerprint_hash, name, user_agent, is_trusted, trust_expires_at,
		       current_ip, current_location, session_active, session_started_at, session_expires_at,
		       last_activity, first_seen, created_at, updated_at
		FROM devices
		WHERE id = $1
	`
	return r.scanDevice(r.db.QueryRowContext(ctx, query, id))
}

// GetByUserAndFingerprint finds a device by user ID and fingerprint hash
func (r *DeviceRepository) GetByUserAndFingerprint(ctx context.Context, userID, fingerprintHash string) (*model.Device, error) {
	query := `
		SELECT id, user_id, fingerprint_hash, name, user_agent, is_trusted, trust_expires_at,
		       current_ip, current_location, session_active, session_started_at, session_expires_at,
		       last_activity, first_seen, created_at, updated_at
		FROM devices
		WHERE user_id = $1 AND fingerprint_hash = $2
	`
	return r.scanDevice(r.db.QueryRowContext(ctx, query, userID, fingerprintHash))
}

// UpdateSession updates the session state of a device
func (r *DeviceRepository) UpdateSession(ctx context.Context, id string, active bool, startedAt, expiresAt *time.Time, ip *string) error {
	query := `
		UPDATE devices
		SET session_active = $1, session_started_at = $2, session_expires_at = $3,
		    current_ip = $4, last_activity = NOW()
		WHERE id = $5
	`
	_, err := r.db.ExecContext(ctx, query, active, startedAt, expiresAt, ip, id)
	if err != nil {
		return fmt.Errorf("failed to update device session: %w", err)
	}
	return nil
}

// GetByUserID returns all devices for a user
func (r *DeviceRepository) GetByUserID(ctx context.Context, userID string) ([]model.Device, error) {
	query := `
		SELECT id, user_id, fingerprint_hash, name, user_agent, is_trusted, trust_expires_at,
		       current_ip, current_location, session_active, session_started_at, session_expires_at,
		       last_activity, first_seen, created_at, updated_at
		FROM devices
		WHERE user_id = $1
		ORDER BY last_activity DESC
	`
	rows, err := r.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to query user devices: %w", err)
	}
	defer rows.Close()

	var devices []model.Device
	for rows.Next() {
		var device model.Device
		err := rows.Scan(
			&device.ID,
			&device.UserID,
			&device.FingerprintHash,
			&device.Name,
			&device.UserAgent,
			&device.IsTrusted,
			&device.TrustExpiresAt,
			&device.CurrentIP,
			&device.CurrentLocation,
			&device.SessionActive,
			&device.SessionStartedAt,
			&device.SessionExpiresAt,
			&device.LastActivity,
			&device.FirstSeen,
			&device.CreatedAt,
			&device.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan device row: %w", err)
		}
		devices = append(devices, device)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate device rows: %w", err)
	}
	return devices, nil
}

// UpdateTrust updates the trust status of a device
func (r *DeviceRepository) UpdateTrust(ctx context.Context, id string, trusted bool, expiresAt *time.Time) error {
	query := `
		UPDATE devices
		SET is_trusted = $1, trust_expires_at = $2, updated_at = NOW()
		WHERE id = $3
	`
	_, err := r.db.ExecContext(ctx, query, trusted, expiresAt, id)
	if err != nil {
		return fmt.Errorf("failed to update device trust: %w", err)
	}
	return nil
}

// UpdateName updates a device's name
func (r *DeviceRepository) UpdateName(ctx context.Context, id, name string) error {
	query := `
		UPDATE devices
		SET name = $1, updated_at = NOW()
		WHERE id = $2
	`
	_, err := r.db.ExecContext(ctx, query, name, id)
	if err != nil {
		return fmt.Errorf("failed to update device name: %w", err)
	}
	return nil
}

// Delete removes a device record
func (r *DeviceRepository) Delete(ctx context.Context, id string) error {
	query := `DELETE FROM devices WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete device: %w", err)
	}
	return nil
}

// DeactivateAllUserSessions deactivates all sessions for a user
func (r *DeviceRepository) DeactivateAllUserSessions(ctx context.Context, userID string) error {
	query := `
		UPDATE devices
		SET session_active = FALSE
		WHERE user_id = $1 AND session_active = TRUE
	`
	_, err := r.db.ExecContext(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("failed to deactivate user sessions: %w", err)
	}
	return nil
}

// UpdateLastActivity updates the last_activity timestamp for a device
func (r *DeviceRepository) UpdateLastActivity(ctx context.Context, id string, lastActivity time.Time) error {
	query := `UPDATE devices SET last_activity = $1 WHERE id = $2`
	_, err := r.db.ExecContext(ctx, query, lastActivity, id)
	if err != nil {
		return fmt.Errorf("failed to update last activity: %w", err)
	}
	return nil
}

// GetActiveSessionsByUserID returns all devices with active sessions for a user
func (r *DeviceRepository) GetActiveSessionsByUserID(ctx context.Context, userID string) ([]model.Device, error) {
	query := `
		SELECT id, user_id, fingerprint_hash, name, user_agent, is_trusted, trust_expires_at,
		       current_ip, current_location, session_active, session_started_at, session_expires_at,
		       last_activity, first_seen, created_at, updated_at
		FROM devices
		WHERE user_id = $1 AND session_active = TRUE
		ORDER BY last_activity DESC
	`
	rows, err := r.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to query active sessions: %w", err)
	}
	defer rows.Close()

	var devices []model.Device
	for rows.Next() {
		var device model.Device
		err := rows.Scan(
			&device.ID,
			&device.UserID,
			&device.FingerprintHash,
			&device.Name,
			&device.UserAgent,
			&device.IsTrusted,
			&device.TrustExpiresAt,
			&device.CurrentIP,
			&device.CurrentLocation,
			&device.SessionActive,
			&device.SessionStartedAt,
			&device.SessionExpiresAt,
			&device.LastActivity,
			&device.FirstSeen,
			&device.CreatedAt,
			&device.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan device row: %w", err)
		}
		devices = append(devices, device)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate device rows: %w", err)
	}
	return devices, nil
}

// CountByUserID returns the number of devices for a user
func (r *DeviceRepository) CountByUserID(ctx context.Context, userID string) (int, error) {
	query := `SELECT COUNT(*) FROM devices WHERE user_id = $1`
	var count int
	err := r.db.QueryRowContext(ctx, query, userID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count user devices: %w", err)
	}
	return count, nil
}

// scanDevice scans a single device row
func (r *DeviceRepository) scanDevice(row *sql.Row) (*model.Device, error) {
	var device model.Device
	err := row.Scan(
		&device.ID,
		&device.UserID,
		&device.FingerprintHash,
		&device.Name,
		&device.UserAgent,
		&device.IsTrusted,
		&device.TrustExpiresAt,
		&device.CurrentIP,
		&device.CurrentLocation,
		&device.SessionActive,
		&device.SessionStartedAt,
		&device.SessionExpiresAt,
		&device.LastActivity,
		&device.FirstSeen,
		&device.CreatedAt,
		&device.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to scan device: %w", err)
	}
	return &device, nil
}
