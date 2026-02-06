package repository

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hostedid/hostedid/internal/database"
	"github.com/hostedid/hostedid/internal/model"
)

// AuditRepository handles audit log persistence
type AuditRepository struct {
	db *database.Postgres
}

// NewAuditRepository creates a new AuditRepository
func NewAuditRepository(db *database.Postgres) *AuditRepository {
	return &AuditRepository{db: db}
}

// Create inserts a new audit log entry
func (r *AuditRepository) Create(ctx context.Context, log *model.AuditLog) error {
	metadataJSON, err := json.Marshal(log.Metadata)
	if err != nil {
		metadataJSON = []byte("{}")
	}

	query := `
		INSERT INTO audit_logs (id, user_id, action, resource_type, resource_id,
		    ip_address, user_agent, metadata, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`
	_, err = r.db.ExecContext(ctx, query,
		log.ID,
		log.UserID,
		log.Action,
		log.ResourceType,
		log.ResourceID,
		log.IPAddress,
		log.UserAgent,
		metadataJSON,
		log.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create audit log: %w", err)
	}
	return nil
}
