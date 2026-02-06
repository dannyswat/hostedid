package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/hostedid/hostedid/internal/config"
	_ "github.com/lib/pq"
)

// Postgres wraps the SQL database connection
type Postgres struct {
	*sql.DB
}

// NewPostgres creates a new PostgreSQL connection
func NewPostgres(cfg config.DatabaseConfig) (*Postgres, error) {
	db, err := sql.Open("postgres", cfg.DSN())
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(cfg.MaxConnections)
	db.SetMaxIdleConns(cfg.MaxConnections / 4)
	db.SetConnMaxLifetime(time.Hour)
	db.SetConnMaxIdleTime(30 * time.Minute)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return &Postgres{DB: db}, nil
}

// HealthCheck verifies the database connection is healthy
func (p *Postgres) HealthCheck(ctx context.Context) error {
	return p.PingContext(ctx)
}

// BeginTx starts a new transaction with the given options
func (p *Postgres) BeginTx(ctx context.Context) (*sql.Tx, error) {
	return p.DB.BeginTx(ctx, nil)
}

// ExecContext executes a query without returning any rows
func (p *Postgres) ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error) {
	return p.DB.ExecContext(ctx, query, args...)
}

// QueryContext executes a query that returns rows
func (p *Postgres) QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error) {
	return p.DB.QueryContext(ctx, query, args...)
}

// QueryRowContext executes a query that returns at most one row
func (p *Postgres) QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row {
	return p.DB.QueryRowContext(ctx, query, args...)
}
