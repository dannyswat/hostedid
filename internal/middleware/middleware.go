package middleware

import (
	"github.com/hostedid/hostedid/internal/config"
	"github.com/hostedid/hostedid/internal/database"
	"github.com/hostedid/hostedid/internal/logger"
)

// Middleware holds all HTTP middleware
type Middleware struct {
	rdb *database.Redis
	log *logger.Logger
	cfg *config.Config
}

// New creates a new Middleware instance
func New(rdb *database.Redis, log *logger.Logger, cfg *config.Config) *Middleware {
	return &Middleware{
		rdb: rdb,
		log: log,
		cfg: cfg,
	}
}
