package handler

import (
	"github.com/hostedid/hostedid/internal/config"
	"github.com/hostedid/hostedid/internal/database"
	"github.com/hostedid/hostedid/internal/logger"
	"github.com/hostedid/hostedid/internal/service"
)

// Handler holds all HTTP handlers
type Handler struct {
	db             *database.Postgres
	rdb            *database.Redis
	log            *logger.Logger
	cfg            *config.Config
	authSvc        *service.AuthService
	keySvc         *service.KeyService
	mfaSvc         *service.MFAService
	deviceSvc      *service.DeviceService
	sessionSvc     *service.SessionService
	backChannelSvc *service.BackChannelLogoutService
}

// New creates a new Handler instance
func New(db *database.Postgres, rdb *database.Redis, log *logger.Logger, cfg *config.Config, authSvc *service.AuthService, keySvc *service.KeyService, mfaSvc *service.MFAService, deviceSvc *service.DeviceService, sessionSvc *service.SessionService, backChannelSvc *service.BackChannelLogoutService) *Handler {
	return &Handler{
		db:             db,
		rdb:            rdb,
		log:            log,
		cfg:            cfg,
		authSvc:        authSvc,
		keySvc:         keySvc,
		mfaSvc:         mfaSvc,
		deviceSvc:      deviceSvc,
		sessionSvc:     sessionSvc,
		backChannelSvc: backChannelSvc,
	}
}
