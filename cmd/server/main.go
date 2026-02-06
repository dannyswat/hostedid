package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/hostedid/hostedid/internal/auth"
	"github.com/hostedid/hostedid/internal/config"
	"github.com/hostedid/hostedid/internal/database"
	"github.com/hostedid/hostedid/internal/handler"
	"github.com/hostedid/hostedid/internal/logger"
	"github.com/hostedid/hostedid/internal/middleware"
	"github.com/hostedid/hostedid/internal/repository"
	"github.com/hostedid/hostedid/internal/router"
	"github.com/hostedid/hostedid/internal/service"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		os.Exit(1)
	}

	// Initialize logger
	log := logger.New(cfg.Log.Level, cfg.Log.Format)
	log.Info().Str("version", "0.1.0").Msg("starting HostedID server")

	// Connect to PostgreSQL
	db, err := database.NewPostgres(cfg.Database)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to connect to database")
	}
	defer db.Close()
	log.Info().Msg("connected to PostgreSQL")

	// Connect to Redis
	rdb, err := database.NewRedis(cfg.Redis)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to connect to Redis")
	}
	defer rdb.Close()
	log.Info().Msg("connected to Redis")

	// Initialize repositories
	userRepo := repository.NewUserRepository(db)
	tokenRepo := repository.NewTokenRepository(db)
	deviceRepo := repository.NewDeviceRepository(db)
	auditRepo := repository.NewAuditRepository(db)
	passwordResetRepo := repository.NewPasswordResetRepository(db)
	signingKeyRepo := repository.NewSigningKeyRepository(db)
	mfaRepo := repository.NewMFARepository(db)

	// Initialize key service (must be before token service)
	keySvc := service.NewKeyService(signingKeyRepo, log)
	if err := keySvc.Initialize(context.Background(), cfg.Security.Tokens.SigningAlgorithm); err != nil {
		log.Fatal().Err(err).Msg("failed to initialize key service")
	}
	log.Info().
		Str("algorithm", keySvc.GetAlgorithm()).
		Str("active_key_id", keySvc.GetActiveKeyID()).
		Msg("key service initialized")

	// Initialize token service with key provider
	tokenSvc, err := auth.NewTokenService(cfg.Security.Tokens, keySvc)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to initialize token service")
	}
	log.Info().Str("algorithm", cfg.Security.Tokens.SigningAlgorithm).Msg("token service initialized")

	// Initialize services
	authSvc := service.NewAuthService(userRepo, tokenRepo, deviceRepo, auditRepo, passwordResetRepo, mfaRepo, tokenSvc, cfg, log)

	// Initialize MFA service
	mfaSvc, err := service.NewMFAService(mfaRepo, userRepo, cfg, log)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to initialize MFA service")
	}
	log.Info().Msg("MFA service initialized")

	// Initialize device service
	deviceSvc := service.NewDeviceService(deviceRepo, tokenRepo, auditRepo, cfg, log)
	log.Info().Msg("device service initialized")

	// Initialize session service
	sessionSvc := service.NewSessionService(deviceRepo, tokenRepo, auditRepo, rdb, cfg, log)
	log.Info().Msg("session service initialized")

	// Initialize back-channel logout service
	backChannelSvc := service.NewBackChannelLogoutService(sessionSvc, tokenSvc, deviceRepo, auditRepo, cfg, log)
	log.Info().Msg("back-channel logout service initialized")

	// Initialize handlers
	h := handler.New(db, rdb, log, cfg, authSvc, keySvc, mfaSvc, deviceSvc, sessionSvc, backChannelSvc)

	// Initialize middleware
	mw := middleware.New(rdb, log, cfg)

	// Set up router
	r := router.New(h, mw, log, tokenSvc)

	// Create HTTP server
	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	srv := &http.Server{
		Addr:         addr,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in goroutine
	go func() {
		log.Info().Str("addr", addr).Msg("HTTP server listening")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Msg("HTTP server error")
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info().Msg("shutting down server...")

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal().Err(err).Msg("server forced to shutdown")
	}

	log.Info().Msg("server stopped")
}
