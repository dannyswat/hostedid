package main

import (
	"fmt"
	"os"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/hostedid/hostedid/internal/config"
	"github.com/hostedid/hostedid/internal/database"
	"github.com/hostedid/hostedid/internal/logger"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Database migration tool for HostedID",
}

var upCmd = &cobra.Command{
	Use:   "up",
	Short: "Run all pending migrations",
	RunE:  runUp,
}

var downCmd = &cobra.Command{
	Use:   "down",
	Short: "Rollback the last migration",
	RunE:  runDown,
}

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show migration status",
	RunE:  runStatus,
}

var createCmd = &cobra.Command{
	Use:   "create [name]",
	Short: "Create a new migration file",
	Args:  cobra.ExactArgs(1),
	RunE:  runCreate,
}

func init() {
	rootCmd.AddCommand(upCmd)
	rootCmd.AddCommand(downCmd)
	rootCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(createCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func getMigrator() (*migrate.Migrate, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	db, err := database.NewPostgres(cfg.Database)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	driver, err := postgres.WithInstance(db.DB, &postgres.Config{})
	if err != nil {
		return nil, fmt.Errorf("failed to create migration driver: %w", err)
	}

	m, err := migrate.NewWithDatabaseInstance(
		"file://migrations",
		"postgres",
		driver,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create migrator: %w", err)
	}

	return m, nil
}

func runUp(cmd *cobra.Command, args []string) error {
	log := logger.New("info", "text")
	log.Info().Msg("running migrations...")

	m, err := getMigrator()
	if err != nil {
		return err
	}

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("migration failed: %w", err)
	}

	log.Info().Msg("migrations completed successfully")
	return nil
}

func runDown(cmd *cobra.Command, args []string) error {
	log := logger.New("info", "text")
	log.Info().Msg("rolling back last migration...")

	m, err := getMigrator()
	if err != nil {
		return err
	}

	if err := m.Steps(-1); err != nil {
		return fmt.Errorf("rollback failed: %w", err)
	}

	log.Info().Msg("rollback completed successfully")
	return nil
}

func runStatus(cmd *cobra.Command, args []string) error {
	m, err := getMigrator()
	if err != nil {
		return err
	}

	version, dirty, err := m.Version()
	if err != nil && err != migrate.ErrNilVersion {
		return fmt.Errorf("failed to get version: %w", err)
	}

	if err == migrate.ErrNilVersion {
		fmt.Println("No migrations have been applied")
	} else {
		fmt.Printf("Current version: %d\n", version)
		fmt.Printf("Dirty: %v\n", dirty)
	}

	return nil
}

func runCreate(cmd *cobra.Command, args []string) error {
	name := args[0]

	// Create migrations directory if it doesn't exist
	if err := os.MkdirAll("migrations", 0755); err != nil {
		return fmt.Errorf("failed to create migrations directory: %w", err)
	}

	// Get next version number
	entries, err := os.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("failed to read migrations directory: %w", err)
	}

	version := 1
	for _, entry := range entries {
		if !entry.IsDir() {
			version++
		}
	}
	version = (version / 2) + 1

	// Create up and down migration files
	upFile := fmt.Sprintf("migrations/%06d_%s.up.sql", version, name)
	downFile := fmt.Sprintf("migrations/%06d_%s.down.sql", version, name)

	if err := os.WriteFile(upFile, []byte("-- Add migration SQL here\n"), 0644); err != nil {
		return fmt.Errorf("failed to create up migration: %w", err)
	}

	if err := os.WriteFile(downFile, []byte("-- Add rollback SQL here\n"), 0644); err != nil {
		return fmt.Errorf("failed to create down migration: %w", err)
	}

	fmt.Printf("Created migration files:\n  %s\n  %s\n", upFile, downFile)
	return nil
}
