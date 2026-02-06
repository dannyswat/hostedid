.PHONY: help build run test clean docker-build docker-up docker-down migrate-up migrate-down fmt lint

# Default target
help:
	@echo "HostedID - Self-Hosted Identity Solution"
	@echo ""
	@echo "Usage:"
	@echo "  make build          Build the server binary"
	@echo "  make run            Run the server locally"
	@echo "  make test           Run all tests"
	@echo "  make clean          Clean build artifacts"
	@echo "  make docker-build   Build Docker images"
	@echo "  make docker-up      Start all services with Docker Compose"
	@echo "  make docker-down    Stop all services"
	@echo "  make migrate-up     Run database migrations"
	@echo "  make migrate-down   Rollback last migration"
	@echo "  make migrate-status Show migration status"
	@echo "  make fmt            Format Go code"
	@echo "  make lint           Run linter"
	@echo "  make deps           Download dependencies"
	@echo "  make dev            Run in development mode"
	@echo ""

# Build the server
build:
	go build -o bin/server ./cmd/server
	go build -o bin/migrate ./cmd/migrate

# Run the server locally
run:
	go run ./cmd/server

# Run tests
test:
	go test -v -race -cover ./...

# Clean build artifacts
clean:
	rm -rf bin/
	go clean

# Download dependencies
deps:
	go mod download
	go mod tidy

# Format code
fmt:
	go fmt ./...
	gofumpt -l -w .

# Run linter
lint:
	golangci-lint run ./...

# Docker commands
docker-build:
	docker compose build

docker-up:
	docker compose up -d

docker-down:
	docker compose down

docker-logs:
	docker compose logs -f

# Migration commands
migrate-up:
	go run ./cmd/migrate up

migrate-down:
	go run ./cmd/migrate down

migrate-status:
	go run ./cmd/migrate status

migrate-create:
	@read -p "Migration name: " name; \
	go run ./cmd/migrate create $$name

# Development mode (with hot reload using air)
dev:
	@if command -v air > /dev/null; then \
		air; \
	else \
		echo "Installing air..."; \
		go install github.com/air-verse/air@latest; \
		air; \
	fi

# Start local development dependencies
dev-deps:
	docker compose up -d postgres redis

# Stop local development dependencies
dev-deps-down:
	docker compose down postgres redis

# Run frontend development server
frontend-dev:
	cd frontend && npm run dev

# Install frontend dependencies
frontend-install:
	cd frontend && npm install

# Build frontend
frontend-build:
	cd frontend && npm run build
