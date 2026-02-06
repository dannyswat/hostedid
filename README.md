# HostedID

A self-hosted identity and authentication solution with post-quantum cryptography support.

## Features

- 🔐 **Post-Quantum Ready** - Uses NIST-approved algorithms (ML-KEM, ML-DSA)
- 🏠 **Self-Hosted** - Full control over your authentication infrastructure
- 🔑 **Multi-Factor Authentication** - TOTP, WebAuthn/Passkeys, Backup Codes
- 📱 **Device Management** - Track and manage authenticated devices
- 🚦 **Rate Limiting** - Protection against brute force attacks
- 🔒 **Account Security** - Progressive lockout, breach detection

## Quick Start

### Prerequisites

- Go 1.22+
- Docker & Docker Compose
- Node.js 20+ (for frontend development)

### Development Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/hostedid/hostedid.git
   cd hostedid
   ```

2. **Copy configuration**
   ```bash
   cp config.example.yaml config.yaml
   ```

3. **Start dependencies**
   ```bash
   make dev-deps
   ```

4. **Run migrations**
   ```bash
   make migrate-up
   ```

5. **Start the server**
   ```bash
   make run
   ```

6. **Start the frontend** (in another terminal)
   ```bash
   make frontend-install
   make frontend-dev
   ```

### Using Docker

```bash
# Build and start all services
docker compose up -d

# Run migrations
docker compose run migrate up

# View logs
docker compose logs -f api
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/ready` | GET | Readiness check |
| `/api/v1/auth/register` | POST | User registration |
| `/api/v1/auth/login` | POST | User login |
| `/api/v1/auth/logout` | POST | User logout |
| `/api/v1/auth/token/refresh` | POST | Refresh access token |

See [SPECS.md](SPECS.md) for full API documentation.

## Project Structure

```
hostedid/
├── cmd/
│   ├── server/          # Main server application
│   └── migrate/         # Database migration tool
├── internal/
│   ├── config/          # Configuration management
│   ├── database/        # Database connections
│   ├── handler/         # HTTP handlers
│   ├── logger/          # Structured logging
│   ├── middleware/      # HTTP middleware
│   └── router/          # HTTP router
├── migrations/          # SQL migrations
├── frontend/            # React frontend
├── config.example.yaml  # Example configuration
├── docker-compose.yml   # Docker Compose configuration
└── Makefile             # Build and development tasks
```

## Configuration

Configuration can be provided via:
- YAML file (`config.yaml`)
- Environment variables (prefixed with `HOSTEDID_`)

See `config.example.yaml` for all available options.

## License

MIT License - see [LICENSE](LICENSE) for details.
