# HostedID - Self-Hosted Identity Solution

## Specification Document

**Version:** 1.0.0  
**Created:** February 1, 2026  
**Status:** Draft

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Goals & Principles](#goals--principles)
3. [Architecture Overview](#architecture-overview)
4. [Security Design](#security-design)
5. [Post-Quantum Cryptography](#post-quantum-cryptography)
6. [Feature Specifications](#feature-specifications)
7. [API Design](#api-design)
8. [Database Schema](#database-schema)
9. [Frontend Architecture](#frontend-architecture)
10. [Implementation Steps](#implementation-steps)
11. [Deployment Considerations](#deployment-considerations)

---

## Executive Summary

HostedID is a self-hosted identity and authentication solution designed to provide secure, future-proof authentication services for applications within the same domain. It balances security with usability, implementing post-quantum cryptography to ensure long-term protection against emerging threats.

### Key Differentiators

- **Post-Quantum Ready**: Uses NIST-approved post-quantum cryptographic algorithms
- **Self-Hosted**: Full control over user data and authentication infrastructure
- **Domain-Scoped SSO**: Seamless authentication across applications in the same domain
- **Modern Security**: Implements defense-in-depth with rate limiting, MFA, and device management

---

## Goals & Principles

### Primary Goals

1. **Security First**: All design decisions prioritize security without compromising usability
2. **Future-Proof**: Post-quantum cryptography ensures long-term security
3. **Self-Contained**: No external dependencies for core authentication flows
4. **Scalable**: Designed to handle growth from small deployments to enterprise scale
5. **Compliance Ready**: Built with GDPR, SOC2, and similar frameworks in mind

### Design Principles

- **Zero Trust**: Verify every request, trust nothing by default
- **Defense in Depth**: Multiple layers of security controls
- **Minimal Data**: Collect only necessary user information
- **Transparent Security**: Clear audit trails and user visibility into account activity
- **Graceful Degradation**: Maintain core functionality during partial outages

---

## Architecture Overview

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Client Applications                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐ │
│  │   App A     │  │   App B     │  │   App C     │  │   Admin UI  │ │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘ │
└─────────┼────────────────┼────────────────┼────────────────┼────────┘
          │                │                │                │
          └────────────────┴────────────────┴────────────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    │         Load Balancer         │
                    └───────────────┬───────────────┘
                                    │
┌───────────────────────────────────┼───────────────────────────────────┐
│                           HostedID Core                                │
│  ┌────────────────────────────────┴────────────────────────────────┐  │
│  │                      API Gateway / Rate Limiter                  │  │
│  └────────────────────────────────┬────────────────────────────────┘  │
│                                   │                                    │
│  ┌────────────┬───────────────────┼───────────────────┬────────────┐  │
│  │            │                   │                   │            │  │
│  │  ┌─────────▼─────────┐  ┌──────▼──────┐  ┌────────▼────────┐   │  │
│  │  │   Auth Service    │  │ User Service │  │  Token Service  │   │  │
│  │  └─────────┬─────────┘  └──────┬──────┘  └────────┬────────┘   │  │
│  │            │                   │                   │            │  │
│  │  ┌─────────▼─────────┐  ┌──────▼──────────────────────────┐    │  │
│  │  │   MFA Service     │  │      Device Service             │    │  │
│  │  └───────────────────┘  └─────────────────────────────────┘    │  │
│  │                                                                 │  │
│  └─────────────────────────────────────────────────────────────────┘  │
│                                   │                                    │
│  ┌────────────────────────────────┴────────────────────────────────┐  │
│  │                       Data Layer                                 │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │  │
│  │  │ PostgreSQL  │  │    Redis    │  │  Key Management (HSM)   │  │  │
│  │  │  (Primary)  │  │  (Cache/    │  │  Post-Quantum Keys      │  │  │
│  │  │             │  │   Sessions) │  │                         │  │  │
│  │  └─────────────┘  └─────────────┘  └─────────────────────────┘  │  │
│  └─────────────────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────────────────┘
```

### Technology Stack

| Component | Technology | Justification |
|-----------|------------|---------------|
| Backend | Go 1.22+ | Performance, strong typing, excellent crypto libraries |
| Frontend | React 18+ with TypeScript | Component reusability, type safety |
| Database | PostgreSQL 16+ | ACID compliance, JSON support, reliability |
| Cache | Redis 7+ | Session storage, rate limiting, pub/sub for back-channel |
| PQ Crypto | liboqs-go, CIRCL | NIST-approved PQ algorithms |

### Service Breakdown

| Service | Responsibility |
|---------|----------------|
| Auth Service | Login, logout, password validation, account lockout |
| User Service | Registration, profile management, password changes |
| Token Service | JWT issuance, refresh tokens, token revocation |
| MFA Service | TOTP, WebAuthn, backup codes management |
| Device Service | Device registration, fingerprinting, trust management, session tracking, back-channel logout |

---

## Security Design

### Authentication Flow

```
┌──────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────┐
│  Client  │     │   HostedID   │     │  MFA Service │     │   App    │
└────┬─────┘     └──────┬───────┘     └──────┬───────┘     └────┬─────┘
     │                  │                    │                  │
     │  1. Login Request│                    │                  │
     │─────────────────►│                    │                  │
     │                  │                    │                  │
     │                  │ 2. Validate Creds  │                  │
     │                  │───────────────────►│                  │
     │                  │                    │                  │
     │  3. MFA Challenge│                    │                  │
     │◄─────────────────│                    │                  │
     │                  │                    │                  │
     │  4. MFA Response │                    │                  │
     │─────────────────►│                    │                  │
     │                  │ 5. Verify MFA      │                  │
     │                  │───────────────────►│                  │
     │                  │                    │                  │
     │                  │ 6. MFA Valid       │                  │
     │                  │◄───────────────────│                  │
     │                  │                    │                  │
     │  7. Tokens       │                    │                  │
     │◄─────────────────│                    │                  │
     │                  │                    │                  │
     │                  │                    │  8. API Request  │
     │                  │                    │        + Token   │
     │─────────────────────────────────────────────────────────►│
     │                  │                    │                  │
```

### Token Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Token Types                               │
├─────────────────┬───────────────────┬───────────────────────────┤
│   Access Token  │   Refresh Token   │      ID Token             │
├─────────────────┼───────────────────┼───────────────────────────┤
│ Short-lived     │ Long-lived        │ User identity claims      │
│ (15 minutes)    │ (7-30 days)       │ (matches access token)    │
│ Stateless JWT   │ Stateful (DB)     │ Stateless JWT             │
│ PQ-signed       │ Opaque + PQ-MAC   │ PQ-signed                 │
└─────────────────┴───────────────────┴───────────────────────────┘
```

### Password Security

- **Hashing**: Argon2id with tuned parameters
  - Memory: 64 MB
  - Iterations: 3
  - Parallelism: 4
  - Salt: 16 bytes (crypto/rand)
- **Requirements**:
  - Minimum 12 characters
  - Checked against HaveIBeenPwned API (k-anonymity)
  - No character class requirements (NIST 800-63B compliant)
  - Entropy estimation using zxcvbn

### Rate Limiting Strategy

| Endpoint | Window | Limit | Scope |
|----------|--------|-------|-------|
| Login | 15 min | 5 attempts | IP + Username |
| Registration | 1 hour | 3 attempts | IP |
| Password Reset | 1 hour | 3 attempts | IP + Email |
| Token Refresh | 1 min | 10 requests | User ID |
| API General | 1 min | 100 requests | API Key |

### Account Lockout Policy

```
Lockout Progression:
├── 5 failed attempts  → 5 minute lockout
├── 10 failed attempts → 30 minute lockout
├── 15 failed attempts → 2 hour lockout
└── 20 failed attempts → Account locked (manual unlock required)

Lockout applies to:
- Login attempts
- MFA verification
- Password reset verification
```

---

## Post-Quantum Cryptography

### Algorithm Selection

Based on NIST PQC standardization (finalized 2024):

| Use Case | Algorithm | Standard | Parameters |
|----------|-----------|----------|------------|
| Key Encapsulation | ML-KEM (Kyber) | FIPS 203 | ML-KEM-768 |
| Digital Signatures | ML-DSA (Dilithium) | FIPS 204 | ML-DSA-65 |
| Hash-based Signatures | SLH-DSA (SPHINCS+) | FIPS 205 | SLH-DSA-SHAKE-128f |

### Hybrid Approach

To ensure backward compatibility and defense-in-depth:

```
┌─────────────────────────────────────────────────────────────┐
│                    Hybrid Cryptography                       │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   Token Signing:                                             │
│   signature = Ed25519(data) || ML-DSA-65(data)              │
│                                                              │
│   Key Exchange (future TLS):                                 │
│   shared_secret = HKDF(X25519(sk, pk) || ML-KEM-768(ct))    │
│                                                              │
│   Verification: MUST verify BOTH signatures                  │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Key Management

```
┌─────────────────────────────────────────────────────────────┐
│                    Key Hierarchy                             │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   Root Key (HSM/Vault)                                       │
│   └── Signing Key (ML-DSA-65 + Ed25519)                     │
│       ├── Access Token Signing                               │
│       ├── ID Token Signing                                   │
│       └── Refresh Token MAC                                  │
│   └── Encryption Key (ML-KEM-768 + X25519)                  │
│       ├── Database Encryption                                │
│       └── Backup Encryption                                  │
│                                                              │
│   Key Rotation: Every 90 days (automatic)                    │
│   Key Validity: Signing keys valid for verification 1 year   │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Implementation Notes

```go
// Example: Hybrid signature generation
type HybridSigner struct {
    classicalKey ed25519.PrivateKey
    pqKey        mldsa.PrivateKey
}

func (s *HybridSigner) Sign(message []byte) ([]byte, error) {
    classicalSig := ed25519.Sign(s.classicalKey, message)
    pqSig, err := s.pqKey.Sign(message)
    if err != nil {
        return nil, err
    }
    return append(classicalSig, pqSig...), nil
}
```

---

## Feature Specifications

### 1. User Registration

**Endpoint**: `POST /api/v1/auth/register`

**Flow**:
1. User submits email, password, and optional profile data
2. Server validates input and checks email uniqueness
3. Password is checked against breach database
4. User record created with `status: pending_verification`
5. Verification email sent with time-limited token
6. User clicks link to verify email
7. Account activated

**Request**:
```json
{
  "email": "user@example.com",
  "password": "secure_password_here",
  "profile": {
    "display_name": "John Doe",
    "locale": "en-US",
    "timezone": "America/New_York"
  }
}
```

**Response**:
```json
{
  "user_id": "usr_01H7X5K2V3N8M6P4Q9R2S1T8W",
  "email": "user@example.com",
  "status": "pending_verification",
  "verification_sent_at": "2026-02-01T10:30:00Z"
}
```

### 2. Login

**Endpoint**: `POST /api/v1/auth/login`

**Flow**:
1. User submits credentials
2. Rate limit check (IP + username)
3. Account lockout check
4. Credential validation
5. Device fingerprint check
6. MFA challenge (if enabled)
7. Session creation
8. Token issuance

**Request**:
```json
{
  "email": "user@example.com",
  "password": "secure_password_here",
  "device_fingerprint": "fp_abc123...",
  "remember_device": true
}
```

**Response** (MFA required):
```json
{
  "status": "mfa_required",
  "mfa_token": "mfa_temp_token_here",
  "available_methods": ["totp", "webauthn", "backup_code"],
  "preferred_method": "totp"
}
```

**Response** (Success):
```json
{
  "access_token": "eyJhbGciOiJIUzI1...",
  "refresh_token": "rt_01H7X5K2V3N8M6P4...",
  "id_token": "eyJhbGciOiJIUzI1...",
  "token_type": "Bearer",
  "expires_in": 900,
  "device_id": "dev_01H7X5K2V3N8M6P4Q9R2S1T8W"
}
```

### 3. Password Reset

**Endpoint**: `POST /api/v1/auth/password/reset-request`

**Flow**:
1. User requests password reset with email
2. Rate limit check
3. If email exists, generate secure token (32 bytes)
4. Store token hash with expiration (1 hour)
5. Send reset email (always return success to prevent enumeration)
6. User clicks link with token
7. User submits new password with token
8. Validate token and update password
9. Invalidate all existing sessions
10. Send notification email

**Request** (Initiate):
```json
{
  "email": "user@example.com"
}
```

**Request** (Complete):
```json
{
  "token": "reset_token_from_email",
  "new_password": "new_secure_password"
}
```

### 4. Change Password

**Endpoint**: `POST /api/v1/auth/password/change`

**Requirements**: Authenticated session

**Flow**:
1. Validate current password
2. Validate new password requirements
3. Check new password not same as current
4. Update password hash
5. Optionally invalidate other sessions
6. Send notification email

**Request**:
```json
{
  "current_password": "old_password",
  "new_password": "new_secure_password",
  "invalidate_other_sessions": true
}
```

### 5. Refresh Token

**Endpoint**: `POST /api/v1/auth/token/refresh`

**Flow**:
1. Validate refresh token
2. Check token not revoked
3. Check session still valid
4. Issue new access token
5. Optionally rotate refresh token (sliding window)

**Request**:
```json
{
  "refresh_token": "rt_01H7X5K2V3N8M6P4..."
}
```

**Response**:
```json
{
  "access_token": "eyJhbGciOiJIUzI1...",
  "refresh_token": "rt_02J8Y6L3W4O9N7Q5...",
  "expires_in": 900
}
```

### 6. Device Management

**Endpoints**:
- `GET /api/v1/devices` - List all devices (with session info)
- `GET /api/v1/devices/{id}` - Get device details
- `GET /api/v1/devices/current` - Get current device
- `POST /api/v1/devices/trust` - Trust a device
- `PATCH /api/v1/devices/{id}` - Update device (e.g., rename)
- `DELETE /api/v1/devices/{id}` - Remove device and revoke its session
- `POST /api/v1/devices/{id}/logout` - Logout device (end session, keep device record)

**Device Fingerprint Components**:
```json
{
  "user_agent": "Mozilla/5.0...",
  "screen_resolution": "1920x1080",
  "timezone": "America/New_York",
  "language": "en-US",
  "platform": "MacIntel",
  "webgl_renderer": "Apple M1",
  "canvas_hash": "abc123..."
}
```

**Device Record** (unified with session):
```json
{
  "device_id": "dev_01H7X5K2V3N8M6P4Q9R2S1T8W",
  "name": "Chrome on MacBook Pro",
  "fingerprint_hash": "sha256:abc123...",
  "first_seen": "2026-01-15T10:30:00Z",
  "last_activity": "2026-02-01T14:22:00Z",
  "current_ip": "192.168.1.100",
  "current_location": "San Francisco, CA",
  "is_trusted": true,
  "trust_expires_at": "2026-05-01T10:30:00Z",
  "session": {
    "is_active": true,
    "started_at": "2026-02-01T09:00:00Z",
    "expires_at": "2026-02-08T09:00:00Z",
    "last_refresh": "2026-02-01T14:22:00Z"
  },
  "is_current_device": true
}
```

### 7. Rate Limiting

**Implementation**: Token bucket algorithm with Redis

**Headers Returned**:
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1706789400
Retry-After: 60 (only when limited)
```

**Rate Limit Response** (429):
```json
{
  "error": "rate_limit_exceeded",
  "message": "Too many requests. Please try again later.",
  "retry_after": 60
}
```

### 8. Personalized MFA

**Supported Methods**:

| Method | Description | Risk Level |
|--------|-------------|------------|
| TOTP | Time-based OTP (Google Authenticator) | Standard |
| WebAuthn | Hardware keys, biometrics | High Security |
| Backup Codes | One-time recovery codes | Emergency |
| Email OTP | Code sent to verified email | Low Security |
| SMS OTP | Code sent to phone (if enabled) | Low Security |

**MFA Configuration per User**:
```json
{
  "mfa_enabled": true,
  "preferred_method": "webauthn",
  "enrolled_methods": [
    {
      "method": "totp",
      "enrolled_at": "2026-01-10T10:00:00Z",
      "last_used": "2026-02-01T09:15:00Z"
    },
    {
      "method": "webauthn",
      "enrolled_at": "2026-01-15T14:00:00Z",
      "last_used": "2026-02-01T14:22:00Z",
      "credentials": [
        {
          "id": "cred_abc123",
          "name": "YubiKey 5",
          "created_at": "2026-01-15T14:00:00Z"
        }
      ]
    }
  ],
  "backup_codes_remaining": 8,
  "adaptive_mfa": {
    "skip_for_trusted_devices": true,
    "require_for_sensitive_actions": true,
    "risk_threshold": "medium"
  }
}
```

**Adaptive MFA Logic**:
```
Risk Score Calculation:
├── New device: +30 points
├── New IP: +20 points
├── New location: +25 points
├── Unusual time: +15 points
├── Failed attempts (last hour): +10 points each
└── Trusted device: -40 points

Thresholds:
├── < 20: No MFA (trusted context)
├── 20-50: MFA optional (user preference)
└── > 50: MFA required
```

### 9. Account Lockout

**Endpoint**: `POST /api/v1/auth/unlock` (Admin or self-service)

**Lockout Record**:
```json
{
  "user_id": "usr_01H7X5K2V3N8M6P4Q9R2S1T8W",
  "locked_at": "2026-02-01T10:30:00Z",
  "unlock_at": "2026-02-01T10:35:00Z",
  "reason": "excessive_failed_attempts",
  "failed_attempts": 5,
  "last_attempt_ip": "192.168.1.100",
  "requires_manual_unlock": false
}
```

**Self-Service Unlock** (if enabled):
1. User requests unlock via verified email
2. Security questions (if configured)
3. MFA verification (if available)
4. CAPTCHA challenge
5. Account unlocked with forced password reset

### 10. Back-Channel Sign Out

**Endpoint**: `POST /api/v1/auth/logout/backchannel`

**OpenID Connect Back-Channel Logout Implementation**:

```
┌──────────┐     ┌──────────────┐     ┌──────────────┐
│ HostedID │     │    Redis     │     │   App (RP)   │
└────┬─────┘     └──────┬───────┘     └──────┬───────┘
     │                  │                    │
     │  1. User Logout  │                    │
     │─────────────────►│                    │
     │                  │                    │
     │  2. Publish Event│                    │
     │─────────────────►│                    │
     │                  │                    │
     │                  │  3. Subscribe      │
     │                  │◄───────────────────│
     │                  │                    │
     │                  │  4. Logout Event   │
     │                  │───────────────────►│
     │                  │                    │
     │                  │                    │  5. Invalidate
     │                  │                    │     Local Session
     │                  │                    │
```

**Logout Token** (JWT):
```json
{
  "iss": "https://auth.example.com",
  "sub": "usr_01H7X5K2V3N8M6P4Q9R2S1T8W",
  "aud": "client_app_id",
  "iat": 1706789400,
  "jti": "logout_token_unique_id",
  "events": {
    "http://schemas.openid.net/event/backchannel-logout": {}
  },
  "device_id": "dev_01H7X5K2V3N8M6P4Q9R2S1T8W"
}
```

### 11. Update Profile

**Endpoint**: `PATCH /api/v1/users/me/profile`

**Updatable Fields**:
```json
{
  "display_name": "John Doe",
  "avatar_url": "https://...",
  "locale": "en-US",
  "timezone": "America/New_York",
  "metadata": {
    "theme": "dark",
    "notifications_enabled": true
  }
}
```

**Sensitive Field Updates** (require re-authentication):
- Email change (verification required)
- Phone number change (verification required)

---

## API Design

### RESTful Endpoints

```
Authentication:
  POST   /api/v1/auth/register
  POST   /api/v1/auth/login
  POST   /api/v1/auth/logout
  POST   /api/v1/auth/logout/all
  POST   /api/v1/auth/logout/backchannel
  POST   /api/v1/auth/token/refresh
  POST   /api/v1/auth/token/revoke

Password:
  POST   /api/v1/auth/password/reset-request
  POST   /api/v1/auth/password/reset-complete
  POST   /api/v1/auth/password/change

MFA:
  GET    /api/v1/mfa/methods
  POST   /api/v1/mfa/totp/setup
  POST   /api/v1/mfa/totp/verify
  POST   /api/v1/mfa/webauthn/register/begin
  POST   /api/v1/mfa/webauthn/register/complete
  POST   /api/v1/mfa/webauthn/authenticate/begin
  POST   /api/v1/mfa/webauthn/authenticate/complete
  POST   /api/v1/mfa/backup-codes/generate
  DELETE /api/v1/mfa/{method}

User:
  GET    /api/v1/users/me
  PATCH  /api/v1/users/me/profile
  POST   /api/v1/users/me/email/change
  POST   /api/v1/users/me/email/verify

Devices:
  GET    /api/v1/devices
  GET    /api/v1/devices/{id}
  GET    /api/v1/devices/current
  POST   /api/v1/devices/trust
  PATCH  /api/v1/devices/{id}
  DELETE /api/v1/devices/{id}
  POST   /api/v1/devices/{id}/logout

Admin:
  GET    /api/v1/admin/users
  GET    /api/v1/admin/users/{id}
  POST   /api/v1/admin/users/{id}/lock
  POST   /api/v1/admin/users/{id}/unlock
  POST   /api/v1/admin/users/{id}/reset-mfa
```

### Error Response Format

```json
{
  "error": {
    "code": "invalid_credentials",
    "message": "The email or password is incorrect.",
    "details": {
      "remaining_attempts": 3,
      "lockout_duration": 300
    },
    "request_id": "req_01H7X5K2V3N8M6P4Q9R2S1T8W"
  }
}
```

### Common Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `invalid_credentials` | 401 | Wrong email/password |
| `account_locked` | 403 | Account temporarily locked |
| `mfa_required` | 403 | MFA verification needed |
| `token_expired` | 401 | Access token expired |
| `token_revoked` | 401 | Token has been revoked |
| `rate_limited` | 429 | Too many requests |
| `validation_error` | 400 | Input validation failed |
| `not_found` | 404 | Resource not found |
| `forbidden` | 403 | Insufficient permissions |

---

## Database Schema

### PostgreSQL Tables

```sql
-- Users table
CREATE TABLE users (
    id              VARCHAR(32) PRIMARY KEY,
    email           VARCHAR(255) UNIQUE NOT NULL,
    email_verified  BOOLEAN DEFAULT FALSE,
    password_hash   VARCHAR(255) NOT NULL,
    status          VARCHAR(20) DEFAULT 'pending_verification',
    failed_attempts INTEGER DEFAULT 0,
    locked_until    TIMESTAMP WITH TIME ZONE,
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    deleted_at      TIMESTAMP WITH TIME ZONE
);

-- User profiles
CREATE TABLE user_profiles (
    user_id         VARCHAR(32) PRIMARY KEY REFERENCES users(id),
    display_name    VARCHAR(100),
    avatar_url      VARCHAR(500),
    locale          VARCHAR(10) DEFAULT 'en-US',
    timezone        VARCHAR(50) DEFAULT 'UTC',
    metadata        JSONB DEFAULT '{}',
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Devices (unified with sessions)
CREATE TABLE devices (
    id                  VARCHAR(32) PRIMARY KEY,
    user_id             VARCHAR(32) REFERENCES users(id),
    fingerprint_hash    VARCHAR(64) NOT NULL,
    name                VARCHAR(100),
    user_agent          TEXT,
    
    -- Trust settings
    is_trusted          BOOLEAN DEFAULT FALSE,
    trust_expires_at    TIMESTAMP WITH TIME ZONE,
    
    -- Location tracking
    current_ip          INET,
    current_location    VARCHAR(100),
    
    -- Session state (embedded)
    session_active      BOOLEAN DEFAULT FALSE,
    session_started_at  TIMESTAMP WITH TIME ZONE,
    session_expires_at  TIMESTAMP WITH TIME ZONE,
    last_activity       TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Timestamps
    first_seen          TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_at          TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at          TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Refresh tokens
CREATE TABLE refresh_tokens (
    id              VARCHAR(32) PRIMARY KEY,
    user_id         VARCHAR(32) REFERENCES users(id),
    token_hash      VARCHAR(64) NOT NULL,
    device_id       VARCHAR(32) REFERENCES devices(id),
    expires_at      TIMESTAMP WITH TIME ZONE NOT NULL,
    revoked_at      TIMESTAMP WITH TIME ZONE,
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- MFA methods
CREATE TABLE mfa_methods (
    id              VARCHAR(32) PRIMARY KEY,
    user_id         VARCHAR(32) REFERENCES users(id),
    method          VARCHAR(20) NOT NULL,
    secret          BYTEA,
    credential_data JSONB,
    is_primary      BOOLEAN DEFAULT FALSE,
    last_used       TIMESTAMP WITH TIME ZONE,
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Backup codes
CREATE TABLE backup_codes (
    id              VARCHAR(32) PRIMARY KEY,
    user_id         VARCHAR(32) REFERENCES users(id),
    code_hash       VARCHAR(64) NOT NULL,
    used_at         TIMESTAMP WITH TIME ZONE,
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Password reset tokens
CREATE TABLE password_reset_tokens (
    id              VARCHAR(32) PRIMARY KEY,
    user_id         VARCHAR(32) REFERENCES users(id),
    token_hash      VARCHAR(64) NOT NULL,
    expires_at      TIMESTAMP WITH TIME ZONE NOT NULL,
    used_at         TIMESTAMP WITH TIME ZONE,
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Audit log
CREATE TABLE audit_logs (
    id              VARCHAR(32) PRIMARY KEY,
    user_id         VARCHAR(32) REFERENCES users(id),
    action          VARCHAR(50) NOT NULL,
    resource_type   VARCHAR(50),
    resource_id     VARCHAR(32),
    ip_address      INET,
    user_agent      TEXT,
    metadata        JSONB DEFAULT '{}',
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Signing keys
CREATE TABLE signing_keys (
    id              VARCHAR(32) PRIMARY KEY,
    algorithm       VARCHAR(20) NOT NULL,
    public_key      BYTEA NOT NULL,
    private_key_enc BYTEA NOT NULL,
    is_active       BOOLEAN DEFAULT TRUE,
    expires_at      TIMESTAMP WITH TIME ZONE,
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    rotated_at      TIMESTAMP WITH TIME ZONE
);

-- Indexes
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_devices_user_id ON devices(user_id);
CREATE INDEX idx_devices_session_active ON devices(user_id, session_active) WHERE session_active = TRUE;
CREATE INDEX idx_devices_session_expires ON devices(session_expires_at) WHERE session_active = TRUE;
CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_device_id ON refresh_tokens(device_id);
CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at);
```

---

## Frontend Architecture

### React Application Structure

```
frontend/
├── public/
│   ├── index.html
│   └── favicon.ico
├── src/
│   ├── components/
│   │   ├── auth/
│   │   │   ├── LoginForm.tsx
│   │   │   ├── RegisterForm.tsx
│   │   │   ├── PasswordResetForm.tsx
│   │   │   ├── MFAChallenge.tsx
│   │   │   └── DeviceVerification.tsx
│   │   ├── mfa/
│   │   │   ├── TOTPSetup.tsx
│   │   │   ├── WebAuthnSetup.tsx
│   │   │   ├── BackupCodes.tsx
│   │   │   └── MFAMethodSelector.tsx
│   │   ├── profile/
│   │   │   ├── ProfileForm.tsx
│   │   │   ├── PasswordChange.tsx
│   │   │   └── EmailChange.tsx
│   │   ├── devices/
│   │   │   ├── DeviceList.tsx
│   │   │   ├── DeviceCard.tsx
│   │   │   └── DeviceSessionInfo.tsx
│   │   └── common/
│   │       ├── Button.tsx
│   │       ├── Input.tsx
│   │       ├── Alert.tsx
│   │       └── Loading.tsx
│   ├── hooks/
│   │   ├── useAuth.ts
│   │   ├── useDevices.ts
│   │   └── useMFA.ts
│   ├── services/
│   │   ├── api.ts
│   │   ├── authService.ts
│   │   ├── tokenService.ts
│   │   └── deviceFingerprint.ts
│   ├── contexts/
│   │   └── AuthContext.tsx
│   ├── pages/
│   │   ├── Login.tsx
│   │   ├── Register.tsx
│   │   ├── Dashboard.tsx
│   │   ├── Profile.tsx
│   │   ├── Security.tsx
│   │   └── Devices.tsx
│   ├── utils/
│   │   ├── crypto.ts
│   │   ├── validation.ts
│   │   └── constants.ts
│   ├── types/
│   │   └── index.ts
│   ├── App.tsx
│   └── index.tsx
├── package.json
├── tsconfig.json
├── vite.config.ts
└── tailwind.config.js
```

### Key Frontend Technologies

| Technology | Purpose |
|------------|---------|
| React 18+ | UI framework |
| TypeScript | Type safety |
| Vite | Build tool |
| TailwindCSS | Styling |
| React Query | Server state management |
| React Router | Routing |
| Zod | Schema validation |
| @simplewebauthn/browser | WebAuthn support |

---

## Implementation Steps

### Phase 1: Foundation (Weeks 1-2)

#### Week 1: Project Setup & Core Infrastructure

- [ ] **1.1 Initialize Go Backend**
  - Set up Go module structure
  - Configure project layout (cmd, internal, pkg)
  - Set up configuration management (Viper)
  - Implement structured logging (zerolog)
  - Create Docker Compose for local development

- [ ] **1.2 Database Setup**
  - Set up PostgreSQL with migrations (golang-migrate)
  - Create initial schema migrations
  - Implement database connection pooling
  - Set up Redis for caching/sessions

- [ ] **1.3 Initialize React Frontend**
  - Create Vite + React + TypeScript project
  - Configure TailwindCSS
  - Set up routing structure
  - Create base component library
  - Configure API client (axios)

#### Week 2: Core Authentication

- [ ] **2.1 User Model & Repository**
  - Implement User entity and repository pattern
  - Add password hashing (Argon2id)
  - Create user service layer

- [ ] **2.2 Registration Flow**
  - Implement registration endpoint
  - Email validation and uniqueness check
  - Password strength validation
  - Email verification token generation
  - Registration frontend form

- [ ] **2.3 Login Flow (Basic)**
  - Implement credential validation
  - Create session management
  - Basic JWT token generation (Ed25519)
  - Login frontend form

### Phase 2: Security Features (Weeks 3-4)

#### Week 3: Token System & Password Management

- [ ] **3.1 Token Service**
  - Implement access token generation
  - Implement refresh token generation
  - Token validation middleware
  - Token refresh endpoint

- [ ] **3.2 Password Reset**
  - Password reset request endpoint
  - Secure token generation and storage
  - Reset completion endpoint
  - Frontend password reset flow

- [ ] **3.3 Change Password**
  - Change password endpoint
  - Current password validation
  - Session invalidation option
  - Frontend password change form

#### Week 4: Rate Limiting & Account Lockout

- [ ] **4.1 Rate Limiting**
  - Implement token bucket in Redis
  - Create rate limiting middleware
  - Configure per-endpoint limits
  - Add rate limit headers

- [ ] **4.2 Account Lockout**
  - Track failed login attempts
  - Implement progressive lockout
  - Create unlock mechanisms
  - Admin unlock endpoint

### Phase 3: Advanced Security (Weeks 5-6)

#### Week 5: Post-Quantum Cryptography

- [ ] **5.1 PQ Crypto Integration**
  - Integrate liboqs-go or CIRCL library
  - Implement ML-DSA-65 signing
  - Create hybrid signature scheme
  - Key generation and storage

- [ ] **5.2 Key Management**
  - Implement key hierarchy
  - Key rotation mechanism
  - Secure key storage (consider HashiCorp Vault)
  - Key versioning for tokens

#### Week 6: MFA Implementation

- [ ] **6.1 TOTP Setup**
  - TOTP secret generation
  - QR code generation
  - TOTP verification
  - Frontend TOTP setup flow

- [ ] **6.2 WebAuthn/Passkeys**
  - WebAuthn registration ceremony
  - WebAuthn authentication ceremony
  - Credential management
  - Frontend WebAuthn integration

- [ ] **6.3 Backup Codes**
  - Backup code generation
  - Secure storage (hashed)
  - Backup code verification
  - Regeneration flow

### Phase 4: Device Management (Weeks 7-8)

#### Week 7: Device Core

- [ ] **7.1 Device Fingerprinting**
  - Frontend fingerprint collection
  - Backend fingerprint validation
  - Device recognition logic

- [ ] **7.2 Device Trust & Registration**
  - Device registration flow
  - Trust/untrust mechanisms
  - Device listing and management
  - Frontend device management UI

#### Week 8: Device Sessions & Logout

- [ ] **8.1 Device Session Tracking**
  - Active session tracking within devices
  - Session metadata (IP, location, timestamps)
  - Per-device session revocation
  - Frontend device/session management

- [ ] **8.2 Back-Channel Logout**
  - Implement OIDC back-channel logout
  - Redis pub/sub for logout events
  - Logout token generation (references device_id)
  - Client integration guide

### Phase 5: User Management & Polish (Weeks 9-10)

#### Week 9: Profile Management

- [ ] **9.1 Profile Updates**
  - Profile update endpoint
  - Avatar upload (optional)
  - Email change with verification
  - Frontend profile editing

- [ ] **9.2 Adaptive MFA**
  - Risk scoring implementation
  - MFA decision engine
  - User preference management
  - Trusted device integration

#### Week 10: Testing & Documentation

- [ ] **10.1 Testing**
  - Unit tests for all services
  - Integration tests for API
  - E2E tests with Playwright
  - Security testing (OWASP)

- [ ] **10.2 Documentation**
  - API documentation (OpenAPI)
  - Integration guide
  - Deployment guide
  - Security best practices

### Phase 6: Production Readiness (Weeks 11-12)

#### Week 11: Observability & Monitoring

- [ ] **11.1 Logging & Metrics**
  - Structured logging implementation
  - Prometheus metrics
  - Health check endpoints
  - Audit logging

- [ ] **11.2 Error Handling**
  - Global error handling
  - Error tracking integration
  - User-friendly error messages

#### Week 12: Deployment & Hardening

- [ ] **12.1 Deployment**
  - Production Docker images
  - Kubernetes manifests (optional)
  - CI/CD pipeline
  - Database migrations strategy

- [ ] **12.2 Security Hardening**
  - Security headers
  - CORS configuration
  - TLS/SSL setup
  - Penetration testing

---

## Deployment Considerations

### Environment Configuration

```yaml
# config.yaml
server:
  host: "0.0.0.0"
  port: 8080
  tls:
    enabled: true
    cert_file: "/etc/ssl/certs/server.crt"
    key_file: "/etc/ssl/private/server.key"

database:
  host: "postgres"
  port: 5432
  name: "hostedid"
  user: "${DB_USER}"
  password: "${DB_PASSWORD}"
  ssl_mode: "require"
  max_connections: 100

redis:
  host: "redis"
  port: 6379
  password: "${REDIS_PASSWORD}"
  db: 0

security:
  password:
    min_length: 12
    argon2_memory: 65536
    argon2_iterations: 3
    argon2_parallelism: 4
  tokens:
    access_token_ttl: "15m"
    refresh_token_ttl: "168h"
    signing_algorithm: "hybrid"
  rate_limiting:
    enabled: true
    default_limit: 100
    default_window: "1m"

mfa:
  totp:
    issuer: "HostedID"
    digits: 6
    period: 30
  webauthn:
    rp_id: "example.com"
    rp_origins: ["https://auth.example.com"]
```

### Docker Compose (Development)

```yaml
version: '3.8'
services:
  api:
    build:
      context: .
      dockerfile: Dockerfile
    ports:
      - "8080:8080"
    environment:
      - DB_HOST=postgres
      - REDIS_HOST=redis
    depends_on:
      - postgres
      - redis

  frontend:
    build:
      context: ./frontend
      dockerfile: Dockerfile
    ports:
      - "3000:3000"

  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: hostedid
      POSTGRES_USER: hostedid
      POSTGRES_PASSWORD: localdev
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"

volumes:
  postgres_data:
```

### Production Checklist

- [ ] TLS/SSL certificates configured
- [ ] Database encryption at rest enabled
- [ ] Redis authentication enabled
- [ ] Environment variables secured (Vault/Secrets Manager)
- [ ] Rate limiting configured
- [ ] CORS properly restricted
- [ ] Security headers enabled
- [ ] Audit logging enabled
- [ ] Backup strategy implemented
- [ ] Monitoring and alerting configured
- [ ] Incident response plan documented

---

## Appendix

### Security References

- NIST SP 800-63B: Digital Identity Guidelines
- OWASP Authentication Cheat Sheet
- FIPS 203, 204, 205: Post-Quantum Cryptography Standards
- RFC 6749: OAuth 2.0
- RFC 7519: JSON Web Token (JWT)
- OpenID Connect Core 1.0

### Useful Libraries

**Go:**
- `github.com/golang-jwt/jwt/v5` - JWT handling
- `github.com/cloudflare/circl` - Post-quantum crypto
- `github.com/go-webauthn/webauthn` - WebAuthn support
- `github.com/pquerna/otp` - TOTP/HOTP
- `github.com/alexedwards/argon2id` - Argon2id hashing
- `github.com/redis/go-redis/v9` - Redis client

**React:**
- `@simplewebauthn/browser` - WebAuthn client
- `otplib` - TOTP generation
- `@fingerprintjs/fingerprintjs` - Device fingerprinting
- `zod` - Schema validation
- `@tanstack/react-query` - Data fetching

---

*This specification is a living document and will be updated as the project evolves.*
