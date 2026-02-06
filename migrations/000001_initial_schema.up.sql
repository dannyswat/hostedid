-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

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
    user_id         VARCHAR(32) PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
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
    user_id             VARCHAR(32) REFERENCES users(id) ON DELETE CASCADE,
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
    user_id         VARCHAR(32) REFERENCES users(id) ON DELETE CASCADE,
    token_hash      VARCHAR(64) NOT NULL,
    device_id       VARCHAR(32) REFERENCES devices(id) ON DELETE CASCADE,
    expires_at      TIMESTAMP WITH TIME ZONE NOT NULL,
    revoked_at      TIMESTAMP WITH TIME ZONE,
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- MFA methods
CREATE TABLE mfa_methods (
    id              VARCHAR(32) PRIMARY KEY,
    user_id         VARCHAR(32) REFERENCES users(id) ON DELETE CASCADE,
    method          VARCHAR(20) NOT NULL,
    secret          BYTEA,
    credential_data JSONB,
    is_primary      BOOLEAN DEFAULT FALSE,
    last_used       TIMESTAMP WITH TIME ZONE,
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    UNIQUE(user_id, method)
);

-- Backup codes
CREATE TABLE backup_codes (
    id              VARCHAR(32) PRIMARY KEY,
    user_id         VARCHAR(32) REFERENCES users(id) ON DELETE CASCADE,
    code_hash       VARCHAR(64) NOT NULL,
    used_at         TIMESTAMP WITH TIME ZONE,
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Password reset tokens
CREATE TABLE password_reset_tokens (
    id              VARCHAR(32) PRIMARY KEY,
    user_id         VARCHAR(32) REFERENCES users(id) ON DELETE CASCADE,
    token_hash      VARCHAR(64) NOT NULL,
    expires_at      TIMESTAMP WITH TIME ZONE NOT NULL,
    used_at         TIMESTAMP WITH TIME ZONE,
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Email verification tokens
CREATE TABLE email_verification_tokens (
    id              VARCHAR(32) PRIMARY KEY,
    user_id         VARCHAR(32) REFERENCES users(id) ON DELETE CASCADE,
    token_hash      VARCHAR(64) NOT NULL,
    email           VARCHAR(255) NOT NULL,
    expires_at      TIMESTAMP WITH TIME ZONE NOT NULL,
    used_at         TIMESTAMP WITH TIME ZONE,
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Audit log
CREATE TABLE audit_logs (
    id              VARCHAR(32) PRIMARY KEY,
    user_id         VARCHAR(32) REFERENCES users(id) ON DELETE SET NULL,
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
CREATE INDEX idx_users_status ON users(status);
CREATE INDEX idx_users_deleted_at ON users(deleted_at) WHERE deleted_at IS NULL;

CREATE INDEX idx_devices_user_id ON devices(user_id);
CREATE INDEX idx_devices_fingerprint ON devices(user_id, fingerprint_hash);
CREATE INDEX idx_devices_session_active ON devices(user_id, session_active) WHERE session_active = TRUE;
CREATE INDEX idx_devices_session_expires ON devices(session_expires_at) WHERE session_active = TRUE;

CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_device_id ON refresh_tokens(device_id);
CREATE INDEX idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);

CREATE INDEX idx_mfa_methods_user_id ON mfa_methods(user_id);

CREATE INDEX idx_backup_codes_user_id ON backup_codes(user_id);

CREATE INDEX idx_password_reset_tokens_user_id ON password_reset_tokens(user_id);
CREATE INDEX idx_password_reset_tokens_expires_at ON password_reset_tokens(expires_at);

CREATE INDEX idx_email_verification_tokens_user_id ON email_verification_tokens(user_id);

CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);

CREATE INDEX idx_signing_keys_active ON signing_keys(is_active) WHERE is_active = TRUE;

-- Updated at trigger function
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Apply updated_at triggers
CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_user_profiles_updated_at
    BEFORE UPDATE ON user_profiles
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_devices_updated_at
    BEFORE UPDATE ON devices
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
