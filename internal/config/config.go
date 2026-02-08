package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config holds all configuration for the application
type Config struct {
	Server            ServerConfig            `mapstructure:"server"`
	Database          DatabaseConfig          `mapstructure:"database"`
	Redis             RedisConfig             `mapstructure:"redis"`
	Log               LogConfig               `mapstructure:"log"`
	Security          SecurityConfig          `mapstructure:"security"`
	MFA               MFAConfig               `mapstructure:"mfa"`
	Cookie            CookieConfig            `mapstructure:"cookie"`
	Email             EmailConfig             `mapstructure:"email"`
	EmailVerification EmailVerificationConfig `mapstructure:"email_verification"`
}

// ServerConfig holds HTTP server configuration
type ServerConfig struct {
	Host string `mapstructure:"host"`
	Port int    `mapstructure:"port"`
	TLS  struct {
		Enabled  bool   `mapstructure:"enabled"`
		CertFile string `mapstructure:"cert_file"`
		KeyFile  string `mapstructure:"key_file"`
	} `mapstructure:"tls"`
}

// DatabaseConfig holds PostgreSQL configuration
type DatabaseConfig struct {
	Host           string `mapstructure:"host"`
	Port           int    `mapstructure:"port"`
	Name           string `mapstructure:"name"`
	User           string `mapstructure:"user"`
	Password       string `mapstructure:"password"`
	SSLMode        string `mapstructure:"ssl_mode"`
	MaxConnections int    `mapstructure:"max_connections"`
}

// DSN returns the PostgreSQL connection string
func (c DatabaseConfig) DSN() string {
	return fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		c.Host, c.Port, c.User, c.Password, c.Name, c.SSLMode,
	)
}

// RedisConfig holds Redis configuration
type RedisConfig struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Password string `mapstructure:"password"`
	DB       int    `mapstructure:"db"`
}

// Addr returns the Redis address
func (c RedisConfig) Addr() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

// LogConfig holds logging configuration
type LogConfig struct {
	Level  string `mapstructure:"level"`
	Format string `mapstructure:"format"`
}

// SecurityConfig holds security-related configuration
type SecurityConfig struct {
	Password     PasswordConfig     `mapstructure:"password"`
	Tokens       TokenConfig        `mapstructure:"tokens"`
	RateLimiting RateLimitingConfig `mapstructure:"rate_limiting"`
}

// PasswordConfig holds password hashing configuration
type PasswordConfig struct {
	MinLength         int    `mapstructure:"min_length"`
	Argon2Memory      uint32 `mapstructure:"argon2_memory"`
	Argon2Iterations  uint32 `mapstructure:"argon2_iterations"`
	Argon2Parallelism uint8  `mapstructure:"argon2_parallelism"`
}

// TokenConfig holds JWT token configuration
type TokenConfig struct {
	AccessTokenTTL   time.Duration `mapstructure:"access_token_ttl"`
	RefreshTokenTTL  time.Duration `mapstructure:"refresh_token_ttl"`
	SigningAlgorithm string        `mapstructure:"signing_algorithm"`
	Issuer           string        `mapstructure:"issuer"`
}

// RateLimitingConfig holds rate limiting configuration
type RateLimitingConfig struct {
	Enabled       bool   `mapstructure:"enabled"`
	DefaultLimit  int    `mapstructure:"default_limit"`
	DefaultWindow string `mapstructure:"default_window"`
}

// MFAConfig holds MFA configuration
type MFAConfig struct {
	TOTP     TOTPConfig     `mapstructure:"totp"`
	WebAuthn WebAuthnConfig `mapstructure:"webauthn"`
}

// TOTPConfig holds TOTP configuration
type TOTPConfig struct {
	Issuer string `mapstructure:"issuer"`
	Digits int    `mapstructure:"digits"`
	Period int    `mapstructure:"period"`
}

// WebAuthnConfig holds WebAuthn configuration
type WebAuthnConfig struct {
	RPID      string   `mapstructure:"rp_id"`
	RPOrigins []string `mapstructure:"rp_origins"`
	RPName    string   `mapstructure:"rp_name"`
}

// CookieConfig holds cookie configuration
type CookieConfig struct {
	// Domain is the base domain for cross-subdomain cookies (e.g. "example.com")
	// Access and ID tokens use this domain (prefixed with ".") for subdomain sharing.
	// Refresh token uses no domain (locked to the issuing host).
	Domain string `mapstructure:"domain"`
	// Secure sets the Secure flag on cookies (should be true in production with HTTPS)
	Secure bool `mapstructure:"secure"`
	// SameSite controls the SameSite attribute: "lax", "strict", or "none"
	SameSite string `mapstructure:"same_site"`
	// AllowedReturnURLs is a list of URL prefixes allowed for return_url redirection
	AllowedReturnURLs []string `mapstructure:"allowed_return_urls"`
}

// EmailConfig holds email sending configuration
type EmailConfig struct {
	// Provider is the email provider to use: "gmail", "smtp", etc.
	Provider string `mapstructure:"provider"`
	// AppName is the application name shown in emails (defaults to "HostedID")
	AppName string `mapstructure:"app_name"`
	// Gmail holds Gmail-specific configuration
	Gmail GmailEmailConfig `mapstructure:"gmail"`
}

// GmailEmailConfig holds Gmail API configuration
type GmailEmailConfig struct {
	// CredentialsJSON is the service account credentials JSON content
	CredentialsJSON string `mapstructure:"credentials_json"`
	// ClientID for OAuth2 token-based auth (alternative to service account)
	ClientID string `mapstructure:"client_id"`
	// ClientSecret for OAuth2 token-based auth
	ClientSecret string `mapstructure:"client_secret"`
	// RefreshToken for OAuth2 token-based auth
	RefreshToken string `mapstructure:"refresh_token"`
	// SenderAddress is the "From" email address
	SenderAddress string `mapstructure:"sender_address"`
	// SenderName is the display name for the sender
	SenderName string `mapstructure:"sender_name"`
}

// EmailVerificationConfig holds email verification settings
type EmailVerificationConfig struct {
	// Enabled controls whether email verification is required on registration
	Enabled bool `mapstructure:"enabled"`
	// OTPLength is the number of digits in the OTP code (default: 6)
	OTPLength int `mapstructure:"otp_length"`
	// OTPTTL is how long the OTP is valid (default: 10m)
	OTPTTL time.Duration `mapstructure:"otp_ttl"`
	// ResendCooldown is the minimum time between resend attempts (default: 60s)
	ResendCooldown time.Duration `mapstructure:"resend_cooldown"`
}

// Load reads configuration from file and environment variables
func Load() (*Config, error) {
	v := viper.New()

	// Set config file name and paths
	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath(".")
	v.AddConfigPath("./config")
	v.AddConfigPath("/etc/hostedid")

	// Set defaults
	setDefaults(v)

	// Read config file (optional)
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
		// Config file not found is OK, we'll use defaults and env vars
	}

	// Bind environment variables
	v.SetEnvPrefix("HOSTEDID")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// Unmarshal config
	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return &cfg, nil
}

func setDefaults(v *viper.Viper) {
	// Server defaults
	v.SetDefault("server.host", "0.0.0.0")
	v.SetDefault("server.port", 8080)
	v.SetDefault("server.tls.enabled", false)

	// Database defaults
	v.SetDefault("database.host", "localhost")
	v.SetDefault("database.port", 5432)
	v.SetDefault("database.name", "hostedid")
	v.SetDefault("database.user", "hostedid")
	v.SetDefault("database.password", "")
	v.SetDefault("database.ssl_mode", "disable")
	v.SetDefault("database.max_connections", 25)

	// Redis defaults
	v.SetDefault("redis.host", "localhost")
	v.SetDefault("redis.port", 6379)
	v.SetDefault("redis.password", "")
	v.SetDefault("redis.db", 0)

	// Log defaults
	v.SetDefault("log.level", "info")
	v.SetDefault("log.format", "json")

	// Security defaults
	v.SetDefault("security.password.min_length", 12)
	v.SetDefault("security.password.argon2_memory", 65536)
	v.SetDefault("security.password.argon2_iterations", 3)
	v.SetDefault("security.password.argon2_parallelism", 4)

	v.SetDefault("security.tokens.access_token_ttl", "15m")
	v.SetDefault("security.tokens.refresh_token_ttl", "168h")
	v.SetDefault("security.tokens.signing_algorithm", "hybrid")
	v.SetDefault("security.tokens.issuer", "hostedid")

	v.SetDefault("security.rate_limiting.enabled", true)
	v.SetDefault("security.rate_limiting.default_limit", 100)
	v.SetDefault("security.rate_limiting.default_window", "1m")

	// MFA defaults
	v.SetDefault("mfa.totp.issuer", "HostedID")
	v.SetDefault("mfa.totp.digits", 6)
	v.SetDefault("mfa.totp.period", 30)

	v.SetDefault("mfa.webauthn.rp_id", "localhost")
	v.SetDefault("mfa.webauthn.rp_origins", []string{"http://localhost:3000"})
	v.SetDefault("mfa.webauthn.rp_name", "HostedID")

	// Cookie defaults
	v.SetDefault("cookie.domain", "")
	v.SetDefault("cookie.secure", false)
	v.SetDefault("cookie.same_site", "lax")
	v.SetDefault("cookie.allowed_return_urls", []string{"http://localhost"})

	// Email defaults
	v.SetDefault("email.provider", "gmail")
	v.SetDefault("email.app_name", "HostedID")
	v.SetDefault("email.gmail.sender_address", "")
	v.SetDefault("email.gmail.sender_name", "HostedID")

	// Email verification defaults
	v.SetDefault("email_verification.enabled", false)
	v.SetDefault("email_verification.otp_length", 6)
	v.SetDefault("email_verification.otp_ttl", "10m")
	v.SetDefault("email_verification.resend_cooldown", "60s")
}
