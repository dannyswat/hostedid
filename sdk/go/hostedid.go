package hostedid

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Config holds the configuration for the HostedID client.
type Config struct {
	// BaseURL is the root URL of the HostedID server.
	// Examples: "https://auth.example.com" or "https://auth.example.com/api/v1"
	// The "/api/v1" suffix is appended automatically if missing.
	BaseURL string

	// CookieName is the name of the access token cookie set by HostedID.
	// Default: "hostedid_access_token"
	CookieName string

	// CacheTTL controls how long validated tokens are cached in memory
	// to reduce calls to the HostedID server. Set to 0 to disable caching.
	// Default: 2 minutes
	CacheTTL time.Duration

	// HTTPClient is an optional custom HTTP client.
	// If nil, a default client with 10s timeout is used.
	HTTPClient *http.Client
}

func (c *Config) defaults() {
	if c.CookieName == "" {
		c.CookieName = "hostedid_access_token"
	}
	if c.CacheTTL == 0 {
		c.CacheTTL = 2 * time.Minute
	}
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	c.BaseURL = strings.TrimSuffix(c.BaseURL, "/")
	if !strings.HasSuffix(c.BaseURL, "/api/v1") {
		c.BaseURL = c.BaseURL + "/api/v1"
	}
}

// Client is the HostedID SDK client. It provides methods for calling
// HostedID APIs and Echo middleware for protecting routes.
type Client struct {
	cfg   Config
	cache *tokenCache
}

// NewClient creates a new HostedID client with the given configuration.
func NewClient(cfg Config) *Client {
	cfg.defaults()
	return &Client{
		cfg:   cfg,
		cache: newTokenCache(),
	}
}

// ValidateToken validates an access token by calling the HostedID server.
// Results are cached according to CacheTTL to reduce network calls.
func (c *Client) ValidateToken(ctx context.Context, token string) (*User, error) {
	if token == "" {
		return nil, ErrNoToken
	}

	// Check cache first
	if c.cfg.CacheTTL > 0 {
		if user, ok := c.cache.get(token); ok {
			return user, nil
		}
	}

	// Call HostedID to validate
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.BaseURL+"/users/me", nil)
	if err != nil {
		return nil, fmt.Errorf("hostedid: failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("hostedid: request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("hostedid: failed to read response: %w", err)
	}

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, ErrTokenInvalid
	}
	if resp.StatusCode == http.StatusForbidden {
		return nil, ErrTokenForbidden
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("hostedid: unexpected status %d: %s", resp.StatusCode, string(body))
	}

	var user User
	if err := json.Unmarshal(body, &user); err != nil {
		return nil, fmt.Errorf("hostedid: failed to parse user: %w", err)
	}

	// Cache the result
	if c.cfg.CacheTTL > 0 {
		c.cache.set(token, &user, c.cfg.CacheTTL)
	}

	return &user, nil
}

// InvalidateToken removes a token from the local cache. Call this after
// logout to ensure stale tokens are not served from cache.
func (c *Client) InvalidateToken(token string) {
	c.cache.delete(token)
}

// Login authenticates a user with email and password.
// Returns an AuthResult containing either a LoginResponse or an MFARequiredResponse.
func (c *Client) Login(ctx context.Context, req LoginRequest) (*AuthResult, error) {
	body, err := c.post(ctx, "/auth/login", req, "")
	if err != nil {
		return nil, err
	}

	var result AuthResult

	// Check if MFA is required
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("hostedid: failed to parse response: %w", err)
	}

	if _, ok := raw["status"]; ok {
		var mfa MFARequiredResponse
		if err := json.Unmarshal(body, &mfa); err == nil && mfa.Status == "mfa_required" {
			result.MFARequired = &mfa
			return &result, nil
		}
	}

	var login LoginResponse
	if err := json.Unmarshal(body, &login); err != nil {
		return nil, fmt.Errorf("hostedid: failed to parse login response: %w", err)
	}
	result.Login = &login
	return &result, nil
}

// Register creates a new user account.
func (c *Client) Register(ctx context.Context, req RegisterRequest) (*RegisterResponse, error) {
	body, err := c.post(ctx, "/auth/register", req, "")
	if err != nil {
		return nil, err
	}

	var resp RegisterResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("hostedid: failed to parse register response: %w", err)
	}
	return &resp, nil
}

// Logout logs out the current session. The token is the access token.
func (c *Client) Logout(ctx context.Context, token string) error {
	_, err := c.post(ctx, "/auth/logout", nil, token)
	if err != nil {
		return err
	}
	c.cache.delete(token)
	return nil
}

// LogoutAll logs out all sessions for the user.
func (c *Client) LogoutAll(ctx context.Context, token string) error {
	_, err := c.post(ctx, "/auth/logout/all", nil, token)
	if err != nil {
		return err
	}
	c.cache.clear()
	return nil
}

// RefreshToken exchanges a refresh token for new tokens.
func (c *Client) RefreshToken(ctx context.Context, refreshToken string) (*RefreshTokenResponse, error) {
	body, err := c.post(ctx, "/auth/token/refresh", map[string]string{
		"refreshToken": refreshToken,
	}, "")
	if err != nil {
		return nil, err
	}

	var resp RefreshTokenResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("hostedid: failed to parse refresh response: %w", err)
	}
	return &resp, nil
}

// VerifyMFA completes MFA verification during login.
func (c *Client) VerifyMFA(ctx context.Context, req MFAVerifyRequest) (*LoginResponse, error) {
	body, err := c.post(ctx, "/mfa/verify", req, "")
	if err != nil {
		return nil, err
	}

	var resp LoginResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("hostedid: failed to parse MFA response: %w", err)
	}
	return &resp, nil
}

// GetUserByToken retrieves user info using a valid access token.
func (c *Client) GetUserByToken(ctx context.Context, token string) (*User, error) {
	return c.ValidateToken(ctx, token)
}

// post sends a POST request to the HostedID API.
func (c *Client) post(ctx context.Context, path string, payload interface{}, token string) ([]byte, error) {
	var bodyReader io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("hostedid: failed to marshal request: %w", err)
		}
		bodyReader = strings.NewReader(string(data))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.BaseURL+path, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("hostedid: failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := c.cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("hostedid: request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("hostedid: failed to read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, parseAPIError(resp.StatusCode, body)
	}

	return body, nil
}

// tokenCache provides in-memory caching for validated tokens.
type tokenCache struct {
	mu      sync.RWMutex
	entries map[string]*cacheEntry
}

type cacheEntry struct {
	user      *User
	expiresAt time.Time
}

func newTokenCache() *tokenCache {
	tc := &tokenCache{
		entries: make(map[string]*cacheEntry),
	}
	go tc.cleanup()
	return tc
}

func (tc *tokenCache) get(token string) (*User, bool) {
	tc.mu.RLock()
	defer tc.mu.RUnlock()
	entry, ok := tc.entries[token]
	if !ok || time.Now().After(entry.expiresAt) {
		return nil, false
	}
	return entry.user, true
}

func (tc *tokenCache) set(token string, user *User, ttl time.Duration) {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	tc.entries[token] = &cacheEntry{
		user:      user,
		expiresAt: time.Now().Add(ttl),
	}
}

func (tc *tokenCache) delete(token string) {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	delete(tc.entries, token)
}

func (tc *tokenCache) clear() {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	tc.entries = make(map[string]*cacheEntry)
}

func (tc *tokenCache) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		tc.mu.Lock()
		now := time.Now()
		for k, v := range tc.entries {
			if now.After(v.expiresAt) {
				delete(tc.entries, k)
			}
		}
		tc.mu.Unlock()
	}
}
