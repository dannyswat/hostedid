package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/hostedid/hostedid/internal/auth/hybrid"
	"github.com/hostedid/hostedid/internal/config"
)

// KeyProvider is the interface the token service uses to obtain signing keys.
// Implemented by service.KeyService.
type KeyProvider interface {
	// GetActiveKeyPair returns the active hybrid key pair and key ID.
	GetActiveKeyPair() (*hybrid.HybridKeyPair, string, error)
	// GetActiveEd25519Key returns the Ed25519 private/public key and key ID.
	GetActiveEd25519Key() (ed25519.PrivateKey, ed25519.PublicKey, string, error)
	// FindVerificationKey returns a verification key by key ID.
	// Returns *hybrid.HybridPublicKey or ed25519.PublicKey.
	FindVerificationKey(keyID string) (interface{}, string, error)
	// GetAlgorithm returns the active signing algorithm ("hybrid" or "ed25519").
	GetAlgorithm() string
}

// TokenService handles JWT token creation and validation.
type TokenService struct {
	cfg         config.TokenConfig
	keyProvider KeyProvider
}

// TokenClaims represents the claims in an access token.
type TokenClaims struct {
	jwt.RegisteredClaims
	Email    string `json:"email,omitempty"`
	DeviceID string `json:"device_id,omitempty"`
	KeyID    string `json:"kid,omitempty"`
}

// TokenPair represents an access token and refresh token pair.
type TokenPair struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	IDToken      string `json:"idToken"`
	TokenType    string `json:"tokenType"`
	ExpiresIn    int    `json:"expiresIn"`
}

// NewTokenService creates a new TokenService.
// If keyProvider is nil, it falls back to an ephemeral Ed25519 key (dev mode).
func NewTokenService(cfg config.TokenConfig, keyProvider KeyProvider) (*TokenService, error) {
	return &TokenService{
		cfg:         cfg,
		keyProvider: keyProvider,
	}, nil
}

// GenerateTokenPair creates a new access token, refresh token, and ID token.
func (s *TokenService) GenerateTokenPair(userID, email, deviceID string) (*TokenPair, string, error) {
	now := time.Now()
	accessExpiry := now.Add(s.cfg.AccessTokenTTL)

	useHybrid := s.keyProvider != nil && s.keyProvider.GetAlgorithm() == "hybrid"

	var accessTokenString, idTokenString string
	var err error

	if useHybrid {
		accessTokenString, err = s.signHybrid(userID, email, deviceID, now, accessExpiry)
		if err != nil {
			return nil, "", fmt.Errorf("failed to sign access token (hybrid): %w", err)
		}
		idTokenString, err = s.signHybrid(userID, email, "", now, accessExpiry)
		if err != nil {
			return nil, "", fmt.Errorf("failed to sign ID token (hybrid): %w", err)
		}
	} else {
		accessTokenString, err = s.signEd25519(userID, email, deviceID, now, accessExpiry)
		if err != nil {
			return nil, "", fmt.Errorf("failed to sign access token (ed25519): %w", err)
		}
		idTokenString, err = s.signEd25519(userID, email, "", now, accessExpiry)
		if err != nil {
			return nil, "", fmt.Errorf("failed to sign ID token (ed25519): %w", err)
		}
	}

	// Refresh Token - opaque random token
	refreshTokenRaw := make([]byte, 32)
	if _, err := rand.Read(refreshTokenRaw); err != nil {
		return nil, "", fmt.Errorf("failed to generate refresh token: %w", err)
	}
	refreshTokenString := hex.EncodeToString(refreshTokenRaw)
	refreshTokenHash := HashToken(refreshTokenString)

	return &TokenPair{
		AccessToken:  accessTokenString,
		RefreshToken: refreshTokenString,
		IDToken:      idTokenString,
		TokenType:    "Bearer",
		ExpiresIn:    int(s.cfg.AccessTokenTTL.Seconds()),
	}, refreshTokenHash, nil
}

func (s *TokenService) signHybrid(userID, email, deviceID string, now, expiry time.Time) (string, error) {
	kp, keyID, err := s.keyProvider.GetActiveKeyPair()
	if err != nil {
		return "", err
	}

	claims := TokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.cfg.Issuer,
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiry),
			ID:        uuid.New().String(),
		},
		Email:    email,
		DeviceID: deviceID,
		KeyID:    keyID,
	}

	token := jwt.NewWithClaims(hybrid.SigningMethodHybrid, claims)
	token.Header["kid"] = keyID
	return token.SignedString(kp)
}

func (s *TokenService) signEd25519(userID, email, deviceID string, now, expiry time.Time) (string, error) {
	var sk ed25519.PrivateKey
	var keyID string

	if s.keyProvider != nil {
		var err error
		sk, _, keyID, err = s.keyProvider.GetActiveEd25519Key()
		if err != nil {
			return "", err
		}
	} else {
		return "", fmt.Errorf("no key provider configured")
	}

	claims := TokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.cfg.Issuer,
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiry),
			ID:        uuid.New().String(),
		},
		Email:    email,
		DeviceID: deviceID,
		KeyID:    keyID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = keyID
	return token.SignedString(sk)
}

// ValidateAccessToken validates an access token and returns the claims.
// Supports both hybrid and Ed25519-only tokens.
func (s *TokenService) ValidateAccessToken(tokenString string) (*TokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Extract key ID from header
		kidRaw, _ := token.Header["kid"].(string)
		algHeader, _ := token.Header["alg"].(string)

		if s.keyProvider != nil {
			verKey, algo, err := s.keyProvider.FindVerificationKey(kidRaw)
			if err != nil {
				return nil, fmt.Errorf("key not found: %w", err)
			}

			// Validate signing method matches
			switch algHeader {
			case hybrid.AlgName:
				if algo != "hybrid" {
					return nil, fmt.Errorf("algorithm mismatch: token=%s key=%s", algHeader, algo)
				}
				return verKey, nil
			case "EdDSA":
				// Accept Ed25519 verification from hybrid key pair too
				if pk, ok := verKey.(ed25519.PublicKey); ok {
					return pk, nil
				}
				if hpk, ok := verKey.(*hybrid.HybridPublicKey); ok {
					return hpk.Classical, nil
				}
				return nil, fmt.Errorf("unexpected key type for EdDSA: %T", verKey)
			default:
				return nil, fmt.Errorf("unexpected signing method: %s", algHeader)
			}
		}

		return nil, fmt.Errorf("no key provider configured")
	})

	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	claims, ok := token.Claims.(*TokenClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	return claims, nil
}

// HashToken creates a SHA-256 hash of a token for secure storage.
func HashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

// GetRefreshTokenTTL returns the configured refresh token TTL.
func (s *TokenService) GetRefreshTokenTTL() time.Duration {
	return s.cfg.RefreshTokenTTL
}
