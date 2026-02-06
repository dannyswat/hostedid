package service

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/hostedid/hostedid/internal/auth/hybrid"
	"github.com/hostedid/hostedid/internal/logger"
	"github.com/hostedid/hostedid/internal/model"
	"github.com/hostedid/hostedid/internal/repository"
)

// Key-related errors.
var (
	ErrNoActiveKey    = errors.New("no active signing key found")
	ErrKeyNotFound    = errors.New("signing key not found")
	ErrKeyDeactivated = errors.New("signing key already deactivated")
)

const (
	// AlgorithmHybrid is the DB value for hybrid Ed25519+ML-DSA-65 keys.
	AlgorithmHybrid = "hybrid"
	// AlgorithmEd25519 is the DB value for Ed25519-only keys.
	AlgorithmEd25519 = "ed25519"

	// KeyRotationPeriod is 90 days per spec.
	KeyRotationPeriod = 90 * 24 * time.Hour
	// KeyVerificationValidity is 1 year per spec.
	KeyVerificationValidity = 365 * 24 * time.Hour
)

// KeyService manages signing key lifecycle.
type KeyService struct {
	repo *repository.SigningKeyRepository
	log  *logger.Logger

	mu         sync.RWMutex
	activeKey  *cachedKey   // currently active signing key
	verifyKeys []*cachedKey // all keys valid for verification
}

// cachedKey holds a deserialized key in memory.
type cachedKey struct {
	id        string
	algorithm string
	hybrid    *hybrid.HybridKeyPair // non-nil if algorithm == "hybrid"
	ed25519Pk ed25519.PublicKey     // always set
	ed25519Sk ed25519.PrivateKey    // set for active signing key
	pqPk      *mldsa65.PublicKey    // set if hybrid
	createdAt time.Time
	expiresAt *time.Time
}

// NewKeyService creates a new KeyService.
func NewKeyService(repo *repository.SigningKeyRepository, log *logger.Logger) *KeyService {
	return &KeyService{
		repo: repo,
		log:  log.WithComponent("key_service"),
	}
}

// Initialize loads or creates the active signing key.
// Call this at server startup.
func (s *KeyService) Initialize(ctx context.Context, algorithm string) error {
	if algorithm == "" {
		algorithm = AlgorithmHybrid
	}

	// Try to load existing active key
	key, err := s.repo.GetActive(ctx, algorithm)
	if err != nil && !errors.Is(err, repository.ErrNotFound) {
		return fmt.Errorf("failed to load active key: %w", err)
	}

	if key != nil {
		// Check if rotation is needed
		if time.Since(key.CreatedAt) > KeyRotationPeriod {
			s.log.Info().Str("key_id", key.ID).Msg("active key needs rotation")
			if _, err := s.RotateKey(ctx, algorithm); err != nil {
				return fmt.Errorf("failed to rotate expired key: %w", err)
			}
		} else {
			// Load the key into memory
			ck, err := s.deserializeKey(key)
			if err != nil {
				return fmt.Errorf("failed to deserialize active key: %w", err)
			}
			s.mu.Lock()
			s.activeKey = ck
			s.mu.Unlock()
			s.log.Info().Str("key_id", key.ID).Str("algorithm", algorithm).Msg("loaded active signing key from database")
		}
	} else {
		// No active key — generate one
		s.log.Info().Str("algorithm", algorithm).Msg("no active signing key found, generating new one")
		if _, err := s.generateAndStoreKey(ctx, algorithm); err != nil {
			return fmt.Errorf("failed to generate initial key: %w", err)
		}
	}

	// Load all verification keys
	if err := s.loadVerificationKeys(ctx, algorithm); err != nil {
		return fmt.Errorf("failed to load verification keys: %w", err)
	}

	return nil
}

// GetActiveKeyPair returns the active hybrid key pair for token signing.
func (s *KeyService) GetActiveKeyPair() (*hybrid.HybridKeyPair, string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.activeKey == nil {
		return nil, "", ErrNoActiveKey
	}

	if s.activeKey.hybrid != nil {
		return s.activeKey.hybrid, s.activeKey.id, nil
	}

	// Ed25519-only mode: wrap in hybrid pair (ML-DSA will be nil)
	return &hybrid.HybridKeyPair{
		ClassicalPrivate: s.activeKey.ed25519Sk,
		ClassicalPublic:  s.activeKey.ed25519Pk,
	}, s.activeKey.id, nil
}

// GetActiveEd25519Key returns just the Ed25519 key pair (for ed25519-only mode).
func (s *KeyService) GetActiveEd25519Key() (ed25519.PrivateKey, ed25519.PublicKey, string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.activeKey == nil {
		return nil, nil, "", ErrNoActiveKey
	}

	return s.activeKey.ed25519Sk, s.activeKey.ed25519Pk, s.activeKey.id, nil
}

// FindVerificationKey finds a key for verifying a token.
// For hybrid mode it returns *hybrid.HybridPublicKey, for ed25519 it returns ed25519.PublicKey.
// It tries all known verification keys.
func (s *KeyService) FindVerificationKey(keyID string) (interface{}, string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Search by key ID if provided
	for _, ck := range s.verifyKeys {
		if ck.id == keyID {
			return s.buildVerificationKey(ck), ck.algorithm, nil
		}
	}

	// Also check active key
	if s.activeKey != nil && s.activeKey.id == keyID {
		return s.buildVerificationKey(s.activeKey), s.activeKey.algorithm, nil
	}

	// If no key ID match, return the active key (backward compat)
	if s.activeKey != nil {
		return s.buildVerificationKey(s.activeKey), s.activeKey.algorithm, nil
	}

	return nil, "", ErrNoActiveKey
}

// RotateKey generates a new key and deactivates the old one.
func (s *KeyService) RotateKey(ctx context.Context, algorithm string) (*model.SigningKeyInfo, error) {
	if algorithm == "" {
		algorithm = AlgorithmHybrid
	}

	// Deactivate current active key(s)
	if err := s.repo.DeactivateAllForAlgorithm(ctx, algorithm); err != nil {
		s.log.Error().Err(err).Msg("failed to deactivate old keys during rotation")
	}

	// Generate and store new key
	keyInfo, err := s.generateAndStoreKey(ctx, algorithm)
	if err != nil {
		return nil, err
	}

	// Reload verification keys
	if err := s.loadVerificationKeys(ctx, algorithm); err != nil {
		s.log.Error().Err(err).Msg("failed to reload verification keys after rotation")
	}

	s.log.Info().Str("new_key_id", keyInfo.ID).Str("algorithm", algorithm).Msg("signing key rotated")
	return keyInfo, nil
}

// ListKeys returns all signing keys (public info only).
func (s *KeyService) ListKeys(ctx context.Context) ([]*model.SigningKeyInfo, error) {
	keys, err := s.repo.ListAll(ctx)
	if err != nil {
		return nil, err
	}

	infos := make([]*model.SigningKeyInfo, len(keys))
	for i, k := range keys {
		infos[i] = k.ToInfo()
	}
	return infos, nil
}

// GetAlgorithm returns the algorithm of the active key.
func (s *KeyService) GetAlgorithm() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.activeKey != nil {
		return s.activeKey.algorithm
	}
	return AlgorithmHybrid
}

// --- internal ---

func (s *KeyService) generateAndStoreKey(ctx context.Context, algorithm string) (*model.SigningKeyInfo, error) {
	var pubBytes, privBytes []byte
	var ck *cachedKey
	now := time.Now()
	keyID := generateID("sk")
	expiresAt := now.Add(KeyRotationPeriod)

	switch algorithm {
	case AlgorithmHybrid:
		kp, err := hybrid.GenerateHybridKeyPair()
		if err != nil {
			return nil, fmt.Errorf("failed to generate hybrid key pair: %w", err)
		}

		pubBytes = s.serializeHybridPublic(kp)
		privBytes = s.serializeHybridPrivate(kp)

		ck = &cachedKey{
			id:        keyID,
			algorithm: AlgorithmHybrid,
			hybrid:    kp,
			ed25519Pk: kp.ClassicalPublic,
			ed25519Sk: kp.ClassicalPrivate,
			pqPk:      kp.PQPublic,
			createdAt: now,
			expiresAt: &expiresAt,
		}

	case AlgorithmEd25519:
		pub, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			return nil, fmt.Errorf("failed to generate Ed25519 key: %w", err)
		}

		pubBytes = []byte(pub)
		privBytes = []byte(priv)

		ck = &cachedKey{
			id:        keyID,
			algorithm: AlgorithmEd25519,
			ed25519Pk: pub,
			ed25519Sk: priv,
			createdAt: now,
			expiresAt: &expiresAt,
		}

	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}

	// Store in DB
	// NOTE: In production, private_key_enc should be encrypted with a KEK/HSM.
	// For now we store raw bytes (the column is named _enc to indicate it should be encrypted).
	dbKey := &model.SigningKey{
		ID:            keyID,
		Algorithm:     algorithm,
		PublicKey:     pubBytes,
		PrivateKeyEnc: privBytes,
		IsActive:      true,
		ExpiresAt:     &expiresAt,
		CreatedAt:     now,
	}

	if err := s.repo.Create(ctx, dbKey); err != nil {
		return nil, fmt.Errorf("failed to store signing key: %w", err)
	}

	// Update in-memory cache
	s.mu.Lock()
	s.activeKey = ck
	s.mu.Unlock()

	return dbKey.ToInfo(), nil
}

func (s *KeyService) loadVerificationKeys(ctx context.Context, algorithm string) error {
	keys, err := s.repo.ListAllVerificationKeys(ctx, algorithm)
	if err != nil {
		return err
	}

	var cached []*cachedKey
	for _, k := range keys {
		ck, err := s.deserializeKey(k)
		if err != nil {
			s.log.Warn().Err(err).Str("key_id", k.ID).Msg("skipping unreadable verification key")
			continue
		}
		cached = append(cached, ck)
	}

	s.mu.Lock()
	s.verifyKeys = cached
	s.mu.Unlock()

	s.log.Debug().Int("count", len(cached)).Msg("loaded verification keys")
	return nil
}

func (s *KeyService) deserializeKey(k *model.SigningKey) (*cachedKey, error) {
	ck := &cachedKey{
		id:        k.ID,
		algorithm: k.Algorithm,
		createdAt: k.CreatedAt,
		expiresAt: k.ExpiresAt,
	}

	switch k.Algorithm {
	case AlgorithmHybrid:
		kp, err := s.deserializeHybridKeys(k.PublicKey, k.PrivateKeyEnc)
		if err != nil {
			return nil, err
		}
		ck.hybrid = kp
		ck.ed25519Pk = kp.ClassicalPublic
		ck.ed25519Sk = kp.ClassicalPrivate
		ck.pqPk = kp.PQPublic

	case AlgorithmEd25519:
		if len(k.PrivateKeyEnc) == ed25519.PrivateKeySize {
			ck.ed25519Sk = ed25519.PrivateKey(k.PrivateKeyEnc)
			ck.ed25519Pk = ck.ed25519Sk.Public().(ed25519.PublicKey)
		} else if len(k.PublicKey) == ed25519.PublicKeySize {
			ck.ed25519Pk = ed25519.PublicKey(k.PublicKey)
		} else {
			return nil, fmt.Errorf("invalid Ed25519 key sizes: pub=%d priv=%d", len(k.PublicKey), len(k.PrivateKeyEnc))
		}

	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", k.Algorithm)
	}

	return ck, nil
}

func (s *KeyService) buildVerificationKey(ck *cachedKey) interface{} {
	if ck.algorithm == AlgorithmHybrid && ck.pqPk != nil {
		return &hybrid.HybridPublicKey{
			Classical: ck.ed25519Pk,
			PQ:        ck.pqPk,
		}
	}
	return ck.ed25519Pk
}

// --- Hybrid key serialization ---
// Format: [32 bytes Ed25519 pub] [64 bytes Ed25519 priv] ... for private
// Format: [32 bytes Ed25519 pub] [ML-DSA-65 pub bytes] ... for public

func (s *KeyService) serializeHybridPublic(kp *hybrid.HybridKeyPair) []byte {
	pqPubBytes, _ := kp.PQPublic.MarshalBinary()
	buf := make([]byte, ed25519.PublicKeySize+len(pqPubBytes))
	copy(buf[:ed25519.PublicKeySize], kp.ClassicalPublic)
	copy(buf[ed25519.PublicKeySize:], pqPubBytes)
	return buf
}

func (s *KeyService) serializeHybridPrivate(kp *hybrid.HybridKeyPair) []byte {
	pqPrivBytes, _ := kp.PQPrivate.MarshalBinary()
	buf := make([]byte, ed25519.PrivateKeySize+len(pqPrivBytes))
	copy(buf[:ed25519.PrivateKeySize], kp.ClassicalPrivate)
	copy(buf[ed25519.PrivateKeySize:], pqPrivBytes)
	return buf
}

func (s *KeyService) deserializeHybridKeys(pubBytes, privBytes []byte) (*hybrid.HybridKeyPair, error) {
	kp := &hybrid.HybridKeyPair{}

	// Public key
	if len(pubBytes) < ed25519.PublicKeySize {
		return nil, fmt.Errorf("hybrid public key too short: %d bytes", len(pubBytes))
	}
	kp.ClassicalPublic = ed25519.PublicKey(pubBytes[:ed25519.PublicKeySize])
	pqPubBytes := pubBytes[ed25519.PublicKeySize:]
	kp.PQPublic = new(mldsa65.PublicKey)
	if err := kp.PQPublic.UnmarshalBinary(pqPubBytes); err != nil {
		return nil, fmt.Errorf("failed to unmarshal ML-DSA-65 public key: %w", err)
	}

	// Private key
	if len(privBytes) < ed25519.PrivateKeySize {
		return nil, fmt.Errorf("hybrid private key too short: %d bytes", len(privBytes))
	}
	kp.ClassicalPrivate = ed25519.PrivateKey(privBytes[:ed25519.PrivateKeySize])
	pqPrivBytes := privBytes[ed25519.PrivateKeySize:]
	kp.PQPrivate = new(mldsa65.PrivateKey)
	if err := kp.PQPrivate.UnmarshalBinary(pqPrivBytes); err != nil {
		return nil, fmt.Errorf("failed to unmarshal ML-DSA-65 private key: %w", err)
	}

	return kp, nil
}

// NeedsRotation checks if the current active key should be rotated.
func (s *KeyService) NeedsRotation() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.activeKey == nil {
		return true
	}
	return time.Since(s.activeKey.createdAt) > KeyRotationPeriod
}

// GetActiveKeyID returns the active key's ID.
func (s *KeyService) GetActiveKeyID() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.activeKey == nil {
		return ""
	}
	return s.activeKey.id
}
