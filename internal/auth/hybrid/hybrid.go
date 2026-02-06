package hybrid

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/golang-jwt/jwt/v5"
)

const (
	// AlgName is the JWT algorithm identifier for the hybrid scheme.
	AlgName = "EdDSA+ML-DSA-65"

	// Ed25519SignatureSize is the size of an Ed25519 signature.
	Ed25519SignatureSize = ed25519.SignatureSize // 64 bytes
)

// signingMethodHybrid implements jwt.SigningMethod for the
// hybrid Ed25519 + ML-DSA-65 scheme specified in SPECS.md.
//
// The combined signature is:
//
//	[2-byte Ed25519 sig length (big-endian)] || Ed25519 sig || ML-DSA-65 sig
//
// Verification requires BOTH signatures to be valid.
type signingMethodHybrid struct{}

// SigningMethodHybrid is the singleton instance registered with jwt.
var SigningMethodHybrid *signingMethodHybrid

func init() {
	SigningMethodHybrid = &signingMethodHybrid{}
	jwt.RegisterSigningMethod(AlgName, func() jwt.SigningMethod {
		return SigningMethodHybrid
	})
}

func (m *signingMethodHybrid) Alg() string { return AlgName }

// HybridKeyPair holds both classical and post-quantum key pairs.
type HybridKeyPair struct {
	ClassicalPrivate ed25519.PrivateKey
	ClassicalPublic  ed25519.PublicKey
	PQPrivate        *mldsa65.PrivateKey
	PQPublic         *mldsa65.PublicKey
}

// GenerateHybridKeyPair generates fresh Ed25519 + ML-DSA-65 key pairs.
func GenerateHybridKeyPair() (*HybridKeyPair, error) {
	// Ed25519
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ed25519 keygen: %w", err)
	}

	// ML-DSA-65
	pqPub, pqPriv, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ml-dsa-65 keygen: %w", err)
	}

	return &HybridKeyPair{
		ClassicalPrivate: priv,
		ClassicalPublic:  pub,
		PQPrivate:        pqPriv,
		PQPublic:         pqPub,
	}, nil
}

// Sign produces a hybrid signature.
// key must be *HybridKeyPair.
func (m *signingMethodHybrid) Sign(signingString string, key any) ([]byte, error) {
	kp, ok := key.(*HybridKeyPair)
	if !ok {
		return nil, fmt.Errorf("hybrid sign: expected *HybridKeyPair, got %T", key)
	}

	msg := []byte(signingString)

	// Ed25519 signature
	classicalSig := ed25519.Sign(kp.ClassicalPrivate, msg)

	// ML-DSA-65 signature
	pqSig, err := kp.PQPrivate.Sign(rand.Reader, msg, crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("ml-dsa-65 sign: %w", err)
	}

	// Encode: [2-byte classical sig length] || classical sig || pq sig
	combined := make([]byte, 2+len(classicalSig)+len(pqSig))
	binary.BigEndian.PutUint16(combined[:2], uint16(len(classicalSig)))
	copy(combined[2:2+len(classicalSig)], classicalSig)
	copy(combined[2+len(classicalSig):], pqSig)

	return combined, nil
}

// HybridPublicKey holds both public keys for verification.
type HybridPublicKey struct {
	Classical ed25519.PublicKey
	PQ        *mldsa65.PublicKey
}

// Verify checks BOTH signatures. key must be *HybridPublicKey.
func (m *signingMethodHybrid) Verify(signingString string, sig []byte, key any) error {
	pk, ok := key.(*HybridPublicKey)
	if !ok {
		return fmt.Errorf("hybrid verify: expected *HybridPublicKey, got %T", key)
	}

	if len(sig) < 4 { // minimum: 2 byte length + at least something
		return errors.New("hybrid verify: signature too short")
	}

	classicalLen := int(binary.BigEndian.Uint16(sig[:2]))
	if 2+classicalLen > len(sig) {
		return errors.New("hybrid verify: malformed signature")
	}

	classicalSig := sig[2 : 2+classicalLen]
	pqSig := sig[2+classicalLen:]

	msg := []byte(signingString)

	// MUST verify BOTH signatures (spec requirement)
	if !ed25519.Verify(pk.Classical, msg, classicalSig) {
		return errors.New("hybrid verify: Ed25519 signature invalid")
	}

	if !mldsa65.Verify(pk.PQ, msg, nil, pqSig) {
		return errors.New("hybrid verify: ML-DSA-65 signature invalid")
	}

	return nil
}
