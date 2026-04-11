// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"sync"

	"github.com/go-jose/go-jose/v3"

	"github.com/pkg/errors"
)

// RotatingKeySigner supports key rotation by maintaining a set of keys.
// The first key in the set is used for signing; all keys are available for
// verification. This enables zero-downtime JWKS rotation: add a new key,
// deploy, remove the old key after all outstanding tokens expire.
type RotatingKeySigner struct {
	mu   sync.RWMutex
	keys []RotatingKey
}

// RotatingKey pairs a private key with a stable identifier used in the
// "kid" JWT header.
type RotatingKey struct {
	// KeyID is the "kid" header value written into JWTs signed with this key.
	KeyID string
	// Key is the private key (one of *rsa.PrivateKey, *ecdsa.PrivateKey,
	// *jose.JSONWebKey, or jose.OpaqueSigner).
	Key interface{}
}

// NewRotatingKeySigner creates a signer that signs with the first key
// and can verify with any key in the provided set.
func NewRotatingKeySigner(keys ...RotatingKey) (*RotatingKeySigner, error) {
	if len(keys) == 0 {
		return nil, errors.New("at least one signing key is required")
	}
	return &RotatingKeySigner{keys: keys}, nil
}

// AddKey prepends a new signing key to the key set, making it the active
// signing key. Existing keys remain available for verification.
func (r *RotatingKeySigner) AddKey(key RotatingKey) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.keys = append([]RotatingKey{key}, r.keys...)
}

// Keys returns a snapshot of all keys currently in the set.
func (r *RotatingKeySigner) Keys() []RotatingKey {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]RotatingKey, len(r.keys))
	copy(out, r.keys)
	return out
}

// Generate signs a JWT with the first (newest) key.
func (r *RotatingKeySigner) Generate(ctx context.Context, claims MapClaims, header Mapper) (string, string, error) {
	r.mu.RLock()
	key := r.keys[0]
	r.mu.RUnlock()

	if header == nil || claims == nil {
		return "", "", errors.New("either claims or header is nil")
	}

	alg, rawKey := resolveAlgAndKey(key)

	token := NewWithClaims(alg, claims)
	token.Header = assign(token.Header, header.ToMap())
	if key.KeyID != "" {
		token.Header["kid"] = key.KeyID
	}

	rawToken, err := token.SignedString(rawKey)
	if err != nil {
		return "", "", err
	}

	sig, err := getTokenSignature(rawToken)
	return rawToken, sig, err
}

// Validate verifies the token signature against any key in the set.
func (r *RotatingKeySigner) Validate(ctx context.Context, token string) (string, error) {
	r.mu.RLock()
	keys := make([]RotatingKey, len(r.keys))
	copy(keys, r.keys)
	r.mu.RUnlock()

	var lastErr error
	for _, k := range keys {
		pub := publicKey(k.Key)
		if pub == nil {
			continue
		}
		_, err := decodeToken(token, pub)
		if err == nil {
			return getTokenSignature(token)
		}
		lastErr = err
	}
	if lastErr != nil {
		return "", lastErr
	}
	return "", errors.New("no matching key found for token validation")
}

// Decode decodes a token, trying all keys in the set for verification.
func (r *RotatingKeySigner) Decode(ctx context.Context, token string) (*Token, error) {
	r.mu.RLock()
	keys := make([]RotatingKey, len(r.keys))
	copy(keys, r.keys)
	r.mu.RUnlock()

	var lastErr error
	for _, k := range keys {
		pub := publicKey(k.Key)
		if pub == nil {
			continue
		}
		t, err := decodeToken(token, pub)
		if err == nil {
			return t, nil
		}
		lastErr = err
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, errors.New("no matching key found for token decoding")
}

// GetSignature returns the signature segment of a token.
func (r *RotatingKeySigner) GetSignature(ctx context.Context, token string) (string, error) {
	return getTokenSignature(token)
}

// Hash returns the SHA-256 hash of the input.
func (r *RotatingKeySigner) Hash(ctx context.Context, in []byte) ([]byte, error) {
	return hashSHA256(in)
}

// GetSigningMethodLength returns the SHA-256 hash size.
func (r *RotatingKeySigner) GetSigningMethodLength(ctx context.Context) int {
	return SHA256HashSize
}

// PublicKeys returns the public keys of all keys in the set, suitable for
// exposing via a JWKS endpoint.
func (r *RotatingKeySigner) PublicKeys() []jose.JSONWebKey {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]jose.JSONWebKey, 0, len(r.keys))
	for _, k := range r.keys {
		pub := publicKey(k.Key)
		if pub == nil {
			continue
		}
		jwk := jose.JSONWebKey{
			Key:   pub,
			KeyID: k.KeyID,
			Use:   "sig",
		}
		switch pub.(type) {
		case *rsa.PublicKey, rsa.PublicKey:
			jwk.Algorithm = string(jose.RS256)
		case *ecdsa.PublicKey, ecdsa.PublicKey:
			jwk.Algorithm = string(jose.ES256)
		}
		out = append(out, jwk)
	}
	return out
}

// resolveAlgAndKey determines the signing algorithm and raw key material.
func resolveAlgAndKey(rk RotatingKey) (jose.SignatureAlgorithm, interface{}) {
	switch t := rk.Key.(type) {
	case *jose.JSONWebKey:
		return jose.SignatureAlgorithm(t.Algorithm), t
	case jose.JSONWebKey:
		return jose.SignatureAlgorithm(t.Algorithm), t
	case *rsa.PrivateKey:
		return jose.RS256, t
	case *ecdsa.PrivateKey:
		return jose.ES256, t
	case jose.OpaqueSigner:
		if len(t.Algs()) > 0 {
			return t.Algs()[0], t
		}
		return jose.RS256, t
	default:
		return jose.RS256, t
	}
}

// publicKey extracts the public key from a private key or JWK.
func publicKey(key interface{}) interface{} {
	switch t := key.(type) {
	case *jose.JSONWebKey:
		return t.Public().Key
	case jose.JSONWebKey:
		return t.Public().Key
	case *rsa.PrivateKey:
		return &t.PublicKey
	case *ecdsa.PrivateKey:
		return &t.PublicKey
	case jose.OpaqueSigner:
		return t.Public().Key
	default:
		return nil
	}
}
