// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"context"
	"testing"
	"time"

	"github.com/atol-sh/fosite/internal/gen"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRotatingKeySigner_RequiresAtLeastOneKey(t *testing.T) {
	_, err := NewRotatingKeySigner()
	require.Error(t, err)
}

func TestRotatingKeySigner_SignAndVerify(t *testing.T) {
	key1 := gen.MustRSAKey()
	signer, err := NewRotatingKeySigner(RotatingKey{KeyID: "key-1", Key: key1})
	require.NoError(t, err)

	claims := &JWTClaims{ExpiresAt: time.Now().UTC().Add(time.Hour)}
	h := &Headers{Extra: map[string]interface{}{"foo": "bar"}}

	token, sig, err := signer.Generate(context.Background(), claims.ToMapClaims(), h)
	require.NoError(t, err)
	require.NotEmpty(t, token)
	require.NotEmpty(t, sig)

	// Validate with same signer
	gotSig, err := signer.Validate(context.Background(), token)
	require.NoError(t, err)
	assert.Equal(t, sig, gotSig)

	// Decode
	decoded, err := signer.Decode(context.Background(), token)
	require.NoError(t, err)
	require.NotNil(t, decoded)
	assert.Equal(t, "key-1", decoded.Header["kid"])
}

func TestRotatingKeySigner_SignWithNewVerifyWithOld(t *testing.T) {
	oldKey := gen.MustRSAKey()
	signer, err := NewRotatingKeySigner(RotatingKey{KeyID: "old-key", Key: oldKey})
	require.NoError(t, err)

	claims := &JWTClaims{ExpiresAt: time.Now().UTC().Add(time.Hour)}
	h := &Headers{Extra: map[string]interface{}{}}

	// Sign with old key
	oldToken, _, err := signer.Generate(context.Background(), claims.ToMapClaims(), h)
	require.NoError(t, err)

	// Rotate: add new key
	newKey := gen.MustRSAKey()
	signer.AddKey(RotatingKey{KeyID: "new-key", Key: newKey})

	// Sign with new key
	newToken, _, err := signer.Generate(context.Background(), claims.ToMapClaims(), h)
	require.NoError(t, err)

	// New token should have new kid
	decodedNew, err := signer.Decode(context.Background(), newToken)
	require.NoError(t, err)
	assert.Equal(t, "new-key", decodedNew.Header["kid"])

	// Old token should still validate (verified with old key)
	_, err = signer.Validate(context.Background(), oldToken)
	require.NoError(t, err)

	// New token should validate too
	_, err = signer.Validate(context.Background(), newToken)
	require.NoError(t, err)

	// Old token should still decode
	decodedOld, err := signer.Decode(context.Background(), oldToken)
	require.NoError(t, err)
	assert.Equal(t, "old-key", decodedOld.Header["kid"])
}

func TestRotatingKeySigner_VerifyWithNewKey(t *testing.T) {
	key := gen.MustRSAKey()
	signer, err := NewRotatingKeySigner(RotatingKey{KeyID: "k1", Key: key})
	require.NoError(t, err)

	claims := &JWTClaims{ExpiresAt: time.Now().UTC().Add(time.Hour)}
	h := &Headers{Extra: map[string]interface{}{}}

	token, _, err := signer.Generate(context.Background(), claims.ToMapClaims(), h)
	require.NoError(t, err)

	_, err = signer.Validate(context.Background(), token)
	require.NoError(t, err)
}

func TestRotatingKeySigner_RejectsUnknownKey(t *testing.T) {
	key1 := gen.MustRSAKey()
	signer1, err := NewRotatingKeySigner(RotatingKey{KeyID: "k1", Key: key1})
	require.NoError(t, err)

	claims := &JWTClaims{ExpiresAt: time.Now().UTC().Add(time.Hour)}
	h := &Headers{Extra: map[string]interface{}{}}

	token, _, err := signer1.Generate(context.Background(), claims.ToMapClaims(), h)
	require.NoError(t, err)

	// Different signer with different key should reject
	key2 := gen.MustRSAKey()
	signer2, err := NewRotatingKeySigner(RotatingKey{KeyID: "k2", Key: key2})
	require.NoError(t, err)

	_, err = signer2.Validate(context.Background(), token)
	require.Error(t, err)
}

func TestRotatingKeySigner_ECDSAKeys(t *testing.T) {
	key1 := gen.MustES256Key()
	key2 := gen.MustES256Key()
	signer, err := NewRotatingKeySigner(
		RotatingKey{KeyID: "ec-1", Key: key1},
		RotatingKey{KeyID: "ec-2", Key: key2},
	)
	require.NoError(t, err)

	claims := &JWTClaims{ExpiresAt: time.Now().UTC().Add(time.Hour)}
	h := &Headers{Extra: map[string]interface{}{}}

	token, _, err := signer.Generate(context.Background(), claims.ToMapClaims(), h)
	require.NoError(t, err)

	decoded, err := signer.Decode(context.Background(), token)
	require.NoError(t, err)
	assert.Equal(t, "ec-1", decoded.Header["kid"])

	_, err = signer.Validate(context.Background(), token)
	require.NoError(t, err)
}

func TestRotatingKeySigner_MixedKeyTypes(t *testing.T) {
	rsaKey := gen.MustRSAKey()
	ecKey := gen.MustES256Key()

	signer, err := NewRotatingKeySigner(
		RotatingKey{KeyID: "rsa-active", Key: rsaKey},
		RotatingKey{KeyID: "ec-old", Key: ecKey},
	)
	require.NoError(t, err)

	claims := &JWTClaims{ExpiresAt: time.Now().UTC().Add(time.Hour)}
	h := &Headers{Extra: map[string]interface{}{}}

	// Signs with RSA (first key)
	token, _, err := signer.Generate(context.Background(), claims.ToMapClaims(), h)
	require.NoError(t, err)

	decoded, err := signer.Decode(context.Background(), token)
	require.NoError(t, err)
	assert.Equal(t, "rsa-active", decoded.Header["kid"])
}

func TestRotatingKeySigner_PublicKeys(t *testing.T) {
	key1 := gen.MustRSAKey()
	key2 := gen.MustES256Key()
	signer, err := NewRotatingKeySigner(
		RotatingKey{KeyID: "rsa-1", Key: key1},
		RotatingKey{KeyID: "ec-1", Key: key2},
	)
	require.NoError(t, err)

	pubs := signer.PublicKeys()
	require.Len(t, pubs, 2)

	assert.Equal(t, "rsa-1", pubs[0].KeyID)
	assert.Equal(t, "sig", pubs[0].Use)
	assert.Equal(t, "RS256", pubs[0].Algorithm)

	assert.Equal(t, "ec-1", pubs[1].KeyID)
	assert.Equal(t, "sig", pubs[1].Use)
	assert.Equal(t, "ES256", pubs[1].Algorithm)
}

func TestRotatingKeySigner_HashAndSignature(t *testing.T) {
	key := gen.MustRSAKey()
	signer, err := NewRotatingKeySigner(RotatingKey{KeyID: "k1", Key: key})
	require.NoError(t, err)

	out, err := signer.Hash(context.Background(), []byte("test"))
	require.NoError(t, err)
	require.NotEmpty(t, out)

	assert.Equal(t, SHA256HashSize, signer.GetSigningMethodLength(context.Background()))

	_, err = signer.GetSignature(context.Background(), "a.b.c")
	require.NoError(t, err)
}

func TestRotatingKeySigner_Keys(t *testing.T) {
	key1 := gen.MustRSAKey()
	key2 := gen.MustRSAKey()
	signer, err := NewRotatingKeySigner(
		RotatingKey{KeyID: "k1", Key: key1},
		RotatingKey{KeyID: "k2", Key: key2},
	)
	require.NoError(t, err)

	keys := signer.Keys()
	require.Len(t, keys, 2)
	assert.Equal(t, "k1", keys[0].KeyID)
	assert.Equal(t, "k2", keys[1].KeyID)

	// AddKey should prepend
	key3 := gen.MustRSAKey()
	signer.AddKey(RotatingKey{KeyID: "k3", Key: key3})

	keys = signer.Keys()
	require.Len(t, keys, 3)
	assert.Equal(t, "k3", keys[0].KeyID)
	assert.Equal(t, "k1", keys[1].KeyID)
}

// TestRotatingKeySigner_ImplementsSigner ensures compile-time interface satisfaction.
func TestRotatingKeySigner_ImplementsSigner(t *testing.T) {
	var _ Signer = (*RotatingKeySigner)(nil)
}
