// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package openid

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/atol-sh/fosite"
	"github.com/atol-sh/fosite/token/jwt"
)

// testSigningAlgClient is a test client that implements IDTokenSigningAlgClient.
type testSigningAlgClient struct {
	*fosite.DefaultClient
	signingAlg string
}

func (c *testSigningAlgClient) GetIDTokenSigningAlg() string {
	return c.signingAlg
}

func TestGenerateIDToken_PerClientSigningAlg(t *testing.T) {
	j := &DefaultStrategy{
		Signer: &jwt.DefaultSigner{
			GetPrivateKey: func(_ context.Context) (interface{}, error) {
				return key, nil
			},
		},
		Config: &fosite.Config{
			MinParameterEntropy: fosite.MinParameterEntropy,
		},
	}

	t.Run("client without IDTokenSigningAlgClient uses default", func(t *testing.T) {
		req := fosite.NewAccessRequest(&DefaultSession{
			Claims: &jwt.IDTokenClaims{
				Subject: "peter",
			},
			Headers: &jwt.Headers{},
		})
		req.Client = &fosite.DefaultClient{ID: "plain-client"}

		token, err := j.GenerateIDToken(context.Background(), time.Hour, req)
		require.NoError(t, err)
		assert.NotEmpty(t, token)
	})

	t.Run("client with empty signing alg uses default", func(t *testing.T) {
		req := fosite.NewAccessRequest(&DefaultSession{
			Claims: &jwt.IDTokenClaims{
				Subject: "peter",
			},
			Headers: &jwt.Headers{},
		})
		req.Client = &testSigningAlgClient{
			DefaultClient: &fosite.DefaultClient{ID: "empty-alg-client"},
			signingAlg:    "",
		}

		token, err := j.GenerateIDToken(context.Background(), time.Hour, req)
		require.NoError(t, err)
		assert.NotEmpty(t, token)
	})

	t.Run("client with RS256 sets alg header", func(t *testing.T) {
		sess := &DefaultSession{
			Claims: &jwt.IDTokenClaims{
				Subject: "peter",
			},
			Headers: &jwt.Headers{},
		}
		req := fosite.NewAccessRequest(sess)
		req.Client = &testSigningAlgClient{
			DefaultClient: &fosite.DefaultClient{ID: "rs256-client"},
			signingAlg:    "RS256",
		}

		token, err := j.GenerateIDToken(context.Background(), time.Hour, req)
		require.NoError(t, err)
		assert.NotEmpty(t, token)

		// The alg header should have been set on the session
		assert.Equal(t, "RS256", sess.IDTokenHeaders().Get("alg"))
	})

	t.Run("client with ES256 sets alg header", func(t *testing.T) {
		sess := &DefaultSession{
			Claims: &jwt.IDTokenClaims{
				Subject: "peter",
			},
			Headers: &jwt.Headers{},
		}
		req := fosite.NewAccessRequest(sess)
		req.Client = &testSigningAlgClient{
			DefaultClient: &fosite.DefaultClient{ID: "es256-client"},
			signingAlg:    "ES256",
		}

		// This will fail at signing because the key is RSA but the alg header
		// is ES256 -- but the alg header WILL be set, which is the point.
		// In production, the signer key must match the requested alg.
		// We only verify the header was set.
		_, _ = j.GenerateIDToken(context.Background(), time.Hour, req)
		assert.Equal(t, "ES256", sess.IDTokenHeaders().Get("alg"))
	})
}

func TestDefaultOpenIDConnectClient_GetIDTokenSigningAlg(t *testing.T) {
	client := &fosite.DefaultOpenIDConnectClient{
		DefaultClient:           &fosite.DefaultClient{ID: "test"},
		IDTokenSigningAlgorithm: "ES256",
	}

	var _ fosite.IDTokenSigningAlgClient = client
	assert.Equal(t, "ES256", client.GetIDTokenSigningAlg())

	client.IDTokenSigningAlgorithm = ""
	assert.Equal(t, "", client.GetIDTokenSigningAlg())
}
