// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/atol-sh/fosite"
	"github.com/atol-sh/fosite/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConcurrentAuthorizeCodeExchange verifies that when multiple goroutines
// attempt to exchange the same authorization code concurrently, only one
// succeeds. This tests the atomic invalidation in InvalidateAuthorizeCodeSession.
func TestConcurrentAuthorizeCodeExchange(t *testing.T) {
	store := storage.NewMemoryStore()
	strategy := hmacshaStrategy

	config := &fosite.Config{
		ScopeStrategy:            fosite.HierarchicScopeStrategy,
		AudienceMatchingStrategy: fosite.DefaultAudienceMatchingStrategy,
		AccessTokenLifespan:      time.Minute,
		RefreshTokenScopes:       []string{},
		AuthorizeCodeLifespan:    time.Minute,
	}

	client := &fosite.DefaultClient{
		ID:         "test-client",
		GrantTypes: fosite.Arguments{"authorization_code"},
	}

	// Generate a valid authorization code
	code, sig, err := strategy.GenerateAuthorizeCode(context.Background(), nil)
	require.NoError(t, err)

	// Store the authorize code session
	authReq := &fosite.Request{
		Client:       client,
		GrantedScope: fosite.Arguments{"foo"},
		Session:      &fosite.DefaultSession{},
		RequestedAt:  time.Now().UTC(),
	}
	require.NoError(t, store.CreateAuthorizeCodeSession(context.Background(), sig, authReq))

	// All goroutines call HandleTokenEndpointRequest sequentially first
	// to avoid data races on the shared session. Then they call
	// PopulateTokenEndpointResponse concurrently -- that is where the
	// atomic InvalidateAuthorizeCodeSession matters.
	const concurrency = 10

	// Phase 1: prepare each request (sequential, no race).
	requests := make([]*fosite.AccessRequest, concurrency)
	for i := 0; i < concurrency; i++ {
		areq := &fosite.AccessRequest{
			GrantTypes: fosite.Arguments{"authorization_code"},
			Request: fosite.Request{
				Form:         url.Values{"code": {code}},
				Client:       client,
				GrantedScope: fosite.Arguments{"foo"},
				Session:      &fosite.DefaultSession{},
				RequestedAt:  time.Now().UTC(),
			},
		}

		h := AuthorizeExplicitGrantHandler{
			CoreStorage:            store,
			AuthorizeCodeStrategy:  strategy,
			AccessTokenStrategy:    strategy,
			RefreshTokenStrategy:   strategy,
			TokenRevocationStorage: store,
			Config:                 config,
		}

		err := h.HandleTokenEndpointRequest(context.Background(), areq)
		require.NoError(t, err, "HandleTokenEndpointRequest should succeed for all requests")
		requests[i] = areq
	}

	// Phase 2: concurrent PopulateTokenEndpointResponse.
	var wg sync.WaitGroup
	results := make([]error, concurrency)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			h := AuthorizeExplicitGrantHandler{
				CoreStorage:            store,
				AuthorizeCodeStrategy:  strategy,
				AccessTokenStrategy:    strategy,
				RefreshTokenStrategy:   strategy,
				TokenRevocationStorage: store,
				Config:                 config,
			}

			aresp := fosite.NewAccessResponse()
			results[idx] = h.PopulateTokenEndpointResponse(context.Background(), requests[idx], aresp)
		}(i)
	}

	wg.Wait()

	successCount := 0
	for _, err := range results {
		if err == nil {
			successCount++
		}
	}

	assert.Equal(t, 1, successCount, "exactly one concurrent exchange should succeed")
}

func TestInvalidateAuthorizeCodeSession_AlreadyInvalidated(t *testing.T) {
	store := storage.NewMemoryStore()
	strategy := hmacshaStrategy

	_, sig, err := strategy.GenerateAuthorizeCode(context.Background(), nil)
	require.NoError(t, err)

	client := &fosite.DefaultClient{ID: "test"}
	authReq := &fosite.Request{
		Client:      client,
		Session:     &fosite.DefaultSession{},
		RequestedAt: time.Now().UTC(),
	}
	require.NoError(t, store.CreateAuthorizeCodeSession(context.Background(), sig, authReq))

	// First invalidation should succeed
	err = store.InvalidateAuthorizeCodeSession(context.Background(), sig)
	require.NoError(t, err)

	// Second invalidation should return ErrInvalidatedAuthorizeCode
	err = store.InvalidateAuthorizeCodeSession(context.Background(), sig)
	assert.ErrorIs(t, err, fosite.ErrInvalidatedAuthorizeCode)
}
