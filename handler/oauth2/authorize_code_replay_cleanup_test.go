// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/atol-sh/fosite"
	"github.com/atol-sh/fosite/internal"
	"github.com/atol-sh/fosite/storage"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

type replayTransactionalStorage struct {
	*replayStorageMock
	storage.Transactional
}

type replayTransactionalCoreStore struct {
	storage.Transactional
	CoreStorage
}

func TestAuthorizeCodeReplayCleanupOutcome(t *testing.T) {
	ctx := context.Background()
	request, _ := newAuthorizeCodeReplayRequest(t, ctx)
	ctrl := gomock.NewController(t)
	transactional := internal.NewMockTransactional(ctrl)
	storeMock := newReplayStorageMock(ctrl)
	store := replayTransactionalStorage{replayStorageMock: storeMock, Transactional: transactional}

	gomock.InOrder(
		storeMock.core.EXPECT().
			GetAuthorizeCodeSession(ctx, gomock.Any(), gomock.Any()).
			Return(request, fosite.ErrInvalidatedAuthorizeCode),
		transactional.EXPECT().BeginTX(ctx).Return(ctx, nil),
		storeMock.revocation.EXPECT().RevokeAccessToken(ctx, request.GetID()).Return(nil),
		storeMock.revocation.EXPECT().RevokeRefreshToken(ctx, request.GetID()).Return(nil),
		transactional.EXPECT().Commit(ctx).Return(nil),
	)

	handler := newReplayAuthorizeCodeHandler(store, store)
	err := handler.HandleTokenEndpointRequest(ctx, request)
	require.ErrorIs(t, err, fosite.ErrInvalidGrant)
	require.ErrorIs(t, err, fosite.ErrInvalidatedAuthorizeCode)
	require.ErrorIs(t, err, fosite.ErrTokenReplayCleanupComplete)
}

func TestAuthorizeCodeReplayAlreadyCleanedErrors(t *testing.T) {
	testCases := []struct {
		name       string
		accessErr  error
		refreshErr error
	}{
		{name: "access token missing", accessErr: fosite.ErrNotFound},
		{name: "access token inactive", accessErr: fosite.ErrInactiveToken},
		{name: "refresh token missing", refreshErr: fosite.ErrNotFound},
		{name: "refresh token inactive", refreshErr: fosite.ErrInactiveToken},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			ctx := context.Background()
			request, _ := newAuthorizeCodeReplayRequest(t, ctx)
			ctrl := gomock.NewController(t)
			transactional := internal.NewMockTransactional(ctrl)
			storeMock := newReplayStorageMock(ctrl)
			store := replayTransactionalStorage{replayStorageMock: storeMock, Transactional: transactional}

			gomock.InOrder(
				storeMock.core.EXPECT().
					GetAuthorizeCodeSession(ctx, gomock.Any(), gomock.Any()).
					Return(request, fosite.ErrInvalidatedAuthorizeCode),
				transactional.EXPECT().BeginTX(ctx).Return(ctx, nil),
				storeMock.revocation.EXPECT().RevokeAccessToken(ctx, request.GetID()).Return(testCase.accessErr),
				storeMock.revocation.EXPECT().RevokeRefreshToken(ctx, request.GetID()).Return(testCase.refreshErr),
				transactional.EXPECT().Commit(ctx).Return(nil),
			)

			handler := newReplayAuthorizeCodeHandler(store, store)
			err := handler.HandleTokenEndpointRequest(ctx, request)
			require.ErrorIs(t, err, fosite.ErrInvalidGrant)
			require.ErrorIs(t, err, fosite.ErrTokenReplayCleanupComplete)
		})
	}
}

func TestAuthorizeCodeReplayCleanupFailure(t *testing.T) {
	testCases := []struct {
		name        string
		expectCalls func(
			ctx context.Context,
			request fosite.Requester,
			transactional *internal.MockTransactional,
			store *replayStorageMock,
			failure error,
		)
	}{
		{
			name: "access token revocation",
			expectCalls: func(
				ctx context.Context,
				request fosite.Requester,
				transactional *internal.MockTransactional,
				store *replayStorageMock,
				failure error,
			) {
				gomock.InOrder(
					transactional.EXPECT().BeginTX(ctx).Return(ctx, nil),
					store.revocation.EXPECT().RevokeAccessToken(ctx, request.GetID()).Return(failure),
					transactional.EXPECT().Rollback(ctx).Return(nil),
				)
			},
		},
		{
			name: "refresh token revocation",
			expectCalls: func(
				ctx context.Context,
				request fosite.Requester,
				transactional *internal.MockTransactional,
				store *replayStorageMock,
				failure error,
			) {
				gomock.InOrder(
					transactional.EXPECT().BeginTX(ctx).Return(ctx, nil),
					store.revocation.EXPECT().RevokeAccessToken(ctx, request.GetID()).Return(nil),
					store.revocation.EXPECT().RevokeRefreshToken(ctx, request.GetID()).Return(failure),
					transactional.EXPECT().Rollback(ctx).Return(nil),
				)
			},
		},
		{
			name: "transaction commit",
			expectCalls: func(
				ctx context.Context,
				request fosite.Requester,
				transactional *internal.MockTransactional,
				store *replayStorageMock,
				failure error,
			) {
				gomock.InOrder(
					transactional.EXPECT().BeginTX(ctx).Return(ctx, nil),
					store.revocation.EXPECT().RevokeAccessToken(ctx, request.GetID()).Return(nil),
					store.revocation.EXPECT().RevokeRefreshToken(ctx, request.GetID()).Return(nil),
					transactional.EXPECT().Commit(ctx).Return(failure),
					transactional.EXPECT().Rollback(ctx).Return(nil),
				)
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			ctx := context.Background()
			request, _ := newAuthorizeCodeReplayRequest(t, ctx)
			failure := errors.New("storage failure")
			ctrl := gomock.NewController(t)
			transactional := internal.NewMockTransactional(ctrl)
			storeMock := newReplayStorageMock(ctrl)
			store := replayTransactionalStorage{replayStorageMock: storeMock, Transactional: transactional}

			storeMock.core.EXPECT().
				GetAuthorizeCodeSession(ctx, gomock.Any(), gomock.Any()).
				Return(request, fosite.ErrInvalidatedAuthorizeCode)
			testCase.expectCalls(ctx, request, transactional, storeMock, failure)

			handler := newReplayAuthorizeCodeHandler(store, store)
			err := handler.HandleTokenEndpointRequest(ctx, request)
			require.ErrorIs(t, err, fosite.ErrServerError)
			require.ErrorIs(t, err, failure)
			require.NotErrorIs(t, err, fosite.ErrTokenReplayCleanupComplete)
		})
	}
}

func TestAuthorizeCodeReplayRequiresCompositeTransactionalStorage(t *testing.T) {
	t.Run("nontransactional storage", func(t *testing.T) {
		ctx := context.Background()
		request, _ := newAuthorizeCodeReplayRequest(t, ctx)
		ctrl := gomock.NewController(t)
		store := newReplayStorageMock(ctrl)
		store.core.EXPECT().
			GetAuthorizeCodeSession(ctx, gomock.Any(), gomock.Any()).
			Return(request, fosite.ErrInvalidatedAuthorizeCode)

		handler := newReplayAuthorizeCodeHandler(store, store)
		err := handler.HandleTokenEndpointRequest(ctx, request)
		require.ErrorIs(t, err, fosite.ErrServerError)
		require.NotErrorIs(t, err, fosite.ErrTokenReplayCleanupComplete)
	})

	t.Run("split transaction owners", func(t *testing.T) {
		ctx := context.Background()
		request, _ := newAuthorizeCodeReplayRequest(t, ctx)
		ctrl := gomock.NewController(t)
		coreTransaction := internal.NewMockTransactional(ctrl)
		core := internal.NewMockCoreStorage(ctrl)
		coreStore := replayTransactionalCoreStore{Transactional: coreTransaction, CoreStorage: core}
		revocationTransaction := internal.NewMockTransactional(ctrl)
		revocation := internal.NewMockTokenRevocationStorage(ctrl)
		revocationStore := replayTransactionalRevocationStore{
			Transactional:          revocationTransaction,
			TokenRevocationStorage: revocation,
		}
		core.EXPECT().
			GetAuthorizeCodeSession(ctx, gomock.Any(), gomock.Any()).
			Return(request, fosite.ErrInvalidatedAuthorizeCode)

		handler := newReplayAuthorizeCodeHandler(coreStore, revocationStore)
		err := handler.HandleTokenEndpointRequest(ctx, request)
		require.ErrorIs(t, err, fosite.ErrServerError)
		require.NotErrorIs(t, err, fosite.ErrTokenReplayCleanupComplete)
	})
}

func TestAuthorizeCodeInvalidationRaceCleanupOutcome(t *testing.T) {
	ctx := context.Background()
	request, _ := newAuthorizeCodeReplayRequest(t, ctx)
	response := fosite.NewAccessResponse()
	ctrl := gomock.NewController(t)
	transactional := internal.NewMockTransactional(ctrl)
	storeMock := newReplayStorageMock(ctrl)
	store := replayTransactionalStorage{replayStorageMock: storeMock, Transactional: transactional}

	gomock.InOrder(
		storeMock.core.EXPECT().
			GetAuthorizeCodeSession(ctx, gomock.Any(), gomock.Any()).
			Return(request, nil),
		transactional.EXPECT().BeginTX(ctx).Return(ctx, nil),
		storeMock.core.EXPECT().InvalidateAuthorizeCodeSession(ctx, gomock.Any()).
			Return(fosite.ErrInvalidatedAuthorizeCode),
		storeMock.revocation.EXPECT().RevokeAccessToken(ctx, request.GetID()).Return(nil),
		storeMock.revocation.EXPECT().RevokeRefreshToken(ctx, request.GetID()).Return(nil),
		transactional.EXPECT().Commit(ctx).Return(nil),
	)

	handler := newReplayAuthorizeCodeHandler(store, store)
	err := handler.PopulateTokenEndpointResponse(ctx, request, response)
	require.ErrorIs(t, err, fosite.ErrInvalidGrant)
	require.ErrorIs(t, err, fosite.ErrInvalidatedAuthorizeCode)
	require.ErrorIs(t, err, fosite.ErrTokenReplayCleanupComplete)
	require.Empty(t, response.GetAccessToken())
}

func TestAuthorizeCodeInvalidationRaceFailure(t *testing.T) {
	testCases := []struct {
		name        string
		rollbackErr bool
		expectCalls func(
			ctx context.Context,
			request fosite.Requester,
			transactional *internal.MockTransactional,
			store *replayStorageMock,
			failure error,
			rollbackFailure error,
		)
	}{
		{
			name: "access token revocation",
			expectCalls: func(ctx context.Context, request fosite.Requester, transactional *internal.MockTransactional, store *replayStorageMock, failure error, _ error) {
				gomock.InOrder(
					store.revocation.EXPECT().RevokeAccessToken(ctx, request.GetID()).Return(failure),
					transactional.EXPECT().Rollback(ctx).Return(nil),
				)
			},
		},
		{
			name: "refresh token revocation",
			expectCalls: func(ctx context.Context, request fosite.Requester, transactional *internal.MockTransactional, store *replayStorageMock, failure error, _ error) {
				gomock.InOrder(
					store.revocation.EXPECT().RevokeAccessToken(ctx, request.GetID()).Return(nil),
					store.revocation.EXPECT().RevokeRefreshToken(ctx, request.GetID()).Return(failure),
					transactional.EXPECT().Rollback(ctx).Return(nil),
				)
			},
		},
		{
			name: "transaction commit",
			expectCalls: func(ctx context.Context, request fosite.Requester, transactional *internal.MockTransactional, store *replayStorageMock, failure error, _ error) {
				gomock.InOrder(
					store.revocation.EXPECT().RevokeAccessToken(ctx, request.GetID()).Return(nil),
					store.revocation.EXPECT().RevokeRefreshToken(ctx, request.GetID()).Return(nil),
					transactional.EXPECT().Commit(ctx).Return(failure),
					transactional.EXPECT().Rollback(ctx).Return(nil),
				)
			},
		},
		{
			name:        "transaction rollback",
			rollbackErr: true,
			expectCalls: func(ctx context.Context, request fosite.Requester, transactional *internal.MockTransactional, store *replayStorageMock, failure error, rollbackFailure error) {
				gomock.InOrder(
					store.revocation.EXPECT().RevokeAccessToken(ctx, request.GetID()).Return(failure),
					transactional.EXPECT().Rollback(ctx).Return(rollbackFailure),
				)
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			ctx := context.Background()
			request, _ := newAuthorizeCodeReplayRequest(t, ctx)
			failure := errors.New("storage failure")
			rollbackFailure := errors.New("rollback failure")
			ctrl := gomock.NewController(t)
			transactional := internal.NewMockTransactional(ctrl)
			storeMock := newReplayStorageMock(ctrl)
			store := replayTransactionalStorage{replayStorageMock: storeMock, Transactional: transactional}

			gomock.InOrder(
				storeMock.core.EXPECT().
					GetAuthorizeCodeSession(ctx, gomock.Any(), gomock.Any()).
					Return(request, nil),
				transactional.EXPECT().BeginTX(ctx).Return(ctx, nil),
				storeMock.core.EXPECT().InvalidateAuthorizeCodeSession(ctx, gomock.Any()).
					Return(fosite.ErrInvalidatedAuthorizeCode),
			)
			testCase.expectCalls(ctx, request, transactional, storeMock, failure, rollbackFailure)

			handler := newReplayAuthorizeCodeHandler(store, store)
			err := handler.PopulateTokenEndpointResponse(ctx, request, fosite.NewAccessResponse())
			require.ErrorIs(t, err, fosite.ErrServerError)
			require.ErrorIs(t, err, failure)
			require.NotErrorIs(t, err, fosite.ErrTokenReplayCleanupComplete)
			if testCase.rollbackErr {
				require.Contains(t, fosite.ErrorToRFC6749Error(err).Debug(), rollbackFailure.Error())
			}
		})
	}
}

func TestAuthorizeCodeInvalidationFailureRollsBack(t *testing.T) {
	ctx := context.Background()
	request, _ := newAuthorizeCodeReplayRequest(t, ctx)
	failure := errors.New("invalidation failure")
	ctrl := gomock.NewController(t)
	transactional := internal.NewMockTransactional(ctrl)
	storeMock := newReplayStorageMock(ctrl)
	store := replayTransactionalStorage{replayStorageMock: storeMock, Transactional: transactional}

	gomock.InOrder(
		storeMock.core.EXPECT().
			GetAuthorizeCodeSession(ctx, gomock.Any(), gomock.Any()).
			Return(request, nil),
		transactional.EXPECT().BeginTX(ctx).Return(ctx, nil),
		storeMock.core.EXPECT().InvalidateAuthorizeCodeSession(ctx, gomock.Any()).Return(failure),
		transactional.EXPECT().Rollback(ctx).Return(nil),
	)

	handler := newReplayAuthorizeCodeHandler(store, store)
	err := handler.PopulateTokenEndpointResponse(ctx, request, fosite.NewAccessResponse())
	require.ErrorIs(t, err, fosite.ErrServerError)
	require.ErrorIs(t, err, failure)
	require.NotErrorIs(t, err, fosite.ErrTokenReplayCleanupComplete)
}

func TestAuthorizeCodeInvalidationRaceRejectsUnsafeStorage(t *testing.T) {
	t.Run("nontransactional storage", func(t *testing.T) {
		ctx := context.Background()
		request, _ := newAuthorizeCodeReplayRequest(t, ctx)
		ctrl := gomock.NewController(t)
		store := newReplayStorageMock(ctrl)
		gomock.InOrder(
			store.core.EXPECT().
				GetAuthorizeCodeSession(ctx, gomock.Any(), gomock.Any()).
				Return(request, nil),
			store.core.EXPECT().InvalidateAuthorizeCodeSession(ctx, gomock.Any()).
				Return(fosite.ErrInvalidatedAuthorizeCode),
		)

		handler := newReplayAuthorizeCodeHandler(store, store)
		err := handler.PopulateTokenEndpointResponse(ctx, request, fosite.NewAccessResponse())
		require.ErrorIs(t, err, fosite.ErrServerError)
		require.NotErrorIs(t, err, fosite.ErrTokenReplayCleanupComplete)
	})

	t.Run("split transaction owners", func(t *testing.T) {
		ctx := context.Background()
		request, _ := newAuthorizeCodeReplayRequest(t, ctx)
		ctrl := gomock.NewController(t)
		coreTransaction := internal.NewMockTransactional(ctrl)
		core := internal.NewMockCoreStorage(ctrl)
		coreStore := replayTransactionalCoreStore{Transactional: coreTransaction, CoreStorage: core}
		revocationTransaction := internal.NewMockTransactional(ctrl)
		revocation := internal.NewMockTokenRevocationStorage(ctrl)
		revocationStore := replayTransactionalRevocationStore{
			Transactional:          revocationTransaction,
			TokenRevocationStorage: revocation,
		}
		gomock.InOrder(
			core.EXPECT().
				GetAuthorizeCodeSession(ctx, gomock.Any(), gomock.Any()).
				Return(request, nil),
			coreTransaction.EXPECT().BeginTX(ctx).Return(ctx, nil),
			core.EXPECT().InvalidateAuthorizeCodeSession(ctx, gomock.Any()).
				Return(fosite.ErrInvalidatedAuthorizeCode),
			coreTransaction.EXPECT().Rollback(ctx).Return(nil),
		)

		handler := newReplayAuthorizeCodeHandler(coreStore, revocationStore)
		err := handler.PopulateTokenEndpointResponse(ctx, request, fosite.NewAccessResponse())
		require.ErrorIs(t, err, fosite.ErrServerError)
		require.NotErrorIs(t, err, fosite.ErrTokenReplayCleanupComplete)
	})
}

func newAuthorizeCodeReplayRequest(t *testing.T, ctx context.Context) (*fosite.AccessRequest, string) {
	t.Helper()

	code, signature, err := hmacshaStrategy.GenerateAuthorizeCode(ctx, nil)
	require.NoError(t, err)
	request := fosite.NewAccessRequest(&fosite.DefaultSession{})
	request.SetID("request-id")
	request.GrantTypes = fosite.Arguments{"authorization_code"}
	request.Client = &fosite.DefaultClient{
		ID:         "client-id",
		GrantTypes: fosite.Arguments{"authorization_code", "refresh_token"},
	}
	request.Form = url.Values{"code": {code}}
	return request, signature
}

func newReplayAuthorizeCodeHandler(core CoreStorage, revocation TokenRevocationStorage) AuthorizeExplicitGrantHandler {
	return AuthorizeExplicitGrantHandler{
		CoreStorage:            core,
		TokenRevocationStorage: revocation,
		AccessTokenStrategy:    hmacshaStrategy,
		RefreshTokenStrategy:   hmacshaStrategy,
		AuthorizeCodeStrategy:  hmacshaStrategy,
		Config: &fosite.Config{
			AccessTokenLifespan:      time.Hour,
			RefreshTokenLifespan:     time.Hour,
			AuthorizeCodeLifespan:    time.Hour,
			ScopeStrategy:            fosite.HierarchicScopeStrategy,
			AudienceMatchingStrategy: fosite.DefaultAudienceMatchingStrategy,
		},
	}
}
