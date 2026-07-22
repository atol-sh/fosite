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

type replayTransactionalRevocationStore struct {
	storage.Transactional
	TokenRevocationStorage
}

func TestRefreshTokenReplayCleanupRevokesFamilyWithoutDeletingInactiveSession(t *testing.T) {
	ctx := context.Background()
	request := newRefreshReplayRequest()

	ctrl := gomock.NewController(t)
	transactional := internal.NewMockTransactional(ctrl)
	revocation := internal.NewMockTokenRevocationStorage(ctrl)
	store := replayTransactionalRevocationStore{
		Transactional:          transactional,
		TokenRevocationStorage: revocation,
	}

	gomock.InOrder(
		revocation.EXPECT().
			GetRefreshTokenSession(ctx, gomock.Any(), gomock.Any()).
			Return(request, fosite.ErrInactiveToken),
		transactional.EXPECT().BeginTX(ctx).Return(ctx, nil),
		revocation.EXPECT().RevokeRefreshToken(ctx, request.GetID()).Return(nil),
		revocation.EXPECT().RevokeAccessToken(ctx, request.GetID()).Return(nil),
		transactional.EXPECT().Commit(ctx).Return(nil),
	)

	handler := newReplayRefreshTokenHandler(store)
	err := handler.HandleTokenEndpointRequest(ctx, request)
	require.ErrorIs(t, err, fosite.ErrInvalidGrant)
	require.ErrorIs(t, err, fosite.ErrInactiveToken)
	require.ErrorIs(t, err, fosite.ErrTokenReplayCleanupComplete)
}

func TestRefreshTokenReplayRequiresTransactionalStorage(t *testing.T) {
	testCases := []struct {
		name     string
		exchange func(RefreshTokenGrantHandler, context.Context, *fosite.AccessRequest) error
		setup    func(*internal.MockTokenRevocationStorage, context.Context, *fosite.AccessRequest)
	}{
		{
			name: "read-time replay",
			exchange: func(handler RefreshTokenGrantHandler, ctx context.Context, request *fosite.AccessRequest) error {
				return handler.HandleTokenEndpointRequest(ctx, request)
			},
			setup: func(revocation *internal.MockTokenRevocationStorage, ctx context.Context, request *fosite.AccessRequest) {
				revocation.EXPECT().
					GetRefreshTokenSession(ctx, gomock.Any(), gomock.Any()).
					Return(request, fosite.ErrInactiveToken)
			},
		},
		{
			name: "rotation-time replay",
			exchange: func(handler RefreshTokenGrantHandler, ctx context.Context, request *fosite.AccessRequest) error {
				return handler.PopulateTokenEndpointResponse(ctx, request, fosite.NewAccessResponse())
			},
			setup: func(revocation *internal.MockTokenRevocationStorage, ctx context.Context, request *fosite.AccessRequest) {
				revocation.EXPECT().
					RotateRefreshToken(ctx, request.GetID(), gomock.Any(), gomock.Any()).
					Return(fosite.ErrInactiveToken)
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			ctx := context.Background()
			request := newRefreshReplayRequest()
			ctrl := gomock.NewController(t)
			revocation := internal.NewMockTokenRevocationStorage(ctrl)
			testCase.setup(revocation, ctx, request)

			handler := newReplayRefreshTokenHandler(revocation)
			err := testCase.exchange(handler, ctx, request)
			require.ErrorIs(t, err, fosite.ErrServerError)
			require.NotErrorIs(t, err, fosite.ErrTokenReplayCleanupComplete)
		})
	}
}

func TestRefreshTokenRotationRaceCleanupRevokesFamilyWithoutDeletingInactiveSession(t *testing.T) {
	ctx := context.Background()
	request := newRefreshReplayRequest()
	response := fosite.NewAccessResponse()

	ctrl := gomock.NewController(t)
	transactional := internal.NewMockTransactional(ctrl)
	revocation := internal.NewMockTokenRevocationStorage(ctrl)
	store := replayTransactionalRevocationStore{
		Transactional:          transactional,
		TokenRevocationStorage: revocation,
	}

	gomock.InOrder(
		transactional.EXPECT().BeginTX(ctx).Return(ctx, nil),
		revocation.EXPECT().
			RotateRefreshToken(ctx, request.GetID(), gomock.Any(), gomock.Any()).
			Return(fosite.ErrInactiveToken),
		revocation.EXPECT().RevokeRefreshToken(ctx, request.GetID()).Return(nil),
		revocation.EXPECT().RevokeAccessToken(ctx, request.GetID()).Return(nil),
		transactional.EXPECT().Commit(ctx).Return(nil),
	)

	handler := newReplayRefreshTokenHandler(store)
	err := handler.PopulateTokenEndpointResponse(ctx, request, response)
	require.ErrorIs(t, err, fosite.ErrInvalidGrant)
	require.ErrorIs(t, err, fosite.ErrInactiveToken)
	require.ErrorIs(t, err, fosite.ErrTokenReplayCleanupComplete)
	require.Empty(t, response.GetAccessToken())
}

func TestRefreshTokenRotationSerializationFailureIsNotReplayCleanup(t *testing.T) {
	ctx := context.Background()
	request := newRefreshReplayRequest()

	ctrl := gomock.NewController(t)
	transactional := internal.NewMockTransactional(ctrl)
	revocation := internal.NewMockTokenRevocationStorage(ctrl)
	store := replayTransactionalRevocationStore{
		Transactional:          transactional,
		TokenRevocationStorage: revocation,
	}

	gomock.InOrder(
		transactional.EXPECT().BeginTX(ctx).Return(ctx, nil),
		revocation.EXPECT().
			RotateRefreshToken(ctx, request.GetID(), gomock.Any(), gomock.Any()).
			Return(fosite.ErrSerializationFailure),
		transactional.EXPECT().Rollback(ctx).Return(nil),
	)

	handler := newReplayRefreshTokenHandler(store)
	err := handler.PopulateTokenEndpointResponse(ctx, request, fosite.NewAccessResponse())
	require.ErrorIs(t, err, fosite.ErrInvalidRequest)
	require.ErrorIs(t, err, fosite.ErrSerializationFailure)
	require.NotErrorIs(t, err, fosite.ErrTokenReplayCleanupComplete)
}

func TestRefreshTokenReplayCleanupFailure(t *testing.T) {
	testCases := []struct {
		name        string
		expectCalls func(
			ctx context.Context,
			request fosite.Requester,
			transactional *internal.MockTransactional,
			revocation *internal.MockTokenRevocationStorage,
			failure error,
		)
	}{
		{
			name: "refresh token revocation",
			expectCalls: func(
				ctx context.Context,
				request fosite.Requester,
				transactional *internal.MockTransactional,
				revocation *internal.MockTokenRevocationStorage,
				failure error,
			) {
				gomock.InOrder(
					transactional.EXPECT().BeginTX(ctx).Return(ctx, nil),
					revocation.EXPECT().RevokeRefreshToken(ctx, request.GetID()).Return(failure),
					transactional.EXPECT().Rollback(ctx).Return(nil),
				)
			},
		},
		{
			name: "access token revocation",
			expectCalls: func(
				ctx context.Context,
				request fosite.Requester,
				transactional *internal.MockTransactional,
				revocation *internal.MockTokenRevocationStorage,
				failure error,
			) {
				gomock.InOrder(
					transactional.EXPECT().BeginTX(ctx).Return(ctx, nil),
					revocation.EXPECT().RevokeRefreshToken(ctx, request.GetID()).Return(nil),
					revocation.EXPECT().RevokeAccessToken(ctx, request.GetID()).Return(failure),
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
				revocation *internal.MockTokenRevocationStorage,
				failure error,
			) {
				gomock.InOrder(
					transactional.EXPECT().BeginTX(ctx).Return(ctx, nil),
					revocation.EXPECT().RevokeRefreshToken(ctx, request.GetID()).Return(nil),
					revocation.EXPECT().RevokeAccessToken(ctx, request.GetID()).Return(nil),
					transactional.EXPECT().Commit(ctx).Return(failure),
					transactional.EXPECT().Rollback(ctx).Return(nil),
				)
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			ctx := context.Background()
			request := newRefreshReplayRequest()
			failure := errors.New("storage failure")

			ctrl := gomock.NewController(t)
			transactional := internal.NewMockTransactional(ctrl)
			revocation := internal.NewMockTokenRevocationStorage(ctrl)
			store := replayTransactionalRevocationStore{
				Transactional:          transactional,
				TokenRevocationStorage: revocation,
			}

			revocation.EXPECT().
				GetRefreshTokenSession(ctx, gomock.Any(), gomock.Any()).
				Return(request, fosite.ErrInactiveToken)
			testCase.expectCalls(ctx, request, transactional, revocation, failure)

			handler := newReplayRefreshTokenHandler(store)
			err := handler.HandleTokenEndpointRequest(ctx, request)
			require.ErrorIs(t, err, fosite.ErrServerError)
			require.ErrorIs(t, err, failure)
			require.NotErrorIs(t, err, fosite.ErrTokenReplayCleanupComplete)
		})
	}
}

func TestRefreshTokenRotationRaceCleanupFailure(t *testing.T) {
	ctx := context.Background()
	request := newRefreshReplayRequest()
	failure := errors.New("storage failure")

	ctrl := gomock.NewController(t)
	transactional := internal.NewMockTransactional(ctrl)
	revocation := internal.NewMockTokenRevocationStorage(ctrl)
	store := replayTransactionalRevocationStore{
		Transactional:          transactional,
		TokenRevocationStorage: revocation,
	}

	gomock.InOrder(
		transactional.EXPECT().BeginTX(ctx).Return(ctx, nil),
		revocation.EXPECT().
			RotateRefreshToken(ctx, request.GetID(), gomock.Any(), gomock.Any()).
			Return(fosite.ErrInactiveToken),
		revocation.EXPECT().RevokeRefreshToken(ctx, request.GetID()).Return(failure),
		transactional.EXPECT().Rollback(ctx).Return(nil),
	)

	handler := newReplayRefreshTokenHandler(store)
	err := handler.PopulateTokenEndpointResponse(ctx, request, fosite.NewAccessResponse())
	require.ErrorIs(t, err, fosite.ErrServerError)
	require.ErrorIs(t, err, failure)
	require.NotErrorIs(t, err, fosite.ErrTokenReplayCleanupComplete)
}

func newRefreshReplayRequest() *fosite.AccessRequest {
	request := fosite.NewAccessRequest(&fosite.DefaultSession{})
	request.SetID("request-id")
	request.GrantTypes = fosite.Arguments{"refresh_token"}
	request.Client = &fosite.DefaultClient{
		ID:         "client-id",
		GrantTypes: fosite.Arguments{"refresh_token"},
	}
	request.Form = url.Values{"refresh_token": {"refresh.token"}}
	return request
}

func newReplayRefreshTokenHandler(store TokenRevocationStorage) RefreshTokenGrantHandler {
	return RefreshTokenGrantHandler{
		TokenRevocationStorage: store,
		AccessTokenStrategy:    hmacshaStrategy,
		RefreshTokenStrategy:   hmacshaStrategy,
		Config: &fosite.Config{
			AccessTokenLifespan:      time.Hour,
			RefreshTokenLifespan:     time.Hour,
			ScopeStrategy:            fosite.HierarchicScopeStrategy,
			AudienceMatchingStrategy: fosite.DefaultAudienceMatchingStrategy,
		},
	}
}
