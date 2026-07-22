// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/atol-sh/fosite"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

type replayTransactionOwnerKey struct{}
type replayNestedTransactionKey struct{}

type replayTransactionTracker struct {
	mu            sync.Mutex
	open          bool
	nestedBegins  int
	nestedCommits int
	ownerCommits  int
}

func (t *replayTransactionTracker) BeginTX(ctx context.Context) (context.Context, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if owner, ok := ctx.Value(replayTransactionOwnerKey{}).(*replayTransactionTracker); ok && owner == t {
		t.nestedBegins++
		return context.WithValue(ctx, replayNestedTransactionKey{}, true), nil
	}
	if t.open {
		return nil, errors.New("transaction already open")
	}
	t.open = true
	return context.WithValue(ctx, replayTransactionOwnerKey{}, t), nil
}

func (t *replayTransactionTracker) Commit(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if nested, _ := ctx.Value(replayNestedTransactionKey{}).(bool); nested {
		t.nestedCommits++
		return nil
	}
	if owner, _ := ctx.Value(replayTransactionOwnerKey{}).(*replayTransactionTracker); owner != t || !t.open {
		return errors.New("transaction is not open")
	}
	t.open = false
	t.ownerCommits++
	return nil
}

func (t *replayTransactionTracker) Rollback(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if nested, _ := ctx.Value(replayNestedTransactionKey{}).(bool); nested {
		return nil
	}
	if owner, _ := ctx.Value(replayTransactionOwnerKey{}).(*replayTransactionTracker); owner != t || !t.open {
		return errors.New("transaction is not open")
	}
	t.open = false
	return nil
}

func (t *replayTransactionTracker) state() (open bool, nestedBegins int, nestedCommits int, ownerCommits int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.open, t.nestedBegins, t.nestedCommits, t.ownerCommits
}

type replayTrackedStorage struct {
	*replayStorageMock
	*replayTransactionTracker
}

func TestReplayCleanupLeavesOuterTransactionOpen(t *testing.T) {
	t.Run("refresh replay during request handling", func(t *testing.T) {
		ctx := context.Background()
		request := newRefreshReplayRequest()
		ctrl := gomock.NewController(t)
		storeMock := newReplayStorageMock(ctrl)
		tracker := &replayTransactionTracker{}
		store := replayTrackedStorage{replayStorageMock: storeMock, replayTransactionTracker: tracker}
		outerCtx, err := store.BeginTX(ctx)
		require.NoError(t, err)

		storeMock.core.EXPECT().
			GetRefreshTokenSession(outerCtx, gomock.Any(), gomock.Any()).
			Return(request, fosite.ErrInactiveToken)
		storeMock.core.EXPECT().DeleteRefreshTokenSession(gomock.Any(), gomock.Any()).Return(nil)
		storeMock.revocation.EXPECT().RevokeRefreshToken(gomock.Any(), request.GetID()).Return(nil)
		storeMock.revocation.EXPECT().RevokeAccessToken(gomock.Any(), request.GetID()).Return(nil)

		handler := newReplayRefreshTokenHandler(store)
		err = handler.HandleTokenEndpointRequest(outerCtx, request)
		assertReplayCleanupLeavesOuterOpen(t, store, tracker, outerCtx, err)
	})

	t.Run("refresh replay during rotation", func(t *testing.T) {
		ctx := context.Background()
		request := newRefreshReplayRequest()
		ctrl := gomock.NewController(t)
		storeMock := newReplayStorageMock(ctrl)
		tracker := &replayTransactionTracker{}
		store := replayTrackedStorage{replayStorageMock: storeMock, replayTransactionTracker: tracker}
		outerCtx, err := store.BeginTX(ctx)
		require.NoError(t, err)

		storeMock.core.EXPECT().
			RotateRefreshToken(gomock.Any(), request.GetID(), gomock.Any(), gomock.Any()).
			Return(fosite.ErrInactiveToken)
		storeMock.core.EXPECT().DeleteRefreshTokenSession(gomock.Any(), gomock.Any()).Return(nil)
		storeMock.revocation.EXPECT().RevokeRefreshToken(gomock.Any(), request.GetID()).Return(nil)
		storeMock.revocation.EXPECT().RevokeAccessToken(gomock.Any(), request.GetID()).Return(nil)

		handler := newReplayRefreshTokenHandler(store)
		err = handler.PopulateTokenEndpointResponse(outerCtx, request, fosite.NewAccessResponse())
		assertReplayCleanupLeavesOuterOpen(t, store, tracker, outerCtx, err)
	})

	t.Run("authorization code replay during request handling", func(t *testing.T) {
		ctx := context.Background()
		request, _ := newAuthorizeCodeReplayRequest(t, ctx)
		ctrl := gomock.NewController(t)
		storeMock := newReplayStorageMock(ctrl)
		tracker := &replayTransactionTracker{}
		store := replayTrackedStorage{replayStorageMock: storeMock, replayTransactionTracker: tracker}
		outerCtx, err := store.BeginTX(ctx)
		require.NoError(t, err)

		storeMock.core.EXPECT().
			GetAuthorizeCodeSession(outerCtx, gomock.Any(), gomock.Any()).
			Return(request, fosite.ErrInvalidatedAuthorizeCode)
		storeMock.revocation.EXPECT().RevokeAccessToken(gomock.Any(), request.GetID()).Return(nil)
		storeMock.revocation.EXPECT().RevokeRefreshToken(gomock.Any(), request.GetID()).Return(nil)

		handler := newReplayAuthorizeCodeHandler(store, store)
		err = handler.HandleTokenEndpointRequest(outerCtx, request)
		assertReplayCleanupLeavesOuterOpen(t, store, tracker, outerCtx, err)
	})

	t.Run("authorization code replay during invalidation", func(t *testing.T) {
		ctx := context.Background()
		request, _ := newAuthorizeCodeReplayRequest(t, ctx)
		ctrl := gomock.NewController(t)
		storeMock := newReplayStorageMock(ctrl)
		tracker := &replayTransactionTracker{}
		store := replayTrackedStorage{replayStorageMock: storeMock, replayTransactionTracker: tracker}
		outerCtx, err := store.BeginTX(ctx)
		require.NoError(t, err)

		storeMock.core.EXPECT().
			GetAuthorizeCodeSession(outerCtx, gomock.Any(), gomock.Any()).
			Return(request, nil)
		storeMock.core.EXPECT().InvalidateAuthorizeCodeSession(gomock.Any(), gomock.Any()).
			Return(fosite.ErrInvalidatedAuthorizeCode)
		storeMock.revocation.EXPECT().RevokeAccessToken(gomock.Any(), request.GetID()).Return(nil)
		storeMock.revocation.EXPECT().RevokeRefreshToken(gomock.Any(), request.GetID()).Return(nil)

		handler := newReplayAuthorizeCodeHandler(store, store)
		err = handler.PopulateTokenEndpointResponse(outerCtx, request, fosite.NewAccessResponse())
		assertReplayCleanupLeavesOuterOpen(t, store, tracker, outerCtx, err)
	})
}

func assertReplayCleanupLeavesOuterOpen(
	t *testing.T,
	store replayTrackedStorage,
	tracker *replayTransactionTracker,
	outerCtx context.Context,
	err error,
) {
	t.Helper()
	require.ErrorIs(t, err, fosite.ErrInvalidGrant)
	require.ErrorIs(t, err, fosite.ErrTokenReplayCleanupComplete)
	open, nestedBegins, nestedCommits, ownerCommits := tracker.state()
	require.True(t, open)
	require.Equal(t, 1, nestedBegins)
	require.Equal(t, 1, nestedCommits)
	require.Zero(t, ownerCommits)
	require.NoError(t, store.Commit(outerCtx))
	open, _, _, ownerCommits = tracker.state()
	require.False(t, open)
	require.Equal(t, 1, ownerCommits)
}
