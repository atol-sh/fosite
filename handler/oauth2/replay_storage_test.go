// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"time"

	"github.com/atol-sh/fosite"
	"github.com/atol-sh/fosite/internal"
	"go.uber.org/mock/gomock"
)

type replayStorageMock struct {
	core       *internal.MockCoreStorage
	revocation *internal.MockTokenRevocationStorage
}

func newReplayStorageMock(ctrl *gomock.Controller) *replayStorageMock {
	return &replayStorageMock{
		core:       internal.NewMockCoreStorage(ctrl),
		revocation: internal.NewMockTokenRevocationStorage(ctrl),
	}
}

func (s *replayStorageMock) CreateAuthorizeCodeSession(ctx context.Context, code string, request fosite.Requester) error {
	return s.core.CreateAuthorizeCodeSession(ctx, code, request)
}

func (s *replayStorageMock) GetAuthorizeCodeSession(ctx context.Context, code string, session fosite.Session) (fosite.Requester, error) {
	return s.core.GetAuthorizeCodeSession(ctx, code, session)
}

func (s *replayStorageMock) InvalidateAuthorizeCodeSession(ctx context.Context, code string) error {
	return s.core.InvalidateAuthorizeCodeSession(ctx, code)
}

func (s *replayStorageMock) CreateAccessTokenSession(ctx context.Context, signature string, request fosite.Requester) error {
	return s.core.CreateAccessTokenSession(ctx, signature, request)
}

func (s *replayStorageMock) GetAccessTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	return s.core.GetAccessTokenSession(ctx, signature, session)
}

func (s *replayStorageMock) DeleteAccessTokenSession(ctx context.Context, signature string) error {
	return s.core.DeleteAccessTokenSession(ctx, signature)
}

func (s *replayStorageMock) CreateRefreshTokenSession(
	ctx context.Context,
	signature string,
	accessSignature string,
	request fosite.Requester,
) error {
	return s.core.CreateRefreshTokenSession(ctx, signature, accessSignature, request)
}

func (s *replayStorageMock) GetRefreshTokenSession(
	ctx context.Context,
	signature string,
	session fosite.Session,
) (fosite.Requester, error) {
	return s.core.GetRefreshTokenSession(ctx, signature, session)
}

func (s *replayStorageMock) DeleteRefreshTokenSession(ctx context.Context, signature string) error {
	return s.core.DeleteRefreshTokenSession(ctx, signature)
}

func (s *replayStorageMock) RotateRefreshToken(
	ctx context.Context,
	requestID string,
	refreshTokenSignature string,
	nextExpiry time.Time,
) error {
	return s.core.RotateRefreshToken(ctx, requestID, refreshTokenSignature, nextExpiry)
}

func (s *replayStorageMock) RevokeRefreshToken(ctx context.Context, requestID string) error {
	return s.revocation.RevokeRefreshToken(ctx, requestID)
}

func (s *replayStorageMock) RevokeAccessToken(ctx context.Context, requestID string) error {
	return s.revocation.RevokeAccessToken(ctx, requestID)
}
