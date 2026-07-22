// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"errors"

	"github.com/atol-sh/fosite"
	"github.com/atol-sh/fosite/storage"
	"github.com/ory/x/errorsx"
)

var errReplayCleanupRequiresTransactionalStorage = errors.New("token replay cleanup requires one transactional storage owner")

type transactionalTokenRevocationStorage interface {
	TokenRevocationStorage
	storage.Transactional
}

func tokenReplayCleanupError(cause error, hint string, debug string) error {
	return errorsx.WithStack(fosite.ErrInvalidGrant.
		WithWrap(errors.Join(cause, fosite.ErrTokenReplayCleanupComplete)).
		WithHint(hint).
		WithDebug(debug))
}

func replayCleanupStorageError() error {
	return errorsx.WithStack(fosite.ErrServerError.
		WithWrap(errReplayCleanupRequiresTransactionalStorage).
		WithDebug(errReplayCleanupRequiresTransactionalStorage.Error()))
}
