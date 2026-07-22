// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"fmt"
	"time"

	"github.com/ory/x/errorsx"

	"github.com/atol-sh/fosite/storage"

	"github.com/pkg/errors"

	"github.com/atol-sh/fosite"
)

// HandleTokenEndpointRequest implements
// * https://tools.ietf.org/html/rfc6749#section-4.1.3 (everything)
func (c *AuthorizeExplicitGrantHandler) HandleTokenEndpointRequest(ctx context.Context, request fosite.AccessRequester) error {
	if !c.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(errorsx.WithStack(fosite.ErrUnknownRequest))
	}

	if !request.GetClient().GetGrantTypes().Has("authorization_code") {
		return errorsx.WithStack(fosite.ErrUnauthorizedClient.WithHint("The OAuth 2.0 Client is not allowed to use authorization grant \"authorization_code\"."))
	}

	code := request.GetRequestForm().Get("code")
	signature := c.AuthorizeCodeStrategy.AuthorizeCodeSignature(ctx, code)
	authorizeRequest, err := c.CoreStorage.GetAuthorizeCodeSession(ctx, signature, request.GetSession())
	if errors.Is(err, fosite.ErrInvalidatedAuthorizeCode) {
		if authorizeRequest == nil {
			return fosite.ErrServerError.
				WithHint("Misconfigured code lead to an error that prohibited the OAuth 2.0 Framework from processing this request.").
				WithDebug("GetAuthorizeCodeSession must return a value for \"fosite.Requester\" when returning \"ErrInvalidatedAuthorizeCode\".")
		}

		// If an authorize code is used twice, we revoke all refresh and access tokens associated with this request.
		replayStore, ok := c.CoreStorage.(AuthorizeCodeReplayStorage)
		if !ok {
			return replayCleanupStorageError()
		}
		return c.handleAuthorizeCodeReplay(ctx, replayStore, authorizeRequest, err)
	} else if err != nil && errors.Is(err, fosite.ErrNotFound) {
		return errorsx.WithStack(fosite.ErrInvalidGrant.WithWrap(err).WithDebug(err.Error()))
	} else if err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	// The authorization server MUST verify that the authorization code is valid
	// This needs to happen after store retrieval for the session to be hydrated properly
	if err := c.AuthorizeCodeStrategy.ValidateAuthorizeCode(ctx, request, code); err != nil {
		return errorsx.WithStack(fosite.ErrInvalidGrant.WithWrap(err).WithDebug(err.Error()))
	}

	// Override scopes
	request.SetRequestedScopes(authorizeRequest.GetRequestedScopes())

	// Override audiences
	request.SetRequestedAudience(authorizeRequest.GetRequestedAudience())

	// The authorization server MUST ensure that the authorization code was issued to the authenticated
	// confidential client, or if the client is public, ensure that the
	// code was issued to "client_id" in the request,
	if authorizeRequest.GetClient().GetID() != request.GetClient().GetID() {
		return errorsx.WithStack(fosite.ErrInvalidGrant.WithHint("The OAuth 2.0 Client ID from this request does not match the one from the authorize request."))
	}

	// ensure that the "redirect_uri" parameter is present if the
	// "redirect_uri" parameter was included in the initial authorization
	// request as described in Section 4.1.1, and if included ensure that
	// their values are identical.
	forcedRedirectURI := authorizeRequest.GetRequestForm().Get("redirect_uri")
	if forcedRedirectURI != "" && forcedRedirectURI != request.GetRequestForm().Get("redirect_uri") {
		return errorsx.WithStack(fosite.ErrInvalidGrant.WithHint("The \"redirect_uri\" from this request does not match the one from the authorize request."))
	}

	// Checking of POST client_id skipped, because:
	// If the client type is confidential or the client was issued client
	// credentials (or assigned other authentication requirements), the
	// client MUST authenticate with the authorization server as described
	// in Section 3.2.1.
	request.SetSession(authorizeRequest.GetSession())
	request.SetID(authorizeRequest.GetID())

	atLifespan := fosite.GetEffectiveLifespan(request.GetClient(), fosite.GrantTypeAuthorizationCode, fosite.AccessToken, c.Config.GetAccessTokenLifespan(ctx))
	request.GetSession().SetExpiresAt(fosite.AccessToken, time.Now().UTC().Add(atLifespan).Round(time.Second))

	rtLifespan := fosite.GetEffectiveLifespan(request.GetClient(), fosite.GrantTypeAuthorizationCode, fosite.RefreshToken, c.Config.GetRefreshTokenLifespan(ctx))
	if rtLifespan > -1 {
		request.GetSession().SetExpiresAt(fosite.RefreshToken, time.Now().UTC().Add(rtLifespan).Round(time.Second))
	}

	return nil
}

func (c *AuthorizeExplicitGrantHandler) handleAuthorizeCodeReplay(
	ctx context.Context,
	store AuthorizeCodeReplayStorage,
	request fosite.Requester,
	replayErr error,
) (err error) {
	ctx, err = store.BeginTX(ctx)
	if err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	if err = c.revokeAuthorizeCodeFamily(ctx, store, request.GetID()); err != nil {
		return handleAuthorizeCodeReplayStorageError(ctx, store, err)
	}
	if err = store.Commit(ctx); err != nil {
		return handleAuthorizeCodeReplayStorageError(ctx, store, err)
	}

	return tokenReplayCleanupError(
		replayErr,
		"The authorization code has already been used.",
		"Authorization code replay was detected. All related tokens have been revoked.",
	)
}

func (c *AuthorizeExplicitGrantHandler) revokeAuthorizeCodeFamily(
	ctx context.Context,
	store TokenRevocationStorage,
	requestID string,
) error {
	if err := store.RevokeAccessToken(ctx, requestID); !authorizeCodeTokenAlreadyCleaned(err) {
		return fmt.Errorf("revoke access token family: %w", err)
	}
	if err := store.RevokeRefreshToken(ctx, requestID); !authorizeCodeTokenAlreadyCleaned(err) {
		return fmt.Errorf("revoke refresh token family: %w", err)
	}
	return nil
}

func authorizeCodeTokenAlreadyCleaned(err error) bool {
	return err == nil || errors.Is(err, fosite.ErrNotFound) || errors.Is(err, fosite.ErrInactiveToken)
}

func handleAuthorizeCodeReplayStorageError(ctx context.Context, store storage.Transactional, storageErr error) (err error) {
	err = errorsx.WithStack(fosite.ErrServerError.WithWrap(storageErr).WithDebug(storageErr.Error()))
	if rollbackErr := store.Rollback(ctx); rollbackErr != nil {
		err = errorsx.WithStack(fosite.ErrServerError.
			WithWrap(err).
			WithDebugf("error: %s; rollback error: %s", err, rollbackErr))
	}
	return err
}

func canIssueRefreshToken(ctx context.Context, c *AuthorizeExplicitGrantHandler, request fosite.Requester) bool {
	scope := c.Config.GetRefreshTokenScopes(ctx)
	// Require one of the refresh token scopes, if set.
	if len(scope) > 0 && !request.GetGrantedScopes().HasOneOf(scope...) {
		return false
	}
	// Do not issue a refresh token to clients that cannot use the refresh token grant type.
	if !request.GetClient().GetGrantTypes().Has("refresh_token") {
		return false
	}
	return true
}

func (c *AuthorizeExplicitGrantHandler) PopulateTokenEndpointResponse(ctx context.Context, requester fosite.AccessRequester, responder fosite.AccessResponder) (err error) {
	if !c.CanHandleTokenEndpointRequest(ctx, requester) {
		return errorsx.WithStack(fosite.ErrUnknownRequest)
	}

	code := requester.GetRequestForm().Get("code")
	signature := c.AuthorizeCodeStrategy.AuthorizeCodeSignature(ctx, code)
	authorizeRequest, err := c.CoreStorage.GetAuthorizeCodeSession(ctx, signature, requester.GetSession())
	if err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	} else if err := c.AuthorizeCodeStrategy.ValidateAuthorizeCode(ctx, requester, code); err != nil {
		// This needs to happen after store retrieval for the session to be hydrated properly
		return errorsx.WithStack(fosite.ErrInvalidRequest.WithWrap(err).WithDebug(err.Error()))
	}

	for _, scope := range authorizeRequest.GetGrantedScopes() {
		requester.GrantScope(scope)
	}

	for _, audience := range authorizeRequest.GetGrantedAudience() {
		requester.GrantAudience(audience)
	}

	access, accessSignature, err := c.AccessTokenStrategy.GenerateAccessToken(ctx, requester)
	if err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	var refresh, refreshSignature string
	if canIssueRefreshToken(ctx, c, authorizeRequest) {
		refresh, refreshSignature, err = c.RefreshTokenStrategy.GenerateRefreshToken(ctx, requester)
		if err != nil {
			return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
		}
	}

	ctx, err = storage.MaybeBeginTx(ctx, c.CoreStorage)
	if err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}
	transactionDone := false
	defer func() {
		if err != nil && !transactionDone {
			if rollBackTxnErr := storage.MaybeRollbackTx(ctx, c.CoreStorage); rollBackTxnErr != nil {
				err = errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebugf("error: %s; rollback error: %s", err, rollBackTxnErr))
			}
		}
	}()

	if err = c.CoreStorage.InvalidateAuthorizeCodeSession(ctx, signature); errors.Is(err, fosite.ErrInvalidatedAuthorizeCode) {
		// Another concurrent request already exchanged this code. Per RFC 6749
		// Section 4.1.2, revoke the related token family and deny the duplicate exchange.
		replayErr := err
		replayStore, ok := c.CoreStorage.(AuthorizeCodeReplayStorage)
		if !ok {
			err = replayCleanupStorageError()
			return err
		}
		if err = c.revokeAuthorizeCodeFamily(ctx, replayStore, requester.GetID()); err != nil {
			return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
		}
		if err = replayStore.Commit(ctx); err != nil {
			return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
		}
		transactionDone = true
		return tokenReplayCleanupError(
			replayErr,
			"The authorization code has already been used.",
			"Authorization code replay was detected during exchange. All related tokens have been revoked.",
		)
	} else if err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	} else if err = c.CoreStorage.CreateAccessTokenSession(ctx, accessSignature, requester.Sanitize([]string{})); err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	} else if refreshSignature != "" {
		if err = c.CoreStorage.CreateRefreshTokenSession(ctx, refreshSignature, accessSignature, requester.Sanitize([]string{})); err != nil {
			return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
		}
	}

	responder.SetAccessToken(access)
	responder.SetTokenType("bearer")
	atLifespan := fosite.GetEffectiveLifespan(requester.GetClient(), fosite.GrantTypeAuthorizationCode, fosite.AccessToken, c.Config.GetAccessTokenLifespan(ctx))
	responder.SetExpiresIn(getExpiresIn(requester, fosite.AccessToken, atLifespan, time.Now().UTC()))
	responder.SetScopes(requester.GetGrantedScopes())
	if refresh != "" {
		responder.SetExtra("refresh_token", refresh)
	}

	if err = storage.MaybeCommitTx(ctx, c.CoreStorage); err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}
	transactionDone = true

	return nil
}

func (c *AuthorizeExplicitGrantHandler) CanSkipClientAuth(ctx context.Context, requester fosite.AccessRequester) bool {
	return false
}

func (c *AuthorizeExplicitGrantHandler) CanHandleTokenEndpointRequest(ctx context.Context, requester fosite.AccessRequester) bool {
	// grant_type REQUIRED.
	// Value MUST be set to "authorization_code"
	return requester.GetGrantTypes().ExactOne("authorization_code")
}
