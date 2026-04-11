// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite

// IDTokenSigningAlgClient is an optional interface that clients can implement
// to specify their preferred ID token signing algorithm. When a client
// implements this interface, the OpenID Connect token strategy uses the
// returned algorithm instead of the server-wide default.
type IDTokenSigningAlgClient interface {
	// GetIDTokenSigningAlg returns the JWS algorithm (e.g. "RS256", "ES256")
	// that should be used when signing ID tokens for this client. An empty
	// string means "use the server default".
	GetIDTokenSigningAlg() string
}
