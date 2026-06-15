// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

//go:generate go run go.uber.org/mock/mockgen -package rfc8693 -destination storage_mock.go github.com/atol-sh/fosite/handler/rfc8693 RFC8693Storage

package rfc8693
