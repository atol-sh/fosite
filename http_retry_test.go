// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type retryRoundTripper func(*http.Request) (*http.Response, error)

func (roundTrip retryRoundTripper) RoundTrip(
	request *http.Request,
) (*http.Response, error) {
	return roundTrip(request)
}

type trackedReadCloser struct {
	io.Reader
	closed bool
}

func (body *trackedReadCloser) Close() error {
	body.closed = true
	return nil
}

func TestDefaultPooledHTTPClientIsBounded(t *testing.T) {
	client := defaultPooledHTTPClient()
	require.Zero(t, client.Timeout)

	transport, ok := client.Transport.(*http.Transport)
	require.True(t, ok)
	require.Equal(t, 10*time.Second, transport.TLSHandshakeTimeout)
	require.Equal(t, 90*time.Second, transport.IdleConnTimeout)
	require.Equal(t, 1*time.Second, transport.ExpectContinueTimeout)
	require.Equal(t, 100, transport.MaxIdleConns)
	require.Positive(t, transport.MaxIdleConnsPerHost)
	require.True(t, transport.ForceAttemptHTTP2)
}

func TestShouldRetryRequest(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name     string
		response *http.Response
		err      error
		want     bool
	}{
		{
			name:     "too_many_requests",
			response: &http.Response{StatusCode: http.StatusTooManyRequests},
			want:     true,
		},
		{
			name:     "status_zero",
			response: &http.Response{StatusCode: 0},
			want:     true,
		},
		{
			name:     "server_error",
			response: &http.Response{StatusCode: http.StatusBadGateway},
			want:     true,
		},
		{
			name:     "not_implemented",
			response: &http.Response{StatusCode: http.StatusNotImplemented},
			want:     false,
		},
		{
			name:     "client_error",
			response: &http.Response{StatusCode: http.StatusBadRequest},
			want:     false,
		},
		{
			name: "transient_error",
			err:  errors.New("connection reset"),
			want: true,
		},
		{
			name: "canceled",
			err:  context.Canceled,
			want: false,
		},
		{
			name: "deadline",
			err:  context.DeadlineExceeded,
			want: false,
		},
		{
			name: "unsupported",
			err:  http.ErrNotSupported,
			want: false,
		},
		{
			name: "certificate",
			err: &url.Error{
				Err: x509.UnknownAuthorityError{},
			},
			want: false,
		},
		{
			name: "redirect_exhaustion",
			err: &url.Error{
				Err: errors.New("stopped after 10 redirects"),
			},
			want: false,
		},
		{
			name: "invalid_header",
			err: &url.Error{
				Err: errors.New("net/http: invalid header field value"),
			},
			want: false,
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(
				t,
				test.want,
				shouldRetryRequest(test.response, test.err),
			)
		})
	}
}

func TestRetryDelay(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.July, 29, 12, 0, 0, 0, time.UTC)
	require.Equal(t, time.Second, retryDelay(0, nil, now))
	require.Equal(t, 2*time.Second, retryDelay(1, nil, now))
	require.Equal(t, 30*time.Second, retryDelay(10, nil, now))

	tooMany := &http.Response{
		StatusCode: http.StatusTooManyRequests,
		Header:     http.Header{"Retry-After": []string{"7"}},
	}
	require.Equal(t, 7*time.Second, retryDelay(0, tooMany, now))

	serviceUnavailable := &http.Response{
		StatusCode: http.StatusServiceUnavailable,
		Header: http.Header{
			"Retry-After": []string{
				now.Add(90 * time.Second).Format(http.TimeFormat),
			},
		},
	}
	require.Equal(
		t,
		defaultHTTPRetryWaitMax,
		retryDelay(0, serviceUnavailable, now),
	)
}

func TestRetryDelayFallsBackForExpiredHTTPDate(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.July, 29, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name       string
		attempt    int
		retryAfter string
		want       time.Duration
	}{
		{
			name:       "stale_date",
			attempt:    0,
			retryAfter: now.Add(-time.Second).Format(http.TimeFormat),
			want:       time.Second,
		},
		{
			name:       "equal_date",
			attempt:    1,
			retryAfter: now.Format(http.TimeFormat),
			want:       2 * time.Second,
		},
		{
			name:       "explicit_numeric_zero",
			attempt:    2,
			retryAfter: "0",
			want:       0,
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			response := &http.Response{
				StatusCode: http.StatusServiceUnavailable,
				Header: http.Header{
					"Retry-After": []string{test.retryAfter},
				},
			}
			require.Equal(
				t,
				test.want,
				retryDelay(test.attempt, response, now),
			)
		})
	}
}

func TestDoRetryableRequestRetriesAndClosesIntermediateResponses(t *testing.T) {
	t.Parallel()

	firstBody := &trackedReadCloser{Reader: strings.NewReader("retry one")}
	secondBody := &trackedReadCloser{Reader: strings.NewReader("retry two")}
	finalBody := &trackedReadCloser{Reader: strings.NewReader("success")}
	attempt := 0
	client := &http.Client{
		Transport: retryRoundTripper(func(*http.Request) (*http.Response, error) {
			attempt++
			switch attempt {
			case 1:
				return &http.Response{
					StatusCode: http.StatusServiceUnavailable,
					Header: http.Header{
						"Retry-After": []string{"2"},
					},
					Body: firstBody,
				}, nil
			case 2:
				return &http.Response{
					StatusCode: http.StatusBadGateway,
					Header:     make(http.Header),
					Body:       secondBody,
				}, nil
			default:
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body:       finalBody,
				}, nil
			}
		}),
	}
	request, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		"https://issuer.example.test/jwks",
		nil,
	)
	require.NoError(t, err)

	var delays []time.Duration
	response, err := doRetryableRequestWithSleeper(
		client,
		request,
		func(_ context.Context, delay time.Duration) error {
			delays = append(delays, delay)
			return nil
		},
	)
	require.NoError(t, err)
	t.Cleanup(func() { response.Body.Close() })
	require.Equal(t, http.StatusOK, response.StatusCode)
	require.Equal(t, []time.Duration{2 * time.Second, 2 * time.Second}, delays)
	require.True(t, firstBody.closed)
	require.True(t, secondBody.closed)
	require.False(t, finalBody.closed)
}

func TestDoRetryableRequestExhaustsClosed(t *testing.T) {
	t.Parallel()

	var bodies []*trackedReadCloser
	client := &http.Client{
		Transport: retryRoundTripper(func(*http.Request) (*http.Response, error) {
			body := &trackedReadCloser{Reader: strings.NewReader("unavailable")}
			bodies = append(bodies, body)
			return &http.Response{
				StatusCode: http.StatusServiceUnavailable,
				Header:     make(http.Header),
				Body:       body,
			}, nil
		}),
	}
	request, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		"https://issuer.example.test/jwks",
		nil,
	)
	require.NoError(t, err)

	response, err := doRetryableRequestWithSleeper(
		client,
		request,
		func(context.Context, time.Duration) error { return nil },
	)
	require.Nil(t, response)
	require.ErrorIs(t, err, errHTTPRetryExhausted)
	require.Len(t, bodies, defaultHTTPRetryMax+1)
	for _, body := range bodies {
		require.True(t, body.closed)
	}
}

func TestDoRetryableRequestStopsWhenSleepIsCanceled(t *testing.T) {
	t.Parallel()

	body := &trackedReadCloser{Reader: strings.NewReader("unavailable")}
	client := &http.Client{
		Transport: retryRoundTripper(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusBadGateway,
				Header:     make(http.Header),
				Body:       body,
			}, nil
		}),
	}
	request, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		"https://issuer.example.test/jwks",
		nil,
	)
	require.NoError(t, err)

	response, err := doRetryableRequestWithSleeper(
		client,
		request,
		func(context.Context, time.Duration) error {
			return context.Canceled
		},
	)
	require.Nil(t, response)
	require.ErrorIs(t, err, context.Canceled)
	require.True(t, body.closed)
}

func TestDoRetryableRequestRejectsNonGET(t *testing.T) {
	t.Parallel()

	request, err := http.NewRequest(
		http.MethodPost,
		"https://issuer.example.test/jwks",
		strings.NewReader("body"),
	)
	require.NoError(t, err)
	response, err := doRetryableRequest(&http.Client{}, request)
	require.Nil(t, response)
	require.ErrorIs(t, err, errHTTPRetryMethod)
}

func TestDoRetryableRequestPreservesCallerTimeout(t *testing.T) {
	t.Parallel()

	caller := &http.Client{
		Timeout: 2 * time.Minute,
		Transport: retryRoundTripper(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("ok")),
			}, nil
		}),
	}
	request, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		"https://issuer.example.test/jwks",
		nil,
	)
	require.NoError(t, err)

	response, err := doRetryableRequest(caller, request)
	require.NoError(t, err)
	t.Cleanup(func() { response.Body.Close() })
	require.Equal(t, 2*time.Minute, caller.Timeout)
}
