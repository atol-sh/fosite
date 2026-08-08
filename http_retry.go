// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	defaultHTTPRetryWaitMin = 1 * time.Second
	defaultHTTPRetryWaitMax = 30 * time.Second
	defaultHTTPRetryMax     = 4
	defaultHTTPReadDrainMax = 4096
)

var (
	errHTTPRetryExhausted = errors.New("HTTP GET retry budget exhausted")
	errHTTPRetryMethod    = errors.New("retry policy only supports bodyless GET requests")
	errHTTPNilResponse    = errors.New("HTTP client returned a nil response without an error")
)

type httpRetrySleeper func(context.Context, time.Duration) error

func sleepForHTTPRetry(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func defaultPooledHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
				DualStack: true,
			}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			ForceAttemptHTTP2:     true,
			MaxIdleConnsPerHost:   runtime.GOMAXPROCS(0) + 1,
		},
	}
}

func doRetryableRequest(client *http.Client, request *http.Request) (*http.Response, error) {
	return doRetryableRequestWithSleeper(client, request, sleepForHTTPRetry)
}

func doRetryableRequestWithSleeper(
	client *http.Client,
	request *http.Request,
	sleep httpRetrySleeper,
) (*http.Response, error) {
	if request == nil || request.Method != http.MethodGet ||
		(request.Body != nil && request.Body != http.NoBody) {
		return nil, errHTTPRetryMethod
	}
	if sleep == nil {
		return nil, errors.New("HTTP retry sleeper is required")
	}
	if client == nil {
		client = defaultPooledHTTPClient()
	}

	for attempt := 0; attempt <= defaultHTTPRetryMax; attempt++ {
		attemptRequest := request.Clone(request.Context())
		response, err := client.Do(attemptRequest)
		if ctxErr := request.Context().Err(); ctxErr != nil {
			drainAndCloseResponse(response)
			return nil, ctxErr
		}

		if !shouldRetryRequest(response, err) {
			if err != nil {
				drainAndCloseResponse(response)
				return nil, err
			}
			if response == nil {
				return nil, errHTTPNilResponse
			}
			return response, nil
		}

		drainAndCloseResponse(response)
		if attempt == defaultHTTPRetryMax {
			if err != nil {
				return nil, fmt.Errorf(
					"%w after %d attempts: %w",
					errHTTPRetryExhausted,
					attempt+1,
					err,
				)
			}
			return nil, fmt.Errorf(
				"%w after %d attempts",
				errHTTPRetryExhausted,
				attempt+1,
			)
		}

		if sleepErr := sleep(
			request.Context(),
			retryDelay(attempt, response, time.Now()),
		); sleepErr != nil {
			return nil, sleepErr
		}
	}

	panic("unreachable HTTP retry loop")
}

func retryDelay(
	attempt int,
	response *http.Response,
	now time.Time,
) time.Duration {
	if response != nil &&
		(response.StatusCode == http.StatusTooManyRequests ||
			response.StatusCode == http.StatusServiceUnavailable) {
		if delay, ok := retryAfterDelay(response.Header.Get("Retry-After"), now); ok {
			if delay > defaultHTTPRetryWaitMax {
				return defaultHTTPRetryWaitMax
			}
			return delay
		}
	}

	delay := defaultHTTPRetryWaitMin << attempt
	if delay > defaultHTTPRetryWaitMax {
		return defaultHTTPRetryWaitMax
	}
	return delay
}

func retryAfterDelay(value string, now time.Time) (time.Duration, bool) {
	if value == "" {
		return 0, false
	}
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
		if seconds < 0 {
			return 0, false
		}
		return time.Duration(seconds) * time.Second, true
	}

	retryAt, err := http.ParseTime(value)
	if err != nil {
		return 0, false
	}
	if delay := retryAt.Sub(now); delay > 0 {
		return delay, true
	}
	return 0, false
}

func shouldRetryRequest(response *http.Response, err error) bool {
	if err != nil {
		if isPermanentHTTPError(response, err) {
			return false
		}
		return true
	}

	if response == nil {
		return false
	}

	return response.StatusCode == http.StatusTooManyRequests ||
		response.StatusCode == 0 ||
		(response.StatusCode >= http.StatusInternalServerError &&
			response.StatusCode != http.StatusNotImplemented)
}

func isPermanentHTTPError(response *http.Response, err error) bool {
	if errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, http.ErrNotSupported) {
		return true
	}

	var certificateVerificationError *tls.CertificateVerificationError
	if errors.As(err, &certificateVerificationError) {
		return true
	}
	var certificateInvalidError x509.CertificateInvalidError
	if errors.As(err, &certificateInvalidError) {
		return true
	}
	var hostnameError x509.HostnameError
	if errors.As(err, &hostnameError) {
		return true
	}
	var unknownAuthorityError x509.UnknownAuthorityError
	if errors.As(err, &unknownAuthorityError) {
		return true
	}

	var urlError *url.Error
	if !errors.As(err, &urlError) {
		return false
	}

	// net/http returns an untyped error for redirect exhaustion and some
	// request-construction failures. A response paired with a URL error is
	// also a redirect-policy failure. None can recover by repeating the GET.
	if response != nil {
		return true
	}
	message := urlError.Err.Error()
	return strings.Contains(message, "stopped after ") &&
		strings.HasSuffix(message, " redirects") ||
		strings.Contains(message, "unsupported protocol scheme") ||
		strings.Contains(message, "invalid header") ||
		strings.Contains(message, "certificate is not trusted")
}

func drainAndCloseResponse(response *http.Response) {
	if response == nil {
		return
	}
	if response.Body != nil {
		_, _ = io.CopyN(io.Discard, response.Body, defaultHTTPReadDrainMax)
	}
	response.Body.Close()
}
