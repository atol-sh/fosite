// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gomock "go.uber.org/mock/gomock"

	. "github.com/atol-sh/fosite"
	. "github.com/atol-sh/fosite/internal"
)

func TestWriteAuthorizeResponse(t *testing.T) {
	oauth2 := &Fosite{Config: new(Config)}
	header := http.Header{}
	ctrl := gomock.NewController(t)
	rw := NewMockResponseWriter(ctrl)
	ar := NewMockAuthorizeRequester(ctrl)
	resp := NewMockAuthorizeResponder(ctrl)
	defer ctrl.Finish()

	for k, c := range []struct {
		setup  func()
		expect func()
	}{
		{
			setup: func() {
				redir, _ := url.Parse("https://foobar.com/?foo=bar")
				ar.EXPECT().GetRedirectURI().Return(redir)
				ar.EXPECT().GetResponseMode().Return(ResponseModeDefault)
				resp.EXPECT().GetParameters().Return(url.Values{})
				resp.EXPECT().GetHeader().Return(http.Header{})

				rw.EXPECT().Header().Return(header).Times(2)
				rw.EXPECT().WriteHeader(http.StatusSeeOther)
			},
			expect: func() {
				assert.Equal(t, http.Header{
					"Location":      []string{"https://foobar.com/?foo=bar"},
					"Cache-Control": []string{"no-store"},
					"Pragma":        []string{"no-cache"},
				}, header)
			},
		},
		{
			setup: func() {
				redir, _ := url.Parse("https://foobar.com/?foo=bar")
				ar.EXPECT().GetRedirectURI().Return(redir)
				ar.EXPECT().GetResponseMode().Return(ResponseModeFragment)
				resp.EXPECT().GetParameters().Return(url.Values{"bar": {"baz"}})
				resp.EXPECT().GetHeader().Return(http.Header{})

				rw.EXPECT().Header().Return(header).Times(2)
				rw.EXPECT().WriteHeader(http.StatusSeeOther)
			},
			expect: func() {
				assert.Equal(t, http.Header{
					"Location":      []string{"https://foobar.com/?foo=bar#bar=baz"},
					"Cache-Control": []string{"no-store"},
					"Pragma":        []string{"no-cache"},
				}, header)
			},
		},
		{
			setup: func() {
				redir, _ := url.Parse("https://foobar.com/?foo=bar")
				ar.EXPECT().GetRedirectURI().Return(redir)
				ar.EXPECT().GetResponseMode().Return(ResponseModeQuery)
				resp.EXPECT().GetParameters().Return(url.Values{"bar": {"baz"}})
				resp.EXPECT().GetHeader().Return(http.Header{})

				rw.EXPECT().Header().Return(header).Times(2)
				rw.EXPECT().WriteHeader(http.StatusSeeOther)
			},
			expect: func() {
				expectedUrl, _ := url.Parse("https://foobar.com/?foo=bar&bar=baz")
				actualUrl, err := url.Parse(header.Get("Location"))
				assert.Nil(t, err)
				assert.Equal(t, expectedUrl.Query(), actualUrl.Query())
				assert.Equal(t, "no-cache", header.Get("Pragma"))
				assert.Equal(t, "no-store", header.Get("Cache-Control"))
			},
		},
		{
			setup: func() {
				redir, _ := url.Parse("https://foobar.com/?foo=bar")
				ar.EXPECT().GetRedirectURI().Return(redir)
				ar.EXPECT().GetResponseMode().Return(ResponseModeFragment)
				resp.EXPECT().GetParameters().Return(url.Values{"bar": {"b+az ab"}})
				resp.EXPECT().GetHeader().Return(http.Header{"X-Bar": {"baz"}})

				rw.EXPECT().Header().Return(header).Times(2)
				rw.EXPECT().WriteHeader(http.StatusSeeOther)
			},
			expect: func() {
				assert.Equal(t, http.Header{
					"X-Bar":         {"baz"},
					"Location":      {"https://foobar.com/?foo=bar#bar=b%2Baz+ab"},
					"Cache-Control": []string{"no-store"},
					"Pragma":        []string{"no-cache"},
				}, header)
			},
		},
		{
			setup: func() {
				redir, _ := url.Parse("https://foobar.com/?foo=bar")
				ar.EXPECT().GetRedirectURI().Return(redir)
				ar.EXPECT().GetResponseMode().Return(ResponseModeQuery)
				resp.EXPECT().GetParameters().Return(url.Values{"bar": {"b+az"}, "scope": {"a b"}})
				resp.EXPECT().GetHeader().Return(http.Header{"X-Bar": {"baz"}})

				rw.EXPECT().Header().Return(header).Times(2)
				rw.EXPECT().WriteHeader(http.StatusSeeOther)
			},
			expect: func() {
				expectedUrl, err := url.Parse("https://foobar.com/?foo=bar&bar=b%2Baz&scope=a+b")
				assert.Nil(t, err)
				actualUrl, err := url.Parse(header.Get("Location"))
				assert.Nil(t, err)
				assert.Equal(t, expectedUrl.Query(), actualUrl.Query())
				assert.Equal(t, "no-cache", header.Get("Pragma"))
				assert.Equal(t, "no-store", header.Get("Cache-Control"))
				assert.Equal(t, "baz", header.Get("X-Bar"))
			},
		},
		{
			setup: func() {
				redir, _ := url.Parse("https://foobar.com/?foo=bar")
				ar.EXPECT().GetRedirectURI().Return(redir)
				ar.EXPECT().GetResponseMode().Return(ResponseModeFragment)
				resp.EXPECT().GetParameters().Return(url.Values{"scope": {"api:*"}})
				resp.EXPECT().GetHeader().Return(http.Header{"X-Bar": {"baz"}})

				rw.EXPECT().Header().Return(header).Times(2)
				rw.EXPECT().WriteHeader(http.StatusSeeOther)
			},
			expect: func() {
				assert.Equal(t, http.Header{
					"X-Bar":         {"baz"},
					"Location":      {"https://foobar.com/?foo=bar#scope=api%3A%2A"},
					"Cache-Control": []string{"no-store"},
					"Pragma":        []string{"no-cache"},
				}, header)
			},
		},
		{
			setup: func() {
				redir, _ := url.Parse("https://foobar.com/?foo=bar#bar=baz")
				ar.EXPECT().GetRedirectURI().Return(redir)
				ar.EXPECT().GetResponseMode().Return(ResponseModeFragment)
				resp.EXPECT().GetParameters().Return(url.Values{"qux": {"quux"}})
				resp.EXPECT().GetHeader().Return(http.Header{})

				rw.EXPECT().Header().Return(header).Times(2)
				rw.EXPECT().WriteHeader(http.StatusSeeOther)
			},
			expect: func() {
				assert.Equal(t, http.Header{
					"Location":      {"https://foobar.com/?foo=bar#qux=quux"},
					"Cache-Control": []string{"no-store"},
					"Pragma":        []string{"no-cache"},
				}, header)
			},
		},
		{
			setup: func() {
				redir, _ := url.Parse("https://foobar.com/?foo=bar")
				ar.EXPECT().GetRedirectURI().Return(redir)
				ar.EXPECT().GetResponseMode().Return(ResponseModeFragment)
				resp.EXPECT().GetParameters().Return(url.Values{"state": {"{\"a\":\"b=c&d=e\"}"}})
				resp.EXPECT().GetHeader().Return(http.Header{})

				rw.EXPECT().Header().Return(header).Times(2)
				rw.EXPECT().WriteHeader(http.StatusSeeOther)
			},
			expect: func() {
				assert.Equal(t, http.Header{
					"Location":      {"https://foobar.com/?foo=bar#state=%7B%22a%22%3A%22b%3Dc%26d%3De%22%7D"},
					"Cache-Control": []string{"no-store"},
					"Pragma":        []string{"no-cache"},
				}, header)
			},
		},
		{
			setup: func() {
				redir, _ := url.Parse("https://foobar.com/?foo=bar")
				ar.EXPECT().GetRedirectURI().Return(redir)
				ar.EXPECT().GetResponseMode().Return(ResponseModeFormPost)
				resp.EXPECT().GetHeader().Return(http.Header{"X-Bar": {"baz"}})
				resp.EXPECT().GetParameters().Return(url.Values{"code": {"poz65kqoneu"}, "state": {"qm6dnsrn"}})

				rw.EXPECT().Header().Return(header).AnyTimes()
				rw.EXPECT().Write(gomock.Any()).AnyTimes()
			},
			expect: func() {
				assert.Equal(t, "text/html;charset=UTF-8", header.Get("Content-Type"))
			},
		},
	} {
		t.Logf("Starting test case %d", k)
		c.setup()
		oauth2.WriteAuthorizeResponse(context.Background(), rw, ar, resp)
		c.expect()
		header = http.Header{}
		t.Logf("Passed test case %d", k)
	}
}

// TestWriteAuthorizeResponse_WebMessage verifies the web_message response
// mode renders an HTML document that posts the authorization response via
// window.postMessage, targeted at the redirect_uri origin. See
// draft-sakimura-oauth-wmrm-01.
func TestWriteAuthorizeResponse_WebMessage(t *testing.T) {
	oauth2 := &Fosite{Config: new(Config)}
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	for _, tc := range []struct {
		name         string
		redirectURI  string
		params       url.Values
		wantOrigin   string
		wantPostCall bool
		wantContains []string
	}{
		{
			name:        "success response is posted to redirect_uri origin",
			redirectURI: "https://client.example.com/callback",
			params: url.Values{
				"code":  {"auth-code-xyz"},
				"state": {"s123"},
			},
			wantOrigin:   "https://client.example.com",
			wantPostCall: true,
			wantContains: []string{
				`"code":"auth-code-xyz"`,
				`"state":"s123"`,
				`"https://client.example.com"`,
				`"authorization_response"`,
				`opener.postMessage`,
			},
		},
		{
			name:        "localhost redirect preserves port in origin",
			redirectURI: "http://localhost:3005/callback",
			params: url.Values{
				"code": {"c"},
			},
			wantOrigin:   "http://localhost:3005",
			wantPostCall: true,
			wantContains: []string{
				`"http://localhost:3005"`,
			},
		},
		{
			name:        "path and query in redirect_uri are stripped from origin",
			redirectURI: "https://app.example.com/oidc/callback?nested=1",
			params: url.Values{
				"code": {"c"},
			},
			wantOrigin:   "https://app.example.com",
			wantPostCall: true,
			wantContains: []string{
				`"https://app.example.com"`,
			},
		},
		{
			name:        "empty origin guards against postMessage",
			redirectURI: "not-a-valid-uri",
			params: url.Values{
				"code": {"c"},
			},
			wantOrigin:   "",
			wantPostCall: false,
			wantContains: []string{
				`if (!origin) { return; }`,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ar := NewMockAuthorizeRequester(ctrl)
			resp := NewMockAuthorizeResponder(ctrl)

			redir, _ := url.Parse(tc.redirectURI)
			ar.EXPECT().GetRedirectURI().Return(redir)
			ar.EXPECT().GetResponseMode().Return(ResponseModeWebMessage)
			resp.EXPECT().GetHeader().Return(http.Header{})
			resp.EXPECT().GetParameters().Return(tc.params)

			rec := httptest.NewRecorder()
			oauth2.WriteAuthorizeResponse(context.Background(), rec, ar, resp)

			assert.Equal(t, "text/html;charset=UTF-8", rec.Header().Get("Content-Type"))
			assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
			assert.Equal(t, "no-cache", rec.Header().Get("Pragma"))

			body := rec.Body.String()
			for _, needle := range tc.wantContains {
				assert.Contains(t, body, needle, "rendered body missing %q", needle)
			}

			// Spec sanity: every successful render must declare the response
			// map and reference postMessage. The empty-origin guard is checked
			// via wantContains above for that specific case.
			assert.Contains(t, body, "var response =")
			assert.Contains(t, body, "opener.postMessage")

			// The postMessage targetOrigin literal must appear with surrounding
			// quotes so the JS parses it as a string; an empty origin must not
			// produce `""` as a targetOrigin argument to postMessage.
			if tc.wantPostCall {
				assert.Contains(t, body, ", origin)")
			}
			if !tc.wantPostCall {
				assert.NotContains(t, body, `, "")`)
			}
		})
	}
}

// TestExtractRedirectOrigin pins extractRedirectOrigin's behavior for the
// range of redirect URIs fosite callers are allowed to send. It is exposed
// indirectly via the template, so we verify through the template output.
func TestExtractRedirectOriginThroughTemplate(t *testing.T) {
	for _, tc := range []struct {
		redirect   string
		wantOrigin string
	}{
		{"https://client.example.com/callback", "https://client.example.com"},
		{"https://client.example.com:8443/callback", "https://client.example.com:8443"},
		{"http://localhost:3005/callback", "http://localhost:3005"},
		{"custom-scheme://app/callback", "custom-scheme://app"},
		{"", ""},
		{"no-host", ""},
		{"://bad", ""},
	} {
		t.Run(tc.redirect, func(t *testing.T) {
			var buf strings.Builder
			WriteAuthorizeWebMessageResponse(tc.redirect, url.Values{"code": {"c"}}, DefaultWebMessageTemplate, &buf)
			body := buf.String()
			require.Contains(t, body, "var origin =")
			if tc.wantOrigin == "" {
				assert.Contains(t, body, `var origin = "";`)
			} else {
				assert.Contains(t, body, `"`+tc.wantOrigin+`"`)
			}
		})
	}
}
