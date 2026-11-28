package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"html"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// SSOCallbackPortMin and SSOCallbackPortMax are the localhost ports
// Bitwarden Server (StaticClientStore.cs) and Vaultwarden (src/sso.rs)
// whitelist as redirect URIs for desktop and cli OAuth clients.
const (
	SSOCallbackPortMin = 8065
	SSOCallbackPortMax = 8070

	// DefaultSSOWaitTimeout bounds how long a local SSO callback server
	// waits for the user to finish signing in via the browser.
	DefaultSSOWaitTimeout = 10 * time.Minute

	ssoRandomLength = 64
	ssoAlphabet     = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
)

var (
	// ErrSSOCallbackPortUnavailable means every port in 8065..8070 was in use.
	ErrSSOCallbackPortUnavailable = errors.New("api: no localhost callback port available (8065-8070)")
	// ErrSSOStateMismatch means the callback state did not match the one sent.
	ErrSSOStateMismatch = errors.New("api: SSO callback state mismatch")
	// ErrSSOMissingCode means the callback arrived without an authorization code.
	ErrSSOMissingCode = errors.New("api: SSO callback missing authorization code")
)

// SSOCallbackError is an OAuth error returned to the local SSO callback.
type SSOCallbackError struct {
	Code        string
	Description string
}

func (e *SSOCallbackError) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("api: SSO error (%s): %s", e.Code, e.Description)
	}
	return fmt.Sprintf("api: SSO error (%s)", e.Code)
}

// SSOPKCE holds the state and RFC 7636 S256 PKCE parameters for one SSO
// sign-in attempt.
type SSOPKCE struct {
	State         string
	CodeVerifier  string
	CodeChallenge string
}

// NewSSOPKCE generates fresh random state and S256 PKCE parameters.
func NewSSOPKCE() (SSOPKCE, error) {
	state, err := randomAlphanumeric(ssoRandomLength)
	if err != nil {
		return SSOPKCE{}, err
	}
	verifier, err := randomAlphanumeric(ssoRandomLength)
	if err != nil {
		return SSOPKCE{}, err
	}
	return SSOPKCE{
		State:         state,
		CodeVerifier:  verifier,
		CodeChallenge: PKCEChallengeS256(verifier),
	}, nil
}

// PKCEChallengeS256 computes the RFC 7636 S256 code challenge for verifier.
func PKCEChallengeS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func randomAlphanumeric(n int) (string, error) {
	// Rejection sampling over [0, 248) gives uniform selection from 62 chars
	// (248 = 62 * 4).
	const limit = 248
	out := make([]byte, 0, n)
	buf := make([]byte, n*2)
	for len(out) < n {
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		for _, b := range buf {
			if b >= limit {
				continue
			}
			out = append(out, ssoAlphabet[int(b)%len(ssoAlphabet)])
			if len(out) == n {
				break
			}
		}
	}
	return string(out), nil
}

// BuildSSOURL builds the Bitwarden / Vaultwarden web vault SSO entry URL
// matching bitwarden/clients SsoUrlService.buildSsoUrl.
func BuildSSOURL(webVaultURL, clientID, redirectURI string, pkce SSOPKCE, email, orgIdentifier string) (string, error) {
	base := strings.TrimRight(strings.TrimSpace(webVaultURL), "/")
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", fmt.Errorf("api: invalid web vault URL %q", webVaultURL)
	}
	if strings.TrimSpace(clientID) == "" {
		return "", errors.New("api: SSO client ID is required")
	}
	if strings.TrimSpace(redirectURI) == "" {
		return "", errors.New("api: SSO redirect URI is required")
	}
	if pkce.State == "" || pkce.CodeChallenge == "" {
		return "", errors.New("api: SSO PKCE state and challenge are required")
	}

	var b strings.Builder
	b.WriteString(base)
	b.WriteString("/#/sso?clientId=")
	b.WriteString(url.QueryEscape(clientID))
	b.WriteString("&redirectUri=")
	b.WriteString(url.QueryEscape(redirectURI))
	b.WriteString("&state=")
	b.WriteString(url.QueryEscape(pkce.State))
	b.WriteString("&codeChallenge=")
	b.WriteString(url.QueryEscape(pkce.CodeChallenge))
	if e := strings.TrimSpace(email); e != "" {
		b.WriteString("&email=")
		b.WriteString(url.QueryEscape(e))
	}
	if id := strings.TrimSpace(orgIdentifier); id != "" {
		b.WriteString("&identifier=")
		b.WriteString(url.QueryEscape(id))
	}
	return b.String(), nil
}

// VerifySSOState checks that received matches expected. Bitwarden's web
// vault appends "_identifier=<org>" to state before redirecting to
// IdentityServer (external client logins do not request a "_returnUri="
// suffix). Only the base state before "_identifier=" is compared, using
// constant-time equality.
func VerifySSOState(expected, received string) (orgIdentifier string, ok bool) {
	if expected == "" || received == "" {
		return "", false
	}
	base, rest, hasID := strings.Cut(received, "_identifier=")
	if hasID {
		orgIdentifier = rest
	}
	expectedBase, _, _ := strings.Cut(expected, "_identifier=")
	if len(base) != len(expectedBase) {
		return "", false
	}
	if subtle.ConstantTimeCompare([]byte(base), []byte(expectedBase)) != 1 {
		return "", false
	}
	return orgIdentifier, true
}

// SSOCallbackResult is the verified authorization code delivered to the
// local loopback callback server.
type SSOCallbackResult struct {
	Code          string
	OrgIdentifier string
}

type ssoCallbackOutcome struct {
	res SSOCallbackResult
	err error
}

// SSOCallbackServer listens on http://localhost:<port> for one OAuth2
// authorization code callback from the user's browser.
type SSOCallbackServer struct {
	redirectURI string
	server      *http.Server
	listeners   []net.Listener
	done        chan ssoCallbackOutcome
	once        sync.Once
	closeOnce   sync.Once
}

// StartSSOCallbackDefault starts a loopback callback server on the first
// available port in 8065..8070.
func StartSSOCallbackDefault(expectedState string) (*SSOCallbackServer, error) {
	return StartSSOCallback(expectedState, SSOCallbackPortMin, SSOCallbackPortMax)
}

// StartSSOCallback starts a loopback callback server on the first available
// port in [portMin, portMax]. Passing portMin=0, portMax=0 binds an
// ephemeral loopback port (intended for tests).
func StartSSOCallback(expectedState string, portMin, portMax int) (*SSOCallbackServer, error) {
	if expectedState == "" {
		return nil, errors.New("api: expected SSO state is required")
	}
	listeners, port, err := listenLoopbackRange(portMin, portMax)
	if err != nil {
		return nil, err
	}

	cb := &SSOCallbackServer{
		redirectURI: "http://localhost:" + strconv.Itoa(port),
		listeners:   listeners,
		done:        make(chan ssoCallbackOutcome, 1),
	}
	cb.server = &http.Server{
		Handler:           http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { cb.handle(w, r, expectedState) }),
		ReadHeaderTimeout: 10 * time.Second,
	}
	for _, ln := range listeners {
		go func(l net.Listener) {
			_ = cb.server.Serve(l)
		}(ln)
	}
	return cb, nil
}

func listenLoopbackRange(portMin, portMax int) ([]net.Listener, int, error) {
	if portMin == 0 && portMax == 0 {
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			return nil, 0, err
		}
		port := ln.Addr().(*net.TCPAddr).Port
		return []net.Listener{ln}, port, nil
	}
	for port := portMin; port <= portMax; port++ {
		ln4, err := net.Listen("tcp4", "127.0.0.1:"+strconv.Itoa(port))
		if err != nil {
			continue
		}
		// Browsers may resolve "localhost" to either 127.0.0.1 or ::1.
		// Bind [::1] on the same port when IPv6 loopback is available; if
		// another process already holds [::1]:port, skip this port so the
		// browser cannot land on the wrong listener.
		ln6, err6 := net.Listen("tcp6", "[::1]:"+strconv.Itoa(port))
		if err6 != nil {
			if isAddrInUse(err6) {
				_ = ln4.Close()
				continue
			}
			return []net.Listener{ln4}, port, nil
		}
		return []net.Listener{ln4, ln6}, port, nil
	}
	return nil, 0, ErrSSOCallbackPortUnavailable
}

func isAddrInUse(err error) bool {
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if errors.Is(opErr.Err, syscall.EADDRINUSE) {
			return true
		}
	}
	return strings.Contains(strings.ToLower(err.Error()), "address already in use") ||
		strings.Contains(strings.ToLower(err.Error()), "only one usage of each socket address")
}

// RedirectURI returns the http://localhost:<port> URI bound by this server.
func (s *SSOCallbackServer) RedirectURI() string { return s.redirectURI }

// Wait blocks until the browser delivers the SSO callback or ctx is done,
// then shuts down the local server.
func (s *SSOCallbackServer) Wait(ctx context.Context) (SSOCallbackResult, error) {
	defer s.Close()
	select {
	case out := <-s.done:
		return out.res, out.err
	case <-ctx.Done():
		return SSOCallbackResult{}, ctx.Err()
	}
}

// Close shuts down the local callback server and releases its ports.
func (s *SSOCallbackServer) Close() {
	s.closeOnce.Do(func() {
		// Give the browser a brief window to finish reading the HTML response
		// before closing idle/active connections.
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		_ = s.server.Shutdown(ctx)
		for _, ln := range s.listeners {
			_ = ln.Close()
		}
	})
}

func (s *SSOCallbackServer) deliver(out ssoCallbackOutcome) {
	s.once.Do(func() {
		s.done <- out
	})
}

func (s *SSOCallbackServer) handle(w http.ResponseWriter, r *http.Request, expectedState string) {
	if r.Method != http.MethodGet || (r.URL.Path != "/" && r.URL.Path != "") {
		http.NotFound(w, r)
		return
	}
	q := r.URL.Query()
	receivedState := q.Get("state")
	// Only a state-correlated request may terminate Wait; uncorrelated
	// browser probes or stray tabs get HTTP 400 while the listener keeps
	// waiting for the real IdP redirect.
	orgID, ok := VerifySSOState(expectedState, receivedState)
	if !ok {
		writeSSOCallbackHTML(w, http.StatusBadRequest, "Unrecognized request", "This sign-in request does not match an active GoVault session. You may close this tab.")
		return
	}

	oauthErr := strings.TrimSpace(q.Get("error"))
	oauthDesc := strings.TrimSpace(q.Get("error_description"))
	code := strings.TrimSpace(q.Get("code"))

	if oauthErr != "" {
		writeSSOCallbackHTML(w, http.StatusBadRequest, "Sign-in failed", "Single sign-on could not be completed. You may close this tab and return to GoVault.")
		s.deliver(ssoCallbackOutcome{err: &SSOCallbackError{Code: oauthErr, Description: oauthDesc}})
		return
	}
	if code == "" {
		writeSSOCallbackHTML(w, http.StatusBadRequest, "Sign-in failed", "No authorization code was received. You may close this tab and return to GoVault.")
		s.deliver(ssoCallbackOutcome{err: ErrSSOMissingCode})
		return
	}
	// Vaultwarden's oidcsignin_error intentionally redirects with a code and
	// state and reports the IdP error only at token exchange, so do not
	// declare final authentication success here.
	writeSSOCallbackHTML(w, http.StatusOK, "Response received", "Sign-in response received. You may close this tab and return to GoVault to finish signing in.")
	s.deliver(ssoCallbackOutcome{res: SSOCallbackResult{Code: code, OrgIdentifier: orgID}})
}

func writeSSOCallbackHTML(w http.ResponseWriter, status int, title, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>%s | GoVault</title>
<style>
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; background: #f6f7f9; color: #1a1d21; }
main { max-width: 420px; padding: 32px; border-radius: 14px; background: #ffffff; box-shadow: 0 10px 30px rgba(0,0,0,0.08); text-align: center; }
h1 { font-size: 20px; margin: 0 0 10px; }
p { font-size: 14px; line-height: 1.5; color: #525866; margin: 0; }
@media (prefers-color-scheme: dark) {
  body { background: #14161a; color: #eef0f4; }
  main { background: #1e2128; box-shadow: 0 10px 30px rgba(0,0,0,0.35); }
  p { color: #a1a8b5; }
}
</style>
</head>
<body>
<main>
<h1>%s</h1>
<p>%s</p>
</main>
</body>
</html>`, html.EscapeString(title), html.EscapeString(title), html.EscapeString(message))
}
