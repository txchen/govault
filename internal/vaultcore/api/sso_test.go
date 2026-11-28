package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/txchen/govault/internal/vaultcore/crypto"
)

func TestWebVaultURL(t *testing.T) {
	cases := []struct {
		base string
		want string
	}{
		{"", "https://vault.bitwarden.com"},
		{"https://bitwarden.com", "https://vault.bitwarden.com"},
		{"https://vault.bitwarden.com", "https://vault.bitwarden.com"},
		{"https://bitwarden.eu", "https://vault.bitwarden.eu"},
		{"https://vault.bitwarden.eu", "https://vault.bitwarden.eu"},
		{"https://vault.example.com/", "https://vault.example.com"},
		{"https://vault.example.com/subpath/", "https://vault.example.com/subpath"},
	}
	for _, tc := range cases {
		if got := WebVaultURL(tc.base); got != tc.want {
			t.Errorf("WebVaultURL(%q) = %q, want %q", tc.base, got, tc.want)
		}
	}
}

func TestSSOPKCEAndRFC7636Vector(t *testing.T) {
	// RFC 7636 Appendix B test vector.
	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	const wantChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if got := PKCEChallengeS256(verifier); got != wantChallenge {
		t.Fatalf("PKCEChallengeS256 = %q, want %q", got, wantChallenge)
	}

	pkce, err := NewSSOPKCE()
	if err != nil {
		t.Fatal(err)
	}
	if len(pkce.State) != ssoRandomLength || len(pkce.CodeVerifier) != ssoRandomLength {
		t.Fatalf("unexpected lengths: state=%d verifier=%d", len(pkce.State), len(pkce.CodeVerifier))
	}
	if pkce.State == pkce.CodeVerifier {
		t.Fatal("state and code verifier must be independent")
	}
	for _, s := range []string{pkce.State, pkce.CodeVerifier} {
		for i := 0; i < len(s); i++ {
			if strings.IndexByte(ssoAlphabet, s[i]) < 0 {
				t.Fatalf("unexpected non-alphanumeric byte %q in %q", s[i], s)
			}
		}
	}
	if pkce.CodeChallenge != PKCEChallengeS256(pkce.CodeVerifier) {
		t.Fatal("challenge does not match verifier")
	}
}

func TestBuildSSOURL(t *testing.T) {
	pkce := SSOPKCE{State: "state123", CodeVerifier: "verifier123", CodeChallenge: "challenge123"}
	got, err := BuildSSOURL("https://vault.example.com/", "desktop", "http://localhost:8065", pkce, "alice@example.com", "my-org")
	if err != nil {
		t.Fatal(err)
	}
	wantPrefix := "https://vault.example.com/#/sso?"
	if !strings.HasPrefix(got, wantPrefix) {
		t.Fatalf("URL = %q, want prefix %q", got, wantPrefix)
	}
	q, err := url.ParseQuery(strings.TrimPrefix(got, wantPrefix))
	if err != nil {
		t.Fatal(err)
	}
	checks := map[string]string{
		"clientId":      "desktop",
		"redirectUri":   "http://localhost:8065",
		"state":         "state123",
		"codeChallenge": "challenge123",
		"email":         "alice@example.com",
		"identifier":    "my-org",
	}
	for k, want := range checks {
		if v := q.Get(k); v != want {
			t.Errorf("param %s = %q, want %q", k, v, want)
		}
	}

	// Without optional email / identifier.
	minimal, err := BuildSSOURL("https://vault.bitwarden.com", "cli", "http://localhost:8065", pkce, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(minimal, "email=") || strings.Contains(minimal, "identifier=") {
		t.Fatalf("minimal URL unexpectedly contains optional params: %q", minimal)
	}
}

func TestVerifySSOState(t *testing.T) {
	if org, ok := VerifySSOState("abc123", "abc123"); !ok || org != "" {
		t.Fatalf("exact match failed: org=%q ok=%v", org, ok)
	}
	if org, ok := VerifySSOState("abc123", "abc123_identifier=northwind"); !ok || org != "northwind" {
		t.Fatalf("identifier suffix failed: org=%q ok=%v", org, ok)
	}
	if _, ok := VerifySSOState("abc123", "abc124_identifier=northwind"); ok {
		t.Fatal("mismatched state must fail")
	}
	if _, ok := VerifySSOState("", "abc"); ok {
		t.Fatal("empty expected state must fail")
	}
	if _, ok := VerifySSOState("abc", ""); ok {
		t.Fatal("empty received state must fail")
	}
}

func TestSSOCallbackServerSuccessAndIgnoresFavicon(t *testing.T) {
	cb, err := StartSSOCallback("expectedState", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer cb.Close()

	waitCh := make(chan struct {
		res SSOCallbackResult
		err error
	}, 1)
	go func() {
		res, err := cb.Wait(context.Background())
		waitCh <- struct {
			res SSOCallbackResult
			err error
		}{res, err}
	}()

	// Browsers always probe /favicon.ico; it must 404 without terminating Wait.
	favResp, err := http.Get(cb.RedirectURI() + "/favicon.ico")
	if err != nil {
		t.Fatal(err)
	}
	favResp.Body.Close()
	if favResp.StatusCode != http.StatusNotFound {
		t.Fatalf("favicon status = %d, want 404", favResp.StatusCode)
	}

	resp, err := http.Get(cb.RedirectURI() + "/?code=auth-code-42&state=expectedState_identifier=org-1")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("callback status = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(string(body), "GoVault") {
		t.Fatalf("unexpected callback HTML: %q", string(body))
	}

	got := <-waitCh
	if got.err != nil {
		t.Fatalf("Wait error: %v", got.err)
	}
	if got.res.Code != "auth-code-42" || got.res.OrgIdentifier != "org-1" {
		t.Fatalf("Wait result = %+v, want code=auth-code-42 org=org-1", got.res)
	}
}

func TestSSOCallbackServerErrorsAndCancel(t *testing.T) {
	t.Run("uncorrelated requests do not terminate wait", func(t *testing.T) {
		cb, err := StartSSOCallback("goodState", 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer cb.Close()
		waitCh := make(chan struct {
			res SSOCallbackResult
			err error
		}, 1)
		go func() {
			res, err := cb.Wait(context.Background())
			waitCh <- struct {
				res SSOCallbackResult
				err error
			}{res, err}
		}()

		// Stray root GET, forged error without state, and mismatched state all
		// get 400 without consuming the listener.
		for _, path := range []string{
			"/",
			"/?error=access_denied",
			"/?code=forged&state=wrongState",
		} {
			resp, err := http.Get(cb.RedirectURI() + path)
			if err != nil {
				t.Fatalf("GET %s: %v", path, err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("GET %s status = %d, want 400", path, resp.StatusCode)
			}
		}

		// The legitimate state-correlated callback still succeeds afterwards.
		resp, err := http.Get(cb.RedirectURI() + "/?code=real-code&state=goodState")
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "Response received") {
			t.Fatalf("legitimate callback status=%d body=%q", resp.StatusCode, string(body))
		}
		got := <-waitCh
		if got.err != nil || got.res.Code != "real-code" {
			t.Fatalf("Wait = (%+v, %v), want real-code", got.res, got.err)
		}
	})

	t.Run("state-correlated oauth error", func(t *testing.T) {
		cb, err := StartSSOCallback("goodState", 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer cb.Close()
		go func() {
			resp, err := http.Get(cb.RedirectURI() + "/?error=access_denied&error_description=user+cancelled&state=goodState")
			if err == nil {
				resp.Body.Close()
			}
		}()
		_, err = cb.Wait(context.Background())
		var cbErr *SSOCallbackError
		if !errors.As(err, &cbErr) || cbErr.Code != "access_denied" || cbErr.Description != "user cancelled" {
			t.Fatalf("err = %v, want SSOCallbackError(access_denied)", err)
		}
	})

	t.Run("state-correlated missing code", func(t *testing.T) {
		cb, err := StartSSOCallback("goodState", 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer cb.Close()
		go func() {
			resp, err := http.Get(cb.RedirectURI() + "/?state=goodState")
			if err == nil {
				resp.Body.Close()
			}
		}()
		_, err = cb.Wait(context.Background())
		if !errors.Is(err, ErrSSOMissingCode) {
			t.Fatalf("err = %v, want ErrSSOMissingCode", err)
		}
	})

	t.Run("context cancel", func(t *testing.T) {
		cb, err := StartSSOCallback("goodState", 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
		defer cancel()
		_, err = cb.Wait(ctx)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("err = %v, want context.DeadlineExceeded", err)
		}
	})

	t.Run("port range fallback", func(t *testing.T) {
		occupied, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer occupied.Close()
		basePort := occupied.Addr().(*net.TCPAddr).Port
		cb, err := StartSSOCallback("state", basePort, basePort+2)
		if err != nil {
			t.Skipf("adjacent test ports unavailable: %v", err)
		}
		defer cb.Close()
		if cb.RedirectURI() == "http://localhost:"+occupied.Addr().String()[strings.LastIndex(occupied.Addr().String(), ":")+1:] {
			t.Fatalf("callback reused occupied port: %s", cb.RedirectURI())
		}
	})
}

func TestLoginSSOWireFormatAndTwoFactor(t *testing.T) {
	var seenForm url.Values
	var seenEmail2FA []map[string]any
	var seenEmailHeaders []string
	attempt := 0

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/identity/connect/token":
			_ = r.ParseForm()
			seenForm = r.PostForm
			attempt++
			if attempt == 1 {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"error":                   "invalid_grant",
					"error_description":       "Two factor required.",
					"Email":                   "idp-alice@example.com",
					"TwoFactorProviders":      []string{"0", "1"},
					"TwoFactorProviders2":     map[string]any{"0": nil, "1": map[string]any{"Email": "i***e@example.com"}},
					"SsoEmail2faSessionToken": "sso-email-token-99",
				})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token":  "tok-sso",
				"expires_in":    3600,
				"token_type":    "Bearer",
				"refresh_token": "ref-sso",
				"Key":           "2.legacy-key",
				"Kdf":           0,
				"KdfIterations": 600000,
				"UserDecryptionOptions": map[string]any{
					"HasMasterPassword": true,
					"MasterPasswordUnlock": map[string]any{
						"Kdf": map[string]any{
							"KdfType":     1,
							"Iterations":  3,
							"Memory":      64,
							"Parallelism": 4,
						},
						"MasterKeyWrappedUserKey": "2.wrapped-key",
						"Salt":                    "Custom-Salt-Case",
					},
				},
			})
		case "/api/two-factor/send-email-login":
			var m map[string]any
			_ = json.NewDecoder(r.Body).Decode(&m)
			seenEmail2FA = append(seenEmail2FA, m)
			seenEmailHeaders = append(seenEmailHeaders, r.Header.Get("Device-Identifier"))
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c, err := NewClient(ClientConfig{
		ServerURL:  srv.URL,
		DeviceID:   "dev-1",
		DeviceName: "GoVault",
		DeviceType: 2,
		ClientID:   "desktop",
		HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = c.LoginSSO(context.Background(), SSOLoginOptions{
		Code:         "code-1",
		CodeVerifier: "verifier-1",
		RedirectURI:  "http://localhost:8065",
	})
	var tfErr *TwoFactorRequiredError
	if !errors.As(err, &tfErr) {
		t.Fatalf("first call err = %v, want TwoFactorRequiredError", err)
	}
	if tfErr.Challenge.Email != "idp-alice@example.com" {
		t.Fatalf("Email = %q, want idp-alice@example.com", tfErr.Challenge.Email)
	}
	if tfErr.Challenge.SSOEmail2FASessionToken != "sso-email-token-99" {
		t.Fatalf("SSOEmail2FASessionToken = %q, want sso-email-token-99", tfErr.Challenge.SSOEmail2FASessionToken)
	}
	if seenForm.Get("grant_type") != "authorization_code" ||
		seenForm.Get("code") != "code-1" ||
		seenForm.Get("code_verifier") != "verifier-1" ||
		seenForm.Get("redirect_uri") != "http://localhost:8065" ||
		seenForm.Get("scope") != "api offline_access" ||
		seenForm.Get("client_id") != "desktop" {
		t.Fatalf("unexpected token form: %v", seenForm)
	}

	// Bitwarden form: authoritative email + ssoEmail2faSessionToken + Device-Identifier header.
	if err := c.SendEmailTwoFactorLoginSSO(context.Background(), tfErr.Challenge.Email, tfErr.Challenge.SSOEmail2FASessionToken); err != nil {
		t.Fatal(err)
	}
	// Vaultwarden tokenless form: device-only (no email, no masterPasswordHash) + Device-Identifier header.
	if err := c.SendEmailTwoFactorLoginSSO(context.Background(), "typed@example.com", ""); err != nil {
		t.Fatal(err)
	}
	if len(seenEmail2FA) != 2 || seenEmailHeaders[0] != "dev-1" || seenEmailHeaders[1] != "dev-1" {
		t.Fatalf("unexpected email 2FA sends: payloads=%v headers=%v", seenEmail2FA, seenEmailHeaders)
	}
	if seenEmail2FA[0]["email"] != "idp-alice@example.com" ||
		seenEmail2FA[0]["ssoEmail2faSessionToken"] != "sso-email-token-99" ||
		seenEmail2FA[0]["deviceIdentifier"] != "dev-1" {
		t.Fatalf("unexpected Bitwarden send-email-login payload: %v", seenEmail2FA[0])
	}
	if _, hasHash := seenEmail2FA[0]["masterPasswordHash"]; hasHash {
		t.Fatalf("SSO send-email-login must not send masterPasswordHash: %v", seenEmail2FA[0])
	}
	if _, hasEmail := seenEmail2FA[1]["email"]; hasEmail {
		t.Fatalf("Vaultwarden tokenless SSO send-email-login must omit email: %v", seenEmail2FA[1])
	}
	if seenEmail2FA[1]["deviceIdentifier"] != "dev-1" {
		t.Fatalf("unexpected Vaultwarden send-email-login payload: %v", seenEmail2FA[1])
	}

	tok, err := c.LoginSSO(context.Background(), SSOLoginOptions{
		Code:         "code-1",
		CodeVerifier: "verifier-1",
		RedirectURI:  "http://localhost:8065",
		TwoFactor:    &TwoFactorLogin{Provider: TwoFactorAuthenticator, Token: "123 456", Remember: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if seenForm.Get("twoFactorProvider") != "0" || seenForm.Get("twoFactorToken") != "123456" || seenForm.Get("twoFactorRemember") != "1" {
		t.Fatalf("unexpected 2FA form fields: %v", seenForm)
	}
	if tok.MasterPasswordProtectedKey() != "2.wrapped-key" {
		t.Fatalf("MasterPasswordProtectedKey = %q, want 2.wrapped-key", tok.MasterPasswordProtectedKey())
	}
	if tok.MasterPasswordSalt() != "Custom-Salt-Case" {
		t.Fatalf("MasterPasswordSalt = %q, want Custom-Salt-Case", tok.MasterPasswordSalt())
	}
	wantKDF := crypto.KDFConfig{Type: crypto.KDFArgon2id, Iterations: 3, MemoryMB: 64, Parallelism: 4}
	if tok.MasterPasswordKDF() != wantKDF {
		t.Fatalf("MasterPasswordKDF = %+v, want %+v", tok.MasterPasswordKDF(), wantKDF)
	}
}
