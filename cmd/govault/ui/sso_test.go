package ui

import (
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/nsgotest"
	"github.com/txchen/govault/internal/fakeserver"
	"github.com/txchen/govault/internal/vaultcore/api"
	"github.com/txchen/govault/internal/vaultcore/state"
	"github.com/txchen/govault/internal/vaultcore/store"
)

type testSecretStore struct {
	mu sync.Mutex
	m  map[string]string
}

func newTestSecretStore() *testSecretStore { return &testSecretStore{m: map[string]string{}} }
func (s *testSecretStore) Get(k string) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[k]
	return v, ok, nil
}
func (s *testSecretStore) Set(k, v string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[k] = v
	return nil
}
func (s *testSecretStore) Delete(k string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, k)
	return nil
}

func parseSSOOpenURL(t *testing.T, rawURL string) (redirectURI, stateParam, challenge, clientID, email string) {
	t.Helper()
	_, frag, ok := strings.Cut(rawURL, "/#/sso?")
	if !ok {
		t.Fatalf("unexpected SSO URL %q", rawURL)
	}
	q, err := url.ParseQuery(frag)
	if err != nil {
		t.Fatalf("parse SSO query: %v", err)
	}
	return q.Get("redirectUri"), q.Get("state"), q.Get("codeChallenge"), q.Get("clientId"), q.Get("email")
}

func deliverSSOCallback(redirectURI, code, stateParam string) {
	go func() {
		u := redirectURI + "/?code=" + url.QueryEscape(code) + "&state=" + url.QueryEscape(stateParam)
		resp, err := (&http.Client{}).Get(u)
		if err == nil {
			resp.Body.Close()
		}
	}()
}

func TestDesktopSSOLoginTransitionsToLockThenUnlock(t *testing.T) {
	svc := newMockVaultService(state.StatusLoggedOut)
	openedCh := make(chan string, 2)
	var m *AppModel

	app := nsgotest.Start(t, func(cx *core.Scope) core.Node {
		m = NewAppModel(cx, svc, PlatformHooks{
			OpenURL: func(u string) { openedCh <- u },
		})
		m.MainWinVisible.Set(true)
		return MainWindowView(cx, m)
	}, nsgotest.Size(1100, 900))
	app.WaitFor("id:login-sso", 2*time.Second)

	app.Post(func() {
		m.LoginServer.Set("https://vault.example.com")
		m.LoginEmail.Set("alice@example.com")
	})
	app.Press("id:login-sso")
	app.WaitFor("id:sso-waiting-screen", 2*time.Second)

	var opened string
	select {
	case opened = <-openedCh:
	case <-time.After(2 * time.Second):
		t.Fatal("expected browser URL to be opened")
	}

	redirectURI, st, challenge, clientID, email := parseSSOOpenURL(t, opened)
	if clientID != "desktop" {
		t.Fatalf("clientId = %q, want desktop", clientID)
	}
	if email != "alice@example.com" {
		t.Fatalf("email = %q, want alice@example.com", email)
	}
	if challenge == "" || !strings.HasPrefix(redirectURI, "http://localhost:") {
		t.Fatalf("invalid SSO params: redirect=%q challenge=%q", redirectURI, challenge)
	}

	// Clicking "Open browser again" re-opens the same SSO URL.
	app.Press("id:sso-reopen")
	select {
	case reopened := <-openedCh:
		if reopened != opened {
			t.Fatalf("reopened URL = %q, want %q", reopened, opened)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("expected reopen to invoke OpenURL")
	}

	// Simulate IdP callback -> GoVault exchanges code and enters LockView.
	deliverSSOCallback(redirectURI, "sso-auth-code-1", st+"_identifier=00000000-01DC-01DC-01DC-000000000000")
	app.WaitFor("id:lock-screen", 2*time.Second)

	if m.LockState.Get() != state.StatusLocked {
		t.Fatalf("LockState = %v, want StatusLocked", m.LockState.Get())
	}
	if svc.lastSSOLogin.Code != "sso-auth-code-1" || svc.lastSSOLogin.RedirectURI != redirectURI {
		t.Fatalf("unexpected LoginSSO request: %+v", svc.lastSSOLogin)
	}
	if api.PKCEChallengeS256(svc.lastSSOLogin.CodeVerifier) != challenge {
		t.Fatal("PKCE verifier sent to server does not match challenge sent to browser")
	}

	// Enter master password on LockView to unlock the vault.
	app.Post(func() {
		m.LockPassword.Set("master-password")
		m.UnlockWithPassword()
	})
	app.WaitForGone("id:lock-screen", 2*time.Second)
	if m.LockState.Get() != state.StatusUnlocked {
		t.Fatalf("LockState = %v, want StatusUnlocked", m.LockState.Get())
	}
}

func TestDesktopSSOCancelReturnsToSignIn(t *testing.T) {
	svc := newMockVaultService(state.StatusLoggedOut)
	openedCh := make(chan string, 1)
	var m *AppModel

	app := nsgotest.Start(t, func(cx *core.Scope) core.Node {
		m = NewAppModel(cx, svc, PlatformHooks{
			OpenURL: func(u string) { openedCh <- u },
		})
		m.MainWinVisible.Set(true)
		return MainWindowView(cx, m)
	}, nsgotest.Size(1100, 900))
	app.WaitFor("id:login-sso", 2*time.Second)

	app.Post(func() { m.LoginServer.Set("https://vault.example.com") })
	app.Press("id:login-sso")
	app.WaitFor("id:sso-cancel", 2*time.Second)
	<-openedCh

	app.Press("id:sso-cancel")
	app.WaitFor("id:login-screen", 2*time.Second)
	if m.SSOWaiting.Get() {
		t.Fatal("SSOWaiting should be false after cancel")
	}
	if m.LoginError.Get() != "" {
		t.Fatalf("LoginError after cancel = %q, want empty", m.LoginError.Get())
	}
}

func TestDesktopSSOWithEmailTwoFactor(t *testing.T) {
	svc := newMockVaultService(state.StatusLoggedOut)
	svc.twoFactorCode = "246810"
	svc.twoFactorProvider = api.TwoFactorEmail
	svc.twoFactorOffered = []api.TwoFactorProvider{api.TwoFactorEmail}
	openedCh := make(chan string, 1)
	var m *AppModel

	app := nsgotest.Start(t, func(cx *core.Scope) core.Node {
		m = NewAppModel(cx, svc, PlatformHooks{
			OpenURL: func(u string) { openedCh <- u },
		})
		m.MainWinVisible.Set(true)
		return MainWindowView(cx, m)
	}, nsgotest.Size(1100, 900))
	app.WaitFor("id:login-sso", 2*time.Second)

	app.Post(func() { m.LoginServer.Set("https://vault.example.com") })
	app.Press("id:login-sso")
	opened := <-openedCh
	redirectURI, st, _, _, _ := parseSSOOpenURL(t, opened)
	deliverSSOCallback(redirectURI, "sso-2fa-code", st)

	app.WaitFor("id:twofactor-screen", 2*time.Second)
	// SSO email-only 2FA must NOT claim an email was already sent before the
	// user triggers SendTwoFactorEmail (Vaultwarden does not auto-send on SSO).
	if got := m.TwoFactorNotice.Get(); got != "" {
		t.Fatalf("SSO email 2FA prematurely showed notice: %q", got)
	}
	app.Post(func() { m.SendTwoFactorEmail() })
	app.WaitFor("id:twofactor-screen", 2*time.Second)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		svc.mu.RLock()
		n := svc.ssoEmailSends
		tok := svc.ssoEmailToken
		addr := svc.ssoEmailAddr
		svc.mu.RUnlock()
		if n == 1 && tok == "mock-sso-email-token" && addr == "idp-alice@example.com" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	svc.mu.RLock()
	if svc.ssoEmailSends != 1 || svc.ssoEmailToken != "mock-sso-email-token" || svc.ssoEmailAddr != "idp-alice@example.com" {
		svc.mu.RUnlock()
		t.Fatalf("expected SSO email 2FA send with authoritative email + token, got sends=%d addr=%q tok=%q", svc.ssoEmailSends, svc.ssoEmailAddr, svc.ssoEmailToken)
	}
	svc.mu.RUnlock()

	app.Post(func() {
		m.TwoFactorCode.Set("246810")
		m.VerifyTwoFactor()
	})
	app.WaitFor("id:lock-screen", 2*time.Second)
}

func TestDesktopSSOErrorsAndServerRequired(t *testing.T) {
	svc := newMockVaultService(state.StatusLoggedOut)
	openedCh := make(chan string, 1)
	var m *AppModel

	app := nsgotest.Start(t, func(cx *core.Scope) core.Node {
		m = NewAppModel(cx, svc, PlatformHooks{
			OpenURL: func(u string) { openedCh <- u },
		})
		m.MainWinVisible.Set(true)
		return MainWindowView(cx, m)
	}, nsgotest.Size(1100, 900))
	app.WaitFor("id:login-sso", 2*time.Second)

	// Empty server URL shows a clear error without opening a browser.
	app.Post(func() { m.LoginServer.Set("") })
	app.Press("id:login-sso")
	app.WaitFor("id:login-error", 2*time.Second)
	if !strings.Contains(m.LoginError.Get(), "Server URL") {
		t.Fatalf("LoginError = %q, want Server URL error", m.LoginError.Get())
	}

	// Unsupported SSO account decryption path surfaces localized message.
	svc.ssoErr = state.ErrSSOMasterPasswordRequired
	app.Post(func() { m.LoginServer.Set("https://vault.example.com") })
	app.Press("id:login-sso")
	opened := <-openedCh
	redirectURI, st, _, _, _ := parseSSOOpenURL(t, opened)
	deliverSSOCallback(redirectURI, "sso-no-pw", st)
	app.WaitFor("id:login-error", 2*time.Second)
	if !strings.Contains(m.LoginError.Get(), "master password") {
		t.Fatalf("LoginError = %q, want master password guidance", m.LoginError.Get())
	}
}

func TestDesktopSSOReSignInBindsTrustedServerAndAccount(t *testing.T) {
	svc := newMockVaultService(state.StatusLocked)
	svc.trustedServer = "https://vault.trusted.test"
	openedCh := make(chan string, 1)
	var m *AppModel

	app := nsgotest.Start(t, func(cx *core.Scope) core.Node {
		m = NewAppModel(cx, svc, PlatformHooks{
			OpenURL: func(u string) { openedCh <- u },
		})
		m.MainWinVisible.Set(true)
		return MainWindowView(cx, m)
	}, nsgotest.Size(1100, 900))
	app.WaitFor("id:lock-screen", 2*time.Second)

	app.Post(func() { m.SignInAgain() })
	app.WaitFor("id:login-sso", 2*time.Second)
	app.Press("id:login-sso")

	opened := <-openedCh
	if !strings.HasPrefix(opened, "https://vault.trusted.test/#/sso?") {
		t.Fatalf("ReSignIn SSO URL = %q, want trusted server", opened)
	}
	redirectURI, st, _, _, _ := parseSSOOpenURL(t, opened)
	deliverSSOCallback(redirectURI, "resignin-code", st)
	app.WaitFor("id:lock-screen", 2*time.Second)

	svc.mu.RLock()
	got := svc.lastSSOLogin
	svc.mu.RUnlock()
	if got.SameAccount == nil || got.ServerURL != "https://vault.trusted.test" {
		t.Fatalf("ReSignIn LoginSSO = %+v, want SameAccount + trusted server", got)
	}
}

// TestDesktopSSORealServiceWithProductionStatusCallback exercises the exact
// production OnStatusChange wiring from cmd/govault/app.go (which calls
// RevokePending() and ServiceLeftUnlocked() on any non-unlocked status) for
// both initial SSO login and ReSignIn, ensuring SSO completion is never
// self-cancelled.
func TestDesktopSSORealServiceWithProductionStatusCallback(t *testing.T) {
	srv := fakeserver.New()
	defer srv.Close()
	srv.Configure(func(c *fakeserver.Config) {
		c.SSOEnabled = true
		c.SSOOnly = true
		c.StrictRefresh = true
	})

	secrets := newTestSecretStore()
	st := store.NewFileStore(t.TempDir())
	var m *AppModel
	var appScope *core.Scope

	svc, err := state.NewService(state.ServiceConfig{
		Store:      st,
		Secrets:    secrets,
		DeviceID:   "dev-prod-sso",
		DeviceName: "GoVault Desktop",
		DeviceType: 2,
		HTTPClient: srv.Client(),
		OnStatusChange: func(st state.LockStatus) {
			if st != state.StatusUnlocked && m != nil {
				m.RevokePending()
			}
			if appScope == nil {
				return
			}
			appScope.Post(func() {
				if m == nil {
					return
				}
				if st != state.StatusUnlocked {
					m.ServiceLeftUnlocked(st)
					return
				}
				m.LockState.Set(st)
			})
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	openedCh := make(chan string, 4)
	app := nsgotest.Start(t, func(cx *core.Scope) core.Node {
		appScope = cx
		m = NewAppModel(cx, svc, PlatformHooks{
			Secrets: secrets,
			OpenURL: func(u string) { openedCh <- u },
		})
		m.MainWinVisible.Set(true)
		return MainWindowView(cx, m)
	}, nsgotest.Size(1100, 900))
	app.WaitFor("id:login-sso", 2*time.Second)

	driveBrowser := func(opened string) {
		redirectURI, stParam, challenge, clientID, _ := parseSSOOpenURL(t, opened)
		authURL := srv.URL() + "/identity/connect/authorize?client_id=" + url.QueryEscape(clientID) +
			"&redirect_uri=" + url.QueryEscape(redirectURI) +
			"&response_type=code&scope=api%20offline_access" +
			"&state=" + url.QueryEscape(stParam+"_identifier=00000000-01DC-01DC-01DC-000000000000") +
			"&code_challenge=" + url.QueryEscape(challenge) +
			"&code_challenge_method=S256"
		go func() {
			resp, err := (&http.Client{}).Get(authURL)
			if err == nil {
				resp.Body.Close()
			}
		}()
	}

	// 1. First-time SSO login.
	app.Post(func() {
		m.LoginServer.Set(srv.URL())
		m.LoginEmail.Set(fakeserver.Email)
	})
	app.Press("id:login-sso")
	app.WaitFor("id:sso-waiting-screen", 2*time.Second)
	driveBrowser(<-openedCh)
	app.WaitFor("id:lock-screen", 3*time.Second)

	if m.LoginBusy.Get() || m.ReSignIn.Get() || m.LockState.Get() != state.StatusLocked {
		t.Fatalf("post-SSO state invalid: busy=%v resignin=%v lock=%v", m.LoginBusy.Get(), m.ReSignIn.Get(), m.LockState.Get())
	}
	prefs := m.Prefs.Get()
	if prefs.AccountID != fakeserver.UserID || prefs.Email != fakeserver.Email || prefs.ServerURL != srv.URL() {
		t.Fatalf("Prefs not updated after first SSO login: %+v", prefs)
	}

	// Unlock with master password -> vault opens.
	app.Post(func() {
		m.LockPassword.Set(fakeserver.Password)
		m.UnlockWithPassword()
	})
	app.WaitForGone("id:lock-screen", 3*time.Second)
	if m.LockState.Get() != state.StatusUnlocked {
		t.Fatalf("LockState = %v, want StatusUnlocked", m.LockState.Get())
	}

	// 2. Sign In Again via SSO must NOT get stuck on a busy login screen.
	app.Post(func() { m.SignInAgain() })
	app.WaitFor("id:login-sso", 2*time.Second)
	app.Press("id:login-sso")
	app.WaitFor("id:sso-waiting-screen", 2*time.Second)
	driveBrowser(<-openedCh)
	app.WaitFor("id:lock-screen", 3*time.Second)

	if m.LoginBusy.Get() || m.ReSignIn.Get() || m.LockState.Get() != state.StatusLocked {
		t.Fatalf("post-ReSignIn state invalid: busy=%v resignin=%v lock=%v", m.LoginBusy.Get(), m.ReSignIn.Get(), m.LockState.Get())
	}
	app.Post(func() {
		m.LockPassword.Set(fakeserver.Password)
		m.UnlockWithPassword()
	})
	app.WaitForGone("id:lock-screen", 3*time.Second)
	if m.LockState.Get() != state.StatusUnlocked {
		t.Fatalf("LockState after ReSignIn unlock = %v, want StatusUnlocked", m.LockState.Get())
	}
}

func TestDesktopSSOCancelRestartAndSleepIsolation(t *testing.T) {
	svc := newMockVaultService(state.StatusLoggedOut)
	openedCh := make(chan string, 4)
	var m *AppModel

	app := nsgotest.Start(t, func(cx *core.Scope) core.Node {
		m = NewAppModel(cx, svc, PlatformHooks{
			OpenURL: func(u string) { openedCh <- u },
		})
		m.MainWinVisible.Set(true)
		return MainWindowView(cx, m)
	}, nsgotest.Size(1100, 900))
	app.WaitFor("id:login-sso", 2*time.Second)

	// Start attempt 1, cancel, immediately start attempt 2.
	app.Post(func() { m.LoginServer.Set("https://vault.example.com") })
	app.Press("id:login-sso")
	app.WaitFor("id:sso-waiting-screen", 2*time.Second)
	firstOpened := <-openedCh

	app.Press("id:sso-cancel")
	app.WaitFor("id:login-screen", 2*time.Second)

	app.Press("id:login-sso")
	app.WaitFor("id:sso-waiting-screen", 2*time.Second)
	secondOpened := <-openedCh

	// A stale callback from attempt 1 must not break attempt 2.
	firstRedirect, firstState, _, _, _ := parseSSOOpenURL(t, firstOpened)
	deliverSSOCallback(firstRedirect, "stale-code", firstState)
	time.Sleep(50 * time.Millisecond)
	if !m.SSOWaiting.Get() {
		t.Fatal("stale attempt 1 callback must not cancel attempt 2")
	}

	// Attempt 2's own callback completes normally.
	secondRedirect, secondState, _, _, _ := parseSSOOpenURL(t, secondOpened)
	deliverSSOCallback(secondRedirect, "fresh-code", secondState)
	app.WaitFor("id:lock-screen", 2*time.Second)
	svc.mu.RLock()
	if svc.lastSSOLogin.Code != "fresh-code" {
		svc.mu.RUnlock()
		t.Fatalf("expected fresh-code, got %q", svc.lastSSOLogin.Code)
	}
	svc.mu.RUnlock()
}

func TestDesktopSSOSleepClearsWaitingAndPendingTwoFactor(t *testing.T) {
	svc := newMockVaultService(state.StatusLoggedOut)
	svc.twoFactorCode = "998877"
	svc.twoFactorProvider = api.TwoFactorAuthenticator
	svc.twoFactorOffered = []api.TwoFactorProvider{api.TwoFactorAuthenticator}
	openedCh := make(chan string, 4)
	var m *AppModel

	app := nsgotest.Start(t, func(cx *core.Scope) core.Node {
		m = NewAppModel(cx, svc, PlatformHooks{
			OpenURL: func(u string) { openedCh <- u },
		})
		m.MainWinVisible.Set(true)
		return MainWindowView(cx, m)
	}, nsgotest.Size(1100, 900))
	app.WaitFor("id:login-sso", 2*time.Second)

	// Sleep during browser wait clears SSOWaiting and returns to login screen.
	app.Post(func() { m.LoginServer.Set("https://vault.example.com") })
	app.Press("id:login-sso")
	app.WaitFor("id:sso-waiting-screen", 2*time.Second)
	<-openedCh
	app.Post(func() { m.LockOnSystemEvent() })
	app.WaitFor("id:login-screen", 2*time.Second)
	if m.SSOWaiting.Get() {
		t.Fatal("sleep must clear SSOWaiting")
	}

	// Sleep during SSO 2FA clears TwoFactor prompt and pendingSSO.
	app.Press("id:login-sso")
	opened := <-openedCh
	redirectURI, st, _, _, _ := parseSSOOpenURL(t, opened)
	deliverSSOCallback(redirectURI, "sso-sleep-2fa", st)
	app.WaitFor("id:twofactor-screen", 2*time.Second)
	app.Post(func() { m.LockOnSystemEvent() })
	app.WaitFor("id:login-screen", 2*time.Second)
	if m.TwoFactor.Get() != nil || m.pendingSSO != nil {
		t.Fatalf("sleep during SSO 2FA must clear TwoFactor and pendingSSO")
	}
}

func TestDesktopSSOCancelDuringInFlightEmailSendAllowsResendOnNextAttempt(t *testing.T) {
	svc := newMockVaultService(state.StatusLoggedOut)
	svc.twoFactorCode = "246810"
	svc.twoFactorProvider = api.TwoFactorEmail
	svc.twoFactorOffered = []api.TwoFactorProvider{api.TwoFactorEmail}
	gate := make(chan struct{})
	svc.emailGate = gate
	openedCh := make(chan string, 4)
	var m *AppModel

	app := nsgotest.Start(t, func(cx *core.Scope) core.Node {
		m = NewAppModel(cx, svc, PlatformHooks{
			OpenURL: func(u string) { openedCh <- u },
		})
		m.MainWinVisible.Set(true)
		return MainWindowView(cx, m)
	}, nsgotest.Size(1100, 900))
	app.WaitFor("id:login-sso", 2*time.Second)

	// Attempt 1: enter email 2FA, start sending email (blocked on gate), then cancel.
	app.Post(func() { m.LoginServer.Set("https://vault.example.com") })
	app.Press("id:login-sso")
	redirectURI, st, _, _, _ := parseSSOOpenURL(t, <-openedCh)
	deliverSSOCallback(redirectURI, "sso-send-1", st)
	app.WaitFor("id:twofactor-screen", 2*time.Second)

	app.Post(func() { m.SendTwoFactorEmail() })
	app.Settle()
	if !m.TwoFactorSending.Get() {
		t.Fatal("expected TwoFactorSending=true while send is in flight")
	}
	app.Press("id:twofactor-back")
	app.WaitFor("id:login-screen", 2*time.Second)
	if m.TwoFactorSending.Get() {
		t.Fatal("CancelTwoFactor must clear TwoFactorSending immediately")
	}

	// Release gate (old send completes late) and start attempt 2.
	svc.mu.Lock()
	svc.emailGate = nil
	svc.mu.Unlock()
	close(gate)

	app.Press("id:login-sso")
	redirectURI2, st2, _, _, _ := parseSSOOpenURL(t, <-openedCh)
	deliverSSOCallback(redirectURI2, "sso-send-2", st2)
	app.WaitFor("id:twofactor-screen", 2*time.Second)

	app.Post(func() { m.SendTwoFactorEmail() })
	app.WaitUntil(2*time.Second, func() bool {
		svc.mu.RLock()
		defer svc.mu.RUnlock()
		return svc.ssoEmailSends >= 2
	})
}

func TestDesktopSSOSleepAfterCommitBeforeUIPublicationReconcilesLockedAccount(t *testing.T) {
	svc := newMockVaultService(state.StatusLoggedOut)
	svc.trustedServer = "https://vault.example.com"
	gate := make(chan struct{})
	svc.ssoCommitted = gate
	openedCh := make(chan string, 2)
	var m *AppModel

	app := nsgotest.Start(t, func(cx *core.Scope) core.Node {
		m = NewAppModel(cx, svc, PlatformHooks{
			OpenURL: func(u string) { openedCh <- u },
		})
		m.MainWinVisible.Set(true)
		return MainWindowView(cx, m)
	}, nsgotest.Size(1100, 900))
	app.WaitFor("id:login-sso", 2*time.Second)

	app.Post(func() { m.LoginServer.Set("https://vault.example.com") })
	app.Press("id:login-sso")
	redirectURI, st, _, _, _ := parseSSOOpenURL(t, <-openedCh)
	deliverSSOCallback(redirectURI, "sso-commit-race", st)

	// Pump the UI loop until LoginSSO reaches the post-commit gate.
	app.WaitUntil(2*time.Second, func() bool {
		select {
		case <-gate:
			return true
		default:
			return false
		}
	})

	// System sleep lands right between commit and UI publication.
	app.Post(func() { m.LockOnSystemEvent() })
	app.Settle()
	// Let LoginSSO return to the UI callback.
	gate <- struct{}{}

	// App must reconcile to the locked account instead of waking on login-screen.
	app.WaitFor("id:lock-screen", 2*time.Second)
	if m.LockState.Get() != state.StatusLocked || m.LoginBusy.Get() || m.ReSignIn.Get() {
		t.Fatalf("post-sleep reconciled state invalid: lock=%v busy=%v resignin=%v", m.LockState.Get(), m.LoginBusy.Get(), m.ReSignIn.Get())
	}

	// Same post-commit sleep race during Sign In Again clears ReSignIn too.
	app.Post(func() { m.SignInAgain() })
	app.WaitFor("id:login-sso", 2*time.Second)
	app.Press("id:login-sso")
	redirectURI2, st2, _, _, _ := parseSSOOpenURL(t, <-openedCh)
	deliverSSOCallback(redirectURI2, "sso-resignin-commit-race", st2)
	app.WaitUntil(2*time.Second, func() bool {
		select {
		case <-gate:
			return true
		default:
			return false
		}
	})
	app.Post(func() { m.LockOnSystemEvent() })
	app.Settle()
	gate <- struct{}{}
	app.WaitFor("id:lock-screen", 2*time.Second)
	if m.LockState.Get() != state.StatusLocked || m.LoginBusy.Get() || m.ReSignIn.Get() {
		t.Fatalf("post-ReSignIn sleep state invalid: lock=%v busy=%v resignin=%v", m.LockState.Get(), m.LoginBusy.Get(), m.ReSignIn.Get())
	}
}
