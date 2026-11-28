package state_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/txchen/govault/internal/fakeserver"
	"github.com/txchen/govault/internal/vaultcore/api"
	"github.com/txchen/govault/internal/vaultcore/state"
	"github.com/txchen/govault/internal/vaultcore/store"
)

func newSSOService(t *testing.T, srv *fakeserver.Server) (*state.Service, memSecrets) {
	t.Helper()
	st := store.NewFileStore(t.TempDir())
	sec := memSecrets{}
	svc, err := state.NewService(state.ServiceConfig{
		Store:      st,
		Secrets:    sec,
		DeviceID:   "dev-sso-1",
		DeviceName: "GoVault",
		DeviceType: 2,
		HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc, sec
}

func completeBrowserSSO(t *testing.T, srv *fakeserver.Server, clientID string) (code, verifier, redirectURI string) {
	t.Helper()
	pkce, err := api.NewSSOPKCE()
	if err != nil {
		t.Fatal(err)
	}
	cb, err := api.StartSSOCallback(pkce.State, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer cb.Close()

	// Exercise the server's /identity/connect/authorize -> redirect to localhost callback.
	authURL := srv.URL() + "/identity/connect/authorize?client_id=" + clientID +
		"&redirect_uri=" + cb.RedirectURI() +
		"&response_type=code&scope=api%20offline_access" +
		"&state=" + pkce.State + "_identifier=00000000-01DC-01DC-01DC-000000000000" +
		"&code_challenge=" + pkce.CodeChallenge +
		"&code_challenge_method=S256"

	go func() {
		resp, err := (&http.Client{}).Get(authURL)
		if err == nil {
			resp.Body.Close()
		}
	}()

	res, err := cb.Wait(context.Background())
	if err != nil {
		t.Fatalf("SSO callback failed: %v", err)
	}
	return res.Code, pkce.CodeVerifier, cb.RedirectURI()
}

func TestLoginSSOAndUnlockOnSSOOnlyServer(t *testing.T) {
	srv := fakeserver.New()
	defer srv.Close()
	srv.Configure(func(c *fakeserver.Config) {
		c.SSOEnabled = true
		c.SSOOnly = true
	})

	svc, _ := newSSOService(t, srv)
	ctx := context.Background()

	// Reproduce Issue #8: password login is refused with 400 "SSO sign-in is required".
	err := svc.Login(ctx, state.LoginRequest{
		ServerURL:      srv.URL(),
		Email:          fakeserver.Email,
		MasterPassword: []byte(fakeserver.Password),
	})
	var apiErr *api.APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != 400 || apiErr.Message != "SSO sign-in is required" {
		t.Fatalf("password login err = %v, want 400 SSO sign-in is required", err)
	}

	// Complete browser SSO flow and exchange authorization_code.
	code, verifier, redirectURI := completeBrowserSSO(t, srv, "desktop")
	if err := svc.LoginSSO(ctx, state.SSOLoginRequest{
		ServerURL:    srv.URL(),
		Code:         code,
		CodeVerifier: verifier,
		RedirectURI:  redirectURI,
	}); err != nil {
		t.Fatalf("LoginSSO: %v", err)
	}

	// Vault must stay locked until master password is entered.
	if svc.Status() != state.StatusLocked {
		t.Fatalf("status = %v, want StatusLocked", svc.Status())
	}
	acct := svc.Account()
	if acct.ID != fakeserver.UserID || acct.Email != fakeserver.Email {
		t.Fatalf("Account() = %+v, want %s/%s", acct, fakeserver.UserID, fakeserver.Email)
	}
	if got := svc.TrustedServerURL(acct.ID); got != srv.URL() {
		t.Fatalf("TrustedServerURL = %q, want %q", got, srv.URL())
	}

	// Unlock with master password decrypts the vault and syncs using the saved refresh token.
	if err := svc.UnlockWithPassword(ctx, []byte(fakeserver.Password)); err != nil {
		t.Fatalf("UnlockWithPassword: %v", err)
	}
	if svc.Status() != state.StatusUnlocked || svc.LocalOnly() {
		t.Fatalf("status=%v localOnly=%v, want unlocked online", svc.Status(), svc.LocalOnly())
	}
	if len(svc.AllCiphers()) == 0 {
		t.Fatal("expected decrypted ciphers after SSO + unlock")
	}
	if err := svc.SyncNow(ctx); err != nil {
		t.Fatalf("SyncNow after SSO unlock: %v", err)
	}
}

func TestLoginSSOWithTwoFactorAndEmailSend(t *testing.T) {
	for _, tc := range []struct {
		name      string
		bitwarden bool
	}{
		{"vaultwarden_device_only", false},
		{"bitwarden_session_token", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := fakeserver.New()
			defer srv.Close()
			srv.Configure(func(c *fakeserver.Config) {
				c.SSOEnabled = true
				c.BitwardenSSOEmail2FA = tc.bitwarden
				c.TwoFactor = map[int]string{
					int(api.TwoFactorAuthenticator): "654321",
					int(api.TwoFactorEmail):         "112233",
				}
			})

			svc, _ := newSSOService(t, srv)
			ctx := context.Background()
			code, verifier, redirectURI := completeBrowserSSO(t, srv, "desktop")

			err := svc.LoginSSO(ctx, state.SSOLoginRequest{
				ServerURL:    srv.URL(),
				Code:         code,
				CodeVerifier: verifier,
				RedirectURI:  redirectURI,
			})
			var tfErr *api.TwoFactorRequiredError
			if !errors.As(err, &tfErr) {
				t.Fatalf("err = %v, want TwoFactorRequiredError", err)
			}
			if tc.bitwarden && (tfErr.Challenge.SSOEmail2FASessionToken == "" || tfErr.Challenge.Email != fakeserver.Email) {
				t.Fatalf("Bitwarden challenge missing email/token: %+v", tfErr.Challenge)
			}
			if !tc.bitwarden && tfErr.Challenge.SSOEmail2FASessionToken != "" {
				t.Fatalf("Vaultwarden challenge unexpectedly set token: %+v", tfErr.Challenge)
			}

			if err := svc.SendEmailTwoFactorCodeSSO(ctx, srv.URL(), tfErr.Challenge.Email, tfErr.Challenge.SSOEmail2FASessionToken); err != nil {
				t.Fatalf("SendEmailTwoFactorCodeSSO: %v", err)
			}
			if srv.EmailCodesSent() != 1 {
				t.Fatalf("EmailCodesSent = %d, want 1", srv.EmailCodesSent())
			}

			// Retry with same authorization code + 2FA token (as Vaultwarden supports).
			if err := svc.LoginSSO(ctx, state.SSOLoginRequest{
				ServerURL:         srv.URL(),
				Code:              code,
				CodeVerifier:      verifier,
				RedirectURI:       redirectURI,
				TwoFactorProvider: api.TwoFactorEmail,
				TwoFactorCode:     "112233",
				RememberDevice:    true,
			}); err != nil {
				t.Fatalf("LoginSSO with 2FA: %v", err)
			}
			if svc.Status() != state.StatusLocked {
				t.Fatalf("status = %v, want StatusLocked", svc.Status())
			}
		})
	}
}

func TestLoginSSOUnsupportedDecryptionModes(t *testing.T) {
	cases := []struct {
		mode string
		want error
	}{
		{"no_password", state.ErrSSOMasterPasswordRequired},
		{"force_reset", state.ErrSSOForcePasswordReset},
		{"key_connector", state.ErrSSOKeyConnectorUnsupported},
		{"trusted_device", state.ErrSSOTrustedDeviceUnsupported},
	}
	for _, tc := range cases {
		t.Run(tc.mode, func(t *testing.T) {
			srv := fakeserver.New()
			defer srv.Close()
			srv.Configure(func(c *fakeserver.Config) {
				c.SSOEnabled = true
				c.SSODecryptionMode = tc.mode
			})
			svc, _ := newSSOService(t, srv)
			code, verifier, redirectURI := completeBrowserSSO(t, srv, "desktop")
			err := svc.LoginSSO(context.Background(), state.SSOLoginRequest{
				ServerURL:    srv.URL(),
				Code:         code,
				CodeVerifier: verifier,
				RedirectURI:  redirectURI,
			})
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if svc.Status() != state.StatusLoggedOut {
				t.Fatalf("status = %v, want StatusLoggedOut", svc.Status())
			}
		})
	}
}

func TestLoginSSOSameAccountReSignIn(t *testing.T) {
	srv := fakeserver.New()
	defer srv.Close()
	srv.Configure(func(c *fakeserver.Config) { c.SSOEnabled = true; c.SSOOnly = true })

	other := fakeserver.New()
	defer other.Close()
	other.Configure(func(c *fakeserver.Config) { c.SSOEnabled = true })

	svc, _ := newSSOService(t, srv)
	ctx := context.Background()

	// Initial SSO sign-in.
	code, verifier, redirectURI := completeBrowserSSO(t, srv, "desktop")
	if err := svc.LoginSSO(ctx, state.SSOLoginRequest{
		ServerURL: srv.URL(), Code: code, CodeVerifier: verifier, RedirectURI: redirectURI,
	}); err != nil {
		t.Fatal(err)
	}
	acct := svc.Account()
	same := state.Account{ID: acct.ID, ServerURL: srv.URL(), Email: acct.Email}

	// Re-sign-in targeting a different server is refused before any request hits other.
	err := svc.LoginSSO(ctx, state.SSOLoginRequest{
		ServerURL: other.URL(), Code: "x", CodeVerifier: "y", RedirectURI: "http://localhost:8065",
		SameAccount: &same,
	})
	if !errors.Is(err, state.ErrDifferentAccount) {
		t.Fatalf("err = %v, want ErrDifferentAccount", err)
	}
	if len(other.Requests()) != 0 {
		t.Fatalf("other server received %d requests, want 0", len(other.Requests()))
	}

	// Re-sign-in to the same server succeeds.
	code2, verifier2, redirectURI2 := completeBrowserSSO(t, srv, "desktop")
	if err := svc.LoginSSO(ctx, state.SSOLoginRequest{
		ServerURL: srv.URL(), Code: code2, CodeVerifier: verifier2, RedirectURI: redirectURI2,
		SameAccount: &same,
	}); err != nil {
		t.Fatalf("same-account SSO re-sign-in failed: %v", err)
	}
}

func TestLoginSSOCustomMixedCaseSalt(t *testing.T) {
	const customSalt = "Custom-Salt-MixedCase@Org"
	srv := fakeserver.New(fakeserver.WithCustomSalt(customSalt))
	defer srv.Close()
	srv.Configure(func(c *fakeserver.Config) { c.SSOEnabled = true })

	svc, _ := newSSOService(t, srv)
	ctx := context.Background()
	code, verifier, redirectURI := completeBrowserSSO(t, srv, "desktop")
	if err := svc.LoginSSO(ctx, state.SSOLoginRequest{
		ServerURL: srv.URL(), Code: code, CodeVerifier: verifier, RedirectURI: redirectURI,
	}); err != nil {
		t.Fatalf("LoginSSO: %v", err)
	}

	// Account email stays the authoritative email, never overwritten by salt.
	if got := svc.Account().Email; got != fakeserver.Email {
		t.Fatalf("Account().Email = %q, want %q", got, fakeserver.Email)
	}
	// Unlock derives using the preserved mixed-case salt.
	if err := svc.UnlockWithPassword(ctx, []byte(fakeserver.Password)); err != nil {
		t.Fatalf("UnlockWithPassword with custom salt: %v", err)
	}
	if len(svc.AllCiphers()) == 0 {
		t.Fatal("expected decrypted ciphers after custom-salt unlock")
	}
}

func TestLoginSSOSubpathInstallationsAndSubjectMismatch(t *testing.T) {
	srv := fakeserver.New(fakeserver.WithPrefix("/vw1"))
	defer srv.Close()
	srv.Configure(func(c *fakeserver.Config) { c.SSOEnabled = true })

	svc, _ := newSSOService(t, srv)
	ctx := context.Background()
	code, verifier, redirectURI := completeBrowserSSO(t, srv, "desktop")
	if err := svc.LoginSSO(ctx, state.SSOLoginRequest{
		ServerURL: srv.URL(), Code: code, CodeVerifier: verifier, RedirectURI: redirectURI,
	}); err != nil {
		t.Fatalf("LoginSSO: %v", err)
	}

	// Same host, different installation subpath must be rejected by SameAccount.
	acct := svc.Account()
	same := state.Account{ID: acct.ID, ServerURL: srv.URL(), Email: acct.Email}
	otherPath := srv.URL()[:len(srv.URL())-len("/vw1")] + "/vw2"
	err := svc.LoginSSO(ctx, state.SSOLoginRequest{
		ServerURL: otherPath, Code: "x", CodeVerifier: "y", RedirectURI: "http://localhost:8065",
		SameAccount: &same,
	})
	if !errors.Is(err, state.ErrDifferentAccount) {
		t.Fatalf("cross-subpath SameAccount err = %v, want ErrDifferentAccount", err)
	}

	// Token subject mismatch with /api/sync profile.id is rejected.
	badSrv := fakeserver.New()
	defer badSrv.Close()
	badSrv.Configure(func(c *fakeserver.Config) {
		c.SSOEnabled = true
		c.Subject = "99999999-9999-4999-8999-999999999999"
	})
	svc2, _ := newSSOService(t, badSrv)
	code2, verifier2, redirectURI2 := completeBrowserSSO(t, badSrv, "desktop")
	if err := svc2.LoginSSO(ctx, state.SSOLoginRequest{
		ServerURL: badSrv.URL(), Code: code2, CodeVerifier: verifier2, RedirectURI: redirectURI2,
	}); !errors.Is(err, state.ErrDifferentAccount) {
		t.Fatalf("subject mismatch err = %v, want ErrDifferentAccount", err)
	}
	if svc2.Status() != state.StatusLoggedOut {
		t.Fatalf("status after subject mismatch = %v, want StatusLoggedOut", svc2.Status())
	}
}

type failingSecretStore struct{ err error }

func (f failingSecretStore) Get(string) (string, bool, error) { return "", false, nil }
func (f failingSecretStore) Set(string, string) error         { return f.err }
func (f failingSecretStore) Delete(string) error              { return nil }

func TestLoginSSORollsBackSnapshotOnSecretStoreFailure(t *testing.T) {
	srv := fakeserver.New()
	defer srv.Close()
	srv.Configure(func(c *fakeserver.Config) { c.SSOEnabled = true })

	st := store.NewFileStore(t.TempDir())
	wantErr := errors.New("keychain locked")
	svc, err := state.NewService(state.ServiceConfig{
		Store:      st,
		Secrets:    failingSecretStore{err: wantErr},
		DeviceID:   "dev-rollback",
		DeviceName: "GoVault",
		DeviceType: 2,
		HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}

	code, verifier, redirectURI := completeBrowserSSO(t, srv, "desktop")
	if err := svc.LoginSSO(context.Background(), state.SSOLoginRequest{
		ServerURL: srv.URL(), Code: code, CodeVerifier: verifier, RedirectURI: redirectURI,
	}); !errors.Is(err, wantErr) {
		t.Fatalf("err = %v, want %v", err, wantErr)
	}
	if _, err := st.LoadSnapshot(fakeserver.UserID); !errors.Is(err, store.ErrSnapshotNotFound) {
		t.Fatalf("expected rolled-back snapshot, LoadSnapshot err = %v", err)
	}
}

func TestLoginSSORefreshAfterRestartAndExpiry(t *testing.T) {
	srv := fakeserver.New()
	defer srv.Close()
	srv.Configure(func(c *fakeserver.Config) {
		c.SSOEnabled = true
		c.SSOOnly = true
		c.StrictRefresh = true
	})

	dir := t.TempDir()
	st := store.NewFileStore(dir)
	sec := memSecrets{}
	ctx := context.Background()

	svc1, err := state.NewService(state.ServiceConfig{
		Store: st, Secrets: sec, DeviceID: "dev-restart", DeviceName: "GoVault", DeviceType: 2, HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	code, verifier, redirectURI := completeBrowserSSO(t, srv, "desktop")
	if err := svc1.LoginSSO(ctx, state.SSOLoginRequest{
		ServerURL: srv.URL(), Code: code, CodeVerifier: verifier, RedirectURI: redirectURI,
	}); err != nil {
		t.Fatal(err)
	}

	// Simulate app restart with a fresh Service instance loading the snapshot.
	svc2, err := state.NewService(state.ServiceConfig{
		Store: st, Secrets: sec, AccountID: fakeserver.UserID,
		DeviceID: "dev-restart", DeviceName: "GoVault", DeviceType: 2, HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc2.UnlockWithPassword(ctx, []byte(fakeserver.Password)); err != nil {
		t.Fatalf("UnlockWithPassword after restart: %v", err)
	}
	srv.RejectNextToken()
	if err := svc2.SyncNow(ctx); err != nil {
		t.Fatalf("SyncNow after expiry + restart: %v", err)
	}
	if srv.GrantCount("refresh_token") < 1 {
		t.Fatalf("expected refresh_token renewal, got %d", srv.GrantCount("refresh_token"))
	}
}

type scriptedSecretStore struct {
	data      map[string]string
	failGet   func(key string) error
	failSet   func(key string) error
}

func (s *scriptedSecretStore) Get(k string) (string, bool, error) {
	if s.failGet != nil {
		if err := s.failGet(k); err != nil {
			return "", false, err
		}
	}
	v, ok := s.data[k]
	return v, ok, nil
}
func (s *scriptedSecretStore) Set(k, v string) error {
	if s.failSet != nil {
		if err := s.failSet(k); err != nil {
			return err
		}
	}
	s.data[k] = v
	return nil
}
func (s *scriptedSecretStore) Delete(k string) error {
	delete(s.data, k)
	return nil
}

type failLoadStore struct {
	store.Store
	failLoad error
}

func (f *failLoadStore) LoadSnapshot(accountID string) (*store.Snapshot, error) {
	if f.failLoad != nil {
		return nil, f.failLoad
	}
	return f.Store.LoadSnapshot(accountID)
}

func TestLoginSSORollbackPreservesExistingAccountOnReadAndSecondSecretFailure(t *testing.T) {
	srv := fakeserver.New()
	defer srv.Close()
	srv.Configure(func(c *fakeserver.Config) { c.SSOEnabled = true })

	baseStore := store.NewFileStore(t.TempDir())
	sec := &scriptedSecretStore{data: map[string]string{}}
	ctx := context.Background()

	svc, err := state.NewService(state.ServiceConfig{
		Store: baseStore, Secrets: sec, DeviceID: "dev-orig", DeviceName: "GoVault", DeviceType: 2, HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	// Seed an existing signed-in account.
	code, verifier, redirectURI := completeBrowserSSO(t, srv, "desktop")
	if err := svc.LoginSSO(ctx, state.SSOLoginRequest{
		ServerURL: srv.URL(), Code: code, CodeVerifier: verifier, RedirectURI: redirectURI,
	}); err != nil {
		t.Fatal(err)
	}
	origRefresh := sec.data["refresh_token:"+fakeserver.UserID]
	origSignIn := sec.data["signin:"+fakeserver.UserID]
	origSnap, err := baseStore.LoadSnapshot(fakeserver.UserID)
	if err != nil {
		t.Fatal(err)
	}

	// 1. A snapshot backup read error must abort before overwriting or deleting anything.
	readErr := errors.New("disk I/O error")
	flakyStore := &failLoadStore{Store: baseStore, failLoad: readErr}
	svcReadFail, err := state.NewService(state.ServiceConfig{
		Store: flakyStore, Secrets: sec, DeviceID: "dev-orig", DeviceName: "GoVault", DeviceType: 2, HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	code2, verifier2, redirectURI2 := completeBrowserSSO(t, srv, "desktop")
	if err := svcReadFail.LoginSSO(ctx, state.SSOLoginRequest{
		ServerURL: srv.URL(), Code: code2, CodeVerifier: verifier2, RedirectURI: redirectURI2,
	}); !errors.Is(err, readErr) {
		t.Fatalf("expected snapshot read error, got %v", err)
	}
	if _, err := baseStore.LoadSnapshot(fakeserver.UserID); err != nil {
		t.Fatalf("existing snapshot lost after backup read failure: %v", err)
	}

	// 2. A keychain read error before write must abort without deleting anything.
	keychainReadErr := errors.New("keychain read denied")
	sec.failGet = func(k string) error {
		if strings.HasPrefix(k, "refresh_token:") {
			return keychainReadErr
		}
		return nil
	}
	code3, verifier3, redirectURI3 := completeBrowserSSO(t, srv, "desktop")
	if err := svc.LoginSSO(ctx, state.SSOLoginRequest{
		ServerURL: srv.URL(), Code: code3, CodeVerifier: verifier3, RedirectURI: redirectURI3,
	}); !errors.Is(err, keychainReadErr) {
		t.Fatalf("expected keychain read error, got %v", err)
	}
	sec.failGet = nil
	if sec.data["refresh_token:"+fakeserver.UserID] != origRefresh || sec.data["signin:"+fakeserver.UserID] != origSignIn {
		t.Fatal("existing secrets modified after keychain backup read failure")
	}

	// 3. Failure on the SECOND secret write (signin:) after refresh_token: succeeded
	// must restore BOTH the original snapshot AND the original refresh token.
	secondWriteErr := errors.New("signin write failed")
	sec.failSet = func(k string) error {
		if strings.HasPrefix(k, "signin:") {
			return secondWriteErr
		}
		return nil
	}
	code4, verifier4, redirectURI4 := completeBrowserSSO(t, srv, "desktop")
	if err := svc.LoginSSO(ctx, state.SSOLoginRequest{
		ServerURL: srv.URL(), Code: code4, CodeVerifier: verifier4, RedirectURI: redirectURI4,
	}); !errors.Is(err, secondWriteErr) {
		t.Fatalf("expected second secret write error, got %v", err)
	}
	sec.failSet = nil
	if sec.data["refresh_token:"+fakeserver.UserID] != origRefresh {
		t.Fatalf("refresh token not restored: got %q want %q", sec.data["refresh_token:"+fakeserver.UserID], origRefresh)
	}
	if sec.data["signin:"+fakeserver.UserID] != origSignIn {
		t.Fatalf("signin record not restored: got %q want %q", sec.data["signin:"+fakeserver.UserID], origSignIn)
	}
	afterSnap, err := baseStore.LoadSnapshot(fakeserver.UserID)
	if err != nil || !afterSnap.LastSyncAt.Equal(origSnap.LastSyncAt) {
		t.Fatalf("snapshot not restored: err=%v got=%v want=%v", err, afterSnap, origSnap)
	}

	// Reopening the service still unlocks and syncs the original account.
	reopened, err := state.NewService(state.ServiceConfig{
		Store: baseStore, Secrets: sec, AccountID: fakeserver.UserID,
		DeviceID: "dev-orig", DeviceName: "GoVault", DeviceType: 2, HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.UnlockWithPassword(ctx, []byte(fakeserver.Password)); err != nil {
		t.Fatalf("UnlockWithPassword after rollback: %v", err)
	}
	if reopened.LocalOnly() {
		t.Fatal("original account became local-only after rollback")
	}
	if err := reopened.SyncNow(ctx); err != nil {
		t.Fatalf("SyncNow after rollback: %v", err)
	}
}

func TestLegacyV0RefreshTokenUpgradeDisambiguation(t *testing.T) {
	for _, prefix := range []string{"", "/vw1"} {
		name := "root"
		if prefix != "" {
			name = "subpath"
		}
		t.Run(name, func(t *testing.T) {
			var opts []fakeserver.Option
			if prefix != "" {
				opts = append(opts, fakeserver.WithPrefix(prefix))
			}
			srv := fakeserver.New(opts...)
			defer srv.Close()
			srv.Configure(func(c *fakeserver.Config) { c.SSOEnabled = true })

			st := store.NewFileStore(t.TempDir())
			sec := memSecrets{}
			ctx := context.Background()

			// Sign in once so snapshot + signin record exist.
			svc1, err := state.NewService(state.ServiceConfig{
				Store: st, Secrets: sec, DeviceID: "dev-061", DeviceName: "GoVault", DeviceType: 2, HTTPClient: srv.Client(),
			})
			if err != nil {
				t.Fatal(err)
			}
			code, verifier, redirectURI := completeBrowserSSO(t, srv, "desktop")
			if err := svc1.LoginSSO(ctx, state.SSOLoginRequest{
				ServerURL: srv.URL(), Code: code, CodeVerifier: verifier, RedirectURI: redirectURI,
			}); err != nil {
				t.Fatal(err)
			}

			// Extract actual refresh token and overwrite it in GoVault 0.6.1 host-only format (no "v", no path).
			var cur struct {
				Token string `json:"token"`
			}
			if err := json.Unmarshal([]byte(sec["refresh_token:"+fakeserver.UserID]), &cur); err != nil {
				t.Fatal(err)
			}
			u, _ := url.Parse(srv.URL())
			legacyOrigin := u.Scheme + "://" + u.Host
			legacyRaw, _ := json.Marshal(map[string]string{"origin": legacyOrigin, "token": cur.Token})
			sec["refresh_token:"+fakeserver.UserID] = string(legacyRaw)

			// 1. Unchanged snapshot + trusted signin record upgrades cleanly (online, not local-only).
			reopened, err := state.NewService(state.ServiceConfig{
				Store: st, Secrets: sec, AccountID: fakeserver.UserID,
				DeviceID: "dev-061", DeviceName: "GoVault", DeviceType: 2, HTTPClient: srv.Client(),
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := reopened.UnlockWithPassword(ctx, []byte(fakeserver.Password)); err != nil {
				t.Fatal(err)
			}
			if reopened.LocalOnly() {
				t.Fatalf("0.6.1 %s profile with trusted signin record should stay online", name)
			}
			if err := reopened.SyncNow(ctx); err != nil {
				t.Fatalf("SyncNow on upgraded 0.6.1 %s profile: %v", name, err)
			}

			// 2. Tampering snapshot to a different path on the same host (e.g. root vs /vw1 or /vw2)
			// must unlock local-only even with a host-only 0.6.1 token!
			sec["refresh_token:"+fakeserver.UserID] = string(legacyRaw)
			snap, err := st.LoadSnapshot(fakeserver.UserID)
			if err != nil {
				t.Fatal(err)
			}
			origURL := snap.ServerURL
			if prefix == "" {
				snap.ServerURL = legacyOrigin + "/other"
			} else {
				snap.ServerURL = legacyOrigin // root instead of /vw1
			}
			if err := st.SaveSnapshot(snap); err != nil {
				t.Fatal(err)
			}
			tampered, err := state.NewService(state.ServiceConfig{
				Store: st, Secrets: sec, AccountID: fakeserver.UserID,
				DeviceID: "dev-061", DeviceName: "GoVault", DeviceType: 2, HTTPClient: srv.Client(),
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := tampered.UnlockWithPassword(ctx, []byte(fakeserver.Password)); err != nil {
				t.Fatal(err)
			}
			if !tampered.LocalOnly() {
				t.Fatalf("tampered snapshot path on 0.6.1 %s token must unlock local-only", name)
			}

			// 3. Without a trusted signin record, a host-only 0.6.1 token cannot be
			// disambiguated and requires one fresh sign-in (local-only).
			snap.ServerURL = origURL
			if err := st.SaveSnapshot(snap); err != nil {
				t.Fatal(err)
			}
			delete(sec, "signin:"+fakeserver.UserID)
			noRecord, err := state.NewService(state.ServiceConfig{
				Store: st, Secrets: sec, AccountID: fakeserver.UserID,
				DeviceID: "dev-061", DeviceName: "GoVault", DeviceType: 2, HTTPClient: srv.Client(),
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := noRecord.UnlockWithPassword(ctx, []byte(fakeserver.Password)); err != nil {
				t.Fatal(err)
			}
			if !noRecord.LocalOnly() {
				t.Fatalf("0.6.1 %s token without trusted signin record must unlock local-only", name)
			}
		})
	}
}
