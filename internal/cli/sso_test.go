package cli

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/txchen/govault/internal/fakeserver"
	"github.com/txchen/govault/internal/vaultcore/api"
)

// simulateBrowserSSO parses the web vault /#/sso URL that gv opened and
// drives fakeserver's /identity/connect/authorize redirect back to gv's
// localhost callback server.
func simulateBrowserSSO(t *testing.T, srv *fakeserver.Server, wantOrg string) func(string) error {
	t.Helper()
	return func(ssoURL string) error {
		t.Helper()
		_, frag, ok := strings.Cut(ssoURL, "/#/sso?")
		if !ok {
			t.Errorf("unexpected SSO URL %q", ssoURL)
			return nil
		}
		q, err := url.ParseQuery(frag)
		if err != nil {
			t.Errorf("parse SSO query: %v", err)
			return nil
		}
		if q.Get("clientId") != "cli" {
			t.Errorf("clientId = %q, want cli", q.Get("clientId"))
		}
		if wantOrg != "" && q.Get("identifier") != wantOrg {
			t.Errorf("identifier = %q, want %q", q.Get("identifier"), wantOrg)
		}
		state := q.Get("state")
		if id := q.Get("identifier"); id != "" {
			state += "_identifier=" + id
		}
		authURL := srv.URL() + "/identity/connect/authorize?client_id=" + url.QueryEscape(q.Get("clientId")) +
			"&redirect_uri=" + url.QueryEscape(q.Get("redirectUri")) +
			"&response_type=code&scope=api%20offline_access" +
			"&state=" + url.QueryEscape(state) +
			"&code_challenge=" + url.QueryEscape(q.Get("codeChallenge")) +
			"&code_challenge_method=S256"
		go func() {
			resp, err := (&http.Client{}).Get(authURL)
			if err == nil {
				resp.Body.Close()
			}
		}()
		return nil
	}
}

func TestLoginSSOAndUnlock(t *testing.T) {
	g := newGV(t)
	g.srv.Configure(func(c *fakeserver.Config) {
		c.SSOEnabled = true
		c.SSOOnly = true
	})
	g.openURL = simulateBrowserSSO(t, g.srv, "northwind")

	// Password login fails on SSO-only server.
	r := g.run("login", fakeserver.Email, fakeserver.Password)
	if r.code == 0 || !strings.Contains(r.err, "SSO sign-in is required") {
		t.Fatalf("password login = %+v, want SSO sign-in is required", r)
	}

	// SSO login succeeds and stays locked (keyring stores refresh token).
	r = g.run("login", "--sso", "northwind")
	if r.code != 0 {
		t.Fatalf("login --sso failed: %+v", r)
	}
	if !strings.Contains(r.out, "You are logged in!") || !strings.Contains(r.out, "gv unlock") {
		t.Fatalf("unexpected login --sso output: %q", r.out)
	}

	// Unlock with master password, then sync and list items.
	session := strings.TrimSpace(g.mustRun("unlock", fakeserver.Password, "--raw"))
	if session == "" {
		t.Fatal("expected session key from unlock")
	}
	g.mustRun("sync", "--session", session)
	items := g.mustRun("list", "items", "--session", session)
	if !strings.Contains(items, "GitHub") {
		t.Fatalf("expected decrypted vault items, got: %q", items)
	}
}

func TestLoginSSOWithTwoFactor(t *testing.T) {
	for _, tc := range []struct {
		name      string
		bitwarden bool
	}{
		{"vaultwarden_device_only", false},
		{"bitwarden_session_token", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := newGV(t)
			g.srv.Configure(func(c *fakeserver.Config) {
				c.SSOEnabled = true
				c.BitwardenSSOEmail2FA = tc.bitwarden
				c.TwoFactor = map[int]string{int(api.TwoFactorEmail): "445566"}
			})
			g.openURL = simulateBrowserSSO(t, g.srv, "")
			g.term = &scriptedTerminal{answers: []string{"445566"}}

			r := g.run("login", "--sso")
			if r.code != 0 {
				t.Fatalf("login --sso with 2FA failed: %+v", r)
			}
			if g.srv.EmailCodesSent() != 1 {
				t.Fatalf("EmailCodesSent = %d, want 1", g.srv.EmailCodesSent())
			}
		})
	}
}

func TestLoginSSOWithoutKeyringUnlocksToSealCredentials(t *testing.T) {
	g := newGV(t)
	g.ring = nil
	g.srv.Configure(func(c *fakeserver.Config) {
		c.SSOEnabled = true
		c.SSOOnly = true
		c.StrictRefresh = true
	})
	g.openURL = simulateBrowserSSO(t, g.srv, "")
	g.term = &scriptedTerminal{answers: []string{fakeserver.Password}}

	r := g.run("login", "--sso", "--raw")
	if r.code != 0 {
		t.Fatalf("keyring-free login --sso failed: %+v", r)
	}
	session := strings.TrimSpace(r.out)
	if session == "" {
		t.Fatal("expected session key when keyring-free login --sso unlocked")
	}
	// Expire access token and verify rotating refresh token renewal works.
	g.srv.RejectNextToken()
	g.mustRun("sync", "--session", session)
	if g.srv.GrantCount("refresh_token") < 1 {
		t.Fatalf("expected refresh_token renewal after expiry, got %d", g.srv.GrantCount("refresh_token"))
	}
}

func TestLoginSSOWithoutKeyringRejectsMissingPasswordWithoutCommitting(t *testing.T) {
	cases := []struct {
		name string
		prep func(t *testing.T, g *gvTest) []string
	}{
		{
			name: "eof prompt",
			prep: func(_ *testing.T, g *gvTest) []string {
				g.term = &scriptedTerminal{} // returns error on ReadSecret
				return []string{"login", "--sso"}
			},
		},
		{
			name: "empty prompt",
			prep: func(_ *testing.T, g *gvTest) []string {
				g.term = &scriptedTerminal{answers: []string{""}}
				return []string{"login", "--sso"}
			},
		},
		{
			name: "empty password file",
			prep: func(t *testing.T, _ *gvTest) []string {
				p := filepath.Join(t.TempDir(), "empty.pw")
				if err := os.WriteFile(p, nil, 0o600); err != nil {
					t.Fatal(err)
				}
				return []string{"login", "--sso", "--passwordfile", p}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := newGV(t)
			g.ring = nil
			g.srv.Configure(func(c *fakeserver.Config) { c.SSOEnabled = true })
			g.openURL = simulateBrowserSSO(t, g.srv, "")
			args := tc.prep(t, g)

			r := g.run(args...)
			if r.code == 0 {
				t.Fatalf("expected failure when keyring-free SSO has no password, got: %+v", r)
			}
			// No account must have been committed.
			st := g.mustRun("status")
			if !strings.Contains(st, `"unauthenticated"`) {
				t.Fatalf("expected unauthenticated after failed keyring-free login, got: %s", st)
			}
		})
	}
}

func TestLoginSSORejectsConcurrentConfigChangeBeforeTokenExchange(t *testing.T) {
	g := newGV(t)
	g.srv.Configure(func(c *fakeserver.Config) { c.SSOEnabled = true })
	other := fakeserver.New()
	defer other.Close()

	// While the browser is completing SSO, mutate the identity server override.
	g.openURL = func(ssoURL string) error {
		g.mustRun("config", "server", g.srv.URL(), "--identity", other.URL()+"/identity")
		return simulateBrowserSSO(t, g.srv, "")(ssoURL)
	}

	r := g.run("login", "--sso")
	if r.code == 0 {
		t.Fatalf("expected login --sso to fail after concurrent config change, got: %+v", r)
	}
	if len(other.Requests()) != 0 {
		t.Fatalf("code/verifier leaked to mutated identity server: %d requests", len(other.Requests()))
	}
	if g.srv.GrantCount("authorization_code") != 0 {
		t.Fatalf("authorization_code should not have been exchanged after config drift")
	}
}

func TestLoginSSOForcePasswordResetRejected(t *testing.T) {
	g := newGV(t)
	g.srv.Configure(func(c *fakeserver.Config) {
		c.SSOEnabled = true
		c.SSODecryptionMode = "force_reset"
	})
	g.openURL = simulateBrowserSSO(t, g.srv, "")

	r := g.run("login", "--sso")
	if r.code == 0 || !strings.Contains(r.err, "reset") {
		t.Fatalf("expected force password reset rejection, got: %+v", r)
	}
	st := g.mustRun("status")
	if !strings.Contains(st, `"unauthenticated"`) {
		t.Fatalf("expected unauthenticated after force reset rejection, got: %s", st)
	}
}

func TestLoginSSOCustomMixedCaseSalt(t *testing.T) {
	const customSalt = "Custom-Salt-MixedCase@Org"
	for _, keyringEnabled := range []bool{true, false} {
		name := "with_keyring"
		if !keyringEnabled {
			name = "without_keyring"
		}
		t.Run(name, func(t *testing.T) {
			g := newGV(t, fakeserver.WithCustomSalt(customSalt))
			if !keyringEnabled {
				g.ring = nil
				g.term = &scriptedTerminal{answers: []string{fakeserver.Password}}
			}
			g.srv.Configure(func(c *fakeserver.Config) {
				c.SSOEnabled = true
				c.StrictRefresh = true
			})
			g.openURL = simulateBrowserSSO(t, g.srv, "")

			var session string
			if keyringEnabled {
				g.mustRun("login", "--sso")
				session = strings.TrimSpace(g.mustRun("unlock", fakeserver.Password, "--raw"))
			} else {
				session = strings.TrimSpace(g.mustRun("login", "--sso", "--raw"))
			}
			st := g.mustRun("status", "--session", session)
			if !strings.Contains(st, `"`+fakeserver.Email+`"`) {
				t.Fatalf("status should keep authoritative email %q, got: %s", fakeserver.Email, st)
			}
			g.srv.RejectNextToken()
			g.mustRun("sync", "--session", session)
		})
	}
}

func TestLoginSSONoInteractionRejected(t *testing.T) {
	g := newGV(t)
	r := g.run("login", "--sso", "--nointeraction")
	if r.code == 0 || !strings.Contains(r.err, "interactive") {
		t.Fatalf("expected non-interactive rejection, got: %+v", r)
	}
}
