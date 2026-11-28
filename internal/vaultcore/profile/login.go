package profile

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/txchen/govault/internal/vaultcore/api"
	"github.com/txchen/govault/internal/vaultcore/crypto"
	"github.com/txchen/govault/internal/vaultcore/store"
)

// PasswordLogin is a password login in progress: the master key is
// derived once, then the login completes, possibly after a two-step
// challenge.
type PasswordLogin struct {
	p         *Profile
	ps        *profileState
	endpoints api.Endpoints
	client    *api.Client
	email     string
	kdf       crypto.KDFConfig
	masterKey [32]byte
	hash      string
}

// BeginPasswordLogin derives the master key for email at the configured
// server. It refuses while an account is signed in.
// beforeAccountCommit, set by tests, runs just before a login writes the
// active account record.
var beforeAccountCommit func() error

func (p *Profile) BeginPasswordLogin(ctx context.Context, email string, password []byte) (*PasswordLogin, error) {
	ps, e, err := p.loggedOutEndpoints()
	if err != nil {
		return nil, err
	}
	client, err := p.newClient(e, ps.DeviceID)
	if err != nil {
		return nil, err
	}
	kdf, err := client.Prelogin(ctx, email)
	if err != nil {
		return nil, err
	}
	mk, err := crypto.DeriveMasterKey(password, email, kdf)
	if err != nil {
		return nil, err
	}
	return &PasswordLogin{
		p: p, ps: ps, endpoints: e, client: client, email: crypto.NormalizeEmail(email), kdf: kdf,
		masterKey: mk, hash: crypto.HashMasterPasswordForServer(mk, password),
	}, nil
}

func (p *Profile) loggedOutEndpoints() (*profileState, api.Endpoints, error) {
	var ps *profileState
	var e api.Endpoints
	err := p.shared(func() error {
		if acct, err := p.activeAccount(); err == nil {
			return &AlreadyLoggedInError{Email: acct.Email}
		} else if !errors.Is(err, ErrNotLoggedIn) {
			return err
		}
		var err error
		if ps, err = p.loadProfile(); err != nil {
			return err
		}
		e, err = p.endpoints(ps)
		return err
	})
	return ps, e, err
}

// Close wipes the master key.
func (l *PasswordLogin) Close() { crypto.ZeroBytes(l.masterKey[:]) }

// SendEmailCode asks the server to email a two-step login code.
func (l *PasswordLogin) SendEmailCode(ctx context.Context) error {
	return l.client.SendEmailTwoFactorLogin(ctx, l.email, l.hash)
}

// ResendNewDeviceCode asks the server to email the new device verification
// code again, for this device.
func (l *PasswordLogin) ResendNewDeviceCode(ctx context.Context) error {
	return l.client.ResendNewDeviceOTP(ctx, l.email, l.hash)
}

// Complete signs in, with twoFactor when the server asked for it
// (*api.TwoFactorRequiredError), syncs, and returns a session key for the
// unlocked vault.
func (l *PasswordLogin) Complete(ctx context.Context, twoFactor *api.TwoFactorLogin) (string, error) {
	return l.CompleteWith(ctx, api.PasswordLoginOptions{TwoFactor: twoFactor})
}

// CompleteWith is Complete with every option of the password grant, such
// as the new device verification code the server asked for with
// *api.NewDeviceVerificationRequiredError.
func (l *PasswordLogin) CompleteWith(ctx context.Context, opts api.PasswordLoginOptions) (string, error) {
	tok, err := l.client.LoginPasswordWith(ctx, l.email, l.hash, opts)
	if err != nil {
		return "", err
	}
	userKey, err := crypto.DecryptUserKey(tok.Key, l.masterKey)
	if err != nil {
		return "", err
	}
	defer userKey.Zero()
	return l.p.commitLogin(ctx, l.ps, loginResult{
		endpoints: l.endpoints, client: l.client, token: tok, grant: GrantPassword,
		email: l.email, kdf: l.kdf, userKey: userKey,
	})
}

// SSOLogin binds an entire browser SSO login attempt to the server
// configuration captured before opening the browser. Authenticate verifies
// the configuration has not changed before exchanging the code (retrying
// after two-step verification if requested), and Commit syncs and saves the
// account.
type SSOLogin struct {
	p            *Profile
	ps           *profileState
	endpoints    api.Endpoints
	webVaultURL  string
	client       *api.Client
	code         string
	codeVerifier string
	redirectURI  string
	tok          *api.TokenResponse
}

// PrepareSSOLogin snapshots the logged-out server endpoints, web vault URL,
// device ID, and configuration generation before the browser opens.
func (p *Profile) PrepareSSOLogin() (*SSOLogin, error) {
	ps, e, err := p.loggedOutEndpoints()
	if err != nil {
		return nil, err
	}
	client, err := p.newClient(e, ps.DeviceID)
	if err != nil {
		return nil, err
	}
	webVault := ps.Overrides.WebVault
	if webVault == "" {
		webVault = api.WebVaultURL(ps.Server)
	}
	return &SSOLogin{
		p: p, ps: ps, endpoints: e, webVaultURL: webVault, client: client,
	}, nil
}

// BeginSSOLogin prepares to exchange an SSO authorization code at the
// configured server. Prefer PrepareSSOLogin before opening the browser so
// the authorization and exchange stay bound to the same configuration.
func (p *Profile) BeginSSOLogin(_ context.Context, code, codeVerifier, redirectURI string) (*SSOLogin, error) {
	l, err := p.PrepareSSOLogin()
	if err != nil {
		return nil, err
	}
	l.SetCallback(code, codeVerifier, redirectURI)
	return l, nil
}

// WebVaultURL returns the web vault URL captured when this attempt started.
func (l *SSOLogin) WebVaultURL() string { return l.webVaultURL }

// SetCallback records the verified callback code and PKCE parameters for
// this attempt.
func (l *SSOLogin) SetCallback(code, codeVerifier, redirectURI string) {
	l.code, l.codeVerifier, l.redirectURI = code, codeVerifier, redirectURI
}

// HasKeyring reports whether this profile has an OS credential store that
// can seal credentials without unlocking the vault first.
func (p *Profile) HasKeyring() bool { return p.opts.Keyring != nil }

// checkUnchanged refuses to send the authorization code or PKCE verifier
// if the profile's server configuration or login state changed while the
// browser was open.
func (l *SSOLogin) checkUnchanged() error {
	return l.p.shared(func() error {
		if acct, err := l.p.activeAccount(); err == nil {
			return &AlreadyLoggedInError{Email: acct.Email}
		} else if !errors.Is(err, ErrNotLoggedIn) {
			return err
		}
		cur, err := l.p.loadProfile()
		if err != nil {
			return err
		}
		if cur.Generation != l.ps.Generation || cur.Server != l.ps.Server || cur.Overrides != l.ps.Overrides {
			return ErrStale
		}
		return nil
	})
}

// SendEmailCode asks the server to email a two-step login code during an
// SSO login, where there is no master password hash.
func (l *SSOLogin) SendEmailCode(ctx context.Context, email, ssoSessionToken string) error {
	if err := l.checkUnchanged(); err != nil {
		return err
	}
	return l.client.SendEmailTwoFactorLoginSSO(ctx, email, ssoSessionToken)
}

// Authenticate exchanges the SSO authorization code for tokens. It returns
// *api.TwoFactorRequiredError when two-step verification is needed.
func (l *SSOLogin) Authenticate(ctx context.Context, twoFactor *api.TwoFactorLogin) error {
	if err := l.checkUnchanged(); err != nil {
		return err
	}
	tok, err := l.client.LoginSSO(ctx, api.SSOLoginOptions{
		Code:         l.code,
		CodeVerifier: l.codeVerifier,
		RedirectURI:  l.redirectURI,
		TwoFactor:    twoFactor,
	})
	if err != nil {
		return err
	}
	if tok.ForcePasswordReset {
		return ErrSSOForcePasswordReset
	}
	if opt := tok.UserDecryptionOptions; opt != nil && !opt.HasMasterPassword {
		switch {
		case opt.KeyConnectorOption != nil:
			return ErrSSOKeyConnectorUnsupported
		case opt.TrustedDeviceOption != nil:
			return ErrSSOTrustedDeviceUnsupported
		default:
			return ErrSSOMasterPasswordRequired
		}
	}
	l.tok = tok
	return nil
}

// Commit syncs and saves the authenticated SSO account. When masterPassword
// is non-empty, it also unlocks the vault (required on hosts without an OS
// keyring so the refresh token can be sealed) and returns a session key.
func (l *SSOLogin) Commit(ctx context.Context, masterPassword []byte) (string, error) {
	if l.tok == nil {
		return "", errors.New("profile: SSO login has not authenticated yet")
	}
	if !l.p.HasKeyring() && len(masterPassword) == 0 {
		return "", ErrPasswordRequiredNoKeyring
	}
	if err := l.checkUnchanged(); err != nil {
		return "", err
	}
	kdf := l.tok.MasterPasswordKDF()
	rawSalt := l.tok.MasterPasswordSalt()
	var userKey *crypto.SymmetricKey
	if len(masterPassword) > 0 {
		protectedKey := l.tok.MasterPasswordProtectedKey()
		deriveSalt := rawSalt
		if protectedKey == "" || deriveSalt == "" || kdf.Iterations == 0 {
			syncResp, _, err := l.client.Sync(ctx, l.tok.AccessToken)
			if err != nil {
				return "", err
			}
			if protectedKey == "" {
				protectedKey = syncResp.Profile.Key
			}
			if deriveSalt == "" {
				deriveSalt = crypto.NormalizeEmail(syncResp.Profile.Email)
			}
			if kdf.Iterations == 0 {
				kdf = crypto.KDFConfig{Type: crypto.KDFType(syncResp.Profile.KDF), Iterations: uint32(syncResp.Profile.KDFIters)}
				if syncResp.Profile.KDFMemory != nil {
					kdf.MemoryMB = uint32(*syncResp.Profile.KDFMemory)
				}
				if syncResp.Profile.KDFParallel != nil {
					kdf.Parallelism = uint32(*syncResp.Profile.KDFParallel)
				}
			}
		}
		if protectedKey == "" {
			return "", ErrSSOMasterPasswordRequired
		}
		mk, err := crypto.DeriveKeyFromPassword(masterPassword, deriveSalt, kdf)
		if err != nil {
			return "", err
		}
		defer crypto.ZeroBytes(mk[:])
		uk, err := crypto.DecryptUserKey(protectedKey, mk)
		if err != nil {
			return "", ErrInvalidPassword
		}
		defer uk.Zero()
		userKey = uk
	}
	return l.p.commitLogin(ctx, l.ps, loginResult{
		endpoints: l.endpoints, client: l.client, token: l.tok, grant: GrantSSO,
		kdfSalt: rawSalt, kdf: kdf, userKey: userKey,
	})
}

// Complete runs Authenticate followed by Commit without unlocking.
func (l *SSOLogin) Complete(ctx context.Context, twoFactor *api.TwoFactorLogin) error {
	if err := l.Authenticate(ctx, twoFactor); err != nil {
		return err
	}
	_, err := l.Commit(ctx, nil)
	return err
}

// LoginAPIKey signs in with a personal API key. The key cannot decrypt the
// vault, so the vault stays locked until Unlock. Without a credential store
// the key is not kept; Unlock can take it again to keep it encrypted.
func (p *Profile) LoginAPIKey(ctx context.Context, key APIKey) error {
	ps, e, err := p.loggedOutEndpoints()
	if err != nil {
		return err
	}
	client, err := p.newClient(e, ps.DeviceID)
	if err != nil {
		return err
	}
	tok, err := client.LoginAPIKey(ctx, key.ClientID, key.ClientSecret)
	if err != nil {
		return err
	}
	kdf := crypto.KDFConfig{Type: crypto.KDFType(tok.KDF), Iterations: uint32(tok.KDFIters)}
	if tok.KDFMemory != nil {
		kdf.MemoryMB = uint32(*tok.KDFMemory)
	}
	if tok.KDFParallel != nil {
		kdf.Parallelism = uint32(*tok.KDFParallel)
	}
	_, err = p.commitLogin(ctx, ps, loginResult{
		endpoints: e, client: client, token: tok, grant: GrantAPIKey, kdf: kdf, apiKey: &key,
	})
	return err
}

type loginResult struct {
	endpoints api.Endpoints
	client    *api.Client
	token     *api.TokenResponse
	grant     string
	email     string
	kdfSalt   string
	kdf       crypto.KDFConfig
	userKey   *crypto.SymmetricKey // nil for an API key or locked SSO login
	apiKey    *APIKey
}

// commitLogin fetches the vault with a new token and records the account.
// It returns a session key when the vault was unlocked.
func (p *Profile) commitLogin(ctx context.Context, startPS *profileState, r loginResult) (string, error) {
	sub, err := api.TokenSubject(r.token.AccessToken)
	if err != nil {
		return "", err
	}
	revDate, _ := r.client.RevisionDate(ctx, r.token.AccessToken)
	syncResp, rawSync, err := r.client.Sync(ctx, r.token.AccessToken)
	if err != nil {
		return "", err
	}
	if syncResp.Profile.ID != sub {
		return "", ErrDifferentAccount
	}
	email := r.email
	if email == "" {
		email = crypto.NormalizeEmail(syncResp.Profile.Email)
	}
	now := p.opts.Now().UTC()
	acct := &accountState{
		Version: formatVersion, AccountID: sub, Email: email, LoginID: randomID(),
		Grant: r.grant, Endpoints: r.endpoints, Credentials: backendFile,
	}
	if p.opts.Keyring != nil {
		acct.Credentials = backendKeyring
	}
	if r.apiKey != nil {
		if acct.KeyBinding, err = keyBinding(acct, *r.apiKey); err != nil {
			return "", err
		}
	}
	creds := &credentials{
		Version: formatVersion, AccountID: sub, LoginID: acct.LoginID, Endpoints: r.endpoints, Grant: r.grant,
		RefreshToken: r.token.RefreshToken, AccessToken: r.token.AccessToken,
		AccessExpiry: now.Add(time.Duration(r.token.ExpiresIn) * time.Second),
	}
	if r.apiKey != nil {
		creds.ClientID, creds.ClientSecret = r.apiKey.ClientID, r.apiKey.ClientSecret
	}
	protectedKey := r.token.MasterPasswordProtectedKey()
	if protectedKey == "" {
		protectedKey = syncResp.Profile.Key
	}
	if protectedKey == "" {
		return "", ErrSSOMasterPasswordRequired
	}
	kdf := r.kdf
	if kdf.Iterations == 0 {
		kdf = crypto.KDFConfig{Type: crypto.KDFType(syncResp.Profile.KDF), Iterations: uint32(syncResp.Profile.KDFIters)}
		if syncResp.Profile.KDFMemory != nil {
			kdf.MemoryMB = uint32(*syncResp.Profile.KDFMemory)
		}
		if syncResp.Profile.KDFParallel != nil {
			kdf.Parallelism = uint32(*syncResp.Profile.KDFParallel)
		}
	}
	snap := &store.Snapshot{
		SchemaVersion: store.CurrentSchemaVersion, AccountID: sub, ServerURL: r.endpoints.API, Email: email,
		KDFSalt: r.kdfSalt, KDF: kdf, ProtectedKey: protectedKey, RevisionDate: revDate, LastSyncAt: now, RawSyncJSON: json.RawMessage(rawSync),
	}
	var session string
	err = p.exclusive(func() error {
		if cur, err := p.loadAccount(); err == nil && cur.gone() {
			if err := p.finishLogout(cur); err != nil {
				return err
			}
		} else if err == nil {
			return &AlreadyLoggedInError{Email: cur.Email}
		} else if !errors.Is(err, ErrNotLoggedIn) {
			return err
		}
		ps, err := p.loadProfile()
		if err != nil {
			return err
		}
		if ps.Generation != startPS.Generation || ps.Server != startPS.Server || ps.Overrides != startPS.Overrides {
			return ErrStale
		}
		// The account is journaled as pending before anything else is
		// saved: an interrupted login is rolled back by the next Open.
		pending := *acct
		pending.Pending = true
		if err := writeJSON(p.path(accountFile), &pending); err != nil {
			return err
		}
		committed := false
		defer func() {
			if !committed {
				_ = p.finishLogout(&pending)
			}
		}()
		if err := p.store.SaveSnapshot(snap); err != nil {
			return err
		}
		if err := p.withLock(credsLockFile, true, func() error {
			return p.saveCredentials(ps, acct, creds, r.userKey)
		}); err != nil {
			return err
		}
		ps.Generation++
		if r.userKey != nil {
			if session, err = p.newSession(ps, acct, ps.Generation, r.userKey); err != nil {
				return err
			}
		}
		if err := p.saveProfile(ps); err != nil {
			return err
		}
		if beforeAccountCommit != nil {
			if err := beforeAccountCommit(); err != nil {
				return err
			}
		}
		// The active account record is the last write: until it lands,
		// the login is pending and rolled back.
		if err := writeJSON(p.path(accountFile), acct); err != nil {
			return err
		}
		committed = true
		return nil
	})
	return session, err
}
