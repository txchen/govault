// Package profile keeps a command-line client's sign-in and encrypted vault
// cache in one directory, shared safely by concurrent processes.
//
// A profile holds one account. Its files are private to the user and
// replaced atomically. Processes coordinate with two OS-released locks:
// state.lock orders every state transition (readers hold it shared while
// they use decrypted data), and credentials.lock orders token renewal.
// Code holding credentials.lock never takes state.lock.
//
// The unlocked state lives with the caller: Unlock returns a session key,
// and a session record on disk holds the user key sealed under it. The
// record is bound to the profile, account, sign-in, server and a
// generation that every unlock, lock and logout advances, so a lock or
// logout invalidates every session key at once.
package profile

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/txchen/govault/internal/vaultcore/api"
	"github.com/txchen/govault/internal/vaultcore/keyring"
	"github.com/txchen/govault/internal/vaultcore/privatefile"
	"github.com/txchen/govault/internal/vaultcore/store"
)

var (
	ErrNotLoggedIn      = errors.New("profile: not logged in")
	ErrLocked           = errors.New("profile: vault is locked")
	ErrInvalidPassword  = errors.New("profile: invalid master password")
	ErrServerChanged    = errors.New("profile: the configured server differs from the one this account signed in to; log out first")
	ErrSignInRequired   = errors.New("profile: the saved sign-in was rejected; log in again")
	ErrNoCredentials    = errors.New("profile: no sign-in credentials are available while the vault is locked on a system without a credential store; unlock first or provide the API key")
	ErrDifferentAccount = errors.New("profile: the credentials belong to a different account")
	// ErrUntrustedServer means an API key from the environment was not
	// the one this account signed in to its server with, so it is not
	// sent there.
	ErrUntrustedServer = errors.New("profile: the API key was not used to sign in to this account's server; log in with it again")
	ErrStale                       = errors.New("profile: the profile changed while the request was running")
	ErrLogoutRequired              = errors.New("profile: log out before changing the server")
	ErrSSOMasterPasswordRequired   = errors.New("profile: this SSO account has no master password yet; set one in the web vault first")
	ErrSSOForcePasswordReset       = errors.New("profile: your organization requires a master password reset; reset it in the web vault first")
	ErrSSOKeyConnectorUnsupported  = errors.New("profile: SSO with Key Connector is not supported yet")
	ErrSSOTrustedDeviceUnsupported = errors.New("profile: SSO with Trusted Device Encryption is not supported yet")
	ErrPasswordRequiredNoKeyring   = errors.New("profile: master password is required to save SSO credentials on a system without a credential store")
)

// AlreadyLoggedInError reports an attempt to log in over an account.
type AlreadyLoggedInError struct{ Email string }

func (e *AlreadyLoggedInError) Error() string { return "profile: already logged in as " + e.Email }

const (
	formatVersion   = 1
	keyringService  = "GoVault CLI"
	profileFile     = "profile.json"
	accountFile     = "account.json"
	sessionFile     = "session.json"
	credentialsFile = "credentials.json"
	stateLockFile   = "state.lock"
	credsLockFile   = "credentials.lock"

	GrantPassword = "password"
	GrantAPIKey   = "apikey"
	GrantSSO      = "sso"

	backendKeyring = "keyring"
	backendFile    = "file"
)

// Options configures a profile's environment.
type Options struct {
	// Keyring is the OS credential store; nil means the system has none,
	// so credentials are sealed under the vault's user key in a file.
	Keyring    keyring.Store
	HTTPClient *http.Client
	DeviceName string
	DeviceType int
	ClientName string
	UserAgent  string
	Now        func() time.Time
}

// Profile is an open profile directory.
type Profile struct {
	dir   string
	opts  Options
	store sequencedStore
}

// profileState survives logout: the profile's identity, the configured
// server and the session generation.
type profileState struct {
	Version    int         `json:"version"`
	ProfileID  string      `json:"profileId"`
	DeviceID   string      `json:"deviceId"`
	Server     string      `json:"server"`
	Overrides  ServiceURLs `json:"overrides,omitempty"`
	Generation uint64      `json:"generation"`
}

// ServiceURLs replace services of the server that do not live under its
// base URL. gv uses the API and identity URLs; the others are kept as
// configured, as Bitwarden's CLI keeps them.
type ServiceURLs struct {
	API           string `json:"api,omitempty"`
	Identity      string `json:"identity,omitempty"`
	WebVault      string `json:"webVault,omitempty"`
	Icons         string `json:"icons,omitempty"`
	Notifications string `json:"notifications,omitempty"`
	Events        string `json:"events,omitempty"`
}

// accountState is the signed-in account. LoginID is new for every login,
// so work started under one login never lands on another.
type accountState struct {
	Version     int           `json:"version"`
	AccountID   string        `json:"accountId"`
	Email       string        `json:"email"`
	LoginID     string        `json:"loginId"`
	Grant       string        `json:"grant"`
	Endpoints   api.Endpoints `json:"endpoints"`
	Credentials string        `json:"credentials"`
	LoggingOut  bool          `json:"loggingOut,omitempty"`
	// Pending marks a login that has not finished saving: Open rolls it
	// back as it finishes a logout.
	Pending bool `json:"pending,omitempty"`
	// KeyBinding authenticates the server an API-key login used with the
	// key itself, so a key from the environment goes nowhere else.
	KeyBinding string `json:"keyBinding,omitempty"`
}

// gone reports an account that is being logged out or never finished
// logging in.
func (a *accountState) gone() bool { return a.LoggingOut || a.Pending }

// Open opens or creates the profile in dir, finishing an interrupted
// logout first.
func Open(dir string, opts Options) (*Profile, error) {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if err := privatefile.MkdirAll(dir); err != nil {
		return nil, err
	}
	p := &Profile{dir: dir, opts: opts, store: sequencedStore{store.NewFileStore(dir)}}
	if err := p.exclusive(func() error {
		if _, err := p.loadProfile(); err != nil {
			return err
		}
		acct, err := p.loadAccount()
		if err == nil && acct.gone() {
			return p.finishLogout(acct)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *Profile) path(name string) string { return filepath.Join(p.dir, name) }

func (p *Profile) withLock(name string, exclusive bool, fn func() error) error {
	l, err := lockFile(p.path(name), exclusive)
	if err != nil {
		return fmt.Errorf("profile: lock %s: %w", name, err)
	}
	defer l.unlock()
	return fn()
}

func (p *Profile) shared(fn func() error) error    { return p.withLock(stateLockFile, false, fn) }
func (p *Profile) exclusive(fn func() error) error { return p.withLock(stateLockFile, true, fn) }

func readJSON(path string, v any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, v)
}

func writeJSON(path string, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return privatefile.WriteFile(path, raw)
}

func randomID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// loadProfile reads profile.json, creating it on first use. The caller
// holds the state lock exclusively when the file may not exist yet.
func (p *Profile) loadProfile() (*profileState, error) {
	var ps profileState
	err := readJSON(p.path(profileFile), &ps)
	if errors.Is(err, os.ErrNotExist) {
		ps = profileState{Version: formatVersion, ProfileID: randomID(), DeviceID: randomID()}
		return &ps, writeJSON(p.path(profileFile), &ps)
	}
	if err != nil {
		return nil, fmt.Errorf("profile: read %s: %w", profileFile, err)
	}
	if ps.Version != formatVersion || ps.ProfileID == "" || ps.DeviceID == "" {
		return nil, fmt.Errorf("profile: unsupported %s", profileFile)
	}
	return &ps, nil
}

func (p *Profile) saveProfile(ps *profileState) error { return writeJSON(p.path(profileFile), ps) }

// loadAccount returns the account, or ErrNotLoggedIn.
func (p *Profile) loadAccount() (*accountState, error) {
	var a accountState
	err := readJSON(p.path(accountFile), &a)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotLoggedIn
	}
	if err != nil {
		return nil, fmt.Errorf("profile: read %s: %w", accountFile, err)
	}
	if a.Version != formatVersion || a.AccountID == "" || a.LoginID == "" {
		return nil, fmt.Errorf("profile: unsupported %s", accountFile)
	}
	return &a, nil
}

// activeAccount is loadAccount, with an account being logged out treated
// as gone.
func (p *Profile) activeAccount() (*accountState, error) {
	a, err := p.loadAccount()
	if err != nil {
		return nil, err
	}
	if a.gone() {
		return nil, ErrNotLoggedIn
	}
	return a, nil
}

// Server returns the configured base URL, "" for the default cloud.
func (p *Profile) Server() (string, error) {
	var server string
	err := p.shared(func() error {
		ps, err := p.loadProfile()
		if err != nil {
			return err
		}
		server = ps.Server
		return nil
	})
	return server, err
}

// WebVaultURL returns the configured web vault URL for browser flows such
// as SSO, respecting any --web-vault override.
func (p *Profile) WebVaultURL() (string, error) {
	var webVault string
	err := p.shared(func() error {
		ps, err := p.loadProfile()
		if err != nil {
			return err
		}
		if ps.Overrides.WebVault != "" {
			webVault = ps.Overrides.WebVault
		} else {
			webVault = api.WebVaultURL(ps.Server)
		}
		return nil
	})
	return webVault, err
}

// SetServer configures the server while logged out; base is a URL from
// api.FormatServerURL.
func (p *Profile) SetServer(base string) error { return p.SetServerURLs(base, ServiceURLs{}) }

// SetServerURLs configures the server and service overrides while logged
// out.
func (p *Profile) SetServerURLs(base string, overrides ServiceURLs) error {
	if _, err := resolve(base, overrides); err != nil {
		return err
	}
	return p.exclusive(func() error {
		if _, err := p.loadAccount(); err == nil {
			return ErrLogoutRequired
		} else if !errors.Is(err, ErrNotLoggedIn) {
			return err
		}
		ps, err := p.loadProfile()
		if err != nil {
			return err
		}
		if ps.Server != base || ps.Overrides != overrides {
			ps.Generation++
		}
		ps.Server, ps.Overrides = base, overrides
		return p.saveProfile(ps)
	})
}

// endpoints resolves the configured server.
func (p *Profile) endpoints(ps *profileState) (api.Endpoints, error) {
	return resolve(ps.Server, ps.Overrides)
}

func resolve(base string, o ServiceURLs) (api.Endpoints, error) {
	e, err := api.ResolveEndpoints(base)
	if err != nil {
		return e, err
	}
	if o.API != "" {
		e.API = o.API
	}
	if o.Identity != "" {
		e.Identity = o.Identity
	}
	for _, u := range []string{e.API, e.Identity} {
		if _, err := api.ResolveEndpoints(u); err != nil {
			return e, err
		}
	}
	return e, nil
}

// checkEndpoints refuses to send an account's credentials anywhere but the
// server it signed in to, which must still be the configured one.
func (p *Profile) checkEndpoints(ps *profileState, acct *accountState) error {
	e, err := p.endpoints(ps)
	if err != nil {
		return err
	}
	if e != acct.Endpoints {
		return ErrServerChanged
	}
	return nil
}

func (p *Profile) newClient(e api.Endpoints, deviceID string) (*api.Client, error) {
	c, err := api.NewClient(api.ClientConfig{
		ServerURL:   e.Base,
		APIURL:      e.API,
		IdentityURL: e.Identity,
		DeviceID:    deviceID,
		DeviceName:  p.opts.DeviceName,
		DeviceType:  p.opts.DeviceType,
		ClientID:    "cli",
		ClientName:  p.opts.ClientName,
		HTTPClient:  p.opts.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	if p.opts.UserAgent != "" {
		c.SetUserAgent(p.opts.UserAgent)
	}
	return c, nil
}

// State is the account state Status reports.
type State int

const (
	Unauthenticated State = iota
	Locked
	Unlocked
)

// Status is what `status` shows.
type Status struct {
	// Server is the configured base URL, "" for the default cloud.
	Server   string
	LastSync time.Time
	Email    string
	UserID   string
	State    State
}

// Status reports the profile's state; sessionKey decides locked or
// unlocked. It needs no network.
func (p *Profile) Status(sessionKey string) (Status, error) {
	var st Status
	err := p.shared(func() error {
		ps, err := p.loadProfile()
		if err != nil {
			return err
		}
		st.Server = ps.Server
		acct, err := p.activeAccount()
		if errors.Is(err, ErrNotLoggedIn) {
			return nil
		}
		if err != nil {
			return err
		}
		st.Email, st.UserID, st.State = acct.Email, acct.AccountID, Locked
		if snap, err := p.store.LoadSnapshot(acct.AccountID); err == nil {
			st.LastSync = snap.LastSyncAt
		}
		if key, err := p.openSession(ps, acct, sessionKey); err == nil {
			key.Zero()
			st.State = Unlocked
		}
		return nil
	})
	return st, err
}

// LastSync is the time of the last successful sync, zero before the first
// one or when logged out.
func (p *Profile) LastSync() (time.Time, error) {
	var t time.Time
	err := p.shared(func() error {
		acct, err := p.activeAccount()
		if err != nil {
			return err
		}
		snap, err := p.store.LoadSnapshot(acct.AccountID)
		if err == nil {
			t = snap.LastSyncAt
		}
		return nil
	})
	return t, err
}

// Account returns the signed-in account's email, or ErrNotLoggedIn.
func (p *Profile) Account() (email string, err error) {
	err = p.shared(func() error {
		acct, err := p.activeAccount()
		if err != nil {
			return err
		}
		email = acct.Email
		return nil
	})
	return email, err
}

// Lock ends every session of the profile.
func (p *Profile) Lock() error {
	return p.exclusive(func() error {
		if _, err := p.activeAccount(); err != nil {
			return err
		}
		ps, err := p.loadProfile()
		if err != nil {
			return err
		}
		ps.Generation++
		if err := p.saveProfile(ps); err != nil {
			return err
		}
		return removeIfExists(p.path(sessionFile))
	})
}

// Logout removes the sign-in. It first marks the account as logging out
// and ends every session, so an interruption leaves nothing usable; the
// next Open finishes the cleanup.
func (p *Profile) Logout() error {
	return p.exclusive(func() error {
		acct, err := p.activeAccount()
		if err != nil {
			return err
		}
		acct.LoggingOut = true
		if err := writeJSON(p.path(accountFile), acct); err != nil {
			return err
		}
		ps, err := p.loadProfile()
		if err != nil {
			return err
		}
		ps.Generation++
		if err := p.saveProfile(ps); err != nil {
			return err
		}
		return p.finishLogout(acct)
	})
}

// finishLogout erases everything the account left: credentials in every
// backend, the session record and the snapshot. The caller holds the
// state lock exclusively.
func (p *Profile) finishLogout(acct *accountState) error {
	ps, err := p.loadProfile()
	if err != nil {
		return err
	}
	err = p.withLock(credsLockFile, true, func() error {
		var errs []error
		if p.opts.Keyring != nil {
			if err := p.opts.Keyring.Delete(keyringService, ps.ProfileID); err != nil {
				errs = append(errs, err)
			}
		} else if acct.Credentials == backendKeyring {
			errs = append(errs, errors.New("profile: the credentials are in a credential store that is not available now"))
		}
		errs = append(errs, removeIfExists(p.path(credentialsFile)))
		return errors.Join(errs...)
	})
	if err != nil {
		return err
	}
	if err := removeIfExists(p.path(sessionFile)); err != nil {
		return err
	}
	if err := p.store.DeleteSnapshot(acct.AccountID); err != nil {
		return err
	}
	return removeIfExists(p.path(accountFile))
}

func removeIfExists(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
