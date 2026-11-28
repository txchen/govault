package profile

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/txchen/govault/internal/vaultcore/api"
	"github.com/txchen/govault/internal/vaultcore/crypto"
	"github.com/txchen/govault/internal/vaultcore/keyring"
	"github.com/txchen/govault/internal/vaultcore/privatefile"
)

const credentialsInfo = "govault-cli credentials v1"

// renewMargin renews an access token this long before it expires.
const renewMargin = time.Minute

// APIKey is a personal API key.
type APIKey struct {
	ClientID     string
	ClientSecret string
}

// credentials is the sign-in a profile keeps: the grant's long-lived
// secret, the current access token, and the server they are bound to.
type credentials struct {
	Version      int           `json:"version"`
	AccountID    string        `json:"accountId"`
	LoginID      string        `json:"loginId"`
	Endpoints    api.Endpoints `json:"endpoints"`
	Grant        string        `json:"grant"`
	ClientID     string        `json:"clientId,omitempty"`
	ClientSecret string        `json:"clientSecret,omitempty"`
	RefreshToken string        `json:"refreshToken,omitempty"`
	AccessToken  string        `json:"accessToken,omitempty"`
	AccessExpiry time.Time     `json:"accessExpiry"`
}

// valid reports whether c belongs to acct.
func (c *credentials) valid(acct *accountState) bool {
	return c.Version == formatVersion && c.AccountID == acct.AccountID && c.LoginID == acct.LoginID &&
		c.Endpoints == acct.Endpoints && c.Grant == acct.Grant
}

func (c *credentials) fresh(now time.Time) bool {
	return c.AccessToken != "" && now.Add(renewMargin).Before(c.AccessExpiry)
}

func (p *Profile) credentialsAD(ps *profileState, acct *accountState) []byte {
	ad, _ := json.Marshal(struct {
		ProfileID, AccountID, LoginID string
	}{ps.ProfileID, acct.AccountID, acct.LoginID})
	return ad
}

// credentialsFileKey is the key that seals the credentials file: kept in
// the credential store, or derived from userKey for the file backend.
// Reading takes an existing key; writing creates the credential store's
// first. ok is false when there is none to use, which means no
// credentials.
func (p *Profile) credentialsFileKey(ps *profileState, acct *accountState, userKey *crypto.SymmetricKey, create bool) (key [32]byte, ok bool, err error) {
	switch acct.Credentials {
	case backendKeyring:
		if p.opts.Keyring == nil {
			return key, false, errors.New("profile: this account's credentials are in a credential store that is not available now")
		}
		if create {
			key, err = p.keyringKey(ps)
			return key, err == nil, err
		}
		v, err := p.opts.Keyring.Get(keyringService, ps.ProfileID)
		if errors.Is(err, keyring.ErrNotFound) {
			return key, false, nil
		}
		if err != nil {
			return key, false, err
		}
		defer crypto.ZeroBytes(v)
		if len(v) != 32 {
			return key, false, fmt.Errorf("profile: the credential store holds no %s key", credentialsFile)
		}
		copy(key[:], v)
		return key, true, nil
	case backendFile:
		if userKey == nil {
			return key, false, nil
		}
		key, err = p.credentialsKey(userKey)
		return key, err == nil, err
	}
	return key, false, nil
}

// loadCredentials reads the account's credentials. A file backend needs
// userKey to open them; without it they are absent (nil, nil).
func (p *Profile) loadCredentials(ps *profileState, acct *accountState, userKey *crypto.SymmetricKey) (*credentials, error) {
	key, ok, err := p.credentialsFileKey(ps, acct, userKey, false)
	defer crypto.ZeroBytes(key[:])
	if err != nil || !ok {
		return nil, err
	}
	sealed, err := os.ReadFile(p.path(credentialsFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	raw, err := crypto.Open(key, sealed, p.credentialsAD(ps, acct))
	if err != nil {
		return nil, fmt.Errorf("profile: %s: %w", credentialsFile, err)
	}
	defer crypto.ZeroBytes(raw)
	var c credentials
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("profile: invalid credentials: %w", err)
	}
	if !c.valid(acct) {
		return nil, ErrServerChanged
	}
	return &c, nil
}

func (p *Profile) credentialsKey(userKey *crypto.SymmetricKey) ([32]byte, error) {
	raw := userKey.Bytes()
	defer crypto.ZeroBytes(raw[:])
	return crypto.SealKey(raw[:], credentialsInfo)
}

// saveCredentials seals c into the credentials file. The credential store
// keeps a fixed-size key, as tokens can outgrow what some stores hold
// (Windows Credential Manager's 2,560 bytes); the file backend needs
// userKey, and without one the credentials stay in memory only.
func (p *Profile) saveCredentials(ps *profileState, acct *accountState, c *credentials, userKey *crypto.SymmetricKey) error {
	key, ok, err := p.credentialsFileKey(ps, acct, userKey, true)
	defer crypto.ZeroBytes(key[:])
	if err != nil || !ok {
		return err
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return err
	}
	defer crypto.ZeroBytes(raw)
	sealed, err := crypto.Seal(key, raw, p.credentialsAD(ps, acct))
	if err != nil {
		return err
	}
	return privatefile.WriteFile(p.path(credentialsFile), sealed)
}

// keyringKey returns the profile's credentials key from the credential
// store, creating it there first if it has none.
func (p *Profile) keyringKey(ps *profileState) ([32]byte, error) {
	var key [32]byte
	v, err := p.opts.Keyring.Get(keyringService, ps.ProfileID)
	switch {
	case err == nil && len(v) == 32:
		copy(key[:], v)
		crypto.ZeroBytes(v)
		return key, nil
	case err != nil && !errors.Is(err, keyring.ErrNotFound):
		return key, err
	}
	if _, err := rand.Read(key[:]); err != nil {
		return key, err
	}
	if err := p.opts.Keyring.Set(keyringService, ps.ProfileID, key[:]); err != nil {
		return key, err
	}
	return key, nil
}

// keyBinding authenticates the account, login and endpoints an API key
// signed in to with a key derived from its secret.
func keyBinding(acct *accountState, key APIKey) (string, error) {
	k, err := crypto.SealKey([]byte(key.ClientSecret), "govault-cli api key binding v1")
	if err != nil {
		return "", err
	}
	defer crypto.ZeroBytes(k[:])
	msg, err := json.Marshal(struct {
		AccountID, LoginID, ClientID string
		Endpoints                    api.Endpoints
	}{acct.AccountID, acct.LoginID, key.ClientID, acct.Endpoints})
	if err != nil {
		return "", err
	}
	m := hmac.New(sha256.New, k[:])
	m.Write(msg)
	return base64.StdEncoding.EncodeToString(m.Sum(nil)), nil
}

// checkEnvKey runs before an API key from the environment is sent: the
// key must name this account's user, and the account's server must be the
// one this key signed in to.
func checkEnvKey(acct *accountState, key APIKey) error {
	uuid, ok := strings.CutPrefix(strings.ToLower(key.ClientID), "user.")
	if !ok || uuid != strings.ToLower(acct.AccountID) {
		return ErrDifferentAccount
	}
	want, err := keyBinding(acct, key)
	if err != nil {
		return err
	}
	if acct.KeyBinding == "" || !hmac.Equal([]byte(want), []byte(acct.KeyBinding)) {
		return ErrUntrustedServer
	}
	return nil
}

// online is one authenticated client of the account.
type online struct {
	p       *Profile
	ps      *profileState
	acct    *accountState
	client  *api.Client
	userKey *crypto.SymmetricKey
	envKey  *APIKey
	creds   *credentials
}

// connect prepares authenticated requests for acct. userKey (from a valid
// session) opens file-backed credentials; envKey stands in for missing
// API-key credentials.
func (p *Profile) connect(ps *profileState, acct *accountState, userKey *crypto.SymmetricKey, envKey *APIKey) (*online, error) {
	if err := p.checkEndpoints(ps, acct); err != nil {
		return nil, err
	}
	client, err := p.newClient(acct.Endpoints, ps.DeviceID)
	if err != nil {
		return nil, err
	}
	return &online{p: p, ps: ps, acct: acct, client: client, userKey: userKey, envKey: envKey}, nil
}

// token returns an access token that is not stale, renewing it when it
// expires or was rejected. Renewal runs under credentials.lock: a process
// that waited finds the token another one renewed and uses it.
func (o *online) token(ctx context.Context, stale string) (string, error) {
	if o.creds != nil && o.creds.AccessToken != stale && o.creds.fresh(o.p.opts.Now()) {
		return o.creds.AccessToken, nil
	}
	var tok string
	err := o.p.withLock(credsLockFile, true, func() error {
		acct, err := o.p.loadAccount()
		if err != nil || acct.LoginID != o.acct.LoginID || acct.gone() {
			return ErrStale
		}
		creds, err := o.p.loadCredentials(o.ps, o.acct, o.userKey)
		if err != nil {
			return err
		}
		if creds != nil && creds.AccessToken != stale && creds.fresh(o.p.opts.Now()) {
			o.creds, tok = creds, creds.AccessToken
			return nil
		}
		if creds == nil {
			if o.acct.Grant != GrantAPIKey || o.envKey == nil {
				return ErrNoCredentials
			}
			if err := checkEnvKey(o.acct, *o.envKey); err != nil {
				return err
			}
			creds = &credentials{
				Version: formatVersion, AccountID: o.acct.AccountID, LoginID: o.acct.LoginID,
				Endpoints: o.acct.Endpoints, Grant: GrantAPIKey,
				ClientID: o.envKey.ClientID, ClientSecret: o.envKey.ClientSecret,
			}
		}
		if err := o.renew(ctx, creds); err != nil {
			return err
		}
		if err := o.p.saveCredentials(o.ps, o.acct, creds, o.userKey); err != nil {
			return err
		}
		o.creds, tok = creds, creds.AccessToken
		return nil
	})
	return tok, err
}

// renew exchanges the grant's secret for a new access token and checks it
// was issued for this account.
func (o *online) renew(ctx context.Context, c *credentials) error {
	var resp *api.TokenResponse
	var err error
	switch c.Grant {
	case GrantPassword, GrantSSO:
		if c.RefreshToken == "" {
			return ErrSignInRequired
		}
		resp, err = o.client.RefreshToken(ctx, c.RefreshToken)
	case GrantAPIKey:
		resp, err = o.client.LoginAPIKey(ctx, c.ClientID, c.ClientSecret)
	default:
		return ErrSignInRequired
	}
	if err != nil {
		var apiErr *api.APIError
		if errors.As(err, &apiErr) && apiErr.StatusCode == 400 {
			return fmt.Errorf("%w: %s", ErrSignInRequired, apiErr.Message)
		}
		return err
	}
	sub, err := api.TokenSubject(resp.AccessToken)
	if err != nil {
		return err
	}
	if sub != c.AccountID {
		return ErrDifferentAccount
	}
	c.AccessToken = resp.AccessToken
	c.AccessExpiry = o.p.opts.Now().Add(time.Duration(resp.ExpiresIn) * time.Second)
	if resp.RefreshToken != "" {
		c.RefreshToken = resp.RefreshToken
	}
	return nil
}

// call runs fn with a valid access token; when the server rejects the
// token, it renews it and retries once.
func call[T any](ctx context.Context, o *online, fn func(token string) (T, error)) (T, error) {
	var zero T
	tok, err := o.token(ctx, "")
	if err != nil {
		return zero, err
	}
	res, err := fn(tok)
	if !errors.Is(err, api.ErrUnauthorized) {
		return res, err
	}
	if tok, err = o.token(ctx, tok); err != nil {
		return zero, err
	}
	return fn(tok)
}
