package profile

import (
	"context"
	"encoding/base64"
	"errors"
	"time"

	"github.com/txchen/govault/internal/vaultcore/api"
	"github.com/txchen/govault/internal/vaultcore/crypto"
	"github.com/txchen/govault/internal/vaultcore/state"
	"github.com/txchen/govault/internal/vaultcore/store"
)

// UnlockRequest unlocks the vault with the master password.
type UnlockRequest struct {
	Password []byte
	// APIKey, when the account signed in with an API key on a system with
	// no credential store and kept none, is validated against the
	// configured server and kept encrypted under the user key.
	APIKey *APIKey
}

// Unlock checks the master password against the local copy of the vault,
// ends every earlier session and returns the key of a new one. It needs
// no network unless it takes an API key to keep.
func (p *Profile) Unlock(ctx context.Context, req UnlockRequest) (string, error) {
	var ps *profileState
	var acct *accountState
	var snap *store.Snapshot
	err := p.shared(func() error {
		var err error
		if acct, err = p.activeAccount(); err != nil {
			return err
		}
		if ps, err = p.loadProfile(); err != nil {
			return err
		}
		snap, err = p.store.LoadSnapshot(acct.AccountID)
		return err
	})
	if err != nil {
		return "", err
	}
	mk, err := crypto.DeriveKeyFromPassword(req.Password, snap.EffectiveKDFSalt(), snap.KDF)
	if err != nil {
		return "", err
	}
	userKey, err := crypto.DecryptUserKey(snap.ProtectedKey, mk)
	crypto.ZeroBytes(mk[:])
	if err != nil {
		return "", ErrInvalidPassword
	}
	defer userKey.Zero()

	var adopt *credentials
	if acct.Credentials == backendFile && acct.Grant == GrantAPIKey && req.APIKey != nil {
		if existing, err := p.loadCredentials(ps, acct, userKey); err == nil && existing == nil {
			if adopt, err = p.adoptAPIKey(ctx, ps, acct, *req.APIKey); err != nil {
				return "", err
			}
		}
	}

	var session string
	err = p.exclusive(func() error {
		cur, err := p.activeAccount()
		if err != nil {
			return err
		}
		if cur.LoginID != acct.LoginID {
			return ErrStale
		}
		ps, err := p.loadProfile()
		if err != nil {
			return err
		}
		if adopt != nil {
			if err := p.withLock(credsLockFile, true, func() error {
				return p.saveCredentials(ps, acct, adopt, userKey)
			}); err != nil {
				return err
			}
		}
		ps.Generation++
		if session, err = p.newSession(ps, acct, ps.Generation, userKey); err != nil {
			return err
		}
		return p.saveProfile(ps)
	})
	return session, err
}

// adoptAPIKey exchanges key at the configured server, which must be the
// account's, and checks the token is for this account.
func (p *Profile) adoptAPIKey(ctx context.Context, ps *profileState, acct *accountState, key APIKey) (*credentials, error) {
	if err := checkEnvKey(acct, key); err != nil {
		return nil, err
	}
	o, err := p.connect(ps, acct, nil, nil)
	if err != nil {
		return nil, err
	}
	c := &credentials{
		Version: formatVersion, AccountID: acct.AccountID, LoginID: acct.LoginID, Endpoints: acct.Endpoints,
		Grant: GrantAPIKey, ClientID: key.ClientID, ClientSecret: key.ClientSecret,
	}
	if err := o.renew(ctx, c); err != nil {
		return nil, err
	}
	return c, nil
}

// CheckSession reports whether sessionKey unlocks the vault, without
// changing anything.
func (p *Profile) CheckSession(sessionKey string) error {
	return p.shared(func() error {
		acct, err := p.activeAccount()
		if err != nil {
			return err
		}
		ps, err := p.loadProfile()
		if err != nil {
			return err
		}
		key, err := p.openSession(ps, acct, sessionKey)
		if err != nil {
			return err
		}
		key.Zero()
		return nil
	})
}

// Vault is the unlocked vault of one read, with the server access that
// network reads need.
type Vault struct {
	*state.VaultView
	AccountID string
	Email     string
	// KDF is the account's key derivation, which password-protected
	// exports use as Bitwarden's do.
	KDF crypto.KDFConfig
	o   *online
}

// Read opens the vault with sessionKey and runs fn while holding the
// profile shared, so no lock or logout lands until fn returns. envKey may
// stand in for missing API-key credentials in network reads.
func (p *Profile) Read(sessionKey string, envKey *APIKey, fn func(*Vault) error) error {
	return p.shared(func() error {
		acct, err := p.activeAccount()
		if err != nil {
			return err
		}
		ps, err := p.loadProfile()
		if err != nil {
			return err
		}
		userKey, err := p.openSession(ps, acct, sessionKey)
		if err != nil {
			return err
		}
		defer userKey.Zero()
		snap, err := p.store.LoadSnapshot(acct.AccountID)
		if err != nil {
			return err
		}
		view, err := state.OpenVault(snap.RawSyncJSON, userKey)
		if err != nil {
			return err
		}
		defer view.Close()
		v := &Vault{VaultView: view, AccountID: acct.AccountID, Email: acct.Email, KDF: snap.KDF}
		if o, err := p.connect(ps, acct, userKey, envKey); err == nil {
			v.o = o
		}
		return fn(v)
	})
}

func (v *Vault) online() (*online, error) {
	if v.o == nil {
		return nil, ErrServerChanged
	}
	return v.o, nil
}

// UserPublicKey fetches another user's public key (SPKI DER).
func (v *Vault) UserPublicKey(ctx context.Context, userID string) ([]byte, error) {
	o, err := v.online()
	if err != nil {
		return nil, err
	}
	b64, err := call(ctx, o, func(tok string) (string, error) { return o.client.UserPublicKey(ctx, tok, userID) })
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(b64)
}

// OrganizationCollections lists an organization's collections from the
// server: all of them when the membership may view all, else the user's.
func (v *Vault) OrganizationCollections(ctx context.Context, org state.ViewOrganization) ([]state.ViewCollection, error) {
	o, err := v.online()
	if err != nil {
		return nil, err
	}
	enc, err := call(ctx, o, func(tok string) ([]api.EncryptedCollection, error) {
		if org.CanViewAllCollections {
			return o.client.OrganizationCollections(ctx, tok, org.ID)
		}
		return o.client.UserCollections(ctx, tok)
	})
	if err != nil {
		return nil, err
	}
	var mine []api.EncryptedCollection
	for _, c := range enc {
		if c.OrganizationID == org.ID {
			mine = append(mine, c)
		}
	}
	return v.DecryptCollections(mine), nil
}

// Attachment downloads and decrypts an attachment of c.
func (v *Vault) Attachment(ctx context.Context, c *state.Cipher, attachmentID string) ([]byte, error) {
	o, err := v.online()
	if err != nil {
		return nil, err
	}
	return v.DownloadAttachment(ctx, attachmentSource{o: o}, c, attachmentID)
}

type attachmentSource struct{ o *online }

func (s attachmentSource) Metadata(ctx context.Context, cipherID, attachmentID string) (*api.EncryptedAttachment, error) {
	return call(ctx, s.o, func(tok string) (*api.EncryptedAttachment, error) {
		return s.o.client.GetAttachment(ctx, tok, cipherID, attachmentID)
	})
}

func (s attachmentSource) Download(ctx context.Context, url string) ([]byte, error) {
	return call(ctx, s.o, func(tok string) ([]byte, error) { return s.o.client.DownloadAttachmentBytes(ctx, tok, url) })
}

// SyncRequest pulls the vault from the server.
type SyncRequest struct {
	// Force fetches even when the server's revision is unchanged.
	Force bool
	// SessionKey, when valid, opens credentials kept in a file.
	SessionKey string
	APIKey     *APIKey
}

// syncAttempts bounds how often Sync fetches again because a commit landed
// while it fetched.
const syncAttempts = 3

// ErrSyncRaced means other changes kept landing while Sync fetched.
var ErrSyncRaced = errors.New("profile: the local copy kept changing during the sync; try again")

// Sync fetches the encrypted vault and replaces the local copy, unless the
// account changed meanwhile. A result fetched while another write or sync
// committed is discarded and fetched again, so an older copy never
// replaces a newer one. The vault may stay locked.
func (p *Profile) Sync(ctx context.Context, req SyncRequest) error {
	for range syncAttempts {
		if err := p.syncOnce(ctx, req); !errors.Is(err, errSnapshotMoved) {
			return err
		}
		req.Force = true
	}
	return ErrSyncRaced
}

var errSnapshotMoved = errors.New("profile: the snapshot changed during the sync")

func (p *Profile) syncOnce(ctx context.Context, req SyncRequest) error {
	var o *online
	var snap *store.Snapshot
	var userKey *crypto.SymmetricKey
	err := p.shared(func() error {
		acct, err := p.activeAccount()
		if err != nil {
			return err
		}
		ps, err := p.loadProfile()
		if err != nil {
			return err
		}
		if snap, err = p.store.LoadSnapshot(acct.AccountID); err != nil {
			return err
		}
		if k, err := p.openSession(ps, acct, req.SessionKey); err == nil {
			userKey = k
		}
		o, err = p.connect(ps, acct, userKey, req.APIKey)
		return err
	})
	if userKey != nil {
		defer userKey.Zero()
	}
	if err != nil {
		return err
	}
	revDate, revErr := call(ctx, o, func(tok string) (time.Time, error) { return o.client.RevisionDate(ctx, tok) })
	if errors.Is(revErr, ErrNoCredentials) || errors.Is(revErr, ErrSignInRequired) || errors.Is(revErr, ErrDifferentAccount) {
		return revErr
	}
	updated := *snap
	updated.LastSyncAt = p.opts.Now().UTC()
	if req.Force || revErr != nil || snap.RevisionDate.IsZero() || !revDate.Equal(snap.RevisionDate) {
		type fetched struct {
			resp *api.SyncResponse
			raw  []byte
		}
		f, err := call(ctx, o, func(tok string) (fetched, error) {
			resp, raw, err := o.client.Sync(ctx, tok)
			return fetched{resp, raw}, err
		})
		if err != nil {
			return err
		}
		if f.resp.Profile.ID != o.acct.AccountID {
			return ErrDifferentAccount
		}
		updated.RawSyncJSON = f.raw
		if f.resp.Profile.Key != "" {
			updated.ProtectedKey = f.resp.Profile.Key
		}
		if revErr == nil {
			updated.RevisionDate = revDate
		}
	}
	return p.exclusive(func() error {
		cur, err := p.activeAccount()
		if err != nil {
			return err
		}
		if cur.LoginID != o.acct.LoginID {
			return ErrStale
		}
		seq, err := p.store.sequence(o.acct.AccountID)
		if err != nil {
			return err
		}
		if seq != snap.Sequence {
			return errSnapshotMoved
		}
		return p.store.saveAfter(&updated, seq)
	})
}
