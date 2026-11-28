package main

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/nsgo-dev/nsgo/core"
	govaultui "github.com/txchen/govault/cmd/govault/ui"
	"github.com/txchen/govault/internal/vaultcore/crypto"
	"github.com/txchen/govault/internal/vaultcore/store"
)

type SecretStoreAdapter struct {
	secrets core.Secrets
}

func NewSecretStoreAdapter(secrets core.Secrets) *SecretStoreAdapter {
	return &SecretStoreAdapter{secrets: secrets}
}

func (a *SecretStoreAdapter) Get(account string) (string, bool, error) {
	return a.secrets.Get(account)
}

func (a *SecretStoreAdapter) Set(account, value string) error {
	return a.secrets.Set(account, value)
}

func (a *SecretStoreAdapter) Delete(account string) error {
	return a.secrets.Delete(account)
}

type ClipboardAdapter struct {
	scope     *core.Scope
	concealed *ConcealedClipboard

	mu    sync.Mutex
	timer *time.Timer
	// owned is the secret GoVault put on the clipboard and has yet to
	// clear. It stays owned until a clipboard read shows it is gone, so
	// quitting at any point before that still clears it.
	owned   string
	retries int

	// The clipboard as the app sees it; tests replace these.
	post  func(func())
	read  func(func(string))
	write func(string)
	later func(func())
}

func NewClipboardAdapter(scope *core.Scope) *ClipboardAdapter {
	return &ClipboardAdapter{
		scope:     scope,
		concealed: NewConcealedClipboard(),
		post:      scope.Post,
		read:      scope.ReadClipboard,
		write:     scope.SetClipboard,
		later:     func(f func()) { time.AfterFunc(time.Second, f) },
	}
}

func (c *ClipboardAdapter) IsConcealed() bool {
	return runtime.GOOS == "darwin"
}

func (c *ClipboardAdapter) CopySecret(secret string, clearAfter time.Duration) (bool, error) {
	if runtime.GOOS == "darwin" {
		if _, err := c.concealed.Copy(secret, clearAfter); err != nil {
			return false, err
		}
		return true, nil
	}

	c.write(secret)

	c.mu.Lock()
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
	c.owned, c.retries = "", 0
	if clearAfter > 0 {
		expected := secret
		c.owned = secret
		c.timer = time.AfterFunc(clearAfter, func() { c.expire(expected) })
	}
	c.mu.Unlock()

	return false, nil
}

// expire clears expected if the clipboard still holds it, keeping it owned
// until a later read confirms it is gone: the clear is only queued when it
// is asked for.
//
// An empty read proves nothing: Windows returns "" when another app holds
// the clipboard open. Ownership is dropped only for a read that returns
// something else, and an empty read retries the clear later; quitting
// still clears an owned secret either way.
func (c *ClipboardAdapter) expire(expected string) {
	c.post(func() {
		c.read(func(current string) {
			switch current {
			case expected:
				c.write("")
			case "":
				c.retryExpire(expected)
			default:
				c.release(expected)
			}
		})
	})
}

const clipboardRetries = 5

func (c *ClipboardAdapter) retryExpire(expected string) {
	c.mu.Lock()
	if c.owned != expected || c.retries >= clipboardRetries {
		c.mu.Unlock()
		return
	}
	c.retries++
	c.mu.Unlock()
	c.later(func() { c.expire(expected) })
}

func (c *ClipboardAdapter) release(secret string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.owned == secret {
		c.owned = ""
	}
}

func (c *ClipboardAdapter) CopyPlain(text string) {
	c.scope.SetClipboard(text)
}

// ClearOnQuit clears a secret still waiting to be cleared, synchronously,
// before the app exits and its timers stop: the concealed copy on macOS,
// else the clipboard if it still holds the secret GoVault put there.
func (c *ClipboardAdapter) ClearOnQuit() {
	c.concealed.ClearPending()
	c.mu.Lock()
	owned := c.owned
	c.owned = ""
	c.mu.Unlock()
	if owned != "" {
		clearClipboardIfOwned(owned)
	}
	c.Cancel()
}

func (c *ClipboardAdapter) Cancel() {
	c.concealed.Cancel()
	c.mu.Lock()
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
	c.owned = ""
	c.mu.Unlock()
}

func DiscoverAccountSnapshot(dataDir, preferredAccountID string) *govaultui.AccountSnapshotMeta {
	fs := store.NewFileStore(dataDir)
	if preferredAccountID != "" {
		if snap, err := fs.LoadSnapshot(preferredAccountID); err == nil {
			return snapshotToMeta(snap)
		}
	}

	entries, err := os.ReadDir(dataDir)
	if err != nil {
		return nil
	}

	var latest *store.Snapshot
	var latestMod time.Time
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasPrefix(name, "vault_") || !strings.HasSuffix(name, ".enc.json") {
			continue
		}
		accountID := strings.TrimSuffix(strings.TrimPrefix(name, "vault_"), ".enc.json")
		snap, err := fs.LoadSnapshot(accountID)
		if err != nil {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if latest == nil || info.ModTime().After(latestMod) {
			latest = snap
			latestMod = info.ModTime()
		}
	}
	if latest == nil {
		return nil
	}
	return snapshotToMeta(latest)
}

func VerifyMasterPasswordOffline(dataDir, accountID string, password []byte) error {
	if accountID == "" {
		return errors.New("no active account")
	}
	snap, err := store.NewFileStore(dataDir).LoadSnapshot(accountID)
	if err != nil {
		return err
	}
	masterKey, err := crypto.DeriveKeyFromPassword(password, snap.EffectiveKDFSalt(), snap.KDF)
	if err != nil {
		return err
	}
	defer crypto.ZeroBytes(masterKey[:])

	userKey, err := crypto.DecryptUserKey(snap.ProtectedKey, masterKey)
	if err != nil {
		return err
	}
	userKey.Zero()
	return nil
}

func snapshotToMeta(snap *store.Snapshot) *govaultui.AccountSnapshotMeta {
	kdf := snap.KDF
	return &govaultui.AccountSnapshotMeta{
		AccountID:  snap.AccountID,
		ServerURL:  snap.ServerURL,
		Email:      snap.Email,
		KDF:        &kdf,
		LastSyncAt: snap.LastSyncAt,
	}
}

func ensureDataDir(scope *core.Scope) string {
	dir := scope.DataDir()
	if dir == "" {
		if home, err := os.UserHomeDir(); err == nil {
			dir = filepath.Join(home, ".govault")
		} else {
			dir = os.TempDir()
		}
	}
	_ = os.MkdirAll(dir, 0o700)
	return dir
}

func deviceTypeForOS() int {
	switch runtime.GOOS {
	case "darwin":
		return 7 // macOS Desktop
	case "linux":
		return 8 // Linux Desktop
	default:
		return 6 // Windows Desktop
	}
}
