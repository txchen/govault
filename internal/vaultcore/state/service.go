package state

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/txchen/govault/internal/vaultcore/api"
	"github.com/txchen/govault/internal/vaultcore/crypto"
	"github.com/txchen/govault/internal/vaultcore/realtime"
	"github.com/txchen/govault/internal/vaultcore/store"
)

const (
	refreshTokenKeyPrefix = "refresh_token:"
	userKeyPrefix         = "userkey:"

	twoFactorRememberPrefix = "twofactor_remember:"
)

type ServiceConfig struct {
	Store             store.Store
	Secrets           store.SecretStore
	AccountID         string
	DeviceID          string
	DeviceName        string
	DeviceType        int
	HTTPClient        *http.Client
	NewRealtimeClient func(serverURL string) (realtime.Client, error)
	OnStatusChange    func(LockStatus)
	OnVaultUpdated    func()
	// Tokens, when set, supplies access tokens instead of the refresh
	// token kept in Secrets, for a client that manages its own sign-in,
	// such as gv. A session unlocked with it is never local-only.
	Tokens TokenSource
	// NewClient, when set, builds the API client instead of the default
	// one for the snapshot's server URL.
	NewClient func(serverURL string) (*api.Client, error)
}

// TokenSource gives a Service its access tokens.
type TokenSource interface {
	// AccessToken returns a valid access token other than stale,
	// renewing one when needed.
	AccessToken(ctx context.Context, stale string) (string, error)
}

type Service struct {
	cfg ServiceConfig

	mu             sync.RWMutex
	status         LockStatus
	accountID      string
	snapshot       *store.Snapshot
	apiClient      *api.Client
	accessToken    string
	userKey        *crypto.SymmetricKey
	ciphers        map[string]*Cipher
	folders        map[string]Folder
	orgs           map[string]Organization
	collections    map[string]Collection
	orgKeys        map[string]*crypto.SymmetricKey
	realtimeCancel context.CancelFunc

	sessionGen    uint64
	sessionCtx    context.Context
	sessionCancel context.CancelFunc
	unreadable    []string
	// userID is the server ID of the signed-in user (profile.id), which item
	// writes name as encryptedFor. It is kept apart from accountID, the key
	// the vault is stored under, which an older server may have left as
	// the email.
	userID        string
	premium       bool
	archiveKnown  bool
	archiveAbsent bool
	credsUnsaved  bool
	// localOnly marks an unlocked session whose saved sign-in could not be
	// validated: the vault is readable, but nothing goes to the server
	// until the user signs in again.
	localOnly bool
	// persistMu orders every snapshot writer: it is held from choosing the
	// snapshot to edit, through the disk write, to publishing the result
	// in memory. snapSeq counts publications, so a sync that fetched before
	// a change was committed can tell it is stale.
	persistMu sync.Mutex
	snapSeq   uint64
	secretMu  sync.Mutex
	// refreshMu makes one token refresh at a time, so concurrent callers
	// never send the same rotating refresh token twice.
	refreshMu sync.Mutex
	// unsavedRefresh holds a refresh token the server issued but the
	// secret store could not save, for the rest of the session.
	unsavedRefresh string
}

var _ VaultService = (*Service)(nil)

func NewService(cfg ServiceConfig) (*Service, error) {
	if cfg.Store == nil {
		return nil, errors.New("state: Store is required")
	}
	s := &Service{
		cfg:       cfg,
		status:    StatusLoggedOut,
		accountID: cfg.AccountID,
	}
	if cfg.AccountID != "" {
		if snap, err := cfg.Store.LoadSnapshot(cfg.AccountID); err == nil {
			s.snapshot = snap
			s.status = StatusLocked
		}
	}
	return s, nil
}

func (s *Service) Status() LockStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.status
}

func (s *Service) Login(ctx context.Context, req LoginRequest) error {
	gen := s.attemptFrom(ctx)
	serverURL, email := req.ServerURL, req.Email
	// Sign In Again goes only to the server this account last signed in to,
	// as the secret store records it; nothing, prelogin included, is sent
	// anywhere else.
	if want := req.SameAccount; want != nil {
		if trusted := s.TrustedServerURL(want.ID); trusted != "" && serverOrigin(trusted) != serverOrigin(serverURL) {
			return ErrDifferentAccount
		}
	}
	client, kdfCfg, masterKey, pwHash, err := s.prepareLogin(ctx, req)
	if err != nil {
		return err
	}
	defer crypto.ZeroBytes(masterKey[:])

	rememberKey := twoFactorRememberKey(serverURL, email)
	var twoFactor *api.TwoFactorLogin
	usedRemembered := false
	if code := strings.TrimSpace(req.TwoFactorCode); code != "" {
		twoFactor = &api.TwoFactorLogin{Provider: req.TwoFactorProvider, Token: code, Remember: req.RememberDevice}
	} else if s.cfg.Secrets != nil {
		if remembered, ok, _ := s.cfg.Secrets.Get(rememberKey); ok && remembered != "" {
			twoFactor = &api.TwoFactorLogin{Provider: api.TwoFactorRemember, Token: remembered}
			usedRemembered = true
		}
	}

	tok, err := client.LoginPasswordWith(ctx, email, pwHash, api.PasswordLoginOptions{TwoFactor: twoFactor, NewDeviceOTP: req.NewDeviceOTP})
	if err != nil {
		if usedRemembered && errors.Is(err, api.ErrTwoFactorRequired) {
			_ = s.cfg.Secrets.Delete(rememberKey)
		}
		return err
	}

	userKey, err := crypto.DecryptUserKey(tok.Key, masterKey)
	if err != nil {
		return err
	}

	// The revision is read before the vault, so a change made in between
	// makes the snapshot look older, never newer, than it is.
	revDate, _ := client.RevisionDate(ctx, tok.AccessToken)
	syncResp, rawSync, err := client.Sync(ctx, tok.AccessToken)
	if err != nil {
		userKey.Zero()
		return err
	}

	data, err := decryptSyncResponse(syncResp, userKey)
	if err != nil {
		userKey.Zero()
		return err
	}
	committed := false
	defer func() {
		if !committed {
			data.zero()
		}
	}()

	accountID := syncResp.Profile.ID
	if accountID == "" {
		accountID = crypto.NormalizeEmail(email)
	}
	if want := req.SameAccount; want != nil && (want.ID != accountID || serverOrigin(want.ServerURL) != serverOrigin(serverURL)) {
		userKey.Zero()
		return ErrDifferentAccount
	}
	snap := &store.Snapshot{
		SchemaVersion: store.CurrentSchemaVersion,
		AccountID:     accountID,
		ServerURL:     strings.TrimRight(strings.TrimSpace(serverURL), "/"),
		Email:         crypto.NormalizeEmail(email),
		KDF:           kdfCfg,
		ProtectedKey:  tok.Key,
		RevisionDate:  revDate,
		LastSyncAt:    time.Now().UTC(),
		RawSyncJSON:   rawSync,
	}
	if s.attemptGen() != gen {
		userKey.Zero()
		return ErrLocked
	}
	if err := s.cfg.Store.SaveSnapshot(snap); err != nil {
		userKey.Zero()
		return err
	}
	if s.cfg.Secrets != nil && tok.RefreshToken != "" {
		// secretMu orders this write with logout's deletion: a logout that
		// began first wins, and one that comes later deletes the token.
		s.secretMu.Lock()
		if s.attemptGen() != gen {
			s.secretMu.Unlock()
			userKey.Zero()
			return ErrLocked
		}
		err := s.saveRefreshToken(accountID, snap.ServerURL, tok.RefreshToken)
		if err == nil {
			err = s.saveSignInRecord(accountID, snap.ServerURL)
		}
		s.secretMu.Unlock()
		if err != nil {
			userKey.Zero()
			return err
		}
	}
	if s.cfg.Secrets != nil && tok.TwoFactorToken != "" {
		_ = s.cfg.Secrets.Set(rememberKey, tok.TwoFactorToken)
	}

	s.mu.Lock()
	if s.sessionGen != gen {
		s.mu.Unlock()
		userKey.Zero()
		return ErrLocked
	}
	s.stopRealtimeLocked()
	s.startSessionLocked()
	if s.userKey != nil {
		s.userKey.Zero()
	}
	s.accountID = accountID
	s.snapshot = snap
	s.apiClient = client
	s.accessToken = tok.AccessToken
	s.localOnly = false
	s.credsUnsaved = false
	s.userKey = userKey
	s.applyDataLocked(data)
	committed = true
	s.status = StatusUnlocked
	s.mu.Unlock()

	s.notifyStatus(StatusUnlocked)
	s.notifyUpdated()
	return nil
}

// LoginSSO exchanges an SSO authorization code and PKCE verifier for a
// signed-in session and saves the encrypted vault snapshot. Because SSO
// does not supply the master password, the vault enters StatusLocked so
// the caller can unlock it with UnlockWithPassword.
func (s *Service) LoginSSO(ctx context.Context, req SSOLoginRequest) error {
	gen := s.attemptFrom(ctx)
	serverURL := req.ServerURL
	if want := req.SameAccount; want != nil {
		if trusted := s.TrustedServerURL(want.ID); trusted != "" && serverOrigin(trusted) != serverOrigin(serverURL) {
			return ErrDifferentAccount
		}
	}
	client, err := s.newAPIClient(serverURL)
	if err != nil {
		return err
	}

	var twoFactor *api.TwoFactorLogin
	usedRemembered := false
	rememberKey := ""
	if code := strings.TrimSpace(req.TwoFactorCode); code != "" {
		twoFactor = &api.TwoFactorLogin{Provider: req.TwoFactorProvider, Token: code, Remember: req.RememberDevice}
	} else if s.cfg.Secrets != nil && strings.TrimSpace(req.Email) != "" {
		rememberKey = twoFactorRememberKey(serverURL, req.Email)
		if remembered, ok, _ := s.cfg.Secrets.Get(rememberKey); ok && remembered != "" {
			twoFactor = &api.TwoFactorLogin{Provider: api.TwoFactorRemember, Token: remembered}
			usedRemembered = true
		}
	}

	tok, err := client.LoginSSO(ctx, api.SSOLoginOptions{
		Code:         req.Code,
		CodeVerifier: req.CodeVerifier,
		RedirectURI:  req.RedirectURI,
		TwoFactor:    twoFactor,
	})
	if err != nil {
		if usedRemembered && rememberKey != "" && errors.Is(err, api.ErrTwoFactorRequired) {
			_ = s.cfg.Secrets.Delete(rememberKey)
		}
		return err
	}

	if err := checkSSODecryptionSupport(tok); err != nil {
		return err
	}
	sub, err := api.TokenSubject(tok.AccessToken)
	if err != nil {
		return err
	}

	revDate, _ := client.RevisionDate(ctx, tok.AccessToken)
	syncResp, rawSync, err := client.Sync(ctx, tok.AccessToken)
	if err != nil {
		return err
	}

	if syncResp.Profile.ID != "" && syncResp.Profile.ID != sub {
		return ErrDifferentAccount
	}
	email := crypto.NormalizeEmail(syncResp.Profile.Email)
	if email == "" {
		email = crypto.NormalizeEmail(req.Email)
	}
	accountID := syncResp.Profile.ID
	if accountID == "" {
		accountID = sub
	}
	if accountID == "" {
		accountID = email
	}
	if want := req.SameAccount; want != nil && (want.ID != accountID || serverOrigin(want.ServerURL) != serverOrigin(serverURL)) {
		return ErrDifferentAccount
	}

	protectedKey := tok.MasterPasswordProtectedKey()
	if protectedKey == "" {
		protectedKey = syncResp.Profile.Key
	}
	if protectedKey == "" {
		return ErrSSOMasterPasswordRequired
	}

	kdfCfg := tok.MasterPasswordKDF()
	if kdfCfg.Iterations == 0 {
		kdfCfg = crypto.KDFConfig{Type: crypto.KDFType(syncResp.Profile.KDF), Iterations: uint32(syncResp.Profile.KDFIters)}
		if syncResp.Profile.KDFMemory != nil {
			kdfCfg.MemoryMB = uint32(*syncResp.Profile.KDFMemory)
		}
		if syncResp.Profile.KDFParallel != nil {
			kdfCfg.Parallelism = uint32(*syncResp.Profile.KDFParallel)
		}
	}

	snap := &store.Snapshot{
		SchemaVersion: store.CurrentSchemaVersion,
		AccountID:     accountID,
		ServerURL:     strings.TrimRight(strings.TrimSpace(serverURL), "/"),
		Email:         email,
		KDFSalt:       tok.MasterPasswordSalt(),
		KDF:           kdfCfg,
		ProtectedKey:  protectedKey,
		RevisionDate:  revDate,
		LastSyncAt:    time.Now().UTC(),
		RawSyncJSON:   rawSync,
	}

	// Serialize durable writes with persistMu and secretMu so revocation or
	// a failing secret store cannot leave a half-written account on disk.
	prevStatus, err := s.commitSSODurable(gen, client, accountID, serverURL, email, snap, tok)
	if err != nil {
		return err
	}

	// Only notify if an unlocked session was actually left; on normal SSO
	// login (LoggedOut -> Locked) and ReSignIn (Locked -> Locked), the
	// caller drives the transition to the unlock screen without triggering
	// the production shell's "left unlocked" revocation handler.
	if prevStatus == StatusUnlocked {
		s.notifyStatus(StatusLocked)
	}
	return nil
}

func (s *Service) commitSSODurable(gen uint64, client *api.Client, accountID, serverURL, email string, snap *store.Snapshot, tok *api.TokenResponse) (LockStatus, error) {
	s.persistMu.Lock()
	defer s.persistMu.Unlock()
	s.secretMu.Lock()
	defer s.secretMu.Unlock()

	if s.attemptGen() != gen {
		return StatusLoggedOut, ErrLocked
	}
	// Positively read existing durable state (or confirm not-found) before
	// writing anything, so rollback can never delete data it failed to read.
	prevSnap, prevSnapErr := s.cfg.Store.LoadSnapshot(accountID)
	var hadPrevSnap bool
	switch {
	case prevSnapErr == nil && prevSnap != nil:
		hadPrevSnap = true
	case errors.Is(prevSnapErr, store.ErrSnapshotNotFound):
		hadPrevSnap = false
	default:
		return StatusLoggedOut, prevSnapErr
	}
	restoreSnap := func() error {
		if hadPrevSnap {
			return s.cfg.Store.SaveSnapshot(prevSnap)
		}
		return s.cfg.Store.DeleteSnapshot(accountID)
	}

	var prevRefresh, prevSignIn string
	var hadRefresh, hadSignIn bool
	if s.cfg.Secrets != nil && tok.RefreshToken != "" {
		var err error
		if prevRefresh, hadRefresh, err = s.cfg.Secrets.Get(refreshTokenKeyPrefix + accountID); err != nil {
			return StatusLoggedOut, err
		}
		if prevSignIn, hadSignIn, err = s.cfg.Secrets.Get(signInRecordPrefix + accountID); err != nil {
			return StatusLoggedOut, err
		}
	}
	restoreSecrets := func() error {
		if s.cfg.Secrets == nil || tok.RefreshToken == "" {
			return nil
		}
		var rErr, sErr error
		if hadRefresh {
			rErr = s.cfg.Secrets.Set(refreshTokenKeyPrefix+accountID, prevRefresh)
		} else {
			rErr = s.cfg.Secrets.Delete(refreshTokenKeyPrefix + accountID)
		}
		if hadSignIn {
			sErr = s.cfg.Secrets.Set(signInRecordPrefix+accountID, prevSignIn)
		} else {
			sErr = s.cfg.Secrets.Delete(signInRecordPrefix + accountID)
		}
		return errors.Join(rErr, sErr)
	}

	if err := s.cfg.Store.SaveSnapshot(snap); err != nil {
		return StatusLoggedOut, err
	}
	if s.cfg.Secrets != nil && tok.RefreshToken != "" {
		if err := s.saveRefreshToken(accountID, snap.ServerURL, tok.RefreshToken); err != nil {
			return StatusLoggedOut, errors.Join(err, restoreSnap())
		}
		if err := s.saveSignInRecord(accountID, snap.ServerURL); err != nil {
			return StatusLoggedOut, errors.Join(err, restoreSecrets(), restoreSnap())
		}
	}

	s.mu.Lock()
	if s.sessionGen != gen {
		s.mu.Unlock()
		return StatusLoggedOut, errors.Join(ErrLocked, restoreSecrets(), restoreSnap())
	}
	prevStatus := s.status
	s.stopRealtimeLocked()
	s.endSessionLocked()
	if s.userKey != nil {
		s.userKey.Zero()
		s.userKey = nil
	}
	s.clearDataLocked()
	s.accountID = accountID
	s.snapshot = snap
	s.apiClient = client
	s.localOnly = false
	s.credsUnsaved = false
	s.status = StatusLocked
	s.mu.Unlock()

	if s.cfg.Secrets != nil && tok.TwoFactorToken != "" && email != "" {
		_ = s.cfg.Secrets.Set(twoFactorRememberKey(serverURL, email), tok.TwoFactorToken)
	}
	return prevStatus, nil
}

func checkSSODecryptionSupport(tok *api.TokenResponse) error {
	if tok == nil {
		return nil
	}
	if tok.ForcePasswordReset {
		return ErrSSOForcePasswordReset
	}
	if tok.UserDecryptionOptions == nil || tok.UserDecryptionOptions.HasMasterPassword {
		return nil
	}
	opt := tok.UserDecryptionOptions
	if opt.KeyConnectorOption != nil {
		return ErrSSOKeyConnectorUnsupported
	}
	if opt.TrustedDeviceOption != nil {
		return ErrSSOTrustedDeviceUnsupported
	}
	return ErrSSOMasterPasswordRequired
}

func (s *Service) SendEmailTwoFactorCode(ctx context.Context, req LoginRequest) error {
	client, _, masterKey, pwHash, err := s.prepareLogin(ctx, req)
	if err != nil {
		return err
	}
	crypto.ZeroBytes(masterKey[:])
	return client.SendEmailTwoFactorLogin(ctx, req.Email, pwHash)
}

func (s *Service) SendEmailTwoFactorCodeSSO(ctx context.Context, serverURL, email, ssoSessionToken string) error {
	client, err := s.newAPIClient(serverURL)
	if err != nil {
		return err
	}
	return client.SendEmailTwoFactorLoginSSO(ctx, email, ssoSessionToken)
}

// ResendNewDeviceOTP asks the server to email the new device verification
// code again, for the login req describes.
func (s *Service) ResendNewDeviceOTP(ctx context.Context, req LoginRequest) error {
	if want := req.SameAccount; want != nil {
		if trusted := s.TrustedServerURL(want.ID); trusted != "" && serverOrigin(trusted) != serverOrigin(req.ServerURL) {
			return ErrDifferentAccount
		}
	}
	client, _, masterKey, pwHash, err := s.prepareLogin(ctx, req)
	if err != nil {
		return err
	}
	crypto.ZeroBytes(masterKey[:])
	return client.ResendNewDeviceOTP(ctx, req.Email, pwHash)
}

func (s *Service) prepareLogin(ctx context.Context, req LoginRequest) (*api.Client, crypto.KDFConfig, [32]byte, string, error) {
	client, err := s.newAPIClient(req.ServerURL)
	if err != nil {
		return nil, crypto.KDFConfig{}, [32]byte{}, "", err
	}
	kdfCfg, err := client.Prelogin(ctx, req.Email)
	if err != nil {
		return nil, kdfCfg, [32]byte{}, "", err
	}
	masterKey, err := crypto.DeriveMasterKey(req.MasterPassword, req.Email, kdfCfg)
	if err != nil {
		return nil, kdfCfg, [32]byte{}, "", err
	}
	return client, kdfCfg, masterKey, crypto.HashMasterPasswordForServer(masterKey, req.MasterPassword), nil
}

func twoFactorRememberKey(serverURL, email string) string {
	return twoFactorRememberPrefix + strings.TrimRight(strings.TrimSpace(serverURL), "/") + "|" + crypto.NormalizeEmail(email)
}

// attemptGen is the session generation an unlock or login starts under.
// Lock, logout and a system sleep advance it, so an attempt still running
// then can never publish an unlocked vault afterwards.
func (s *Service) attemptGen() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sessionGen
}

// AuthAttempt names a sign-in or unlock about to start. Passed in its
// context (WithAuthAttempt), it lets the service refuse to publish an
// attempt that a sleep, lock or logout revoked before it finished.
func (s *Service) AuthAttempt() uint64 { return s.attemptGen() }

// RevokeAuthAttempts ends every sign-in and unlock in progress, for a
// sleep, lock, logout or Back to Unlock while the user sees no unlocked
// vault. One that already committed its session in the meantime, before
// the UI heard of it, is locked again: either way nothing it started
// stays open.
func (s *Service) RevokeAuthAttempts() {
	s.mu.Lock()
	if s.status == StatusUnlocked {
		s.mu.Unlock()
		s.Lock()
		return
	}
	s.endSessionLocked()
	s.mu.Unlock()
}

// Account is the account of the vault on this device: the one open, or
// else the one whose snapshot would be unlocked. Its server is left out:
// the snapshot is editable, so where to sign in comes only from
// TrustedServerURL.
func (s *Service) Account() Account {
	snap, err := s.loadCurrentSnapshot()
	if err != nil || snap == nil {
		return Account{}
	}
	return Account{ID: snap.AccountID, Email: snap.Email}
}

// TrustedServerURL is the server accountID last signed in to, from the
// record each sign-in keeps in the secret store, or "" when there is none
// (such as after an upgrade from a version that kept no record).
func (s *Service) TrustedServerURL(accountID string) string {
	if s.cfg.Secrets == nil || accountID == "" {
		return ""
	}
	raw, ok, err := s.cfg.Secrets.Get(signInRecordPrefix + accountID)
	if err != nil || !ok {
		return ""
	}
	var rec signInRecord
	if json.Unmarshal([]byte(raw), &rec) != nil || rec.AccountID != accountID || serverOrigin(rec.ServerURL) == "" {
		return ""
	}
	return rec.ServerURL
}

const signInRecordPrefix = "signin:"

// signInRecord is where an account signed in, kept apart from its refresh
// token so it survives token problems.
type signInRecord struct {
	ServerURL string `json:"server"`
	AccountID string `json:"account"`
}

func (s *Service) saveSignInRecord(accountID, serverURL string) error {
	raw, err := json.Marshal(signInRecord{ServerURL: serverURL, AccountID: accountID})
	if err != nil {
		return err
	}
	return s.cfg.Secrets.Set(signInRecordPrefix+accountID, string(raw))
}

type authAttemptKey struct{}

// WithAuthAttempt binds a sign-in or unlock to the attempt captured when
// the user started it.
func WithAuthAttempt(ctx context.Context, attempt uint64) context.Context {
	return context.WithValue(ctx, authAttemptKey{}, attempt)
}

func (s *Service) attemptFrom(ctx context.Context) uint64 {
	if a, ok := ctx.Value(authAttemptKey{}).(uint64); ok {
		return a
	}
	return s.attemptGen()
}

// LocalOnly reports an unlocked vault whose saved sign-in could not be
// validated, so it does not sync until the user signs in again.
func (s *Service) LocalOnly() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.status == StatusUnlocked && s.localOnly
}

// CredentialsNotSaved reports that the server issued a new sign-in this
// session that could not be saved, so after locking the user must sign in
// again. It stays set until a later save succeeds or the user signs in.
func (s *Service) CredentialsNotSaved() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.status == StatusUnlocked && s.credsUnsaved
}

func (s *Service) UnlockWithPassword(ctx context.Context, masterPassword []byte) error {
	gen := s.attemptFrom(ctx)
	snap, err := s.loadCurrentSnapshot()
	if err != nil {
		return err
	}

	masterKey, err := crypto.DeriveKeyFromPassword(masterPassword, snap.EffectiveKDFSalt(), snap.KDF)
	if err != nil {
		return err
	}
	defer crypto.ZeroBytes(masterKey[:])

	userKey, err := crypto.DecryptUserKey(snap.ProtectedKey, masterKey)
	if err != nil {
		return err
	}
	defer userKey.Zero()

	return s.unlock(ctx, userKey, gen)
}

func (s *Service) UnlockWithUserKey(ctx context.Context, userKey *crypto.SymmetricKey) error {
	return s.unlock(ctx, userKey, s.attemptFrom(ctx))
}

func (s *Service) unlock(ctx context.Context, userKey *crypto.SymmetricKey, gen uint64) error {
	if userKey == nil {
		return crypto.ErrInvalidKeyLength
	}
	snap, err := s.loadCurrentSnapshot()
	if err != nil {
		return err
	}

	var syncResp api.SyncResponse
	if err := json.Unmarshal(snap.RawSyncJSON, &syncResp); err != nil {
		return err
	}

	ownedBytes := userKey.Bytes()
	ownedKey, err := crypto.SymmetricKeyFromBytes(ownedBytes[:])
	crypto.ZeroBytes(ownedBytes[:])
	if err != nil {
		return err
	}

	data, err := decryptSyncResponse(&syncResp, ownedKey)
	if err != nil {
		ownedKey.Zero()
		return err
	}

	// The vault decrypted, so it opens even when the saved sign-in cannot
	// be trusted or read; it is then local only.
	// A local-only session builds no API client, so a malformed server
	// address in the snapshot cannot keep a good vault shut.
	var credErr error
	if s.cfg.Tokens == nil {
		_, credErr = s.loadRefreshToken(snap.AccountID, snap.ServerURL)
	}
	localOnly := credErr != nil || snap.ServerURL == ""
	var client *api.Client
	if !localOnly {
		if client, err = s.newAPIClient(snap.ServerURL); err != nil {
			localOnly, client = true, nil
		}
	}

	s.mu.Lock()
	if s.sessionGen != gen {
		s.mu.Unlock()
		ownedKey.Zero()
		data.zero()
		return ErrLocked
	}
	s.stopRealtimeLocked()
	s.startSessionLocked()
	if s.userKey != nil {
		s.userKey.Zero()
	}
	s.accountID = snap.AccountID
	s.snapshot = snap
	s.apiClient = client
	s.localOnly = localOnly
	s.credsUnsaved = false
	s.userKey = ownedKey
	s.applyDataLocked(data)
	s.status = StatusUnlocked
	s.mu.Unlock()

	s.notifyStatus(StatusUnlocked)
	s.notifyUpdated()
	return nil
}

func (s *Service) EnableBiometricUnlock(secrets store.SecretStore) error {
	if secrets == nil {
		return ErrInvalidSecretStore
	}
	s.mu.RLock()
	if s.status != StatusUnlocked || s.userKey == nil {
		s.mu.RUnlock()
		return ErrLocked
	}
	accountID := s.accountID
	raw := s.userKey.Bytes()
	s.mu.RUnlock()
	defer crypto.ZeroBytes(raw[:])

	return secrets.Set(userKeyPrefix+accountID, base64.StdEncoding.EncodeToString(raw[:]))
}

func (s *Service) DisableBiometricUnlock(secrets store.SecretStore) error {
	if secrets == nil {
		return ErrInvalidSecretStore
	}
	s.mu.RLock()
	accountID := s.accountID
	s.mu.RUnlock()
	if accountID == "" {
		return ErrLoggedOut
	}
	return secrets.Delete(userKeyPrefix + accountID)
}

func (s *Service) Lock() {
	s.mu.Lock()
	s.endSessionLocked()
	s.stopRealtimeLocked()
	if s.userKey != nil {
		s.userKey.Zero()
		s.userKey = nil
	}
	s.clearDataLocked()
	nextStatus := s.status
	if s.status == StatusUnlocked {
		if s.snapshot != nil || s.accountID != "" {
			s.status = StatusLocked
		} else {
			s.status = StatusLoggedOut
		}
		nextStatus = s.status
	}
	s.mu.Unlock()

	s.notifyStatus(nextStatus)
}

// Logout ends the session and clears memory first, so observers can revoke
// derived secrets before the slower snapshot and keychain deletion.
func (s *Service) Logout(ctx context.Context, secrets store.SecretStore) error {
	return s.logout(secrets, nil)
}

// logoutIfSession logs out only while gen is still the active session, so a
// delayed event from an earlier session cannot end a later one.
func (s *Service) logoutIfSession(gen uint64, secrets store.SecretStore) error {
	return s.logout(secrets, &gen)
}

func (s *Service) logout(secrets store.SecretStore, gen *uint64) error {
	s.mu.Lock()
	if gen != nil && (s.sessionGen != *gen || s.sessionCtx == nil) {
		s.mu.Unlock()
		return nil
	}
	s.endSessionLocked()
	s.stopRealtimeLocked()
	accountID := s.accountID
	if s.userKey != nil {
		s.userKey.Zero()
		s.userKey = nil
	}
	s.clearDataLocked()
	s.snapshot = nil
	s.apiClient = nil
	s.accountID = ""
	s.status = StatusLoggedOut
	s.mu.Unlock()

	s.notifyStatus(StatusLoggedOut)
	if accountID == "" {
		return nil
	}

	var errs []error
	s.persistMu.Lock()
	if err := s.cfg.Store.DeleteSnapshot(accountID); err != nil && !errors.Is(err, store.ErrSnapshotNotFound) {
		errs = append(errs, err)
	}
	s.persistMu.Unlock()
	s.secretMu.Lock()
	defer s.secretMu.Unlock()
	stores := []store.SecretStore{secrets}
	if s.cfg.Secrets != nil && s.cfg.Secrets != secrets {
		stores = append(stores, s.cfg.Secrets)
	}
	for _, sec := range stores {
		if sec == nil {
			continue
		}
		for _, key := range []string{refreshTokenKeyPrefix + accountID, userKeyPrefix + accountID, signInRecordPrefix + accountID} {
			if err := sec.Delete(key); err != nil {
				errs = append(errs, fmt.Errorf("state: delete %s: %w", strings.TrimSuffix(key, accountID), err))
			}
		}
	}
	return errors.Join(errs...)
}

func (s *Service) SyncNow(ctx context.Context) error {
	return s.sync(ctx, false)
}

func (s *Service) forceSync(ctx context.Context) error {
	return s.sync(ctx, true)
}

// errSyncStale means a change was committed while a sync was fetching, so
// its data is older than the snapshot and must not replace it.
var errSyncStale = errors.New("state: sync result is older than a committed change")

func (s *Service) sync(ctx context.Context, force bool) error {
	for range 3 {
		err := s.syncOnce(ctx, force)
		if !errors.Is(err, errSyncStale) {
			return err
		}
		force = true
	}
	// Changes keep landing; every fetch was older than what is committed,
	// so nothing was applied. A later sync catches up.
	return ErrSyncDeferred
}

func (s *Service) syncOnce(ctx context.Context, force bool) error {
	o, err := s.beginOp(ctx)
	if err != nil {
		return err
	}
	defer o.end()

	revDate, revErr := withAuth(o, func(ctx context.Context, tok string) (time.Time, error) {
		return o.client.RevisionDate(ctx, tok)
	})
	if !force && revErr == nil && !o.snap.RevisionDate.IsZero() && revDate.Equal(o.snap.RevisionDate) {
		return nil
	}

	type syncResult struct {
		resp *api.SyncResponse
		raw  []byte
	}
	res, err := withAuth(o, func(ctx context.Context, tok string) (syncResult, error) {
		resp, raw, err := o.client.Sync(ctx, tok)
		return syncResult{resp: resp, raw: raw}, err
	})
	if err != nil {
		return err
	}

	data, err := decryptSyncResponse(res.resp, o.userKey)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			data.zero()
		}
	}()

	if err := o.commitSync(res.raw, res.resp.Profile.Key, revDate, data); err != nil {
		return err
	}
	committed = true
	s.notifyUpdated()
	return nil
}

// commitSync replaces the snapshot and memory with a sync result, unless a
// change was committed since o began; then it returns errSyncStale and
// leaves both untouched.
func (o *op) commitSync(raw []byte, protectedKey string, revDate time.Time, data *vaultData) error {
	s := o.s
	s.persistMu.Lock()
	defer s.persistMu.Unlock()
	s.mu.RLock()
	cur, seq, ok := s.snapshot, s.snapSeq, o.currentLocked()
	s.mu.RUnlock()
	switch {
	case !ok:
		return ErrLocked
	case cur == nil:
		return ErrLoggedOut
	case seq != o.seq:
		return errSyncStale
	}
	updated := *cur
	if !revDate.IsZero() {
		updated.RevisionDate = revDate
	}
	if protectedKey != "" {
		updated.ProtectedKey = protectedKey
	}
	updated.LastSyncAt = time.Now().UTC()
	updated.RawSyncJSON = raw
	if err := s.cfg.Store.SaveSnapshot(&updated); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !o.currentLocked() {
		return ErrLocked
	}
	s.snapshot = &updated
	s.snapSeq++
	s.applyDataLocked(data)
	return nil
}

func (s *Service) StartRealtime(ctx context.Context) error {
	o, err := s.beginOp(ctx)
	if err != nil {
		return err
	}
	o.userKey.Zero()
	serverURL := o.snap.ServerURL

	s.mu.Lock()
	if !o.currentLocked() {
		s.mu.Unlock()
		o.release()
		return ErrLocked
	}
	s.stopRealtimeLocked()
	s.realtimeCancel = o.release
	s.mu.Unlock()

	var rtClient realtime.Client
	if s.cfg.NewRealtimeClient != nil {
		rtClient, err = s.cfg.NewRealtimeClient(serverURL)
	} else {
		rtClient, err = realtime.NewClient(realtime.Config{
			ServerURL:  serverURL,
			HTTPClient: s.cfg.HTTPClient,
		})
	}
	if err != nil {
		o.release()
		return err
	}

	go func() {
		_ = rtClient.Run(o.ctx, opTokens{o}, func() {
			// Changes made while disconnected sent no notification.
			go func() { _ = s.SyncNow(o.ctx) }()
		}, func(ev realtime.Event) {
			_ = s.handleRealtimeEvent(o.ctx, o.gen, ev)
		})
	}()
	return nil
}

// opTokens gives the realtime connection the session's access token; a
// token the hub rejected is dropped so the next one is refreshed.
type opTokens struct{ o *op }

func (t opTokens) Token() (string, error) { return t.o.accessToken() }

func (t opTokens) Rejected(token string) {
	t.o.s.mu.Lock()
	defer t.o.s.mu.Unlock()
	if t.o.currentLocked() && t.o.s.accessToken == token {
		t.o.s.accessToken = ""
	}
}

// HandleRealtimeEvent applies ev to the current session.
func (s *Service) HandleRealtimeEvent(ctx context.Context, ev realtime.Event) error {
	s.mu.RLock()
	gen := s.sessionGen
	s.mu.RUnlock()
	return s.handleRealtimeEvent(ctx, gen, ev)
}

// handleRealtimeEvent applies ev only while gen, the session whose stream
// delivered it, is still active.
func (s *Service) handleRealtimeEvent(ctx context.Context, gen uint64, ev realtime.Event) error {
	if ev.Type == realtime.LogOut {
		return s.logoutIfSession(gen, s.cfg.Secrets)
	}
	s.mu.RLock()
	stale := s.sessionGen != gen
	s.mu.RUnlock()
	if stale {
		return nil
	}
	if ev.ContextID != "" && ev.ContextID == s.cfg.DeviceID {
		return nil
	}
	if ev.Type >= realtime.SyncCipherUpdate && ev.Type <= realtime.SyncFolderUpdate {
		return s.forceSync(ctx)
	}
	return nil
}

func (s *Service) Search(query string, filter SearchFilter) []CipherSummary {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.status != StatusUnlocked {
		return nil
	}
	return searchCiphers(s.ciphers, query, filter, s.effectiveHidePasswordLocked)
}

func (s *Service) GetCipher(id string) (*Cipher, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.status != StatusUnlocked {
		return nil, ErrLocked
	}
	c, ok := s.ciphers[id]
	if !ok {
		return nil, ErrCipherNotFound
	}
	return cloneCipher(c), nil
}

// AllCiphers returns copies of every decrypted item for local analysis.
// HidePassword also reflects collections that hide passwords, and hidden
// passwords are removed from the copies.
func (s *Service) AllCiphers() []*Cipher {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.allCiphersLocked()
}

// BackupData is everything an export reads, taken at one moment.
type BackupData struct {
	Ciphers    []*Cipher
	Folders    []Folder
	Unreadable []string
}

// BackupData returns the items, folders and unreadable item IDs under one
// read lock, so a sync can never slip between checking that the backup is
// complete and reading what goes into it.
func (s *Service) BackupData() BackupData {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.status != StatusUnlocked {
		return BackupData{}
	}
	d := BackupData{Ciphers: s.allCiphersLocked(), Unreadable: slices.Clone(s.unreadable)}
	for _, f := range s.folders {
		d.Folders = append(d.Folders, Folder{ID: f.ID, Name: f.Name, RevisionDate: cloneTimePtr(f.RevisionDate), Extra: cloneExtra(f.Extra)})
	}
	return d
}

func (s *Service) allCiphersLocked() []*Cipher {
	if s.status != StatusUnlocked {
		return nil
	}
	out := make([]*Cipher, 0, len(s.ciphers))
	for _, c := range s.ciphers {
		cp := cloneCipher(c)
		cp.HidePassword = s.effectiveHidePasswordLocked(c)
		cp.ReadOnly = s.effectiveReadOnlyLocked(c)
		if cp.HidePassword {
			if cp.Login != nil {
				cp.Login.Password = ""
			}
			cp.PasswordHistory = nil
		}
		out = append(out, cp)
	}
	return out
}

func (s *Service) SaveCipher(ctx context.Context, c *Cipher) (*Cipher, error) {
	if c == nil {
		return nil, ErrCipherNotFound
	}
	o, err := s.beginOp(ctx)
	if err != nil {
		return nil, err
	}
	defer o.end()

	c = cloneCipher(c)
	s.mu.RLock()
	premium := s.premium
	s.mu.RUnlock()
	if c.ID == "" && c.ArchivedDate != nil && !premium {
		// Creating an archived item, as an import can, needs premium like
		// archiving does; without it the item is created in the vault.
		c.ArchivedDate = nil
	}
	if c.ID != "" {
		existing, err := o.editableCipher(c.ID)
		if err != nil && !errors.Is(err, ErrCipherNotFound) {
			return nil, err
		}
		// The archive is per user and changes without touching the item's
		// revision, so a draft may carry a stale archive date. Every update
		// takes the server's current one, also for an item gone from this
		// device; the draft's revision still guards the content.
		cur, err := withAuth(o, func(ctx context.Context, tok string) (*api.EncryptedCipher, error) {
			return o.client.GetCipher(ctx, tok, c.ID)
		})
		if errors.Is(err, api.ErrNotFound) {
			return nil, ErrCipherNotFound
		}
		if err != nil {
			return nil, err
		}
		s.noteArchiveEvidence(cur)
		c.ArchivedDate = cloneTimePtr(cur.ArchivedDate)
		if cur.ArchivedDate != nil && !premium && cur.Favorite != c.Favorite {
			return nil, ErrPremiumRequired
		}
		if existing != nil {
			recordPasswordChange(existing, c, time.Now().UTC())
			if c.OrganizationID == nil {
				c.OrganizationID = cloneStringPtr(existing.OrganizationID)
			}
			if len(c.CollectionIDs) == 0 {
				c.CollectionIDs = append([]string(nil), existing.CollectionIDs...)
			}
		}
	}
	key, err := o.itemKey(c.OrganizationID)
	if err != nil {
		return nil, err
	}
	defer key.Zero()

	payload, err := encryptCipherPayload(c, key)
	if err != nil {
		return nil, err
	}
	userID, err := o.serverUserID()
	if err != nil {
		return nil, err
	}
	payload.EncryptedFor = &userID

	encResp, err := withAuth(o, func(ctx context.Context, tok string) (*api.EncryptedCipher, error) {
		switch {
		case c.ID == "" && c.OrganizationID != nil && *c.OrganizationID != "":
			return o.client.CreateOrganizationCipher(ctx, tok, payload, c.CollectionIDs)
		case c.ID == "":
			return o.client.CreateCipher(ctx, tok, payload)
		}
		return o.client.UpdateCipher(ctx, tok, c.ID, payload)
	})
	if err != nil {
		return nil, err
	}

	respKey := key
	if !sameOrg(encResp.OrganizationID, c.OrganizationID) {
		if respKey, err = o.itemKey(encResp.OrganizationID); err != nil {
			return nil, err
		}
		defer respKey.Zero()
	}
	decrypted, err := decryptCipher(encResp, respKey)
	if err != nil {
		return nil, err
	}
	if len(decrypted.CollectionIDs) == 0 {
		decrypted.CollectionIDs = append([]string(nil), c.CollectionIDs...)
	}
	return o.commitCipher(decrypted, encResp)
}

// commitCipherIfUnchanged is commitCipher for a response that must not
// land on a vault that changed during the request (errSnapshotMoved).
func (o *op) commitCipherIfUnchanged(decrypted *Cipher, enc *api.EncryptedCipher) (*Cipher, error) {
	o.s.noteArchiveEvidence(enc)
	// The copies are taken before decrypted is published: once it is in
	// s.ciphers, other operations change it under s.mu.
	out := cloneCipher(decrypted)
	stored := *enc
	if len(stored.CollectionIDs) == 0 {
		stored.CollectionIDs = append([]string(nil), decrypted.CollectionIDs...)
	}
	err := o.updateSnapshotFrom(true, replaceSnapshotCipher(&stored), func() { o.s.ciphers[decrypted.ID] = decrypted })
	if errors.Is(err, ErrLocked) || errors.Is(err, errSnapshotMoved) {
		return nil, err
	}
	o.s.notifyUpdated()
	if lc := (*LocalCopyError)(nil); errors.As(err, &lc) {
		lc.Cipher = cloneCipher(out)
		return out, lc
	}
	return out, err
}

// commitCipher records a cipher the server returned after a change, in the
// encrypted snapshot and in memory (see updateSnapshot). On a
// *LocalCopyError the committed item is returned too, and carried in the
// error.
func (o *op) commitCipher(decrypted *Cipher, enc *api.EncryptedCipher) (*Cipher, error) {
	o.s.noteArchiveEvidence(enc)
	// The copies are taken before decrypted is published: once it is in
	// s.ciphers, other operations change it under s.mu.
	out := cloneCipher(decrypted)
	stored := *enc
	if len(stored.CollectionIDs) == 0 {
		stored.CollectionIDs = append([]string(nil), decrypted.CollectionIDs...)
	}
	err := o.updateSnapshot(replaceSnapshotCipher(&stored), func() { o.s.ciphers[decrypted.ID] = decrypted })
	if errors.Is(err, ErrLocked) {
		return nil, ErrLocked
	}
	o.s.notifyUpdated()
	if lc := (*LocalCopyError)(nil); errors.As(err, &lc) {
		lc.Cipher = cloneCipher(out)
		return out, lc
	}
	return out, err
}

func (s *Service) SoftDeleteCipher(ctx context.Context, id string) error {
	o, err := s.beginOp(ctx)
	if err != nil {
		return err
	}
	defer o.end()
	if _, err := o.editableCipher(id); err != nil {
		return err
	}

	_, err = withAuth(o, func(ctx context.Context, tok string) (struct{}, error) {
		return struct{}{}, o.client.SoftDeleteCipher(ctx, tok, id)
	})
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	err = o.updateSnapshot(func(resp *api.SyncResponse) {
		for i := range resp.Ciphers {
			if resp.Ciphers[i].ID == id {
				resp.Ciphers[i].DeletedDate = &now
			}
		}
	}, func() {
		if c, ok := s.ciphers[id]; ok {
			c.DeletedDate = &now
		}
	})
	s.notifyUpdated()
	return err
}

// moveBatch is the most IDs Bitwarden's cloud takes in one move.
const moveBatch = 500

// MoveCiphers puts the items of ids in folderID, or in no folder for nil,
// then syncs, also after a failed batch, as the batches before it moved.
func (s *Service) MoveCiphers(ctx context.Context, ids []string, folderID *string) error {
	o, err := s.beginOp(ctx)
	if err != nil {
		return err
	}
	defer o.end()
	var moveErr error
	for start := 0; start < len(ids) && moveErr == nil; start += moveBatch {
		batch := ids[start:min(start+moveBatch, len(ids))]
		_, moveErr = withAuth(o, func(ctx context.Context, tok string) (struct{}, error) {
			return struct{}{}, o.client.MoveCiphers(ctx, tok, batch, folderID)
		})
	}
	err = s.sync(ctx, true)
	s.notifyUpdated()
	if errors.Is(err, ErrSyncDeferred) {
		err = nil
	}
	if moveErr != nil {
		return moveErr
	}
	return err
}

func (s *Service) RestoreCipher(ctx context.Context, id string) error {
	o, err := s.beginOp(ctx)
	if err != nil {
		return err
	}
	defer o.end()
	if _, err := o.editableCipher(id); err != nil {
		return err
	}

	encResp, err := withAuth(o, func(ctx context.Context, tok string) (*api.EncryptedCipher, error) {
		return o.client.RestoreCipher(ctx, tok, id)
	})
	if err != nil {
		return err
	}

	key, err := o.itemKey(encResp.OrganizationID)
	if err != nil {
		return err
	}
	defer key.Zero()
	decrypted, err := decryptCipher(encResp, key)
	if err != nil {
		return err
	}
	s.mu.RLock()
	if prev := s.ciphers[decrypted.ID]; prev != nil && len(decrypted.CollectionIDs) == 0 {
		decrypted.CollectionIDs = append([]string(nil), prev.CollectionIDs...)
	}
	s.mu.RUnlock()
	_, err = o.commitCipher(decrypted, encResp)
	return err
}

func (s *Service) HardDeleteCipher(ctx context.Context, id string) error {
	o, err := s.beginOp(ctx)
	if err != nil {
		return err
	}
	defer o.end()
	if _, err := o.editableCipher(id); err != nil {
		return err
	}

	_, err = withAuth(o, func(ctx context.Context, tok string) (struct{}, error) {
		return struct{}{}, o.client.HardDeleteCipher(ctx, tok, id)
	})
	if err != nil {
		return err
	}

	err = o.removeCipher(id)
	s.notifyUpdated()
	return err
}

func (o *op) removeCipher(id string) error {
	return o.updateSnapshot(func(resp *api.SyncResponse) {
		resp.Ciphers = slices.DeleteFunc(resp.Ciphers, func(c api.EncryptedCipher) bool { return c.ID == id })
	}, func() { delete(o.s.ciphers, id) })
}

// TrashSelection lists the items in Trash the user may delete, with the
// revisions an Empty Trash confirmation is bound to.
func (s *Service) TrashSelection() TrashSelection {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sel := TrashSelection{AccountID: s.accountID}
	if s.status != StatusUnlocked {
		return sel
	}
	for id, c := range s.ciphers {
		switch {
		case c.DeletedDate == nil:
		case s.effectiveReadOnlyLocked(c):
			sel.ReadOnly++
		default:
			sel.Items = append(sel.Items, TrashItem{ID: id, RevisionDate: cloneTimePtr(c.RevisionDate)})
		}
	}
	slices.SortFunc(sel.Items, func(a, b TrashItem) int { return strings.Compare(a.ID, b.ID) })
	return sel
}

// EmptyTrash permanently deletes the items sel lists, which the user
// confirmed, then resyncs. Each item is fetched first and kept (Skipped)
// unless the server still has it in Trash at the confirmed revision.
func (s *Service) EmptyTrash(ctx context.Context, sel TrashSelection) (TrashResult, error) {
	res := TrashResult{ReadOnly: sel.ReadOnly}
	o, err := s.beginOp(ctx)
	if err != nil {
		return res, err
	}
	defer o.end()
	if o.accountID != sel.AccountID {
		return res, ErrAccountChanged
	}

	var errs []error
	for _, item := range sel.Items {
		cur, err := withAuth(o, func(ctx context.Context, tok string) (*api.EncryptedCipher, error) {
			return o.client.GetCipher(ctx, tok, item.ID)
		})
		if errors.Is(err, api.ErrNotFound) {
			res.Skipped++
			continue
		}
		if err == nil && (cur.DeletedDate == nil || !sameTime(cur.RevisionDate, item.RevisionDate) || (cur.Edit != nil && !*cur.Edit)) {
			res.Skipped++
			continue
		}
		if err == nil {
			// The server deletes unconditionally: a restore between this check and the delete is still lost.
			_, err = withAuth(o, func(ctx context.Context, tok string) (struct{}, error) {
				return struct{}{}, o.client.HardDeleteCipher(ctx, tok, item.ID)
			})
		}
		if err != nil {
			errs = append(errs, err)
			if errors.Is(err, ErrLocked) || o.ctx.Err() != nil {
				break
			}
			continue
		}
		res.Deleted++
		if err := o.removeCipher(item.ID); err != nil {
			errs = append(errs, err)
		}
	}
	if res.Deleted > 0 || res.Skipped > 0 {
		if err := s.sync(ctx, true); err != nil && !errors.Is(err, ErrLocked) && !errors.Is(err, ErrSyncDeferred) {
			errs = append(errs, err)
		}
		s.notifyUpdated()
	}
	return res, errors.Join(errs...)
}

func sameTime(a, b *time.Time) bool {
	return (a == nil) == (b == nil) && (a == nil || a.Equal(*b))
}

func (s *Service) Folders() []Folder {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.status != StatusUnlocked {
		return nil
	}
	out := make([]Folder, 0, len(s.folders))
	for _, f := range s.folders {
		out = append(out, Folder{
			ID:           f.ID,
			Name:         f.Name,
			RevisionDate: cloneTimePtr(f.RevisionDate),
			Extra:        cloneExtra(f.Extra),
		})
	}
	slices.SortFunc(out, func(a, b Folder) int {
		return strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name))
	})
	return out
}

func (s *Service) SaveFolder(ctx context.Context, f *Folder) (*Folder, error) {
	if f == nil {
		return nil, ErrFolderNotFound
	}
	o, err := s.beginOp(ctx)
	if err != nil {
		return nil, err
	}
	defer o.end()

	encName, err := crypto.EncryptString(f.Name, o.userKey)
	if err != nil {
		return nil, err
	}

	encResp, err := withAuth(o, func(ctx context.Context, tok string) (*api.EncryptedFolder, error) {
		if f.ID == "" {
			return o.client.CreateFolder(ctx, tok, encName)
		}
		return o.client.UpdateFolder(ctx, tok, f.ID, encName)
	})
	if err != nil {
		return nil, err
	}

	decrypted, err := decryptFolder(encResp, o.userKey)
	if err != nil {
		return nil, err
	}

	err = o.updateSnapshot(func(resp *api.SyncResponse) {
		for i := range resp.Folders {
			if resp.Folders[i].ID == encResp.ID {
				resp.Folders[i] = *encResp
				return
			}
		}
		resp.Folders = append(resp.Folders, *encResp)
	}, func() { s.folders[decrypted.ID] = decrypted })
	if errors.Is(err, ErrLocked) {
		return nil, ErrLocked
	}
	s.notifyUpdated()
	cp := decrypted
	return &cp, err
}

func (s *Service) DeleteFolder(ctx context.Context, id string) error {
	o, err := s.beginOp(ctx)
	if err != nil {
		return err
	}
	defer o.end()

	_, err = withAuth(o, func(ctx context.Context, tok string) (struct{}, error) {
		return struct{}{}, o.client.DeleteFolder(ctx, tok, id)
	})
	if err != nil {
		return err
	}

	err = o.updateSnapshot(func(resp *api.SyncResponse) {
		resp.Folders = slices.DeleteFunc(resp.Folders, func(f api.EncryptedFolder) bool { return f.ID == id })
		for i := range resp.Ciphers {
			if f := resp.Ciphers[i].FolderID; f != nil && *f == id {
				resp.Ciphers[i].FolderID = nil
			}
		}
	}, func() {
		delete(s.folders, id)
		for _, c := range s.ciphers {
			if c.FolderID != nil && *c.FolderID == id {
				c.FolderID = nil
			}
		}
	})
	s.notifyUpdated()
	return err
}

func (s *Service) loadCurrentSnapshot() (*store.Snapshot, error) {
	s.mu.RLock()
	snap := s.snapshot
	accountID := s.accountID
	s.mu.RUnlock()

	if snap != nil {
		cp := *snap
		return &cp, nil
	}
	if accountID == "" {
		return nil, ErrLoggedOut
	}
	return s.cfg.Store.LoadSnapshot(accountID)
}

func (s *Service) newAPIClient(serverURL string) (*api.Client, error) {
	if s.cfg.NewClient != nil {
		return s.cfg.NewClient(serverURL)
	}
	// Bitwarden's US and EU clouds serve the API and identity on hosts of
	// their own, as gv resolves them; other servers under their base URL.
	var apiURL, identityURL string
	if e, err := api.ResolveEndpoints(strings.TrimRight(strings.TrimSpace(serverURL), "/")); err == nil {
		apiURL, identityURL = e.API, e.Identity
	}
	return api.NewClient(api.ClientConfig{
		ServerURL:   serverURL,
		APIURL:      apiURL,
		IdentityURL: identityURL,
		DeviceID:    s.cfg.DeviceID,
		DeviceName:  s.cfg.DeviceName,
		DeviceType:  s.cfg.DeviceType,
		HTTPClient:  s.cfg.HTTPClient,
	})
}

func (s *Service) stopRealtimeLocked() {
	if s.realtimeCancel != nil {
		s.realtimeCancel()
		s.realtimeCancel = nil
	}
}

func (s *Service) notifyStatus(st LockStatus) {
	if s.cfg.OnStatusChange != nil {
		s.cfg.OnStatusChange(st)
	}
}

func (s *Service) notifyUpdated() {
	if s.cfg.OnVaultUpdated != nil {
		s.cfg.OnVaultUpdated()
	}
}

type vaultData struct {
	// unreadable lists personal items GoVault cannot read, such as ones in
	// a newer format; a backup without them would be incomplete.
	unreadable []string
	userID     string
	premium    bool
	// archiveKnown: the server reported archivedDate on its ciphers;
	// archiveAbsent: it sent ciphers and none reported it.
	archiveKnown  bool
	archiveAbsent bool
	ciphers       map[string]*Cipher
	folders       map[string]Folder
	orgs          map[string]Organization
	collections   map[string]Collection
	orgKeys       map[string]*crypto.SymmetricKey
}

func (d *vaultData) zero() {
	if d == nil {
		return
	}
	for _, k := range d.orgKeys {
		k.Zero()
	}
	clear(d.orgKeys)
}

func (s *Service) applyDataLocked(d *vaultData) {
	s.clearDataLocked()
	s.ciphers = d.ciphers
	s.folders = d.folders
	s.orgs = d.orgs
	s.collections = d.collections
	s.orgKeys = d.orgKeys
	s.unreadable = d.unreadable
	s.premium = d.premium
	s.userID = d.userID
	s.archiveKnown = d.archiveKnown
	s.archiveAbsent = !d.archiveKnown && len(d.ciphers) > 0
}

// noteArchiveEvidence records that the server supports Archive when a
// cipher it returns reports archivedDate.
func (s *Service) noteArchiveEvidence(enc *api.EncryptedCipher) {
	if enc == nil || !enc.ReportsArchive() {
		return
	}
	s.mu.Lock()
	s.archiveKnown, s.archiveAbsent = true, false
	s.mu.Unlock()
}

func profileFlag(extra map[string]json.RawMessage, name string) bool {
	var on bool
	return json.Unmarshal(extra[name], &on) == nil && on
}

// CanArchive reports whether the account may archive items: Bitwarden
// makes Archive a premium feature, from a personal or organization plan
// (Vaultwarden gives every account premium). Unarchiving is always
// allowed, so items archived before premium ended can come back.
func (s *Service) CanArchive() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.status == StatusUnlocked && s.premium
}

// ArchiveCipher moves an item to the user's Archive. Like a favorite, the
// archive is per user, so read-only organization items can be archived
// too; items in Trash cannot.
func (s *Service) ArchiveCipher(ctx context.Context, id string) error {
	return s.setArchived(ctx, id, true)
}

// UnarchiveCipher moves an item from the Archive back to the vault.
func (s *Service) UnarchiveCipher(ctx context.Context, id string) error {
	return s.setArchived(ctx, id, false)
}

func (s *Service) setArchived(ctx context.Context, id string, archive bool) error {
	o, err := s.beginOp(ctx)
	if err != nil {
		return err
	}
	defer o.end()
	// Copied under the lock: a trash or sync may change the cipher once
	// it is released.
	s.mu.RLock()
	c, premium, known := s.ciphers[id], s.premium, s.archiveKnown
	var exists, deleted, archived bool
	var prevCollections []string
	if c != nil {
		exists, deleted, archived = true, c.DeletedDate != nil, c.ArchivedDate != nil
		prevCollections = slices.Clone(c.CollectionIDs)
	}
	s.mu.RUnlock()
	switch {
	case !exists:
		return ErrCipherNotFound
	case deleted:
		return ErrCipherInTrash
	case archived == archive:
		return nil
	case archive && !premium:
		return ErrPremiumRequired
	}

	encResp, err := withAuth(o, func(ctx context.Context, tok string) (*api.EncryptedCipher, error) {
		if archive {
			return o.client.ArchiveCipher(ctx, tok, id)
		}
		return o.client.UnarchiveCipher(ctx, tok, id)
	})
	if err == api.ErrNotFound {
		// A plain 404 is ambiguous: a server without Archive, or one that
		// applied the change but will not send this item back. A sync shows
		// which.
		if serr := s.sync(o.ctx, true); serr != nil && !errors.Is(serr, ErrSyncDeferred) {
			return serr
		}
		s.mu.RLock()
		now, known, absent := s.ciphers[id], s.archiveKnown || known, s.archiveAbsent
		s.mu.RUnlock()
		switch {
		case now != nil && (now.ArchivedDate != nil) == archive:
			return nil
		case absent && !known:
			// Only a server that sent ciphers without archivedDate is
			// known to lack Archive; no evidence either way is no proof.
			return ErrArchiveUnsupported
		}
		return ErrArchiveNotConfirmed
	}
	if err != nil {
		return err
	}
	key, err := o.itemKey(encResp.OrganizationID)
	if err != nil {
		return err
	}
	defer key.Zero()
	decrypted, err := decryptCipher(encResp, key)
	if err != nil {
		return err
	}
	if len(decrypted.CollectionIDs) == 0 {
		decrypted.CollectionIDs = prevCollections
	}
	// Commit only over the vault the request started from. Anything that
	// changed it meanwhile, such as a sync that removed the item, wins:
	// the response is dropped and a sync shows the result.
	if _, err := o.commitCipherIfUnchanged(decrypted, encResp); errors.Is(err, errSnapshotMoved) {
		if serr := s.sync(o.ctx, true); serr != nil && !errors.Is(serr, ErrSyncDeferred) {
			return serr
		}
		return nil
	} else if err != nil {
		return err
	}
	return nil
}

// UnreadableItems lists the IDs of personal items GoVault could not read,
// which a backup would be missing.
func (s *Service) UnreadableItems() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.status != StatusUnlocked {
		return nil
	}
	return slices.Clone(s.unreadable)
}

func (s *Service) clearDataLocked() {
	for _, k := range s.orgKeys {
		k.Zero()
	}
	s.orgKeys = nil
	s.orgs = nil
	s.collections = nil
	s.ciphers = nil
	s.folders = nil
	s.unreadable = nil
	s.premium = false
	s.userID = ""
	s.archiveKnown = false
	s.archiveAbsent = false
}

func (s *Service) Organizations() []Organization {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.status != StatusUnlocked {
		return nil
	}
	out := make([]Organization, 0, len(s.orgs))
	for _, o := range s.orgs {
		out = append(out, o)
	}
	slices.SortFunc(out, func(a, b Organization) int { return strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name)) })
	return out
}

func (s *Service) Collections() []Collection {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.status != StatusUnlocked {
		return nil
	}
	out := make([]Collection, 0, len(s.collections))
	for _, c := range s.collections {
		out = append(out, c)
	}
	slices.SortFunc(out, func(a, b Collection) int { return strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name)) })
	return out
}

// wrappedPrivateKey is the account's private key wrapped with the user
// key: profile.privateKey, or accountKeys, which newer servers send.
func wrappedPrivateKey(p *api.Profile) string {
	if p.PrivateKey != nil && *p.PrivateKey != "" {
		return *p.PrivateKey
	}
	var keys struct {
		PublicKeyEncryptionKeyPair struct {
			WrappedPrivateKey string `json:"wrappedPrivateKey"`
		} `json:"publicKeyEncryptionKeyPair"`
	}
	_ = json.Unmarshal(p.Extra["accountKeys"], &keys)
	return keys.PublicKeyEncryptionKeyPair.WrappedPrivateKey
}

func unwrapOrgKeys(p *api.Profile, userKey *crypto.SymmetricKey) map[string]*crypto.SymmetricKey {
	keys := map[string]*crypto.SymmetricKey{}
	wrapped := wrappedPrivateKey(p)
	if wrapped == "" || len(p.Organizations) == 0 {
		return keys
	}
	priv, err := crypto.DecryptPrivateKey(wrapped, userKey)
	if err != nil {
		return keys
	}
	defer crypto.ZeroPrivateKey(priv)
	for _, org := range p.Organizations {
		if !org.Enabled || org.Key == "" {
			continue
		}
		if k, err := crypto.DecryptOrgKey(org.Key, priv); err == nil {
			keys[org.ID] = k
		}
	}
	return keys
}

func decryptSyncResponse(resp *api.SyncResponse, userKey *crypto.SymmetricKey) (*vaultData, error) {
	d := &vaultData{
		ciphers:     make(map[string]*Cipher, len(resp.Ciphers)),
		folders:     make(map[string]Folder, len(resp.Folders)),
		orgs:        map[string]Organization{},
		collections: map[string]Collection{},
		orgKeys:     unwrapOrgKeys(&resp.Profile, userKey),
		premium:     profileFlag(resp.Profile.Extra, "premium") || profileFlag(resp.Profile.Extra, "premiumFromOrganization"),
		userID:      resp.Profile.ID,
	}
	for _, org := range resp.Profile.Organizations {
		if _, ok := d.orgKeys[org.ID]; ok {
			d.orgs[org.ID] = Organization{ID: org.ID, Name: org.Name, Type: org.Type, Enabled: org.Enabled}
		}
	}

	for i := range resp.Ciphers {
		enc := &resp.Ciphers[i]
		d.archiveKnown = d.archiveKnown || enc.ReportsArchive()
		key := userKey
		isOrg := enc.OrganizationID != nil && *enc.OrganizationID != ""
		if isOrg {
			if key = d.orgKeys[*enc.OrganizationID]; key == nil {
				continue
			}
		}
		c, err := decryptCipher(enc, key)
		if err != nil {
			if isOrg {
				continue
			}
			if errors.Is(err, ErrUnsupportedCipherFormat) {
				d.unreadable = append(d.unreadable, enc.ID)
				continue
			}
			d.zero()
			return nil, err
		}
		d.ciphers[c.ID] = c
	}

	for i := range resp.Folders {
		f, err := decryptFolder(&resp.Folders[i], userKey)
		if err != nil {
			d.zero()
			return nil, err
		}
		d.folders[f.ID] = f
	}

	for _, col := range resp.Collections {
		key := d.orgKeys[col.OrganizationID]
		if key == nil {
			continue
		}
		name, err := crypto.DecryptString(col.Name, key)
		if err != nil {
			continue
		}
		d.collections[col.ID] = Collection{
			ID: col.ID, OrganizationID: col.OrganizationID, Name: name,
			ReadOnly: col.ReadOnly, HidePasswords: col.HidePasswords, Manage: col.Manage,
		}
	}
	return d, nil
}

const maxPasswordHistory = 5

func recordPasswordChange(existing, updated *Cipher, now time.Time) {
	if existing.Login == nil || updated.Login == nil {
		return
	}
	old := existing.Login.Password
	if old == "" || old == updated.Login.Password {
		return
	}
	history := updated.PasswordHistory
	if history == nil {
		history = existing.PasswordHistory
	}
	next := make([]PasswordHistoryEntry, 0, maxPasswordHistory)
	next = append(next, PasswordHistoryEntry{Password: old, LastUsedDate: now})
	for _, h := range history {
		if len(next) == maxPasswordHistory {
			break
		}
		next = append(next, h)
	}
	updated.PasswordHistory = next
	updated.Login.PasswordRevisionDate = &now
}

func sameOrg(a, b *string) bool {
	av, bv := "", ""
	if a != nil {
		av = *a
	}
	if b != nil {
		bv = *b
	}
	return av == bv
}
