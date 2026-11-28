package ui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/nsgotest"
	"github.com/txchen/govault/internal/vaultcore/api"
	"github.com/txchen/govault/internal/vaultcore/crypto"
	"github.com/txchen/govault/internal/vaultcore/state"
	"github.com/txchen/govault/internal/vaultcore/store"
)

type mockVaultService struct {
	mu       sync.RWMutex
	status   state.LockStatus
	password string
	ciphers  map[string]*state.Cipher
	order    []string
	folders  []state.Folder

	twoFactorCode string
	// twoFactorProvider is the method twoFactorCode is for, and
	// twoFactorOffered the methods the challenge lists; they default to
	// Email and Authenticator App with Email.
	twoFactorProvider api.TwoFactorProvider
	twoFactorOffered  []api.TwoFactorProvider
	logins            int
	rejectMessage     string // the error message for a wrong code
	emailSends        int
	// newDeviceCode, when set, makes a login without it meet new device
	// verification, and newDeviceSends counts resends.
	newDeviceCode  string
	newDeviceSends int

	organizations []state.Organization
	collections   []state.Collection

	downloadGate chan struct{}
	// downloaded, when set, receives the bytes each download returns, so
	// a test can see the app wipe them.
	downloaded chan []byte

	// localCopyFails makes saves succeed on the "server" but report a
	// failed local copy, as state.Service does when the snapshot write fails.
	localCopyFails bool
	creates        int

	syncErrs  []error
	syncCalls int

	unreadable []string
	noPremium  bool
	// session names the mock's current session; archiveSessions records
	// the session each archive request was bound to.
	session         int
	archiveSessions []any
	uploads         int
	attempt         uint64
	revokes         int
	localOnly       bool
	credsUnsaved    bool
	lastLogin       state.LoginRequest
	lastSSOLogin    state.SSOLoginRequest
	ssoErr          error
	ssoEmailSends   int
	ssoEmailAddr    string
	ssoEmailToken   string
	// trustedServer is the server the trusted sign-in record names.
	trustedServer string
	// emailGate, when set, holds SendEmailTwoFactorCode until closed.
	emailGate chan struct{}
	// unlockCommitted, when set, holds UnlockWithPassword after it commits
	// until the test answers.
	unlockCommitted chan struct{}
	// ssoCommitted, when set, holds LoginSSO after it commits StatusLocked
	// until the test answers.
	ssoCommitted chan struct{}
	// saveGate, when set, holds SaveCipher until it is closed.
	saveGate chan struct{}
}

func newMockVaultService(initial state.LockStatus) *mockVaultService {
	c1 := &state.Cipher{
		ID:       "c-github",
		Type:     api.CipherTypeLogin,
		Name:     "GitHub",
		Favorite: true,
		Login: &state.Login{
			Username: "alice@example.com",
			Password: "gh-secret-password",
			TOTP:     "JBSWY3DPEHPK3PXP",
			URIs:     []state.LoginURI{{URI: "https://github.com"}},
		},
	}
	c2 := &state.Cipher{
		ID:         "c-note",
		Type:       api.CipherTypeSecureNote,
		Name:       "SSH Recovery Note",
		Notes:      "Keep safe",
		SecureNote: &state.SecureNote{Type: 0},
	}
	return &mockVaultService{
		status:   initial,
		password: "master-password",
		ciphers: map[string]*state.Cipher{
			c1.ID: c1,
			c2.ID: c2,
		},
		order: []string{c1.ID, c2.ID},
		folders: []state.Folder{
			{ID: "f-work", Name: "Work"},
		},
	}
}

func (m *mockVaultService) Status() state.LockStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.status
}

func (m *mockVaultService) Login(_ context.Context, req state.LoginRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastLogin = req
	m.logins++
	if string(req.MasterPassword) != m.password {
		return api.ErrUnauthorized
	}
	if m.newDeviceCode != "" {
		switch req.NewDeviceOTP {
		case m.newDeviceCode:
		case "":
			return &api.NewDeviceVerificationRequiredError{Message: "new device verification required"}
		default:
			return fmt.Errorf("%w", api.ErrInvalidNewDeviceOTP)
		}
	}
	wantProvider := m.twoFactorProvider
	if wantProvider == 0 {
		wantProvider = api.TwoFactorEmail
	}
	if m.twoFactorCode != "" && (req.TwoFactorProvider != wantProvider || req.TwoFactorCode != m.twoFactorCode) {
		if req.TwoFactorCode != "" {
			msg := m.rejectMessage
			if msg == "" {
				msg = "Invalid TOTP code"
			}
			return &api.APIError{StatusCode: 400, Message: msg}
		}
		offered := m.twoFactorOffered
		if offered == nil {
			offered = []api.TwoFactorProvider{api.TwoFactorAuthenticator, api.TwoFactorEmail}
		}
		return &api.TwoFactorRequiredError{Challenge: api.TwoFactorChallenge{
			Providers: offered,
			ProviderData: map[api.TwoFactorProvider]json.RawMessage{
				api.TwoFactorEmail:   json.RawMessage(`{"Email":"a***@example.com"}`),
				api.TwoFactorYubiKey: json.RawMessage(`{"Nfc":false}`),
			},
		}}
	}
	m.status = state.StatusUnlocked
	return nil
}

func (m *mockVaultService) LoginSSO(_ context.Context, req state.SSOLoginRequest) error {
	m.mu.Lock()
	m.lastSSOLogin = req
	m.logins++
	if m.ssoErr != nil {
		err := m.ssoErr
		m.mu.Unlock()
		return err
	}
	if req.Code == "" || req.CodeVerifier == "" {
		m.mu.Unlock()
		return api.ErrUnauthorized
	}
	wantProvider := m.twoFactorProvider
	if wantProvider == 0 {
		wantProvider = api.TwoFactorEmail
	}
	if m.twoFactorCode != "" && (req.TwoFactorProvider != wantProvider || req.TwoFactorCode != m.twoFactorCode) {
		if req.TwoFactorCode != "" {
			msg := m.rejectMessage
			if msg == "" {
				msg = "Invalid TOTP code"
			}
			m.mu.Unlock()
			return &api.APIError{StatusCode: 400, Message: msg}
		}
		offered := m.twoFactorOffered
		if offered == nil {
			offered = []api.TwoFactorProvider{api.TwoFactorAuthenticator, api.TwoFactorEmail}
		}
		m.mu.Unlock()
		return &api.TwoFactorRequiredError{Challenge: api.TwoFactorChallenge{
			Providers:               offered,
			Email:                   "idp-alice@example.com",
			SSOEmail2FASessionToken: "mock-sso-email-token",
			ProviderData: map[api.TwoFactorProvider]json.RawMessage{
				api.TwoFactorEmail:   json.RawMessage(`{"Email":"a***@example.com"}`),
				api.TwoFactorYubiKey: json.RawMessage(`{"Nfc":false}`),
			},
		}}
	}
	m.status = state.StatusLocked
	committed := m.ssoCommitted
	m.mu.Unlock()
	if committed != nil {
		committed <- struct{}{}
		<-committed
	}
	return nil
}

func (m *mockVaultService) SendEmailTwoFactorCode(_ context.Context, req state.LoginRequest) error {
	m.mu.RLock()
	gate := m.emailGate
	m.mu.RUnlock()
	if gate != nil {
		<-gate
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if string(req.MasterPassword) != m.password {
		return api.ErrUnauthorized
	}
	m.emailSends++
	return nil
}

func (m *mockVaultService) SendEmailTwoFactorCodeSSO(_ context.Context, _, email, ssoSessionToken string) error {
	m.mu.RLock()
	gate := m.emailGate
	m.mu.RUnlock()
	if gate != nil {
		<-gate
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ssoEmailAddr = email
	m.ssoEmailToken = ssoSessionToken
	m.ssoEmailSends++
	m.emailSends++
	return nil
}

func (m *mockVaultService) ResendNewDeviceOTP(_ context.Context, req state.LoginRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if string(req.MasterPassword) != m.password {
		return api.ErrUnauthorized
	}
	m.newDeviceSends++
	return nil
}

func (m *mockVaultService) UnlockWithPassword(_ context.Context, pw []byte) error {
	m.mu.Lock()
	if string(pw) != m.password {
		m.mu.Unlock()
		return crypto.ErrInvalidMAC
	}
	m.status = state.StatusUnlocked
	committed := m.unlockCommitted
	m.mu.Unlock()
	if committed != nil {
		// The service has committed the session; the UI has not heard yet.
		committed <- struct{}{}
		<-committed
	}
	return nil
}

func (m *mockVaultService) UnlockWithUserKey(_ context.Context, _ *crypto.SymmetricKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.status = state.StatusUnlocked
	return nil
}

func (m *mockVaultService) EnableBiometricUnlock(_ store.SecretStore) error  { return nil }
func (m *mockVaultService) DisableBiometricUnlock(_ store.SecretStore) error { return nil }

func (m *mockVaultService) Lock() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.status == state.StatusUnlocked {
		m.status = state.StatusLocked
	}
}

func (m *mockVaultService) Logout(_ context.Context, _ store.SecretStore) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.status = state.StatusLoggedOut
	return nil
}

func (m *mockVaultService) SyncNow(_ context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.syncCalls++
	if len(m.syncErrs) == 0 {
		return nil
	}
	err := m.syncErrs[0]
	m.syncErrs = m.syncErrs[1:]
	return err
}

func (m *mockVaultService) Search(query string, filter state.SearchFilter) []state.CipherSummary {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.status != state.StatusUnlocked {
		return nil
	}
	q := strings.ToLower(strings.TrimSpace(query))
	var out []state.CipherSummary
	for _, id := range m.order {
		c := m.ciphers[id]
		if c == nil {
			continue
		}
		deleted := c.DeletedDate != nil
		if filter.Category == state.FilterTrash {
			if !deleted {
				continue
			}
		} else if deleted {
			continue
		} else if (filter.Category == state.FilterArchive) != (c.ArchivedDate != nil) {
			continue
		}
		if filter.Category == state.FilterFavorites && !c.Favorite {
			continue
		}
		if filter.Type != nil && c.Type != *filter.Type {
			continue
		}
		if filter.CollectionID != "" && !slices.Contains(c.CollectionIDs, filter.CollectionID) {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(c.Name), q) {
			continue
		}
		sub := ""
		hasTOTP, hasPasskey := false, false
		if c.Login != nil {
			sub = c.Login.Username
			hasTOTP = strings.TrimSpace(c.Login.TOTP) != ""
			hasPasskey = len(c.Login.Fido2Credentials) > 0
		}
		out = append(out, state.CipherSummary{
			HasPasskey: hasPasskey,
			ID:         c.ID,
			Type:       c.Type,
			FolderID:   c.FolderID,
			Favorite:   c.Favorite,
			Deleted:    deleted,
			Archived:   c.ArchivedDate != nil,
			Name:       c.Name,
			Subtitle:   sub,
			HasTOTP:    hasTOTP,
			Reprompt:   c.Reprompt,
			URIs:       loginURIs(c),

			OrganizationID: c.OrganizationID,
			CollectionIDs:  c.CollectionIDs,
		})
	}
	return out
}

func (m *mockVaultService) GetCipher(id string) (*state.Cipher, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.status != state.StatusUnlocked {
		return nil, state.ErrLocked
	}
	c, ok := m.ciphers[id]
	if !ok {
		return nil, state.ErrCipherNotFound
	}
	cp := *c
	return &cp, nil
}

func (m *mockVaultService) SaveCipher(_ context.Context, c *state.Cipher) (*state.Cipher, error) {
	m.mu.RLock()
	gate := m.saveGate
	m.mu.RUnlock()
	if gate != nil {
		<-gate
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.status != state.StatusUnlocked {
		return nil, state.ErrLocked
	}
	cp := *c
	if cp.ID == "" {
		cp.ID = "c-new"
		for i := 2; m.ciphers[cp.ID] != nil; i++ {
			cp.ID = fmt.Sprintf("c-new-%d", i)
		}
		m.order = append(m.order, cp.ID)
		m.creates++
	}
	m.ciphers[cp.ID] = &cp
	if m.localCopyFails {
		out := cp
		return &out, &state.LocalCopyError{Cipher: &out, Err: errors.New("disk full")}
	}
	return &cp, nil
}

func (m *mockVaultService) SoftDeleteCipher(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.ciphers[id]
	if !ok {
		return state.ErrCipherNotFound
	}
	now := time.Now()
	c.DeletedDate = &now
	return nil
}

func (m *mockVaultService) RestoreCipher(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.ciphers[id]
	if !ok {
		return state.ErrCipherNotFound
	}
	c.DeletedDate = nil
	return nil
}

func (m *mockVaultService) MoveCiphers(_ context.Context, ids []string, folderID *string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, id := range ids {
		if c, ok := m.ciphers[id]; ok {
			c.FolderID = folderID
		}
	}
	return nil
}

func (m *mockVaultService) HardDeleteCipher(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.ciphers, id)
	return nil
}

func (m *mockVaultService) Account() state.Account {
	return state.Account{ID: "acct-1", Email: "alice@example.com"}
}

func (m *mockVaultService) TrustedServerURL(string) string { return m.trustedServer }

func (m *mockVaultService) AuthAttempt() uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.attempt
}

func (m *mockVaultService) RevokeAuthAttempts() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.attempt++
	m.revokes++
	if m.status == state.StatusUnlocked {
		m.status = state.StatusLocked
	}
}

func (m *mockVaultService) LocalOnly() bool { return m.localOnly }

func (m *mockVaultService) CredentialsNotSaved() bool { return m.credsUnsaved }

func (m *mockVaultService) BackupData() state.BackupData {
	return state.BackupData{Ciphers: m.AllCiphers(), Folders: m.Folders(), Unreadable: m.unreadable}
}

func (m *mockVaultService) UnreadableItems() []string { return m.unreadable }

type mockSessionKey struct{}

func (m *mockVaultService) SessionContext(parent context.Context) (context.Context, context.CancelFunc, error) {
	m.mu.RLock()
	session := m.session
	m.mu.RUnlock()
	ctx, cancel := context.WithCancel(context.WithValue(parent, mockSessionKey{}, session))
	return ctx, cancel, nil
}

func (m *mockVaultService) CanArchive() bool { return !m.noPremium }

func (m *mockVaultService) ArchiveCipher(ctx context.Context, id string) error {
	m.mu.Lock()
	m.archiveSessions = append(m.archiveSessions, ctx.Value(mockSessionKey{}))
	m.mu.Unlock()
	return m.setArchived(id, true)
}

func (m *mockVaultService) UnarchiveCipher(_ context.Context, id string) error {
	return m.setArchived(id, false)
}

func (m *mockVaultService) setArchived(id string, archive bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.ciphers[id]
	if !ok {
		return state.ErrCipherNotFound
	}
	if archive && m.noPremium {
		return state.ErrPremiumRequired
	}
	if archive {
		now := time.Now()
		c.ArchivedDate = &now
	} else {
		c.ArchivedDate = nil
	}
	return nil
}

func (m *mockVaultService) TrashSelection() state.TrashSelection {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var sel state.TrashSelection
	for id, c := range m.ciphers {
		switch {
		case c.DeletedDate == nil:
		case c.ReadOnly:
			sel.ReadOnly++
		default:
			sel.Items = append(sel.Items, state.TrashItem{ID: id, RevisionDate: c.RevisionDate})
		}
	}
	return sel
}

func (m *mockVaultService) EmptyTrash(_ context.Context, sel state.TrashSelection) (state.TrashResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	res := state.TrashResult{ReadOnly: sel.ReadOnly}
	for _, it := range sel.Items {
		c, ok := m.ciphers[it.ID]
		// As the service, an item no longer in Trash at the confirmed
		// revision is kept.
		if !ok || c.DeletedDate == nil || (c.RevisionDate == nil) != (it.RevisionDate == nil) ||
			c.RevisionDate != nil && !c.RevisionDate.Equal(*it.RevisionDate) {
			res.Skipped++
			continue
		}
		delete(m.ciphers, it.ID)
		res.Deleted++
	}
	return res, nil
}

func (m *mockVaultService) Folders() []state.Folder {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]state.Folder(nil), m.folders...)
}

func (m *mockVaultService) SaveFolder(_ context.Context, f *state.Folder) (*state.Folder, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if f.ID == "" {
		f.ID = "f-new"
		m.folders = append(m.folders, *f)
	}
	return f, nil
}

func (m *mockVaultService) Organizations() []state.Organization {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]state.Organization(nil), m.organizations...)
}

func (m *mockVaultService) Collections() []state.Collection {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]state.Collection(nil), m.collections...)
}

func (m *mockVaultService) DeleteFolder(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, f := range m.folders {
		if f.ID == id {
			m.folders = append(m.folders[:i], m.folders[i+1:]...)
			return nil
		}
	}
	return errors.New("not found")
}

func TestCoreStateTransitions(t *testing.T) {
	svc := newMockVaultService(state.StatusLoggedOut)
	var model *AppModel

	app := nsgotest.Start(t, func(cx *core.Scope) core.Node {
		model = NewAppModel(cx, svc, PlatformHooks{})
		model.MainWinVisible.Set(true)
		return MainWindowView(cx, model)
	}, nsgotest.Size(980, 640))

	app.Find("id:login-screen")
	app.Type("id:login-server", "https://vault.example.com")
	app.Type("id:login-email", "alice@example.com")
	app.Type("id:login-password", "master-password")
	app.Press("id:login-submit")
	app.WaitFor("id:vault-shell", 2*time.Second)

	app.Type("id:vault-search", "GitHub")
	app.Find("id:vault-item-list >> text:GitHub")
	app.Press("id:vault-row")
	app.Find("id:detail-view")
	app.Find("id:detail-view >> text:alice@example.com")

	app.Press("id:detail-edit")
	app.Find("id:editor-pane")
	app.Clear("id:editor-name")
	app.Type("id:editor-name", "GitHub Enterprise")
	app.Press("id:editor-save")
	app.WaitFor("id:detail-view", 2*time.Second)
	app.Find("id:detail-title")
	app.Find("id:detail-view >> text:GitHub Enterprise")

	app.Press("id:toolbar-lock")
	app.WaitFor("id:lock-screen", 2*time.Second)

	app.Type("id:lock-password", "master-password")
	app.Press("id:lock-submit")
	app.WaitFor("id:vault-shell", 2*time.Second)
}

func TestLoginTwoFactorEmailVerify(t *testing.T) {
	svc := newMockVaultService(state.StatusLoggedOut)
	svc.twoFactorCode = "654321"
	var releases []bool

	app := nsgotest.Start(t, func(cx *core.Scope) core.Node {
		model := NewAppModel(cx, svc, PlatformHooks{ReleaseSecureInput: func(force bool) { releases = append(releases, force) }})
		model.MainWinVisible.Set(true)
		return MainWindowView(cx, model)
	}, nsgotest.Size(980, 720))

	app.Type("id:login-server", "https://vault.example.com")
	app.Type("id:login-email", "alice@example.com")
	app.Type("id:login-password", "master-password")
	app.Press("id:login-submit")
	app.WaitFor("id:twofactor-screen", 2*time.Second)

	app.Press("id:twofactor-provider-email")
	app.Press("id:twofactor-send-email")
	app.WaitFor("text:A verification code was sent to a***@example.com.", 2*time.Second)

	app.Type("id:twofactor-code", "111111")
	app.Press("id:twofactor-verify")
	app.WaitFor("id:twofactor-error", 2*time.Second)

	app.Type("id:twofactor-code", "654 321")
	app.Press("id:twofactor-remember")
	app.Press("id:twofactor-verify")
	app.WaitFor("id:vault-shell", 2*time.Second)

	svc.mu.RLock()
	sends := svc.emailSends
	svc.mu.RUnlock()
	if sends != 1 {
		t.Fatalf("email sends = %d, want 1", sends)
	}
	if len(releases) == 0 || !releases[len(releases)-1] {
		t.Fatalf("secure input not force-released after login: %v", releases)
	}
}

func TestLoginNewDeviceVerification(t *testing.T) {
	svc := newMockVaultService(state.StatusLoggedOut)
	svc.newDeviceCode = "424242"
	var releases []bool
	var model *AppModel

	app := nsgotest.Start(t, func(cx *core.Scope) core.Node {
		model = NewAppModel(cx, svc, PlatformHooks{ReleaseSecureInput: func(force bool) { releases = append(releases, force) }})
		model.MainWinVisible.Set(true)
		return MainWindowView(cx, model)
	}, nsgotest.Size(980, 720))

	app.Type("id:login-server", "https://vault.example.com")
	app.Type("id:login-email", "alice@example.com")
	app.Type("id:login-password", "master-password")
	app.Press("id:login-submit")
	app.WaitFor("id:newdevice-screen", 2*time.Second)
	app.Find("text:Your server doesn’t recognize this device. Enter the code sent to alice@example.com.")

	app.Press("id:newdevice-verify")
	app.WaitFor("text:Enter the verification code.", 2*time.Second)

	app.Press("id:newdevice-resend")
	app.WaitFor("text:A verification code was sent to alice@example.com.", 2*time.Second)

	app.Type("id:newdevice-code", "111111")
	app.Press("id:newdevice-verify")
	app.WaitFor("text:Invalid or expired verification code. Check the code, or choose Resend Code to get a new one.", 2*time.Second)
	if got := model.TwoFactorCode.Get(); got != "" {
		t.Fatalf("code field after a wrong code = %q", got)
	}

	// Back to Sign In leaves the step; signing in again returns to it.
	n := len(releases)
	app.Press("id:newdevice-back")
	app.WaitFor("id:login-screen", 2*time.Second)
	if len(releases) == n || !releases[len(releases)-1] {
		t.Fatalf("secure input not released on Back to Sign In: %v", releases)
	}
	app.Press("id:login-submit")
	app.WaitFor("id:newdevice-screen", 2*time.Second)

	app.Type("id:newdevice-code", "424 242")
	app.Press("id:newdevice-verify")
	app.WaitFor("id:vault-shell", 2*time.Second)

	svc.mu.RLock()
	sends, last := svc.newDeviceSends, svc.lastLogin
	svc.mu.RUnlock()
	if sends != 1 || last.NewDeviceOTP != "424242" || last.TwoFactorCode != "" {
		t.Fatalf("resends = %d, last login = %+v", sends, last)
	}
	if len(releases) == 0 || !releases[len(releases)-1] {
		t.Fatalf("secure input not force-released after login: %v", releases)
	}
}

func TestTOTPTickerVisibilityGating(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	var model *AppModel

	app := nsgotest.Start(t, func(cx *core.Scope) core.Node {
		model = NewAppModel(cx, svc, PlatformHooks{})
		model.MainWinVisible.Set(true)
		return MainWindowView(cx, model)
	}, nsgotest.Size(980, 640))

	if model.TOTPTickerActive() {
		t.Fatal("expected TOTP ticker stopped before selecting a TOTP item")
	}

	app.Post(func() {
		model.SelectCipher(model.Scope, "c-github")
	})
	app.WaitUntil(2*time.Second, func() bool {
		return model.TOTPTickerActive() && model.TOTPCode.Get() != ""
	})

	app.Post(func() {
		model.SelectCipher(model.Scope, "c-note")
	})
	app.WaitUntil(2*time.Second, func() bool {
		return !model.TOTPTickerActive()
	})

	app.Post(func() {
		model.SelectCipher(model.Scope, "c-github")
	})
	app.WaitUntil(2*time.Second, func() bool {
		return model.TOTPTickerActive()
	})

	app.Post(func() {
		model.MainWinVisible.Set(false)
	})
	app.WaitUntil(2*time.Second, func() bool {
		return !model.TOTPTickerActive()
	})

	app.Post(func() {
		model.MainWinVisible.Set(true)
	})
	app.WaitUntil(2*time.Second, func() bool {
		return model.TOTPTickerActive()
	})

	app.Post(func() {
		model.Lock()
	})
	app.WaitUntil(2*time.Second, func() bool {
		return !model.TOTPTickerActive()
	})
}

func TestTrayIconOffKeepsDockReachable(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	var model *AppModel
	var trayCalls, dockCalls []bool

	app := nsgotest.Start(t, func(cx *core.Scope) core.Node {
		model = NewAppModel(cx, svc, PlatformHooks{
			SetTrayVisible: func(on bool) { trayCalls = append(trayCalls, on) },
			SetDockVisible: func(on bool) { dockCalls = append(dockCalls, on) },
		})
		model.MainWinVisible.Set(true)
		return MainWindowView(cx, model)
	}, nsgotest.Size(980, 640))

	if !model.Prefs.Get().ShowTrayIcon {
		t.Fatal("expected the tray icon to be shown by default")
	}

	app.Post(func() {
		model.UpdatePrefs(func(p UserPrefs) UserPrefs { p.HideDockIcon = true; return p })
		model.SetShowTrayIcon(false)
	})
	app.Settle()

	p := model.Prefs.Get()
	if p.ShowTrayIcon || p.HideDockIcon {
		t.Fatalf("expected tray off and Dock shown, got ShowTrayIcon=%v HideDockIcon=%v", p.ShowTrayIcon, p.HideDockIcon)
	}
	if len(trayCalls) != 1 || trayCalls[0] || len(dockCalls) != 1 || !dockCalls[0] {
		t.Fatalf("expected tray hidden and Dock shown, got tray=%v dock=%v", trayCalls, dockCalls)
	}
	if raw, ok := app.Storage().GetItem("govault.prefs"); !ok || !strings.Contains(raw, `"showTrayIcon":false`) {
		t.Fatalf("expected showTrayIcon persisted, got ok=%v raw=%q", ok, raw)
	}
}

func TestSearchStaysInSectionUntilWidened(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	svc.ciphers["c-github"].FolderID = ptr("f-work")
	var model *AppModel

	app := nsgotest.Start(t, func(cx *core.Scope) core.Node {
		model = NewAppModel(cx, svc, PlatformHooks{})
		model.MainWinVisible.Set(true)
		model.RefreshVaultData()
		return MainWindowView(cx, model)
	}, nsgotest.Size(1100, 640))

	noteType := api.CipherTypeSecureNote
	app.Post(func() { model.SetSidebarFilter(state.SearchFilter{Category: state.FilterAll, Type: &noteType}) })
	app.Type("id:vault-search", "GitHub")
	app.Settle()
	if n := model.FilteredItems.Len(); n != 0 || model.SearchIsGlobal() {
		t.Fatalf("search left Secure Notes by default: %d items, global=%v", n, model.SearchIsGlobal())
	}
	app.Find("id:search-scope >> text:In Secure Notes")
	app.Find("id:search-empty-all")

	app.Press("id:search-scope-all")
	app.WaitUntil(2*time.Second, func() bool {
		return model.FilteredItems.Len() == 1 && model.FilteredItems.KeyAt(0) == "c-github"
	})
	app.Find("id:search-scope >> text:In All Items")

	app.Press("id:search-scope-section")
	app.WaitUntil(2*time.Second, func() bool { return model.FilteredItems.Len() == 0 })

	app.Post(func() { model.SetSidebarFilter(state.SearchFilter{FolderID: "f-work"}) })
	app.WaitUntil(2*time.Second, func() bool {
		return model.FilteredItems.Len() == 1 && !model.SearchIsGlobal()
	})
	app.Find("id:search-scope >> text:In Work")
}

func ptr[T any](v T) *T { return &v }

func TestLockOnSleepPreferenceAndSystemEvent(t *testing.T) {
	var legacy UserPrefs
	if err := json.Unmarshal([]byte(`{"autoLockMinutes":5}`), &legacy); err != nil || !legacy.LockOnSleep {
		t.Fatalf("legacy prefs LockOnSleep = %v (err %v), want true", legacy.LockOnSleep, err)
	}

	svc := newMockVaultService(state.StatusUnlocked)
	var model *AppModel
	var releases []bool
	app := nsgotest.Start(t, func(cx *core.Scope) core.Node {
		model = NewAppModel(cx, svc, PlatformHooks{
			SleepLockSupported: true,
			ReleaseSecureInput: func(force bool) { releases = append(releases, force) },
		})
		model.MainWinVisible.Set(true)
		model.Route.Set(RouteSettings)
		return MainWindowView(cx, model)
	}, nsgotest.Size(980, 720))

	app.Press("id:settings-lock-on-sleep")
	app.WaitUntil(time.Second, func() bool { return !model.Prefs.Get().LockOnSleep })

	systemLock := func() bool {
		done, result := false, false
		app.Post(func() { result, done = model.LockOnSystemEvent(), true })
		app.WaitUntil(time.Second, func() bool { return done })
		return result
	}
	if systemLock() || svc.Status() != state.StatusUnlocked {
		t.Fatal("system event locked the vault with LockOnSleep off")
	}

	app.Press("id:settings-lock-on-sleep")
	app.WaitUntil(time.Second, func() bool { return model.Prefs.Get().LockOnSleep })

	releases = nil
	if !systemLock() {
		t.Fatal("system event did not lock the unlocked vault")
	}
	app.WaitFor("id:lock-screen", 2*time.Second)
	if svc.Status() != state.StatusLocked || model.TOTPTickerActive() || len(releases) == 0 || !releases[len(releases)-1] {
		t.Fatalf("after lock: status=%v ticker=%v releases=%v", svc.Status(), model.TOTPTickerActive(), releases)
	}
	if systemLock() {
		t.Fatal("system event re-locked an already locked vault")
	}
}

func loginURIs(c *state.Cipher) []string {
	if c.Login == nil {
		return nil
	}
	out := make([]string, 0, len(c.Login.URIs))
	for _, u := range c.Login.URIs {
		out = append(out, u.URI)
	}
	return out
}

func TestSidebarCollectionsFilterItems(t *testing.T) {
	personal := newMockVaultService(state.StatusUnlocked)
	app := nsgotest.Start(t, func(cx *core.Scope) core.Node {
		model := NewAppModel(cx, personal, PlatformHooks{})
		model.MainWinVisible.Set(true)
		model.RefreshVaultData()
		return MainWindowView(cx, model)
	}, nsgotest.Size(980, 640))
	app.WaitFor("id:vault-item-list >> text:GitHub", 2*time.Second)
	if app.Exists("id:sidebar-collections-toggle") {
		t.Fatal("personal-only vault shows a Collections section")
	}

	svc := newMockVaultService(state.StatusUnlocked)
	org := "org-1"
	svc.organizations = []state.Organization{{ID: org, Name: "Acme", Enabled: true}}
	svc.collections = []state.Collection{{ID: "col-eng", OrganizationID: org, Name: "Engineering", ReadOnly: true}}
	svc.ciphers["c-github"].OrganizationID = &org
	svc.ciphers["c-github"].CollectionIDs = []string{"col-eng"}

	app = nsgotest.Start(t, func(cx *core.Scope) core.Node {
		model := NewAppModel(cx, svc, PlatformHooks{})
		model.MainWinVisible.Set(true)
		model.RefreshVaultData()
		return MainWindowView(cx, model)
	}, nsgotest.Size(980, 640))

	app.WaitFor("id:sidebar-collections >> text:Engineering", 2*time.Second)
	app.Press("id:sidebar-collection")
	app.WaitForGone("id:vault-item-list >> text:SSH Recovery Note", 2*time.Second)
	app.Find("id:vault-item-list >> text:GitHub")

	app.Press("id:vault-row")
	app.WaitFor("id:detail-view >> text:Acme", 2*time.Second)
	app.Find("id:detail-view >> text:View only")
}

func (m *mockVaultService) DownloadAttachment(_ context.Context, cipherID, attachmentID string) ([]byte, string, error) {
	if m.downloadGate != nil {
		<-m.downloadGate
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	c, ok := m.ciphers[cipherID]
	if !ok {
		return nil, "", state.ErrCipherNotFound
	}
	for _, a := range c.Attachments {
		if a.ID == attachmentID {
			data := []byte("contents of " + a.FileName)
			if m.downloaded != nil {
				m.downloaded <- data
			}
			return data, a.FileName, nil
		}
	}
	return nil, "", state.ErrAttachmentNotFound
}

func (m *mockVaultService) UploadAttachment(_ context.Context, cipherID, fileName string, plain []byte) (*state.Cipher, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.ciphers[cipherID]
	if !ok {
		return nil, state.ErrCipherNotFound
	}
	c.Attachments = append(slices.Clone(c.Attachments), state.Attachment{ID: "att-" + fileName, FileName: fileName, Size: int64(len(plain))})
	m.uploads++
	cp := *c
	if m.localCopyFails {
		return &cp, &state.LocalCopyError{Cipher: &cp, Err: errors.New("disk full")}
	}
	return &cp, nil
}

func (m *mockVaultService) DeleteAttachment(_ context.Context, cipherID, attachmentID string) (*state.Cipher, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.ciphers[cipherID]
	if !ok {
		return nil, state.ErrCipherNotFound
	}
	c.Attachments = slices.DeleteFunc(slices.Clone(c.Attachments), func(a state.Attachment) bool { return a.ID == attachmentID })
	cp := *c
	return &cp, nil
}

func (m *mockVaultService) AllCiphers() []*state.Cipher {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.status != state.StatusUnlocked {
		return nil
	}
	out := make([]*state.Cipher, 0, len(m.order))
	for _, id := range m.order {
		if c := m.ciphers[id]; c != nil {
			cp := *c
			out = append(out, &cp)
		}
	}
	return out
}
