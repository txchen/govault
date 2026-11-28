package demo

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/txchen/govault/internal/vaultcore/api"
	"github.com/txchen/govault/internal/vaultcore/crypto"
	"github.com/txchen/govault/internal/vaultcore/gen"
	"github.com/txchen/govault/internal/vaultcore/state"
	"github.com/txchen/govault/internal/vaultcore/store"
)

const (
	AccountID = "demo-account"
	Email     = "alex.morgan@northwind.dev"
	ServerURL = "https://vault.northwind.dev"
)

// KDF is the demo account's key derivation settings.
var KDF = crypto.KDFConfig{Type: crypto.KDFArgon2id, Iterations: 3, MemoryMB: 64, Parallelism: 4}

type Service struct {
	mu      sync.RWMutex
	status  state.LockStatus
	ciphers map[string]*state.Cipher
	folders []state.Folder
	nextID  int
	blobs   map[string][]byte
}

const demoOrgID = "o-northwind"

var (
	demoOrganizations = []state.Organization{{ID: demoOrgID, Name: "Northwind Labs", Type: 2, Enabled: true}}
	demoCollections   = []state.Collection{
		{ID: "col-finance", OrganizationID: demoOrgID, Name: "Finance", ReadOnly: true},
		{ID: "col-infra", OrganizationID: demoOrgID, Name: "Infrastructure"},
	}
	demoShared = map[string][]string{
		"c-cloudflare": {"col-infra"},
		"c-stripe":     {"col-finance"},
	}
)

func NewService(status state.LockStatus) *Service {
	s := &Service{status: status, ciphers: map[string]*state.Cipher{}, blobs: map[string][]byte{
		"a-recovery": []byte("GitHub recovery codes\n\na7f2-9c1e\n44d0-b8e3\n91be-0c7a\n"),
	}}
	s.folders = []state.Folder{
		{ID: "f-work", Name: "Work"},
		{ID: "f-personal", Name: "Personal"},
		{ID: "f-finance", Name: "Finance"},
	}
	for _, c := range seedCiphers() {
		if cols, ok := demoShared[c.ID]; ok {
			org := demoOrgID
			c.OrganizationID = &org
			c.CollectionIDs = cols
		}
		s.ciphers[c.ID] = c
	}
	return s
}

func (s *Service) Organizations() []state.Organization {
	if s.Status() != state.StatusUnlocked {
		return nil
	}
	return append([]state.Organization(nil), demoOrganizations...)
}

func (s *Service) Collections() []state.Collection {
	if s.Status() != state.StatusUnlocked {
		return nil
	}
	return append([]state.Collection(nil), demoCollections...)
}

type SecretStore struct {
	mu     sync.Mutex
	values map[string]string
}

func NewSecretStore() *SecretStore {
	key := make([]byte, 64)
	for i := range key {
		key[i] = byte(i*7 + 3)
	}
	return &SecretStore{values: map[string]string{
		"userkey:" + AccountID: base64.StdEncoding.EncodeToString(key),
	}}
}

func (s *SecretStore) Get(account string) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.values[account]
	return v, ok, nil
}

func (s *SecretStore) Set(account, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.values[account] = value
	return nil
}

func (s *SecretStore) Delete(account string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.values, account)
	return nil
}

func (s *Service) Status() state.LockStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.status
}

func (s *Service) setStatus(st state.LockStatus) {
	s.mu.Lock()
	s.status = st
	s.mu.Unlock()
}

func (s *Service) Login(_ context.Context, req state.LoginRequest) error {
	if len(req.MasterPassword) == 0 {
		return api.ErrUnauthorized
	}
	time.Sleep(350 * time.Millisecond)
	s.setStatus(state.StatusUnlocked)
	return nil
}

func (s *Service) LoginSSO(_ context.Context, _ state.SSOLoginRequest) error {
	time.Sleep(350 * time.Millisecond)
	s.setStatus(state.StatusLocked)
	return nil
}

func (s *Service) SendEmailTwoFactorCode(context.Context, state.LoginRequest) error     { return nil }
func (s *Service) SendEmailTwoFactorCodeSSO(context.Context, string, string, string) error { return nil }
func (s *Service) ResendNewDeviceOTP(context.Context, state.LoginRequest) error         { return nil }

func (s *Service) UnlockWithPassword(_ context.Context, pw []byte) error {
	if len(pw) == 0 {
		return crypto.ErrInvalidMAC
	}
	time.Sleep(250 * time.Millisecond)
	s.setStatus(state.StatusUnlocked)
	return nil
}

func (s *Service) UnlockWithUserKey(_ context.Context, _ *crypto.SymmetricKey) error {
	s.setStatus(state.StatusUnlocked)
	return nil
}

func (s *Service) EnableBiometricUnlock(store.SecretStore) error  { return nil }
func (s *Service) DisableBiometricUnlock(store.SecretStore) error { return nil }

func (s *Service) Lock() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.status == state.StatusUnlocked {
		s.status = state.StatusLocked
	}
}

func (s *Service) Logout(context.Context, store.SecretStore) error {
	s.setStatus(state.StatusLoggedOut)
	return nil
}

func (s *Service) SyncNow(context.Context) error {
	time.Sleep(600 * time.Millisecond)
	return nil
}

func (s *Service) Search(query string, filter state.SearchFilter) []state.CipherSummary {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.status != state.StatusUnlocked {
		return nil
	}
	q := strings.ToLower(strings.TrimSpace(query))
	var out []state.CipherSummary
	for _, c := range s.ciphers {
		deleted := c.DeletedDate != nil
		if (filter.Category == state.FilterTrash) != deleted {
			continue
		}
		if !deleted && (filter.Category == state.FilterArchive) != (c.ArchivedDate != nil) {
			continue
		}
		if filter.Category == state.FilterFavorites && !c.Favorite {
			continue
		}
		hasFolder := c.FolderID != nil && *c.FolderID != ""
		if filter.Category == state.FilterNoFolder && hasFolder {
			continue
		}
		if filter.FolderID != "" && (!hasFolder || *c.FolderID != filter.FolderID) {
			continue
		}
		if filter.Type != nil && c.Type != *filter.Type {
			continue
		}
		if filter.CollectionID != "" && !slices.Contains(c.CollectionIDs, filter.CollectionID) {
			continue
		}
		if filter.OrganizationID != "" && (c.OrganizationID == nil || *c.OrganizationID != filter.OrganizationID) {
			continue
		}
		sub := subtitle(c)
		if q != "" && !strings.Contains(strings.ToLower(c.Name+" "+sub), q) {
			continue
		}
		out = append(out, state.CipherSummary{
			ID:       c.ID,
			Type:     c.Type,
			FolderID: c.FolderID,
			Favorite: c.Favorite,
			Deleted:  deleted,
			Archived: c.ArchivedDate != nil,
			Name:     c.Name,
			Subtitle: sub,
			HasTOTP:  c.Login != nil && strings.TrimSpace(c.Login.TOTP) != "",
			Reprompt: c.Reprompt,

			HasPasskey:   c.Login != nil && len(c.Login.Fido2Credentials) > 0,
			RevisionDate: c.RevisionDate,
			URIs:         loginURIs(c),

			OrganizationID: c.OrganizationID,
			CollectionIDs:  c.CollectionIDs,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out
}

func subtitle(c *state.Cipher) string {
	switch {
	case c.Login != nil:
		return c.Login.Username
	case c.Card != nil:
		n := strings.ReplaceAll(c.Card.Number, " ", "")
		if len(n) >= 4 {
			return c.Card.Brand + " •••• " + n[len(n)-4:]
		}
		return c.Card.Brand
	case c.Identity != nil:
		return strings.TrimSpace(c.Identity.FirstName + " " + c.Identity.LastName)
	case c.SSHKey != nil:
		return c.SSHKey.KeyFingerprint
	}
	return ""
}

func (s *Service) AllCiphers() []*state.Cipher {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.status != state.StatusUnlocked {
		return nil
	}
	out := make([]*state.Cipher, 0, len(s.ciphers))
	for _, c := range s.ciphers {
		cp := *c
		out = append(out, &cp)
	}
	return out
}

func (s *Service) GetCipher(id string) (*state.Cipher, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.status != state.StatusUnlocked {
		return nil, state.ErrLocked
	}
	c, ok := s.ciphers[id]
	if !ok {
		return nil, state.ErrCipherNotFound
	}
	cp := *c
	return &cp, nil
}

func (s *Service) SaveCipher(_ context.Context, c *state.Cipher) (*state.Cipher, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.status != state.StatusUnlocked {
		return nil, state.ErrLocked
	}
	cp := *c
	now := time.Now()
	if cp.ID == "" {
		s.nextID++
		cp.ID = fmt.Sprintf("c-new-%d", s.nextID)
		cp.CreationDate = &now
	}
	cp.RevisionDate = &now
	s.ciphers[cp.ID] = &cp
	out := cp
	return &out, nil
}

func (s *Service) SoftDeleteCipher(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.ciphers[id]
	if !ok {
		return state.ErrCipherNotFound
	}
	now := time.Now()
	c.DeletedDate = &now
	return nil
}

func (s *Service) RestoreCipher(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.ciphers[id]
	if !ok {
		return state.ErrCipherNotFound
	}
	c.DeletedDate = nil
	return nil
}

func (s *Service) MoveCiphers(_ context.Context, ids []string, folderID *string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, id := range ids {
		if c, ok := s.ciphers[id]; ok {
			c.FolderID = folderID
		}
	}
	return nil
}

func (s *Service) HardDeleteCipher(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.ciphers, id)
	return nil
}

func (s *Service) Account() state.Account {
	return state.Account{ID: "demo", Email: "demo@govault.dev"}
}

func (s *Service) TrustedServerURL(string) string { return "" }

func (s *Service) AuthAttempt() uint64 { return 0 }

func (s *Service) RevokeAuthAttempts() {}

func (s *Service) LocalOnly() bool { return false }

func (s *Service) CredentialsNotSaved() bool { return false }

func (s *Service) BackupData() state.BackupData {
	return state.BackupData{Ciphers: s.AllCiphers(), Folders: s.Folders(), Unreadable: nil}
}

func (s *Service) UnreadableItems() []string { return nil }

func (s *Service) SessionContext(parent context.Context) (context.Context, context.CancelFunc, error) {
	ctx, cancel := context.WithCancel(parent)
	return ctx, cancel, nil
}

func (s *Service) CanArchive() bool { return true }

func (s *Service) ArchiveCipher(_ context.Context, id string) error { return s.setArchived(id, true) }

func (s *Service) UnarchiveCipher(_ context.Context, id string) error {
	return s.setArchived(id, false)
}

func (s *Service) setArchived(id string, archive bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.ciphers[id]
	if !ok {
		return state.ErrCipherNotFound
	}
	if archive {
		now := time.Now()
		c.ArchivedDate = &now
	} else {
		c.ArchivedDate = nil
	}
	return nil
}

func (s *Service) TrashSelection() state.TrashSelection {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var sel state.TrashSelection
	for id, c := range s.ciphers {
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

func (s *Service) EmptyTrash(_ context.Context, sel state.TrashSelection) (state.TrashResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	res := state.TrashResult{ReadOnly: sel.ReadOnly}
	for _, it := range sel.Items {
		if c, ok := s.ciphers[it.ID]; !ok || c.DeletedDate == nil {
			res.Skipped++
			continue
		}
		delete(s.ciphers, it.ID)
		res.Deleted++
	}
	return res, nil
}

func (s *Service) Folders() []state.Folder {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]state.Folder(nil), s.folders...)
}

func (s *Service) SaveFolder(_ context.Context, f *state.Folder) (*state.Folder, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *f
	if cp.ID == "" {
		s.nextID++
		cp.ID = fmt.Sprintf("f-new-%d", s.nextID)
		s.folders = append(s.folders, cp)
		return &cp, nil
	}
	for i := range s.folders {
		if s.folders[i].ID == cp.ID {
			s.folders[i].Name = cp.Name
		}
	}
	return &cp, nil
}

func (s *Service) DeleteFolder(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, f := range s.folders {
		if f.ID == id {
			s.folders = append(s.folders[:i], s.folders[i+1:]...)
			break
		}
	}
	for _, c := range s.ciphers {
		if c.FolderID != nil && *c.FolderID == id {
			c.FolderID = nil
		}
	}
	return nil
}

func seedCiphers() []*state.Cipher {
	now := time.Now()
	ago := func(d time.Duration) *time.Time {
		t := now.Add(-d)
		return &t
	}
	folder := func(id string) *string { return &id }
	login := func(user, pw, totp string, uris ...string) *state.Login {
		l := &state.Login{Username: user, Password: pw, TOTP: totp}
		for _, u := range uris {
			l.URIs = append(l.URIs, state.LoginURI{URI: u})
		}
		return l
	}
	const day = 24 * time.Hour
	soon := now.AddDate(0, 1, 0)
	soonMonth, soonYear := fmt.Sprintf("%02d", int(soon.Month())), fmt.Sprintf("%d", soon.Year())

	return []*state.Cipher{
		{
			ID: "c-github", Type: api.CipherTypeLogin, Name: "GitHub", Favorite: true,
			FolderID: folder("f-work"),
			Login: withPasskey(login("alex-morgan", "x7#Kq9!vLm2@Pz4w&Rt8", "JBSWY3DPEHPK3PXP", "https://github.com/login", "https://github.com/northwind"),
				state.Fido2Credential{RpID: "github.com", RpName: "GitHub", UserName: "alex-morgan", CreationDate: "2026-03-14T10:22:00Z"}),
			Fields: []state.CustomField{
				{Name: "Organization", Value: "northwind", Type: 0},
				{Name: "Recovery code", Value: "a7f2-9c1e-44d0-b8e3", Type: 1},
			},
			Notes:       "Primary work account. SSO enforced for the northwind org; hardware key registered as backup.",
			Attachments: []state.Attachment{{ID: "a-recovery", FileName: "github-recovery-codes.txt", Size: 53}},
			PasswordHistory: []state.PasswordHistoryEntry{
				{Password: "Gh!2024-northwind", LastUsedDate: *ago(3 * day)},
				{Password: "octo-cat-42", LastUsedDate: *ago(180 * day)},
			},
			CreationDate: ago(412 * day), RevisionDate: ago(3 * day),
		},
		{
			ID: "c-aws", Type: api.CipherTypeLogin, Name: "AWS Production", Favorite: true, Reprompt: 1,
			FolderID: folder("f-work"),
			Login:    login("alex.morgan@northwind.dev", "Qm8$wE2^tY6!nB4zKd1#", "KRSXG5CTMVRXEZLUKN2XAZLSKRUGS3TH", "https://northwind-prod.signin.aws.amazon.com/console"),
			Fields: []state.CustomField{
				{Name: "Account ID", Value: "4821-0937-5521", Type: 0},
				{Name: "Access key ID", Value: "AKIA4NW7EXAMPLE2QX", Type: 1},
			},
			CreationDate: ago(300 * day), RevisionDate: ago(12 * day),
		},
		{
			ID: "c-cloudflare", Type: api.CipherTypeLogin, Name: "Cloudflare",
			FolderID:     folder("f-work"),
			Login:        login("ops@northwind.dev", "cF!9vR3#hL7@pW2xQ5", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "https://dash.cloudflare.com"),
			CreationDate: ago(220 * day), RevisionDate: ago(41 * day),
		},
		{
			ID: "c-stripe", Type: api.CipherTypeLogin, Name: "Stripe Dashboard",
			FolderID:     folder("f-finance"),
			Login:        login("finance@northwind.dev", "St4ipe!Kx9#mQ2vW8", "MFRGGZDFMZTWQ2LKNNWG23TPOBYXE43U", "https://dashboard.stripe.com"),
			CreationDate: ago(180 * day), RevisionDate: ago(20 * day),
		},
		{
			ID: "c-apple", Type: api.CipherTypeLogin, Name: "Apple ID", Favorite: true,
			FolderID:     folder("f-personal"),
			Login:        login("alex.morgan@icloud.com", "Orchard-Velvet-Comet-42", "NB2W45DFOIZA4ZLUN5ZGK3TBMUZDGNBV", "https://appleid.apple.com"),
			CreationDate: ago(900 * day), RevisionDate: ago(64 * day),
		},
		{
			ID: "c-google", Type: api.CipherTypeLogin, Name: "Google Workspace",
			FolderID:     folder("f-work"),
			Login:        login("alex@northwind.dev", "gW$7nK2!pQ9#vX4m", "", "https://accounts.google.com"),
			CreationDate: ago(500 * day), RevisionDate: ago(90 * day),
		},
		{
			ID: "c-linear", Type: api.CipherTypeLogin, Name: "Linear",
			FolderID:     folder("f-work"),
			Login:        login("alex@northwind.dev", "Ln3ar!Plan#2026", "", "https://linear.app"),
			CreationDate: ago(120 * day), RevisionDate: ago(8 * day),
		},
		{
			ID: "c-figma", Type: api.CipherTypeLogin, Name: "Figma",
			FolderID:     folder("f-work"),
			Login:        login("alex@northwind.dev", "F1gma#Frames!77", "", "https://www.figma.com"),
			CreationDate: ago(140 * day), RevisionDate: ago(33 * day),
		},
		{
			ID: "c-netflix", Type: api.CipherTypeLogin, Name: "Netflix",
			FolderID:     folder("f-personal"),
			Login:        login("alex.morgan@icloud.com", "Orchard-Velvet-Comet-42", "", "https://www.netflix.com"),
			CreationDate: ago(700 * day), RevisionDate: ago(200 * day),
		},
		{
			ID: "c-router", Type: api.CipherTypeLogin, Name: "Home Router",
			FolderID:     folder("f-personal"),
			Login:        login("admin", "admin123", "", "http://192.168.1.1"),
			CreationDate: ago(900 * day), RevisionDate: ago(600 * day),
		},
		{
			ID: "c-visa", Type: api.CipherTypeCard, Name: "Chase Sapphire Visa", Favorite: true,
			FolderID: folder("f-finance"),
			Card: &state.Card{
				CardholderName: "Alex Morgan", Brand: "Visa", Number: "4147 2026 8890 1234",
				ExpMonth: "08", ExpYear: "2029", Code: "731",
			},
			CreationDate: ago(365 * day), RevisionDate: ago(30 * day),
		},
		{
			ID: "c-amex", Type: api.CipherTypeCard, Name: "Amex Business Gold",
			FolderID: folder("f-finance"),
			Card: &state.Card{
				CardholderName: "Alex Morgan", Brand: "Amex", Number: "3782 822463 10005",
				ExpMonth: soonMonth, ExpYear: soonYear, Code: "4410",
			},
			CreationDate: ago(250 * day), RevisionDate: ago(70 * day),
		},
		{
			ID: "c-identity", Type: api.CipherTypeIdentity, Name: "Personal Identity",
			FolderID: folder("f-personal"),
			Identity: &state.Identity{
				FirstName: "Alex", LastName: "Morgan", Company: "Northwind Labs",
				Email: "alex.morgan@icloud.com", Phone: "+1 415 555 0142",
				Address1: "220 Valencia St", City: "San Francisco", State: "CA", PostalCode: "94103", Country: "US",
				PassportNumber: "X48120931",
			},
			CreationDate: ago(800 * day), RevisionDate: ago(100 * day),
		},
		{
			ID: "c-wifi", Type: api.CipherTypeSecureNote, Name: "Home Wi-Fi",
			FolderID:     folder("f-personal"),
			SecureNote:   &state.SecureNote{},
			Notes:        "Network: Morgan-Home-5G\nPassword: lantern-orbit-meadow\nRouter admin: http://192.168.1.1",
			CreationDate: ago(600 * day), RevisionDate: ago(150 * day),
		},
		{
			ID: "c-ssh", Type: api.CipherTypeSecureNote, Name: "Server Recovery Keys",
			FolderID:     folder("f-work"),
			SecureNote:   &state.SecureNote{},
			Notes:        "Break-glass procedure for the production bastion. Keys are stored offline in the office safe; rotate every 90 days.",
			CreationDate: ago(200 * day), RevisionDate: ago(15 * day),
		},
		{
			ID: "c-deploy-key", Type: api.CipherTypeSSHKey, Name: "Bastion Deploy Key",
			FolderID:     folder("f-work"),
			SSHKey:       demoSSHKey("deploy@northwind"),
			Notes:        "Used by CI to reach the production bastion.",
			CreationDate: ago(90 * day), RevisionDate: ago(12 * day),
		},
		{
			ID: "c-myspace", Type: api.CipherTypeLogin, Name: "Myspace",
			Login:        login("alexmorgan88", "summer-2008-tunes", "", "https://myspace.com"),
			Notes:        "Kept for the old photos; archived to keep it out of the way.",
			CreationDate: ago(2400 * day), RevisionDate: ago(30 * day), ArchivedDate: ago(30 * day),
		},
		{
			ID: "c-dropbox", Type: api.CipherTypeLogin, Name: "Dropbox (old)",
			Login:        login("alex.morgan@icloud.com", "old-password-2019", "", "https://www.dropbox.com"),
			CreationDate: ago(1500 * day), RevisionDate: ago(400 * day), DeletedDate: ago(5 * day),
		},
	}
}

func withPasskey(l *state.Login, f state.Fido2Credential) *state.Login {
	l.Fido2Credentials = append(l.Fido2Credentials, f)
	return l
}

func demoSSHKey(comment string) *state.SSHKey {
	seed := make([]byte, ed25519.SeedSize)
	copy(seed, "govault-demo-ssh-key-seed")
	k, err := gen.SSHKeyFromEd25519(ed25519.NewKeyFromSeed(seed), comment)
	if err != nil {
		return &state.SSHKey{}
	}
	return &state.SSHKey{PrivateKey: k.PrivateKey, PublicKey: k.PublicKey, KeyFingerprint: k.KeyFingerprint}
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
