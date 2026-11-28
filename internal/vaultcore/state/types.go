package state

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/txchen/govault/internal/vaultcore/api"
	"github.com/txchen/govault/internal/vaultcore/crypto"
	"github.com/txchen/govault/internal/vaultcore/store"
)

type LockStatus int

const (
	StatusLoggedOut LockStatus = iota
	StatusLocked
	StatusUnlocked
)

var (
	ErrLocked                  = errors.New("state: vault is locked")
	ErrLoggedOut               = errors.New("state: no active account")
	ErrCipherNotFound          = errors.New("state: cipher not found")
	ErrFolderNotFound          = errors.New("state: folder not found")
	ErrUnsupportedCipherFormat = errors.New("state: unsupported v2 sealed blob cipher format")
	ErrInvalidSecretStore      = errors.New("state: secret store is required")
	ErrReadOnlyCipher          = errors.New("state: item is read-only")
	ErrOrganizationKeyMissing  = errors.New("state: organization key unavailable")
	ErrAttachmentNotFound      = errors.New("state: attachment not found")
	ErrHiddenByOrganization    = errors.New("state: hidden by your organization")
	ErrUnsupportedUpload       = errors.New("state: server requested an unsupported attachment upload method")
	ErrSyncDeferred            = errors.New("state: changes kept landing during sync; nothing was synced yet")
	ErrServerMismatch          = errors.New("state: the saved sign-in belongs to a different server than this vault copy; sign in again")
	ErrSignInRequired          = errors.New("state: sign in again to sync; the vault is available offline until then")
	ErrDifferentAccount        = errors.New("state: this signs in to a different account than the vault on this device; to use a different account, log out first")
	ErrArchiveUnsupported      = errors.New("state: this server does not support Archive; it needs Vaultwarden 1.36 or later")
	ErrArchiveNotConfirmed     = errors.New("state: the server did not confirm the change; GoVault synced to show where the item is now")
	ErrPremiumRequired         = errors.New("state: archiving items needs a premium membership")
	ErrCipherInTrash           = errors.New("state: the item is in Trash")
	ErrAccountIDUnknown            = errors.New("state: could not confirm your account ID with the server; sync and try again")
	ErrAccountChanged              = errors.New("state: the account changed since this was confirmed")
	ErrSnapshotNotUpdated          = errors.New("state: the server has the change, but the local copy could not be updated; sync to refresh it")
	ErrSSOMasterPasswordRequired   = errors.New("state: this SSO account has no master password yet; set one in the web vault first")
	ErrSSOForcePasswordReset       = errors.New("state: your organization requires a master password reset; reset it in the web vault first")
	ErrSSOKeyConnectorUnsupported  = errors.New("state: SSO with Key Connector is not supported yet")
	ErrSSOTrustedDeviceUnsupported = errors.New("state: SSO with Trusted Device Encryption is not supported yet")
)

// LocalCopyError reports a change the server accepted and GoVault now
// shows, but could not write to the encrypted local copy. The change is
// done: retrying it would repeat it (a second item, for a create). Sync
// instead. Cipher is the committed item, for changes that have one.
type LocalCopyError struct {
	Cipher *Cipher
	Err    error
}

func (e *LocalCopyError) Error() string {
	return ErrSnapshotNotUpdated.Error() + ": " + e.Err.Error()
}

func (e *LocalCopyError) Unwrap() []error { return []error{ErrSnapshotNotUpdated, e.Err} }

type FilterCategory int

const (
	FilterAll FilterCategory = iota
	FilterFavorites
	FilterTrash
	FilterNoFolder
	// FilterArchive lists archived items, which every other category but
	// Trash leaves out, as Bitwarden's clients do.
	FilterArchive
)

type SearchFilter struct {
	Category       FilterCategory
	FolderID       string
	OrganizationID string
	CollectionID   string
	Type           *api.CipherType
}

type CipherSummary struct {
	ID       string
	Type     api.CipherType
	FolderID *string
	Favorite bool
	Deleted  bool
	Archived bool
	Name     string
	Subtitle string
	// RevisionDate is when the item last changed, for sorting.
	RevisionDate *time.Time
	HasTOTP      bool
	HasPasskey   bool
	Reprompt     int
	URIs         []string

	OrganizationID *string
	CollectionIDs  []string
}

type Cipher struct {
	ID               string
	Type             api.CipherType
	FolderID         *string
	OrganizationID   *string
	Favorite         bool
	Reprompt         int
	Key              *string
	Name             string
	Notes            string
	RevisionDate     *time.Time
	CreationDate     *time.Time
	DeletedDate      *time.Time
	ArchivedDate     *time.Time
	Login            *Login
	SecureNote       *SecureNote
	Card             *Card
	Identity         *Identity
	SSHKey           *SSHKey
	Fields           []CustomField
	PasswordHistory  []PasswordHistoryEntry
	Attachments      []Attachment
	Data             json.RawMessage
	EncryptedFor     *string
	EncryptedByKeyID *string
	CollectionIDs    []string
	ReadOnly         bool
	HidePassword     bool
	Extra            map[string]json.RawMessage
	// SealedKeyID identifies the key the server copies of this item's
	// encrypted blobs (passkeys, URI checksums, encrypted unknown fields)
	// are sealed with. A save under the same key sends them back unchanged;
	// under another key they cannot be decrypted and are dropped (see
	// keepSealed).
	SealedKeyID string
	// ProvenSealed holds the SHA-256 (hex) of each unknown-field string
	// proven to be ciphertext under that key, which a save under another
	// key may drop (see keepSealed). It holds no key material.
	ProvenSealed map[string]bool
}

type Login struct {
	Username             string
	Password             string
	TOTP                 string
	URIs                 []LoginURI
	PasswordRevisionDate *time.Time
	Fido2Credentials     []Fido2Credential
	Extra                map[string]json.RawMessage
	Shape                api.Shape
}

type LoginURI struct {
	URI   string
	Match *int
	// Checksum is the server's encrypted checksum of ChecksumOf, the URI text
	// it was computed for. It is sent back while URI still equals ChecksumOf
	// and recomputed otherwise.
	Checksum   *string
	ChecksumOf string
	Extra      map[string]json.RawMessage
	Shape      api.Shape
}

// Fido2Credential is a passkey. GoVault shows and can remove passkeys but
// never creates or uses them. Sealed is the passkey exactly as the server
// sent it, which is what a save sends back; the decrypted fields are for
// display and for export.
type Fido2Credential struct {
	CredentialID    string
	KeyType         string
	KeyAlgorithm    string
	KeyCurve        string
	KeyValue        string
	RpID            string
	UserHandle      string
	UserName        string
	Counter         string
	RpName          string
	UserDisplayName string
	Discoverable    string
	CreationDate    string
	Sealed          json.RawMessage
	// Unreadable names the fields that did not decrypt, so an export can
	// refuse to write a passkey that would not work.
	Unreadable []string
}

type SecureNote struct {
	Type  int
	Extra map[string]json.RawMessage
	Shape api.Shape
}

type Card struct {
	CardholderName string
	Brand          string
	Number         string
	ExpMonth       string
	ExpYear        string
	Code           string
	Extra          map[string]json.RawMessage
	Shape          api.Shape
}

type Identity struct {
	Title          string
	FirstName      string
	MiddleName     string
	LastName       string
	Address1       string
	Address2       string
	Address3       string
	City           string
	State          string
	PostalCode     string
	Country        string
	Company        string
	Email          string
	Phone          string
	SSN            string
	Username       string
	PassportNumber string
	LicenseNumber  string
	Extra          map[string]json.RawMessage
	Shape          api.Shape
}

type SSHKey struct {
	PrivateKey     string
	PublicKey      string
	KeyFingerprint string
	Extra          map[string]json.RawMessage
	Shape          api.Shape
}

type CustomField struct {
	Name     string
	Value    string
	Type     int
	LinkedID *int
	Extra    map[string]json.RawMessage
	Shape    api.Shape
}

type Attachment struct {
	ID       string
	URL      string
	FileName string
	Key      *string
	Size     int64
	SizeName string
	Extra    map[string]json.RawMessage
}

type PasswordHistoryEntry struct {
	Password     string
	LastUsedDate time.Time
	Extra        map[string]json.RawMessage
	Shape        api.Shape
}

// TrashResult reports what EmptyTrash did: items deleted and read-only
// items left in Trash.
type TrashResult struct {
	Deleted  int
	ReadOnly int
	// Skipped counts items that changed since the user confirmed, such as
	// one restored on another device; they were kept.
	Skipped int
}

// TrashItem is an item in Trash as the user saw it when confirming.
type TrashItem struct {
	ID           string
	RevisionDate *time.Time
}

// TrashSelection is exactly what one Empty Trash confirmation covers.
type TrashSelection struct {
	AccountID string
	Items     []TrashItem
	ReadOnly  int
}

type Folder struct {
	ID           string
	Name         string
	RevisionDate *time.Time
	Extra        map[string]json.RawMessage
}

type LoginRequest struct {
	ServerURL      string
	Email          string
	MasterPassword []byte

	TwoFactorProvider api.TwoFactorProvider
	TwoFactorCode     string
	RememberDevice    bool

	// NewDeviceOTP is the code the server emailed after refusing a login
	// from this device with *api.NewDeviceVerificationRequiredError.
	NewDeviceOTP string

	// SameAccount, when set, is the account of the local vault this
	// sign-in renews (Sign In Again). A login to any other account or
	// server is refused with ErrDifferentAccount before anything is saved.
	SameAccount *Account
}

// SSOLoginRequest exchanges an SSO authorization code and PKCE verifier
// for an authenticated, locked vault ready to be unlocked with the account's
// master password.
type SSOLoginRequest struct {
	ServerURL    string
	Code         string
	CodeVerifier string
	RedirectURI  string
	// Email is optional; when set, any remembered two-factor token for this
	// server and email is tried automatically.
	Email string

	TwoFactorProvider api.TwoFactorProvider
	TwoFactorCode     string
	RememberDevice    bool

	// SameAccount, when set, restricts Sign In Again to this account and
	// its trusted server.
	SameAccount *Account
}

// Account is who a vault belongs to: the account ID and the server and
// email it was signed in with.
type Account struct {
	ID        string
	ServerURL string
	Email     string
}

type Organization struct {
	ID      string
	Name    string
	Type    int
	Enabled bool
}

type Collection struct {
	ID             string
	OrganizationID string
	Name           string
	ReadOnly       bool
	HidePasswords  bool
	Manage         bool
}

type VaultService interface {
	Status() LockStatus
	Login(ctx context.Context, req LoginRequest) error
	LoginSSO(ctx context.Context, req SSOLoginRequest) error
	SendEmailTwoFactorCode(ctx context.Context, req LoginRequest) error
	SendEmailTwoFactorCodeSSO(ctx context.Context, serverURL, email, ssoSessionToken string) error
	ResendNewDeviceOTP(ctx context.Context, req LoginRequest) error
	UnlockWithPassword(ctx context.Context, masterPassword []byte) error
	UnlockWithUserKey(ctx context.Context, userKey *crypto.SymmetricKey) error
	EnableBiometricUnlock(secrets store.SecretStore) error
	DisableBiometricUnlock(secrets store.SecretStore) error
	Lock()
	Logout(ctx context.Context, secrets store.SecretStore) error

	SyncNow(ctx context.Context) error
	Search(query string, filter SearchFilter) []CipherSummary
	GetCipher(id string) (*Cipher, error)
	AllCiphers() []*Cipher
	SaveCipher(ctx context.Context, c *Cipher) (*Cipher, error)
	SoftDeleteCipher(ctx context.Context, id string) error
	RestoreCipher(ctx context.Context, id string) error
	MoveCiphers(ctx context.Context, ids []string, folderID *string) error
	HardDeleteCipher(ctx context.Context, id string) error
	TrashSelection() TrashSelection
	ArchiveCipher(ctx context.Context, id string) error
	UnarchiveCipher(ctx context.Context, id string) error
	CanArchive() bool
	UnreadableItems() []string
	BackupData() BackupData
	Account() Account
	TrustedServerURL(accountID string) string
	AuthAttempt() uint64
	RevokeAuthAttempts()
	LocalOnly() bool
	CredentialsNotSaved() bool
	SessionContext(parent context.Context) (context.Context, context.CancelFunc, error)
	EmptyTrash(ctx context.Context, sel TrashSelection) (TrashResult, error)
	Folders() []Folder
	SaveFolder(ctx context.Context, f *Folder) (*Folder, error)
	DeleteFolder(ctx context.Context, id string) error
	DownloadAttachment(ctx context.Context, cipherID, attachmentID string) ([]byte, string, error)
	UploadAttachment(ctx context.Context, cipherID, fileName string, plain []byte) (*Cipher, error)
	DeleteAttachment(ctx context.Context, cipherID, attachmentID string) (*Cipher, error)
	Organizations() []Organization
	Collections() []Collection
}
