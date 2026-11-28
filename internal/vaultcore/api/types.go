package api

import (
	"bytes"
	"encoding/json"
	"maps"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/txchen/govault/internal/vaultcore/crypto"
)

type CipherType int

const (
	CipherTypeLogin          CipherType = 1
	CipherTypeSecureNote     CipherType = 2
	CipherTypeCard           CipherType = 3
	CipherTypeIdentity       CipherType = 4
	CipherTypeSSHKey         CipherType = 5
	CipherTypeBankAccount    CipherType = 6
	CipherTypeDriversLicense CipherType = 7
	CipherTypePassport       CipherType = 8
)

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	Key          string `json:"Key"`
	PrivateKey   string `json:"PrivateKey"`
	KDF          int    `json:"Kdf"`
	KDFIters     int    `json:"KdfIterations"`
	KDFMemory    *int   `json:"KdfMemory"`
	KDFParallel  *int   `json:"KdfParallelism"`

	TwoFactorToken        string                 `json:"TwoFactorToken"`
	ForcePasswordReset    bool                   `json:"ForcePasswordReset,omitempty"`
	UserDecryptionOptions *UserDecryptionOptions `json:"UserDecryptionOptions,omitempty"`
}

// UserDecryptionOptions describes how an authenticated account can decrypt
// its vault (Vaultwarden identity.rs / bitwarden/server).
type UserDecryptionOptions struct {
	HasMasterPassword    bool                  `json:"HasMasterPassword"`
	MasterPasswordUnlock *MasterPasswordUnlock `json:"MasterPasswordUnlock,omitempty"`
	KeyConnectorOption   *KeyConnectorOption   `json:"KeyConnectorOption,omitempty"`
	TrustedDeviceOption  *TrustedDeviceOption  `json:"TrustedDeviceOption,omitempty"`
}

type MasterPasswordUnlock struct {
	KDF                       *MasterPasswordUnlockKDF `json:"Kdf,omitempty"`
	MasterKeyEncryptedUserKey string                   `json:"MasterKeyEncryptedUserKey,omitempty"`
	MasterKeyWrappedUserKey   string                   `json:"MasterKeyWrappedUserKey,omitempty"`
	Salt                      string                   `json:"Salt,omitempty"`
}

type MasterPasswordUnlockKDF struct {
	KDFType     int  `json:"KdfType"`
	Iterations  int  `json:"Iterations"`
	Memory      *int `json:"Memory,omitempty"`
	Parallelism *int `json:"Parallelism,omitempty"`
}

type KeyConnectorOption struct {
	KeyConnectorURL string `json:"KeyConnectorUrl,omitempty"`
}

type TrustedDeviceOption struct {
	HasAdminApproval                 bool   `json:"HasAdminApproval,omitempty"`
	HasLoginApprovingDevice          bool   `json:"HasLoginApprovingDevice,omitempty"`
	HasManageResetPasswordPermission bool   `json:"HasManageResetPasswordPermission,omitempty"`
	EncryptedPrivateKey              string `json:"EncryptedPrivateKey,omitempty"`
	EncryptedUserKey                 string `json:"EncryptedUserKey,omitempty"`
}

// MasterPasswordProtectedKey returns the master-key-wrapped user key from
// MasterPasswordUnlock or the top-level Key field.
func (t *TokenResponse) MasterPasswordProtectedKey() string {
	if t == nil {
		return ""
	}
	if opt := t.UserDecryptionOptions; opt != nil && opt.MasterPasswordUnlock != nil {
		if k := opt.MasterPasswordUnlock.MasterKeyWrappedUserKey; k != "" {
			return k
		}
		if k := opt.MasterPasswordUnlock.MasterKeyEncryptedUserKey; k != "" {
			return k
		}
	}
	return t.Key
}

// MasterPasswordSalt returns the KDF salt from MasterPasswordUnlock, or ""
// when absent.
func (t *TokenResponse) MasterPasswordSalt() string {
	if t == nil || t.UserDecryptionOptions == nil || t.UserDecryptionOptions.MasterPasswordUnlock == nil {
		return ""
	}
	return t.UserDecryptionOptions.MasterPasswordUnlock.Salt
}

// MasterPasswordKDF returns the KDF parameters for master-password unlock,
// preferring UserDecryptionOptions.MasterPasswordUnlock.Kdf when present.
func (t *TokenResponse) MasterPasswordKDF() crypto.KDFConfig {
	if t == nil {
		return crypto.KDFConfig{}
	}
	if opt := t.UserDecryptionOptions; opt != nil && opt.MasterPasswordUnlock != nil && opt.MasterPasswordUnlock.KDF != nil {
		k := opt.MasterPasswordUnlock.KDF
		cfg := crypto.KDFConfig{Type: crypto.KDFType(k.KDFType), Iterations: uint32(k.Iterations)}
		if k.Memory != nil {
			cfg.MemoryMB = uint32(*k.Memory)
		}
		if k.Parallelism != nil {
			cfg.Parallelism = uint32(*k.Parallelism)
		}
		return cfg
	}
	cfg := crypto.KDFConfig{Type: crypto.KDFType(t.KDF), Iterations: uint32(t.KDFIters)}
	if t.KDFMemory != nil {
		cfg.MemoryMB = uint32(*t.KDFMemory)
	}
	if t.KDFParallel != nil {
		cfg.Parallelism = uint32(*t.KDFParallel)
	}
	return cfg
}

type SyncResponse struct {
	Profile     Profile                    `json:"profile"`
	Folders     []EncryptedFolder          `json:"folders"`
	Ciphers     []EncryptedCipher          `json:"ciphers"`
	Collections []EncryptedCollection      `json:"collections,omitempty"`
	Sends       json.RawMessage            `json:"sends,omitempty"`
	Policies    json.RawMessage            `json:"policies,omitempty"`
	Extra       map[string]json.RawMessage `json:"-"`
}

func (s *SyncResponse) UnmarshalJSON(data []byte) error {
	type alias SyncResponse
	var a alias
	if err := unmarshalWithExtra(data, &a, &a.Extra); err != nil {
		return err
	}
	*s = SyncResponse(a)
	return nil
}

func (s SyncResponse) MarshalJSON() ([]byte, error) {
	type alias SyncResponse
	return marshalWithExtra(alias(s), s.Extra)
}

type Profile struct {
	ID            string                     `json:"id"`
	Email         string                     `json:"email"`
	Name          *string                    `json:"name,omitempty"`
	Key           string                     `json:"key"`
	PrivateKey    *string                    `json:"privateKey,omitempty"`
	KDF           int                        `json:"kdf"`
	KDFIters      int                        `json:"kdfIterations"`
	KDFMemory     *int                       `json:"kdfMemory,omitempty"`
	KDFParallel   *int                       `json:"kdfParallelism,omitempty"`
	Organizations []ProfileOrganization      `json:"organizations,omitempty"`
	Extra         map[string]json.RawMessage `json:"-"`
}

func (p *Profile) UnmarshalJSON(data []byte) error {
	type alias Profile
	var a alias
	if err := unmarshalWithExtra(data, &a, &a.Extra); err != nil {
		return err
	}
	*p = Profile(a)
	return nil
}

func (p Profile) MarshalJSON() ([]byte, error) {
	type alias Profile
	return marshalWithExtra(alias(p), p.Extra)
}

const OrganizationStatusConfirmed = 2

type ProfileOrganization struct {
	ID      string                     `json:"id"`
	Name    string                     `json:"name"`
	Key     string                     `json:"key"`
	Enabled bool                       `json:"enabled"`
	Status  int                        `json:"status"`
	Type    int                        `json:"type"`
	Extra   map[string]json.RawMessage `json:"-"`
}

func (o *ProfileOrganization) UnmarshalJSON(data []byte) error {
	type alias ProfileOrganization
	var a alias
	if err := unmarshalWithExtra(data, &a, &a.Extra); err != nil {
		return err
	}
	*o = ProfileOrganization(a)
	return nil
}

func (o ProfileOrganization) MarshalJSON() ([]byte, error) {
	type alias ProfileOrganization
	return marshalWithExtra(alias(o), o.Extra)
}

type EncryptedCollection struct {
	ID             string                     `json:"id"`
	OrganizationID string                     `json:"organizationId"`
	Name           string                     `json:"name"`
	ReadOnly       bool                       `json:"readOnly"`
	HidePasswords  bool                       `json:"hidePasswords"`
	Manage         bool                       `json:"manage"`
	ExternalID     *string                    `json:"externalId,omitempty"`
	Extra          map[string]json.RawMessage `json:"-"`
}

func (c *EncryptedCollection) UnmarshalJSON(data []byte) error {
	type alias EncryptedCollection
	var a alias
	if err := unmarshalWithExtra(data, &a, &a.Extra); err != nil {
		return err
	}
	*c = EncryptedCollection(a)
	return nil
}

func (c EncryptedCollection) MarshalJSON() ([]byte, error) {
	type alias EncryptedCollection
	return marshalWithExtra(alias(c), c.Extra)
}

type EncryptedFolder struct {
	ID           string                     `json:"id"`
	Name         string                     `json:"name"`
	RevisionDate *time.Time                 `json:"revisionDate,omitempty"`
	Extra        map[string]json.RawMessage `json:"-"`
}

func (f *EncryptedFolder) UnmarshalJSON(data []byte) error {
	type alias EncryptedFolder
	var a alias
	if err := unmarshalWithExtra(data, &a, &a.Extra); err != nil {
		return err
	}
	*f = EncryptedFolder(a)
	return nil
}

func (f EncryptedFolder) MarshalJSON() ([]byte, error) {
	type alias EncryptedFolder
	return marshalWithExtra(alias(f), f.Extra)
}

type EncryptedCipher struct {
	ID               string                     `json:"id"`
	Type             CipherType                 `json:"type"`
	FolderID         *string                    `json:"folderId"`
	OrganizationID   *string                    `json:"organizationId"`
	Favorite         bool                       `json:"favorite"`
	Reprompt         int                        `json:"reprompt"`
	Key              *string                    `json:"key,omitempty"`
	Name             string                     `json:"name"`
	Notes            *string                    `json:"notes"`
	RevisionDate     *time.Time                 `json:"revisionDate,omitempty"`
	CreationDate     *time.Time                 `json:"creationDate,omitempty"`
	DeletedDate      *time.Time                 `json:"deletedDate,omitempty"`
	ArchivedDate     *time.Time                 `json:"archivedDate,omitempty"`
	Login            *EncryptedLogin            `json:"login,omitempty"`
	SecureNote       *EncryptedSecureNote       `json:"secureNote,omitempty"`
	Card             *EncryptedCard             `json:"card,omitempty"`
	Identity         *EncryptedIdentity         `json:"identity,omitempty"`
	SSHKey           *EncryptedSSHKey           `json:"sshKey,omitempty"`
	Fields           []EncryptedField           `json:"fields,omitempty"`
	PasswordHistory  []EncryptedPasswordHistory `json:"passwordHistory,omitempty"`
	Attachments      []EncryptedAttachment      `json:"attachments,omitempty"`
	Data             json.RawMessage            `json:"data,omitempty"`
	EncryptedFor     *string                    `json:"encryptedFor,omitempty"`
	EncryptedByKeyID *string                    `json:"encryptedByKeyId,omitempty"`
	CollectionIDs    []string                   `json:"collectionIds,omitempty"`
	Edit             *bool                      `json:"edit,omitempty"`
	ViewPassword     *bool                      `json:"viewPassword,omitempty"`
	Extra            map[string]json.RawMessage `json:"-"`
}

func (c *EncryptedCipher) UnmarshalJSON(data []byte) error {
	type alias EncryptedCipher
	var a alias
	if err := unmarshalWithExtra(data, &a, &a.Extra); err != nil {
		return err
	}
	// A server with Archive sends archivedDate on every cipher, null when
	// not archived. Keeping that null lets a rewritten snapshot still show
	// the server supports it.
	if a.ArchivedDate == nil && bytes.Contains(data, []byte(`"archivedDate"`)) {
		if a.Extra == nil {
			a.Extra = map[string]json.RawMessage{}
		}
		a.Extra["archivedDate"] = json.RawMessage("null")
	}
	*c = EncryptedCipher(a)
	return nil
}

// ReportsArchive tells whether the server sent this cipher's archivedDate,
// which servers with Archive (Vaultwarden 1.36 or later) always do.
func (c *EncryptedCipher) ReportsArchive() bool {
	_, sent := c.Extra["archivedDate"]
	return c.ArchivedDate != nil || sent
}

func (c EncryptedCipher) MarshalJSON() ([]byte, error) {
	type alias EncryptedCipher
	return marshalWithExtra(alias(c), c.Extra)
}

type CipherPayload struct {
	Type           CipherType `json:"type"`
	FolderID       *string    `json:"folderId"`
	OrganizationID *string    `json:"organizationId"`
	Favorite       bool       `json:"favorite"`
	Reprompt       int        `json:"reprompt"`
	Key            *string    `json:"key,omitempty"`
	// EncryptedFor is the ID of the user the item is encrypted for, which
	// Bitwarden's clients send on every write. Vaultwarden 1.37.4 and
	// 1.37.5 require it (CipherData.encrypted_for: UserId) and answer
	// HTTP 422 to a create or update without it.
	EncryptedFor          *string    `json:"encryptedFor,omitempty"`
	Name                  string     `json:"name"`
	Notes                 *string    `json:"notes"`
	LastKnownRevisionDate *time.Time `json:"lastKnownRevisionDate,omitempty"`
	// ArchivedDate is always sent: Vaultwarden and Bitwarden unarchive an
	// item whose update omits it.
	ArchivedDate    *time.Time                 `json:"archivedDate"`
	Login           *EncryptedLogin            `json:"login,omitempty"`
	SecureNote      *EncryptedSecureNote       `json:"secureNote,omitempty"`
	Card            *EncryptedCard             `json:"card,omitempty"`
	Identity        *EncryptedIdentity         `json:"identity,omitempty"`
	SSHKey          *EncryptedSSHKey           `json:"sshKey,omitempty"`
	Fields          []EncryptedField           `json:"fields,omitempty"`
	PasswordHistory []EncryptedPasswordHistory `json:"passwordHistory,omitempty"`
	CollectionIDs   []string                   `json:"collectionIds,omitempty"`
	Extra           map[string]json.RawMessage `json:"-"`
}

func (p *CipherPayload) UnmarshalJSON(data []byte) error {
	type alias CipherPayload
	var a alias
	if err := unmarshalWithExtra(data, &a, &a.Extra); err != nil {
		return err
	}
	*p = CipherPayload(a)
	return nil
}

func (p CipherPayload) MarshalJSON() ([]byte, error) {
	type alias CipherPayload
	return marshalWithExtra(alias(p), p.Extra)
}

type EncryptedAttachment struct {
	ID       string                     `json:"id"`
	URL      string                     `json:"url,omitempty"`
	FileName string                     `json:"fileName"`
	Key      *string                    `json:"key,omitempty"`
	Size     FlexInt                    `json:"size"`
	SizeName string                     `json:"sizeName,omitempty"`
	Extra    map[string]json.RawMessage `json:"-"`
	Shape    Shape                      `json:"-"`
}

func (a *EncryptedAttachment) UnmarshalJSON(data []byte) error {
	type alias EncryptedAttachment
	var v alias
	if err := unmarshalNested(data, &v, &v.Extra, &v.Shape); err != nil {
		return err
	}
	*a = EncryptedAttachment(v)
	return nil
}

func (a EncryptedAttachment) MarshalJSON() ([]byte, error) {
	type alias EncryptedAttachment
	return marshalNested(alias(a), a.Extra, a.Shape)
}

// FlexInt decodes an integer sent either as a JSON number or a string, as
// attachment sizes are, and encodes it as a string.
type FlexInt int64

func (n *FlexInt) UnmarshalJSON(data []byte) error {
	s := strings.Trim(strings.TrimSpace(string(data)), `"`)
	if s == "" || s == "null" {
		*n = 0
		return nil
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return err
	}
	*n = FlexInt(v)
	return nil
}

func (n FlexInt) MarshalJSON() ([]byte, error) {
	return json.Marshal(strconv.FormatInt(int64(n), 10))
}

type AttachmentUploadRequest struct {
	Key      string `json:"key"`
	FileName string `json:"fileName"`
	FileSize int64  `json:"fileSize"`
}

// File upload types of an attachment upload: Direct posts the file to
// the server; Azure puts it to a signed blob storage URL, which the server
// learns of from the storage service.
const (
	FileUploadTypeDirect = 0
	FileUploadTypeAzure  = 1
)

type AttachmentUploadResponse struct {
	AttachmentID   string           `json:"attachmentId"`
	URL            string           `json:"url"`
	FileUploadType int              `json:"fileUploadType"`
	CipherResponse *EncryptedCipher `json:"cipherResponse,omitempty"`
}

func unmarshalWithExtra(data []byte, dst any, extra *map[string]json.RawMessage) error {
	if err := json.Unmarshal(data, dst); err != nil {
		return err
	}
	var all map[string]json.RawMessage
	if err := json.Unmarshal(data, &all); err != nil {
		return err
	}
	t := reflect.TypeOf(dst).Elem()
	for i := range t.NumField() {
		tag := t.Field(i).Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		name, _, _ := strings.Cut(tag, ",")
		if name != "" {
			delete(all, name)
		}
	}
	if len(all) > 0 {
		*extra = all
	}
	return nil
}

func marshalWithExtra(src any, extra map[string]json.RawMessage) ([]byte, error) {
	baseBytes, err := json.Marshal(src)
	if err != nil {
		return nil, err
	}
	if len(extra) == 0 {
		return baseBytes, nil
	}
	var merged map[string]json.RawMessage
	if err := json.Unmarshal(baseBytes, &merged); err != nil {
		return nil, err
	}
	if merged == nil {
		merged = make(map[string]json.RawMessage, len(extra))
	}
	out := make(map[string]json.RawMessage, len(extra)+len(merged))
	maps.Copy(out, extra)
	maps.Copy(out, merged)
	return json.Marshal(out)
}
