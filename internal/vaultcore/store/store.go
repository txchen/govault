package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/txchen/govault/internal/vaultcore/crypto"
)

const CurrentSchemaVersion = 1

var (
	ErrSnapshotNotFound = errors.New("store: snapshot not found")
	ErrInvalidAccountID = errors.New("store: invalid account ID")
	ErrInvalidSnapshot  = errors.New("store: invalid snapshot")
)

type Snapshot struct {
	SchemaVersion int              `json:"schemaVersion"`
	AccountID     string           `json:"accountId"`
	ServerURL     string           `json:"serverUrl"`
	Email         string           `json:"email"`
	// KDFSalt is the verbatim salt for master-password key derivation when
	// the server supplied one (MasterPasswordUnlock.Salt), which may differ
	// from Email or be case-sensitive. Empty falls back to normalized Email.
	KDFSalt      string           `json:"kdfSalt,omitempty"`
	KDF          crypto.KDFConfig `json:"kdf"`
	ProtectedKey string           `json:"protectedKey"`
	RevisionDate time.Time        `json:"revisionDate"`
	LastSyncAt   time.Time        `json:"lastSyncAt"`
	RawSyncJSON  json.RawMessage  `json:"rawSyncJson"`
	// Sequence counts the snapshots a profile store saved, so a writer can
	// tell whether another one committed since it loaded.
	Sequence uint64 `json:"sequence,omitempty"`
}

// EffectiveKDFSalt returns the salt to pass verbatim to
// crypto.DeriveKeyFromPassword: KDFSalt when stored, else normalized Email.
func (s *Snapshot) EffectiveKDFSalt() string {
	if s != nil && s.KDFSalt != "" {
		return s.KDFSalt
	}
	if s == nil {
		return ""
	}
	return crypto.NormalizeEmail(s.Email)
}

type Store interface {
	LoadSnapshot(accountID string) (*Snapshot, error)
	SaveSnapshot(snap *Snapshot) error
	DeleteSnapshot(accountID string) error
}

type SecretStore interface {
	Get(account string) (string, bool, error)
	Set(account, value string) error
	Delete(account string) error
}

type FileStore struct {
	dir string
}

func NewFileStore(dir string) *FileStore {
	return &FileStore{dir: dir}
}

func (s *FileStore) LoadSnapshot(accountID string) (*Snapshot, error) {
	path, err := s.snapshotPath(accountID)
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrSnapshotNotFound
		}
		return nil, err
	}

	var snap Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidSnapshot, err)
	}
	if snap.SchemaVersion != CurrentSchemaVersion {
		return nil, fmt.Errorf("%w: unsupported schema version %d", ErrInvalidSnapshot, snap.SchemaVersion)
	}
	return &snap, nil
}

func (s *FileStore) SaveSnapshot(snap *Snapshot) error {
	if snap == nil {
		return ErrInvalidSnapshot
	}
	path, err := s.snapshotPath(snap.AccountID)
	if err != nil {
		return err
	}

	toWrite := *snap
	if toWrite.SchemaVersion == 0 {
		toWrite.SchemaVersion = CurrentSchemaVersion
	}
	if toWrite.SchemaVersion != CurrentSchemaVersion {
		return fmt.Errorf("%w: unsupported schema version %d", ErrInvalidSnapshot, toWrite.SchemaVersion)
	}

	data, err := json.Marshal(&toWrite)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}

	tmp, err := os.CreateTemp(s.dir, ".vault-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func (s *FileStore) DeleteSnapshot(accountID string) error {
	path, err := s.snapshotPath(accountID)
	if err != nil {
		return err
	}
	err = os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (s *FileStore) snapshotPath(accountID string) (string, error) {
	if accountID == "" || strings.ContainsAny(accountID, `/\`) || strings.Contains(accountID, "..") {
		return "", ErrInvalidAccountID
	}
	return filepath.Join(s.dir, "vault_"+accountID+".enc.json"), nil
}
