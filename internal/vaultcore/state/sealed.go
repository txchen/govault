package state

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/txchen/govault/internal/vaultcore/api"
	"github.com/txchen/govault/internal/vaultcore/crypto"
)

// sealedKeyID names a key without revealing it, so a save can tell whether
// it encrypts under the key the server copies of an item were sealed with.
func sealedKeyID(key *crypto.SymmetricKey) string {
	raw := key.Bytes()
	defer crypto.ZeroBytes(raw[:])
	sum := sha256.Sum256(raw[:])
	return hex.EncodeToString(sum[:16])
}

// ErrSealedField means an item holds encrypted data GoVault does not know
// and cannot carry to a new key, so the save is refused instead of
// silently dropping or corrupting it.
var ErrSealedField = errors.New("state: this item holds encrypted data GoVault cannot copy to a new key")

// keepSealed returns the unknown fields to send back with a save.
//
// Under the key they were sealed with they are kept byte for byte. Under
// another key (a clone, an import copy, a move to another key) nothing is
// guessed. A string is dropped only when it is proven old-key ciphertext:
// a type-2 EncString that decrypted, MAC verified, under the old key when
// the item was read (proven, see proveSealed). Every other string that
// parses as an EncString of any type, or could be one of an unknown type,
// makes the save fail with ErrSealedField; it is never deleted. A proven
// string inside an array also fails, since removing it shifts the rest.
// All other values are plaintext and are kept.
func keepSealed(m map[string]json.RawMessage, sameKey bool, proven map[string]bool) (map[string]json.RawMessage, error) {
	if len(m) == 0 {
		return nil, nil
	}
	out := make(map[string]json.RawMessage, len(m))
	for k, v := range m {
		if sameKey {
			out[k] = append(json.RawMessage(nil), v...)
			continue
		}
		kept, keep, err := stripSealed(v, proven)
		if err != nil {
			return nil, fmt.Errorf("%w (field %q)", err, k)
		}
		if keep {
			out[k] = kept
		}
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// stripSealed removes the proven old-key ciphertext from one JSON value.
// keep is false when the value itself is proven ciphertext.
func stripSealed(raw json.RawMessage, proven map[string]bool) (json.RawMessage, bool, error) {
	var v any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return nil, false, ErrSealedField
	}
	changed := false
	var strip func(v any, inArray bool) (any, bool, error)
	strip = func(v any, inArray bool) (any, bool, error) {
		switch t := v.(type) {
		case string:
			switch {
			case proven[sealedHash(t)] && inArray:
				return nil, false, fmt.Errorf("%w: a list holds encrypted data", ErrSealedField)
			case proven[sealedHash(t)]:
				changed = true
				return nil, false, nil
			case crypto.ClassifyEncString(t) != crypto.NotEncString:
				return nil, false, fmt.Errorf("%w: it holds data that may be encrypted with another key", ErrSealedField)
			}
			return t, true, nil
		case []any:
			for i, e := range t {
				ne, _, err := strip(e, true)
				if err != nil {
					return nil, false, err
				}
				t[i] = ne
			}
			return t, true, nil
		case map[string]any:
			for k, e := range t {
				ne, keep, err := strip(e, false)
				if err != nil {
					return nil, false, err
				}
				if keep {
					t[k] = ne
				} else {
					delete(t, k)
				}
			}
			return t, true, nil
		}
		return v, true, nil
	}
	nv, keep, err := strip(v, false)
	if err != nil || !keep {
		return nil, false, err
	}
	if !changed {
		return append(json.RawMessage(nil), raw...), true, nil
	}
	out, err := json.Marshal(nv)
	return out, err == nil, err
}

// sealedHash names a ciphertext string without keeping it.
func sealedHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// proveSealed records in proven every string in the unknown fields that is
// a type-2 EncString decrypting, MAC verified, under key: proof that it is
// ciphertext of this item, which a save under another key may drop.
func proveSealed(proven map[string]bool, key *crypto.SymmetricKey, extras ...map[string]json.RawMessage) {
	var walk func(any)
	walk = func(v any) {
		switch t := v.(type) {
		case string:
			if enc, err := crypto.ParseEncString(t); err == nil && enc.Type == crypto.EncAesCbc256HmacSha256B64 {
				if plain, err := crypto.DecryptBytes(enc, key); err == nil {
					crypto.ZeroBytes(plain)
					proven[sealedHash(t)] = true
				}
			}
		case []any:
			for _, e := range t {
				walk(e)
			}
		case map[string]any:
			for _, e := range t {
				walk(e)
			}
		}
	}
	for _, m := range extras {
		for _, raw := range m {
			var v any
			if json.Unmarshal(raw, &v) == nil {
				walk(v)
			}
		}
	}
}

// uriChecksum is the checksum Bitwarden stores with each login URI: the
// base64 SHA-256 of the URI text, encrypted with the cipher key
// (bitwarden/sdk-internal, LoginUriView::generate_checksum).
func uriChecksum(uri string, key *crypto.SymmetricKey) (*string, error) {
	sum := sha256.Sum256([]byte(uri))
	enc, err := crypto.EncryptString(base64.StdEncoding.EncodeToString(sum[:]), key)
	if err != nil {
		return nil, err
	}
	return &enc, nil
}

// boundRefreshToken is how a refresh token is stored: with the canonical
// base URL (scheme, host, non-default port, installation path) of the
// server that issued it, so a token is only ever sent back there.
// Version 2 binds Origin including installation path; version 0 (GoVault
// 0.6.1) stored only scheme://host and is disambiguated via the trusted
// keychain sign-in record.
type boundRefreshToken struct {
	Version int    `json:"v,omitempty"`
	Origin  string `json:"origin"`
	Token   string `json:"token"`
}

const refreshTokenBindingVersion = 2

func hostOrigin(serverURL string) string {
	u, err := url.Parse(strings.TrimSpace(serverURL))
	if err != nil || u.Host == "" {
		return ""
	}
	scheme, host, port := strings.ToLower(u.Scheme), strings.ToLower(u.Hostname()), u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port != "" {
		host += ":" + port
	}
	return scheme + "://" + host
}

func serverOrigin(serverURL string) string {
	base := hostOrigin(serverURL)
	if base == "" {
		return ""
	}
	u, err := url.Parse(strings.TrimSpace(serverURL))
	if err != nil {
		return ""
	}
	if p := strings.TrimRight(u.EscapedPath(), "/"); p != "" {
		base += p
	}
	return base
}

// loadRefreshToken returns the refresh token for accountID if it was issued
// by serverURL's canonical base (including installation path). A token from
// GoVault 0.6.1 (stored without a version and without path) is accepted only
// when the trusted keychain sign-in record establishes its exact server base;
// otherwise it takes one fresh sign-in (ErrSignInRequired). No token gives
// api.ErrUnauthorized.
func (s *Service) loadRefreshToken(accountID, serverURL string) (string, error) {
	s.mu.RLock()
	unsaved := s.unsavedRefresh
	s.mu.RUnlock()
	if unsaved != "" {
		return unsaved, nil
	}
	if s.cfg.Secrets == nil {
		return "", api.ErrUnauthorized
	}
	raw, ok, err := s.cfg.Secrets.Get(refreshTokenKeyPrefix + accountID)
	if err != nil {
		return "", err
	}
	if !ok || raw == "" {
		return "", api.ErrUnauthorized
	}
	var bound boundRefreshToken
	if json.Unmarshal([]byte(raw), &bound) != nil || bound.Token == "" {
		return "", ErrSignInRequired
	}
	if bound.Origin == "" {
		return "", ErrServerMismatch
	}
	want := serverOrigin(serverURL)
	if want == "" {
		return "", ErrServerMismatch
	}
	if bound.Version >= refreshTokenBindingVersion {
		if bound.Origin != want {
			return "", ErrServerMismatch
		}
		return bound.Token, nil
	}
	// Legacy v0 (0.6.1) record stored only scheme://host. Disambiguate using
	// the trusted keychain sign-in record rather than trusting the editable
	// snapshot alone.
	trusted := s.TrustedServerURL(accountID)
	if trusted == "" {
		return "", ErrSignInRequired
	}
	if hostOrigin(trusted) != bound.Origin || serverOrigin(trusted) != want {
		return "", ErrServerMismatch
	}
	return bound.Token, nil
}

func (s *Service) saveRefreshToken(accountID, serverURL, token string) error {
	raw, err := json.Marshal(boundRefreshToken{
		Version: refreshTokenBindingVersion,
		Origin:  serverOrigin(serverURL),
		Token:   token,
	})
	if err != nil {
		return err
	}
	return s.cfg.Secrets.Set(refreshTokenKeyPrefix+accountID, string(raw))
}
