package fakeserver

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/txchen/govault/internal/vaultcore/crypto"
)

// Fixed identifiers of the fixture vault.
const (
	UserID         = "5d2c7e1a-6b3f-4c8e-9a0d-1f2e3d4c5b6a"
	PeerUserID     = "7a8b9c0d-1e2f-4a3b-8c4d-5e6f7a8b9c0d"
	Email          = "alice@example.com"
	Password       = "correct horse battery staple"
	ClientID       = "user." + UserID
	ClientSecret   = "s3cr3t-api-key-0123456789"
	OrgID          = "0f1e2d3c-4b5a-4968-8776-655443322110"
	OrgName        = "Acme"
	CollectionEng  = "c0c0c0c0-1111-4222-8333-444455556666"
	CollectionSec  = "c1c1c1c1-1111-4222-8333-444455556666"
	FolderWork     = "f0f0f0f0-aaaa-4bbb-8ccc-dddddddddddd"
	FolderHome     = "f1f1f1f1-aaaa-4bbb-8ccc-dddddddddddd"
	ItemGitHub     = "a0000001-0000-4000-8000-000000000001"
	ItemGitHubEnt  = "a0000002-0000-4000-8000-000000000002"
	ItemNote       = "a0000003-0000-4000-8000-000000000003"
	ItemCard       = "a0000004-0000-4000-8000-000000000004"
	ItemIdentity   = "a0000005-0000-4000-8000-000000000005"
	ItemSSH        = "a0000006-0000-4000-8000-000000000006"
	ItemOrgShared  = "a0000007-0000-4000-8000-000000000007"
	ItemOrgHidden  = "a0000008-0000-4000-8000-000000000008"
	ItemTrashed    = "a0000009-0000-4000-8000-000000000009"
	ItemArchived   = "a000000a-0000-4000-8000-00000000000a"
	ItemMatchModes = "a000000b-0000-4000-8000-00000000000b"
	ItemEmpty      = "a000000c-0000-4000-8000-00000000000c"
	AttachmentID   = "att0readme0001"
	AttachmentName = "readme.txt"
	AttachmentBody = "attachment body\x00\x01\x02 with binary bytes\n"
	TOTPSecret     = "JBSWY3DPEHPK3PXP"
)

// DefaultKDFIterations is low so tests derive keys quickly.
const DefaultKDFIterations = 5000

var (
	created  = time.Date(2026, 1, 2, 3, 4, 5, 678000000, time.UTC)
	revised  = time.Date(2026, 2, 3, 4, 5, 6, 789000000, time.UTC)
	deleted  = time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	archived = time.Date(2026, 3, 5, 6, 7, 8, 0, time.UTC)
	pwUsed   = time.Date(2025, 12, 1, 0, 0, 0, 0, time.UTC)
)

func iso(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000000Z") }

// keys holds the fixture account's key material.
type keys struct {
	masterKey [32]byte
	userKey   *crypto.SymmetricKey
	orgKey    *crypto.SymmetricKey
	itemKey   *crypto.SymmetricKey
	attKey    *crypto.SymmetricKey
	userPriv  *rsa.PrivateKey
	peerPriv  *rsa.PrivateKey
}

func mustKey(seed byte) *crypto.SymmetricKey {
	raw := make([]byte, 64)
	for i := range raw {
		raw[i] = seed + byte(i)
	}
	k, err := crypto.SymmetricKeyFromBytes(raw)
	if err != nil {
		panic(err)
	}
	return k
}

func parsePriv(b64 string) *rsa.PrivateKey {
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		panic(err)
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		panic(err)
	}
	return k.(*rsa.PrivateKey)
}

func newKeys(salt, password string, iterations int) *keys {
	mk, err := crypto.DeriveKeyFromPassword([]byte(password), salt, crypto.KDFConfig{Type: crypto.KDFPBKDF2, Iterations: uint32(iterations)})
	if err != nil {
		panic(err)
	}
	return &keys{
		masterKey: mk,
		userKey:   mustKey(1),
		orgKey:    mustKey(70),
		itemKey:   mustKey(140),
		attKey:    mustKey(200),
		userPriv:  parsePriv(userPrivateKeyB64),
		peerPriv:  parsePriv(peerPrivateKeyB64),
	}
}

func (k *keys) protectedUserKey() string {
	stretched, err := crypto.StretchMasterKey(k.masterKey)
	if err != nil {
		panic(err)
	}
	raw := k.userKey.Bytes()
	enc, err := crypto.EncryptBytes(raw[:], stretched)
	if err != nil {
		panic(err)
	}
	return enc.String()
}

func (k *keys) encPrivateKey() string {
	der, err := x509.MarshalPKCS8PrivateKey(k.userPriv)
	if err != nil {
		panic(err)
	}
	enc, err := crypto.EncryptBytes(der, k.userKey)
	if err != nil {
		panic(err)
	}
	return enc.String()
}

func publicKeyB64(priv *rsa.PrivateKey) string {
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

func (k *keys) encOrgKey() string {
	raw := k.orgKey.Bytes()
	enc, err := crypto.EncryptRSA(raw[:], &k.userPriv.PublicKey, crypto.EncRsa2048OaepSha1B64)
	if err != nil {
		panic(err)
	}
	return enc.String()
}

func enc(plain string, key *crypto.SymmetricKey) any {
	s, err := crypto.EncryptString(plain, key)
	if err != nil {
		panic(err)
	}
	return s
}

func wrap(inner, outer *crypto.SymmetricKey) string {
	raw := inner.Bytes()
	e, err := crypto.EncryptBytes(raw[:], outer)
	if err != nil {
		panic(err)
	}
	return e.String()
}

type obj = map[string]any

// cipherBase is the part of a Vaultwarden 1.37 cipherDetails every item has.
func cipherBase(id string, typ int, name string, key *crypto.SymmetricKey) obj {
	return obj{
		"object":              "cipherDetails",
		"id":                  id,
		"type":                typ,
		"creationDate":        iso(created),
		"revisionDate":        iso(revised),
		"deletedDate":         nil,
		"archivedDate":        nil,
		"reprompt":            0,
		"organizationId":      nil,
		"key":                 nil,
		"attachments":         nil,
		"organizationUseTotp": true,
		"collectionIds":       []string{},
		"name":                enc(name, key),
		"notes":               nil,
		"fields":              nil,
		"passwordHistory":     nil,
		"login":               nil,
		"secureNote":          nil,
		"card":                nil,
		"identity":            nil,
		"sshKey":              nil,
		"bankAccount":         nil,
		"driversLicense":      nil,
		"passport":            nil,
		"folderId":            nil,
		"favorite":            false,
		"edit":                true,
		"viewPassword":        true,
		"permissions":         obj{"delete": true, "restore": true},
	}
}

func uri(u string, match any, key *crypto.SymmetricKey) obj {
	sum := sha256.Sum256([]byte(u))
	return obj{"uri": enc(u, key), "match": match, "uriChecksum": enc(base64.StdEncoding.EncodeToString(sum[:]), key)}
}

func login(key *crypto.SymmetricKey, username, password, totp string, uris ...obj) obj {
	l := obj{"username": nil, "password": nil, "totp": nil, "uris": uris, "passwordRevisionDate": nil, "autofillOnPageLoad": nil, "fido2Credentials": nil}
	if username != "" {
		l["username"] = enc(username, key)
	}
	if password != "" {
		l["password"] = enc(password, key)
	}
	if totp != "" {
		l["totp"] = enc(totp, key)
	}
	if len(uris) > 0 {
		l["uri"] = uris[0]["uri"]
	} else {
		l["uri"] = nil
	}
	return l
}

// AttachmentData is the encrypted attachment payload the server stores.
func (k *keys) attachmentData() []byte {
	data, err := crypto.EncryptBuffer([]byte(AttachmentBody), k.attKey)
	if err != nil {
		panic(err)
	}
	return data
}

// seedCiphers is the fixture vault the server starts with.
func (s *Server) seedCiphers() []obj {
	k := s.keys
	uk := k.userKey

	gh := cipherBase(ItemGitHub, 1, "GitHub", k.itemKey)
	gh["key"] = wrap(k.itemKey, uk)
	gh["folderId"] = FolderWork
	gh["favorite"] = true
	gh["notes"] = enc("Personal account", k.itemKey)
	gh["login"] = login(k.itemKey, "alice", "gh-secret", TOTPSecret,
		uri("https://github.com/login", nil, k.itemKey),
		uri("https://gist.github.com", 1, k.itemKey))
	gh["login"].(obj)["passwordRevisionDate"] = iso(pwUsed)
	gh["fields"] = []obj{
		{"name": enc("recovery email", k.itemKey), "value": enc("alice@recovery.example", k.itemKey), "type": 0, "linkedId": nil},
		{"name": enc("pin", k.itemKey), "value": enc("4321", k.itemKey), "type": 1, "linkedId": nil},
		{"name": enc("2fa", k.itemKey), "value": enc("true", k.itemKey), "type": 2, "linkedId": nil},
		{"name": enc("user", k.itemKey), "value": nil, "type": 3, "linkedId": 100},
	}
	gh["passwordHistory"] = []obj{{"password": enc("old-gh-secret", k.itemKey), "lastUsedDate": iso(pwUsed)}}
	gh["attachments"] = []obj{{
		"id":       AttachmentID,
		"url":      s.URL() + "/attachments/" + ItemGitHub + "/" + AttachmentID,
		"fileName": enc(AttachmentName, k.itemKey),
		"key":      wrap(k.attKey, k.itemKey),
		"size":     fmt.Sprint(len(s.attachment)),
		"sizeName": fmt.Sprintf("%d Bytes", len(s.attachment)),
		"object":   "attachment",
	}}

	ghe := cipherBase(ItemGitHubEnt, 1, "GitHub Enterprise", uk)
	ghe["login"] = login(uk, "alice-corp", "ghe-secret", "", uri("https://github.example.com", nil, uk))

	note := cipherBase(ItemNote, 2, "Recovery codes", uk)
	note["notes"] = enc("code-1\ncode-2", uk)
	note["secureNote"] = obj{"type": 0}
	note["folderId"] = FolderHome

	card := cipherBase(ItemCard, 3, "Visa", uk)
	card["card"] = obj{
		"cardholderName": enc("Alice Example", uk), "brand": enc("Visa", uk), "number": enc("4111111111111111", uk),
		"expMonth": enc("12", uk), "expYear": enc("2030", uk), "code": enc("123", uk),
	}

	ident := cipherBase(ItemIdentity, 4, "Passport identity", uk)
	ident["identity"] = obj{
		"title": enc("Ms", uk), "firstName": enc("Alice", uk), "middleName": nil, "lastName": enc("Example", uk),
		"address1": enc("1 Main St", uk), "address2": nil, "address3": nil, "city": enc("Springfield", uk),
		"state": nil, "postalCode": enc("12345", uk), "country": enc("US", uk), "company": nil,
		"email": enc("alice@example.com", uk), "phone": nil, "ssn": nil, "username": enc("alice", uk),
		"passportNumber": nil, "licenseNumber": nil,
	}

	ssh := cipherBase(ItemSSH, 5, "Deploy key", uk)
	ssh["sshKey"] = obj{
		"privateKey":     enc("-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n", uk),
		"publicKey":      enc("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample deploy", uk),
		"keyFingerprint": enc("SHA256:examplefingerprint", uk),
	}

	shared := cipherBase(ItemOrgShared, 1, "Shared DB", k.orgKey)
	shared["organizationId"] = OrgID
	shared["collectionIds"] = []string{CollectionEng}
	shared["login"] = login(k.orgKey, "dbadmin", "db-secret", TOTPSecret, uri("db.example.com:5432", 1, k.orgKey))

	hidden := cipherBase(ItemOrgHidden, 1, "Hidden Prod", k.orgKey)
	hidden["organizationId"] = OrgID
	hidden["collectionIds"] = []string{CollectionSec}
	hidden["viewPassword"] = false
	hidden["edit"] = false
	hidden["login"] = login(k.orgKey, "root", "prod-secret", TOTPSecret, uri("https://prod.example.com", nil, k.orgKey))
	hidden["fields"] = []obj{
		{"name": enc("api token", k.orgKey), "value": enc("tok-hidden", k.orgKey), "type": 1, "linkedId": nil},
		{"name": enc("region", k.orgKey), "value": enc("eu-west", k.orgKey), "type": 0, "linkedId": nil},
	}
	hidden["passwordHistory"] = []obj{{"password": enc("prod-old", k.orgKey), "lastUsedDate": iso(pwUsed)}}

	trashed := cipherBase(ItemTrashed, 1, "Old GitHub", uk)
	trashed["deletedDate"] = iso(deleted)
	trashed["login"] = login(uk, "old", "old-secret", "", uri("https://github.com", nil, uk))

	arch := cipherBase(ItemArchived, 1, "Archived GitHub", uk)
	arch["archivedDate"] = iso(archived)
	arch["login"] = login(uk, "archived", "arch-secret", "", uri("https://github.com", nil, uk))

	modes := cipherBase(ItemMatchModes, 1, "Match modes", uk)
	modes["login"] = login(uk, "modes", "modes-secret", "",
		uri("https://exact.example.org/path?q=1", 3, uk),
		uri("https://starts.example.org/app", 2, uk),
		uri(`^https://re\.example\.org/[0-9]+$`, 4, uk),
		uri("https://never.example.org", 5, uk),
		uri("https://host.example.org:8443", 1, uk))

	empty := cipherBase(ItemEmpty, 1, "Empty login", uk)
	empty["login"] = login(uk, "", "", "")

	return []obj{gh, ghe, note, card, ident, ssh, shared, hidden, trashed, arch, modes, empty}
}

func (s *Server) seedFolders() []obj {
	return []obj{
		{"id": FolderWork, "name": enc("Work", s.keys.userKey), "revisionDate": iso(revised), "object": "folder"},
		{"id": FolderHome, "name": enc("Home", s.keys.userKey), "revisionDate": iso(revised), "object": "folder"},
	}
}

// syncBody is the /api/sync answer, encoded while the caller holds s.mu
// so no write changes the vault underneath.
func (s *Server) syncBody() []byte {
	k := s.keys
	cfg := s.cfg
	org := obj{
		"id": OrgID, "name": OrgName, "key": k.encOrgKey(), "status": 2, "type": 2, "enabled": true,
		"useTotp": true, "usePolicies": true, "usersGetPremium": true, "selfHost": true,
		"permissions": obj{"editAnyCollection": false, "deleteAnyCollection": false, "createNewCollections": false},
		"object":      "profileOrganization", "userId": UserID,
	}
	profile := obj{
		"id": UserID, "name": "Alice", "email": s.email, "emailVerified": true,
		"premium": cfg.Premium, "premiumFromOrganization": false, "culture": "en-US", "twoFactorEnabled": len(cfg.TwoFactor) > 0,
		"key": k.protectedUserKey(), "privateKey": k.encPrivateKey(), "securityStamp": "stamp",
		"organizations": []obj{org}, "providers": []obj{}, "providerOrganizations": []obj{},
		"forcePasswordReset": false, "avatarColor": nil, "usesKeyConnector": false, "creationDate": iso(created),
		"object": "profile",
		"accountKeys": obj{
			"publicKeyEncryptionKeyPair": obj{"wrappedPrivateKey": k.encPrivateKey(), "publicKey": publicKeyB64(k.userPriv), "Object": "publicKeyEncryptionKeyPair"},
			"Object":                     "privateKeys",
		},
	}
	collections := []obj{
		{"id": CollectionEng, "organizationId": OrgID, "name": enc("Engineering", k.orgKey), "externalId": nil, "object": "collectionDetails", "readOnly": false, "hidePasswords": cfg.EngHidesPasswords, "manage": false},
		{"id": CollectionSec, "organizationId": OrgID, "name": enc("Secrets", k.orgKey), "externalId": nil, "object": "collectionDetails", "readOnly": true, "hidePasswords": true, "manage": false},
	}
	ciphers := s.items
	if cfg.OmitPermissions {
		ciphers = nil
		for _, it := range s.items {
			cp := obj{}
			for k, v := range it {
				if k != "edit" && k != "viewPassword" {
					cp[k] = v
				}
			}
			ciphers = append(ciphers, cp)
		}
	}
	var userKeyID any
	if s.userKeyID != "" {
		userKeyID = s.userKeyID
	}
	policies := []obj{}
	for _, p := range cfg.Policies {
		policies = append(policies, p)
	}
	body, err := json.Marshal(obj{
		"profile":     profile,
		"folders":     s.folders,
		"collections": collections,
		"policies":    policies,
		"policiesNew": policies,
		"ciphers":     ciphers,
		"domains":     nil,
		"sends":       []obj{},
		"userDecryption": obj{
			"masterPasswordUnlock": obj{
				"kdf":                       obj{"kdfType": 0, "iterations": s.kdfIterations, "memory": nil, "parallelism": nil},
				"masterKeyEncryptedUserKey": k.protectedUserKey(),
				"masterKeyWrappedUserKey":   k.protectedUserKey(),
				"salt":                      s.email,
			},
			"userKeyId": userKeyID,
		},
		"object": "sync",
	})
	if err != nil {
		panic(err)
	}
	return body
}
