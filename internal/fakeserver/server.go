// Package fakeserver is a Bitwarden-compatible test server shaped after
// Vaultwarden 1.37.5. It serves one fixture account to gv tests and, for
// contract fixtures, to the official bw client.
package fakeserver

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/txchen/govault/internal/vaultcore/crypto"
)

// Request is one request the server received.
type Request struct {
	Method string
	Path   string
	Query  string
	Auth   string
	Form   map[string]string
}

// Config is what tests may change while the server runs.
type Config struct {
	// Premium sends premium: true in the profile.
	Premium bool
	// TwoFactor lists the providers (by number) a password login must pass,
	// with the code each accepts.
	TwoFactor map[int]string
	// TokenLifetime is the expires_in the server answers.
	TokenLifetime time.Duration
	// Policies is the sync policies list.
	Policies []map[string]any
	// OnSync runs inside each /api/sync request before it is answered.
	OnSync func()
	// Subject, when set, is the user ID new access tokens claim.
	Subject string
	// OmitPermissions leaves edit and viewPassword out of every item.
	OmitPermissions bool
	// OnWrite runs inside each request that changes the vault, before it
	// is applied.
	OnWrite func()
	// EngHidesPasswords makes the Engineering collection hide passwords.
	EngHidesPasswords bool
	// AzureUploads answers attachment uploads as Bitwarden's cloud does:
	// fileUploadType 1 with a signed blob storage URL, expired already
	// when AzureURLExpired is set.
	AzureUploads    bool
	AzureURLExpired bool
	// BlobFails makes blob storage refuse every upload, and
	// AttachmentDeleteFails the server refuse attachment deletes.
	BlobFails             bool
	AttachmentDeleteFails bool
	// DirectUploadFails refuses direct attachment uploads with a message.
	DirectUploadFails bool
	// MovesBeforeFailure, when set, fails every move request after that
	// many.
	MovesBeforeFailure int
	// ClaimPadding adds a claim of this many bytes to access tokens, as
	// claim-heavy servers issue them.
	ClaimPadding int
	// NewDeviceOTP, when set, turns on Bitwarden's new device verification
	// (which Vaultwarden does not have): a password login without two-step
	// login from a device the server does not know must send this code in
	// newDeviceOtp (DeviceValidator.cs in bitwarden/server).
	NewDeviceOTP string
	// SSOEnabled turns on Vaultwarden's OIDC SSO endpoints and the
	// authorization_code token grant.
	SSOEnabled bool
	// SSOOnly makes password logins fail with Vaultwarden's 400 "SSO
	// sign-in is required" when SSOEnabled is also set.
	SSOOnly bool
	// SSODecryptionMode shapes UserDecryptionOptions on SSO logins: ""
	// (master password), "no_password", "key_connector", "trusted_device",
	// or "force_reset".
	SSODecryptionMode string
	// BitwardenSSOEmail2FA makes SSO email 2FA follow Bitwarden Server
	// (top-level Email + SsoEmail2faSessionToken) instead of Vaultwarden
	// (tokenless device-only send-email-login).
	BitwardenSSOEmail2FA bool
	// StrictRefresh enforces issuing client_id matching and single-use
	// refresh token rotation on grant_type=refresh_token.
	StrictRefresh bool
}

type ssoCodeRecord struct {
	challenge   string
	redirectURI string
	clientID    string
	email       string
}

// Server is a running fake server.
type Server struct {
	prefix string
	cfg    Config

	mu            sync.Mutex
	http          *httptest.Server
	email         string
	kdfSalt       string
	keys          *keys
	attachment    []byte
	requests      []Request
	tokens        map[string]string // access token -> grant type
	refresh       map[string]string // refresh token -> issuing client_id
	ssoCodes      map[string]ssoCodeRecord
	rejectNext    bool
	tokenSeq      int
	emailSends    int
	deviceSends   int
	knownDevices  map[string]bool
	revision      time.Time
	userKeyID     string
	items         []obj
	blobPuts      []http.Header
	moves         int
	renewals      int
	folders       []obj
	blobs         map[string][]byte
	idSeq         int
	kdfIterations int
}

// Option configures a server before it starts.
type Option func(*Server)

// WithKDFIterations sets the account's PBKDF2 iterations. Official clients
// migrate accounts below 600000, which this server does not implement.
func WithKDFIterations(n int) Option { return func(s *Server) { s.kdfIterations = n } }

// WithPrefix mounts the server under a path, like a self-hosted server
// whose base URL has one.
func WithPrefix(prefix string) Option { return func(s *Server) { s.prefix = prefix } }

// WithCustomSalt configures a verbatim KDF salt distinct from the account's
// normalized email (as Bitwarden accounts with an opaque or mixed-case salt
// report in MasterPasswordUnlock.Salt).
func WithCustomSalt(salt string) Option { return func(s *Server) { s.kdfSalt = salt } }

// New starts a fake server with the fixture vault, over plain HTTP.
func New(opts ...Option) *Server { return start(false, opts) }

// NewTLS starts it over HTTPS with a self-signed certificate, which
// CertPEM returns.
func NewTLS(opts ...Option) *Server { return start(true, opts) }

func start(useTLS bool, opts []Option) *Server {
	s := &Server{
		cfg:           Config{Premium: true, TokenLifetime: time.Hour},
		email:         Email,
		kdfIterations: DefaultKDFIterations,
		tokens:        map[string]string{},
		refresh:       map[string]string{},
		ssoCodes:      map[string]ssoCodeRecord{},
		revision:      revised,
	}
	for _, o := range opts {
		o(s)
	}
	salt := s.kdfSalt
	if salt == "" {
		salt = crypto.NormalizeEmail(s.email)
	}
	s.keys = newKeys(salt, Password, s.kdfIterations)
	s.attachment = s.keys.attachmentData()
	s.blobs = map[string][]byte{AttachmentID: s.attachment}
	// The vault is seeded under the lock once the address is known, before
	// any client can have it.
	s.mu.Lock()
	defer s.mu.Unlock()
	if useTLS {
		s.http = httptest.NewTLSServer(http.HandlerFunc(s.serve))
	} else {
		s.http = httptest.NewServer(http.HandlerFunc(s.serve))
	}
	s.items = s.seedCiphers()
	s.folders = s.seedFolders()
	return s
}

// CertPEM is the server certificate of a NewTLS server.
func (s *Server) CertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.http.Certificate().Raw})
}

// Client is an HTTP client that trusts the server.
func (s *Server) Client() *http.Client { return s.http.Client() }

// Close stops the server.
func (s *Server) Close() { s.http.Close() }

// URL is the base URL a client configures, including the prefix.
func (s *Server) URL() string { return s.http.URL + s.prefix }

// Configure changes the configuration under the server's lock.
func (s *Server) Configure(fn func(*Config)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(&s.cfg)
}

func (s *Server) config() Config {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cfg
}

// Requests returns the requests received so far.
func (s *Server) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Request(nil), s.requests...)
}

// Count returns how many received requests satisfy match.
func (s *Server) Count(match func(Request) bool) int {
	n := 0
	for _, r := range s.Requests() {
		if match(r) {
			n++
		}
	}
	return n
}

// RejectNextToken makes the next authenticated request fail with 401 and
// forget every access token issued so far, as an expired token would.
func (s *Server) RejectNextToken() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rejectNext = true
}

// NewDeviceCodesSent counts new device verification codes issued, by a
// login challenge or a resend.
func (s *Server) NewDeviceCodesSent() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deviceSends
}

// EmailCodesSent counts email two-factor codes requested.
func (s *Server) EmailCodesSent() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.emailSends
}

// UserPublicKey is the fixture account's public key (SPKI, base64).
func UserPublicKey() string { return publicKeyB64(parsePriv(userPrivateKeyB64)) }

// PeerPublicKey is the public key of PeerUserID.
func PeerPublicKey() string { return publicKeyB64(parsePriv(peerPrivateKeyB64)) }

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if s.prefix != "" {
		if !strings.HasPrefix(path, s.prefix+"/") {
			http.NotFound(w, r)
			return
		}
		path = strings.TrimPrefix(path, s.prefix)
	}
	_ = r.ParseForm()
	form := map[string]string{}
	for k, v := range r.PostForm {
		form[k] = strings.Join(v, ",")
	}
	s.mu.Lock()
	s.requests = append(s.requests, Request{Method: r.Method, Path: path, Query: r.URL.RawQuery, Auth: r.Header.Get("Authorization"), Form: form})
	s.mu.Unlock()

	switch {
	case r.Method == http.MethodPost && (path == "/identity/accounts/prelogin" || path == "/identity/accounts/prelogin/password"):
		writeJSON(w, 200, obj{
			"kdf": 0, "kdfIterations": s.kdfIterations, "kdfMemory": nil, "kdfParallelism": nil,
			"kdfSettings": obj{"iterations": s.kdfIterations, "kdfType": 0, "memory": nil, "parallelism": nil},
			"salt":        nil,
		})
	case r.Method == http.MethodPost && path == "/identity/connect/token":
		s.token(w, r)
	case r.Method == http.MethodGet && path == "/identity/sso/prevalidate":
		if !s.config().SSOEnabled {
			writeJSON(w, 400, obj{"error": "invalid_request", "ErrorModel": obj{"Message": "SSO sign-in is not available", "Object": "error"}})
			return
		}
		writeJSON(w, 200, obj{"token": "fake-sso-prevalidate-token"})
	case r.Method == http.MethodGet && path == "/identity/connect/authorize":
		s.authorize(w, r)
	case r.Method == http.MethodPost && path == "/api/two-factor/send-email-login":
		s.sendEmailTwoFactor(w, r)
	case r.Method == http.MethodPost && path == "/api/accounts/resend-new-device-otp":
		// Bitwarden answers success whatever the secret, so a resend
		// cannot test a password.
		if s.config().NewDeviceOTP != "" && r.Header.Get("Device-Identifier") != "" {
			s.mu.Lock()
			s.deviceSends++
			s.mu.Unlock()
		}
		w.WriteHeader(200)
	case r.Method == http.MethodGet && path == "/api/config":
		writeJSON(w, 200, obj{"version": "2026.1.0", "gitHash": "fake", "server": obj{"name": "Vaultwarden", "url": "https://github.com/dani-garcia/vaultwarden"}, "environment": obj{"vault": s.URL(), "api": s.URL() + "/api", "identity": s.URL() + "/identity", "notifications": s.URL() + "/notifications", "sso": ""}, "featureStates": obj{}, "object": "config"})
	case r.Method == http.MethodGet && path == "/api/devices/knowndevice":
		writeJSON(w, 200, true)
	case strings.HasPrefix(path, "/attachments/"):
		s.attachmentData(w, path)
	case strings.HasPrefix(path, "/blob/"):
		s.azureBlob(w, r, path)
	case strings.HasPrefix(path, "/api/"):
		if !s.authorized(w, r) {
			return
		}
		s.api(w, r, path)
	default:
		writeJSON(w, 404, obj{"message": "Not found"})
	}
}

func (s *Server) authorized(w http.ResponseWriter, r *http.Request) bool {
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rejectNext {
		s.rejectNext = false
		s.tokens = map[string]string{}
	}
	if _, ok := s.tokens[tok]; !ok {
		w.WriteHeader(401)
		return false
	}
	return true
}

func (s *Server) api(w http.ResponseWriter, r *http.Request, path string) {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	switch {
	case r.Method == http.MethodGet && path == "/api/sync":
		s.mu.Lock()
		hook := s.cfg.OnSync
		body := s.syncBody()
		s.mu.Unlock()
		if hook != nil {
			hook()
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	case r.Method == http.MethodPost && path == "/api/accounts/key-management/user-key-id":
		var body struct {
			UserKeyID string `json:"userKeyId"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		s.mu.Lock()
		s.userKeyID = body.UserKeyID
		s.mu.Unlock()
		w.WriteHeader(200)
	case r.Method == http.MethodGet && path == "/api/accounts/revision-date":
		s.mu.Lock()
		rev := s.revision
		s.mu.Unlock()
		writeJSON(w, 200, rev.UnixMilli())
	case r.Method == http.MethodGet && len(parts) == 4 && parts[1] == "users" && parts[3] == "public-key":
		switch parts[2] {
		case UserID:
			writeJSON(w, 200, obj{"userId": UserID, "publicKey": UserPublicKey(), "object": "userKey"})
		case PeerUserID:
			writeJSON(w, 200, obj{"userId": PeerUserID, "publicKey": PeerPublicKey(), "object": "userKey"})
		default:
			writeJSON(w, 404, obj{"message": "User doesn't exist"})
		}
	case r.Method == http.MethodGet && path == "/api/collections":
		writeJSON(w, 200, obj{"data": s.orgCollections(), "object": "list", "continuationToken": nil})
	case r.Method == http.MethodGet && len(parts) == 4 && parts[1] == "organizations" && parts[3] == "collections":
		if parts[2] != OrgID {
			writeJSON(w, 404, obj{"message": "Organization not found"})
			return
		}
		writeJSON(w, 200, obj{"data": s.orgCollections(), "object": "list", "continuationToken": nil})
	case r.Method == http.MethodGet && len(parts) == 5 && parts[1] == "ciphers" && parts[3] == "attachment":
		s.attachmentMeta(w, parts[2], parts[4])
	default:
		if !s.write(w, r, parts) {
			writeJSON(w, 404, obj{"message": "Not found"})
		}
	}
}

func (s *Server) orgCollections() []obj {
	return []obj{
		{"id": CollectionEng, "organizationId": OrgID, "name": enc("Engineering", s.keys.orgKey), "externalId": nil, "object": "collectionDetails", "readOnly": false, "hidePasswords": s.config().EngHidesPasswords, "manage": false},
		{"id": CollectionSec, "organizationId": OrgID, "name": enc("Secrets", s.keys.orgKey), "externalId": nil, "object": "collectionDetails", "readOnly": true, "hidePasswords": true, "manage": false},
	}
}

func (s *Server) attachmentData(w http.ResponseWriter, path string) {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	s.mu.Lock()
	var data []byte
	ok := false
	if len(parts) == 3 {
		data, ok = s.blobs[parts[2]]
	}
	s.mu.Unlock()
	if !ok {
		w.WriteHeader(404)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(data)
}

// IssueSSOCode registers a PKCE code challenge as if the browser completed
// /identity/connect/authorize and returns the authorization code.
func (s *Server) IssueSSOCode(challenge, redirectURI, clientID string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokenSeq++
	code := "sso-code-" + strconv.Itoa(s.tokenSeq)
	s.ssoCodes[code] = ssoCodeRecord{
		challenge:   challenge,
		redirectURI: redirectURI,
		clientID:    clientID,
		email:       s.email,
	}
	return code
}

func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	if !s.config().SSOEnabled {
		writeJSON(w, 400, obj{"error": "invalid_request", "ErrorModel": obj{"Message": "SSO sign-in is not available", "Object": "error"}})
		return
	}
	q := r.URL.Query()
	if q.Get("code_challenge_method") != "S256" {
		writeJSON(w, 400, obj{"error": "invalid_request", "ErrorModel": obj{"Message": "Unsupported code challenge method", "Object": "error"}})
		return
	}
	redirectURI := q.Get("redirect_uri")
	u, err := url.Parse(redirectURI)
	if err != nil || u.Scheme != "http" || u.Hostname() != "localhost" {
		writeJSON(w, 400, obj{"error": "invalid_request", "ErrorModel": obj{"Message": "Unsupported redirect uri", "Object": "error"}})
		return
	}
	code := s.IssueSSOCode(q.Get("code_challenge"), redirectURI, q.Get("client_id"))
	rq := u.Query()
	rq.Set("code", code)
	rq.Set("state", q.Get("state"))
	u.RawQuery = rq.Encode()
	http.Redirect(w, r, u.String(), http.StatusTemporaryRedirect)
}

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	f := r.PostForm
	switch f.Get("grant_type") {
	case "password":
		if cfg := s.config(); cfg.SSOEnabled && cfg.SSOOnly {
			writeJSON(w, 400, obj{"error": "invalid_grant", "error_description": "SSO sign-in is required", "ErrorModel": obj{"Message": "SSO sign-in is required", "Object": "error"}})
			return
		}
		if !strings.EqualFold(f.Get("username"), s.email) || f.Get("password") != crypto.HashMasterPasswordForServer(s.keys.masterKey, []byte(Password)) {
			writeJSON(w, 400, obj{"error": "invalid_grant", "error_description": "invalid_username_or_password", "ErrorModel": obj{"Message": "Username or password is incorrect. Try again", "Object": "error"}})
			return
		}
		if tf := s.config().TwoFactor; len(tf) > 0 {
			provider, _ := strconv.Atoi(f.Get("twoFactorProvider"))
			code, ok := tf[provider]
			if f.Get("twoFactorToken") == "" || !ok || code != f.Get("twoFactorToken") {
				s.twoFactorChallenge(w, f.Get("twoFactorToken") != "", false)
				return
			}
		} else if !s.verifyDevice(w, f.Get("deviceIdentifier"), f.Get("newDeviceOtp")) {
			return
		}
		writeJSON(w, 200, s.issue("password", f.Get("client_id"), true))
	case "authorization_code":
		cfg := s.config()
		if !cfg.SSOEnabled {
			writeJSON(w, 400, obj{"error": "invalid_grant", "ErrorModel": obj{"Message": "SSO sign-in is not available", "Object": "error"}})
			return
		}
		code := f.Get("code")
		verifier := f.Get("code_verifier")
		redirectURI := f.Get("redirect_uri")
		s.mu.Lock()
		rec, ok := s.ssoCodes[code]
		s.mu.Unlock()
		if !ok || verifier == "" {
			writeJSON(w, 400, obj{"error": "invalid_grant", "ErrorModel": obj{"Message": "Invalid code cannot retrieve sso auth", "Object": "error"}})
			return
		}
		sum := sha256.Sum256([]byte(verifier))
		if base64.RawURLEncoding.EncodeToString(sum[:]) != rec.challenge {
			writeJSON(w, 400, obj{"error": "invalid_grant", "ErrorModel": obj{"Message": "PKCE code verifier mismatch", "Object": "error"}})
			return
		}
		if rec.redirectURI != "" && redirectURI != "" && redirectURI != rec.redirectURI {
			writeJSON(w, 400, obj{"error": "invalid_grant", "ErrorModel": obj{"Message": "Redirect URI mismatch", "Object": "error"}})
			return
		}
		// Like Vaultwarden src/sso.rs, the code remains redeemable for a 2FA
		// retry and is deleted only after 2FA succeeds.
		if tf := cfg.TwoFactor; len(tf) > 0 {
			provider, _ := strconv.Atoi(f.Get("twoFactorProvider"))
			want, has := tf[provider]
			if f.Get("twoFactorToken") == "" || !has || want != f.Get("twoFactorToken") {
				s.twoFactorChallenge(w, f.Get("twoFactorToken") != "", true)
				return
			}
		}
		s.mu.Lock()
		delete(s.ssoCodes, code)
		s.mu.Unlock()
		resp := s.issue("authorization_code", f.Get("client_id"), true)
		switch cfg.SSODecryptionMode {
		case "no_password":
			delete(resp, "Key")
			resp["UserDecryptionOptions"] = obj{"HasMasterPassword": false, "MasterPasswordUnlock": nil, "Object": "userDecryptionOptions"}
		case "key_connector":
			delete(resp, "Key")
			resp["UserDecryptionOptions"] = obj{
				"HasMasterPassword":  false,
				"KeyConnectorOption": obj{"KeyConnectorUrl": "https://kc.example.com"},
				"Object":             "userDecryptionOptions",
			}
		case "trusted_device":
			delete(resp, "Key")
			resp["UserDecryptionOptions"] = obj{
				"HasMasterPassword":   false,
				"TrustedDeviceOption": obj{"HasAdminApproval": true},
				"Object":              "userDecryptionOptions",
			}
		case "force_reset":
			resp["ForcePasswordReset"] = true
		}
		writeJSON(w, 200, resp)
	case "refresh_token":
		rt := f.Get("refresh_token")
		reqClient := f.Get("client_id")
		cfg := s.config()
		s.mu.Lock()
		issuedClient, ok := s.refresh[rt]
		if ok && cfg.StrictRefresh {
			if issuedClient != "" && reqClient != issuedClient {
				ok = false
			} else {
				delete(s.refresh, rt)
			}
		}
		s.mu.Unlock()
		if !ok {
			writeJSON(w, 400, obj{"error": "invalid_grant", "error_description": "Invalid refresh token"})
			return
		}
		writeJSON(w, 200, s.issue("refresh_token", reqClient, true))
	case "client_credentials":
		if f.Get("scope") != "api" || f.Get("client_id") != ClientID || f.Get("client_secret") != ClientSecret {
			writeJSON(w, 400, obj{"error": "invalid_client", "error_description": "invalid_client"})
			return
		}
		if f.Get("deviceIdentifier") == "" || f.Get("deviceName") == "" || f.Get("deviceType") == "" {
			writeJSON(w, 400, obj{"error": "invalid_request", "error_description": "device_identifier cannot be blank"})
			return
		}
		writeJSON(w, 200, s.issue("client_credentials", f.Get("client_id"), false))
	default:
		writeJSON(w, 400, obj{"error": "unsupported_grant_type"})
	}
}

// verifyDevice applies new device verification to a password login from
// an account without two-step login, answering as Bitwarden's
// DeviceValidator does when it refuses.
func (s *Server) verifyDevice(w http.ResponseWriter, device, otp string) bool {
	want := s.config().NewDeviceOTP
	s.mu.Lock()
	defer s.mu.Unlock()
	if want == "" || (otp == "" && s.knownDevices[device]) {
		return true
	}
	switch {
	case otp == "":
		s.deviceSends++
		writeJSON(w, 400, obj{"error": "device_error", "error_description": "New device verification required", "ErrorModel": obj{"Message": "new device verification required", "Object": "error"}})
		return false
	case otp != want:
		writeJSON(w, 400, obj{"error": "device_error", "error_description": "Invalid New Device OTP", "ErrorModel": obj{"Message": "invalid new device otp", "Object": "error"}})
		return false
	}
	if s.knownDevices == nil {
		s.knownDevices = map[string]bool{}
	}
	s.knownDevices[device] = true
	return true
}

// GrantCount counts token grants of grantType issued so far.
func (s *Server) GrantCount(grantType string) int {
	return s.Count(func(r Request) bool { return r.Path == "/identity/connect/token" && r.Form["grant_type"] == grantType })
}

func (s *Server) sendEmailTwoFactor(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email                   string `json:"email"`
		MasterPasswordHash      string `json:"masterPasswordHash"`
		DeviceIdentifier        string `json:"deviceIdentifier"`
		SSOEmail2FASessionToken string `json:"ssoEmail2faSessionToken"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.MasterPasswordHash == "" {
		cfg := s.config()
		if cfg.BitwardenSSOEmail2FA {
			if !strings.EqualFold(body.Email, s.email) || body.SSOEmail2FASessionToken != "fake-sso-email-token" {
				writeJSON(w, 400, obj{"ErrorModel": obj{"Message": "Invalid SSO email 2FA request", "Object": "error"}})
				return
			}
		} else {
			// Vaultwarden 1.37.4+ rejects an email without a password hash and
			// accepts a device-only SSO send-email-login request.
			if body.Email != "" {
				writeJSON(w, 400, obj{"ErrorModel": obj{"Message": "No password hash has been submitted.", "Object": "error"}})
				return
			}
			if body.DeviceIdentifier == "" && r.Header.Get("Device-Identifier") == "" {
				writeJSON(w, 400, obj{"ErrorModel": obj{"Message": "Missing device identifier", "Object": "error"}})
				return
			}
		}
	}
	s.mu.Lock()
	s.emailSends++
	s.mu.Unlock()
	w.WriteHeader(200)
}

func (s *Server) twoFactorChallenge(w http.ResponseWriter, wrongCode, sso bool) {
	body := obj{
		"error":               "invalid_grant",
		"error_description":   "Two factor required.",
		"TwoFactorProviders":  s.providerList(),
		"TwoFactorProviders2": s.providerData(),
	}
	if wrongCode {
		body["ErrorModel"] = obj{"Message": "Invalid TOTP code", "Object": "error"}
	} else {
		body["MasterPasswordPolicy"] = obj{"Object": "masterPasswordPolicy"}
	}
	if sso && s.config().BitwardenSSOEmail2FA {
		if _, hasEmail := s.config().TwoFactor[1]; hasEmail {
			body["Email"] = s.email
			body["SsoEmail2faSessionToken"] = "fake-sso-email-token"
		}
	}
	writeJSON(w, 400, body)
}

func (s *Server) providerList() []string {
	var out []string
	tf := s.config().TwoFactor
	for p := range 8 {
		if _, ok := tf[p]; ok {
			out = append(out, strconv.Itoa(p))
		}
	}
	return out
}

func (s *Server) providerData() obj {
	out := obj{}
	for p := range s.config().TwoFactor {
		switch p {
		case 1:
			out["1"] = obj{"Email": "a***e@example.com"}
		case 3:
			out["3"] = obj{"Nfc": true}
		default:
			out[strconv.Itoa(p)] = nil
		}
	}
	return out
}

func (s *Server) issue(grant, reqClientID string, withRefresh bool) obj {
	s.mu.Lock()
	s.tokenSeq++
	seq := s.tokenSeq
	cfg := s.cfg
	s.mu.Unlock()
	lifetime := cfg.TokenLifetime

	clientID := reqClientID
	if clientID == "" {
		clientID = "cli"
	}
	if grant == "client_credentials" {
		clientID = ClientID
	}
	sub := UserID
	if cfg.Subject != "" {
		sub = cfg.Subject
	}
	now := time.Now()
	claims := obj{
		"nbf": now.Unix(), "exp": now.Add(lifetime).Unix(), "iss": s.URL() + "|login",
		"sub": sub, "premium": cfg.Premium, "name": "Alice", "email": s.email, "email_verified": true,
		"sstamp": "stamp", "device": "dev", "devicetype": "MacOsCLI", "client_id": clientID, "scope": []string{"api", "offline_access"}, "amr": []string{"Application"},
	}
	if cfg.ClaimPadding > 0 {
		claims["padding"] = strings.Repeat("p", cfg.ClaimPadding)
	}
	payload, _ := json.Marshal(claims)
	access := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9." + base64.RawURLEncoding.EncodeToString(payload) + ".sig" + strconv.Itoa(seq)

	s.mu.Lock()
	s.tokens[access] = grant
	s.mu.Unlock()
	k := s.keys
	salt := s.kdfSalt
	if salt == "" {
		salt = s.email
	}
	resp := obj{
		"access_token": access, "expires_in": int(lifetime.Seconds()), "token_type": "Bearer",
		"Key": k.protectedUserKey(), "PrivateKey": k.encPrivateKey(),
		"Kdf": 0, "KdfIterations": s.kdfIterations, "KdfMemory": nil, "KdfParallelism": nil,
		"ForcePasswordReset": false, "ResetMasterPassword": false, "scope": "api offline_access", "unofficialServer": true,
		"AccountKeys": obj{
			"publicKeyEncryptionKeyPair": obj{"wrappedPrivateKey": k.encPrivateKey(), "publicKey": publicKeyB64(k.userPriv), "Object": "publicKeyEncryptionKeyPair"},
			"Object":                     "privateKeys",
		},
		"UserDecryptionOptions": obj{
			"HasMasterPassword": true,
			"MasterPasswordUnlock": obj{
				"Kdf":                       obj{"KdfType": 0, "Iterations": s.kdfIterations, "Memory": nil, "Parallelism": nil},
				"MasterKeyEncryptedUserKey": k.protectedUserKey(),
				"MasterKeyWrappedUserKey":   k.protectedUserKey(),
				"Salt":                      salt,
			},
			"Object": "userDecryptionOptions",
		},
	}
	if withRefresh {
		rt := "refresh-" + strconv.Itoa(seq)
		s.mu.Lock()
		s.refresh[rt] = clientID
		s.mu.Unlock()
		resp["refresh_token"] = rt
	} else {
		resp["scope"] = "api"
	}
	return resp
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
