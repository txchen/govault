package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/txchen/govault/internal/vaultcore/crypto"
)

const defaultUserAgent = "GoVault/0.1"

// ClientVersion is the Bitwarden client release whose protocol GoVault
// follows. Every API request sends it as Bitwarden-Client-Version, and
// servers gate features on it: Vaultwarden 1.33 and later send SSH key
// items only to 2024.12.0 and newer, and Vaultwarden after 1.37.5 refuses
// logins without the header and V2-encryption accounts below 2026.10.1
// (2026.10.2 for desktop device types).
//
// Bump it when GoVault supports what a newer Bitwarden release added, after
// checking which server gates the new version opens, since a server trusts
// it to understand everything that release does. The gv contract fixtures
// in internal/cli/testdata/bw are recorded from the same bw release.
const ClientVersion = "2026.11.0"

type ClientConfig struct {
	ServerURL string
	// APIURL and IdentityURL override the API and identity services, which
	// otherwise live at ServerURL/api and ServerURL/identity.
	APIURL      string
	IdentityURL string
	DeviceID    string
	DeviceName  string
	DeviceType  int
	// ClientID is the OAuth client the tokens are issued to; "desktop"
	// when empty.
	ClientID string
	// ClientName is sent as Bitwarden-Client-Name; "desktop" when empty.
	ClientName string
	HTTPClient *http.Client
}

type Client struct {
	baseURL     string
	apiURL      string
	identityURL string
	httpClient  *http.Client
	// apiHTTP sends every request to the server's API: login, two-factor,
	// token refresh and authenticated calls. It never follows a redirect
	// to another scheme, host or port, so credentials stay on the origin
	// the user signed in to.
	apiHTTP    *http.Client
	deviceID   string
	deviceName string
	deviceType int
	userAgent  string
	clientID   string
	headers    map[string]string
}

func NewClient(cfg ClientConfig) (*Client, error) {
	base := strings.TrimRight(strings.TrimSpace(cfg.ServerURL), "/")
	apiURL := strings.TrimRight(strings.TrimSpace(cfg.APIURL), "/")
	identityURL := strings.TrimRight(strings.TrimSpace(cfg.IdentityURL), "/")
	if base == "" && (apiURL == "" || identityURL == "") {
		return nil, errors.New("api: ServerURL is required")
	}
	if apiURL == "" {
		apiURL = base + "/api"
	}
	if identityURL == "" {
		identityURL = base + "/identity"
	}
	if base == "" {
		base = apiURL
	}
	for _, raw := range []string{base, apiURL, identityURL} {
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return nil, fmt.Errorf("api: invalid server URL %q", raw)
		}
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}

	apiHTTP := *httpClient
	inner := httpClient.CheckRedirect
	apiHTTP.CheckRedirect = func(next *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("api: too many redirects")
		}
		if !sameOrigin(next.URL, via[0].URL) {
			return fmt.Errorf("%w to %s://%s", ErrRedirectRefused, next.URL.Scheme, next.URL.Host)
		}
		if inner != nil {
			return inner(next, via)
		}
		return nil
	}

	clientID := cfg.ClientID
	if clientID == "" {
		clientID = "desktop"
	}
	clientName := cfg.ClientName
	if clientName == "" {
		clientName = "desktop"
	}
	headers := map[string]string{
		"Bitwarden-Client-Name":    clientName,
		"Bitwarden-Client-Version": ClientVersion,
		"Device-Type":              strconv.Itoa(cfg.DeviceType),
	}
	return &Client{
		baseURL:     base,
		apiURL:      apiURL,
		identityURL: identityURL,
		httpClient:  httpClient,
		apiHTTP:     &apiHTTP,
		deviceID:    cfg.DeviceID,
		deviceName:  cfg.DeviceName,
		deviceType:  cfg.DeviceType,
		userAgent:   defaultUserAgent,
		clientID:    clientID,
		headers:     headers,
	}, nil
}

// SetUserAgent replaces the User-Agent sent with every request.
func (c *Client) SetUserAgent(ua string) { c.userAgent = ua }

func (c *Client) Prelogin(ctx context.Context, email string) (crypto.KDFConfig, error) {
	var cfg crypto.KDFConfig
	body, err := json.Marshal(struct {
		Email string `json:"email"`
	}{Email: crypto.NormalizeEmail(email)})
	if err != nil {
		return cfg, err
	}

	raw, err := c.do(ctx, http.MethodPost, "/identity/accounts/prelogin", "application/json", "", nil, body)
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func (c *Client) LoginPassword(ctx context.Context, email, masterPasswordHash string, twoFactor *TwoFactorLogin) (*TokenResponse, error) {
	return c.LoginPasswordWith(ctx, email, masterPasswordHash, PasswordLoginOptions{TwoFactor: twoFactor})
}

// PasswordLoginOptions are the optional parts of a password grant.
type PasswordLoginOptions struct {
	TwoFactor *TwoFactorLogin
	// NewDeviceOTP answers a *NewDeviceVerificationRequiredError with the
	// code the server emailed.
	NewDeviceOTP string
}

// LoginPasswordWith signs in with the password grant. It returns a
// *TwoFactorRequiredError or *NewDeviceVerificationRequiredError when the
// server asks for a code.
func (c *Client) LoginPasswordWith(ctx context.Context, email, masterPasswordHash string, opts PasswordLoginOptions) (*TokenResponse, error) {
	twoFactor := opts.TwoFactor
	normEmail := crypto.NormalizeEmail(email)
	form := url.Values{
		"grant_type":       {"password"},
		"username":         {normEmail},
		"password":         {masterPasswordHash},
		"scope":            {"api offline_access"},
		"client_id":        {c.clientID},
		"deviceIdentifier": {c.deviceID},
		"deviceName":       {c.deviceName},
		"deviceType":       {strconv.Itoa(c.deviceType)},
	}
	if twoFactor != nil {
		form.Set("twoFactorProvider", strconv.Itoa(int(twoFactor.Provider)))
		form.Set("twoFactorToken", strings.Join(strings.Fields(twoFactor.Token), ""))
		if twoFactor.Remember {
			form.Set("twoFactorRemember", "1")
		} else {
			form.Set("twoFactorRemember", "0")
		}
	}
	if otp := strings.Join(strings.Fields(opts.NewDeviceOTP), ""); otp != "" {
		form.Set("newDeviceOtp", otp)
	}
	headers := map[string]string{
		"Auth-Email": base64.RawURLEncoding.EncodeToString([]byte(normEmail)),
	}

	raw, err := c.do(ctx, http.MethodPost, "/identity/connect/token", "application/x-www-form-urlencoded", "", headers, []byte(form.Encode()))
	if err != nil {
		return nil, err
	}
	var resp TokenResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// SSOLoginOptions are the parameters of an authorization_code grant after
// the browser SSO callback completes.
type SSOLoginOptions struct {
	Code         string
	CodeVerifier string
	RedirectURI  string
	TwoFactor    *TwoFactorLogin
}

// LoginSSO exchanges an SSO authorization code and PKCE verifier for an
// access token and refresh token. It returns a *TwoFactorRequiredError
// when the server asks for two-step verification.
func (c *Client) LoginSSO(ctx context.Context, opts SSOLoginOptions) (*TokenResponse, error) {
	form := url.Values{
		"grant_type":       {"authorization_code"},
		"code":             {opts.Code},
		"code_verifier":    {opts.CodeVerifier},
		"redirect_uri":     {opts.RedirectURI},
		"scope":            {"api offline_access"},
		"client_id":        {c.clientID},
		"deviceIdentifier": {c.deviceID},
		"deviceName":       {c.deviceName},
		"deviceType":       {strconv.Itoa(c.deviceType)},
	}
	if tf := opts.TwoFactor; tf != nil {
		form.Set("twoFactorProvider", strconv.Itoa(int(tf.Provider)))
		form.Set("twoFactorToken", strings.Join(strings.Fields(tf.Token), ""))
		if tf.Remember {
			form.Set("twoFactorRemember", "1")
		} else {
			form.Set("twoFactorRemember", "0")
		}
	}

	raw, err := c.do(ctx, http.MethodPost, "/identity/connect/token", "application/x-www-form-urlencoded", "", nil, []byte(form.Encode()))
	if err != nil {
		return nil, err
	}
	var resp TokenResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// LoginAPIKey exchanges a personal API key for an access token with the
// client credentials grant. The server issues no refresh token: the same
// exchange renews the token.
func (c *Client) LoginAPIKey(ctx context.Context, clientID, clientSecret string) (*TokenResponse, error) {
	form := url.Values{
		"grant_type":       {"client_credentials"},
		"scope":            {"api"},
		"client_id":        {clientID},
		"client_secret":    {clientSecret},
		"deviceIdentifier": {c.deviceID},
		"deviceName":       {c.deviceName},
		"deviceType":       {strconv.Itoa(c.deviceType)},
	}
	raw, err := c.do(ctx, http.MethodPost, "/identity/connect/token", "application/x-www-form-urlencoded", "", nil, []byte(form.Encode()))
	if err != nil {
		return nil, err
	}
	var resp TokenResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) RefreshToken(ctx context.Context, refreshToken string) (*TokenResponse, error) {
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {c.clientID},
	}

	raw, err := c.do(ctx, http.MethodPost, "/identity/connect/token", "application/x-www-form-urlencoded", "", nil, []byte(form.Encode()))
	if err != nil {
		return nil, err
	}
	var resp TokenResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) RevisionDate(ctx context.Context, accessToken string) (time.Time, error) {
	raw, err := c.do(ctx, http.MethodGet, "/api/accounts/revision-date", "", accessToken, nil, nil)
	if err != nil {
		return time.Time{}, err
	}
	trimmed := strings.TrimSpace(string(raw))
	if ms, err := strconv.ParseInt(trimmed, 10, 64); err == nil {
		return time.UnixMilli(ms).UTC(), nil
	}

	var iso string
	if err := json.Unmarshal(raw, &iso); err != nil {
		return time.Time{}, fmt.Errorf("api: invalid revision-date %q: %w", trimmed, err)
	}
	t, err := time.Parse(time.RFC3339Nano, iso)
	if err != nil {
		return time.Time{}, err
	}
	return t.UTC(), nil
}

func (c *Client) Sync(ctx context.Context, accessToken string) (*SyncResponse, []byte, error) {
	raw, err := c.do(ctx, http.MethodGet, "/api/sync?excludeDomains=true", "", accessToken, nil, nil)
	if err != nil {
		return nil, nil, err
	}
	var resp SyncResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, nil, err
	}
	return &resp, raw, nil
}

func (c *Client) CreateCipher(ctx context.Context, accessToken string, payload *CipherPayload) (*EncryptedCipher, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	raw, err := c.do(ctx, http.MethodPost, "/api/ciphers", "application/json", accessToken, nil, body)
	if err != nil {
		return nil, err
	}
	var cipher EncryptedCipher
	if err := json.Unmarshal(raw, &cipher); err != nil {
		return nil, err
	}
	return &cipher, nil
}

func (c *Client) UpdateCipher(ctx context.Context, accessToken, cipherID string, payload *CipherPayload) (*EncryptedCipher, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	raw, err := c.do(ctx, http.MethodPut, "/api/ciphers/"+url.PathEscape(cipherID), "application/json", accessToken, nil, body)
	if err != nil {
		return nil, err
	}
	var cipher EncryptedCipher
	if err := json.Unmarshal(raw, &cipher); err != nil {
		return nil, err
	}
	return &cipher, nil
}

func (c *Client) SoftDeleteCipher(ctx context.Context, accessToken, cipherID string) error {
	_, err := c.do(ctx, http.MethodPut, "/api/ciphers/"+url.PathEscape(cipherID)+"/delete", "", accessToken, nil, nil)
	return err
}

// MoveCiphers puts the items of ids in folderID, or in no folder for nil.
// Folders are per user, so this changes nothing else of them.
func (c *Client) MoveCiphers(ctx context.Context, accessToken string, ids []string, folderID *string) error {
	body, err := json.Marshal(struct {
		IDs      []string `json:"ids"`
		FolderID *string  `json:"folderId"`
	}{ids, folderID})
	if err != nil {
		return err
	}
	_, err = c.do(ctx, http.MethodPut, "/api/ciphers/move", "application/json", accessToken, nil, body)
	return err
}

func (c *Client) RestoreCipher(ctx context.Context, accessToken, cipherID string) (*EncryptedCipher, error) {
	raw, err := c.do(ctx, http.MethodPut, "/api/ciphers/"+url.PathEscape(cipherID)+"/restore", "", accessToken, nil, nil)
	if err != nil {
		return nil, err
	}
	var cipher EncryptedCipher
	if err := json.Unmarshal(raw, &cipher); err != nil {
		return nil, err
	}
	return &cipher, nil
}

// ArchiveCipher moves a cipher to the user's Archive
// (PUT /api/ciphers/{id}/archive, Vaultwarden 1.36 or later) and returns it.
func (c *Client) ArchiveCipher(ctx context.Context, accessToken, cipherID string) (*EncryptedCipher, error) {
	return c.putCipherAction(ctx, accessToken, cipherID, "archive")
}

// UnarchiveCipher moves a cipher out of the user's Archive
// (PUT /api/ciphers/{id}/unarchive) and returns it.
func (c *Client) UnarchiveCipher(ctx context.Context, accessToken, cipherID string) (*EncryptedCipher, error) {
	return c.putCipherAction(ctx, accessToken, cipherID, "unarchive")
}

func (c *Client) putCipherAction(ctx context.Context, accessToken, cipherID, action string) (*EncryptedCipher, error) {
	raw, err := c.do(ctx, http.MethodPut, "/api/ciphers/"+url.PathEscape(cipherID)+"/"+action, "", accessToken, nil, nil)
	if err != nil {
		return nil, err
	}
	var cipher EncryptedCipher
	if err := json.Unmarshal(raw, &cipher); err != nil {
		return nil, err
	}
	return &cipher, nil
}

func (c *Client) HardDeleteCipher(ctx context.Context, accessToken, cipherID string) error {
	_, err := c.do(ctx, http.MethodDelete, "/api/ciphers/"+url.PathEscape(cipherID), "", accessToken, nil, nil)
	return err
}

func (c *Client) CreateFolder(ctx context.Context, accessToken, encryptedName string) (*EncryptedFolder, error) {
	body, err := json.Marshal(struct {
		Name string `json:"name"`
	}{Name: encryptedName})
	if err != nil {
		return nil, err
	}
	raw, err := c.do(ctx, http.MethodPost, "/api/folders", "application/json", accessToken, nil, body)
	if err != nil {
		return nil, err
	}
	var folder EncryptedFolder
	if err := json.Unmarshal(raw, &folder); err != nil {
		return nil, err
	}
	return &folder, nil
}

func (c *Client) UpdateFolder(ctx context.Context, accessToken, folderID, encryptedName string) (*EncryptedFolder, error) {
	body, err := json.Marshal(struct {
		Name string `json:"name"`
	}{Name: encryptedName})
	if err != nil {
		return nil, err
	}
	raw, err := c.do(ctx, http.MethodPut, "/api/folders/"+url.PathEscape(folderID), "application/json", accessToken, nil, body)
	if err != nil {
		return nil, err
	}
	var folder EncryptedFolder
	if err := json.Unmarshal(raw, &folder); err != nil {
		return nil, err
	}
	return &folder, nil
}

func (c *Client) DeleteFolder(ctx context.Context, accessToken, folderID string) error {
	_, err := c.do(ctx, http.MethodDelete, "/api/folders/"+url.PathEscape(folderID), "", accessToken, nil, nil)
	return err
}

func DoWithRefresh[T any](
	ctx context.Context,
	accessToken string,
	refresh func(context.Context) (string, error),
	fn func(token string) (T, error),
) (T, error) {
	res, err := fn(accessToken)
	if err == nil || !errors.Is(err, ErrUnauthorized) || refresh == nil {
		return res, err
	}
	newToken, refreshErr := refresh(ctx)
	if refreshErr != nil {
		var zero T
		return zero, refreshErr
	}
	return fn(newToken)
}

func (c *Client) do(
	ctx context.Context,
	method, path, contentType, accessToken string,
	headers map[string]string,
	body []byte,
) ([]byte, error) {
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.resolve(path), bodyReader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", "application/json")
	for k, v := range c.headers {
		req.Header.Set(k, v)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+accessToken)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := c.apiHTTP.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if errors.Is(err, ErrRedirectRefused) {
			// The refused target is not repeated: it can carry a
			// signature.
			return nil, ErrRedirectRefused
		}
		return nil, fmt.Errorf("%w: %s", ErrNetworkOffline, transportDiagnostic(err))
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return raw, nil
	}
	return nil, classifyError(resp.StatusCode, raw)
}

// resolve maps a path under /api or /identity to its service URL.
func (c *Client) resolve(path string) string {
	switch {
	case strings.HasPrefix(path, "/api/"):
		return c.apiURL + strings.TrimPrefix(path, "/api")
	case strings.HasPrefix(path, "/identity/"):
		return c.identityURL + strings.TrimPrefix(path, "/identity")
	}
	return c.baseURL + path
}

func classifyError(status int, body []byte) error {
	if status == http.StatusUnauthorized {
		return ErrUnauthorized
	}
	if status == http.StatusConflict {
		return ErrRevisionConflict
	}
	if status == http.StatusNotFound {
		return ErrNotFound
	}

	if status == http.StatusBadRequest {
		if tfErr, ok := parseTwoFactorChallenge(body); ok {
			return tfErr
		}
		if ndErr := newDeviceError(status, body); ndErr != nil {
			return ndErr
		}
	}

	var parsed struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
		Message          string `json:"message"`
		ErrorModel       *struct {
			Message string `json:"message"`
		} `json:"errorModel"`
	}
	_ = json.Unmarshal(body, &parsed)

	msg := parsed.Message
	if msg == "" && parsed.ErrorModel != nil {
		msg = parsed.ErrorModel.Message
	}
	if msg == "" {
		msg = parsed.ErrorDescription
	}
	if msg == "" {
		msg = parsed.Error
	}

	// Vaultwarden answers a stale write and a missing cipher with HTTP 400
	// (src/api/core/ciphers.rs): "The client copy of this cipher is out of
	// date. Resync the client and try again." and "Cipher doesn't exist".
	if status == http.StatusBadRequest {
		switch lower := strings.ToLower(msg); {
		case strings.Contains(lower, "out of date"), strings.Contains(lower, "revision"):
			return ErrRevisionConflict
		case strings.Contains(lower, "doesn't exist"), strings.Contains(lower, "does not exist"):
			return &notFoundError{APIError{StatusCode: status, Message: msg, Body: string(body)}}
		}
	}

	return &APIError{
		StatusCode: status,
		Message:    msg,
		Code:       parsed.Error,
		Body:       string(body),
	}
}

const (
	// MaxAttachmentSize limits attachment plaintext.
	MaxAttachmentSize = 100 << 20
	// MaxAttachmentWireSize limits encrypted attachment data: the plaintext
	// limit plus the EncArrayBuffer header and one block of padding.
	MaxAttachmentWireSize = MaxAttachmentSize + 1 + 16 + 32 + 16
)

var ErrAttachmentTooLarge = errors.New("api: attachment exceeds the 100 MiB limit")

func (c *Client) GetCipher(ctx context.Context, accessToken, cipherID string) (*EncryptedCipher, error) {
	raw, err := c.do(ctx, http.MethodGet, "/api/ciphers/"+url.PathEscape(cipherID), "", accessToken, nil, nil)
	if err != nil {
		return nil, err
	}
	var cipher EncryptedCipher
	if err := json.Unmarshal(raw, &cipher); err != nil {
		return nil, err
	}
	return &cipher, nil
}

func attachmentPath(cipherID, attachmentID string) string {
	return "/api/ciphers/" + url.PathEscape(cipherID) + "/attachment/" + url.PathEscape(attachmentID)
}

func (c *Client) GetAttachment(ctx context.Context, accessToken, cipherID, attachmentID string) (*EncryptedAttachment, error) {
	raw, err := c.do(ctx, http.MethodGet, attachmentPath(cipherID, attachmentID), "", accessToken, nil, nil)
	if err != nil {
		return nil, err
	}
	var att EncryptedAttachment
	if err := json.Unmarshal(raw, &att); err != nil {
		return nil, err
	}
	return &att, nil
}

// DownloadAttachmentBytes fetches encrypted attachment data. The access token
// is only sent to the origin of the server, and it is stripped from every
// redirect hop that leaves that origin.
func (c *Client) DownloadAttachmentBytes(ctx context.Context, accessToken, downloadURL string) ([]byte, error) {
	base, err := url.Parse(c.apiURL)
	if err != nil {
		return nil, err
	}
	target, err := base.Parse(downloadURL)
	if err != nil || (target.Scheme != "http" && target.Scheme != "https") || target.Host == "" {
		return nil, fmt.Errorf("api: invalid attachment URL")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.userAgent)
	if accessToken != "" && sameOrigin(target, base) {
		req.Header.Set("Authorization", "Bearer "+accessToken)
	}

	hc := *c.httpClient
	inner := c.httpClient.CheckRedirect
	hc.CheckRedirect = func(next *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("api: too many redirects")
		}
		if next.URL.Scheme != "http" && next.URL.Scheme != "https" {
			return errors.New("api: invalid attachment redirect")
		}
		if !sameOrigin(next.URL, base) {
			next.Header.Del("Authorization")
		}
		if inner != nil {
			return inner(next, via)
		}
		return nil
	}

	resp, err := hc.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("%w: %s", ErrNetworkOffline, transportDiagnostic(err))
	}
	defer resp.Body.Close()
	if resp.ContentLength > MaxAttachmentWireSize {
		return nil, ErrAttachmentTooLarge
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxAttachmentWireSize+1))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, classifyError(resp.StatusCode, raw)
	}
	if len(raw) > MaxAttachmentWireSize {
		return nil, ErrAttachmentTooLarge
	}
	return raw, nil
}

// sameOrigin compares scheme, host and port, with default ports made explicit.
func sameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Hostname(), b.Hostname()) && originPort(a) == originPort(b)
}

func originPort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if strings.EqualFold(u.Scheme, "https") {
		return "443"
	}
	return "80"
}

func (c *Client) CreateAttachmentV2(ctx context.Context, accessToken, cipherID string, req AttachmentUploadRequest) (*AttachmentUploadResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	raw, err := c.do(ctx, http.MethodPost, "/api/ciphers/"+url.PathEscape(cipherID)+"/attachment/v2", "application/json", accessToken, nil, body)
	if err != nil {
		return nil, err
	}
	var resp AttachmentUploadResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) UploadAttachmentData(ctx context.Context, accessToken, cipherID, attachmentID, fileName string, encryptedData []byte) error {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	part, err := w.CreateFormFile("data", fileName)
	if err != nil {
		return err
	}
	if _, err := part.Write(encryptedData); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	_, err = c.do(ctx, http.MethodPost, attachmentPath(cipherID, attachmentID), w.FormDataContentType(), accessToken, nil, buf.Bytes())
	return err
}

func (c *Client) DeleteAttachment(ctx context.Context, accessToken, cipherID, attachmentID string) error {
	_, err := c.do(ctx, http.MethodDelete, attachmentPath(cipherID, attachmentID), "", accessToken, nil, nil)
	return err
}

// InsecureServer reports that serverURL is plain HTTP to a host other than
// this machine, so passwords and vault data cross the network unencrypted.
func InsecureServer(serverURL string) bool {
	u, err := url.Parse(strings.TrimSpace(serverURL))
	if err != nil || !strings.EqualFold(u.Scheme, "http") {
		return false
	}
	host := u.Hostname()
	if strings.EqualFold(host, "localhost") {
		return false
	}
	ip := net.ParseIP(host)
	return ip == nil || !ip.IsLoopback()
}
