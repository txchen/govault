package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/txchen/govault/internal/vaultcore/crypto"
)

type TwoFactorProvider int

const (
	TwoFactorAuthenticator   TwoFactorProvider = 0
	TwoFactorEmail           TwoFactorProvider = 1
	TwoFactorDuo             TwoFactorProvider = 2
	TwoFactorYubiKey         TwoFactorProvider = 3
	TwoFactorU2F             TwoFactorProvider = 4
	TwoFactorRemember        TwoFactorProvider = 5
	TwoFactorOrganizationDuo TwoFactorProvider = 6
	TwoFactorWebAuthn        TwoFactorProvider = 7
)

func (p TwoFactorProvider) String() string {
	switch p {
	case TwoFactorAuthenticator:
		return "Authenticator App"
	case TwoFactorEmail:
		return "Email"
	case TwoFactorDuo:
		return "Duo"
	case TwoFactorYubiKey:
		return "YubiKey"
	case TwoFactorU2F:
		return "FIDO U2F"
	case TwoFactorRemember:
		return "Remembered Device"
	case TwoFactorOrganizationDuo:
		return "Duo (Organization)"
	case TwoFactorWebAuthn:
		return "Passkey / WebAuthn"
	default:
		return "Provider " + strconv.Itoa(int(p))
	}
}

type TwoFactorLogin struct {
	Provider TwoFactorProvider
	Token    string
	Remember bool
}

type TwoFactorChallenge struct {
	Providers    []TwoFactorProvider
	ProviderData map[TwoFactorProvider]json.RawMessage
	// Email is the authoritative account email returned at the top level of
	// an SSO two-factor challenge by Bitwarden (distinct from the redacted
	// delivery address inside TwoFactorProviders2["1"]).
	Email string
	// SSOEmail2FASessionToken is issued during an SSO login when email
	// two-factor is available, standing in for a master password hash when
	// asking the server to email a code.
	SSOEmail2FASessionToken string
}

func (c TwoFactorChallenge) Has(p TwoFactorProvider) bool {
	return slices.Contains(c.Providers, p)
}

func (c TwoFactorChallenge) EmailHint() string {
	raw, ok := c.ProviderData[TwoFactorEmail]
	if !ok {
		return ""
	}
	var data map[string]any
	if err := json.Unmarshal(raw, &data); err != nil {
		return ""
	}
	for k, v := range data {
		if strings.EqualFold(k, "email") {
			if s, ok := v.(string); ok {
				return s
			}
		}
	}
	return ""
}

// YubiKeyOTPLength is the length of a Yubico OTP: a 12-character public
// ID and a 32-character encrypted part, all in modhex. Vaultwarden refuses
// any other length ("Invalid Yubikey OTP length",
// src/api/core/two_factor/yubikey.rs).
const YubiKeyOTPLength = 44

const modhexAlphabet = "cbdefghijklnrtuv"

// NormalizeYubiKeyOTP returns the OTP a YubiKey typed without whitespace,
// in lowercase modhex, and whether it has the shape of a Yubico OTP.
// Caps Lock types it in capitals, so case is folded.
func NormalizeYubiKeyOTP(s string) (string, bool) {
	otp := strings.ToLower(strings.Join(strings.Fields(s), ""))
	if len(otp) != YubiKeyOTPLength {
		return otp, false
	}
	for i := 0; i < len(otp); i++ {
		if strings.IndexByte(modhexAlphabet, otp[i]) < 0 {
			return otp, false
		}
	}
	return otp, true
}

type TwoFactorRequiredError struct {
	Challenge TwoFactorChallenge
	Message   string
}

func (e *TwoFactorRequiredError) Error() string {
	names := make([]string, len(e.Challenge.Providers))
	for i, p := range e.Challenge.Providers {
		names[i] = p.String()
	}
	return fmt.Sprintf("%s (providers: %s)", ErrTwoFactorRequired, strings.Join(names, ", "))
}

func (e *TwoFactorRequiredError) Unwrap() error { return ErrTwoFactorRequired }

func parseTwoFactorChallenge(body []byte) (*TwoFactorRequiredError, bool) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		return nil, false
	}
	var listRaw, dataRaw, descRaw, emailRaw, ssoTokenRaw json.RawMessage
	for k, v := range fields {
		switch strings.ToLower(k) {
		case "twofactorproviders":
			listRaw = v
		case "twofactorproviders2":
			dataRaw = v
		case "error_description":
			descRaw = v
		case "email":
			emailRaw = v
		case "ssoemail2fasessiontoken":
			ssoTokenRaw = v
		}
	}
	if len(listRaw) == 0 && len(dataRaw) == 0 {
		return nil, false
	}

	ch := TwoFactorChallenge{ProviderData: map[TwoFactorProvider]json.RawMessage{}}
	_ = json.Unmarshal(emailRaw, &ch.Email)
	_ = json.Unmarshal(ssoTokenRaw, &ch.SSOEmail2FASessionToken)
	var data map[string]json.RawMessage
	if json.Unmarshal(dataRaw, &data) == nil {
		for k, v := range data {
			if n, err := strconv.Atoi(strings.TrimSpace(k)); err == nil {
				ch.ProviderData[TwoFactorProvider(n)] = v
			}
		}
	}
	var list []json.RawMessage
	if json.Unmarshal(listRaw, &list) == nil {
		for _, item := range list {
			s := strings.Trim(strings.TrimSpace(string(item)), `"`)
			if n, err := strconv.Atoi(s); err == nil && !ch.Has(TwoFactorProvider(n)) {
				ch.Providers = append(ch.Providers, TwoFactorProvider(n))
			}
		}
	}
	if len(ch.Providers) == 0 {
		for p := range ch.ProviderData {
			ch.Providers = append(ch.Providers, p)
		}
	}
	slices.Sort(ch.Providers)

	var desc string
	_ = json.Unmarshal(descRaw, &desc)
	return &TwoFactorRequiredError{Challenge: ch, Message: desc}, true
}

func (c *Client) SendEmailTwoFactorLogin(ctx context.Context, email, masterPasswordHash string) error {
	body, err := json.Marshal(struct {
		Email              string `json:"email"`
		MasterPasswordHash string `json:"masterPasswordHash"`
		DeviceIdentifier   string `json:"deviceIdentifier"`
	}{
		Email:              crypto.NormalizeEmail(email),
		MasterPasswordHash: masterPasswordHash,
		DeviceIdentifier:   c.deviceID,
	})
	if err != nil {
		return err
	}
	_, err = c.do(ctx, http.MethodPost, "/api/two-factor/send-email-login", "application/json", "", nil, body)
	return err
}

// SendEmailTwoFactorLoginSSO asks the server to email a two-step login
// code during an SSO login, where there is no master password hash.
// When ssoSessionToken is present (Bitwarden), the request sends the
// challenge's authoritative email and token; when absent (Vaultwarden), it
// sends the device-only form because Vaultwarden rejects an email without a
// masterPasswordHash and resolves the user by device identifier.
func (c *Client) SendEmailTwoFactorLoginSSO(ctx context.Context, email, ssoSessionToken string) error {
	payload := struct {
		Email                   string `json:"email,omitempty"`
		SSOEmail2FASessionToken string `json:"ssoEmail2faSessionToken,omitempty"`
		DeviceIdentifier        string `json:"deviceIdentifier"`
	}{
		DeviceIdentifier: c.deviceID,
	}
	if ssoSessionToken != "" {
		payload.Email = crypto.NormalizeEmail(email)
		payload.SSOEmail2FASessionToken = ssoSessionToken
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	headers := map[string]string{"Device-Identifier": c.deviceID}
	_, err = c.do(ctx, http.MethodPost, "/api/two-factor/send-email-login", "application/json", "", headers, body)
	return err
}
