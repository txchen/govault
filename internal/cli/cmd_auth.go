package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/txchen/govault/internal/vaultcore/api"
	"github.com/txchen/govault/internal/vaultcore/crypto"
	"github.com/txchen/govault/internal/vaultcore/profile"
)

// invalidYubiKeyOTP is checked locally, as the desktop checks it, so a
// stray paste never reaches the server.
const invalidYubiKeyOTP = "That is not a YubiKey code: touch the key to type one."

func (a *app) status(p *parsed) response {
	prof, err := a.openProfile()
	if err != nil {
		return errResponse(err)
	}
	st, err := prof.Status(a.flags.session)
	if err != nil {
		return errResponse(err)
	}
	t := obj{}.set("serverUrl", nullIfEmpty(st.Server))
	if st.LastSync.IsZero() {
		t = t.set("lastSync", nil)
	} else {
		t = t.set("lastSync", jsTime(st.LastSync))
	}
	t = t.opt("userEmail", st.Email).opt("userId", st.UserID)
	t = t.set("status", [...]string{"unauthenticated", "locked", "unlocked"}[st.State])
	return success(templateData{template: t})
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func (a *app) config(p *parsed) response {
	if strings.ToLower(p.arg(0)) != "server" {
		return failure("Unknown setting.")
	}
	if p.has("key-connector") {
		return failure("gv does not support Key Connector.")
	}
	overrides := profile.ServiceURLs{
		API: api.FormatServiceURL(optValue(p, "api")), Identity: api.FormatServiceURL(optValue(p, "identity")),
		WebVault: api.FormatServiceURL(optValue(p, "web-vault")), Icons: api.FormatServiceURL(optValue(p, "icons")),
		Notifications: api.FormatServiceURL(optValue(p, "notifications")), Events: api.FormatServiceURL(optValue(p, "events")),
	}
	prof, err := a.openProfile()
	if err != nil {
		return errResponse(err)
	}
	value := p.arg(0 + 1)
	if strings.TrimSpace(value) == "" && overrides == (profile.ServiceURLs{}) {
		server, err := prof.Server()
		if err != nil {
			return errResponse(err)
		}
		if server == "" {
			server = "https://bitwarden.com"
		}
		return str(server)
	}
	base := api.FormatServerURL(value)
	if strings.TrimSpace(value) == "" {
		base = ""
	}
	if err := prof.SetServerURLs(base, overrides); err != nil {
		if errors.Is(err, profile.ErrLogoutRequired) {
			return failure("Logout required before server config update.")
		}
		return errResponse(err)
	}
	for _, u := range []string{base, overrides.API, overrides.Identity} {
		if api.InsecureServer(u) {
			a.warn("Warning: " + u + " is not HTTPS. Your master password hash, tokens and vault data will cross the network unencrypted.")
		}
	}
	return msg("Saved setting `config`.")
}

// readFirstLine reads the first line of a password file.
func readFirstLine(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	line, err := bufio.NewReader(f).ReadString('\n')
	if err != nil && line == "" {
		return "", nil
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// password resolves a master password from, in order, the argument,
// --passwordfile, --passwordenv and a prompt.
func (a *app) password(arg string, p *parsed, required string) (string, *response) {
	pw := arg
	if pw == "" {
		if file, ok := p.opt("passwordfile"); ok && file != "" {
			line, err := readFirstLine(file)
			if err != nil {
				r := failure("Cannot read the password file: " + err.Error())
				return "", &r
			}
			pw = line
		} else if name, ok := p.opt("passwordenv"); ok && name != "" {
			if pw = a.getenv(name); pw == "" {
				a.warn("Warning: Provided passwordenv " + name + " is not set")
			}
		}
	}
	if pw == "" {
		if !a.canPrompt() {
			r := failure(required)
			return "", &r
		}
		line, err := a.env.Terminal.ReadSecret("Master password:")
		if err != nil {
			r := failure(required)
			return "", &r
		}
		pw = line
	}
	return pw, nil
}

const unlockPasswordRequired = "Master password is required. Try again in interactive mode or provide a password file or environment variable."

// invalidPasswordMessage is what bw 2026.11 reports for a wrong master
// password, from its SDK.
const invalidPasswordMessage = "Cryptography error, The decryption operation failed"

func sessionMessage(title, key string) message {
	text := "\nTo unlock your vault, set your session key to the `BW_SESSION` environment variable. ex:\n" +
		"$ export BW_SESSION=\"" + key + "\"\n" +
		"> $env:BW_SESSION=\"" + key + "\"\n\n" +
		"You can also pass the session key to any command with the `--session` option. ex:\n" +
		"$ gv list items --session " + key
	return message{title: title, text: &text, raw: &key}
}

func (a *app) apiKeyFromEnv() *profile.APIKey {
	id, secret := a.getenv("BW_CLIENTID"), a.getenv("BW_CLIENTSECRET")
	if id == "" || secret == "" {
		return nil
	}
	return &profile.APIKey{ClientID: id, ClientSecret: secret}
}

func (a *app) unlock(p *parsed) response {
	prof, err := a.openProfile()
	if err != nil {
		return errResponse(err)
	}
	if _, err := prof.Account(); err != nil {
		return errResponse(err)
	}
	if p.has("check") {
		if err := prof.CheckSession(a.flags.session); err != nil {
			return errResponse(err)
		}
		return msg("Vault is unlocked!")
	}
	pw, fail := a.password(p.arg(0), p, unlockPasswordRequired)
	if fail != nil {
		return *fail
	}
	key, err := prof.Unlock(a.ctx, profile.UnlockRequest{Password: []byte(pw), APIKey: a.apiKeyFromEnv()})
	if errors.Is(err, profile.ErrInvalidPassword) {
		return failure(invalidPasswordMessage)
	}
	if err != nil {
		return errResponse(err)
	}
	a.flags.session = key
	return success(sessionMessage("Your vault is now unlocked!", key))
}

func (a *app) lock(p *parsed) response {
	prof, err := a.openProfile()
	if err != nil {
		return errResponse(err)
	}
	if err := prof.Lock(); err != nil {
		return errResponse(err)
	}
	return msg("Your vault is locked.")
}

func (a *app) logout(p *parsed) response {
	prof, err := a.openProfile()
	if err != nil {
		return errResponse(err)
	}
	if err := prof.Logout(); err != nil {
		return errResponse(err)
	}
	return msg("You have logged out.")
}

func (a *app) sync(p *parsed) response {
	prof, err := a.openProfile()
	if err != nil {
		return errResponse(err)
	}
	if _, err := prof.Account(); err != nil {
		return errResponse(err)
	}
	if p.has("last") {
		t, err := prof.LastSync()
		if err != nil {
			return errResponse(err)
		}
		if t.IsZero() {
			return success(stringData{})
		}
		return str(jsTime(t))
	}
	err = prof.Sync(a.ctx, profile.SyncRequest{Force: p.has("force"), SessionKey: a.flags.session, APIKey: a.apiKeyFromEnv()})
	if err != nil {
		r := errResponse(err)
		r.message = "Syncing failed: " + r.message
		return r
	}
	return msg("Syncing complete.")
}

// unlocked runs fn with the unlocked vault. A locked vault is unlocked by
// prompting when interaction is allowed, as bw does.
func (a *app) unlocked(fn func(v *profile.Vault) response) response {
	prof, err := a.openProfile()
	if err != nil {
		return errResponse(err)
	}
	if fail := a.ensureUnlocked(prof); fail != nil {
		return *fail
	}
	var r response
	err = prof.Read(a.flags.session, a.apiKeyFromEnv(), func(v *profile.Vault) error {
		r = fn(v)
		return nil
	})
	if err != nil {
		return errResponse(err)
	}
	return r
}

// ensureUnlocked unlocks a locked vault by prompting when interaction is
// allowed, as bw does before a command that needs the vault.
func (a *app) ensureUnlocked(prof *profile.Profile) *response {
	fail := func(r response) *response { return &r }
	if _, err := prof.Account(); err != nil {
		return fail(errResponse(err))
	}
	if err := prof.CheckSession(a.flags.session); !errors.Is(err, profile.ErrLocked) || !a.canPrompt() {
		return nil
	}
	pw, failed := a.password("", &parsed{opts: map[string]string{}}, unlockPasswordRequired)
	if failed != nil {
		return failed
	}
	key, err := prof.Unlock(a.ctx, profile.UnlockRequest{Password: []byte(pw), APIKey: a.apiKeyFromEnv()})
	if errors.Is(err, profile.ErrInvalidPassword) {
		return fail(failure(invalidPasswordMessage))
	}
	if err != nil {
		return fail(errResponse(err))
	}
	a.flags.session = key
	return nil
}

// twoFactorNames are the providers gv offers, in Bitwarden's order.
var twoFactorProviders = []struct {
	p    api.TwoFactorProvider
	name string
}{
	{api.TwoFactorAuthenticator, "Authenticator App"},
	{api.TwoFactorYubiKey, "Yubico OTP Security Key"},
	{api.TwoFactorEmail, "Email"},
}

func (a *app) login(p *parsed) response {
	prof, err := a.openProfile()
	if err != nil {
		return errResponse(err)
	}
	if p.has("check") {
		if _, err := prof.Account(); err != nil {
			return errResponse(err)
		}
		return msg("You are logged in!")
	}
	if email, err := prof.Account(); err == nil {
		return failure("You are already logged in as " + email + ".")
	}
	if p.has("sso") {
		return a.loginSSO(prof, p)
	}
	if p.has("apikey") {
		return a.loginAPIKey(prof, p)
	}
	email := p.arg(0)
	if email == "" && a.canPrompt() {
		email, _ = a.env.Terminal.ReadLine("Email address:")
	}
	if strings.TrimSpace(email) == "" {
		return failure("Email address is required.")
	}
	if !strings.Contains(email, "@") {
		return failure("Email address is invalid.")
	}
	pw := p.arg(1)
	if pw == "" {
		if file, ok := p.opt("passwordfile"); ok && file != "" {
			line, err := readFirstLine(file)
			if err != nil {
				return failure("Cannot read the password file: " + err.Error())
			}
			pw = line
		} else if name, ok := p.opt("passwordenv"); ok && name != "" && a.getenv(name) != "" {
			pw = a.getenv(name)
		} else if a.canPrompt() {
			pw, _ = a.env.Terminal.ReadSecret("Master password:")
		}
	}
	if pw == "" {
		return failure("Master password is required.")
	}
	method := -1
	if m, ok := p.opt("method"); ok {
		n, err := strconv.Atoi(strings.TrimSpace(m))
		if err != nil || n < 0 || n > 8 {
			return failure("Invalid two-step login method.")
		}
		method = n
	}
	code, hasCode := p.opt("code")

	if hasCode && api.TwoFactorProvider(method) == api.TwoFactorYubiKey {
		otp, ok := api.NormalizeYubiKeyOTP(code)
		if !ok {
			return failure(invalidYubiKeyOTP)
		}
		code = otp
	}
	pwBytes := []byte(pw)
	login, err := prof.BeginPasswordLogin(a.ctx, email, pwBytes)
	// The derived key is all the login keeps.
	crypto.ZeroBytes(pwBytes)
	if err != nil {
		return loginFailure(err, prof)
	}
	defer login.Close()
	var twoFactor *api.TwoFactorLogin
	if hasCode && method >= 0 {
		twoFactor = &api.TwoFactorLogin{Provider: api.TwoFactorProvider(method), Token: code}
	}
	key, err := login.Complete(a.ctx, twoFactor)
	var tfErr *api.TwoFactorRequiredError
	if errors.As(err, &tfErr) && twoFactor != nil {
		return failure("Login failed.")
	}
	if errors.As(err, &tfErr) {
		var offered []int
		for i, tp := range twoFactorProviders {
			if tfErr.Challenge.Has(tp.p) {
				offered = append(offered, i)
			}
		}
		if len(offered) == 0 {
			return failure("No providers available for this client.")
		}
		chosen := -1
		for _, i := range offered {
			if int(twoFactorProviders[i].p) == method {
				chosen = i
			}
		}
		if chosen < 0 {
			switch {
			case len(offered) == 1:
				chosen = offered[0]
			case a.canPrompt():
				chosen = a.chooseProvider(offered)
				if chosen == -2 {
					return failure("Login failed.")
				}
			}
			if chosen < 0 {
				return failure("Login failed. No provider selected.")
			}
		}
		provider := twoFactorProviders[chosen].p
		if !hasCode && provider == api.TwoFactorEmail {
			if err := login.SendEmailCode(a.ctx); err != nil {
				return loginFailure(err, prof)
			}
		}
		if !hasCode {
			if a.canPrompt() {
				code, _ = a.env.Terminal.ReadLine("Two-step login code:")
			}
			if code == "" {
				return failure("Code is required.")
			}
		}
		if provider == api.TwoFactorYubiKey {
			otp, ok := api.NormalizeYubiKeyOTP(code)
			if !ok {
				return failure(invalidYubiKeyOTP)
			}
			code = otp
		}
		twoFactor = &api.TwoFactorLogin{Provider: provider, Token: code}
		key, err = login.Complete(a.ctx, twoFactor)
		if errors.As(err, &tfErr) {
			return failure("Login failed.")
		}
	}
	// New device verification, as bw asks for it: only by prompt, with no
	// option to pass the code, and "Code is required." without one.
	if errors.Is(err, api.ErrNewDeviceVerificationRequired) {
		var otp string
		if a.canPrompt() {
			otp, _ = a.env.Terminal.ReadLine(newDevicePrompt)
		}
		if strings.TrimSpace(otp) == "" {
			return failure("Code is required.")
		}
		key, err = login.CompleteWith(a.ctx, api.PasswordLoginOptions{TwoFactor: twoFactor, NewDeviceOTP: otp})
		if errors.As(err, &tfErr) {
			return failure("Login failed.")
		}
	}
	if err != nil {
		return loginFailure(err, prof)
	}
	a.flags.session = key
	return success(sessionMessage("You are logged in!", key))
}

// newDevicePrompt is bw's prompt for the code Bitwarden emails when a
// password login comes from a device it does not know
// (apps/cli/src/auth/commands/login.command.ts).
const newDevicePrompt = "New device verification required. Enter OTP sent to login email:"

// chooseProvider prompts for a two-step method: an index into
// twoFactorProviders, -2 to cancel, -1 when nothing was chosen.
func (a *app) chooseProvider(offered []int) int {
	var b strings.Builder
	b.WriteString("Two-step login method:")
	for n, i := range offered {
		b.WriteString(fmt.Sprintf("\n  %d) %s", n+1, twoFactorProviders[i].name))
	}
	b.WriteString(fmt.Sprintf("\n  %d) Cancel\nChoose a number:", len(offered)+1))
	answer, err := a.env.Terminal.ReadLine(b.String())
	if err != nil {
		return -1
	}
	n, err := strconv.Atoi(strings.TrimSpace(answer))
	switch {
	case err != nil || n < 1 || n > len(offered)+1:
		return -1
	case n == len(offered)+1:
		return -2
	}
	return offered[n-1]
}

func loginFailure(err error, prof *profile.Profile) response {
	var apiErr *api.APIError
	if errors.As(err, &apiErr) && apiErr.Message == "Username or password is incorrect. Try again." {
		host := "vault.bitwarden.com"
		if server, _ := prof.Server(); server != "" {
			if u, err := url.Parse(server); err == nil {
				host = u.Host
			}
		}
		return failure("Invalid master password. Confirm your email is correct and your account was created on " + host + ".")
	}
	if errors.As(err, &apiErr) && apiErr.Message != "" {
		return failure(apiErr.Message)
	}
	return errResponse(err)
}

func (a *app) loginAPIKey(prof *profile.Profile, p *parsed) response {
	id := a.getenv("BW_CLIENTID")
	if id == "" && a.canPrompt() {
		id, _ = a.env.Terminal.ReadLine("client_id:")
	}
	if strings.TrimSpace(id) == "" {
		return failure("client_id is required.")
	}
	secret := a.getenv("BW_CLIENTSECRET")
	if secret == "" && a.canPrompt() {
		secret, _ = a.env.Terminal.ReadSecret("client_secret:")
	}
	if secret == "" {
		return failure("client_secret is required.")
	}
	if m, ok := p.opt("method"); ok {
		if n, err := strconv.Atoi(strings.TrimSpace(m)); err != nil || n < 0 || n > 8 {
			return failure("Invalid two-step login method.")
		}
	}
	if !strings.HasPrefix(id, "user") {
		return failure("Invalid API Key; Organization API Key currently not supported")
	}
	err := prof.LoginAPIKey(a.ctx, profile.APIKey{ClientID: id, ClientSecret: secret})
	var apiErr *api.APIError
	if errors.As(err, &apiErr) && apiErr.Code == "invalid_client" {
		return failure("client_id or client_secret is incorrect. Try again.")
	}
	if err != nil {
		return loginFailure(err, prof)
	}
	if !a.flags.noInteraction {
		text := "\nTo unlock your vault, use the `unlock` command. ex:\n$ gv unlock"
		return success(message{title: "You are logged in!", text: &text})
	}
	// bw prints a session key here too, though it unlocks nothing until
	// `unlock`; gv does the same so scripts parse the same output.
	return success(sessionMessage("You are logged in!", profile.RandomSessionKey()))
}

func (a *app) loginSSO(prof *profile.Profile, p *parsed) response {
	if a.flags.noInteraction {
		return failure("SSO login requires interactive browser authentication.")
	}
	method := -1
	if m, ok := p.opt("method"); ok {
		n, err := strconv.Atoi(strings.TrimSpace(m))
		if err != nil || n < 0 || n > 8 {
			return failure("Invalid two-step login method.")
		}
		method = n
	}
	codeFlag, hasCode := p.opt("code")
	if hasCode && api.TwoFactorProvider(method) == api.TwoFactorYubiKey {
		otp, ok := api.NormalizeYubiKeyOTP(codeFlag)
		if !ok {
			return failure(invalidYubiKeyOTP)
		}
		codeFlag = otp
	}

	// Capture server endpoints, web vault URL, device ID, and generation
	// before opening the browser so a concurrent `config server` cannot
	// redirect the code and verifier to another identity server.
	login, err := prof.PrepareSSOLogin()
	if err != nil {
		return loginFailure(err, prof)
	}
	pkce, err := api.NewSSOPKCE()
	if err != nil {
		return errResponse(err)
	}
	portMin, portMax := api.SSOCallbackPortMin, api.SSOCallbackPortMax
	if a.env.SSOCallbackPorts != [2]int{} {
		portMin, portMax = a.env.SSOCallbackPorts[0], a.env.SSOCallbackPorts[1]
	}
	cb, err := api.StartSSOCallback(pkce.State, portMin, portMax)
	if err != nil {
		return errResponse(err)
	}
	defer cb.Close()

	orgID := strings.TrimSpace(optValue(p, "sso"))
	ssoURL, err := api.BuildSSOURL(login.WebVaultURL(), "cli", cb.RedirectURI(), pkce, "", orgID)
	if err != nil {
		return errResponse(err)
	}
	openURL := a.env.OpenURL
	if openURL == nil {
		openURL = func(raw string) error { return openBrowserURL(a.env.GOOS, raw) }
	}
	if !a.flags.quiet {
		a.warn("Opening browser for SSO login:\n" + ssoURL)
	}
	if err := openURL(ssoURL); err != nil {
		if a.flags.quiet {
			a.warn("Could not open browser automatically; open this URL to continue:\n" + ssoURL)
		} else {
			a.warn("Could not open browser automatically; open the URL above to continue.")
		}
	}

	waitCtx, cancelWait := context.WithTimeout(a.ctx, api.DefaultSSOWaitTimeout)
	defer cancelWait()
	res, err := cb.Wait(waitCtx)
	if err != nil {
		return errResponse(err)
	}
	login.SetCallback(res.Code, pkce.CodeVerifier, cb.RedirectURI())

	var twoFactor *api.TwoFactorLogin
	if hasCode && method >= 0 {
		twoFactor = &api.TwoFactorLogin{Provider: api.TwoFactorProvider(method), Token: codeFlag}
	}
	err = login.Authenticate(a.ctx, twoFactor)
	var tfErr *api.TwoFactorRequiredError
	if errors.As(err, &tfErr) && twoFactor != nil {
		return failure("Login failed.")
	}
	if errors.As(err, &tfErr) {
		var offered []int
		for i, tp := range twoFactorProviders {
			if tfErr.Challenge.Has(tp.p) {
				offered = append(offered, i)
			}
		}
		if len(offered) == 0 {
			return failure("No providers available for this client.")
		}
		chosen := -1
		for _, i := range offered {
			if int(twoFactorProviders[i].p) == method {
				chosen = i
			}
		}
		if chosen < 0 {
			switch {
			case len(offered) == 1:
				chosen = offered[0]
			case a.canPrompt():
				chosen = a.chooseProvider(offered)
				if chosen == -2 {
					return failure("Login failed.")
				}
			}
			if chosen < 0 {
				return failure("Login failed. No provider selected.")
			}
		}
		provider := twoFactorProviders[chosen].p
		if !hasCode && provider == api.TwoFactorEmail {
			if err := login.SendEmailCode(a.ctx, tfErr.Challenge.Email, tfErr.Challenge.SSOEmail2FASessionToken); err != nil {
				return loginFailure(err, prof)
			}
		}
		code := codeFlag
		if !hasCode {
			if a.canPrompt() {
				code, _ = a.env.Terminal.ReadLine("Two-step login code:")
			}
			if code == "" {
				return failure("Code is required.")
			}
		}
		if provider == api.TwoFactorYubiKey {
			otp, ok := api.NormalizeYubiKeyOTP(code)
			if !ok {
				return failure(invalidYubiKeyOTP)
			}
			code = otp
		}
		twoFactor = &api.TwoFactorLogin{Provider: provider, Token: code}
		err = login.Authenticate(a.ctx, twoFactor)
		if errors.As(err, &tfErr) {
			return failure("Login failed.")
		}
	}
	if err != nil {
		return loginFailure(err, prof)
	}

	// On systems without a credential store, sealing the refresh token needs
	// the vault's user key. Require a master password before committing so an
	// SSO login never commits an account whose refresh token was discarded.
	var pw []byte
	if !prof.HasKeyring() {
		if file, ok := p.opt("passwordfile"); ok && file != "" {
			line, err := readFirstLine(file)
			if err != nil {
				return failure("Cannot read the password file: " + err.Error())
			}
			pw = []byte(line)
		} else if name, ok := p.opt("passwordenv"); ok && name != "" && a.getenv(name) != "" {
			pw = []byte(a.getenv(name))
		} else if a.canPrompt() {
			line, err := a.env.Terminal.ReadSecret("Master password:")
			if err != nil {
				return failure("Master password is required to save SSO credentials without a credential store.")
			}
			pw = []byte(line)
		}
		if len(pw) == 0 {
			return failure("Master password is required to save SSO credentials without a credential store.")
		}
		defer crypto.ZeroBytes(pw)
	}

	key, err := login.Commit(a.ctx, pw)
	if errors.Is(err, profile.ErrInvalidPassword) {
		return failure(invalidPasswordMessage)
	}
	if err != nil {
		return loginFailure(err, prof)
	}
	if key != "" {
		a.flags.session = key
		return success(sessionMessage("You are logged in!", key))
	}
	text := "\nTo unlock your vault, use the `unlock` command. ex:\n$ gv unlock"
	return success(message{title: "You are logged in!", text: &text})
}
