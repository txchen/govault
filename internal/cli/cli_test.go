package cli

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/txchen/govault/internal/fakeserver"
	"github.com/txchen/govault/internal/vaultcore/keyring"
	"github.com/txchen/govault/internal/vaultcore/totp"
)

// scriptedTerminal answers prompts in order and records them.
type scriptedTerminal struct {
	answers []string
	prompts []string
}

func (s *scriptedTerminal) next(prompt string) (string, error) {
	s.prompts = append(s.prompts, prompt)
	if len(s.answers) == 0 {
		return "", errors.New("no answer scripted")
	}
	a := s.answers[0]
	s.answers = s.answers[1:]
	return a, nil
}

func (s *scriptedTerminal) ReadLine(p string) (string, error)   { return s.next(p) }
func (s *scriptedTerminal) ReadSecret(p string) (string, error) { return s.next(p) }

type gvTest struct {
	t    *testing.T
	srv  *fakeserver.Server
	env  map[string]string
	ring keyring.Store
	term *scriptedTerminal
	tty  bool
	goos string
	// stdout, when set, receives standard output instead of the result.
	stdout  io.Writer
	openURL func(string) error
}

type result struct {
	out, err string
	code     int
}

func newGV(t *testing.T, opts ...fakeserver.Option) *gvTest {
	t.Helper()
	srv := fakeserver.New(opts...)
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	g := &gvTest{t: t, srv: srv, ring: keyring.NewMemory(), goos: "linux",
		env: map[string]string{"HOME": dir, "BITWARDENCLI_APPDATA_DIR": filepath.Join(dir, "bw")}}
	g.mustRun("config", "server", srv.URL())
	return g
}

func (g *gvTest) run(args ...string) result {
	g.t.Helper()
	var stdout, stderr bytes.Buffer
	env := &Environment{
		Args: args, Getenv: func(k string) string { return g.env[k] },
		Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr,
		StdoutTTY: g.tty, StderrTTY: g.tty,
		HTTPClient: g.srv.Client(), Version: "9.9.9", GOOS: g.goos,
		Keyring: func() (keyring.Store, error) {
			if g.ring == nil {
				return nil, keyring.ErrUnavailable
			}
			return g.ring, nil
		},
	}
	if g.term != nil {
		env.Terminal = g.term
	}
	if g.stdout != nil {
		env.Stdout = g.stdout
	}
	if g.openURL != nil {
		env.OpenURL = g.openURL
	}
	code := Run(env)
	return result{stdout.String(), stderr.String(), code}
}

func (g *gvTest) mustRun(args ...string) string {
	g.t.Helper()
	r := g.run(args...)
	if r.code != 0 {
		g.t.Fatalf("gv %v: exit %d: %s%s", args, r.code, r.err, r.out)
	}
	return r.out
}

func (g *gvTest) login() string {
	g.t.Helper()
	g.env["PW"] = fakeserver.Password
	key := g.mustRun("login", fakeserver.Email, "--passwordenv", "PW", "--raw")
	g.env["BW_SESSION"] = key
	return key
}

func lastTokenForm(srv *fakeserver.Server) map[string]string {
	var form map[string]string
	for _, r := range srv.Requests() {
		if r.Path == "/identity/connect/token" {
			form = r.Form
		}
	}
	return form
}

func TestLoginAuthenticatorCodeKeepsLeadingZeros(t *testing.T) {
	g := newGV(t)
	g.srv.Configure(func(c *fakeserver.Config) { c.TwoFactor = map[int]string{0: "012345"} })
	g.env["PW"] = fakeserver.Password
	key := g.mustRun("login", fakeserver.Email, "--passwordenv", "PW", "--method", "0", "--code", "012345", "--raw")
	if len(key) != 88 {
		t.Fatalf("session key = %q", key)
	}
	if f := lastTokenForm(g.srv); f["twoFactorToken"] != "012345" || f["twoFactorProvider"] != "0" {
		t.Fatalf("two-factor form = %v", f)
	}
}

func TestLoginEmailCodeIsSentThenPrompted(t *testing.T) {
	g := newGV(t)
	g.srv.Configure(func(c *fakeserver.Config) { c.TwoFactor = map[int]string{1: "007007"} })
	g.term = &scriptedTerminal{answers: []string{"007007"}}
	g.env["PW"] = fakeserver.Password
	g.mustRun("login", fakeserver.Email, "--passwordenv", "PW")
	if n := g.srv.EmailCodesSent(); n != 1 {
		t.Fatalf("email codes sent = %d, want 1", n)
	}
	if len(g.term.prompts) != 1 || g.term.prompts[0] != "Two-step login code:" {
		t.Fatalf("prompts = %q", g.term.prompts)
	}
}

func TestLoginYubiKeyOTPIsSubmittedWhole(t *testing.T) {
	otp := "cccccbhuinjgtvnkhlvrtcfgknbejnfrrhldkkubfebd"
	g := newGV(t)
	g.srv.Configure(func(c *fakeserver.Config) { c.TwoFactor = map[int]string{3: otp, 1: "x"} })
	g.env["PW"] = fakeserver.Password
	typed := strings.ToUpper(otp[:20]) + " " + otp[20:]
	g.mustRun("login", fakeserver.Email, "--passwordenv", "PW", "--method", "3", "--code", typed)
	if f := lastTokenForm(g.srv); f["twoFactorToken"] != otp {
		t.Fatalf("submitted OTP = %q", f["twoFactorToken"])
	}
}

func TestLoginTwoFactorWithoutInteraction(t *testing.T) {
	g := newGV(t)
	g.env["PW"] = fakeserver.Password
	g.srv.Configure(func(c *fakeserver.Config) { c.TwoFactor = map[int]string{0: "1", 1: "2"} })
	if r := g.run("login", fakeserver.Email, "--passwordenv", "PW", "--nointeraction"); r.code != 1 || r.err != "Login failed. No provider selected." {
		t.Fatalf("two providers = %+v", r)
	}
	g.srv.Configure(func(c *fakeserver.Config) { c.TwoFactor = map[int]string{0: "1"} })
	if r := g.run("login", fakeserver.Email, "--passwordenv", "PW", "--nointeraction"); r.code != 1 || r.err != "Code is required." {
		t.Fatalf("no code = %+v", r)
	}
	g.srv.Configure(func(c *fakeserver.Config) { c.TwoFactor = map[int]string{7: "webauthn"} })
	if r := g.run("login", fakeserver.Email, "--passwordenv", "PW"); r.err != "No providers available for this client." {
		t.Fatalf("unsupported provider = %+v", r)
	}
	if g.srv.EmailCodesSent() != 0 {
		t.Fatal("an email code was requested without being chosen")
	}
}

func TestLoginNewDeviceVerification(t *testing.T) {
	g := newGV(t)
	g.srv.Configure(func(c *fakeserver.Config) { c.NewDeviceOTP = "424242" })
	g.env["PW"] = fakeserver.Password

	// Without interaction gv reports the code is needed and exits, as bw
	// does; the server has already emailed one.
	if r := g.run("login", fakeserver.Email, "--passwordenv", "PW", "--nointeraction"); r.code != 1 || r.err != "Code is required." {
		t.Fatalf("no interaction = %+v", r)
	}
	// --code is a two-step code; it does not answer the device check.
	if r := g.run("login", fakeserver.Email, "--passwordenv", "PW", "--method", "0", "--code", "424242", "--nointeraction"); r.code != 1 || r.err != "Code is required." {
		t.Fatalf("--code = %+v", r)
	}

	g.term = &scriptedTerminal{answers: []string{"000000"}}
	if r := g.run("login", fakeserver.Email, "--passwordenv", "PW"); r.code != 1 || r.err != "invalid new device otp" {
		t.Fatalf("wrong code = %+v", r)
	}
	if len(g.term.prompts) != 1 || g.term.prompts[0] != "New device verification required. Enter OTP sent to login email:" {
		t.Fatalf("prompts = %q", g.term.prompts)
	}
	if st := g.mustRun("status"); !strings.Contains(st, `"status":"unauthenticated"`) {
		t.Fatalf("status after a wrong code = %s", st)
	}

	g.term = &scriptedTerminal{answers: []string{" 424242 "}}
	key := g.mustRun("login", fakeserver.Email, "--passwordenv", "PW", "--raw")
	if len(key) != 88 {
		t.Fatalf("session key = %q", key)
	}
	if f := lastTokenForm(g.srv); f["newDeviceOtp"] != "424242" || f["grant_type"] != "password" {
		t.Fatalf("verified login form = %v", f)
	}
	if n := g.srv.NewDeviceCodesSent(); n != 4 {
		t.Fatalf("codes issued = %d, want 4", n)
	}
	if n := g.srv.EmailCodesSent(); n != 0 {
		t.Fatalf("two-step emails = %d", n)
	}
}

// API keys and two-step accounts never meet the device check, and gv
// never sends newDeviceOtp unasked.
func TestLoginNewDeviceVerificationSkipped(t *testing.T) {
	g := newGV(t)
	g.srv.Configure(func(c *fakeserver.Config) { c.NewDeviceOTP = "424242" })
	g.env["BW_CLIENTID"], g.env["BW_CLIENTSECRET"] = fakeserver.ClientID, fakeserver.ClientSecret
	g.mustRun("login", "--apikey", "--nointeraction")
	g.mustRun("logout")
	delete(g.env, "BW_CLIENTID")
	delete(g.env, "BW_CLIENTSECRET")

	g.srv.Configure(func(c *fakeserver.Config) { c.TwoFactor = map[int]string{0: "012345"} })
	g.env["PW"] = fakeserver.Password
	g.mustRun("login", fakeserver.Email, "--passwordenv", "PW", "--method", "0", "--code", "012345", "--nointeraction")
	if n := g.srv.NewDeviceCodesSent(); n != 0 {
		t.Fatalf("codes issued = %d", n)
	}
	for _, r := range g.srv.Requests() {
		if _, ok := r.Form["newDeviceOtp"]; ok {
			t.Fatalf("newDeviceOtp sent: %v", r.Form)
		}
	}
}

func TestLockedReadPromptsForTheMasterPassword(t *testing.T) {
	g := newGV(t)
	g.login()
	delete(g.env, "BW_SESSION")
	g.term = &scriptedTerminal{answers: []string{fakeserver.Password}}
	out := g.mustRun("list", "folders")
	if !strings.Contains(out, `"name":"Work"`) || len(g.term.prompts) != 1 || g.term.prompts[0] != "Master password:" {
		t.Fatalf("out %q, prompts %q", out, g.term.prompts)
	}
}

func TestSessionOptionWinsOverEnvironment(t *testing.T) {
	g := newGV(t)
	key := g.login()
	g.env["BW_SESSION"] = "stale"
	g.mustRun("get", "username", fakeserver.ItemGitHub, "--session", key)
}

// Without a credential store an API-key login keeps no secret: a locked
// sync needs the key again, and an unlock adopts it.
func TestKeyringFreeHostFlow(t *testing.T) {
	g := newGV(t)
	g.ring = nil
	g.env["BW_CLIENTID"], g.env["BW_CLIENTSECRET"] = fakeserver.ClientID, fakeserver.ClientSecret
	g.mustRun("login", "--apikey", "--nointeraction")
	delete(g.env, "BW_CLIENTID")
	delete(g.env, "BW_CLIENTSECRET")
	if r := g.run("sync"); r.code != 1 || !strings.HasPrefix(r.err, "Syncing failed: No sign-in credentials") {
		t.Fatalf("locked sync = %+v", r)
	}
	g.env["BW_CLIENTID"], g.env["BW_CLIENTSECRET"] = fakeserver.ClientID, fakeserver.ClientSecret
	g.env["PW"] = fakeserver.Password
	g.env["BW_SESSION"] = g.mustRun("unlock", "--passwordenv", "PW", "--raw")
	delete(g.env, "BW_CLIENTID")
	delete(g.env, "BW_CLIENTSECRET")
	g.mustRun("sync", "-f")
	if got := g.mustRun("get", "password", fakeserver.ItemGitHub); got != "gh-secret" {
		t.Fatalf("password = %q", got)
	}
}

func TestSelfHostedBaseWithPath(t *testing.T) {
	g := newGV(t, fakeserver.WithPrefix("/vault"))
	g.login()
	g.mustRun("sync", "-f")
	for _, r := range g.srv.Requests() {
		if !strings.HasPrefix(r.Path, "/api/") && !strings.HasPrefix(r.Path, "/identity/") {
			t.Fatalf("request outside the base path: %s", r.Path)
		}
	}
}

func TestConfigWarnsAboutPlainHTTP(t *testing.T) {
	g := newGV(t)
	if r := g.run("config", "server", "http://vault.example.com"); r.code != 0 || !strings.Contains(r.err, "not HTTPS") {
		t.Fatalf("remote http = %+v", r)
	}
	if r := g.run("config", "server", "http://127.0.0.1:8080", "--nointeraction"); r.code != 0 || r.err != "" {
		t.Fatalf("loopback http = %+v", r)
	}
	if r := g.run("config", "server", "--key-connector", "https://kc.example.com"); r.code != 1 {
		t.Fatalf("--key-connector = %+v", r)
	}
}

func TestReadsSendNoVaultChanges(t *testing.T) {
	g := newGV(t)
	g.login()
	dir := t.TempDir()
	for _, args := range [][]string{
		{"list", "items"}, {"list", "org-collections", "--organizationid", fakeserver.OrgID}, {"get", "item", "github enterprise"},
		{"get", "totp", fakeserver.ItemGitHub}, {"get", "fingerprint", fakeserver.PeerUserID}, {"status"}, {"sync", "-f"},
		{"get", "attachment", fakeserver.AttachmentName, "--itemid", fakeserver.ItemGitHub, "--output", dir + "/"},
	} {
		g.mustRun(args...)
	}
	for _, r := range g.srv.Requests() {
		if r.Method != "GET" && !strings.HasPrefix(r.Path, "/identity/") {
			t.Errorf("%s %s changes server state", r.Method, r.Path)
		}
	}
	got, err := os.ReadFile(filepath.Join(dir, fakeserver.AttachmentName))
	if err != nil || string(got) != fakeserver.AttachmentBody {
		t.Fatalf("attachment = %q, %v", got, err)
	}
	if fi, _ := os.Stat(filepath.Join(dir, fakeserver.AttachmentName)); fi.Mode().Perm() != 0o600 {
		t.Fatalf("attachment mode = %v", fi.Mode())
	}
}

func TestAttachmentNeverWritesThroughASymlink(t *testing.T) {
	g := newGV(t)
	g.login()
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "out.txt")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	r := g.run("get", "attachment", fakeserver.AttachmentName, "--itemid", fakeserver.ItemGitHub, "--output", link)
	if r.code != 1 || !strings.Contains(r.err, "symbolic link") {
		t.Fatalf("symlink output = %+v", r)
	}
	if b, _ := os.ReadFile(victim); string(b) != "keep" {
		t.Fatal("the symlink target was overwritten")
	}
}

func TestServerFileNamesBecomeBaseNames(t *testing.T) {
	for in, want := range map[string]string{"../../etc/passwd": "passwd", `..\..\boot.ini`: "boot.ini", "report.pdf": "report.pdf"} {
		if got := safeFileName(in); got != want {
			t.Errorf("safeFileName(%q) = %q, want %q", in, got, want)
		}
	}
	if got := safeFileName(".."); !strings.HasPrefix(got, "BitwardenAttachment-") {
		t.Errorf("safeFileName(..) = %q", got)
	}
}

func TestTerminalOutputEndsLinesAndColors(t *testing.T) {
	g := newGV(t)
	g.tty = true
	if out := g.mustRun("config", "server", "--raw"); out != g.srv.URL()+"\n" {
		t.Fatalf("tty scalar = %q", out)
	}
	if r := g.run("lock"); r.err != "\x1b[91mYou are not logged in.\x1b[39m\n" {
		t.Fatalf("tty error = %q", r.err)
	}
	g.goos = "windows"
	if out := g.mustRun("config", "server"); out != g.srv.URL() {
		t.Fatalf("windows tty scalar = %q", out)
	}
}

func TestUnsupportedCommandsFailExplicitly(t *testing.T) {
	g := newGV(t)
	r := g.run("move", "x", "y", "eyJ9", "--organizationid", "x")
	if r.code != 1 || !strings.Contains(r.err, "`move` is not available in gv") {
		t.Fatalf("move = %+v", r)
	}
	r = g.run("send", "text", "--response")
	if r.code != 1 || !strings.HasPrefix(r.out, `{"success":false,"message":"`+"`send`") {
		t.Fatalf("send --response = %+v", r)
	}
	if r := g.run("get", "exposed", "x"); r.code != 1 || r.err == "" {
		t.Fatalf("get exposed = %+v", r)
	}
}

func TestVersionAndHelp(t *testing.T) {
	g := newGV(t)
	if out := g.mustRun("--version"); out != "9.9.9\n" {
		t.Fatalf("--version = %q", out)
	}
	if out := g.mustRun("list", "--help"); !strings.Contains(out, "Usage: gv list") {
		t.Fatalf("list --help = %q", out)
	}
	if r := g.run(); r.code != 1 || !strings.Contains(r.err, "Usage: gv") {
		t.Fatalf("no arguments = %+v", r)
	}
}

func TestGenerateMatchesBitwardenRules(t *testing.T) {
	g := newGV(t)
	classes := func(s string) (upper, lower, digit, other bool) {
		for _, r := range s {
			switch {
			case unicode.IsUpper(r):
				upper = true
			case unicode.IsLower(r):
				lower = true
			case unicode.IsDigit(r):
				digit = true
			default:
				other = true
			}
		}
		return
	}
	pw := g.mustRun("generate")
	if u, l, d, o := classes(pw); len(pw) != 14 || !u || !l || !d || o {
		t.Fatalf("default = %q", pw)
	}
	if pw := g.mustRun("generate", "--length", "3"); len(pw) != 5 {
		t.Fatalf("--length 3 = %q, want the minimum of 5", pw)
	}
	if pw := g.mustRun("generate", "-n", "--length", "30", "--ambiguous"); strings.ContainsAny(pw, "01") || len(pw) != 30 {
		t.Fatalf("--ambiguous digits = %q", pw)
	}
	if pw := g.mustRun("generate", "-s", "--minSpecial", "6", "--length", "6"); strings.Trim(pw, "!@#$%^&*") != "" {
		t.Fatalf("specials = %q", pw)
	}
	if pp := g.mustRun("generate", "-p", "--words", "2"); len(strings.Split(pp, "-")) != 3 {
		t.Fatalf("passphrase = %q, want the minimum of 3 words", pp)
	}
	if pp := g.mustRun("generate", "-p", "--separator", "space", "-c"); len(strings.Split(pp, " ")) != 6 || !unicode.IsUpper(rune(pp[0])) {
		t.Fatalf("passphrase = %q", pp)
	}
	if pp := g.mustRun("generate", "-p", "--separator", "_x"); len(strings.Split(pp, "_")) != 6 {
		t.Fatalf("separator = %q, want the first character", pp)
	}
}

func TestProfileDirectoryPerPlatform(t *testing.T) {
	for _, c := range []struct{ goos, want string }{
		{"darwin", "/home/u/Library/Application Support/GoVault CLI"},
		{"linux", "/home/u/.config/GoVault CLI"},
		{"windows", filepath.Join(`C:\Users\u\AppData\Roaming`, "GoVault CLI")},
	} {
		env := map[string]string{"HOME": "/home/u", "APPDATA": `C:\Users\u\AppData\Roaming`}
		a := &app{env: &Environment{GOOS: c.goos, Getenv: func(k string) string { return env[k] }}}
		if got, _ := a.profileDir(); got != c.want {
			t.Errorf("%s: %q, want %q", c.goos, got, c.want)
		}
	}
	env := map[string]string{"HOME": "/home/u", "XDG_CONFIG_HOME": "/xdg"}
	a := &app{env: &Environment{GOOS: "linux", Getenv: func(k string) string { return env[k] }}}
	if got, _ := a.profileDir(); got != "/xdg/GoVault CLI" {
		t.Errorf("XDG_CONFIG_HOME: %q", got)
	}
}

// Without permission data from the server, organization items hide their
// passwords; personal items do not.
func TestMissingPermissionsHideOrganizationPasswords(t *testing.T) {
	g := newGV(t)
	g.srv.Configure(func(c *fakeserver.Config) { c.OmitPermissions = true })
	g.login()
	if r := g.run("get", "password", fakeserver.ItemOrgShared); r.code != 1 || r.err != "No password available for this login." {
		t.Fatalf("org item = %+v", r)
	}
	if out := g.mustRun("get", "password", fakeserver.ItemGitHubEnt); out != "ghe-secret" {
		t.Fatalf("personal item = %q", out)
	}
}

// Endpoint overrides route the API and identity services and bind the
// sign-in to them.
func TestConfigServerOverridesRouteServices(t *testing.T) {
	g := newGV(t)
	if r := g.run("config", "server", "https://unused.example.com", "--api", g.srv.URL()+"/api", "--identity", g.srv.URL()+"/identity"); r.code != 0 || r.err != "" {
		t.Fatalf("config = %+v", r)
	}
	g.login()
	if out := g.mustRun("get", "username", fakeserver.ItemGitHub); out != "alice" {
		t.Fatalf("username = %q", out)
	}
	if r := g.run("config", "server", "--api", "http://api.example.com"); r.err != "Logout required before server config update." {
		t.Fatalf("config while logged in = %+v", r)
	}
}

// Accounts without premium get TOTP codes too, as in the GoVault app.
func TestTOTPCodesWithoutPremium(t *testing.T) {
	g := newGV(t)
	g.srv.Configure(func(c *fakeserver.Config) { c.Premium = false })
	g.login()
	got := g.mustRun("get", "totp", fakeserver.ItemGitHub)
	cfg, err := totp.ParseTOTP(fakeserver.TOTPSecret)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	want, _, _, _ := totp.Generate(cfg, now)
	prev, _, _, _ := totp.Generate(cfg, now.Add(-30*time.Second))
	if len(got) != 6 || (got != want && got != prev) {
		t.Fatalf("totp = %q, want %q", got, want)
	}
}
