// Package cli implements gv, GoVault's command-line client. Its
// commands, flags, environment variables and output follow the official
// Bitwarden CLI (bw), so scripts written for bw run with gv.
package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/txchen/govault/internal/vaultcore/keyring"
	"github.com/txchen/govault/internal/vaultcore/profile"
)

// Environment is everything gv reads from and writes to the outside
// world, so tests can run it in process.
type Environment struct {
	Args   []string
	Getenv func(string) string
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	// StdinTTY and the others say whether each stream is a terminal.
	StdinTTY, StdoutTTY, StderrTTY bool
	// Terminal reads masked input; nil when stdin is not a terminal.
	Terminal Terminal
	// Keyring opens the credential store, which may be unavailable; nil
	// means there is none.
	Keyring    func() (keyring.Store, error)
	HTTPClient *http.Client
	// OpenURL opens a URL in the user's browser for interactive flows such
	// as SSO. When nil, Run uses the platform's browser launcher.
	OpenURL func(string) error
	// SSOCallbackPorts overrides the localhost callback port range for SSO
	// tests; zero uses api.SSOCallbackPortMin..api.SSOCallbackPortMax.
	SSOCallbackPorts [2]int
	Version          string
	// GOOS selects platform defaults; runtime.GOOS when empty.
	GOOS string
	Now  func() time.Time
	Ctx  context.Context
}

// Terminal prompts on the terminal.
type Terminal interface {
	// ReadLine shows prompt on stderr and reads a visible line.
	ReadLine(prompt string) (string, error)
	// ReadSecret shows prompt and reads a line without echo.
	ReadSecret(prompt string) (string, error)
}

// flags are the global options, and the BW_* variables they set.
type flags struct {
	pretty, raw, response, quiet, noInteraction, cleanExit bool
	session                                                string
}

type app struct {
	env   *Environment
	flags flags
	ctx   context.Context
	prof  *profile.Profile
}

// Run executes gv with env and returns the exit status.
func Run(env *Environment) int {
	if env.Getenv == nil {
		env.Getenv = func(string) string { return "" }
	}
	if env.GOOS == "" {
		env.GOOS = runtime.GOOS
	}
	if env.Now == nil {
		env.Now = time.Now
	}
	a := &app{env: env, ctx: env.Ctx}
	if a.ctx == nil {
		a.ctx = context.Background()
	}
	return a.run(env.Args)
}

func (a *app) getenv(k string) string { return a.env.Getenv(k) }

func (a *app) loadFlags(p *parsed) {
	f := &a.flags
	f.pretty = p.has("pretty") || a.getenv("BW_PRETTY") == "true"
	f.raw = p.has("raw") || a.getenv("BW_RAW") == "true"
	f.response = p.has("response") || a.getenv("BW_RESPONSE") == "true"
	f.quiet = p.has("quiet") || a.getenv("BW_QUIET") == "true"
	f.noInteraction = p.has("nointeraction") || a.getenv("BW_NOINTERACTION") == "true"
	f.cleanExit = p.has("cleanexit") || a.getenv("BW_CLEANEXIT") != ""
	f.session = a.getenv("BW_SESSION")
	if s, ok := p.opts["session"]; ok {
		f.session = s
	}
}

// canPrompt reports whether gv may ask the user.
func (a *app) canPrompt() bool { return !a.flags.noInteraction && a.env.Terminal != nil }

// profileDir is where gv keeps its state: a "GoVault CLI" directory
// beside Bitwarden CLI's, or inside BITWARDENCLI_APPDATA_DIR when set.
func (a *app) profileDir() (string, error) {
	const name = "GoVault CLI"
	if d := a.getenv("BITWARDENCLI_APPDATA_DIR"); d != "" {
		abs, err := filepath.Abs(d)
		if err != nil {
			return "", err
		}
		return filepath.Join(abs, name), nil
	}
	switch a.env.GOOS {
	case "darwin":
		home := a.getenv("HOME")
		if home == "" {
			return "", fmt.Errorf("HOME is not set")
		}
		return filepath.Join(home, "Library", "Application Support", name), nil
	case "windows":
		appData := a.getenv("APPDATA")
		if appData == "" {
			return "", fmt.Errorf("APPDATA is not set")
		}
		return filepath.Join(appData, name), nil
	}
	if x := a.getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, name), nil
	}
	home := a.getenv("HOME")
	if home == "" {
		return "", fmt.Errorf("HOME is not set")
	}
	return filepath.Join(home, ".config", name), nil
}

func (a *app) deviceType() int {
	switch a.env.GOOS {
	case "darwin":
		return 24
	case "windows":
		return 23
	}
	return 25
}

// openProfile opens the profile, once per run.
func (a *app) openProfile() (*profile.Profile, error) {
	if a.prof != nil {
		return a.prof, nil
	}
	dir, err := a.profileDir()
	if err != nil {
		return nil, err
	}
	var store keyring.Store
	if a.env.Keyring != nil {
		if s, err := a.env.Keyring(); err == nil {
			store = s
		} else if !errors.Is(err, keyring.ErrUnavailable) {
			return nil, err
		}
	}
	p, err := profile.Open(dir, profile.Options{
		Keyring:    store,
		HTTPClient: a.env.HTTPClient,
		DeviceName: "GoVault CLI",
		DeviceType: a.deviceType(),
		ClientName: "cli",
		UserAgent:  "GoVault-CLI/" + a.env.Version,
		Now:        a.env.Now,
	})
	if err != nil {
		return nil, err
	}
	a.prof = p
	return p, nil
}

// render prints r as bw's processResponse does and returns the exit status.
func (a *app) render(r response) int {
	f := a.flags
	if !r.success {
		if !f.quiet {
			if f.response {
				a.writeLn(a.env.Stdout, a.env.StdoutTTY, a.json(r.envelope()), true)
			} else {
				a.writeLn(a.env.Stderr, a.env.StderrTTY, a.color(r.message, "91"), true)
			}
		}
		if f.cleanExit {
			return 0
		}
		return 1
	}
	if f.response {
		a.writeLn(a.env.Stdout, a.env.StdoutTTY, a.json(r.envelope()), true)
		return 0
	}
	var out *string
	switch d := r.data.(type) {
	case nil, fileWritten:
	case templateData:
		out = ptr(a.json(d.template))
	case stringData:
		out = d.value
	case listData:
		out = ptr(a.json([]any(d)))
	case message:
		out = a.message(d)
	default:
		out = ptr(a.json(d))
	}
	if out != nil && !f.quiet {
		a.writeLn(a.env.Stdout, a.env.StdoutTTY, *out, true)
	}
	return 0
}

func (a *app) message(m message) *string {
	if a.flags.raw {
		return m.raw
	}
	out := m.title
	if !m.noColor {
		out = a.color(m.title, "92")
	}
	if m.text != nil {
		out += "\n" + *m.text
	}
	if strings.TrimSpace(out) == "" {
		return nil
	}
	return &out
}

// color wraps s in an ANSI color when stderr or stdout is a terminal, as
// chalk does.
func (a *app) color(s, code string) string {
	if (!a.env.StdoutTTY && !a.env.StderrTTY) || a.getenv("NO_COLOR") != "" {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[39m"
}

func (a *app) json(v any) string {
	raw, err := marshal(v)
	if err != nil {
		return fmt.Sprintf("%q", err.Error())
	}
	if !a.flags.pretty {
		return string(raw)
	}
	var buf bytes.Buffer
	if err := json.Indent(&buf, raw, "", "  "); err != nil {
		return string(raw)
	}
	return buf.String()
}

// writeLn writes s, ending it with a newline unless it is the last output
// to a stream that is not a terminal, or the platform is Windows.
func (a *app) writeLn(w io.Writer, tty bool, s string, final bool) {
	if final && (a.env.GOOS == "windows" || !tty) {
		_, _ = io.WriteString(w, s)
		return
	}
	_, _ = io.WriteString(w, s+"\n")
}

// warn prints a warning line on stderr, as bw's log service does.
func (a *app) warn(s string) {
	_, _ = io.WriteString(a.env.Stderr, s+"\n")
}

// StdEnvironment is the process's real environment.
func StdEnvironment(version string) *Environment {
	env := &Environment{
		Args:      os.Args[1:],
		Getenv:    os.Getenv,
		Stdin:     os.Stdin,
		Stdout:    os.Stdout,
		Stderr:    os.Stderr,
		StdinTTY:  isTerminal(os.Stdin),
		StdoutTTY: isTerminal(os.Stdout),
		StderrTTY: isTerminal(os.Stderr),
		Version:   version,
	}
	if env.StdinTTY {
		env.Terminal = newTerminal(os.Stdin, os.Stderr)
	}
	env.Keyring = keyring.System
	env.OpenURL = func(raw string) error { return openBrowserURL(runtime.GOOS, raw) }
	return env
}

func openBrowserURL(goos, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("invalid browser URL")
	}
	var cmd *exec.Cmd
	switch goos {
	case "darwin":
		cmd = exec.Command("open", raw)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", raw)
	default:
		cmd = exec.Command("xdg-open", raw)
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return err
	case <-time.After(250 * time.Millisecond):
		return nil
	}
}
