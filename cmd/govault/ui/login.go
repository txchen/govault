package ui

import (
	"github.com/nsgo-dev/nsgo/base"
	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/icons/lucide"
	"github.com/nsgo-dev/nsgo/ui"
	"github.com/txchen/govault/cmd/govault/locales"
	"github.com/txchen/govault/internal/vaultcore/api"
	"strings"
)

const authFieldHeight core.Points = 34

func LoginView(cx *core.Scope, m *AppModel) core.Node {
	return core.Dynamic(func(cx *core.Scope) core.Node {
		if prompt := m.NewDevice.Get(); prompt != nil {
			return NewDeviceView(cx, m, prompt)
		}
		if prompt := m.TwoFactor.Get(); prompt != nil {
			return TwoFactorView(cx, m, prompt)
		}
		if m.SSOWaiting.Get() {
			return ssoWaitingView(cx, m)
		}
		return signInView(cx, m)
	})
}

func ssoWaitingView(cx *core.Scope, m *AppModel) core.Node {
	return authScreen("sso-waiting-screen", []core.Node{
		core.View{
			Class: "items-center gap-2.5 pb-1",
			Children: []core.Node{
				core.View{
					Class: "w-[56px] h-[56px] rounded-[16px] items-center justify-center bg-gv-fill border border-gv-line",
					Style: core.Style{BorderCurve: core.BorderCurveContinuous},
					Children: []core.Node{
						icon(lucide.Globe(), 24, "text-gv-accent"),
					},
				},
				core.Text{Class: "mt-1.5 text-[19px] font-semibold text-gv-fg text-center", Content: locales.SsoWaitingTitle(cx)},
				core.Text{
					Class:   "text-[12.5px] text-gv-fg2 text-center",
					Content: locales.SsoWaitingDetail(cx),
				},
			},
		},
		core.View{
			Class: "gap-2",
			Children: []core.Node{
				ui.Button{
					TestID:  "sso-reopen",
					Text:    locales.SsoOpenBrowserAgain(cx),
					Icon:    lucide.ExternalLink,
					Variant: ui.ButtonSecondary,
					Size:    ui.SizeLarge,
					Style:   core.Style{Width: core.Pct(100)},
					OnPress: func() { m.ReopenSSOBrowser(cx) },
				},
				ui.Button{
					TestID:  "sso-cancel",
					Text:    locales.Cancel(cx),
					Variant: ui.ButtonGhost,
					Size:    ui.SizeLarge,
					Style:   core.Style{Width: core.Pct(100)},
					OnPress: m.CancelSSO,
				},
			},
		},
	}, locales.SignInFootnote(cx))
}

func signInView(cx *core.Scope, m *AppModel) core.Node {
	// The server choice starts from the saved server and then changes only
	// when the user picks one: typing a URL that happens to read as a
	// cloud server stays self-hosted.
	m.LoginPreset.Set(ServerPresetOf(m.LoginServer.GetUntracked()))
	return authScreen("login-screen", []core.Node{
		core.View{
			Class: "items-center gap-2.5 pb-1",
			Children: []core.Node{
				brandEmblem(56),
				core.Text{Class: "mt-1.5 text-[19px] font-semibold text-gv-fg", Content: locales.SignInTitle(cx)},
				core.Text{
					Class:   "text-[12.5px] text-gv-fg2 text-center",
					Content: locales.SignInSubtitle(cx),
				},
			},
		},
		core.View{
			Class: "gap-3.5",
			Children: []core.Node{
				serverPresets(cx, m),
				core.Show{
					When: func() bool { return m.LoginPreset.Get() == PresetSelfHosted },
					Then: func(cx *core.Scope) core.Node {
						return formField(locales.ServerURL(cx), authInput(base.Input{
							TestID:        "login-server",
							Placeholder:   "https://vault.example.com",
							NoAutoCorrect: true,
							Value:         m.LoginServer.Get,
							OnChange:      m.LoginServer.Set,
							Disabled:      m.serverLocked,
						}))
					},
				},
				formField(locales.Email(cx), authInput(base.Input{
					TestID:        "login-email",
					Placeholder:   locales.EmailPlaceholder(cx),
					NoAutoCorrect: true,
					Value:         m.LoginEmail.Get,
					OnChange:      m.LoginEmail.Set,
					Disabled:      func() bool { return m.LoginBusy.Get() || m.CanReturnToUnlock() },
				})),
				formField(locales.MasterPassword(cx), passwordField(cx, base.Input{
					TestID:        "login-password",
					Placeholder:   locales.Required(cx),
					NoAutoCorrect: true,
					Value:         m.LoginPassword.Get,
					OnChange:      m.LoginPassword.Set,
					OnSubmit:      func(string) { m.Login() },
					Disabled:      m.LoginBusy.Get,
				}, authFieldHeight, m.LoginShowPW, "login-toggle-pw")),
			},
		},
		core.Show{
			When: func() bool { return api.InsecureServer(m.LoginServer.Get()) },
			Then: func(cx *core.Scope) core.Node {
				return core.Text{
					TestID:  "login-insecure",
					Class:   "text-[12px] text-gv-warn",
					Content: locales.InsecureServer(cx),
				}
			},
		},
		core.Show{
			When: func() bool { return m.LoginError.Get() != "" },
			Then: func(cx *core.Scope) core.Node { return errorBanner("login-error", m.LoginError.Get) },
		},
		core.View{
			Class: "gap-3",
			Children: []core.Node{
				ui.Button{
					TestID:  "login-submit",
					Text:    locales.SignIn(cx),
					Variant: ui.ButtonPrimary,
					Size:    ui.SizeLarge,
					Busy:    m.LoginBusy.Get,
					Style:   core.Style{Width: core.Pct(100)},
					OnPress: m.Login,
				},
				core.View{
					Class: "flex-row items-center gap-2.5",
					Children: []core.Node{
						core.View{Class: "flex-1 h-px bg-gv-line"},
						core.Text{Class: "text-[11px] text-gv-fg3", Content: locales.OrSignInWith(cx)},
						core.View{Class: "flex-1 h-px bg-gv-line"},
					},
				},
				ui.Button{
					TestID:   "login-sso",
					Text:     locales.SignInWithSSO(cx),
					Icon:     lucide.Globe,
					Variant:  ui.ButtonSecondary,
					Size:     ui.SizeLarge,
					Disabled: m.LoginBusy.Get,
					Style:    core.Style{Width: core.Pct(100)},
					OnPress:  func() { m.LoginWithSSO(cx) },
				},
			},
		},
		core.Show{
			When: m.CanReturnToUnlock,
			Then: func(cx *core.Scope) core.Node {
				return ui.Button{
					TestID:  "login-back-to-unlock",
					Text:    locales.BackToUnlock(cx),
					Variant: ui.ButtonGhost,
					Size:    ui.SizeLarge,
					Style:   core.Style{Width: core.Pct(100)},
					OnPress: m.BackToUnlock,
				}
			},
		},
	}, locales.SignInFootnote(cx))
}

// ServerPreset is a server the sign-in screen offers by name.
type ServerPreset int

const (
	PresetSelfHosted ServerPreset = iota
	PresetUS
	PresetEU
)

// presetURLs are the cloud servers' web vaults, which resolve to their API
// and identity hosts as gv's cloud regions do.
var presetURLs = map[ServerPreset]string{PresetUS: "https://vault.bitwarden.com", PresetEU: "https://vault.bitwarden.eu"}

// ServerPresetOf is the preset a server URL is, or PresetSelfHosted.
func ServerPresetOf(server string) ServerPreset {
	e, err := api.ResolveEndpoints(api.FormatServerURL(server))
	switch {
	case strings.TrimSpace(server) == "" || err != nil:
		return PresetSelfHosted
	case e.Identity == "https://identity.bitwarden.com":
		return PresetUS
	case e.Identity == "https://identity.bitwarden.eu":
		return PresetEU
	}
	return PresetSelfHosted
}

// serverLocked: the server cannot change while signing in, or when signing
// in again to the account the vault on this device belongs to.
func (m *AppModel) serverLocked() bool {
	return m.LoginBusy.Get() || (m.CanReturnToUnlock() && m.ReSignInServer.Get() != "")
}

// SetServerPreset signs in to a cloud preset's server, or clears the
// server for a self-hosted one, unless the server is that preset already.
func (m *AppModel) SetServerPreset(p ServerPreset) {
	m.LoginPreset.Set(p)
	if ServerPresetOf(m.LoginServer.Get()) != p {
		m.LoginServer.Set(presetURLs[p])
	}
}

// serverPresets chooses the server, full width as the card's fields are, so
// every language fits.
func serverPresets(cx *core.Scope, m *AppModel) core.Node {
	return formField(locales.Server(cx), ui.Select[ServerPreset]{
		TestID: "login-server-preset",
		Label:  locales.Server(cx),
		Style:  core.Style{Width: core.Pct(100), Height: core.Pt(authFieldHeight)},
		Options: []ui.Option[ServerPreset]{
			{Value: PresetUS, Label: locales.ServerBitwardenUS(cx)},
			{Value: PresetEU, Label: locales.ServerBitwardenEU(cx)},
			{Value: PresetSelfHosted, Label: locales.SelfHosted(cx)},
		},
		Value:    m.LoginPreset.Get,
		OnChange: m.SetServerPreset,
		Disabled: m.serverLocked,
	})
}

func authScreen(testID string, body []core.Node, footnote string) core.Node {
	return core.View{
		TestID: testID,
		Class:  "flex-1 bg-gv-canvas",
		Children: []core.Node{
			core.View{Style: core.Style{Height: core.Pt(titleBarHeight)}, Desktop: dragRegion()},
			core.View{
				Class: "flex-1 items-center justify-center px-8 pb-[52px] gap-5",
				Children: []core.Node{
					core.View{
						Class: "w-[380px] px-8 pt-8 pb-7 gap-5 rounded-[16px] bg-gv-card border border-gv-line",
						Style: core.Style{
							BorderCurve: core.BorderCurveContinuous,
							Shadows: []core.BoxShadow{
								ui.Shadow(0, 1, 3, 0, core.RGBA(0x000000, 0.05)),
								ui.Shadow(0, 18, 40, -16, core.RGBA(0x000000, 0.22)),
							},
						},
						Children: body,
					},
					core.View{
						Class: "flex-row items-center gap-1.5",
						Children: []core.Node{
							icon(lucide.LockKeyhole(), 11, "text-gv-fg3"),
							core.Text{Class: "text-[11.5px] text-gv-fg3", Content: footnote},
						},
					},
				},
			},
		},
	}
}

func formField(label string, field core.Node) core.Node {
	return core.View{
		Class: "gap-1.5",
		Children: []core.Node{
			core.Text{Class: "text-[12px] font-medium text-gv-fg2", Content: label},
			field,
		},
	}
}

func sizedInput(in base.Input, height core.Points) ui.Input {
	in.Style = core.Style{Height: core.Pt(height), FontSize: 13, CornerRadius: 7}.Merge(in.Style)
	return ui.Input(in)
}

func authInput(in base.Input) core.Node { return sizedInput(in, authFieldHeight) }

// passwordField is a masked input with a reveal toggle and optional trailing controls inside its rim.
func passwordField(cx *core.Scope, in base.Input, height core.Points, show *core.Signal[bool], toggleTestID string, trailing ...core.Node) core.Node {
	inset := core.Points(34 + 28*len(trailing))
	controls := []core.Node{
		ui.Button{
			TestID:   toggleTestID,
			Variant:  ui.ButtonGhost,
			Icon:     func() *core.SVG { return eyeIcon(show.Get()) },
			Label:    locales.TogglePasswordVisibility(cx),
			Side:     height - 8,
			IconSize: 14,
			Tint:     func() core.Color { return themeColor(cx, "gv-fg3") },
			Disabled: in.Disabled,
			OnPress:  func() { show.Set(!show.Get()) },
		},
	}
	controls = append(controls, trailing...)
	return core.View{
		Class: "relative",
		Children: []core.Node{
			core.Dynamic(func(cx *core.Scope) core.Node {
				field := in
				field.Masked = !show.Get()
				field.OnBlur = settleSecureInput
				field.Style = core.Style{Padding: core.Edges{Left: 10, Right: inset}}.Merge(field.Style)
				return sizedInput(field, height)
			}),
			core.View{
				Class:    "absolute right-1 top-0 bottom-0 flex-row items-center gap-0.5",
				Children: controls,
			},
		},
	}
}

func eyeIcon(visible bool) *core.SVG {
	if visible {
		return lucide.EyeOff()
	}
	return lucide.Eye()
}
