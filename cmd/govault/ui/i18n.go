package ui

import (
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/nsgo-dev/nsgo/core"
	"github.com/txchen/govault/cmd/govault/locales"
	"github.com/txchen/govault/internal/vaultcore/api"
	"github.com/txchen/govault/internal/vaultcore/crypto"
	"github.com/txchen/govault/internal/vaultcore/export"
	"github.com/txchen/govault/internal/vaultcore/sshagent"
	"github.com/txchen/govault/internal/vaultcore/state"
)

// Language is a language GoVault can show, by its BCP 47 tag and its name
// in itself.
type Language struct {
	Tag, Name string
}

// Languages are the languages the language setting offers, each named in
// itself so a user can find their own whatever the app shows.
var Languages = []Language{
	{"en", "English"},
	{"zh-Hans", "简体中文"},
	{"zh-Hant", "繁體中文"},
	{"ja", "日本語"},
	{"ko", "한국어"},
	{"de", "Deutsch"},
	{"fr", "Français"},
	{"es", "Español"},
	{"pt-BR", "Português (Brasil)"},
	{"ru", "Русский"},
}

// SetLanguage shows GoVault in lang, one of Languages' tags, or in the
// system's language for "", and keeps the choice for later launches.
func (m *AppModel) SetLanguage(lang string) {
	m.UpdatePrefs(func(p UserPrefs) UserPrefs {
		p.Language = lang
		return p
	})
	m.Scope.SetLocale(lang)
}

// appearanceOf is the appearance a preference names: light, dark, or the
// system's for anything else.
func appearanceOf(pref string) core.Appearance {
	switch pref {
	case "light":
		return core.AppearanceLight
	case "dark":
		return core.AppearanceDark
	}
	return core.AppearanceSystem
}

// SetAppearance shows GoVault light, dark, or as the system does for "",
// and keeps the choice for later launches.
func (m *AppModel) SetAppearance(pref string) {
	m.UpdatePrefs(func(p UserPrefs) UserPrefs {
		p.Appearance = pref
		return p
	})
	m.Scope.SetAppearance(appearanceOf(pref))
}

// RepromptAction is what the master password reprompt protects, which its
// dialog and biometric prompt name.
type RepromptAction string

const (
	RepromptContinue            RepromptAction = ""
	RepromptCopyPassword        RepromptAction = "copyPassword"
	RepromptRevealPassword      RepromptAction = "revealPassword"
	RepromptCopyTOTP            RepromptAction = "copyTOTP"
	RepromptRevealTOTP          RepromptAction = "revealTOTP"
	RepromptRevealCardNumber    RepromptAction = "revealCardNumber"
	RepromptCopyCardNumber      RepromptAction = "copyCardNumber"
	RepromptRevealSecurityCode  RepromptAction = "revealSecurityCode"
	RepromptCopySecurityCode    RepromptAction = "copySecurityCode"
	RepromptRevealSSN           RepromptAction = "revealSSN"
	RepromptCopySSN             RepromptAction = "copySSN"
	RepromptRevealField         RepromptAction = "revealField"
	RepromptCopyField           RepromptAction = "copyField"
	RepromptRevealPrivateKey    RepromptAction = "revealPrivateKey"
	RepromptCopyPrivateKey      RepromptAction = "copyPrivateKey"
	RepromptRevealOldPassword   RepromptAction = "revealOldPassword"
	RepromptCopyOldPassword     RepromptAction = "copyOldPassword"
	RepromptEditItem            RepromptAction = "editItem"
	RepromptCloneItem           RepromptAction = "cloneItem"
	RepromptArchiveItem         RepromptAction = "archiveItem"
	RepromptUnarchiveItem       RepromptAction = "unarchiveItem"
	RepromptDownloadAttachment  RepromptAction = "downloadAttachment"
	RepromptExportVault         RepromptAction = "exportVault"
	RepromptUpdateProtectedItem RepromptAction = "updateProtectedItem"
)

// CipherTypeLabel names an item type in the language shown under cx.
func CipherTypeLabel(cx *core.Scope, t api.CipherType) string {
	switch t {
	case api.CipherTypeLogin:
		return locales.TypeLogin(cx)
	case api.CipherTypeSecureNote:
		return locales.TypeSecureNote(cx)
	case api.CipherTypeCard:
		return locales.TypeCard(cx)
	case api.CipherTypeIdentity:
		return locales.TypeIdentity(cx)
	case api.CipherTypeSSHKey:
		return locales.TypeSSHKey(cx)
	default:
		return locales.TypeItem(cx)
	}
}

// cipherTypeKey is the select key the catalog's messages take per type.
func cipherTypeKey(t api.CipherType) string {
	switch t {
	case api.CipherTypeLogin:
		return "login"
	case api.CipherTypeSecureNote:
		return "secureNote"
	case api.CipherTypeCard:
		return "card"
	case api.CipherTypeIdentity:
		return "identity"
	case api.CipherTypeSSHKey:
		return "sshKey"
	}
	return "item"
}

func twoFactorProviderName(cx *core.Scope, p api.TwoFactorProvider) string {
	switch p {
	case api.TwoFactorAuthenticator:
		return locales.TwoFactorAuthenticator(cx)
	case api.TwoFactorEmail:
		return locales.TwoFactorEmail(cx)
	case api.TwoFactorDuo:
		return locales.TwoFactorDuo(cx)
	case api.TwoFactorYubiKey:
		return locales.TwoFactorYubiKey(cx)
	case api.TwoFactorU2F:
		return locales.TwoFactorU2F(cx)
	case api.TwoFactorRemember:
		return locales.TwoFactorRememberedDevice(cx)
	case api.TwoFactorOrganizationDuo:
		return locales.TwoFactorOrganizationDuo(cx)
	case api.TwoFactorWebAuthn:
		return locales.TwoFactorWebAuthn(cx)
	}
	return locales.TwoFactorOtherProvider(cx, int(p))
}

// formatRelativeTime says how long ago t was, or its date after a week.
func formatRelativeTime(cx *core.Scope, t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return locales.JustNow(cx)
	case d < time.Hour:
		return locales.MinutesAgo(cx, int(d.Minutes()))
	case d < 24*time.Hour:
		return locales.HoursAgo(cx, int(d.Hours()))
	case d < 7*24*time.Hour:
		return locales.DaysAgo(cx, int(d.Hours()/24))
	}
	return locales.ShortDate(cx, t.Local())
}

// KDFSummary describes an account's key derivation settings.
func KDFSummary(cx *core.Scope, kdf crypto.KDFConfig) string {
	if kdf.Type == crypto.KDFArgon2id {
		return locales.KdfArgon2id(cx, int(kdf.MemoryMB), int(kdf.Iterations), int(kdf.Parallelism))
	}
	return locales.KdfPBKDF2(cx, int(kdf.Iterations))
}

func formatByteSize(cx *core.Scope, n int64) string {
	const unit = 1024
	if n < unit {
		return locales.Bytes(cx, int(n))
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit && exp < 3; v /= unit {
		div *= unit
		exp++
	}
	size := float64(n) / float64(div)
	switch exp {
	case 0:
		return locales.Kilobytes(cx, size)
	case 1:
		return locales.Megabytes(cx, size)
	case 2:
		return locales.Gigabytes(cx, size)
	}
	return locales.Terabytes(cx, size)
}

// joinList joins the parts of a list GoVault builds, such as field
// names; the comma reads naturally in the languages GoVault ships.
func joinList(items []string) string { return strings.Join(items, ", ") }

// errorText says what went wrong in err, in the language shown: a message
// of its own for the errors the vault reports, else a general one with
// the error's technical detail.
func errorText(cx *core.Scope, err error) string {
	if err == nil {
		return ""
	}
	var apiErr *api.APIError
	switch {
	case errors.Is(err, api.ErrTwoFactorRequired):
		return locales.ErrorTwoFactorRequired(cx)
	case errors.Is(err, api.ErrUnauthorized):
		return locales.ErrorUnauthorized(cx)
	case errors.Is(err, api.ErrNetworkOffline):
		return locales.ErrorOffline(cx)
	case errors.Is(err, api.ErrRedirectRefused):
		return locales.ErrorRedirect(cx)
	case errors.Is(err, api.ErrRevisionConflict):
		return locales.ErrorRevisionConflict(cx)
	case errors.Is(err, api.ErrAttachmentTooLarge):
		return locales.ErrorAttachmentTooLarge(cx)
	case errors.Is(err, api.ErrSSOCallbackPortUnavailable):
		return locales.ErrorSSOCallbackPortUnavailable(cx)
	case errors.Is(err, api.ErrSSOStateMismatch):
		return locales.ErrorSSOStateMismatch(cx)
	case errors.Is(err, crypto.ErrInvalidMAC):
		return locales.IncorrectMasterPassword(cx)
	case errors.Is(err, state.ErrArchiveUnsupported):
		return locales.ErrorArchiveUnsupported(cx)
	case errors.Is(err, state.ErrPremiumRequired):
		return locales.ErrorPremiumRequired(cx)
	case errors.Is(err, state.ErrAccountIDUnknown):
		return locales.ErrorAccountIDUnknown(cx)
	case errors.Is(err, state.ErrArchiveNotConfirmed):
		return locales.ErrorArchiveNotConfirmed(cx)
	case errors.Is(err, state.ErrCipherInTrash):
		return locales.ErrorCipherInTrash(cx)
	case errors.Is(err, state.ErrLocked):
		return locales.ErrorLocked(cx)
	case errors.Is(err, state.ErrLoggedOut):
		return locales.ErrorLoggedOut(cx)
	case errors.Is(err, state.ErrCipherNotFound):
		return locales.ErrorCipherNotFound(cx)
	case errors.Is(err, state.ErrFolderNotFound):
		return locales.ErrorFolderNotFound(cx)
	case errors.Is(err, state.ErrReadOnlyCipher):
		return locales.ErrorReadOnly(cx)
	case errors.Is(err, state.ErrOrganizationKeyMissing):
		return locales.ErrorOrganizationKey(cx)
	case errors.Is(err, state.ErrAttachmentNotFound):
		return locales.ErrorAttachmentNotFound(cx)
	case errors.Is(err, state.ErrHiddenByOrganization):
		return locales.ErrorHiddenByOrganization(cx)
	case errors.Is(err, state.ErrUnsupportedUpload):
		return locales.ErrorUnsupportedUpload(cx)
	case errors.Is(err, state.ErrServerMismatch):
		return locales.ErrorServerMismatch(cx)
	case errors.Is(err, state.ErrSignInRequired):
		return locales.ErrorSignInRequired(cx)
	case errors.Is(err, state.ErrDifferentAccount):
		return locales.ErrorDifferentAccount(cx)
	case errors.Is(err, state.ErrSSOMasterPasswordRequired):
		return locales.ErrorSSOMasterPasswordRequired(cx)
	case errors.Is(err, state.ErrSSOForcePasswordReset):
		return locales.ErrorSSOForcePasswordReset(cx)
	case errors.Is(err, state.ErrSSOKeyConnectorUnsupported):
		return locales.ErrorSSOKeyConnectorUnsupported(cx)
	case errors.Is(err, state.ErrSSOTrustedDeviceUnsupported):
		return locales.ErrorSSOTrustedDeviceUnsupported(cx)
	case errors.Is(err, state.ErrAccountChanged):
		return locales.ErrorAccountChanged(cx)
	case errors.Is(err, state.ErrSnapshotNotUpdated):
		return locales.ErrorSnapshotNotUpdated(cx)
	case errors.Is(err, state.ErrSealedField):
		return locales.ErrorSealedField(cx)
	case errors.Is(err, state.ErrUnsupportedCipherFormat):
		return locales.ErrorUnsupportedCipher(cx)
	case errors.Is(err, export.ErrChangedSinceReview):
		return locales.ErrorChangedSinceReview(cx)
	case errors.Is(err, export.ErrRepromptRequired):
		return locales.ErrorRepromptRequired(cx)
	case errors.Is(err, export.ErrUnsupportedType):
		return locales.ErrorUnsupportedType(cx)
	case errors.Is(err, export.ErrAmbiguousUpdate):
		return locales.ErrorAmbiguousUpdate(cx)
	case errors.Is(err, export.ErrUnreadablePasskey):
		return locales.ErrorUnreadablePasskey(cx)
	case errors.Is(err, export.ErrWrongPassword):
		return locales.ErrorWrongBackupPassword(cx)
	case errors.Is(err, export.ErrBackupTooLarge):
		return locales.ErrorBackupTooLarge(cx)
	case errors.Is(err, export.ErrNotBitwardenExport):
		return locales.NotBitwardenExport(cx)
	case errors.Is(err, export.ErrAccountRestricted):
		return locales.BackupAccountRestricted(cx)
	case errors.Is(err, sshagent.ErrInUse):
		return locales.SshAgentInUse(cx)
	case errors.Is(err, sshagent.ErrNotSocket):
		return locales.SshAgentNotSocket(cx)
	case errors.Is(err, sshagent.ErrUnsupported):
		return locales.SshAgentUnsupported(cx)
	case errors.Is(err, api.ErrNotFound):
		return locales.ErrorNotFound(cx)
	case errors.As(err, &apiErr) && apiErr.Message != "":
		return locales.ErrorServer(cx, strconv.Itoa(apiErr.StatusCode), apiErr.Message)
	}
	return locales.ErrorWithDetail(cx, err.Error())
}
