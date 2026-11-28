package api

import (
	"fmt"
	"net/url"
	"strings"
)

// Endpoints are the services of one server. Base is "" for Bitwarden's
// US cloud, the default.
type Endpoints struct {
	Base     string `json:"base"`
	API      string `json:"api"`
	Identity string `json:"identity"`
}

var (
	usCloud = Endpoints{API: "https://api.bitwarden.com", Identity: "https://identity.bitwarden.com"}
	euCloud = Endpoints{API: "https://api.bitwarden.eu", Identity: "https://identity.bitwarden.eu"}
)

// FormatServerURL normalizes a server base URL the way Bitwarden clients
// do: surrounding space and trailing slashes are dropped and a missing
// scheme becomes https. "", "null", "bitwarden.com" and
// "https://bitwarden.com" select the default US cloud and give "".
func FormatServerURL(raw string) string {
	s := strings.TrimSpace(raw)
	switch s {
	case "", "null", "bitwarden.com", "https://bitwarden.com":
		return ""
	}
	s = strings.TrimRight(s, "/")
	if !strings.HasPrefix(s, "http://") && !strings.HasPrefix(s, "https://") {
		s = "https://" + s
	}
	return s
}

// FormatServiceURL normalizes a service URL as FormatServerURL does,
// without the cloud shortcuts.
func FormatServiceURL(raw string) string {
	s := strings.TrimRight(strings.TrimSpace(raw), "/")
	if s != "" && !strings.HasPrefix(s, "http://") && !strings.HasPrefix(s, "https://") {
		s = "https://" + s
	}
	return s
}

// NotificationsURL is where a server's notifications hub lives: Bitwarden's
// US and EU clouds have hosts of their own (bitwarden/clients
// DefaultEnvironmentService), any other server serves it under
// base/notifications.
func NotificationsURL(base string) string {
	e, err := ResolveEndpoints(base)
	switch {
	case err == nil && e.Identity == usCloud.Identity:
		return "https://notifications.bitwarden.com"
	case err == nil && e.Identity == euCloud.Identity:
		return "https://notifications.bitwarden.eu"
	}
	return strings.TrimRight(base, "/") + "/notifications"
}

// WebVaultURL is where a server's web vault lives: Bitwarden's US and EU
// clouds serve it on vault.bitwarden.com and vault.bitwarden.eu; any
// other server serves it at its base URL.
func WebVaultURL(base string) string {
	e, err := ResolveEndpoints(base)
	switch {
	case err == nil && e.Identity == usCloud.Identity:
		return "https://vault.bitwarden.com"
	case err == nil && e.Identity == euCloud.Identity:
		return "https://vault.bitwarden.eu"
	}
	return strings.TrimRight(base, "/")
}

// ResolveEndpoints maps a base URL from FormatServerURL to its services.
// Bitwarden's US and EU clouds have fixed API and identity hosts; any
// other server serves them under its base path.
func ResolveEndpoints(base string) (Endpoints, error) {
	if base == "" {
		return usCloud, nil
	}
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return Endpoints{}, fmt.Errorf("api: invalid server URL %q", base)
	}
	if u.Scheme == "https" && u.Port() == "" && (u.Path == "" || u.Path == "/") {
		switch strings.ToLower(u.Hostname()) {
		case "bitwarden.com", "vault.bitwarden.com":
			e := usCloud
			e.Base = base
			return e, nil
		case "bitwarden.eu", "vault.bitwarden.eu":
			e := euCloud
			e.Base = base
			return e, nil
		}
	}
	return Endpoints{Base: base, API: base + "/api", Identity: base + "/identity"}, nil
}
