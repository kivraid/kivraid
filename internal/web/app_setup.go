package web

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"text/template"
)

// --- Durations ---------------------------------------------------------------

// durationUnits are the suffixes accepted for token lifetimes, largest first
// so formatting picks the most readable exact unit.
var durationUnits = []struct {
	suffix  string
	seconds int64
}{{"d", 86400}, {"h", 3600}, {"m", 60}, {"s", 1}}

// parseDurationSeconds reads a lifetime such as "5m", "30d", "1h" or a bare
// number of seconds.
func parseDurationSeconds(raw string) (int64, error) {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw == "" {
		return 0, fmt.Errorf("is required")
	}
	mult := int64(1)
	for _, u := range durationUnits {
		if strings.HasSuffix(raw, u.suffix) {
			raw, mult = strings.TrimSpace(strings.TrimSuffix(raw, u.suffix)), u.seconds
			break
		}
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("must be a positive duration such as 5m, 1h or 30d")
	}
	return n * mult, nil
}

// formatDurationSeconds renders seconds in the largest unit that divides
// them exactly: 300 → "5m", 2592000 → "30d", 90 → "90s".
func formatDurationSeconds(n int64) string {
	for _, u := range durationUnits {
		if n >= u.seconds && n%u.seconds == 0 {
			return strconv.FormatInt(n/u.seconds, 10) + u.suffix
		}
	}
	return strconv.FormatInt(n, 10) + "s"
}

// humanDuration renders seconds for reading: "5 minutes", "30 days".
func humanDuration(n int64) string {
	names := map[string]string{"d": "day", "h": "hour", "m": "minute", "s": "second"}
	for _, u := range durationUnits {
		if n >= u.seconds && n%u.seconds == 0 {
			v := n / u.seconds
			unit := names[u.suffix]
			if v != 1 {
				unit += "s"
			}
			return strconv.FormatInt(v, 10) + " " + unit
		}
	}
	return strconv.FormatInt(n, 10) + " seconds"
}

// tokenLifetimeLimits bound each lifetime: short-lived access and ID
// tokens, long-lived refresh tokens.
var tokenLifetimeLimits = map[string]int64{
	"Access token":  86400,
	"Refresh token": 365 * 86400,
	"ID token":      86400,
}

// --- Integration presets -----------------------------------------------------

// integrationPreset pre-fills the new-application form for a well-known
// application and renders a ready-to-paste configuration snippet once the
// credentials exist.
type integrationPreset struct {
	ID   string
	Name string
	// RedirectPath is appended to the launch URL's origin to suggest the
	// redirect URI (the post-logout URI defaults to the origin itself).
	RedirectPath string
	// Doc is the integration guide under docs/integrations/.
	Doc string
	// Snippet is a text/template over setupValues.
	Snippet string
}

// setupValues feed an integration snippet.
type setupValues struct {
	Issuer       string
	ClientID     string
	ClientSecret string // empty for public clients and undisplayable legacy secrets
	Public       bool
}

// Secret is the value to paste as the client secret, or a hint when it
// cannot be shown.
func (v setupValues) Secret() string {
	switch {
	case v.Public:
		return "(none — public client, PKCE)"
	case v.ClientSecret == "":
		return "<rotate the secret to display it>"
	}
	return v.ClientSecret
}

var integrationPresets = []integrationPreset{
	{
		ID: "generic", Name: "Other application",
		Snippet: `Issuer:         {{.Issuer}}
Discovery URL:  {{.Issuer}}/.well-known/openid-configuration
Client ID:      {{.ClientID}}
Client secret:  {{.Secret}}
Scopes:         openid profile email groups
Authorization:  {{.Issuer}}/authorize
Token:          {{.Issuer}}/oauth/token
Userinfo:       {{.Issuer}}/userinfo
End session:    {{.Issuer}}/end_session`,
	},
	{
		ID: "grafana", Name: "Grafana", RedirectPath: "/login/generic_oauth", Doc: "grafana.md",
		Snippet: `[auth.generic_oauth]
enabled = true
name = Kivraid
client_id = {{.ClientID}}
client_secret = {{.Secret}}
scopes = openid profile email groups
auth_url = {{.Issuer}}/authorize
token_url = {{.Issuer}}/oauth/token
api_url = {{.Issuer}}/userinfo
use_pkce = true
login_attribute_path = preferred_username
email_attribute_path = email
name_attribute_path = name
signout_redirect_url = {{.Issuer}}/end_session`,
	},
	{
		ID: "gitea", Name: "Gitea / Forgejo", RedirectPath: "/user/oauth2/Kivraid/callback", Doc: "gitea.md",
		Snippet: `# Site Administration → Authentication Sources → Add, or from the CLI:
gitea admin auth add-oauth \
  --name Kivraid \
  --provider openidConnect \
  --key {{.ClientID}} \
  --secret {{.Secret}} \
  --auto-discover-url {{.Issuer}}/.well-known/openid-configuration \
  --scopes groups`,
	},
	{
		ID: "nextcloud", Name: "Nextcloud", RedirectPath: "/apps/user_oidc/code", Doc: "nextcloud.md",
		Snippet: `occ user_oidc:provider Kivraid \
  --clientid={{.ClientID}} \
  --clientsecret={{.Secret}} \
  --discoveryuri={{.Issuer}}/.well-known/openid-configuration \
  --scope="openid profile email" \
  --mapping-uid=sub \
  --mapping-display-name=name \
  --mapping-email=email`,
	},
}

func findPreset(id string) integrationPreset {
	for _, p := range integrationPresets {
		if p.ID == id {
			return p
		}
	}
	return integrationPresets[0]
}

// renderSnippet fills a preset's snippet; a template error degrades to the
// generic listing rather than failing the page.
func (p integrationPreset) renderSnippet(v setupValues) string {
	t, err := template.New(p.ID).Parse(p.Snippet)
	if err != nil {
		return ""
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, v); err != nil {
		return ""
	}
	return buf.String()
}

// setupSnippet is one rendered preset on the credentials page.
type setupSnippet struct {
	ID, Name, Doc, Text string
}

func renderSetupSnippets(v setupValues) []setupSnippet {
	out := make([]setupSnippet, 0, len(integrationPresets))
	for _, p := range integrationPresets {
		out = append(out, setupSnippet{ID: p.ID, Name: p.Name, Doc: p.Doc, Text: p.renderSnippet(v)})
	}
	return out
}
