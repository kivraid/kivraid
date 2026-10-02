// Command screenshots produces the README captures (docs/img/*.png).
//
// It builds a throwaway Kivraid instance seeded with demo data, drives a
// headless Chrome through the real login flow, captures the sign-in page,
// the user portal and the admin console in both themes, and composites
// each pair into a single half-light / half-dark image.
//
//	cd tools/screenshots && go run . --binary ../../kivraid --out ../../docs/img
//
// Requires Google Chrome (or Chromium) installed locally.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/google/uuid"
	"golang.org/x/image/font"
	"golang.org/x/image/font/gofont/gobold"
	"golang.org/x/image/font/opentype"
	"golang.org/x/image/math/fixed"

	"github.com/kivraid/kivraid/internal/audit"
	"github.com/kivraid/kivraid/internal/oidcserver"
	"github.com/kivraid/kivraid/internal/sources/local"
	"github.com/kivraid/kivraid/internal/store"
	"github.com/kivraid/kivraid/internal/store/sqlcgen"
)

const (
	listenAddr = "127.0.0.1:9777"
	baseURL    = "http://" + listenAddr
	adminUser  = "amelia"
	adminPass  = "demo-passw0rd"
)

func main() {
	binary := flag.String("binary", "../../kivraid", "path to the kivraid binary")
	outDir := flag.String("out", "../../docs/img", "directory for the generated PNGs")
	keep := flag.Bool("keep", false, "keep the temporary instance directory")
	flag.Parse()

	if err := run(*binary, *outDir, *keep); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(binary, outDir string, keep bool) error {
	tmp, err := os.MkdirTemp("", "kivraid-screenshots-*")
	if err != nil {
		return err
	}
	if keep {
		fmt.Fprintln(os.Stderr, "instance directory:", tmp)
	} else {
		defer os.RemoveAll(tmp)
	}

	cfgPath := filepath.Join(tmp, "kivraid.yaml")
	if err := writeConfig(cfgPath, filepath.Join(tmp, "kivraid.db")); err != nil {
		return err
	}
	if err := seed(filepath.Join(tmp, "kivraid.db")); err != nil {
		return fmt.Errorf("seed demo data: %w", err)
	}

	cmd := exec.Command(binary, "serve", "--config", cfgPath)
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start kivraid: %w", err)
	}
	defer func() {
		cmd.Process.Signal(syscall.SIGTERM)
		cmd.Wait()
	}()
	if err := waitReady(baseURL + "/healthz"); err != nil {
		return err
	}

	shots, err := captureAll()
	if err != nil {
		return fmt.Errorf("capture: %w", err)
	}

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	for name, pair := range shots {
		out, err := compositeHalves(pair[0], pair[1])
		if err != nil {
			return fmt.Errorf("composite %s: %w", name, err)
		}
		path := filepath.Join(outDir, name+".png")
		if err := os.WriteFile(path, out, 0o644); err != nil {
			return err
		}
		fmt.Println("wrote", path)
	}
	return nil
}

func writeConfig(path, dbPath string) error {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return err
	}
	content := fmt.Sprintf(`listen: "%s"
base_url: "%s"
secret_key: "%s"
database:
  driver: sqlite
  dsn: "%s"
log_level: warn
`, listenAddr, baseURL, hex.EncodeToString(secret), dbPath)
	return os.WriteFile(path, []byte(content), 0o600)
}

// --- Demo data --------------------------------------------------------------

type demoApp struct {
	name, desc, launch string
	kind               string // "oidc" or "proxy"
	letter             string // "" means no icon (initials fallback)
	top, bottom        color.RGBA
	groups             []string // access policy; empty means everyone signed in
}

var demoApps = []demoApp{
	{name: "Grafana", desc: "Dashboards", launch: "https://grafana.home.example.com",
		kind: "oidc", letter: "G", top: rgb(0xF0, 0x5A, 0x28), bottom: rgb(0xF8, 0xA3, 0x4D)},
	{name: "Nextcloud", desc: "Files & calendar", launch: "https://cloud.home.example.com",
		kind: "oidc", letter: "N", top: rgb(0x00, 0x82, 0xC9), bottom: rgb(0x30, 0xB6, 0xFF)},
	{name: "Jellyfin", desc: "Movies & music", launch: "https://media.home.example.com",
		kind: "oidc", letter: "J", top: rgb(0x7B, 0x5B, 0xA6), bottom: rgb(0xC0, 0x6E, 0xD4)},
	{name: "Vaultwarden", desc: "Password vault", launch: "https://vault.home.example.com",
		kind: "oidc", letter: "V", top: rgb(0x17, 0x5D, 0xDC), bottom: rgb(0x5A, 0x8D, 0xEE),
		groups: []string{"family"}},
	{name: "Miniflux", desc: "Feed reader", launch: "https://reader.home.example.com",
		kind: "oidc", letter: "M", top: rgb(0x05, 0x96, 0x69), bottom: rgb(0x34, 0xD3, 0x99)},
	{name: "Home Assistant", desc: "Smart home", launch: "https://hass.home.example.com",
		kind: "proxy", letter: "H", top: rgb(0x03, 0x9B, 0xE5), bottom: rgb(0x41, 0xBD, 0xF5)},
	{name: "Gitea", desc: "Git hosting", launch: "https://git.home.example.com",
		kind: "oidc"},
	{name: "Paperless", desc: "Documents", launch: "https://docs.home.example.com",
		kind: "oidc", groups: []string{"homelab"}},
}

func rgb(r, g, b uint8) color.RGBA { return color.RGBA{r, g, b, 0xFF} }

func seed(dbPath string) error {
	ctx := context.Background()
	st, err := store.Open(ctx, "sqlite", dbPath)
	if err != nil {
		return err
	}
	defer st.Close()

	src := local.NewSource(st)
	admin, err := src.CreateUser(ctx, adminUser, "amelia@example.com", "Amelia Laurent", adminPass, true)
	if err != nil {
		return err
	}
	people := []struct{ username, email, name string }{
		{"marco", "marco@example.com", "Marco Silva"},
		{"sofia", "sofia@example.com", "Sofia Almeida"},
		{"theo", "theo@example.com", "Théo Dubois"},
		{"nadia", "nadia@example.com", "Nadia Karim"},
	}
	users := map[string]string{adminUser: admin.ID}
	for _, p := range people {
		u, err := src.CreateUser(ctx, p.username, p.email, p.name, "demo-passw0rd-2", false)
		if err != nil {
			return err
		}
		users[p.username] = u.ID
	}

	now := time.Now().UTC()
	groups := map[string]string{}
	for _, name := range []string{"engineering", "family", "homelab"} {
		g, err := st.CreateGroup(ctx, sqlcgen.CreateGroupParams{
			ID: uuid.NewString(), Name: name, Source: "local", CreatedAt: now,
		})
		if err != nil {
			return err
		}
		groups[name] = g.ID
	}
	memberships := map[string][]string{
		"engineering": {adminUser, "marco", "sofia"},
		"family":      {adminUser, "theo", "nadia"},
		"homelab":     {adminUser, "marco"},
	}
	for group, members := range memberships {
		for _, m := range members {
			if err := st.AddUserGroup(ctx, sqlcgen.AddUserGroupParams{
				UserID: users[m], GroupID: groups[group],
			}); err != nil {
				return err
			}
		}
	}

	for _, a := range demoApps {
		app, err := st.CreateApplication(ctx, sqlcgen.CreateApplicationParams{
			ID: uuid.NewString(), Name: a.name, Slug: slugify(a.name), Kind: a.kind,
			Description: a.desc, LaunchUrl: a.launch, ProxyHosts: proxyHosts(a),
			CreatedAt: now, UpdatedAt: now,
		})
		if err != nil {
			return err
		}
		if a.kind == "oidc" {
			secret := randomHex(32)
			hash := oidcserver.HashToken(secret)
			if _, err := st.CreateProvider(ctx, sqlcgen.CreateProviderParams{
				ID: uuid.NewString(), ApplicationID: app.ID, ClientID: randomHex(20),
				ClientSecretHash:       &hash,
				RedirectUris:           jsonList([]string{a.launch + "/oauth/callback"}),
				PostLogoutRedirectUris: jsonList([]string{a.launch}),
				AccessTokenTtlSeconds:  300, RefreshTokenTtlSeconds: 30 * 24 * 3600,
				IDTokenTtlSeconds: 3600, CreatedAt: now, UpdatedAt: now,
			}); err != nil {
				return err
			}
		}
		for _, g := range a.groups {
			if err := st.AddAppPolicy(ctx, sqlcgen.AddAppPolicyParams{
				ApplicationID: app.ID, GroupID: groups[g],
			}); err != nil {
				return err
			}
		}
		if len(a.groups) > 0 {
			if err := st.SetApplicationRestricted(ctx, sqlcgen.SetApplicationRestrictedParams{
				Restricted: true, ID: app.ID,
			}); err != nil {
				return err
			}
		}
		if a.letter != "" {
			icon, err := letterIcon(a.letter, a.top, a.bottom)
			if err != nil {
				return err
			}
			mime := "image/png"
			if err := st.UpdateApplicationIcon(ctx, sqlcgen.UpdateApplicationIconParams{
				Icon: icon, IconMime: &mime, UpdatedAt: now, ID: app.ID,
			}); err != nil {
				return err
			}
		}
	}

	// A handful of audit entries so the admin console looks lived-in.
	rec := audit.NewRecorder(st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	rec.Record(ctx, adminUser, audit.ActionLogin, adminUser, "", "192.168.1.24")
	rec.Record(ctx, adminUser, audit.ActionAppCreate, "grafana", "", "192.168.1.24")
	rec.Record(ctx, adminUser, audit.ActionGroupCreate, "engineering", "", "192.168.1.24")
	rec.Record(ctx, "marco", audit.ActionLogin, "marco", "", "192.168.1.31")
	rec.Record(ctx, "sofia", audit.ActionLoginFailed, "sofia", "", "192.168.1.48")
	rec.Record(ctx, "sofia", audit.ActionLogin, "sofia", "", "192.168.1.48")
	return nil
}

func proxyHosts(a demoApp) string {
	if a.kind != "proxy" {
		return ""
	}
	u := a.launch
	if i := len("https://"); len(u) > i {
		u = u[i:]
	}
	return jsonList([]string{u})
}

func slugify(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z':
			out = append(out, r+('a'-'A'))
		case r >= 'a' && r <= 'z' || r >= '0' && r <= '9':
			out = append(out, r)
		case r == ' ' || r == '-':
			out = append(out, '-')
		}
	}
	return string(out)
}

func randomHex(n int) string {
	raw := make([]byte, n)
	rand.Read(raw)
	return hex.EncodeToString(raw)
}

func jsonList(items []string) string {
	raw, _ := json.Marshal(items)
	return string(raw)
}

// letterIcon renders a 256×256 vertical-gradient tile with a centered
// white initial, in the style of a generic app icon.
func letterIcon(letter string, top, bottom color.RGBA) ([]byte, error) {
	const size = 256
	img := image.NewRGBA(image.Rect(0, 0, size, size))
	for y := 0; y < size; y++ {
		t := float64(y) / float64(size-1)
		c := color.RGBA{
			R: lerp(top.R, bottom.R, t),
			G: lerp(top.G, bottom.G, t),
			B: lerp(top.B, bottom.B, t),
			A: 0xFF,
		}
		for x := 0; x < size; x++ {
			img.SetRGBA(x, y, c)
		}
	}

	ft, err := opentype.Parse(gobold.TTF)
	if err != nil {
		return nil, err
	}
	face, err := opentype.NewFace(ft, &opentype.FaceOptions{Size: 136, DPI: 72, Hinting: font.HintingFull})
	if err != nil {
		return nil, err
	}
	defer face.Close()

	d := &font.Drawer{Dst: img, Src: image.White, Face: face}
	w := d.MeasureString(letter)
	m := face.Metrics()
	d.Dot = fixed.Point26_6{
		X: (fixed.I(size) - w) / 2,
		Y: fixed.I(size)/2 + m.CapHeight/2,
	}
	d.DrawString(letter)

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func lerp(a, b uint8, t float64) uint8 {
	return uint8(float64(a) + (float64(b)-float64(a))*t)
}

// --- Capture ----------------------------------------------------------------

func waitReady(url string) error {
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("kivraid did not become ready at %s", url)
}

// captureAll returns, for each output name, the [light, dark] PNG pair.
func captureAll() (map[string][2][]byte, error) {
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", "new"),
		chromedp.Flag("hide-scrollbars", true),
		chromedp.WindowSize(1440, 900),
	)
	allocCtx, cancelAlloc := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancelAlloc()
	ctx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()
	ctx, cancelTimeout := context.WithTimeout(ctx, 90*time.Second)
	defer cancelTimeout()

	shots := map[string][2][]byte{}

	// Sign-in page. Each page gets the viewport height that frames its
	// content without dead space below.
	if err := chromedp.Run(ctx,
		chromedp.EmulateViewport(1440, 900, chromedp.EmulateScale(2)),
		chromedp.Navigate(baseURL+"/login"),
		chromedp.WaitVisible(`#username`),
	); err != nil {
		return nil, err
	}
	pair, err := captureThemes(ctx)
	if err != nil {
		return nil, err
	}
	shots["login"] = pair

	// Log in (identifier-first: username, then password on the next step),
	// then the portal launcher.
	if err := chromedp.Run(ctx,
		chromedp.SendKeys(`#username`, adminUser),
		chromedp.Click(`form[action="/login"] button[type=submit]`),
		chromedp.WaitVisible(`#password`),
		chromedp.SendKeys(`#password`, adminPass),
		chromedp.Click(`form[action="/login/password"] button[type=submit]`),
		chromedp.WaitVisible(`h1`),
		chromedp.EmulateViewport(1440, 570, chromedp.EmulateScale(2)),
	); err != nil {
		return nil, err
	}
	if pair, err = captureThemes(ctx); err != nil {
		return nil, err
	}
	shots["portal"] = pair

	// Admin console: applications.
	if err := chromedp.Run(ctx,
		chromedp.EmulateViewport(1440, 840, chromedp.EmulateScale(2)),
		chromedp.Navigate(baseURL+"/admin/applications"),
		chromedp.WaitVisible(`h1`),
	); err != nil {
		return nil, err
	}
	if pair, err = captureThemes(ctx); err != nil {
		return nil, err
	}
	shots["admin"] = pair

	return shots, nil
}

// captureThemes screenshots the current page in light then dark theme.
func captureThemes(ctx context.Context) ([2][]byte, error) {
	var out [2][]byte
	for i, theme := range []string{"light", "dark"} {
		script := fmt.Sprintf(
			`localStorage.setItem("kivraid-theme", %[1]q);
			 document.documentElement.dataset.theme = %[1]q;
			 if (document.activeElement) document.activeElement.blur();`, theme)
		var buf []byte
		if err := chromedp.Run(ctx,
			chromedp.Evaluate(script, nil),
			chromedp.Sleep(400*time.Millisecond),
			chromedp.CaptureScreenshot(&buf),
		); err != nil {
			return out, err
		}
		out[i] = buf
	}
	return out, nil
}

// compositeHalves joins the left half of the light capture with the right
// half of the dark capture.
func compositeHalves(lightPNG, darkPNG []byte) ([]byte, error) {
	light, err := png.Decode(bytes.NewReader(lightPNG))
	if err != nil {
		return nil, err
	}
	dark, err := png.Decode(bytes.NewReader(darkPNG))
	if err != nil {
		return nil, err
	}
	b := light.Bounds()
	if dark.Bounds() != b {
		return nil, fmt.Errorf("capture sizes differ: %v vs %v", b, dark.Bounds())
	}
	out := image.NewRGBA(b)
	draw.Draw(out, b, light, b.Min, draw.Src)
	mid := b.Min.X + b.Dx()/2
	right := image.Rect(mid, b.Min.Y, b.Max.X, b.Max.Y)
	draw.Draw(out, right, dark, image.Pt(mid, b.Min.Y), draw.Src)

	var buf bytes.Buffer
	if err := png.Encode(&buf, out); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
