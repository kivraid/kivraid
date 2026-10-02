package web

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// postBranding submits the branding form with an optional background file.
func postBranding(t *testing.T, c *http.Client, baseURL, csrf string, background []byte) *http.Response {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	mw.WriteField("_csrf", csrf)
	mw.WriteField("brand_name", "")
	if background != nil {
		fw, _ := mw.CreateFormFile("background", "bg.png")
		fw.Write(background)
	}
	mw.Close()
	req, _ := http.NewRequest("POST", baseURL+"/admin/settings/branding", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp
}

func TestLoginBackgroundUploadServeAndRemove(t *testing.T) {
	ts, _, c, csrf := adminClient(t)
	anon := newClient(t)

	// Default: the login page keeps the gradient, the image route 404s.
	if _, body := getPage(t, anon, ts.URL+"/login"); strings.Contains(body, "aurora-custom") {
		t.Fatal("login page uses a custom background before any upload")
	}
	if status, _ := getPage(t, anon, ts.URL+"/brand/background"); status != http.StatusNotFound {
		t.Fatalf("background before upload: want 404, got %d", status)
	}

	png := []byte("\x89PNG\r\n\x1a\nfake-background-body")
	if resp := postBranding(t, c, ts.URL, csrf, png); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("upload: want 303, got %d", resp.StatusCode)
	}

	// Served publicly (the sign-in page needs it before auth) and used by
	// the sign-in pages.
	resp, err := anon.Get(ts.URL + "/brand/background")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "image/png" ||
		!bytes.Equal(body, png) {
		t.Fatalf("background fetch: %d %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	if _, page := getPage(t, anon, ts.URL+"/login"); !strings.Contains(page, "aurora-custom") ||
		!strings.Contains(page, `src="/brand/background?v=`) {
		t.Fatal("login page does not use the uploaded background")
	}

	// Saving the form without a file keeps the current background.
	postBranding(t, c, ts.URL, csrf, nil)
	if status, _ := getPage(t, anon, ts.URL+"/brand/background"); status != http.StatusOK {
		t.Fatal("background lost on a save without a new file")
	}

	// Removal restores the gradient.
	resp, err = c.PostForm(ts.URL+"/admin/settings/branding/background/delete", url.Values{"_csrf": {csrf}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if status, _ := getPage(t, anon, ts.URL+"/brand/background"); status != http.StatusNotFound {
		t.Fatalf("background after removal: want 404, got %d", status)
	}
	if _, page := getPage(t, anon, ts.URL+"/login"); strings.Contains(page, "aurora-custom") {
		t.Fatal("login page still uses the removed background")
	}
}

func TestLoginBackgroundRejectsNonImage(t *testing.T) {
	ts, _, c, csrf := adminClient(t)
	if resp := postBranding(t, c, ts.URL, csrf, []byte("<svg onload=alert(1)></svg>")); resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("non-image upload: want 422, got %d", resp.StatusCode)
	}
	if status, _ := getPage(t, c, ts.URL+"/brand/background"); status != http.StatusNotFound {
		t.Fatal("rejected upload was stored")
	}
}

func TestLoginBackgroundRequiresAdmin(t *testing.T) {
	ts := newTestServer(t)
	c := newClient(t)
	login(t, c, ts.URL, "alice", "s3cret-pass")
	csrf := fetchCSRFFromPage(t, c, ts.URL+"/profile")
	resp, err := c.PostForm(ts.URL+"/admin/settings/branding/background/delete", url.Values{"_csrf": {csrf}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusSeeOther && resp.Header.Get("Location") == "/admin/settings/branding?saved=1" {
		t.Fatal("non-admin could remove the background")
	}
}
