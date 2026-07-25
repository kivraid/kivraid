package web

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/kivraid/kivraid/internal/sources/local"
)

func TestAdminUsersSearchAndPagination(t *testing.T) {
	ts, st, c, _ := adminClient(t)
	ctx := context.Background()

	// 60 users on top of root → 61 total, two pages of 50.
	src := local.NewSource(st)
	for i := 0; i < 60; i++ {
		name := fmt.Sprintf("user%02d", i)
		if _, err := src.CreateUser(ctx, name, name+"@example.com",
			fmt.Sprintf("User %02d", i), "some-pass-123", false); err != nil {
			t.Fatal(err)
		}
	}

	get := func(url string) string {
		t.Helper()
		resp, err := c.Get(url)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s: want 200, got %d", url, resp.StatusCode)
		}
		body, _ := io.ReadAll(resp.Body)
		return string(body)
	}

	// Page 1 holds the first 50 users; the last ones spill to page 2.
	body := get(ts.URL + "/admin/users")
	if !strings.Contains(body, "Showing 1–50 of 61") {
		t.Fatalf("page 1 range missing, body: %.300s", body)
	}
	if strings.Contains(body, "user59@example.com") {
		t.Fatal("page 1 should not contain the last user")
	}
	body = get(ts.URL + "/admin/users?page=2")
	if !strings.Contains(body, "Showing 51–61 of 61") || !strings.Contains(body, "user59@example.com") {
		t.Fatal("page 2 should show the remaining users")
	}

	// Search matches name, username and email, case-insensitively.
	body = get(ts.URL + "/admin/users?q=USER%2007")
	if !strings.Contains(body, "user07@example.com") || strings.Contains(body, "user08@example.com") {
		t.Fatal("search by display name failed")
	}

	// LIKE wildcards in the search are literal, not wildcards.
	body = get(ts.URL + "/admin/users?q=%25")
	if !strings.Contains(body, "No users match") {
		t.Fatal("a literal % should match nothing, not everything")
	}
}
