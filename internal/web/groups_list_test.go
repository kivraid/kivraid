package web

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/kivraid/kivraid/internal/sources/local"
	"github.com/kivraid/kivraid/internal/store/sqlcgen"
)

func TestGroupsListPaginationAndSearch(t *testing.T) {
	ts, st, c, _ := adminClient(t)
	ctx := context.Background()
	for i := 0; i < groupsPageSize+3; i++ {
		if _, err := st.CreateGroup(ctx, sqlcgen.CreateGroupParams{
			ID: fmt.Sprintf("g%03d", i), Name: fmt.Sprintf("team-%03d", i), Source: "local", CreatedAt: time.Now().UTC(),
		}); err != nil {
			t.Fatal(err)
		}
	}
	_, body := getPage(t, c, ts.URL+"/admin/groups")
	if !strings.Contains(body, "team-000") || strings.Contains(body, fmt.Sprintf("team-%03d", groupsPageSize)) {
		t.Error("first page should hold exactly one page of groups")
	}
	if !strings.Contains(body, fmt.Sprintf("of %d", groupsPageSize+3)) || !strings.Contains(body, `href="?page=2"`) {
		t.Error("groups list should be paginated")
	}
	if _, body = getPage(t, c, ts.URL+"/admin/groups?page=2"); !strings.Contains(body, fmt.Sprintf("team-%03d", groupsPageSize+2)) {
		t.Error("second page should hold the remaining groups")
	}
	_, body = getPage(t, c, ts.URL+"/admin/groups?q=team-007")
	if !strings.Contains(body, "team-007") || strings.Contains(body, "team-008") {
		t.Error("search should filter groups by name")
	}
	if _, body = getPage(t, c, ts.URL+"/admin/groups?source=ldap"); !strings.Contains(body, "No groups match") {
		t.Error("source filter without match should say so")
	}
}

func TestGroupMemberCandidates(t *testing.T) {
	ts, st, c, _ := adminClient(t)
	ctx := context.Background()
	src := local.NewSource(st)
	bob, err := src.CreateUser(ctx, "bob", "bob@example.com", "Bob Builder", "bob-pass-123", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := src.CreateUser(ctx, "bobby", "bobby@example.com", "Bobby Tables", "bobby-pass-123", false); err != nil {
		t.Fatal(err)
	}
	grp, err := st.CreateGroup(ctx, sqlcgen.CreateGroupParams{ID: "ops", Name: "ops", Source: "local", CreatedAt: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.AddUserGroup(ctx, sqlcgen.AddUserGroupParams{UserID: bob.ID, GroupID: grp.ID}); err != nil {
		t.Fatal(err)
	}

	status, body := getPage(t, c, ts.URL+"/admin/groups/"+grp.ID+"/candidates?q=bob")
	if status != 200 {
		t.Fatalf("candidates: want 200, got %d", status)
	}
	var got []struct{ Username, Name string }
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Username != "bobby" {
		t.Fatalf("want only the non-member bobby, got %+v", got)
	}
	// The group page no longer ships every user with it.
	if _, page := getPage(t, c, ts.URL+"/admin/groups/"+grp.ID); strings.Contains(page, "Bobby Tables") {
		t.Error("group page should not embed non-member suggestions")
	}
}
