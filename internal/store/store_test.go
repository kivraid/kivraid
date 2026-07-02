package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/lporcheron/kivraid/internal/store/sqlcgen"
	"github.com/lporcheron/kivraid/internal/store/storetest"
)

// TestStoreRoundtrip exercises migrations and basic CRUD on whichever
// engine storetest selects (SQLite by default, Postgres when
// KIVRAID_TEST_POSTGRES_DSN is set).
func TestStoreRoundtrip(t *testing.T) {
	st := storetest.Open(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	hash := "$argon2id$fake"
	user, err := st.CreateUser(ctx, sqlcgen.CreateUserParams{
		ID: "u1", Username: "alice", Email: "alice@example.com", Name: "Alice",
		PasswordHash: &hash, Source: "local", IsAdmin: true, Active: true,
		CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}

	got, err := st.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Username != "alice" || !got.IsAdmin || got.PasswordHash == nil || *got.PasswordHash != hash {
		t.Fatalf("user roundtrip mismatch: %+v", got)
	}
	if !got.CreatedAt.Equal(user.CreatedAt) {
		t.Fatalf("timestamp roundtrip mismatch: %v != %v", got.CreatedAt, user.CreatedAt)
	}

	group, err := st.CreateGroup(ctx, sqlcgen.CreateGroupParams{ID: "g1", Name: "infra", CreatedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.AddUserGroup(ctx, sqlcgen.AddUserGroupParams{UserID: user.ID, GroupID: group.ID}); err != nil {
		t.Fatal(err)
	}
	groups, err := st.ListUserGroups(ctx, user.ID)
	if err != nil || len(groups) != 1 || groups[0].Name != "infra" {
		t.Fatalf("group roundtrip: %v %v", groups, err)
	}

	if err := st.InsertAudit(ctx, sqlcgen.InsertAuditParams{
		Ts: now, Actor: "alice", Action: "login", Ip: "127.0.0.1",
	}); err != nil {
		t.Fatal(err)
	}
	entries, err := st.ListAudit(ctx, 5)
	if err != nil || len(entries) != 1 || entries[0].Action != "login" {
		t.Fatalf("audit roundtrip: %v %v", entries, err)
	}

	if err := st.CreateRefreshToken(ctx, sqlcgen.CreateRefreshTokenParams{
		ID: "rt1", UserID: user.ID, ClientID: "c1",
		Scopes: `["openid"]`, Audience: `["c1"]`, Amr: `["pwd"]`,
		AuthTime: now, ExpiresAt: now.Add(time.Hour), CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	rt, err := st.GetRefreshToken(ctx, "rt1")
	if err != nil || rt.UserID != user.ID {
		t.Fatalf("refresh token roundtrip: %v %v", rt, err)
	}
}
