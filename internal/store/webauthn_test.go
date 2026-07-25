package store_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/kivraid/kivraid/internal/store/sqlcgen"
	"github.com/kivraid/kivraid/internal/store/storetest"
)

// TestWebauthnCredentialRoundtrip exercises the passkey credential CRUD on
// whichever engine storetest selects.
func TestWebauthnCredentialRoundtrip(t *testing.T) {
	st := storetest.Open(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	hash := "$argon2id$fake"
	user, err := st.CreateUser(ctx, sqlcgen.CreateUserParams{
		ID: "u1", Username: "bob", Email: "bob@example.com", Name: "Bob",
		PasswordHash: &hash, Source: "local", Active: true,
		CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := st.CreateWebauthnCredential(ctx, sqlcgen.CreateWebauthnCredentialParams{
		ID: "c1", UserID: user.ID, CredentialID: "cred-abc",
		Name: "YubiKey", Data: `{"stub":true}`, CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	n, err := st.CountWebauthnCredentials(ctx, user.ID)
	if err != nil || n != 1 {
		t.Fatalf("count: got %d, err %v", n, err)
	}

	creds, err := st.ListWebauthnCredentials(ctx, user.ID)
	if err != nil || len(creds) != 1 {
		t.Fatalf("list: %v %v", creds, err)
	}
	if creds[0].Name != "YubiKey" || creds[0].CredentialID != "cred-abc" {
		t.Fatalf("credential roundtrip mismatch: %+v", creds[0])
	}
	if creds[0].LastUsedAt.Valid {
		t.Fatalf("last_used_at should be null before first use")
	}

	// A login updates the sign-count blob and the last-used timestamp,
	// keyed by the opaque credential ID.
	used := now.Add(time.Hour)
	if err := st.UpdateWebauthnCredential(ctx, sqlcgen.UpdateWebauthnCredentialParams{
		Data: `{"stub":true,"count":1}`, LastUsedAt: sql.NullTime{Time: used, Valid: true},
		CredentialID: "cred-abc",
	}); err != nil {
		t.Fatal(err)
	}
	creds, err = st.ListWebauthnCredentials(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !creds[0].LastUsedAt.Valid || !creds[0].LastUsedAt.Time.Equal(used) {
		t.Fatalf("last_used_at not updated: %+v", creds[0].LastUsedAt)
	}
	if creds[0].Data != `{"stub":true,"count":1}` {
		t.Fatalf("data not updated: %q", creds[0].Data)
	}

	// Delete is scoped to the owner: another user's ID must not remove it.
	if err := st.DeleteWebauthnCredential(ctx, sqlcgen.DeleteWebauthnCredentialParams{
		ID: "c1", UserID: "someone-else",
	}); err != nil {
		t.Fatal(err)
	}
	if n, _ := st.CountWebauthnCredentials(ctx, user.ID); n != 1 {
		t.Fatalf("credential deleted by wrong owner")
	}
	if err := st.DeleteWebauthnCredential(ctx, sqlcgen.DeleteWebauthnCredentialParams{
		ID: "c1", UserID: user.ID,
	}); err != nil {
		t.Fatal(err)
	}
	if n, _ := st.CountWebauthnCredentials(ctx, user.ID); n != 0 {
		t.Fatalf("credential not deleted by owner")
	}
}
