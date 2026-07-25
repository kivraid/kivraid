// Package storetest opens throwaway stores for tests. By default each
// test gets a fresh SQLite file; when KIVRAID_TEST_POSTGRES_DSN points at
// a PostgreSQL server, each test gets its own throwaway database there
// instead, so the whole suite exercises the Postgres backend.
package storetest

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/kivraid/kivraid/internal/store"
)

// EnvPostgresDSN selects the Postgres backend for tests when set. It must
// point at a database the test user may connect to (e.g.
// postgres://postgres:postgres@localhost:5432/postgres); throwaway
// databases are created next to it.
const EnvPostgresDSN = "KIVRAID_TEST_POSTGRES_DSN"

func Open(t *testing.T) *store.Store {
	t.Helper()
	ctx := context.Background()

	adminDSN := os.Getenv(EnvPostgresDSN)
	if adminDSN == "" {
		st, err := store.Open(ctx, "sqlite", filepath.Join(t.TempDir(), "test.db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { st.Close() })
		return st
	}

	admin, err := sql.Open("pgx", adminDSN)
	if err != nil {
		t.Fatal(err)
	}

	raw := make([]byte, 6)
	rand.Read(raw)
	name := "kivraid_test_" + hex.EncodeToString(raw)
	if _, err := admin.ExecContext(ctx, "CREATE DATABASE "+name); err != nil {
		admin.Close()
		t.Fatalf("create test database: %v", err)
	}
	t.Cleanup(func() {
		if _, err := admin.ExecContext(context.Background(),
			fmt.Sprintf("DROP DATABASE %s WITH (FORCE)", name)); err != nil {
			t.Logf("drop test database %s: %v", name, err)
		}
		admin.Close()
	})

	u, err := url.Parse(adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name

	st, err := store.Open(ctx, "postgres", u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}
