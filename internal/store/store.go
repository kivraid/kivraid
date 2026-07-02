// Package store provides database access. SQLite is the only engine for
// now; queries stick to portable SQL so a Postgres implementation can be
// added later (see DESIGN.md).
package store

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"strings"

	_ "modernc.org/sqlite"

	"github.com/lporcheron/kivraid/internal/store/sqlcgen"
)

type Store struct {
	DB *sql.DB
	*sqlcgen.Queries
}

// Open opens the database, applies pragmas suited for a long-running
// server process, and runs pending migrations.
func Open(ctx context.Context, driver, dsn string) (*Store, error) {
	if driver != "sqlite" {
		return nil, fmt.Errorf("unsupported database driver %q", driver)
	}

	db, err := sql.Open("sqlite", sqliteDSN(dsn))
	if err != nil {
		return nil, err
	}
	// SQLite allows a single writer; serializing all access through one
	// connection avoids SQLITE_BUSY without a meaningful throughput cost
	// for an IdP workload.
	db.SetMaxOpenConns(1)

	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("open database: %w", err)
	}
	if err := Migrate(ctx, db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return &Store{DB: db, Queries: sqlcgen.New(db)}, nil
}

func (s *Store) Close() error { return s.DB.Close() }

func sqliteDSN(path string) string {
	pragmas := url.Values{}
	pragmas.Add("_pragma", "journal_mode(WAL)")
	pragmas.Add("_pragma", "foreign_keys(1)")
	pragmas.Add("_pragma", "busy_timeout(5000)")
	pragmas.Add("_pragma", "synchronous(NORMAL)")
	if strings.Contains(path, "?") {
		return path + "&" + pragmas.Encode()
	}
	return "file:" + path + "?" + pragmas.Encode()
}
