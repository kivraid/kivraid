// Package store provides database access. SQLite is the default engine;
// PostgreSQL is supported for larger installs. Queries stick to the
// portable subset both engines accept: $n placeholders (native in both)
// and ANSI-ish DDL split per dialect (see migrations/).
package store

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"strings"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"

	"github.com/kivraid/kivraid/internal/store/sqlcgen"
)

type Store struct {
	// Driver is "sqlite" or "postgres".
	Driver string
	DB     *sql.DB
	*sqlcgen.Queries
}

// Open opens the database, applies engine-appropriate settings, and runs
// pending migrations.
func Open(ctx context.Context, driver, dsn string) (*Store, error) {
	var db *sql.DB
	var err error
	switch driver {
	case "sqlite":
		db, err = sql.Open("sqlite", sqliteDSN(dsn))
		if err != nil {
			return nil, err
		}
		// SQLite allows a single writer; serializing all access through
		// one connection avoids SQLITE_BUSY without a meaningful
		// throughput cost for an IdP workload.
		db.SetMaxOpenConns(1)
	case "postgres":
		db, err = sql.Open("pgx", dsn)
		if err != nil {
			return nil, err
		}
		db.SetMaxOpenConns(10)
	default:
		return nil, fmt.Errorf("unsupported database driver %q", driver)
	}

	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("open database: %w", err)
	}
	if err := Migrate(ctx, db, driver); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return &Store{Driver: driver, DB: db, Queries: sqlcgen.New(db)}, nil
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
