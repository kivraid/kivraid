package store

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"sort"
)

//go:embed migrations/sqlite/*.sql migrations/postgres/*.sql
var migrationsFS embed.FS

// Migrate applies pending migrations for the given dialect in lexical
// filename order. Both dialects share the same numbering; each migration
// runs in its own transaction and is recorded in schema_migrations.
func Migrate(ctx context.Context, db *sql.DB, dialect string) error {
	if _, err := db.ExecContext(ctx,
		`CREATE TABLE IF NOT EXISTS schema_migrations (
			filename   TEXT PRIMARY KEY,
			applied_at TIMESTAMP NOT NULL
		)`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	applied := map[string]bool{}
	rows, err := db.QueryContext(ctx, `SELECT filename FROM schema_migrations`)
	if err != nil {
		return fmt.Errorf("read schema_migrations: %w", err)
	}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return err
		}
		applied[name] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	dir := "migrations/" + dialect
	entries, err := migrationsFS.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("unknown dialect %q: %w", dialect, err)
	}
	names := make([]string, 0, len(entries))
	known := make(map[string]bool, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
		known[e.Name()] = true
	}
	sort.Strings(names)

	// Forward-only guard: a migration recorded in the database but not
	// embedded in this binary means the data was written by a newer
	// kivraid. Refuse to start with a clear message instead of failing
	// later on queries against an unknown schema.
	for name := range applied {
		if !known[name] {
			return fmt.Errorf(
				"database schema contains migration %s, which this binary does not know: "+
					"the data was written by a newer kivraid; upgrade the binary (downgrades are not supported)",
				name)
		}
	}

	for _, name := range names {
		if applied[name] {
			continue
		}
		sqlBytes, err := migrationsFS.ReadFile(dir + "/" + name)
		if err != nil {
			return err
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, string(sqlBytes)); err != nil {
			tx.Rollback()
			return fmt.Errorf("apply migration %s: %w", name, err)
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO schema_migrations (filename, applied_at) VALUES ($1, CURRENT_TIMESTAMP)`,
			name); err != nil {
			tx.Rollback()
			return fmt.Errorf("record migration %s: %w", name, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %s: %w", name, err)
		}
	}
	return nil
}
