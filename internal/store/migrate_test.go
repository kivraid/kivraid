package store_test

import (
	"strings"
	"testing"

	"github.com/kivraid/kivraid/internal/store"
	"github.com/kivraid/kivraid/internal/store/storetest"
)

// A migration recorded in the database but unknown to the binary means
// the schema was written by a newer kivraid: startup must refuse with a
// clear message rather than fail later on arbitrary queries.
func TestMigrateRefusesNewerSchema(t *testing.T) {
	st := storetest.Open(t)

	if _, err := st.DB.ExecContext(t.Context(),
		`INSERT INTO schema_migrations (filename, applied_at) VALUES ('9999_from_the_future.sql', CURRENT_TIMESTAMP)`); err != nil {
		t.Fatal(err)
	}

	err := store.Migrate(t.Context(), st.DB, st.Driver)
	if err == nil {
		t.Fatal("Migrate accepted a schema containing an unknown migration")
	}
	if !strings.Contains(err.Error(), "9999_from_the_future.sql") ||
		!strings.Contains(err.Error(), "downgrades are not supported") {
		t.Fatalf("unhelpful downgrade error: %v", err)
	}
}
