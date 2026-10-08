package postgres

import (
	"fmt"
	"strconv"

	"github.com/identuum/identuum-idp-oss/migrations"
)

// AppliedSchemaVersionSQL reads the newest migration version goose recorded
// as applied; 0 when the table holds none.
const AppliedSchemaVersionSQL = `SELECT COALESCE(MAX(version_id), 0) FROM goose_db_version WHERE is_applied`

// SchemaVersionError says the database schema is at another version than the
// one this binary embeds, older or newer (owner ruling y, 2026-10-08). Its
// text is the operator's instruction and carries no URL.
type SchemaVersionError struct {
	Found, Wanted int64
}

func (e *SchemaVersionError) Error() string {
	return fmt.Sprintf("schema at %d, this server needs %d: run identuum-idp migrate", e.Found, e.Wanted)
}

// EmbeddedSchemaVersion is the newest version the embedded migrations define.
func EmbeddedSchemaVersion() int64 {
	v, err := strconv.ParseInt(migrations.Current(), 10, 64)
	if err != nil {
		return 0
	}
	return v
}

// CheckSchemaVersion returns a *SchemaVersionError when found is not the
// embedded version, and nil when it is.
func CheckSchemaVersion(found int64) error {
	if want := EmbeddedSchemaVersion(); found != want {
		return &SchemaVersionError{Found: found, Wanted: want}
	}
	return nil
}
