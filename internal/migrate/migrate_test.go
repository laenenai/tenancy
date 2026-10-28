package migrate_test

import (
	"context"
	"errors"
	"hash/crc32"
	"io/fs"
	"strings"
	"testing"

	"github.com/laenenai/tenancy/db/migrations"
	"github.com/laenenai/tenancy/internal/domain"
	"github.com/laenenai/tenancy/internal/migrate"
)

// TestLockKeyIsPinned pins the advisory lock key to its literal value.
//
// This is the test the extraction constraint asks for by name. migrate.Identity
// textually contains the module path, and the lock key is a CRC32 of it, so a
// module rename moves the key — silently, because nothing fails: two builds
// either side of a rename simply take two different advisory locks, do not
// serialize against each other, and can migrate concurrently during a rollout,
// which is the exact race the lock exists to prevent.
//
// It is not a hypothetical. On 2026-10-23 a rename of this organisation's
// module path moved both of pgmigrate's extracted consumers' keys (pgmigrate's
// own LockKey doc comment records the before and after values), and the same
// class of change rewrote a hash function's domain-separation tag in a sibling
// module and invalidated its committed test vectors.
//
// So: the literal, and the value the old path would have produced, both
// written out. A rename now shows up here instead of in production.
func TestLockKeyIsPinned(t *testing.T) {
	t.Parallel()

	const (
		wantIdentity = "github.com/laenenai/tenancy/internal/migrate"
		wantKey      = int64(1948322838)

		// What the key was under the pre-2026-10-23 "laenen-ai" path. It
		// is here so that the two values are visibly different and the
		// consequence of a rename is legible rather than abstract.
		oldPathIdentity = "github.com/laenen-ai/tenancy/internal/migrate"
		oldPathKey      = int64(2091873931)
	)

	if migrate.Identity != wantIdentity {
		t.Fatalf("migrate.Identity = %q, want %q.\n"+
			"This constant contains the module path and the advisory lock key is a checksum of it, so "+
			"changing it moves the lock. If the module path genuinely moved, pin Identity to the old value "+
			"for one release (it is a string this module passes, not something read from the build, "+
			"precisely so that it can be held still) and update this test deliberately.",
			migrate.Identity, wantIdentity)
	}
	if got := migrate.LockKey(); got != wantKey {
		t.Fatalf("migrate.LockKey() = %d, want %d: the lock this module migrates under has moved", got, wantKey)
	}
	if got := int64(crc32.ChecksumIEEE([]byte(oldPathIdentity))); got != oldPathKey {
		t.Fatalf("the old module path hashes to %d, want %d (this arm only documents that a rename moves the key)",
			got, oldPathKey)
	}
	if wantKey == oldPathKey {
		t.Fatal("the two keys are equal, which would make this test prove nothing")
	}
}

// TestSchemaIsTenancy pins the schema name, which is the other constant a
// rename or a well-meaning edit could move. It appears in the
// row-level-security exemption list, in every sqlc-generated query, and in
// every consumer's own grants, so the three would silently disagree.
func TestSchemaIsTenancy(t *testing.T) {
	t.Parallel()

	if migrate.Schema != "tenancy" {
		t.Fatalf("migrate.Schema = %q, want \"tenancy\"", migrate.Schema)
	}
	if strings.Contains(migrate.Schema, "/") || strings.Contains(migrate.Schema, ".") {
		t.Fatalf("migrate.Schema = %q looks like it has acquired part of a path", migrate.Schema)
	}
}

// TestMigrationsAreEmbedded checks the embed actually caught the file. An
// empty embed.FS compiles perfectly and then applies nothing, and
// pgmigrate would report success for a database with no tables in it.
func TestMigrationsAreEmbedded(t *testing.T) {
	t.Parallel()

	entries, err := fs.ReadDir(migrations.FS, ".")
	if err != nil {
		t.Fatalf("read the embedded migration directory: %v", err)
	}

	var names []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	if len(names) == 0 {
		t.Fatal("no .sql files are embedded: the migrator would report success against an empty database")
	}
	if names[0] != "00001_registry.sql" {
		t.Errorf("the first migration is %q, want 00001_registry.sql", names[0])
	}

	body, err := fs.ReadFile(migrations.FS, "00001_registry.sql")
	if err != nil {
		t.Fatalf("read 00001_registry.sql: %v", err)
	}
	text := string(body)
	for _, want := range []string{
		"CREATE TABLE tenancy.pools",
		"CREATE TABLE tenancy.tenants",
		"CREATE DOMAIN tenancy.ulid",
		"tenants_security_mode_immutable",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("00001_registry.sql does not contain %q", want)
		}
	}
	// Grants must not be in a versioned migration: that is the trap
	// pgmigrate exists to close, and the reason this module has a
	// reconciler at all. Asserting it here keeps the rule from being
	// undone by someone moving a GRANT "where it belongs".
	//
	// Comment lines are skipped, because the file's header explains this
	// very rule and would otherwise trip it.
	for i, line := range strings.Split(text, "\n") {
		stmt := strings.TrimSpace(line)
		if strings.HasPrefix(stmt, "--") {
			continue
		}
		upper := strings.ToUpper(stmt)
		if strings.HasPrefix(upper, "GRANT ") || strings.HasPrefix(upper, "REVOKE ") ||
			strings.HasPrefix(upper, "CREATE ROLE ") {
			t.Errorf("00001_registry.sql line %d is %q. Privileges and roles are declarative state and must "+
				"be asserted on every run by the reconciler, not recorded once as applied: a deployment that "+
				"later renamed its application role would come up with no privilege separation while the "+
				"migrator reported everything applied.", i+1, stmt)
		}
	}
}

func TestUpRejectsAnIncompleteConfig(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		cfg  migrate.Config
	}{
		{"no DSN", migrate.Config{AppRole: "app", ControlRole: "control"}},
		{"no AppRole", migrate.Config{DSN: "postgres:///x", ControlRole: "control"}},
		{"no ControlRole", migrate.Config{DSN: "postgres:///x", AppRole: "app"}},
		{"AppRole is not a plain identifier", migrate.Config{DSN: "postgres:///x", AppRole: "app role; DROP", ControlRole: "control"}},
		{"ControlRole is not a plain identifier", migrate.Config{DSN: "postgres:///x", AppRole: "app", ControlRole: "control role; DROP"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if err := migrate.Up(context.Background(), tc.cfg); !errors.Is(err, domain.ErrInvalidConfig) {
				t.Fatalf("Up() error = %v, want ErrInvalidConfig", err)
			}
		})
	}

	if _, err := migrate.Status(context.Background(), migrate.Config{}); !errors.Is(err, domain.ErrInvalidConfig) {
		t.Fatalf("Status() with no DSN error = %v, want ErrInvalidConfig", err)
	}
}

// TestUpRejectsABadDSNWithoutLeakingIt covers the one path where the
// migration credential's own connection string could reach a log line.
func TestUpRejectsABadDSNWithoutLeakingIt(t *testing.T) {
	t.Parallel()

	const canary = "MIGRATION_DSN_CANARY" //nolint:gosec // canary value, not a real credential

	err := migrate.Up(context.Background(), migrate.Config{
		DSN:     "not-a-connection-string " + canary,
		AppRole: "app",
	})
	if err == nil {
		t.Fatal("Up() with a malformed DSN succeeded")
	}
	if !errors.Is(err, domain.ErrInvalidConfig) {
		t.Fatalf("Up() error = %v, want ErrInvalidConfig", err)
	}
	if strings.Contains(err.Error(), canary) {
		t.Fatalf("Up() leaked the migration DSN: %v", err)
	}
}
