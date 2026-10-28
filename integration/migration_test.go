package tenancy_test

import (
	"context"
	"testing"

	"github.com/laenenai/tenancy"
	"github.com/laenenai/tenancy/testdb"
)

func TestMigrationStatusNeedsOnlyTheDSNAndTracksUp(t *testing.T) {
	db := testdb.Start(t)
	ctx := context.Background()

	before, err := tenancy.MigrationStatus(ctx, tenancy.MigrateConfig{DSN: db.DSN()})
	if err != nil {
		t.Fatalf("MigrationStatus on an empty database: %v", err)
	}
	if len(before) == 0 {
		t.Fatal("MigrationStatus on an empty database returned no migrations to track")
	}
	for _, m := range before {
		if m.Applied {
			t.Fatalf("MigrationStatus on an empty database reports %s applied", m.Name)
		}
	}

	if err := tenancy.Migrate(ctx, tenancy.MigrateConfig{
		DSN: db.DSN(), AppRole: testdb.AppRole, ControlRole: testdb.ControlRole,
	}); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	after, err := tenancy.MigrationStatus(ctx, tenancy.MigrateConfig{DSN: db.DSN()})
	if err != nil {
		t.Fatalf("MigrationStatus after Migrate: %v", err)
	}
	for _, m := range after {
		if !m.Applied {
			t.Fatalf("MigrationStatus after Migrate reports %s not applied", m.Name)
		}
	}
}
