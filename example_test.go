package tenancy_test

// Compile-checked examples. They intentionally have no // Output comment:
// `go test` compiles them so a documentation change cannot drift into code
// that does not build, but does not require a live Postgres to run them.

import (
	"context"
	"time"

	"github.com/laenenai/tenancy"
)

func ExampleMigrate() {
	_ = tenancy.Migrate(context.Background(), tenancy.MigrateConfig{
		DSN:         tenancy.DSN("postgres://migration@db.invalid/tenancy"),
		AppRole:     "myapp_data",
		ControlRole: "myapp_control",
	})
}

func ExampleOpen() {
	ten, err := tenancy.Open(context.Background(), tenancy.Config{
		RegistryDSN: tenancy.DSN("postgres://control@db.invalid/tenancy"),
		AppRole:     "myapp_data",
		Cache: tenancy.CacheOptions{
			TTL:         time.Minute,
			NegativeTTL: 10 * time.Second,
		},
	})
	if err != nil {
		return
	}
	defer func() { _ = ten.Close() }()
}

func ExampleScoped_Tx() {
	ctx := context.Background()
	ten, err := tenancy.Open(ctx, tenancy.Config{
		RegistryDSN: tenancy.DSN("postgres://control@db.invalid/tenancy"),
		AppRole:     "myapp_data",
	})
	if err != nil {
		return
	}
	defer func() { _ = ten.Close() }()

	tenant, err := ten.Control().TenantByID(ctx, tenancy.NewTenantID(tenancy.SystemClock{}))
	if err != nil {
		return
	}
	scoped, err := ten.Scope(ctx, tenant.ID)
	if err != nil {
		return
	}
	_ = scoped.Tx(ctx, func(ctx context.Context, tx tenancy.TenantTx) error {
		_, err := tx.Exec(ctx, "SELECT set_config('app.tenant_id', $1, true)", string(tx.Tenant()))
		return err
	})
}
