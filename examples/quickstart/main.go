// Command quickstart is the smallest complete control-plane/data-plane wiring:
// migrate, open, resolve a tenant, and run one scoped statement.
//
// It is compile-checked by `go build ./...`. It uses environment variables
// rather than hard-coded DSNs so it is safe to keep in a repository and can be
// pointed at a disposable database.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/laenenai/tenancy"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	migrationDSN, err := required("TENANCY_MIGRATION_DSN")
	if err != nil {
		return err
	}
	controlDSN, err := required("TENANCY_CONTROL_DSN")
	if err != nil {
		return err
	}
	poolDSN, err := required("TENANCY_POOL_DSN")
	if err != nil {
		return err
	}
	appRole := envOr("TENANCY_APP_ROLE", "myapp_data")
	controlRole := envOr("TENANCY_CONTROL_ROLE", "myapp_control")

	// The migration credential is separate from the control-plane credential.
	// Migrate creates the NOLOGIN grantees; the deployment creates the LOGIN
	// identities and makes each a member of its grantee.
	if err := tenancy.Migrate(ctx, tenancy.MigrateConfig{
		DSN:         tenancy.DSN(migrationDSN),
		AppRole:     appRole,
		ControlRole: controlRole,
	}); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}

	// This DSN is a LOGIN role with INHERIT membership in ControlRole. It is
	// never the data-plane login.
	ten, err := tenancy.Open(ctx, tenancy.Config{
		RegistryDSN: tenancy.DSN(controlDSN),
		AppRole:     appRole,
		Cache: tenancy.CacheOptions{
			TTL:         time.Minute,
			NegativeTTL: 10 * time.Second,
		},
	})
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer func() { _ = ten.Close() }()

	pool, err := ensurePool(ctx, ten, poolDSN)
	if err != nil {
		return err
	}
	tenant, err := ensureTenant(ctx, ten, pool.ID)
	if err != nil {
		return err
	}

	// The data plane: one tenant, with app.tenant_id set by Scoped.Tx and the
	// connection narrowed to AppRole.
	scoped, err := ten.Scope(ctx, tenant.ID)
	if err != nil {
		return fmt.Errorf("scope: %w", err)
	}
	if err := scoped.Tx(ctx, func(ctx context.Context, tx tenancy.TenantTx) error {
		var observed string
		if err := tx.QueryRow(ctx,
			"SELECT current_setting('app.tenant_id', true)",
		).Scan(&observed); err != nil {
			return fmt.Errorf("read tenant context: %w", err)
		}
		if observed != string(tx.Tenant()) {
			return fmt.Errorf("tenant context = %q, want %q", observed, tx.Tenant())
		}
		log.Printf("resolved tenant %s on pool %s with tenant context %s", tx.Tenant(), scoped.Pool().ID, observed)
		return nil
	}); err != nil {
		return fmt.Errorf("scoped transaction: %w", err)
	}
	return nil
}

func ensurePool(ctx context.Context, ten *tenancy.Tenancy, poolDSN string) (tenancy.Pool, error) {
	const name = "eu-main"
	pool, err := ten.Control().PoolByName(ctx, name)
	if err == nil {
		return pool, nil
	}
	if !errors.Is(err, tenancy.ErrNotAuthorizedOrNotFound) {
		return tenancy.Pool{}, fmt.Errorf("look up pool %s: %w", name, err)
	}
	pool, err = ten.Control().CreatePool(ctx, tenancy.PoolSpec{
		Name:           name,
		Region:         "eu-west-1",
		MetadataDSN:    tenancy.DSN(poolDSN),
		BlobConfigRef:  "blob-eu-main",
		WorkerCapacity: 8,
	})
	if err != nil {
		return tenancy.Pool{}, fmt.Errorf("create pool %s: %w", name, err)
	}
	return pool, nil
}

func ensureTenant(ctx context.Context, ten *tenancy.Tenancy, poolID tenancy.PoolID) (tenancy.Tenant, error) {
	const name = "acme"
	tenant, err := ten.Control().TenantByName(ctx, name)
	if err == nil {
		return tenant, nil
	}
	if !errors.Is(err, tenancy.ErrNotAuthorizedOrNotFound) {
		return tenancy.Tenant{}, fmt.Errorf("look up tenant %s: %w", name, err)
	}
	tenant, err = ten.Control().CreateTenant(ctx, tenancy.TenantSpec{
		PoolID:       poolID,
		Name:         name,
		SecurityMode: tenancy.SecurityModeManaged,
	})
	if err != nil {
		return tenancy.Tenant{}, fmt.Errorf("create tenant %s: %w", name, err)
	}
	return tenant, nil
}

func required(name string) (string, error) {
	if value := os.Getenv(name); value != "" {
		return value, nil
	}
	return "", fmt.Errorf("%s is required", name)
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
