// Command openbao wires the opt-in dynamic-credential adapter: validate the
// OpenBao role, then give the source to tenancy.Open.
//
// The control-plane DSN remains a static credential; only tenant pools use
// issued credentials. See credentials/openbao for the lease/retirement design.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/laenenai/tenancy"
	"github.com/laenenai/tenancy/credentials/openbao"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	address, err := required("OPENBAO_ADDR")
	if err != nil {
		return err
	}
	token, err := required("OPENBAO_TOKEN")
	if err != nil {
		return err
	}
	role, err := required("OPENBAO_DB_ROLE")
	if err != nil {
		return err
	}
	controlDSN, err := required("TENANCY_CONTROL_DSN")
	if err != nil {
		return err
	}
	appRole := envOr("TENANCY_APP_ROLE", "myapp_data")

	source, err := openbao.Open(ctx, openbao.Config{
		Address: address,
		Token:   token,
		Role:    role,
	})
	if err != nil {
		return fmt.Errorf("openbao.Open: %w", err)
	}
	check, err := source.CheckRole(ctx, role)
	if err != nil {
		return fmt.Errorf("check OpenBao role: %w", err)
	}
	if !check.Usable() {
		return fmt.Errorf("OpenBao role %q is not usable: %v", role, check.Findings())
	}

	// LongestTransaction is required with Credentials. It is the longest
	// transaction this deployment serves, not a security preference.
	ten, err := tenancy.Open(ctx, tenancy.Config{
		RegistryDSN:        tenancy.DSN(controlDSN),
		AppRole:            appRole,
		Credentials:        source,
		LongestTransaction: 2 * time.Minute,
		Cache: tenancy.CacheOptions{
			TTL:         time.Minute,
			NegativeTTL: 10 * time.Second,
		},
	})
	if err != nil {
		return fmt.Errorf("tenancy.Open: %w", err)
	}
	defer func() { _ = ten.Close() }()

	// A real request then resolves a tenant and runs through Scoped.Tx. The
	// pool is opened lazily on this first resolution.
	tenantID, err := required("TENANCY_TENANT_ID")
	if err != nil {
		return err
	}
	id, err := tenancy.ParseTenantID(tenantID)
	if err != nil {
		return fmt.Errorf("TENANCY_TENANT_ID: %w", err)
	}
	scoped, err := ten.Scope(ctx, id)
	if err != nil {
		return fmt.Errorf("scope: %w", err)
	}
	if err := scoped.Tx(ctx, func(ctx context.Context, tx tenancy.TenantTx) error {
		_, err := tx.Exec(ctx, "SELECT 1")
		return err
	}); err != nil {
		return fmt.Errorf("scoped transaction: %w", err)
	}
	log.Printf("dynamic credentials active for tenant %s; stats: %+v", id, ten.Stats())
	return nil
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
