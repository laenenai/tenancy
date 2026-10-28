// Command rls applies and verifies the PostgreSQL row-level-security backstop.
//
// It uses a DDL credential (not the data-plane role) to call EnableRLS, sweeps
// the schema for coverage, then checks enforcement through a resolved tenant.
// The table must already exist and have a tenant_id column; see the README.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"slices"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

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

	ddlDSN, err := required("TENANCY_DDL_DSN")
	if err != nil {
		return err
	}
	controlDSN, err := required("TENANCY_CONTROL_DSN")
	if err != nil {
		return err
	}
	tenantID, err := required("TENANCY_TENANT_ID")
	if err != nil {
		return err
	}
	table := envOr("TENANCY_TABLE", "app.document")
	schema := envOr("TENANCY_SCHEMA", "app")
	appRole := envOr("TENANCY_APP_ROLE", "myapp_data")

	id, err := tenancy.ParseTenantID(tenantID)
	if err != nil {
		return fmt.Errorf("TENANCY_TENANT_ID: %w", err)
	}

	ddl, err := pgxpool.New(ctx, ddlDSN)
	if err != nil {
		return fmt.Errorf("open DDL pool: %w", err)
	}
	defer ddl.Close()

	// This is normally called from the consumer's migration reconciler, not at
	// request time. It creates a restrictive tenant_isolation policy and the
	// permissive tenant_access companion.
	if err := tenancy.EnableRLS(ctx, ddl, table); err != nil {
		return fmt.Errorf("enable RLS on %s: %w", table, err)
	}
	uncovered, err := tenancy.AssertRLSCoverage(ctx, ddl, schema)
	if err != nil {
		return fmt.Errorf("assert RLS coverage: %w", err)
	}
	if slices.Contains(uncovered, table) {
		return fmt.Errorf("%s is not covered by the expected RLS policy pair", table)
	}

	ten, err := tenancy.Open(ctx, tenancy.Config{
		RegistryDSN: tenancy.DSN(controlDSN),
		AppRole:     appRole,
	})
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer func() { _ = ten.Close() }()

	scoped, err := ten.Scope(ctx, id)
	if err != nil {
		return fmt.Errorf("scope: %w", err)
	}
	report, err := scoped.CheckEnforcement(ctx, table)
	if err != nil {
		return fmt.Errorf("check enforcement: %w", err)
	}
	if !report.FailClosed() {
		return fmt.Errorf("RLS is not fail-closed for %s: %v", table, report.Findings())
	}
	log.Printf("RLS is fail-closed for %s as role %s", table, report.Role)
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
