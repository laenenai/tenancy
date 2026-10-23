package pg_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/laenenai/tenancy/internal/domain"
	"github.com/laenenai/tenancy/internal/pg"
	"github.com/laenenai/tenancy/testdb"
)

// These tests are about what Postgres does, so they need Postgres. They
// skip under -short through testdb.Start, which is the module's single
// chokepoint for that convention.
//
// What is here and not in the conformance suite: the failure paths of
// EnableRLS itself. The suite is the contract a consumer runs against its
// own wiring, and a consumer has no business reproducing "what happens when
// CREATE POLICY fails halfway" — that is this module's own obligation.

// fixtureDB starts a database and creates a schema to put fixture tables
// in. No migration: these tests are about EnableRLS, not about the
// registry.
func fixtureDB(t *testing.T) *pgxpool.Pool {
	t.Helper()

	db := testdb.Start(t)
	if _, err := db.Pool().Exec(context.Background(), "CREATE SCHEMA rlsfixture"); err != nil {
		t.Fatalf("create the fixture schema: %v", err)
	}
	return db.Pool()
}

// TestEnableRLS_FailurePartwayThroughLeavesTableUnchanged proves EnableRLS's
// four statements are atomic.
//
// The fixture table has no tenant_id column, so CREATE POLICY fails —
// TenantPredicate references tenant_id — after ENABLE and FORCE would
// otherwise already have succeeded. If those two ran unwrapped, the table
// would be left FORCEd into row security with zero policies, which Postgres
// default-denies for every role including the owner, until someone fixes it
// by hand. On a tenant-scoped table in production that is an outage, and the
// recovery requires privileges the application does not have.
func TestEnableRLS_FailurePartwayThroughLeavesTableUnchanged(t *testing.T) {
	t.Parallel()

	pool := fixtureDB(t)
	ctx := context.Background()

	if _, err := pool.Exec(ctx, "CREATE TABLE rlsfixture.no_tenant_id (id text PRIMARY KEY)"); err != nil {
		t.Fatalf("create a table without tenant_id: %v", err)
	}

	err := pg.EnableRLS(ctx, pool, "rlsfixture.no_tenant_id")
	if err == nil {
		t.Fatal("EnableRLS on a table with no tenant_id column succeeded; CREATE POLICY's predicate " +
			"references that column, so it cannot have")
	}

	var enabled, forced bool
	if err := pool.QueryRow(ctx,
		"SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE oid = 'rlsfixture.no_tenant_id'::regclass",
	).Scan(&enabled, &forced); err != nil {
		t.Fatalf("read pg_class: %v", err)
	}
	if enabled || forced {
		t.Fatalf("relrowsecurity=%v relforcerowsecurity=%v, want both false: ENABLE and FORCE must roll back "+
			"with the failed CREATE POLICY rather than leaving the table forced into row security with zero "+
			"policies, which default-denies every statement from every role", enabled, forced)
	}

	var policies int
	if err := pool.QueryRow(ctx,
		"SELECT count(*) FROM pg_policies WHERE schemaname = 'rlsfixture' AND tablename = 'no_tenant_id'",
	).Scan(&policies); err != nil {
		t.Fatalf("count policies: %v", err)
	}
	if policies != 0 {
		t.Fatalf("policy count = %d, want 0", policies)
	}
}

// TestEnableRLS_ErrorsNeverForwardRawPostgresText follows the module-wide
// rule that a boundary error must not forward a third-party error's text
// verbatim, since that text can carry caller-supplied input and server
// internals. EnableRLS's own argument — a table name the caller supplied —
// is not sensitive and is echoed back deliberately.
func TestEnableRLS_ErrorsNeverForwardRawPostgresText(t *testing.T) {
	t.Parallel()

	pool := fixtureDB(t)
	ctx := context.Background()

	err := pg.EnableRLS(ctx, pool, "rlsfixture.does_not_exist")
	if err == nil {
		t.Fatal("EnableRLS on a nonexistent table succeeded")
	}
	if !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("error = %v, want it to wrap ErrUnavailable", err)
	}
	if !strings.Contains(err.Error(), "rlsfixture.does_not_exist") {
		t.Errorf("error = %v, want it to name the table the caller asked about", err)
	}
	for _, leak := range []string{"SQLSTATE", "does not exist", "relation"} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("error forwards raw Postgres text (%q): %v", leak, err)
		}
	}
}

// TestEnableRLS_IsIdempotentAndRepairsADriftedPredicate covers the one
// behavioural change from `cas`'s version, which used a bare CREATE POLICY
// and failed the second time.
//
// Idempotence is not a nicety here: EnableRLS is meant to be called from a
// pgmigrate reconciler, which runs on every start, and declarative state
// asserted once is the trap that module exists to close. Repair is the
// second half — a policy whose predicate has drifted (hand-edited in an
// incident, or left behind by an older version of this module) must be
// brought back to TenantPredicate rather than left alone because something
// with the right name exists.
func TestEnableRLS_IsIdempotentAndRepairsADriftedPredicate(t *testing.T) {
	t.Parallel()

	pool := fixtureDB(t)
	ctx := context.Background()
	const table = "rlsfixture.scoped"

	if _, err := pool.Exec(ctx,
		"CREATE TABLE "+table+" (id text PRIMARY KEY, tenant_id text NOT NULL)"); err != nil {
		t.Fatalf("create the fixture table: %v", err)
	}

	for i := range 3 {
		if err := pg.EnableRLS(ctx, pool, table); err != nil {
			t.Fatalf("EnableRLS call %d: %v", i+1, err)
		}
	}

	// Two policies, not one: the tenant predicate is RESTRICTIVE and has a
	// permissive companion, because a table whose only policies are
	// restrictive has an empty permissive set and Postgres then denies
	// every row. Asserting the *kinds* and not just the count is the point
	// — a permissive tenant policy is OR-able away by any policy a
	// consumer adds, which is the disclosure this arrangement fixes.
	var policies int
	if err := pool.QueryRow(ctx,
		"SELECT count(*) FROM pg_policies WHERE schemaname = 'rlsfixture' AND tablename = 'scoped'",
	).Scan(&policies); err != nil {
		t.Fatalf("count policies: %v", err)
	}
	if policies != 2 {
		t.Fatalf("policy count = %d after three calls, want exactly 2 "+
			"(the restrictive tenant policy and its permissive companion)", policies)
	}

	var tenantKind, accessKind string
	if err := pool.QueryRow(ctx,
		"SELECT permissive FROM pg_policies WHERE tablename = 'scoped' AND policyname = $1",
		pg.TenantPolicyName).Scan(&tenantKind); err != nil {
		t.Fatalf("read the tenant policy's kind: %v", err)
	}
	if tenantKind != "RESTRICTIVE" {
		t.Fatalf("the tenant policy is %s, want RESTRICTIVE: a permissive tenant predicate "+
			"is OR-ed away by any additional permissive policy on the table, which is a "+
			"cross-tenant disclosure", tenantKind)
	}
	if err := pool.QueryRow(ctx,
		"SELECT permissive FROM pg_policies WHERE tablename = 'scoped' AND policyname = $1",
		pg.TenantAccessPolicyName).Scan(&accessKind); err != nil {
		t.Fatalf("read the companion policy's kind: %v", err)
	}
	if accessKind != "PERMISSIVE" {
		t.Fatalf("the companion policy is %s, want PERMISSIVE: with no permissive policy "+
			"the restrictive one denies every row", accessKind)
	}

	// Drift the predicate to something that filters nothing, exactly as a
	// hand-edit in an incident would, and require EnableRLS to put it
	// back.
	if _, err := pool.Exec(ctx,
		"ALTER POLICY "+pg.TenantPolicyName+" ON "+table+" USING (true) WITH CHECK (true)"); err != nil {
		t.Fatalf("drift the policy: %v", err)
	}
	if err := pg.EnableRLS(ctx, pool, table); err != nil {
		t.Fatalf("EnableRLS over a drifted policy: %v", err)
	}

	var using string
	if err := pool.QueryRow(ctx,
		"SELECT qual FROM pg_policies WHERE schemaname = 'rlsfixture' AND tablename = 'scoped' "+
			"AND policyname = $1", pg.TenantPolicyName,
	).Scan(&using); err != nil {
		t.Fatalf("read the policy's USING expression: %v", err)
	}
	// Postgres renders the expression back with its own casts on the
	// literals — current_setting('app.tenant_id'::text, true) — so the
	// assertion is about the shape rather than the exact text: the
	// tenant_id comparison and the nullif must both be back, and the
	// always-true predicate must be gone.
	if !strings.Contains(using, "tenant_id") || !strings.Contains(strings.ToLower(using), "nullif") {
		t.Fatalf("the policy's USING expression is %q after EnableRLS; a drifted predicate that filters "+
			"nothing must be repaired, not left in place because a policy with the right name exists", using)
	}
	if strings.TrimSpace(using) == "true" {
		t.Fatalf("the policy's USING expression is still %q: it filters nothing", using)
	}
}

// TestAssertRLSCoverage_ReportsATableWithNoPolicy is the sweep a consumer
// wires into its own CI, checked in both directions: it must report a
// tenant-scoped table with no policy, and must not report one that has had
// EnableRLS applied. A sweep that reported nothing would be useless and a
// sweep that reported everything would be ignored.
func TestAssertRLSCoverage_ReportsATableWithNoPolicy(t *testing.T) {
	t.Parallel()

	pool := fixtureDB(t)
	ctx := context.Background()

	if _, err := pool.Exec(ctx,
		"CREATE TABLE rlsfixture.uncovered (id text PRIMARY KEY, tenant_id text NOT NULL)"); err != nil {
		t.Fatalf("create the uncovered table: %v", err)
	}
	if _, err := pool.Exec(ctx,
		"CREATE TABLE rlsfixture.covered (id text PRIMARY KEY, tenant_id text NOT NULL)"); err != nil {
		t.Fatalf("create the covered table: %v", err)
	}
	// A table with no tenant_id column at all is not tenant-scoped and
	// must not be reported: a sweep that demanded a policy on every table
	// would be noise, and noise gets suppressed.
	if _, err := pool.Exec(ctx,
		"CREATE TABLE rlsfixture.not_tenant_scoped (id text PRIMARY KEY, label text NOT NULL)"); err != nil {
		t.Fatalf("create the unscoped table: %v", err)
	}
	if err := pg.EnableRLS(ctx, pool, "rlsfixture.covered"); err != nil {
		t.Fatalf("EnableRLS: %v", err)
	}

	uncovered, err := pg.AssertRLSCoverage(ctx, pool, "rlsfixture")
	if err != nil {
		t.Fatalf("AssertRLSCoverage: %v", err)
	}
	if !slices.Contains(uncovered, "rlsfixture.uncovered") {
		t.Errorf("AssertRLSCoverage = %v, want it to report rlsfixture.uncovered", uncovered)
	}
	if slices.Contains(uncovered, "rlsfixture.covered") {
		t.Errorf("AssertRLSCoverage = %v, want rlsfixture.covered not reported after EnableRLS", uncovered)
	}
	if slices.Contains(uncovered, "rlsfixture.not_tenant_scoped") {
		t.Errorf("AssertRLSCoverage = %v, want a table with no tenant_id column not reported", uncovered)
	}
}

// TestOpen_ReportsAnUnreachableServerAsUnavailable separates the two error
// classes a caller acts on differently: a configuration that cannot work,
// and a dependency that is not reachable just now.
func TestOpen_ReportsAnUnreachableServerAsUnavailable(t *testing.T) {
	t.Parallel()

	// A deliberately closed port. This needs no container, but it is here
	// rather than in the -short tests because the dial timeout is real
	// time.
	_, err := pg.Open(context.Background(),
		"postgres://nobody:nothing@127.0.0.1:1/absent", pg.PoolConfig{ConnectTimeout: 2_000_000_000})
	if !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("Open() against a closed port error = %v, want ErrUnavailable: it is a retryable condition, "+
			"not a wrong configuration", err)
	}
	if errors.Is(err, domain.ErrInvalidConfig) {
		t.Fatalf("Open() error = %v, must not also be ErrInvalidConfig: a caller retries one and not the other", err)
	}
}
