// Package tenancytest is the conformance suite for `tenancy`: the
// authoritative description of the contract's edge-case behaviour, which
// neither the doc comments nor any interface in the module can be.
//
// It is a sibling package rather than a _test.go file for two forced
// reasons. Identifiers in _test.go files are not importable from outside
// their package, and this suite must be callable from another package and
// from another module — a consumer counts as having adopted `tenancy` when
// this suite runs green in that consumer's CI against that consumer's own
// database and roles, which is what makes "adopted" testable instead of
// asserted. And a non-_test.go file that imports testing would make
// testing a dependency of the production package, so every consumer's
// binary would link it and inherit its flag registrations.
//
// # What the suite is parameterised over
//
// A database and two credentials for it — see Deployment. Everything else
// the suite builds itself, through this module's public surface only:
// tenancy.Migrate, tenancy.Open, tenancy.EnableRLS. That is deliberate. A
// suite handed a pre-wired *tenancy.Tenancy would be unable to assert
// anything about how one gets wired, and the configuration mistakes this
// module is most afraid of — an empty AppRole against a superuser
// connection, a table that was never FORCEd — are all wiring mistakes.
//
// # Why half of this file is about proving the tests are not vacuous
//
// The central claim is that row-level security is a fail-closed backstop:
// a query that forgets its tenant predicate returns nothing rather than
// another tenant's data. That claim is unprovable without a real Postgres,
// and — much worse — it is trivially *vacuously* provable.
//
// A superuser bypasses row security unconditionally, FORCE or not. A
// table's owner bypasses it unless FORCE is set. A role with BYPASSRLS
// bypasses it by name. Under any of those, "tenant A cannot see tenant B's
// rows" passes against a database with no policies at all, because nothing
// was filtered — there was simply nothing there to see from the other
// side, or the assertion ran as a role for which the policy is inert.
//
// So the RLS subtests here do four things a naive suite would not:
//
//  1. EnforcementIsRealBeforeAnyRLSClaimIsMade runs first in spirit and in
//     name. It reads the live catalog as the role that actually runs the
//     statements and requires the deployment to be fail-closed, and it
//     requires the *same check* to return false for a deliberately
//     unseparated deployment — because a check that always said "fine"
//     would be worse than no check.
//  2. Where the connecting role is a superuser, as it is in this module's
//     own harness, it asserts the bypass is real: the same query, on the
//     same database, run without the role switch, sees every tenant's
//     rows. That is what makes the role switch demonstrably the operative
//     difference rather than a line of code nobody checked.
//  3. The cross-tenant write assertion requires SQLSTATE 42501 and
//     nothing else, so it cannot pass because a CHECK constraint, a
//     trigger or a foreign key refused instead of the policy.
//  4. RLSIsForcedSoTheTableOwnerIsSubjectToIt is a differential test
//     against two tables identical in every respect but FORCE, run as a
//     non-superuser role that owns both. The owner is filtered in one and
//     not the other, which is the only way to show FORCE is doing work
//     rather than merely being set.
package tenancytest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/laenenai/tenancy"
)

// Deployment is what a consumer supplies: one Postgres database nothing
// else is using, and the credentials for it.
type Deployment struct {
	// MigrationDSN holds the migration rights: it must be able to create a
	// schema, create a role, and grant on both. It is the credential
	// tenancy.Migrate is given, and the suite also uses it for the DDL
	// that stands up its own tenant-scoped fixture tables.
	//
	// Required.
	MigrationDSN tenancy.DSN

	// RuntimeDSN is the credential the control plane and the data plane
	// connect on. Empty means "the same as MigrationDSN", which is the
	// normal shape for a container harness and is why AppRole exists.
	//
	// A deployment that supplies a genuinely separate, non-superuser
	// runtime credential gets a stronger result out of this suite: the
	// superuser-bypass control assertions become inapplicable and say so,
	// because there is no bypass left to demonstrate.
	RuntimeDSN tenancy.DSN

	// AppRole is the role every data-plane transaction narrows itself into
	// with SET LOCAL ROLE. It deliberately receives no registry privileges.
	//
	// Required, even when RuntimeDSN already names a non-superuser role:
	// the suite asserts that the data-plane role cannot read the registry.
	AppRole string

	// ControlRole is the grantee that receives the registry's privileges.
	// The control-plane login role is a member of it.
	//
	// Required.
	ControlRole string
}

// String names the deployment's application role and redacts both
// credentials. A Deployment is what a harness builds and what a failing
// factory is most likely to print. See CONVENTIONS.md's "Rendering a secret".
func (d Deployment) String() string {
	return fmt.Sprintf("tenancytest.Deployment{MigrationDSN: %s, RuntimeDSN: %s, AppRole: %q, ControlRole: %q}",
		d.MigrationDSN, d.RuntimeDSN, d.AppRole, d.ControlRole)
}

// Format implements fmt.Formatter, the only interface fmt consults for every
// verb.
func (d Deployment) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, d.String()) }

// MarshalJSON renders the same summary as a JSON string.
func (d Deployment) MarshalJSON() ([]byte, error) { return json.Marshal(d.String()) }

// LogValue renders the deployment as a slog group with both credentials
// redacted.
func (d Deployment) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("migration_dsn", redactedPlaceholder),
		slog.String("runtime_dsn", redactedPlaceholder),
		slog.String("app_role", d.AppRole),
	)
}

// redactedPlaceholder is the literal every rendering of a credential in this
// package yields. It matches internal/domain's Redacted, which the suite
// cannot import a second copy of without widening what this package depends
// on.
const redactedPlaceholder = "[REDACTED]"

// RunTenancySuite runs the contract every `tenancy` deployment must
// satisfy.
//
// newDeployment is called once per subtest, receiving that subtest's own
// *testing.T, and must return credentials for a freshly created, empty
// database — nothing migrated, no schema of this module's present. A
// harness that needs per-test setup and teardown registers it with
// t.Cleanup inside newDeployment, so every subtest gets isolated state.
//
// Each subtest migrates and wires from scratch, which is slow and is the
// point: the wiring is part of what is under test.
func RunTenancySuite(t *testing.T, newDeployment func(t *testing.T) Deployment) {
	t.Helper()

	// Resolution and caching: the control plane's half of the contract.
	t.Run("ResolutionFindsTheTenantAndItsPool", testResolutionFindsTheTenantAndItsPool(newDeployment))
	t.Run("ResolutionIsCached", testResolutionIsCached(newDeployment))
	t.Run("UnknownAndDeletingTenantsAreIndistinguishable", testUnknownAndDeletingAreIndistinguishable(newDeployment))
	t.Run("SuspendedTenantIsRefusedAndNeverCached", testSuspendedTenantIsRefusedAndNeverCached(newDeployment))
	t.Run("SecurityModeIsImmutableInTheSchema", testSecurityModeIsImmutable(newDeployment))
	t.Run("RoleSplitHoldsOnEveryRun", testAppRolePrivileges(newDeployment))
	t.Run("WorkerCapacityFitsTheColumn", testWorkerCapacityFitsTheColumn(newDeployment))
	t.Run("RenderingsOfAResolvedScope", testRenderingsOfAResolvedScope(newDeployment))

	// Pool and handle lifecycle: the bugs `cas` found, at the level a
	// consumer can observe them.
	t.Run("CacheEntryDoesNotOutliveAPoolRetirement", testCacheEntryDoesNotOutliveRetirement(newDeployment))
	t.Run("HandleBorrowedAfterCloseIsRefused", testHandleBorrowedAfterCloseIsRefused(newDeployment))
	t.Run("PartialBorrowDuringRetirementIsAccountedFor", testPartialBorrowDuringRetirement(newDeployment))
	t.Run("SessionContextIsResetOnHandleReuse", testSessionContextIsResetOnHandleReuse(newDeployment))
	t.Run("ZeroHandleDeniesRatherThanPanicking", testZeroHandleDenies)

	// The central claim. The first of these is the gate the rest depend
	// on: it establishes that the assertions below are being made under
	// enforcement rather than under a bypass.
	t.Run("EnforcementIsRealBeforeAnyRLSClaimIsMade", testEnforcementIsReal(newDeployment))
	t.Run("RLSDeniesWithoutTenantContext", testRLSDeniesWithoutTenantContext(newDeployment))
	t.Run("RLSDeniesTheWrongTenantContext", testRLSDeniesTheWrongTenantContext(newDeployment))
	t.Run("RLSRefusesACrossTenantWrite", testRLSRefusesACrossTenantWrite(newDeployment))
	t.Run("RLSIsForcedSoTheTableOwnerIsSubjectToIt", testRLSIsForced(newDeployment))
	t.Run("RLSCoverageSweepReportsAMissingPolicy", testRLSCoverageSweep(newDeployment))
	t.Run("RLSAnAddedPermissivePolicyCannotWiden", testRLSAddedPermissivePolicyCannotWiden(newDeployment))
}

// The fixture schema and the two tables the suite stands up. They live
// outside tenancy's own schema so that a coverage sweep of the registry
// has no opinion about them either way.
const (
	fixtureSchema       = "tenancytest_fixture"
	forcedTable         = fixtureSchema + ".scoped"
	unforcedTable       = fixtureSchema + ".scoped_unforced"
	uncoveredTable      = fixtureSchema + ".no_policy"
	wrongPredicateTable = fixtureSchema + ".wrong_predicate"
	fixtureOwnerRol     = "tenancytest_owner"
)

// env is one wired deployment: the module, the credentials, and the raw
// administrative pool the suite uses for DDL and for the control
// assertions that must deliberately bypass the module.
type env struct {
	dep     Deployment
	admin   *pgxpool.Pool
	tenancy *tenancy.Tenancy

	poolA   tenancy.Pool
	poolB   tenancy.Pool
	tenantA tenancy.Tenant
	tenantB tenancy.Tenant

	// adminIsSuperuser records whether the runtime credential bypasses row
	// security outright, which decides whether the bypass-is-real control
	// assertions apply at all.
	adminIsSuperuser bool
}

// setup migrates the database, stands up the fixture tables, opens the
// module, and registers two pools and two tenants.
//
// Two pools, both pointing at the same database, is not a contrivance: a
// pool is a named triple of (metadata target, blob store set, region), so
// two pools over one database differ in identity exactly as two pools over
// two databases do, and it is what lets the lifecycle subtests force an
// eviction with MaxPools=1 against a single container.
func setup(t *testing.T, dep Deployment, cache tenancy.CacheOptions, appRole string, maxConns int32) *env {
	t.Helper()
	ctx := context.Background()

	if dep.MigrationDSN == "" {
		t.Fatal("tenancytest: Deployment.MigrationDSN is required")
	}
	if dep.AppRole == "" {
		t.Fatal("tenancytest: Deployment.AppRole is required")
	}
	runtimeDSN := dep.RuntimeDSN
	if runtimeDSN.IsZero() {
		runtimeDSN = dep.MigrationDSN
	}

	if err := tenancy.Migrate(ctx, tenancy.MigrateConfig{
		DSN:         dep.MigrationDSN,
		AppRole:     dep.AppRole,
		ControlRole: dep.ControlRole,
	}); err != nil {
		t.Fatalf("tenancy.Migrate: %v", err)
	}

	admin, err := pgxpool.New(ctx, string(dep.MigrationDSN))
	if err != nil {
		t.Fatalf("open the administrative pool: %v", err)
	}
	t.Cleanup(admin.Close)

	e := &env{dep: dep, admin: admin}
	e.standUpFixtures(ctx, t)

	e.tenancy, err = tenancy.Open(ctx, tenancy.Config{
		RegistryDSN: runtimeDSN,
		AppRole:     appRole,
		Postgres:    tenancy.PoolConfig{MaxConns: maxConns, ApplicationName: "tenancytest"},
		Cache:       cache,
	})
	if err != nil {
		t.Fatalf("tenancy.Open: %v", err)
	}
	t.Cleanup(func() { _ = e.tenancy.Close() })

	control := e.tenancy.Control()
	e.poolA = mustCreatePool(ctx, t, control, "pool-a", runtimeDSN)
	e.poolB = mustCreatePool(ctx, t, control, "pool-b", runtimeDSN)
	e.tenantA = mustCreateTenant(ctx, t, control, e.poolA.ID, "tenant-a")
	e.tenantB = mustCreateTenant(ctx, t, control, e.poolB.ID, "tenant-b")

	e.adminIsSuperuser = runtimeRoleIsSuperuser(ctx, t, admin, runtimeDSN)
	return e
}

// standUpFixtures creates the suite's own tenant-scoped tables: one
// FORCEd through tenancy.EnableRLS, one deliberately not FORCEd but
// otherwise identical, and one with no policy at all for the coverage
// sweep.
//
// The non-superuser owner role is what makes the FORCE claim testable. In
// a container harness the connecting role is a superuser, and a superuser
// bypasses row security no matter what, so "the owner is subject to the
// policy" cannot be demonstrated by the connecting role at all. A separate
// NOSUPERUSER, NOBYPASSRLS role that *owns* the tables can demonstrate it,
// and the unforced twin is the control.
func (e *env) standUpFixtures(ctx context.Context, t *testing.T) {
	t.Helper()

	execAll(ctx, t, e.admin,
		"CREATE SCHEMA IF NOT EXISTS "+quote(fixtureSchema),
	)
	ensureRole(ctx, t, e.admin, fixtureOwnerRol)
	ensureRole(ctx, t, e.admin, e.dep.AppRole)

	execAll(ctx, t, e.admin,
		"GRANT USAGE, CREATE ON SCHEMA "+quote(fixtureSchema)+" TO "+quote(fixtureOwnerRol),
		"GRANT USAGE ON SCHEMA "+quote(fixtureSchema)+" TO "+quote(e.dep.AppRole),
		"CREATE TABLE IF NOT EXISTS "+forcedTable+" (id text PRIMARY KEY, tenant_id text NOT NULL, data text NOT NULL DEFAULT '')",
		"CREATE TABLE IF NOT EXISTS "+unforcedTable+" (id text PRIMARY KEY, tenant_id text NOT NULL, data text NOT NULL DEFAULT '')",
		"CREATE TABLE IF NOT EXISTS "+uncoveredTable+" (id text PRIMARY KEY, tenant_id text NOT NULL)",
		"CREATE TABLE IF NOT EXISTS "+wrongPredicateTable+" (id text PRIMARY KEY, tenant_id text NOT NULL)",
		"ALTER TABLE "+wrongPredicateTable+" ENABLE ROW LEVEL SECURITY",
		"ALTER TABLE "+wrongPredicateTable+" FORCE ROW LEVEL SECURITY",
		"CREATE POLICY "+tenancy.TenantPolicyName+" ON "+wrongPredicateTable+" AS RESTRICTIVE USING (true) WITH CHECK (true)",
		"CREATE POLICY "+tenancy.TenantAccessPolicyName+" ON "+wrongPredicateTable+" AS PERMISSIVE USING (true) WITH CHECK (true)",
		"ALTER TABLE "+forcedTable+" OWNER TO "+quote(fixtureOwnerRol),
		"ALTER TABLE "+unforcedTable+" OWNER TO "+quote(fixtureOwnerRol),
		"GRANT SELECT, INSERT, UPDATE, DELETE ON "+forcedTable+" TO "+quote(e.dep.AppRole),
		"GRANT SELECT, INSERT, UPDATE, DELETE ON "+unforcedTable+" TO "+quote(e.dep.AppRole),
	)

	// The table under test, through the module's own entry point.
	if err := tenancy.EnableRLS(ctx, e.admin, forcedTable); err != nil {
		t.Fatalf("tenancy.EnableRLS(%s): %v", forcedTable, err)
	}
	// Idempotence, asserted where it is cheap: EnableRLS is meant to be
	// called from a reconciler that runs on every start, and `cas`'s
	// version failed the second time.
	if err := tenancy.EnableRLS(ctx, e.admin, forcedTable); err != nil {
		t.Fatalf("tenancy.EnableRLS(%s) a second time: %v (it must be idempotent: a consumer calls it from a reconciler)", forcedTable, err)
	}

	// The control: identical in every respect except FORCE, and built from
	// the module's own exported predicate and policy name so that the one
	// difference is the only difference.
	execAll(ctx, t, e.admin,
		"ALTER TABLE "+unforcedTable+" ENABLE ROW LEVEL SECURITY",
		"DROP POLICY IF EXISTS "+quote(tenancy.TenantPolicyName)+" ON "+unforcedTable,
		"CREATE POLICY "+quote(tenancy.TenantPolicyName)+" ON "+unforcedTable+
			" USING ("+tenancy.TenantPredicate+") WITH CHECK ("+tenancy.TenantPredicate+")",
	)
}

// ---------------------------------------------------------------------------
// Resolution and the control plane
// ---------------------------------------------------------------------------

func testResolutionFindsTheTenantAndItsPool(newDeployment func(t *testing.T) Deployment) func(*testing.T) {
	return func(t *testing.T) {
		e := setup(t, newDeployment(t), defaultCache(), "", 0)
		ctx := context.Background()

		scoped, err := e.tenancy.Scope(ctx, e.tenantA.ID)
		if err != nil {
			t.Fatalf("Scope(tenantA): %v", err)
		}
		if !scoped.Valid() {
			t.Fatal("Scope returned an invalid handle for an active tenant")
		}
		if scoped.Tenant().ID != e.tenantA.ID {
			t.Errorf("handle tenant = %s, want %s", scoped.Tenant().ID, e.tenantA.ID)
		}
		if scoped.Pool().ID != e.poolA.ID {
			t.Errorf("handle pool = %s, want %s (the pool tenancy.tenants.pool_id names)", scoped.Pool().ID, e.poolA.ID)
		}
		if scoped.Pool().Region != e.poolA.Region {
			t.Errorf("handle pool region = %q, want %q: residency is a pool attribute and must survive resolution",
				scoped.Pool().Region, e.poolA.Region)
		}

		// The handle actually works, which is the part no in-memory
		// adapter can prove.
		var one int
		if err := scoped.Tx(ctx, func(ctx context.Context, tx tenancy.TenantTx) error {
			return tx.QueryRow(ctx, "SELECT 1").Scan(&one)
		}); err != nil {
			t.Fatalf("a scoped transaction on a resolved handle: %v", err)
		}
		if one != 1 {
			t.Fatalf("SELECT 1 returned %d", one)
		}
	}
}

func testResolutionIsCached(newDeployment func(t *testing.T) Deployment) func(*testing.T) {
	return func(t *testing.T) {
		e := setup(t, newDeployment(t), defaultCache(), "", 0)
		ctx := context.Background()

		if _, err := e.tenancy.Scope(ctx, e.tenantA.ID); err != nil {
			t.Fatalf("Scope(tenantA): %v", err)
		}

		// Renaming the row behind the cache is how caching is observable
		// through the public surface: there is no counter to read, so the
		// test changes something resolution would otherwise notice.
		execAll(ctx, t, e.admin,
			"UPDATE tenancy.tenants SET name = 'renamed-behind-the-cache' WHERE id = '"+string(e.tenantA.ID)+"'")

		scoped, err := e.tenancy.Scope(ctx, e.tenantA.ID)
		if err != nil {
			t.Fatalf("Scope(tenantA) again: %v", err)
		}
		if scoped.Tenant().Name != e.tenantA.Name {
			t.Errorf("handle tenant name = %q after a write behind the cache, want the cached %q: "+
				"a resolution within TTL must be served from cache", scoped.Tenant().Name, e.tenantA.Name)
		}

		// And the cache is a cache, not a permanent answer: a second
		// Tenancy with a zero TTL sees the new row.
		fresh, err := tenancy.Open(ctx, tenancy.Config{
			RegistryDSN: e.runtimeDSN(),
			Cache:       tenancy.CacheOptions{TTL: 0, NegativeTTL: 0},
		})
		if err != nil {
			t.Fatalf("open a second Tenancy with no TTL: %v", err)
		}
		defer func() { _ = fresh.Close() }()

		uncached, err := fresh.Scope(ctx, e.tenantA.ID)
		if err != nil {
			t.Fatalf("Scope(tenantA) with no TTL: %v", err)
		}
		if uncached.Tenant().Name != "renamed-behind-the-cache" {
			t.Errorf("handle tenant name = %q with a zero TTL, want the row's current value: "+
				"the cache must not be the only source of truth", uncached.Tenant().Name)
		}
	}
}

func testUnknownAndDeletingAreIndistinguishable(newDeployment func(t *testing.T) Deployment) func(*testing.T) {
	return func(t *testing.T) {
		e := setup(t, newDeployment(t), defaultCache(), "", 0)
		ctx := context.Background()

		unknown := tenancy.NewTenantID(tenancy.SystemClock{})
		_, unknownErr := e.tenancy.Scope(ctx, unknown)
		if !errors.Is(unknownErr, tenancy.ErrNotAuthorizedOrNotFound) {
			t.Fatalf("Scope(unknown) error = %v, want ErrNotAuthorizedOrNotFound", unknownErr)
		}

		if _, err := e.tenancy.Control().SetTenantStatus(ctx, e.tenantB.ID, tenancy.TenantStatusDeleting); err != nil {
			t.Fatalf("SetTenantStatus(deleting): %v", err)
		}
		_, deletingErr := e.tenancy.Scope(ctx, e.tenantB.ID)
		if !errors.Is(deletingErr, tenancy.ErrNotAuthorizedOrNotFound) {
			t.Fatalf("Scope(deleting) error = %v, want ErrNotAuthorizedOrNotFound", deletingErr)
		}

		// The messages must be identical, not merely the same sentinel: a
		// caller comparing error strings must learn nothing either.
		if unknownErr.Error() != deletingErr.Error() {
			t.Errorf("an unknown tenant says %q and a deleting one says %q; a caller can tell them apart, "+
				"which is an existence oracle on the tenant id space", unknownErr, deletingErr)
		}

		malformed, err := e.tenancy.Scope(ctx, tenancy.TenantID("not-a-ulid"))
		if !errors.Is(err, tenancy.ErrNotAuthorizedOrNotFound) {
			t.Fatalf("Scope(malformed) error = %v, want ErrNotAuthorizedOrNotFound", err)
		}
		if malformed.Valid() {
			t.Error("Scope(malformed) returned a valid handle")
		}
		if errors.Is(err, tenancy.ErrMalformedID) {
			t.Errorf("Scope(malformed) error = %v, must not report ErrMalformedID on a lookup path", err)
		}
	}
}

func testSuspendedTenantIsRefusedAndNeverCached(newDeployment func(t *testing.T) Deployment) func(*testing.T) {
	return func(t *testing.T) {
		// A long TTL is the point: if suspension were cached, restoring
		// the tenant below would not be visible for an hour.
		e := setup(t, newDeployment(t), tenancy.CacheOptions{TTL: time.Hour, NegativeTTL: time.Hour}, "", 0)
		ctx := context.Background()
		control := e.tenancy.Control()

		// Warm the positive cache first: the status change must invalidate
		// it, not wait for TTL.
		if _, err := e.tenancy.Scope(ctx, e.tenantA.ID); err != nil {
			t.Fatalf("Scope(active): %v", err)
		}

		if _, err := control.SetTenantStatus(ctx, e.tenantA.ID, tenancy.TenantStatusSuspended); err != nil {
			t.Fatalf("SetTenantStatus(suspended): %v", err)
		}

		_, err := e.tenancy.Scope(ctx, e.tenantA.ID)
		if !errors.Is(err, tenancy.ErrUnavailable) {
			t.Fatalf("Scope(suspended after a warm cache) error = %v, want ErrUnavailable", err)
		}
		if errors.Is(err, tenancy.ErrNotAuthorizedOrNotFound) {
			t.Fatalf("Scope(suspended) error = %v, must not also be ErrNotAuthorizedOrNotFound: "+
				"suspension is a distinct, operator-reversible outcome and a caller is told so", err)
		}

		if _, err := control.SetTenantStatus(ctx, e.tenantA.ID, tenancy.TenantStatusActive); err != nil {
			t.Fatalf("SetTenantStatus(active): %v", err)
		}
		if _, err := e.tenancy.Scope(ctx, e.tenantA.ID); err != nil {
			t.Fatalf("Scope() immediately after restoring the tenant = %v, want nil: "+
				"unsuspending is an operator action and must take effect on the next resolution, not after a TTL", err)
		}

		// Deletion invalidates a warm entry too, and must be
		// indistinguishable from unknown.
		if _, err := control.SetTenantStatus(ctx, e.tenantA.ID, tenancy.TenantStatusDeleting); err != nil {
			t.Fatalf("SetTenantStatus(deleting): %v", err)
		}
		if _, err := e.tenancy.Scope(ctx, e.tenantA.ID); !errors.Is(err, tenancy.ErrNotAuthorizedOrNotFound) {
			t.Fatalf("Scope(deleting after a warm cache) error = %v, want ErrNotAuthorizedOrNotFound", err)
		}

		// deleting is terminal: a tenant whose data is being erased must
		// not be resurrected by a status update.
		for _, next := range []tenancy.TenantStatus{tenancy.TenantStatusActive, tenancy.TenantStatusSuspended} {
			if _, err := control.SetTenantStatus(ctx, e.tenantA.ID, next); !errors.Is(err, tenancy.ErrConflict) {
				t.Errorf("SetTenantStatus(deleting -> %s) error = %v, want ErrConflict", next, err)
			}
		}
	}
}

func testSecurityModeIsImmutable(newDeployment func(t *testing.T) Deployment) func(*testing.T) {
	return func(t *testing.T) {
		e := setup(t, newDeployment(t), defaultCache(), "", 0)
		ctx := context.Background()

		// There is no method that could do this, which is the point: the
		// attempt is made in raw SQL as the owner, exactly as a later
		// increment or an incident script would.
		_, err := e.admin.Exec(ctx,
			"UPDATE tenancy.tenants SET security_mode = 'vault' WHERE id = $1", string(e.tenantA.ID))
		if err == nil {
			t.Fatal("the owner was able to change a tenant's security_mode: the schema's immutability trigger " +
				"is not enforcing it, and already-stored content could be orphaned under the wrong key hierarchy")
		}
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "P0001" {
			t.Fatalf("the refusal was %v, want a P0001 raise_exception from the trigger: a refusal from some "+
				"other mechanism would mean the trigger is not what is holding the invariant", err)
		}

		// A status change on the same row must still work, so the trigger
		// is narrow rather than a blanket refusal to update.
		if _, err := e.tenancy.Control().SetTenantStatus(ctx, e.tenantA.ID, tenancy.TenantStatusSuspended); err != nil {
			t.Fatalf("SetTenantStatus after the refused security_mode change: %v", err)
		}

		// A tenant's pool_id decides where its data lives; a pool's
		// metadata_dsn decides which database it is. Both are immutable
		// through an ordinary UPDATE so a mistake or an injection cannot
		// repoint them.
		if _, err := e.admin.Exec(ctx,
			"UPDATE tenancy.tenants SET pool_id = $2 WHERE id = $1", string(e.tenantA.ID), string(e.poolB.ID)); err == nil {
			t.Fatal("pool_id was mutable; a tenant could be repointed without an explicit migration")
		}
		if _, err := e.admin.Exec(ctx,
			"UPDATE tenancy.pools SET metadata_dsn = 'postgres://evil.invalid/db' WHERE id = $1", string(e.poolA.ID)); err == nil {
			t.Fatal("metadata_dsn was mutable; a pool could be repointed without an explicit migration")
		}
	}
}

// testAppRolePrivileges asserts the reconciler's grant set from the
// application role's own point of view: exactly what internal/migrate
// claims, and nothing more.
//
// It matters because the grants are *reconciled* rather than migrated —
// asserted on every Up, recording no version — and the failure mode that
// design exists to close is silent: a deployment that renamed its role
// would otherwise come up with no privilege separation at all while the
// migrator reported everything applied.
func testWorkerCapacityFitsTheColumn(newDeployment func(t *testing.T) Deployment) func(*testing.T) {
	return func(t *testing.T) {
		e := setup(t, newDeployment(t), defaultCache(), "", 0)
		ctx := context.Background()

		_, err := e.tenancy.Control().CreatePool(ctx, tenancy.PoolSpec{
			Name: "overflow", Region: "test-region", MetadataDSN: e.poolA.MetadataDSN,
			BlobConfigRef: "blob-overflow", WorkerCapacity: int(^uint32(0)>>1) + 1,
		})
		if !errors.Is(err, tenancy.ErrInvalidConfig) {
			t.Fatalf("CreatePool with an out-of-range capacity error = %v, want ErrInvalidConfig", err)
		}
	}
}

func testAppRolePrivileges(newDeployment func(t *testing.T) Deployment) func(*testing.T) {
	return func(t *testing.T) {
		dep := newDeployment(t)
		e := setup(t, dep, defaultCache(), dep.AppRole, 0)
		ctx := context.Background()

		controlCases := []struct {
			privilege string
			want      bool
		}{
			{"SELECT", true},
			{"INSERT", true},
			{"UPDATE", true},
			{"DELETE", false},
			{"TRUNCATE", false},
			{"REFERENCES", false},
			{"TRIGGER", false},
		}
		for _, table := range []string{"tenancy.pools", "tenancy.tenants"} {
			for _, tc := range controlCases {
				var has bool
				err := e.admin.QueryRow(ctx,
					"SELECT has_table_privilege($1, $2, $3)", dep.ControlRole, table, tc.privilege).Scan(&has)
				if err != nil {
					t.Fatalf("has_table_privilege(%s, %s, %s): %v", dep.ControlRole, table, tc.privilege, err)
				}
				if has != tc.want {
					t.Errorf("%s on %s for ControlRole = %v, want %v", tc.privilege, table, has, tc.want)
				}
			}
		}

		// The data-plane role must have no registry privilege at all; that
		// is the role split, and it is what keeps a tenant-pool injection
		// away from every pool's DSN.
		for _, table := range []string{"tenancy.pools", "tenancy.tenants"} {
			for _, privilege := range []string{"SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"} {
				var has bool
				if err := e.admin.QueryRow(ctx,
					"SELECT has_table_privilege($1, $2, $3)", dep.AppRole, table, privilege).Scan(&has); err != nil {
					t.Fatalf("has_table_privilege(%s, %s, %s): %v", dep.AppRole, table, privilege, err)
				}
				if has {
					t.Errorf("data-plane role %s has %s on %s; the role split requires none", dep.AppRole, privilege, table)
				}
			}
		}

		// Re-running Up must leave the same answer: that is what
		// "asserted on every run" means.
		if err := tenancy.Migrate(ctx, tenancy.MigrateConfig{DSN: dep.MigrationDSN, AppRole: dep.AppRole, ControlRole: dep.ControlRole}); err != nil {
			t.Fatalf("tenancy.Migrate a second time: %v", err)
		}
		var stillHasDelete bool
		if err := e.admin.QueryRow(ctx,
			"SELECT has_table_privilege($1, 'tenancy.tenants', 'DELETE')", dep.ControlRole).Scan(&stillHasDelete); err != nil {
			t.Fatalf("re-read DELETE: %v", err)
		}
		if stillHasDelete {
			t.Error("DELETE on tenancy.tenants appeared after a second Migrate")
		}

		// Simulate the pre-split grant set, then re-run Up. The reconciler
		// must revoke the data role's old registry access, not merely grant
		// the control role.
		if _, err := e.admin.Exec(ctx, "GRANT SELECT ON tenancy.tenants TO "+quote(dep.AppRole)); err != nil {
			t.Fatalf("grant the old data-role privilege: %v", err)
		}
		if err := tenancy.Migrate(ctx, tenancy.MigrateConfig{DSN: dep.MigrationDSN, AppRole: dep.AppRole, ControlRole: dep.ControlRole}); err != nil {
			t.Fatalf("tenancy.Migrate after granting the old privilege: %v", err)
		}
		var oldGrantSurvived bool
		if err := e.admin.QueryRow(ctx,
			"SELECT has_table_privilege($1, 'tenancy.tenants', 'SELECT')", dep.AppRole).Scan(&oldGrantSurvived); err != nil {
			t.Fatalf("re-read the old data-role privilege: %v", err)
		}
		if oldGrantSurvived {
			t.Error("the data role kept a registry grant after Migrate; the role split is not repaired on upgrade")
		}
	}
}

// ---------------------------------------------------------------------------
// Pool and handle lifecycle
// ---------------------------------------------------------------------------

// testCacheEntryDoesNotOutliveRetirement is the integration-level form of
// the bug `cas` found: an entry evicted from the pool cache must not go on
// handing out the pool it named once that pool has been closed.
//
// MaxPools=1 with two pools forces the eviction; a cancelable context on
// the first resolution is what lets the test release the last borrow and
// make the retired pool actually close.
func testCacheEntryDoesNotOutliveRetirement(newDeployment func(t *testing.T) Deployment) func(*testing.T) {
	return func(t *testing.T) {
		e := setup(t, newDeployment(t), tenancy.CacheOptions{TTL: time.Hour, NegativeTTL: time.Hour, MaxPools: 1}, "", 0)
		ctx := context.Background()

		holdCtx, cancelHold := context.WithCancel(ctx)
		retired, err := e.tenancy.Scope(holdCtx, e.tenantA.ID)
		if err != nil {
			t.Fatalf("Scope(tenantA): %v", err)
		}
		if err := ping(holdCtx, retired); err != nil {
			t.Fatalf("the freshly resolved handle does not work: %v", err)
		}

		// Resolving a tenant in the other pool evicts pool A's entry
		// (MaxPools=1). The handle above must keep working, because its
		// context has not finished.
		if _, err := e.tenancy.Scope(ctx, e.tenantB.ID); err != nil {
			t.Fatalf("Scope(tenantB), the evicting resolution: %v", err)
		}
		if err := ping(holdCtx, retired); err != nil {
			t.Fatalf("an eviction closed a pool a live handle was still using: %v", err)
		}

		// Releasing the last borrow lets the retired pool close.
		cancelHold()
		waitUntilRefused(t, retired)

		// The decisive half: resolving tenant A again must produce a
		// working handle. If the cache had outlived the retirement it
		// would hand back the closed pool.
		again, err := e.tenancy.Scope(ctx, e.tenantA.ID)
		if err != nil {
			t.Fatalf("Scope(tenantA) after its pool was retired: %v", err)
		}
		if err := ping(ctx, again); err != nil {
			t.Fatalf("a resolution after a pool retirement returned a handle onto the closed pool: %v", err)
		}
	}
}

func testHandleBorrowedAfterCloseIsRefused(newDeployment func(t *testing.T) Deployment) func(*testing.T) {
	return func(t *testing.T) {
		e := setup(t, newDeployment(t), defaultCache(), "", 0)
		ctx := context.Background()

		scoped, err := e.tenancy.Scope(ctx, e.tenantA.ID)
		if err != nil {
			t.Fatalf("Scope(tenantA): %v", err)
		}
		if err := ping(ctx, scoped); err != nil {
			t.Fatalf("the handle does not work before Close: %v", err)
		}

		if err := e.tenancy.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}

		err = ping(ctx, scoped)
		if err == nil {
			t.Fatal("a handle borrowed before Close still works afterwards: it is holding a pool Close " +
				"was supposed to have torn down")
		}
		if !errors.Is(err, tenancy.ErrUnavailable) {
			t.Fatalf("the refusal was %v, want ErrUnavailable: a closed pool must surface as this module's "+
				"own retryable sentinel, not as a third-party error", err)
		}

		// And a fresh resolution is refused too, so a caller cannot work
		// around it by resolving again.
		if _, err := e.tenancy.Scope(ctx, e.tenantA.ID); !errors.Is(err, tenancy.ErrUnavailable) {
			t.Fatalf("Scope after Close error = %v, want ErrUnavailable", err)
		}
	}
}

// testPartialBorrowDuringRetirement is the regression `cas` found while
// fixing the previous one: an entry with two live borrowers, evicted, with
// only one borrower released, must still be tracked — still open, because
// the second borrower is live, and still closed by a subsequent Close.
//
// Both borrowers are on the *same* pool, which is what makes the partial
// release possible: two tenants hosted in one pool share one
// reference-counted entry.
func testPartialBorrowDuringRetirement(newDeployment func(t *testing.T) Deployment) func(*testing.T) {
	return func(t *testing.T) {
		e := setup(t, newDeployment(t), tenancy.CacheOptions{TTL: time.Hour, NegativeTTL: time.Hour, MaxPools: 1}, "", 0)
		ctx := context.Background()

		// A second tenant in pool A, so two independent borrowers land on
		// one entry.
		tenantA2 := mustCreateTenant(ctx, t, e.tenancy.Control(), e.poolA.ID, "tenant-a2")

		ctx1, cancel1 := context.WithCancel(ctx)
		first, err := e.tenancy.Scope(ctx1, e.tenantA.ID)
		if err != nil {
			t.Fatalf("Scope(tenantA): %v", err)
		}
		ctx2, cancel2 := context.WithCancel(ctx)
		defer cancel2()
		second, err := e.tenancy.Scope(ctx2, tenantA2.ID)
		if err != nil {
			t.Fatalf("Scope(tenantA2): %v", err)
		}
		if first.Pool().ID != second.Pool().ID {
			t.Fatalf("two tenants in pool %s resolved to pools %s and %s", e.poolA.ID, first.Pool().ID, second.Pool().ID)
		}

		// Evict pool A.
		if _, err := e.tenancy.Scope(ctx, e.tenantB.ID); err != nil {
			t.Fatalf("Scope(tenantB), the evicting resolution: %v", err)
		}

		// Release only the first borrow. The entry must stay open for the
		// second.
		cancel1()
		time.Sleep(100 * time.Millisecond)
		if err := ping(ctx2, second); err != nil {
			t.Fatalf("releasing one of two borrows closed the pool the other was still using: %v", err)
		}

		// And Close must still close it. Under the bug this regresses, the
		// partial release had already dropped the entry from the retired
		// set and Close would have returned without closing it.
		if err := e.tenancy.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if err := ping(ctx2, second); !errors.Is(err, tenancy.ErrUnavailable) {
			t.Fatalf("after Close the partially released pool answers %v, want ErrUnavailable: Close did not "+
				"account for an entry whose borrowers were only partly released", err)
		}
	}
}

// testSessionContextIsResetOnHandleReuse is the pooled-connection claim:
// the tenant scope a transaction establishes must be gone the instant that
// transaction ends, so the next borrower of the same physical connection
// inherits nothing.
//
// MaxConns=1 is what makes it a real test rather than a hopeful one: with
// one connection in the pool, the "next borrower" is necessarily the same
// connection the previous transaction used. Without it, a leaked
// session-level setting could hide on a connection nothing touches again.
func testSessionContextIsResetOnHandleReuse(newDeployment func(t *testing.T) Deployment) func(*testing.T) {
	return func(t *testing.T) {
		dep := newDeployment(t)
		e := setup(t, dep, defaultCache(), dep.AppRole, 1)
		ctx := context.Background()

		// Both tenants in one pool, so both handles share one pgxpool —
		// and with MaxConns=1, one connection.
		tenantA2 := mustCreateTenant(ctx, t, e.tenancy.Control(), e.poolA.ID, "tenant-a2")

		first := mustScope(ctx, t, e.tenancy, e.tenantA.ID)
		second := mustScope(ctx, t, e.tenancy, tenantA2.ID)

		var seen string
		if err := first.Tx(ctx, func(ctx context.Context, tx tenancy.TenantTx) error {
			return tx.QueryRow(ctx, "SELECT current_setting($1, true)", tenancy.TenantGUC).Scan(&seen)
		}); err != nil {
			t.Fatalf("first scoped transaction: %v", err)
		}
		if seen != string(e.tenantA.ID) {
			t.Fatalf("%s inside tenant A's transaction = %q, want %q", tenancy.TenantGUC, seen, e.tenantA.ID)
		}

		// The decisive probe: a transaction on the same pool that sets no
		// tenant context must observe none. This is what the enforcement
		// report calls ResidualTenantContext, and it runs on the one
		// connection tenant A's transaction just used.
		report, err := first.CheckEnforcement(ctx, forcedTable)
		if err != nil {
			t.Fatalf("CheckEnforcement: %v", err)
		}
		if report.ResidualTenantContext != "" {
			t.Fatalf("a transaction that set no tenant context observed %s = %q: tenant A's scope survived "+
				"its own transaction onto a pooled connection, which is a cross-tenant disclosure",
				tenancy.TenantGUC, report.ResidualTenantContext)
		}

		// And the next handle on that same connection sees its own tenant,
		// not the previous one.
		if err := second.Tx(ctx, func(ctx context.Context, tx tenancy.TenantTx) error {
			return tx.QueryRow(ctx, "SELECT current_setting($1, true)", tenancy.TenantGUC).Scan(&seen)
		}); err != nil {
			t.Fatalf("second scoped transaction: %v", err)
		}
		if seen != string(tenantA2.ID) {
			t.Fatalf("%s inside the second tenant's transaction = %q, want %q", tenancy.TenantGUC, seen, tenantA2.ID)
		}

		// A rollback must clear the scope exactly as a commit does, since
		// an error path is the case nobody tests.
		errFromFn := errors.New("tenancytest: deliberate failure")
		if err := first.Tx(ctx, func(context.Context, tenancy.TenantTx) error { return errFromFn }); !errors.Is(err, errFromFn) {
			t.Fatalf("Tx returned %v, want the function's own error unwrapped", err)
		}
		report, err = first.CheckEnforcement(ctx, forcedTable)
		if err != nil {
			t.Fatalf("CheckEnforcement after a rolled-back transaction: %v", err)
		}
		if report.ResidualTenantContext != "" {
			t.Fatalf("after a rolled-back scoped transaction, %s = %q on a reused connection",
				tenancy.TenantGUC, report.ResidualTenantContext)
		}
	}
}

// testZeroHandleDenies needs no database: it is the charter's "a missing
// predicate denies rather than leaking" applied to the one data-plane
// shape Go cannot forbid, a struct's zero value.
func testZeroHandleDenies(t *testing.T) {
	t.Parallel()

	var zero tenancy.Scoped
	if zero.Valid() {
		t.Fatal("the zero Scoped reports itself valid")
	}

	err := zero.Tx(context.Background(), func(context.Context, tenancy.TenantTx) error {
		t.Fatal("the zero Scoped ran a transaction")
		return nil
	})
	if !errors.Is(err, tenancy.ErrNoTenantScope) {
		t.Fatalf("zero Scoped Tx error = %v, want ErrNoTenantScope (a validated refusal, not a panic)", err)
	}

	if _, err := zero.CheckEnforcement(context.Background()); !errors.Is(err, tenancy.ErrNoTenantScope) {
		t.Fatalf("zero Scoped CheckEnforcement error = %v, want ErrNoTenantScope", err)
	}
}

// ---------------------------------------------------------------------------
// The central claim
// ---------------------------------------------------------------------------

// testEnforcementIsReal is the gate every RLS assertion below depends on.
// It establishes three things, and the suite is worthless without all
// three.
func testEnforcementIsReal(newDeployment func(t *testing.T) Deployment) func(*testing.T) {
	return func(t *testing.T) {
		dep := newDeployment(t)
		e := setup(t, dep, defaultCache(), dep.AppRole, 0)
		ctx := context.Background()

		scoped := mustScope(ctx, t, e.tenancy, e.tenantA.ID)

		// One: the deployment the other subtests use is fail-closed, as
		// read from the live catalog by the role that actually runs the
		// statements.
		report, err := scoped.CheckEnforcement(ctx, forcedTable)
		if err != nil {
			t.Fatalf("CheckEnforcement: %v", err)
		}
		if !report.FailClosed() {
			t.Fatalf("the deployment is not fail-closed, so every row-level-security assertion in this suite "+
				"would pass without proving anything: %v", report.Findings())
		}
		if report.Role != dep.AppRole {
			t.Errorf("statements run as %q, want %q: AppRole is not taking effect", report.Role, dep.AppRole)
		}
		if report.Superuser || report.BypassRLS {
			t.Fatalf("%s is superuser=%v bypassrls=%v; either one makes every policy inert",
				report.Role, report.Superuser, report.BypassRLS)
		}
		if len(report.Tables) != 1 {
			t.Fatalf("CheckEnforcement reported %d tables, want 1", len(report.Tables))
		}
		table := report.Tables[0]
		switch {
		case !table.Exists:
			t.Fatalf("%s does not exist", table.Table)
		case !table.RowSecurityEnabled:
			t.Fatalf("%s does not have row-level security enabled", table.Table)
		case !table.RowSecurityForced:
			t.Fatalf("%s does not have row-level security FORCEd, so its owner is exempt from its own policy", table.Table)
		case !table.PolicyPresent:
			t.Fatalf("%s carries no %s policy", table.Table, tenancy.TenantPolicyName)
		case table.OwnedByRole:
			t.Errorf("%s is owned by %s, the role that runs the statements; FORCE covers that, but privilege "+
				"separation is cleaner if the application role owns nothing", table.Table, report.Role)
		}

		// Two: the same check must return false for a deployment with no
		// separation at all. A check that always said "fail-closed" would
		// be worse than no check, and this is the only way to tell.
		unseparated, err := tenancy.Open(ctx, tenancy.Config{RegistryDSN: e.runtimeDSN()})
		if err != nil {
			t.Fatalf("open a Tenancy with no AppRole: %v", err)
		}
		defer func() { _ = unseparated.Close() }()

		bare := mustScope(ctx, t, unseparated, e.tenantA.ID)
		bareReport, err := bare.CheckEnforcement(ctx, forcedTable)
		if err != nil {
			t.Fatalf("CheckEnforcement with no AppRole: %v", err)
		}
		if e.adminIsSuperuser {
			if bareReport.FailClosed() {
				t.Fatal("CheckEnforcement reports a superuser connection with no AppRole as fail-closed; " +
					"a superuser bypasses row security unconditionally, so this check is not distinguishing anything")
			}
			if !bareReport.Superuser {
				t.Errorf("the connecting role was not detected as a superuser: %+v", bareReport)
			}
			if len(bareReport.Findings()) == 0 {
				t.Error("no findings were reported for a deployment with no privilege separation at all")
			}
		} else {
			t.Logf("the runtime credential (%s) is not a superuser, so there is no bypass to demonstrate; "+
				"this deployment has privilege separation at the credential level and AppRole is defence in depth",
				bareReport.Role)
		}

		// Three: the bypass is real. Seed both tenants' rows and read them
		// without the role switch, on the administrative pool. If this
		// does NOT see both rows, the harness's connecting role has
		// changed and every assertion below needs re-examining — because
		// SET LOCAL ROLE would no longer be the operative difference.
		seedRow(ctx, t, scoped, "enforce-a")
		seedRow(ctx, t, mustScope(ctx, t, e.tenancy, e.tenantB.ID), "enforce-b")

		var visible int
		if err := e.admin.QueryRow(ctx, "SELECT count(*) FROM "+forcedTable).Scan(&visible); err != nil {
			t.Fatalf("count rows on the administrative pool: %v", err)
		}
		if e.adminIsSuperuser {
			if visible != 2 {
				t.Fatalf("a superuser connection sees %d of 2 rows across both tenants. A superuser bypasses "+
					"row security unconditionally, so it must see both; if it does not, the role this harness "+
					"connects as has changed and the SET LOCAL ROLE switch is no longer what makes the "+
					"assertions in this suite meaningful", visible)
			}
		} else if visible != 0 {
			t.Errorf("a non-superuser runtime credential with no tenant context sees %d rows, want 0", visible)
		}
	}
}

func testRLSDeniesWithoutTenantContext(newDeployment func(t *testing.T) Deployment) func(*testing.T) {
	return func(t *testing.T) {
		dep := newDeployment(t)
		e := setup(t, dep, defaultCache(), dep.AppRole, 0)
		ctx := context.Background()

		scoped := mustScope(ctx, t, e.tenancy, e.tenantA.ID)
		requireFailClosed(ctx, t, scoped)
		seedRow(ctx, t, scoped, "no-context")

		// A transaction as the application role with no tenant context at
		// all. Both halves of the assertion matter: zero rows AND no
		// error. If an error were acceptable, this test would be proving
		// that something went wrong rather than that the backstop quietly
		// filtered everything — which is exactly what a cast in the policy
		// predicate would cause. See tenancy.TenantPredicate.
		var count int
		err := e.asRole(ctx, t, dep.AppRole, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, "SELECT count(*) FROM "+forcedTable).Scan(&count)
		})
		if err != nil {
			t.Fatalf("a query with no tenant context raised an error, want zero rows and no error: %v", err)
		}
		if count != 0 {
			t.Fatalf("a session with no tenant context sees %d rows, want 0", count)
		}
	}
}

func testRLSDeniesTheWrongTenantContext(newDeployment func(t *testing.T) Deployment) func(*testing.T) {
	return func(t *testing.T) {
		dep := newDeployment(t)
		e := setup(t, dep, defaultCache(), dep.AppRole, 0)
		ctx := context.Background()

		scopedA := mustScope(ctx, t, e.tenancy, e.tenantA.ID)
		scopedB := mustScope(ctx, t, e.tenancy, e.tenantB.ID)
		requireFailClosed(ctx, t, scopedA)

		seedRow(ctx, t, scopedA, "belongs-to-a")
		seedRow(ctx, t, scopedB, "belongs-to-b")

		// Deliberately no WHERE clause. This is the forgotten-predicate
		// case the backstop exists for: the statement a consumer writes
		// when it believes it is already scoped.
		var count int
		var data string
		if err := scopedA.Tx(ctx, func(ctx context.Context, tx tenancy.TenantTx) error {
			if err := tx.QueryRow(ctx, "SELECT count(*) FROM "+forcedTable).Scan(&count); err != nil {
				return err
			}
			return tx.QueryRow(ctx, "SELECT data FROM "+forcedTable).Scan(&data)
		}); err != nil {
			t.Fatalf("tenant A's unpredicated query: %v", err)
		}
		if count != 1 {
			t.Fatalf("tenant A's query with no WHERE clause sees %d rows, want 1 (only its own, despite both "+
				"tenants having one)", count)
		}
		if data != "belongs-to-a" {
			t.Fatalf("tenant A sees %q, want %q", data, "belongs-to-a")
		}

		// The USING side of write enforcement: targeting another tenant's
		// row by its primary key affects zero rows rather than erroring,
		// because the row is filtered out of the set the statement can
		// see at all.
		if err := scopedA.Tx(ctx, func(ctx context.Context, tx tenancy.TenantTx) error {
			tag, err := tx.Exec(ctx, "UPDATE "+forcedTable+" SET data = 'hijacked' WHERE id = $1", "belongs-to-b")
			if err != nil {
				return err
			}
			if tag.RowsAffected() != 0 {
				t.Errorf("tenant A's UPDATE of tenant B's row by primary key affected %d rows, want 0", tag.RowsAffected())
			}
			tag, err = tx.Exec(ctx, "DELETE FROM "+forcedTable+" WHERE id = $1", "belongs-to-b")
			if err != nil {
				return err
			}
			if tag.RowsAffected() != 0 {
				t.Errorf("tenant A's DELETE of tenant B's row affected %d rows, want 0", tag.RowsAffected())
			}
			return nil
		}); err != nil {
			t.Fatalf("tenant A's cross-tenant UPDATE/DELETE: %v", err)
		}

		// Tenant B's row is untouched.
		if err := scopedB.Tx(ctx, func(ctx context.Context, tx tenancy.TenantTx) error {
			return tx.QueryRow(ctx, "SELECT data FROM "+forcedTable+" WHERE id = $1", "belongs-to-b").Scan(&data)
		}); err != nil {
			t.Fatalf("read tenant B's row back: %v", err)
		}
		if data != "belongs-to-b" {
			t.Fatalf("tenant B's row reads %q after tenant A's attempts, want %q", data, "belongs-to-b")
		}
	}
}

// testRLSRefusesACrossTenantWrite is the WITH CHECK side, and the
// assertion is about *which mechanism* refused.
//
// An INSERT can fail for several reasons — a CHECK constraint, a foreign
// key, a trigger, a privilege. A test satisfied by "an error happened"
// passes against a schema whose policy does nothing at all. So this
// requires SQLSTATE 42501 specifically, and additionally requires the
// policy's WITH CHECK to be named in Postgres's own message rather than
// some other mechanism's.
func testRLSRefusesACrossTenantWrite(newDeployment func(t *testing.T) Deployment) func(*testing.T) {
	return func(t *testing.T) {
		dep := newDeployment(t)
		e := setup(t, dep, defaultCache(), dep.AppRole, 0)
		ctx := context.Background()

		scopedA := mustScope(ctx, t, e.tenancy, e.tenantA.ID)
		requireFailClosed(ctx, t, scopedA)

		t.Run("insert_for_another_tenant", func(t *testing.T) {
			err := scopedA.Tx(ctx, func(ctx context.Context, tx tenancy.TenantTx) error {
				_, execErr := tx.Exec(ctx,
					"INSERT INTO "+forcedTable+" (id, tenant_id, data) VALUES ($1, $2, 'smuggled')",
					"cross-insert", string(e.tenantB.ID))
				return execErr
			})
			assertPolicyRefusal(t, err, "an INSERT naming another tenant's id")
		})

		t.Run("update_that_moves_a_row_to_another_tenant", func(t *testing.T) {
			// This is the case USING alone does not catch: tenant A owns
			// the row, so USING lets it see and target the UPDATE, but the
			// new tenant_id belongs to tenant B. Only WITH CHECK refuses
			// it, which is why the policy needs both.
			seedRow(ctx, t, scopedA, "to-be-moved")

			err := scopedA.Tx(ctx, func(ctx context.Context, tx tenancy.TenantTx) error {
				_, execErr := tx.Exec(ctx,
					"UPDATE "+forcedTable+" SET tenant_id = $1 WHERE id = $2",
					string(e.tenantB.ID), "to-be-moved")
				return execErr
			})
			assertPolicyRefusal(t, err, "an UPDATE moving a row this tenant owns into another tenant")

			var owner string
			if err := scopedA.Tx(ctx, func(ctx context.Context, tx tenancy.TenantTx) error {
				return tx.QueryRow(ctx, "SELECT tenant_id FROM "+forcedTable+" WHERE id = $1", "to-be-moved").Scan(&owner)
			}); err != nil {
				t.Fatalf("read the row back: %v", err)
			}
			if owner != string(e.tenantA.ID) {
				t.Fatalf("the row's tenant_id is now %q, want %q: the refused UPDATE still moved it", owner, e.tenantA.ID)
			}
		})

		t.Run("insert_with_no_tenant_context_at_all", func(t *testing.T) {
			err := e.asRole(ctx, t, dep.AppRole, func(tx pgx.Tx) error {
				_, execErr := tx.Exec(ctx,
					"INSERT INTO "+forcedTable+" (id, tenant_id, data) VALUES ($1, $2, 'unscoped')",
					"no-context-insert", string(e.tenantA.ID))
				return execErr
			})
			assertPolicyRefusal(t, err, "an INSERT from a session with no tenant context")
		})
	}
}

// testRLSIsForced is the differential proof that FORCE ROW LEVEL SECURITY
// is doing work rather than merely being set.
//
// Row-level security does not apply to a table's owner by default, so a
// policy without FORCE shows up in pg_policies while protecting nothing
// from any statement that runs as the owning role — a state a deployment
// can sit in for a long time believing it is isolated.
//
// A superuser cannot demonstrate this, because it bypasses row security
// either way. So the fixture tables are owned by a NOSUPERUSER,
// NOBYPASSRLS role, and the suite runs as that role against two tables
// identical in every respect but FORCE. The owner must be filtered in one
// and not the other. If both filtered, the test would pass for the wrong
// reason — something other than FORCE would be doing the filtering — which
// is why the unforced control is asserted too.
func testRLSIsForced(newDeployment func(t *testing.T) Deployment) func(*testing.T) {
	return func(t *testing.T) {
		dep := newDeployment(t)
		e := setup(t, dep, defaultCache(), dep.AppRole, 0)
		ctx := context.Background()

		scopedA := mustScope(ctx, t, e.tenancy, e.tenantA.ID)
		scopedB := mustScope(ctx, t, e.tenancy, e.tenantB.ID)
		requireFailClosed(ctx, t, scopedA)

		seedRow(ctx, t, scopedA, "owner-sees-a")
		seedRow(ctx, t, scopedB, "owner-sees-b")
		// The same two rows in the unforced twin, inserted by the owner so
		// the unforced table's own policy does not get in the way.
		execAll(ctx, t, e.admin,
			"INSERT INTO "+unforcedTable+" (id, tenant_id, data) VALUES ('owner-sees-a', '"+string(e.tenantA.ID)+"', 'a')",
			"INSERT INTO "+unforcedTable+" (id, tenant_id, data) VALUES ('owner-sees-b', '"+string(e.tenantB.ID)+"', 'b')",
		)

		// First, confirm the owner role really is a non-superuser without
		// BYPASSRLS. Without this the whole subtest could pass for the
		// wrong reason in either direction.
		var isSuper, bypasses, owns bool
		if err := e.admin.QueryRow(ctx, `
			SELECT r.rolsuper, r.rolbypassrls, pg_get_userbyid(c.relowner) = r.rolname
			FROM pg_roles r, pg_class c
			WHERE r.rolname = $1 AND c.oid = to_regclass($2)
		`, fixtureOwnerRol, forcedTable).Scan(&isSuper, &bypasses, &owns); err != nil {
			t.Fatalf("read the fixture owner role's attributes: %v", err)
		}
		if isSuper || bypasses {
			t.Fatalf("the fixture owner role %s is superuser=%v bypassrls=%v; it cannot demonstrate anything "+
				"about FORCE", fixtureOwnerRol, isSuper, bypasses)
		}
		if !owns {
			t.Fatalf("%s does not own %s, so this subtest is not about the owner exemption at all",
				fixtureOwnerRol, forcedTable)
		}

		var forcedCount, unforcedCount int
		err := e.asRoleWithTenant(ctx, t, fixtureOwnerRol, e.tenantA.ID, func(tx pgx.Tx) error {
			if err := tx.QueryRow(ctx, "SELECT count(*) FROM "+forcedTable).Scan(&forcedCount); err != nil {
				return err
			}
			return tx.QueryRow(ctx, "SELECT count(*) FROM "+unforcedTable).Scan(&unforcedCount)
		})
		if err != nil {
			t.Fatalf("query as the table owner: %v", err)
		}

		if forcedCount != 1 {
			t.Fatalf("the table's own owner sees %d of 2 rows in the FORCEd table, want 1: FORCE ROW LEVEL "+
				"SECURITY is not binding the owner, so the policy protects nothing from any statement that "+
				"runs as it", forcedCount)
		}
		if unforcedCount != 2 {
			t.Fatalf("the table's own owner sees %d of 2 rows in the table that is NOT FORCEd, want 2. "+
				"The two tables are identical but for FORCE, so if the owner is filtered in both then "+
				"something other than FORCE is doing the filtering and the assertion above proves nothing "+
				"about FORCE", unforcedCount)
		}
	}
}

func testRLSCoverageSweep(newDeployment func(t *testing.T) Deployment) func(*testing.T) {
	return func(t *testing.T) {
		e := setup(t, newDeployment(t), defaultCache(), "", 0)
		ctx := context.Background()

		uncovered, err := tenancy.AssertRLSCoverage(ctx, e.admin, fixtureSchema)
		if err != nil {
			t.Fatalf("AssertRLSCoverage(%s): %v", fixtureSchema, err)
		}
		if !contains(uncovered, uncoveredTable) {
			t.Errorf("AssertRLSCoverage = %v, want it to report %s: a tenant-scoped table with no policy is "+
				"exactly what this sweep exists to catch in a consumer's CI", uncovered, uncoveredTable)
		}
		if !contains(uncovered, wrongPredicateTable) {
			t.Errorf("AssertRLSCoverage = %v, want it to report %s: the policy has the right name but a predicate "+
				"that permits every row", uncovered, wrongPredicateTable)
		}
		if contains(uncovered, forcedTable) {
			t.Errorf("AssertRLSCoverage = %v, want %s covered after EnableRLS", uncovered, forcedTable)
		}

		// The registry's own schema must sweep clean, and the exemption is
		// what makes that a decision rather than an accident.
		registry, err := tenancy.AssertRLSCoverage(ctx, e.admin, tenancy.Schema)
		if err != nil {
			t.Fatalf("AssertRLSCoverage(%s): %v", tenancy.Schema, err)
		}
		if len(registry) != 0 {
			t.Errorf("AssertRLSCoverage(%s) = %v, want empty", tenancy.Schema, registry)
		}
		for table := range tenancy.RegistryTablesExemptFromRLS() {
			if contains(registry, table) {
				t.Errorf("%s is reported uncovered despite being a named exemption", table)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func defaultCache() tenancy.CacheOptions {
	return tenancy.CacheOptions{TTL: time.Minute, NegativeTTL: time.Minute}
}

func (e *env) runtimeDSN() tenancy.DSN {
	if e.dep.RuntimeDSN != "" {
		return e.dep.RuntimeDSN
	}
	return e.dep.MigrationDSN
}

// asRole runs fn in a transaction on the administrative pool that has
// narrowed itself into role and set NO tenant context.
//
// It deliberately bypasses the module: the point of several assertions is
// what Postgres does to a statement this module did not scope.
func (e *env) asRole(ctx context.Context, t *testing.T, role string, fn func(tx pgx.Tx) error) error {
	t.Helper()
	return e.inTx(ctx, t, role, "", fn)
}

// asRoleWithTenant is asRole with a tenant context set, for the assertions
// that are about which *role* is running rather than about the context.
func (e *env) asRoleWithTenant(ctx context.Context, t *testing.T, role string, tenant tenancy.TenantID, fn func(tx pgx.Tx) error) error {
	t.Helper()
	return e.inTx(ctx, t, role, string(tenant), fn)
}

func (e *env) inTx(ctx context.Context, t *testing.T, role, tenant string, fn func(tx pgx.Tx) error) error {
	t.Helper()

	tx, err := e.admin.Begin(ctx)
	if err != nil {
		t.Fatalf("begin on the administrative pool: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// SET LOCAL ROLE first, before anything else runs: the harness
	// connects as a superuser, and a superuser bypasses row security
	// unconditionally, so a statement issued before this line would prove
	// nothing at all.
	if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+quote(role)); err != nil {
		t.Fatalf("SET LOCAL ROLE %s: %v", role, err)
	}
	if tenant != "" {
		if _, err := tx.Exec(ctx, "SELECT set_config($1, $2, true)", tenancy.TenantGUC, tenant); err != nil {
			t.Fatalf("set %s: %v", tenancy.TenantGUC, err)
		}
	}
	return fn(tx)
}

// requireFailClosed refuses to let a row-level-security assertion proceed
// against a deployment where it would prove nothing. Every RLS subtest
// calls it first.
func requireFailClosed(ctx context.Context, t *testing.T, scoped tenancy.Scoped) {
	t.Helper()

	report, err := scoped.CheckEnforcement(ctx, forcedTable)
	if err != nil {
		t.Fatalf("CheckEnforcement: %v", err)
	}
	if !report.FailClosed() {
		t.Fatalf("refusing to assert anything about row-level security against a deployment that is not "+
			"fail-closed, because the assertion would pass without enforcing anything: %v", report.Findings())
	}
}

// seedRow inserts one row for the handle's tenant, through the module,
// exactly as a consumer's own code would.
func seedRow(ctx context.Context, t *testing.T, scoped tenancy.Scoped, id string) {
	t.Helper()

	err := scoped.Tx(ctx, func(ctx context.Context, tx tenancy.TenantTx) error {
		// The tenant id comes off the transaction rather than being
		// carried separately, so the column and the policy cannot
		// disagree.
		_, execErr := tx.Exec(ctx,
			"INSERT INTO "+forcedTable+" (id, tenant_id, data) VALUES ($1, $2, $3)",
			id, string(tx.Tenant()), id)
		return execErr
	})
	if err != nil {
		t.Fatalf("seed row %q for tenant %s: %v", id, scoped.Tenant().ID, err)
	}
}

// assertPolicyRefusal requires that err is Postgres refusing under a
// row-level-security policy and not under anything else.
func assertPolicyRefusal(t *testing.T, err error, what string) {
	t.Helper()

	if err == nil {
		t.Fatalf("%s succeeded; the policy's WITH CHECK is not fail-closed", what)
	}
	if !tenancy.IsRLSPolicyViolation(err) {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			t.Fatalf("%s was refused with SQLSTATE %s (%s), want %s. A refusal from some other mechanism "+
				"would mean the policy is not what is holding the invariant",
				what, pgErr.Code, pgErr.Message, tenancy.RLSViolationCode)
		}
		t.Fatalf("%s was refused with %v, want a %s Postgres error from the policy", what, err, tenancy.RLSViolationCode)
	}

	// 42501 is also what a missing table privilege raises, so the message
	// has to name the policy. Postgres says "new row violates row-level
	// security policy" for a WITH CHECK failure and "permission denied
	// for table" for a missing grant.
	var pgErr *pgconn.PgError
	_ = errors.As(err, &pgErr)
	if pgErr != nil && !strings.Contains(pgErr.Message, "row-level security") {
		t.Fatalf("%s was refused with a %s whose message is %q; it does not name row-level security, so the "+
			"refusal is a missing privilege rather than the policy",
			what, tenancy.RLSViolationCode, pgErr.Message)
	}
}

func mustScope(ctx context.Context, t *testing.T, ten *tenancy.Tenancy, id tenancy.TenantID) tenancy.Scoped {
	t.Helper()
	scoped, err := ten.Scope(ctx, id)
	if err != nil {
		t.Fatalf("Scope(%s): %v", id, err)
	}
	return scoped
}

func mustCreatePool(ctx context.Context, t *testing.T, control *tenancy.Control, name string, dsn tenancy.DSN) tenancy.Pool {
	t.Helper()
	p, err := control.CreatePool(ctx, tenancy.PoolSpec{
		Name:           name,
		Region:         "test-region",
		MetadataDSN:    dsn,
		BlobConfigRef:  "blob-" + name,
		WorkerCapacity: 4,
	})
	if err != nil {
		t.Fatalf("CreatePool(%s): %v", name, err)
	}
	return p
}

func mustCreateTenant(ctx context.Context, t *testing.T, control *tenancy.Control, poolID tenancy.PoolID, name string) tenancy.Tenant {
	t.Helper()
	tn, err := control.CreateTenant(ctx, tenancy.TenantSpec{
		PoolID:       poolID,
		Name:         name,
		SecurityMode: tenancy.SecurityModeManaged,
	})
	if err != nil {
		t.Fatalf("CreateTenant(%s): %v", name, err)
	}
	return tn
}

// ping runs the cheapest possible statement through a handle, which is how
// the lifecycle subtests ask "is the pool behind this still usable".
func ping(ctx context.Context, scoped tenancy.Scoped) error {
	var one int
	return scoped.Tx(ctx, func(ctx context.Context, tx tenancy.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT 1").Scan(&one)
	})
}

// waitUntilRefused polls until a handle's pool reports itself closed.
// Closing is backgrounded on the release path — pgxpool.Close can block on
// a connection some unrelated goroutine still holds — so it is eventual
// rather than immediate.
func waitUntilRefused(t *testing.T, scoped tenancy.Scoped) {
	t.Helper()

	deadline := time.Now().After
	start := time.Now()
	for !deadline(start.Add(5 * time.Second)) {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		err := ping(ctx, scoped)
		cancel()
		if errors.Is(err, tenancy.ErrUnavailable) {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("a retired pool with no remaining borrowers was never closed")
}

// runtimeRoleIsSuperuser reports whether the role the runtime credential
// connects as bypasses row security outright. It decides whether the
// bypass-is-real control assertions apply.
func runtimeRoleIsSuperuser(ctx context.Context, t *testing.T, admin *pgxpool.Pool, runtimeDSN tenancy.DSN) bool {
	t.Helper()

	cfg, err := pgxpool.ParseConfig(string(runtimeDSN))
	if err != nil {
		t.Fatal("parse the runtime dsn")
	}

	var superuser bool
	err = admin.QueryRow(ctx,
		"SELECT coalesce(bool_or(rolsuper OR rolbypassrls), false) FROM pg_roles WHERE rolname = $1",
		cfg.ConnConfig.User).Scan(&superuser)
	if err != nil {
		t.Fatalf("read the runtime role's attributes: %v", err)
	}
	return superuser
}

// ensureRole creates role if it does not exist, tolerating the race two
// parallel subtests on one cluster can lose.
//
// Roles are cluster-wide while a test database is not, and a plain
// "IF NOT EXISTS (SELECT FROM pg_roles)" guard still loses that race:
// both sessions can see "not yet created" before either commits. `cas`
// hit exactly this running its suite with t.Parallel and got a 23505 on
// pg_authid's name index. Catching the conflict is what makes this
// idempotent under concurrency rather than merely idempotent run one at a
// time.
func ensureRole(ctx context.Context, t *testing.T, db *pgxpool.Pool, role string) {
	t.Helper()

	_, err := db.Exec(ctx, `
		DO $$
		BEGIN
		    BEGIN
		        CREATE ROLE `+quote(role)+` NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOLOGIN NOBYPASSRLS;
		    EXCEPTION
		        WHEN duplicate_object OR unique_violation THEN
		            NULL;
		    END;
		END
		$$`)
	if err != nil {
		t.Fatalf("ensure role %s: %v", role, err)
	}
}

func execAll(ctx context.Context, t *testing.T, db *pgxpool.Pool, statements ...string) {
	t.Helper()
	for _, stmt := range statements {
		if _, err := db.Exec(ctx, stmt); err != nil {
			t.Fatalf("exec %q: %v", stmt, err)
		}
	}
}

// quote renders an identifier the way every statement in this file needs
// it: quoted and escaped, never raw-interpolated.
func quote(ident string) string { return pgx.Identifier{ident}.Sanitize() }

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// testRLSAddedPermissivePolicyCannotWiden is the regression test for a
// cross-tenant disclosure this module shipped, found by an OpenBao spike.
//
// Postgres ORs permissive policies together and ANDs restrictive ones over the
// result. A tenant predicate written as a single *permissive* policy is
// therefore OR-able away by any additional permissive policy on the same
// table. Measured on Postgres 18.6 against the arrangement this module first
// shipped: a tenant seeing its own single row saw two the moment a second
// permissive policy existed, and the second row belonged to another tenant.
// Adding a policy weakened isolation, which no consumer would expect and which
// any table owner could do.
//
// So the subtest adds exactly such a policy and requires the tenant to keep
// seeing only its own rows. It fails against a permissive-only tenant policy
// and passes against the restrictive-plus-companion arrangement.
func testRLSAddedPermissivePolicyCannotWiden(newDeployment func(t *testing.T) Deployment) func(*testing.T) {
	return func(t *testing.T) {
		dep := newDeployment(t)
		e := setup(t, dep, defaultCache(), dep.AppRole, 0)
		ctx := context.Background()

		scopedA := mustScope(ctx, t, e.tenancy, e.tenantA.ID)
		requireFailClosed(ctx, t, scopedA)
		seedRow(ctx, t, scopedA, "mine")

		scopedB := mustScope(ctx, t, e.tenancy, e.tenantB.ID)
		seedRow(ctx, t, scopedB, "not-mine")

		// The policy the test exists to defeat. A consumer adding a
		// reporting or admin view would write exactly this.
		if _, err := e.admin.Exec(ctx,
			"CREATE POLICY widen_attempt ON "+forcedTable+" AS PERMISSIVE USING (true)"); err != nil {
			t.Fatalf("could not add the permissive policy this test exists to defeat: %v", err)
		}

		var count int
		err := e.asRole(ctx, t, dep.AppRole, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, "SELECT set_config($1, $2, true)", tenancy.TenantGUC, string(e.tenantA.ID)); err != nil {
				return err
			}
			return tx.QueryRow(ctx, "SELECT count(*) FROM "+forcedTable).Scan(&count)
		})
		if err != nil {
			t.Fatalf("counting as tenant A: %v", err)
		}
		if count != 1 {
			t.Fatalf("with one extra permissive policy present, tenant A sees %d rows, want 1.\n"+
				"the tenant predicate was OR-ed away rather than AND-ed: it must be "+
				"AS RESTRICTIVE, with a permissive companion for it to AND against", count)
		}
	}
}

// testRenderingsOfAResolvedScope holds every value resolution hands back to
// CONVENTIONS.md's "Rendering a secret" convention, against the deployment's
// own real connection string rather than a fixture.
//
// It is in the suite rather than only in the module's unit tests because the
// values under test are the ones a *deployment* produces: the pool row comes
// out of that deployment's registry, and a consumer that supplies its own
// Opener — the documented seam — is holding exactly these values. The unit
// tests prove the types redact; this proves the deployment's own data does.
//
// The material is the deployment's migration DSN, which is also the DSN every
// pool in this suite is registered with, so a rendering that discloses the
// pool's credential and one that discloses the harness's are the same failure.
func testRenderingsOfAResolvedScope(newDeployment func(t *testing.T) Deployment) func(*testing.T) {
	return func(t *testing.T) {
		dep := newDeployment(t)
		e := setup(t, dep, defaultCache(), dep.AppRole, 0)
		ctx := context.Background()

		scoped, err := e.tenancy.Scope(ctx, e.tenantA.ID)
		if err != nil {
			t.Fatalf("Scope(tenantA): %v", err)
		}

		material := []byte(e.runtimeDSN())

		for _, tc := range []struct {
			name  string
			value any
		}{
			{"Pool", e.poolA},
			{"Scoped", scoped},
			{"ScopedPool", scoped.Pool()},
			{"Deployment", dep},
		} {
			t.Run(tc.name, func(t *testing.T) {
				NoSecretLeaksInAnyRendering(t, tc.value, material)
			})
		}
	}
}
