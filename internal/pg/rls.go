package pg

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/laenenai/tenancy/internal/domain"
)

// TenantPolicyName is the fixed name EnableRLS gives the policy it creates
// on every table it is pointed at. One name everywhere is what makes
// AssertRLSCoverage's sweep and CheckEnforcement's probe able to recognize
// the convention rather than guess at it.
const TenantPolicyName = "tenant_isolation"

// TenantAccessPolicyName is the permissive companion to TenantPolicyName.
//
// It exists because TenantPolicyName is RESTRICTIVE, and a table whose only
// policies are restrictive has an empty permissive set — which Postgres treats
// as denying every row. This policy is deliberately `USING (true)`: it grants
// nothing on its own, it exists so the tenant restriction has something to
// AND against, and the tenant restriction is what actually filters.
//
// A consumer adding its own permissive policies ORs them with this one and
// still cannot escape the AND. That is the whole point of the arrangement.
const TenantAccessPolicyName = "tenant_access"

// TenantPredicate is the single source of truth for this system's
// row-level-security convention: every tenant-scoped table carries a
// tenant_id column, and one policy using exactly this expression as both
// USING and WITH CHECK.
//
// # There is no cast, and that is the hard-won part
//
// Two reasons, both found the hard way in `cas`:
//
//   - Every id in this system is a Crockford base32 ULID string, never a
//     uuid, so `tenant_id::uuid` would raise on every real row.
//   - current_setting(TenantGUC, true) returns the empty string, not NULL,
//     once any transaction on the connection has touched the setting via
//     set_config(..., true) and that transaction has ended. So a session
//     with no tenant context can observe the empty string rather than
//     NULL. A cast — to uuid or to anything — would make the predicate
//     *raise an error* for that caller instead of evaluating to false,
//     which turns a quiet, correct denial into a failure the caller can
//     distinguish.
//
// nullif collapses both "never set" (NULL) and "set earlier, now ended"
// (the empty string) to NULL. `tenant_id = NULL` is NULL, which Postgres
// treats as false for USING and WITH CHECK, so the row is filtered and
// nothing is raised.
// The conformance suite's RLSDeniesWithoutTenantContext asserts both
// halves — zero rows AND no error — because a test that passed while the
// statement errored would be testing that something went wrong rather than
// that the backstop quietly filtered everything.
//
// WITH CHECK is not optional and not a duplicate of USING. USING filters
// what a statement can see, so it makes a cross-tenant UPDATE or DELETE
// affect zero rows. Only WITH CHECK stops an INSERT writing a row for
// another tenant, and stops an UPDATE *moving* a row this tenant owns into
// another tenant's id.
const TenantPredicate = "tenant_id = nullif(current_setting('" + TenantGUC + "', true), '')"

// DDL is the narrow handle EnableRLS and AssertRLSCoverage work through.
//
// It is an interface rather than a *pgxpool.Pool so that a consumer can
// call either from inside its own pgmigrate reconciler, where what it
// holds is a pgx.Tx. *pgxpool.Pool, *pgx.Conn and pgx.Tx all satisfy it as
// declared, with no wrapper at the call site.
//
// Begin is in the interface because EnableRLS must be atomic — see
// enableOne. On a pgx.Tx, Begin opens a savepoint, which is exactly the
// nesting that makes the atomicity hold inside a caller's transaction too.
type DDL interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Begin(ctx context.Context) (pgx.Tx, error)
}

// RegistryTablesExemptFromRLS names the registry tables that deliberately
// carry no policy, each with the reason, and AssertRLSCoverage honours it.
//
// It is an explicit, named exemption rather than an implicit rule like
// "tables with no tenant_id column", and the difference matters. Neither
// registry table happens to have a column called tenant_id today, so an
// implicit rule would exempt them silently — and a silent exemption looks
// exactly like an oversight to the next person who reads the schema and
// "fixes" the apparent gap. Naming them keeps the reasoning at the place
// where that mistake would be made.
var registryTablesExemptFromRLS = map[string]string{
	"tenancy.pools": "resolution reads tenancy.pools and tenancy.tenants before any tenant " +
		"session context exists — a policy keyed on " + TenantGUC + " would stop the resolver " +
		"reading the very row that establishes that context; see db/migrations/00001_registry.sql",
	"tenancy.tenants": "resolution reads tenancy.pools and tenancy.tenants before any tenant " +
		"session context exists — a policy keyed on " + TenantGUC + " would stop the resolver " +
		"reading the very row that establishes that context; see db/migrations/00001_registry.sql",
}

// RegistryTablesExemptFromRLS returns a copy of the named exemptions. It is a
// function rather than an exported map so a consumer cannot silently weaken
// the coverage check by mutating the allow-list.
func RegistryTablesExemptFromRLS() map[string]string {
	out := make(map[string]string, len(registryTablesExemptFromRLS))
	for table, reason := range registryTablesExemptFromRLS {
		out[table] = reason
	}
	return out
}

// EnableRLS enables and FORCEs row-level security on each table in tables
// (each given as "schema.table") and creates the two policies enforcing this
// system's tenant isolation convention: a restrictive tenant_isolation policy
// and a permissive tenant_access companion, both using TenantPredicate as
// USING and WITH CHECK.
//
// Each table must already have a tenant_id column; EnableRLS does not
// create one, and CREATE POLICY is what fails if it is missing.
//
// # FORCE is included deliberately
//
// Row-level security does not apply to a table's owner by default.
// Without FORCE the policy still shows up in pg_policies while protecting
// nothing for any statement that happens to run as the owning role — which
// is a mode a deployment can sit in for a long time believing it is
// isolated. The conformance suite proves FORCE is the operative
// difference, not merely present, by running as a non-superuser role that
// *owns* the table and asserting it sees nothing: see
// RLSIsForcedSoTheTableOwnerIsSubjectToIt.
//
// FORCE does not, by itself, protect against a superuser connection, which
// bypasses row security unconditionally. Nothing in SQL can. That is what
// the application role and Scoped's SET LOCAL ROLE are for, and what
// CheckEnforcement reports on.
//
// # It is idempotent, which `cas`'s version was not
//
// EnableRLS is meant to be called from a pgmigrate reconciler, so it runs
// on every Up — and declarative state asserted once is the trap pgmigrate
// exists to close. `cas`'s EnableRLS used a bare CREATE POLICY and failed
// the second time. This one drops the policy by name and recreates it
// inside the same transaction, so it both tolerates a re-run and *repairs*
// a policy whose predicate has drifted from TenantPredicate. There is no
// window in which the table is FORCEd with no policy, because the drop and
// the create share one transaction.
func EnableRLS(ctx context.Context, db DDL, tables ...string) error {
	for _, table := range tables {
		ident, err := qualifiedIdentifier(table)
		if err != nil {
			return err
		}
		if err := enableOne(ctx, db, table, ident); err != nil {
			return err
		}
	}
	return nil
}

// enableOne runs ENABLE, FORCE, and the two policies for one table inside a
// single transaction.
//
// # Why there are two policies, and why the tenant one is RESTRICTIVE
//
// Postgres OR-s permissive policies together and AND-s restrictive ones on
// top. A tenant predicate written as a single *permissive* policy — which is
// what this module shipped first, and what cas and audit still carry — can
// therefore be **OR-ed away by any additional permissive policy on the same
// table**. Measured on Postgres 18.6: a tenant seeing its own single row saw
// two the moment a second permissive policy existed, and the second row
// belonged to another tenant. That is a cross-tenant disclosure created by
// adding a policy, which any table owner can do and which no consumer would
// expect to weaken isolation.
//
// So the tenant predicate is RESTRICTIVE, and a consumer may add as many
// permissive policies as it likes: they OR among themselves and the tenant
// restriction still AND-s over the result. A consumer can narrow within its
// tenant and cannot widen past it.
//
// The permissive companion is required, not decorative: a table with only
// restrictive policies has an empty permissive set, and Postgres then denies
// every row. Verified both ways — restrictive alone returned 0 rows, the pair
// returned exactly the tenant's own, an added permissive policy did not change
// that, no tenant context still returned 0, and a cross-tenant INSERT was
// still refused naming the tenant policy.
//
// The atomicity is not tidiness. Four unwrapped Exec calls could leave the
// table FORCEd into row security with zero policies, and Postgres
// default-denies every command against a table in that state — for every
// role including the owner — until someone fixes it by hand. See
// TestEnableRLS_FailurePartwayThroughLeavesTableUnchanged.
func enableOne(ctx context.Context, db DDL, table, ident string) error {
	tx, err := db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("%w: enable row-level security on %s", domain.ErrUnavailable, table)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	policy := pgx.Identifier{TenantPolicyName}.Sanitize()
	access := pgx.Identifier{TenantAccessPolicyName}.Sanitize()
	statements := []string{
		"ALTER TABLE " + ident + " ENABLE ROW LEVEL SECURITY",
		"ALTER TABLE " + ident + " FORCE ROW LEVEL SECURITY",
		"DROP POLICY IF EXISTS " + policy + " ON " + ident,
		"DROP POLICY IF EXISTS " + access + " ON " + ident,
		// The tenant predicate is RESTRICTIVE, so it is AND-ed with
		// everything and cannot be OR-ed away. See the doc comment above.
		"CREATE POLICY " + policy + " ON " + ident + " AS RESTRICTIVE" +
			" USING (" + TenantPredicate + ") WITH CHECK (" + TenantPredicate + ")",
		// A restrictive policy with no permissive policy to AND against
		// denies every row, so the companion is required rather than
		// decorative.
		"CREATE POLICY " + access + " ON " + ident + " AS PERMISSIVE" +
			" USING (true) WITH CHECK (true)",
	}
	for _, stmt := range statements {
		if _, err := tx.Exec(ctx, stmt); err != nil {
			// The underlying Postgres error's text is never forwarded:
			// this module's rule (see Open) is to state the reason and
			// drop the third-party message, which can carry stored values
			// and server internals. table is the caller's own argument and
			// is safe to echo. See
			// TestEnableRLS_ErrorsNeverForwardRawPostgresText.
			return fmt.Errorf("%w: enable row-level security on %s", classifyDDLError(err), table)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("%w: enable row-level security on %s", domain.ErrUnavailable, table)
	}
	return nil
}

// AssertRLSCoverage reports every table in schema that carries a tenant_id
// column but no row-level-security policy, apart from the tables named in
// RegistryTablesExemptFromRLS.
//
// It is meant to be wired into a consumer's CI as a test, so that a later
// migration cannot add a tenant-scoped table without a policy and have CI
// stay green: the table simply shows up in the returned slice. An empty
// slice is the passing answer.
//
// The sweep keys on the column *name* rather than on a particular domain
// type, which is deliberately broader than `cas`'s version (which required
// the column's type to be the `cas.ulid` domain). A consumer whose
// tenant_id is plain text, or its own domain, is still swept — and
// reporting a table that turns out not to need a policy costs a named
// exemption, while missing one costs a cross-tenant disclosure.
//
// It is hand-written SQL, not sqlc-generated, and that is the documented
// exception rather than a lapse: sqlc resolves every relation against
// db/migrations, which contains no pg_catalog, so a query reading
// information_schema or pg_policies fails generation outright. The
// workaround — a fake catalog schema file — is declined, because generated
// code would then agree with a fiction that drifts from the real catalog.
// See CONVENTIONS.md.
func AssertRLSCoverage(ctx context.Context, db DDL, schema string) ([]string, error) {
	rows, err := db.Query(ctx, `
		SELECT table_name
		FROM information_schema.columns
		WHERE table_schema = $1
		  AND column_name = 'tenant_id'
		ORDER BY table_name
	`, schema)
	if err != nil {
		return nil, fmt.Errorf("%w: querying tenant_id columns in schema %s", domain.ErrUnavailable, schema)
	}
	defer rows.Close()

	var candidates []string
	for rows.Next() {
		var table string
		if err := rows.Scan(&table); err != nil {
			return nil, fmt.Errorf("%w: scanning tenant_id columns in schema %s", domain.ErrUnavailable, schema)
		}
		candidates = append(candidates, table)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: reading tenant_id columns in schema %s", domain.ErrUnavailable, schema)
	}

	var uncovered []string
	for _, table := range candidates {
		qualified := schema + "." + table
		if _, exempt := registryTablesExemptFromRLS[qualified]; exempt {
			continue
		}

		var enabled, forced, tenantPolicy, tenantCheck, tenantPredicate, companion bool
		err := db.QueryRow(ctx, `
			SELECT c.relrowsecurity,
			       c.relforcerowsecurity,
			       EXISTS (
			           SELECT 1 FROM pg_policy p
			           WHERE p.polrelid = c.oid AND p.polname = $3 AND NOT p.polpermissive
			       ),
			       EXISTS (
			           SELECT 1 FROM pg_policy p
			           WHERE p.polrelid = c.oid AND p.polname = $3 AND NOT p.polpermissive
			             AND p.polwithcheck IS NOT NULL
			       ),
			       EXISTS (
			           SELECT 1 FROM pg_policy p
			           WHERE p.polrelid = c.oid AND p.polname = $3 AND NOT p.polpermissive
			             AND lower(coalesce(pg_get_expr(p.polqual, c.oid), '')) LIKE '%tenant_id%'
			             AND lower(coalesce(pg_get_expr(p.polqual, c.oid), '')) LIKE '%nullif%'
			             AND lower(coalesce(pg_get_expr(p.polqual, c.oid), '')) LIKE '%current_setting%'
			             AND lower(coalesce(pg_get_expr(p.polqual, c.oid), '')) LIKE '%' || lower($4) || '%'
			       ),
			       EXISTS (
			           SELECT 1 FROM pg_policy p
			           WHERE p.polrelid = c.oid AND p.polpermissive
			       )
			FROM pg_class c
			JOIN pg_namespace n ON n.oid = c.relnamespace
			WHERE n.nspname = $1 AND c.relname = $2 AND c.relkind IN ('r', 'p')
		`, schema, table, TenantPolicyName, TenantGUC).Scan(
			&enabled, &forced, &tenantPolicy, &tenantCheck, &tenantPredicate, &companion,
		)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				uncovered = append(uncovered, qualified)
				continue
			}
			return nil, fmt.Errorf("%w: reading the row-security state of %s", domain.ErrUnavailable, qualified)
		}
		if !enabled || !forced || !tenantPolicy || !tenantCheck || !tenantPredicate || !companion {
			uncovered = append(uncovered, qualified)
		}
	}
	return uncovered, nil
}

// qualifiedIdentifier parses table as "schema.table" and returns it
// rendered as a safely quoted SQL identifier, never raw-interpolated, or
// domain.ErrInvalidConfig if table is not in that exact two-part shape.
// classifyDDLError separates a missing table/column (a permanent schema
// mistake) and a privilege failure from a transient database problem.
func classifyDDLError(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "42P01", "42703", "3F000": // undefined_table, undefined_column, invalid_schema
			return domain.ErrInvalidConfig
		case "42501":
			return domain.ErrPermission
		}
	}
	return domain.ErrUnavailable
}

func qualifiedIdentifier(table string) (string, error) {
	schema, name, ok := strings.Cut(table, ".")
	if !ok || schema == "" || name == "" || strings.Contains(name, ".") {
		return "", fmt.Errorf("%w: %q is not a \"schema.table\" identifier", domain.ErrInvalidConfig, table)
	}
	return pgx.Identifier{schema, name}.Sanitize(), nil
}
