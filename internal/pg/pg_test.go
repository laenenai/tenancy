package pg_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/laenenai/tenancy/internal/domain"
	"github.com/laenenai/tenancy/internal/pg"
)

// TestTenantGUCIsPinned pins the session variable name to its literal
// value, and that is not pedantry.
//
// The name appears verbatim in the policy SQL of every consumer that has
// already adopted this convention — cas's db/migrations/00003_rls.sql and
// audit's 00001_audit.sql both say 'app.tenant_id'. If this constant moved,
// this module would start setting a variable those existing policies do not
// read, and the policies would evaluate their predicate against NULL for
// every statement. That does not fail: it silently filters everything, and
// then, for an INSERT, refuses everything — a module-wide outage in the
// best case and, if the predicate were ever written to tolerate it, a
// module-wide disclosure in the worst.
//
// The constraint that prompted this test is specific: on 2026-10-23 a
// module rename rewrote a hash function's domain-separation tag in a
// sibling module and invalidated its committed test vectors. A GUC name is
// the same class of constant. So the test also asserts the name contains no
// fragment of this module's import path, which is what would make a rename
// able to touch it at all.
func TestTenantGUCIsPinned(t *testing.T) {
	t.Parallel()

	if pg.TenantGUC != "app.tenant_id" {
		t.Fatalf("pg.TenantGUC = %q, want \"app.tenant_id\".\n"+
			"Existing consumers' row-level-security policies read this exact name. Changing it makes this "+
			"module set a variable those policies do not read, which filters every row without raising "+
			"anything.", pg.TenantGUC)
	}
	guc := pg.TenantGUC
	for _, fragment := range []string{"laenenai", "laenen-ai", "github.com", "tenancy/"} {
		if strings.Contains(guc, fragment) {
			t.Errorf("pg.TenantGUC = %q contains %q, so a module path rename could move it", guc, fragment)
		}
	}
	if pg.TenantPolicyName != "tenant_isolation" {
		t.Fatalf("pg.TenantPolicyName = %q, want \"tenant_isolation\": the sweep and the enforcement probe "+
			"both recognize the convention by this name", pg.TenantPolicyName)
	}
}

// TestTenantPredicateHasNoCast is the shape assertion, and both halves were
// found the hard way in `cas`.
//
// No cast, because current_setting(..., true) returns the empty string
// rather than NULL once any transaction on the connection has set the
// variable and ended — so a session with no tenant context observes the
// empty string. A cast would make the predicate raise for that caller
// instead of evaluating to false, which turns a quiet, correct denial into
// a distinguishable failure. And nullif, because it is what collapses both
// "never set" (NULL)
// and "set earlier, now ended" (the empty string) to NULL.
func TestTenantPredicateHasNoCast(t *testing.T) {
	t.Parallel()

	if strings.Contains(pg.TenantPredicate, "::") {
		t.Fatalf("pg.TenantPredicate = %q contains a cast. Every id here is a Crockford base32 ULID string, "+
			"never a uuid, so a cast would raise on every real row — and a cast against the session variable "+
			"would raise for a session that has no tenant context instead of filtering quietly.",
			pg.TenantPredicate)
	}
	if !strings.Contains(pg.TenantPredicate, "nullif(") {
		t.Fatalf("pg.TenantPredicate = %q does not use nullif. Without it, a session that set the variable "+
			"in an earlier, now-ended transaction observes '' rather than NULL, and '' is not NULL, so the "+
			"comparison would be against the empty string rather than filtering.", pg.TenantPredicate)
	}
	if !strings.Contains(pg.TenantPredicate, pg.TenantGUC) {
		t.Fatalf("pg.TenantPredicate = %q does not reference pg.TenantGUC (%q): the two must not be able to "+
			"drift apart", pg.TenantPredicate, pg.TenantGUC)
	}
	if !strings.HasPrefix(pg.TenantPredicate, "tenant_id =") {
		t.Fatalf("pg.TenantPredicate = %q does not compare the tenant_id column, which is the column "+
			"AssertRLSCoverage sweeps for", pg.TenantPredicate)
	}
}

// TestRegistryTablesAreNamedExemptions asserts the exemption list is
// explicit and carries its reason, because an unexplained exemption looks
// exactly like an oversight to the next reader.
func TestRegistryTablesAreNamedExemptions(t *testing.T) {
	t.Parallel()

	for _, table := range []string{"tenancy.pools", "tenancy.tenants"} {
		reason, ok := pg.RegistryTablesExemptFromRLS()[table]
		if !ok {
			t.Fatalf("%s is not in RegistryTablesExemptFromRLS: the coverage sweep would report it, and "+
				"someone would \"fix\" it by adding a policy that stops the resolver reading the row that "+
				"establishes tenant context", table)
		}
		if len(reason) < 40 || !strings.Contains(reason, "before any tenant") {
			t.Errorf("%s's exemption reason is %q, which does not say why", table, reason)
		}
	}
	if len(pg.RegistryTablesExemptFromRLS()) != 2 {
		t.Errorf("RegistryTablesExemptFromRLS has %d entries, want 2: this list is the one place it may grow, "+
			"and growing it is a decision", len(pg.RegistryTablesExemptFromRLS()))
	}
}

func TestOpenRejectsAMalformedDSNWithoutLeakingIt(t *testing.T) {
	t.Parallel()

	const canary = "POOL_DSN_CANARY" //nolint:gosec // canary value, not a real credential

	_, err := pg.Open(context.Background(), "not-a-connection-string "+canary, pg.PoolConfig{})
	if !errors.Is(err, domain.ErrInvalidConfig) {
		t.Fatalf("Open() error = %v, want ErrInvalidConfig", err)
	}
	if strings.Contains(err.Error(), canary) {
		t.Fatalf("Open() leaked the DSN: %v", err)
	}
	// pgx's own parse error names the offending input and its internals.
	// None of it may be forwarded, because the DSN reaching this function
	// is often a pool row's MetadataDSN, read out of the registry on
	// behalf of a request.
	for _, fragment := range []string{"cannot parse", "invalid dsn", "keyword/value"} {
		if strings.Contains(strings.ToLower(err.Error()), fragment) {
			t.Errorf("Open() forwards pgx's own parse error text (%q): %v", fragment, err)
		}
	}
}

func TestZeroScopedDenies(t *testing.T) {
	t.Parallel()

	var zero pg.Scoped
	if zero.Valid() {
		t.Fatal("the zero Scoped reports itself valid")
	}
	if zero.Tenant().ID != "" || zero.Pool().ID != "" {
		t.Fatal("the zero Scoped carries a tenant or a pool")
	}

	err := zero.Tx(context.Background(), func(context.Context, pg.TenantTx) error {
		t.Error("the zero Scoped ran the function")
		return nil
	})
	if !errors.Is(err, domain.ErrNoTenantScope) {
		t.Fatalf("zero Scoped Tx error = %v, want ErrNoTenantScope", err)
	}
}

func TestEnableRLSRejectsAnIdentifierThatIsNotSchemaQualified(t *testing.T) {
	t.Parallel()

	cases := []string{"", "scoped", ".scoped", "myschema.", "a.b.c"}
	for _, table := range cases {
		t.Run(table, func(t *testing.T) {
			t.Parallel()

			// nil is safe to pass: the identifier is checked before
			// anything touches the handle, which is itself the assertion —
			// a malformed identifier must never reach a statement.
			err := pg.EnableRLS(context.Background(), nil, table)
			if !errors.Is(err, domain.ErrInvalidConfig) {
				t.Fatalf("EnableRLS(%q) error = %v, want ErrInvalidConfig", table, err)
			}
		})
	}
}

func TestRLSPredicates(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name         string
		err          error
		insufficient bool
		policy       bool
	}{
		{"nil", nil, false, false},
		{"a plain error", errors.New("something went wrong"), false, false},
		{"a different SQLSTATE", &pgconn.PgError{Code: "23505"}, false, false},
		{"42501 missing grant", &pgconn.PgError{Code: pg.RLSViolationCode, Message: "permission denied for table documents"}, true, false},
		{"42501 policy", &pgconn.PgError{Code: pg.RLSViolationCode, Message: `new row violates row-level security policy for table "documents"`}, true, true},
		{"42501 policy, wrapped", errors.Join(errors.New("context"), &pgconn.PgError{Code: pg.RLSViolationCode, Message: "new row violates row-level security policy"}), true, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := pg.IsInsufficientPrivilege(tc.err); got != tc.insufficient {
				t.Errorf("IsInsufficientPrivilege(%v) = %v, want %v", tc.err, got, tc.insufficient)
			}
			if got := pg.IsRLSPolicyViolation(tc.err); got != tc.policy {
				t.Errorf("IsRLSPolicyViolation(%v) = %v, want %v", tc.err, got, tc.policy)
			}
		})
	}

	if pg.RLSViolationCode != "42501" {
		t.Errorf("pg.RLSViolationCode = %q, want \"42501\" (insufficient_privilege)", pg.RLSViolationCode)
	}
}

// TestEnforcementFindingsDistinguishEveryBypass is the unit-test half of
// the non-vacuity argument.
//
// A check that answered "fail-closed" unconditionally would be worse than
// no check at all: a conformance suite gated on it would pass against a
// database with no policies. Findings is a method over the measured fields
// precisely so that every state Postgres can be in — including the ones a
// container cannot easily be put into, such as a role holding BYPASSRLS —
// can be constructed here and the verdict asserted.
//
// Each case changes exactly one measurement away from a healthy
// deployment and requires both that the verdict flips and that the stated
// reason is the right one. A finding that named the wrong cause would send
// an operator to fix the wrong thing.
func TestEnforcementFindingsDistinguishEveryBypass(t *testing.T) {
	t.Parallel()

	healthy := pg.Enforcement{
		Role:        "app",
		SessionRole: "v-token-app-role-abc",
		Tables: []pg.TableEnforcement{{
			Table: "x.y", Exists: true,
			RowSecurityEnabled: true, RowSecurityForced: true, PolicyPresent: true,
			PolicyHasCheck: true, PolicyMatchesPredicate: true, AccessPolicyPresent: true,
			RowSecurityActive: true,
		}},
	}
	if !healthy.FailClosed() {
		t.Fatalf("a correctly separated deployment is reported as not fail-closed: %v", healthy.Findings())
	}

	cases := []struct {
		name     string
		mutate   func(*pg.Enforcement)
		wantSaid string
	}{
		{"superuser", func(e *pg.Enforcement) { e.Superuser = true }, "superuser"},
		{"bypassrls", func(e *pg.Enforcement) { e.BypassRLS = true }, "BYPASSRLS"},
		{"residual tenant context", func(e *pg.Enforcement) { e.ResidualTenantContext = "01ARZ" }, "survived"},
		{"table missing", func(e *pg.Enforcement) { e.Tables[0].Exists = false }, "does not exist"},
		{"rls not enabled", func(e *pg.Enforcement) { e.Tables[0].RowSecurityEnabled = false }, "row-level security enabled"},
		{"no policy", func(e *pg.Enforcement) { e.Tables[0].PolicyPresent = false }, "carries no"},
		{"no with check", func(e *pg.Enforcement) { e.Tables[0].PolicyHasCheck = false }, "WITH CHECK"},
		{"wrong predicate", func(e *pg.Enforcement) { e.Tables[0].PolicyMatchesPredicate = false }, "does not look like"},
		{"no permissive companion", func(e *pg.Enforcement) { e.Tables[0].AccessPolicyPresent = false }, "permissive companion"},
		{"not forced", func(e *pg.Enforcement) { e.Tables[0].RowSecurityForced = false }, "FORCEd"},
		{
			"owned by the role even with FORCE",
			func(e *pg.Enforcement) { e.Tables[0].OwnedByRole = true },
			"owned by",
		},
		// The authoritative measurement, and the one case every field
		// above is only an input to: Postgres says this role's statements
		// are not filtered, while enabled, FORCEd and the policy all look
		// right. Whatever the reason, a deployment in that state is not
		// fail-closed and must not be told it is.
		{
			"row security not active for the role",
			func(e *pg.Enforcement) { e.Tables[0].RowSecurityActive = false },
			"row_security_active",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			broken := healthy
			broken.Tables = append([]pg.TableEnforcement(nil), healthy.Tables...)
			tc.mutate(&broken)

			if broken.FailClosed() {
				t.Fatalf("FailClosed() is true with %s: the check is not distinguishing this state, so a "+
					"suite gated on it would pass while proving nothing", tc.name)
			}
			findings := strings.Join(broken.Findings(), "\n")
			if !strings.Contains(findings, tc.wantSaid) {
				t.Fatalf("the findings for %s do not mention %q, so they would send an operator to fix the "+
					"wrong thing:\n%s", tc.name, tc.wantSaid, findings)
			}
		})
	}

	// An owner can disable RLS or drop the policy even when FORCE is set,
	// so ownership is a finding regardless of FORCE.
	ownedButForced := healthy
	ownedButForced.Tables = []pg.TableEnforcement{{
		Table: "x.y", Exists: true,
		RowSecurityEnabled: true, RowSecurityForced: true, PolicyPresent: true,
		PolicyHasCheck: true, PolicyMatchesPredicate: true, AccessPolicyPresent: true,
		OwnedByRole: true, RowSecurityActive: true,
	}}
	if ownedButForced.FailClosed() {
		t.Error("owning a FORCEd table is reported as fail-closed, but an owner can still disable RLS or drop the policy")
	}
}

func TestRegistryTablesExemptFromRLSReturnsACopy(t *testing.T) {
	t.Parallel()

	first := pg.RegistryTablesExemptFromRLS()
	delete(first, "tenancy.tenants")
	if _, ok := pg.RegistryTablesExemptFromRLS()["tenancy.tenants"]; !ok {
		t.Fatal("mutating the returned map removed the tenants exemption from the global list")
	}
}

func TestZeroEnforcementIsNotFailClosed(t *testing.T) {
	t.Parallel()

	if (pg.Enforcement{}).FailClosed() {
		t.Fatal("the zero Enforcement reports fail-closed; a zero value means nothing was measured")
	}
}
