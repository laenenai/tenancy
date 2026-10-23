// This file answers one question a deployment cannot answer by reading its
// own code: *will Postgres actually refuse a cross-tenant statement on this
// connection?*
//
// The question exists because the answer is "no" in several configurations
// that look entirely correct from Go. A superuser bypasses row security
// unconditionally, regardless of FORCE. A table's owner bypasses it unless
// FORCE is set. A role with BYPASSRLS bypasses it by name. A connection
// whose previous transaction leaked its tenant setting at session scope
// carries the wrong tenant into the next borrower. None of those are
// visible in a Go type, and every one of them makes a passing test prove
// nothing.
//
// That is also why this is production surface and not test scaffolding. A
// deployment runs CheckEnforcement at startup and refuses to serve, or
// shouts, if FailClosed is false — and the conformance suite runs the same
// function to establish that its own assertions are being made under
// enforcement rather than under a bypass. A conformance suite that did not
// check this would pass identically against a database with no policies at
// all.
//
// Every query here reads pg_catalog or a session setting. sqlc cannot
// generate any of it — it resolves relations against db/migrations, which
// holds no pg_catalog — so these statements are hand-written, which
// CONVENTIONS.md records as a limit of the tool rather than a judgement
// about the SQL.

package pg

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/laenenai/tenancy/internal/domain"
)

// RLSViolationCode is the SQLSTATE Postgres raises when a row-level
// security WITH CHECK fails: 42501, insufficient_privilege.
//
// It is exported because a caller — and a conformance suite — must be able
// to assert *which mechanism refused* a cross-tenant write, not merely
// that something did. A CHECK constraint, a trigger, a foreign key and a
// policy all refuse an INSERT, and only one of them is the backstop this
// module claims to provide. A test satisfied by "an error happened" passes
// against a schema whose policy does nothing.
const RLSViolationCode = "42501"

// IsRLSViolation reports whether err is Postgres refusing a statement
// under a row-level-security policy's WITH CHECK.
//
// It deliberately does not accept every error: see RLSViolationCode.
func IsRLSViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == RLSViolationCode
}

// Enforcement is what Postgres will actually do to a tenant-scoped
// statement run through a particular Scoped handle.
//
// Every field is read from the live catalog or from the live session, on
// the same pool and as the same effective role a real statement would use.
// None of it is inferred from configuration.
type Enforcement struct {
	// Role is the effective role a scoped statement runs as: the result of
	// current_user inside a transaction this handle opened, which is the
	// application role when AppRole is set and the connecting role
	// otherwise.
	Role string

	// Superuser and BypassRLS are the two role attributes that defeat row
	// security outright. A superuser bypasses it unconditionally, FORCE or
	// not; BYPASSRLS does the same by name. Either one true means nothing
	// else in this struct constrains anything.
	Superuser bool
	BypassRLS bool

	// Tables is one report per table CheckEnforcement was asked about.
	Tables []TableEnforcement

	// ResidualTenantContext is what a transaction on this pool that sets
	// *no* tenant context observes for TenantGUC. It must be empty.
	//
	// A non-empty value means a previous scoped transaction's setting
	// survived its transaction and is now visible to the next borrower of
	// that connection — which is the "session context not reset on handle
	// reuse" failure, and a cross-tenant disclosure. The probe is run on
	// the same pool, so with a small pool it lands on a connection a
	// scoped transaction has already used.
	ResidualTenantContext string
}

// TableEnforcement is the row-security state of one table.
type TableEnforcement struct {
	// Table is the "schema.table" name as it was asked about.
	Table string
	// Exists is false if the table could not be found, in which case
	// nothing else here means anything.
	Exists bool
	// RowSecurityEnabled is pg_class.relrowsecurity.
	RowSecurityEnabled bool
	// RowSecurityForced is pg_class.relforcerowsecurity. Without it the
	// table's owner is exempt from its own policy.
	RowSecurityForced bool
	// PolicyPresent reports whether a policy named TenantPolicyName exists
	// on the table.
	PolicyPresent bool
	// OwnedByRole reports whether Enforcement.Role owns this table. An
	// owner is exempt from row security unless RowSecurityForced.
	OwnedByRole bool
}

// FailClosed reports whether a cross-tenant statement through this handle
// would actually be refused: no bypass on the role, no residual context,
// and every table enabled, FORCEd and carrying the policy.
//
// It is derived from Findings rather than stored, so there is no way for
// the verdict and the reasons to disagree.
func (e Enforcement) FailClosed() bool { return len(e.Findings()) == 0 }

// CheckEnforcement probes what Postgres will do to statements this handle
// runs against each of tables (each given as "schema.table").
//
// It opens two transactions on the handle's own pool: one scoped exactly
// as Tx scopes, to read the effective role and the catalog as that role
// sees it, and one unscoped, to measure ResidualTenantContext. Both are
// rolled back.
func (s Scoped) CheckEnforcement(ctx context.Context, tables ...string) (Enforcement, error) {
	if !s.Valid() {
		return Enforcement{}, fmt.Errorf("%w: this handle was not produced by resolving a tenant", domain.ErrNoTenantScope)
	}

	out := Enforcement{}
	err := s.Tx(ctx, func(ctx context.Context, tx TenantTx) error {
		return out.readAsRole(ctx, tx, tables)
	})
	if err != nil {
		return Enforcement{}, err
	}

	residual, err := s.residualTenantContext(ctx)
	if err != nil {
		return Enforcement{}, err
	}
	out.ResidualTenantContext = residual

	return out, nil
}

// readAsRole fills in everything observable from inside a scoped
// transaction. Reading the catalog as the application role rather than as
// the connecting role is the point: ownership is relative to a role, so
// "does the role that runs the statements own this table" cannot be
// answered from a connection that is not that role.
func (e *Enforcement) readAsRole(ctx context.Context, tx TenantTx, tables []string) error {
	err := tx.QueryRow(ctx, `
		SELECT current_user,
		       coalesce(r.rolsuper, false),
		       coalesce(r.rolbypassrls, false)
		FROM pg_roles r
		WHERE r.rolname = current_user
	`).Scan(&e.Role, &e.Superuser, &e.BypassRLS)
	if err != nil {
		return fmt.Errorf("%w: reading the effective role's attributes", domain.ErrUnavailable)
	}

	for _, table := range tables {
		report, err := tableEnforcement(ctx, tx, table)
		if err != nil {
			return err
		}
		e.Tables = append(e.Tables, report)
	}
	return nil
}

// tableEnforcement reads one table's row-security state.
//
// The regclass lookup is wrapped in to_regclass rather than a cast,
// because a cast raises for a table that does not exist and a missing
// table is a finding to report rather than an error to propagate — a
// deployment asking about a table it has not created yet should be told
// so, not handed a Postgres exception.
func tableEnforcement(ctx context.Context, tx TenantTx, table string) (TableEnforcement, error) {
	if _, err := qualifiedIdentifier(table); err != nil {
		return TableEnforcement{}, err
	}

	out := TableEnforcement{Table: table}
	err := tx.QueryRow(ctx, `
		SELECT c.relrowsecurity,
		       c.relforcerowsecurity,
		       pg_get_userbyid(c.relowner) = current_user,
		       EXISTS (
		           SELECT 1 FROM pg_policy p
		           WHERE p.polrelid = c.oid AND p.polname = $2
		       )
		FROM pg_class c
		WHERE c.oid = to_regclass($1)
	`, table, TenantPolicyName).Scan(
		&out.RowSecurityEnabled, &out.RowSecurityForced, &out.OwnedByRole, &out.PolicyPresent,
	)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return out, nil
	case err != nil:
		return TableEnforcement{}, fmt.Errorf("%w: reading the row-security state of %s", domain.ErrUnavailable, table)
	}
	out.Exists = true
	return out, nil
}

// residualTenantContext opens a transaction on this handle's pool that
// sets no tenant context and reports what it observes for TenantGUC.
//
// It narrows to the application role first, because that is the role whose
// statements the measurement is about, and because a residual setting is
// equally dangerous whichever role observes it.
func (s Scoped) residualTenantContext(ctx context.Context) (string, error) {
	tx, err := s.begin(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if s.appRole != "" {
		if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+pgx.Identifier{s.appRole}.Sanitize()); err != nil {
			return "", fmt.Errorf("%w: narrow the probe transaction to the application role: %w", domain.ErrUnavailable, err)
		}
	}

	var residual string
	if err := tx.QueryRow(ctx, "SELECT current_setting($1, true)", TenantGUC).Scan(&residual); err != nil {
		return "", fmt.Errorf("%w: reading the residual tenant session context", domain.ErrUnavailable)
	}
	return residual, nil
}

// Findings names every reason this deployment is not fail-closed, in prose
// an operator can act on, and an empty result is the passing answer.
//
// It is a method over the measured fields rather than a stored slice, so
// that a value assembled anywhere — including by a test putting the system
// into a state a container cannot easily be put into — gets the same
// verdict as one CheckEnforcement produced, and so that the verdict can
// never be stale with respect to the measurements.
//
// The order is deliberate: a role-level bypass makes every table-level
// finding irrelevant, so it is stated first.
func (e Enforcement) Findings() []string {
	var out []string

	if e.Superuser {
		out = append(out, "the role statements run as ("+e.Role+
			") is a superuser, which bypasses row security unconditionally — FORCE ROW LEVEL SECURITY does not change that; "+
			"configure the runtime credential, or AppRole, as a non-superuser role")
	}
	if e.BypassRLS {
		out = append(out, "the role statements run as ("+e.Role+
			") has BYPASSRLS, so no policy on any table constrains it")
	}
	if e.ResidualTenantContext != "" {
		out = append(out, "a transaction that set no tenant context observed "+TenantGUC+
			" = "+e.ResidualTenantContext+", so a previous transaction's tenant scope survived onto a pooled "+
			"connection and is visible to the next borrower")
	}

	for _, t := range e.Tables {
		switch {
		case !t.Exists:
			out = append(out, t.Table+" does not exist, so nothing can be said about its row security")
		case !t.RowSecurityEnabled:
			out = append(out, t.Table+" does not have row-level security enabled, so its tenant isolation is application-level only")
		case !t.PolicyPresent:
			out = append(out, t.Table+" has row-level security enabled but carries no "+TenantPolicyName+
				" policy: Postgres default-denies every statement against it")
		case !t.RowSecurityForced && t.OwnedByRole:
			out = append(out, t.Table+" is owned by "+e.Role+
				" and its row security is not FORCEd, so the policy does not bind the role that runs the statements")
		case !t.RowSecurityForced:
			out = append(out, t.Table+" does not have row-level security FORCEd, so its owner is exempt from its own policy")
		}
	}

	return out
}
