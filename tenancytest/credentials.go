package tenancytest

// This file is the conformance suite for the credentials port —
// tenancy.Credentials — and it is separate from RunTenancySuite because it is
// parameterised over something else: a credential source and a database for
// it to issue against, rather than a wired deployment.
//
// # Why half of it only runs for a dynamic source
//
// The port has two shipping implementations and they promise different
// amounts. tenancy.StaticDSNCredentials promises only to hand back the
// credential the pool row already carries, and there is nothing else to
// assert about it: whether that credential is a superuser, whether it can do
// DDL, and whether row security binds it are facts about the deployment's
// own configuration, which RunTenancySuite is where they belong.
//
// A source that *issues* a credential is making four further claims, and all
// four are claims whose failure was measured rather than imagined (see
// docs/superpowers/spikes/2026-10-23-openbao-db-credentials.md):
//
//  1. The credential inherits the application role, and inherits it with
//     USAGE. Asserted as pg_has_role(current_user, <app role>, 'USAGE') and
//     never 'MEMBER' — a NOINHERIT credential that holds no privileges at
//     all still answers true to 'MEMBER', so a check written that way passes
//     a credential that cannot read a single row. This subtest exists
//     because of that exact result.
//  2. Row security actually binds it. Asserted as
//     row_security_active(<table>) read *from the issued credential*, plus
//     the three behavioural halves: no tenant context sees nothing, a
//     tenant context sees only its own rows, and a cross-tenant write is
//     refused by the policy.
//  3. It cannot create objects. This is not hygiene. A dynamic credential
//     that owns anything cannot be dropped — Postgres refuses with SQLSTATE
//     2BP01 and the default revocation statements carry no REASSIGN OWNED —
//     so the role stays in Postgres, the lease stays in the issuer, and only
//     manual intervention clears either. The inability to do DDL is what
//     keeps revocation working.
//  4. Releasing it stops new connections being made with it, so that
//     handing a credential back means something.
//
// CredentialSource.Dynamic is what says which half applies, and the subtests
// that do not apply skip with the reason rather than passing silently.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/laenenai/tenancy"
)

// CredentialSource is what a consumer supplies to RunCredentialsSuite.
type CredentialSource struct {
	// Credentials is the source under test.
	//
	// Required.
	Credentials tenancy.Credentials

	// Deployment names the database this source issues credentials for.
	// MigrationDSN must hold DDL rights on it — the suite stands up its
	// own tenant-scoped table there and grants it to AppRole — and AppRole
	// is the application role an issued credential must inherit.
	//
	// RuntimeDSN is not used: the point of this suite is the credential the
	// source issues, not the one a deployment configured.
	//
	// Required.
	Deployment Deployment

	// Dynamic reports whether this source issues its own credentials with
	// an expiry, rather than handing back the connection string the pool
	// row already carries. It decides which half of the suite applies; see
	// this file's comment.
	Dynamic bool
}

// RunCredentialsSuite runs the contract every tenancy.Credentials
// implementation must satisfy.
//
// newSource is called once per subtest, receiving that subtest's own
// *testing.T, and must return a source and a freshly created database for it
// — nothing of this suite's present. A harness that needs per-test setup and
// teardown registers it with t.Cleanup inside newSource, so every subtest
// gets isolated state.
func RunCredentialsSuite(t *testing.T, newSource func(t *testing.T) CredentialSource) {
	t.Helper()

	// What every source promises.
	t.Run("IssuesACredentialThatConnects", testIssuesACredentialThatConnects(newSource))
	t.Run("AnIssuedCredentialDeclaresItsOwnLifetime", testCredentialLifetime(newSource))
	t.Run("ReleasingTheZeroCredentialIsANoOp", testReleaseZeroCredential(newSource))

	// What a source that issues credentials promises on top.
	t.Run("EachIssueIsADistinctCredential", testIssuesAreDistinct(newSource))
	t.Run("IssuedCredentialInheritsTheApplicationRoleThroughUSAGE", testIssuedCredentialInherits(newSource))
	t.Run("IssuedCredentialIsSubjectToRowLevelSecurity", testIssuedCredentialIsSubjectToRLS(newSource))
	t.Run("IssuedCredentialCannotCreateObjects", testIssuedCredentialCannotCreateObjects(newSource))
	t.Run("ReleasedCredentialCannotOpenANewConnection", testReleasedCredentialIsRefused(newSource))
	t.Run("RenderingsOfAnIssuedCredential", testRenderingsOfAnIssuedCredential(newSource))
}

// The fixture this suite stands up in the target database. It is its own
// schema so that it cannot collide with RunTenancySuite's, which a harness
// may well have run against the same server.
const (
	credsSchema = "tenancytest_creds"
	credsTable  = credsSchema + ".scoped"
	credsOwner  = "tenancytest_creds_owner"
)

// The two tenant ids the fixture rows belong to. They are literals rather
// than minted ULIDs because the assertions quote them, and nothing here
// resolves a tenant.
const (
	fixtureTenantAID = "01ARZ3NDEKTSV4RRFFQ69G5FA1"
	fixtureTenantBID = "01ARZ3NDEKTSV4RRFFQ69G5FA2"
)

// credsEnv is one prepared target database: the administrative pool, the
// fixture table, and the pool row the source is asked to issue against.
type credsEnv struct {
	src   CredentialSource
	admin *pgxpool.Pool
	pool  tenancy.Pool
}

// setupCredentials stands up the fixture and returns the environment.
//
// The fixture table is created through tenancy.EnableRLS and owned by a
// separate non-superuser role, for the same reason RunTenancySuite does it:
// row security does not bind a table's owner unless it is FORCEd, and a
// table owned by the role under test would make every assertion below
// vacuous in a way that looks like a pass.
func setupCredentials(t *testing.T, src CredentialSource) *credsEnv {
	t.Helper()
	ctx := context.Background()

	if src.Credentials == nil {
		t.Fatal("tenancytest: CredentialSource.Credentials is required")
	}
	if src.Deployment.MigrationDSN == "" {
		t.Fatal("tenancytest: CredentialSource.Deployment.MigrationDSN is required")
	}
	if src.Deployment.AppRole == "" {
		t.Fatal("tenancytest: CredentialSource.Deployment.AppRole is required")
	}

	admin, err := pgxpool.New(ctx, string(src.Deployment.MigrationDSN))
	if err != nil {
		// Never with the error: pgx's parse failure can carry the
		// connection string through verbatim.
		t.Fatal("tenancytest: open the administrative pool for the credentials suite")
	}
	t.Cleanup(admin.Close)

	execAll(ctx, t, admin, "CREATE SCHEMA IF NOT EXISTS "+quote(credsSchema))
	ensureRole(ctx, t, admin, credsOwner)
	ensureRole(ctx, t, admin, src.Deployment.AppRole)
	execAll(ctx, t, admin,
		"GRANT USAGE, CREATE ON SCHEMA "+quote(credsSchema)+" TO "+quote(credsOwner),
		"GRANT USAGE ON SCHEMA "+quote(credsSchema)+" TO "+quote(src.Deployment.AppRole),
		"CREATE TABLE IF NOT EXISTS "+credsTable+" (id text PRIMARY KEY, tenant_id text NOT NULL)",
		"ALTER TABLE "+credsTable+" OWNER TO "+quote(credsOwner),
		// SELECT and INSERT only. UPDATE, DELETE and TRUNCATE are withheld
		// so that the privilege layer refuses them before any policy is
		// consulted: row security is the backstop here, never the only
		// control.
		"GRANT SELECT, INSERT ON "+credsTable+" TO "+quote(src.Deployment.AppRole),
	)
	if err := tenancy.EnableRLS(ctx, admin, credsTable); err != nil {
		t.Fatalf("tenancy.EnableRLS(%s): %v", credsTable, err)
	}

	// Seeded on the administrative connection, which bypasses the policy,
	// because the fixture needs rows belonging to a tenant the credential
	// under test must not be able to see.
	execAll(ctx, t, admin,
		"INSERT INTO "+credsTable+" (id, tenant_id) VALUES ('a-1', '"+fixtureTenantAID+"') ON CONFLICT DO NOTHING",
		"INSERT INTO "+credsTable+" (id, tenant_id) VALUES ('a-2', '"+fixtureTenantAID+"') ON CONFLICT DO NOTHING",
		"INSERT INTO "+credsTable+" (id, tenant_id) VALUES ('b-1', '"+fixtureTenantBID+"') ON CONFLICT DO NOTHING",
	)

	return &credsEnv{
		src:   src,
		admin: admin,
		pool: tenancy.Pool{
			ID:             tenancy.NewPoolID(tenancy.SystemClock{}),
			Name:           "credentials-suite",
			Region:         "test-region",
			MetadataDSN:    src.Deployment.MigrationDSN,
			BlobConfigRef:  "blob-credentials-suite",
			WorkerCapacity: 4,
		},
	}
}

// issue asks the source for a credential and registers its release.
func (e *credsEnv) issue(ctx context.Context, t *testing.T) tenancy.Credential {
	t.Helper()

	cred, err := e.src.Credentials.Issue(ctx, e.pool)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	t.Cleanup(func() {
		// Best-effort and logged rather than failed: a cleanup failure
		// must not mask the subtest's own result. The context is detached
		// rather than fresh, because a cleanup runs after the test's own
		// context may already have been cancelled.
		if err := e.src.Credentials.Release(context.WithoutCancel(ctx), cred); err != nil {
			t.Logf("cleanup: Release(%s): %v", cred.Username, err)
		}
	})
	return cred
}

// connect opens a pool as cred, through the module's own production opener
// rather than through pgx directly — otherwise the subtests would be
// asserting against this file's idea of how a credential is applied instead
// of against the one real deployments use.
func (e *credsEnv) connect(ctx context.Context, t *testing.T, cred tenancy.Credential) *pgxpool.Pool {
	t.Helper()

	db, err := e.open(ctx, cred)
	if err != nil {
		t.Fatalf("open a pool as the issued credential %s: %v", cred.Username, err)
	}
	t.Cleanup(db.Close)
	return db
}

// open is connect without the t.Fatalf, for the one subtest whose
// expectation is that opening fails.
func (e *credsEnv) open(ctx context.Context, cred tenancy.Credential) (*pgxpool.Pool, error) {
	opener := tenancy.NewOpener(tenancy.PoolConfig{
		MaxConns:        2,
		ApplicationName: "tenancytest-credentials",
	})
	return opener(ctx, e.pool, cred)
}

// ---------------------------------------------------------------------------
// What every source promises
// ---------------------------------------------------------------------------

func testIssuesACredentialThatConnects(newSource func(t *testing.T) CredentialSource) func(*testing.T) {
	return func(t *testing.T) {
		src := newSource(t)
		e := setupCredentials(t, src)
		ctx := context.Background()

		cred := e.issue(ctx, t)
		db := e.connect(ctx, t, cred)

		var currentUser, sessionUser string
		if err := db.QueryRow(ctx, "SELECT current_user, session_user").Scan(&currentUser, &sessionUser); err != nil {
			t.Fatalf("read current_user as the issued credential: %v", err)
		}

		if !src.Dynamic {
			if !cred.IsZero() {
				t.Errorf("a source declared as not dynamic issued %s; a static source must return the zero "+
					"Credential, which is what tells the resolver there is no expiry to retire a pool against", cred)
			}
			return
		}

		if cred.Username == "" || cred.Password == "" {
			t.Fatalf("Issue returned %s: a dynamic source must return both a username and a password", cred)
		}
		// The connection is authenticated as the issued role, not merely
		// opened. session_user is the authenticated identity and cannot be
		// changed by SET ROLE, which is why it is the one asserted here.
		if sessionUser != cred.Username {
			t.Errorf("the connection authenticated as session_user %q, but the credential names %q: the "+
				"credential was not what connected", sessionUser, cred.Username)
		}
	}
}

func testCredentialLifetime(newSource func(t *testing.T) CredentialSource) func(*testing.T) {
	return func(t *testing.T) {
		src := newSource(t)
		e := setupCredentials(t, src)
		ctx := context.Background()

		cred := e.issue(ctx, t)

		if !src.Dynamic {
			if cred.Expires() {
				t.Errorf("a static source issued a credential expiring at %s; a pool would then be retired "+
					"and replaced on a credential that never changes", cred.ExpiresAt)
			}
			return
		}

		if !cred.Expires() {
			t.Fatal("a dynamic source issued a credential with no ExpiresAt. There is then nothing to " +
				"schedule a pool retirement against, and the credential's revocation would be discovered " +
				"as a transaction failing mid-statement")
		}
		if cred.IssuedAt.IsZero() {
			t.Error("the issued credential reports no IssuedAt, so its whole lifetime cannot be read from " +
				"the value — which is what the drain-window check in internal/pool is made against")
		}
		if !cred.ExpiresAt.After(cred.IssuedAt) {
			t.Errorf("the issued credential expires at %s, which is not after it was issued at %s",
				cred.ExpiresAt, cred.IssuedAt)
		}
		if ttl := cred.TTL(); ttl <= 0 {
			t.Errorf("the issued credential's TTL is %s, want a positive duration", ttl)
		}
		if cred.LeaseID == "" {
			t.Error("the issued credential carries no LeaseID, so Release has nothing to hand back and the " +
				"credential can only be waited out")
		}
	}
}

func testReleaseZeroCredential(newSource func(t *testing.T) CredentialSource) func(*testing.T) {
	return func(t *testing.T) {
		src := newSource(t)
		_ = setupCredentials(t, src)

		// The port requires this of every implementation: the resolver
		// calls Release on every pool it closes, including the ones
		// connected on a pool row's own DSN, where there is nothing to
		// hand back.
		if err := src.Credentials.Release(context.Background(), tenancy.Credential{}); err != nil {
			t.Fatalf("Release(zero Credential) = %v, want nil: releasing nothing must be a no-op", err)
		}
	}
}

// ---------------------------------------------------------------------------
// What a source that issues credentials promises on top
// ---------------------------------------------------------------------------

// skipUnlessDynamic skips with the reason rather than passing silently,
// which is the difference between a subtest that does not apply and one that
// asserted nothing.
func skipUnlessDynamic(t *testing.T, src CredentialSource) {
	t.Helper()
	if !src.Dynamic {
		t.Skip("this source hands back the pool row's own credential, so what that credential may do is a " +
			"fact about the deployment's configuration rather than about this source; RunTenancySuite is " +
			"where those assertions live")
	}
}

func testIssuesAreDistinct(newSource func(t *testing.T) CredentialSource) func(*testing.T) {
	return func(t *testing.T) {
		src := newSource(t)
		skipUnlessDynamic(t, src)
		e := setupCredentials(t, src)
		ctx := context.Background()

		first := e.issue(ctx, t)
		second := e.issue(ctx, t)

		if first.Username == second.Username {
			t.Errorf("two issues returned the same username %q: a credential per pool is what keeps the "+
				"blast radius of one credential to one pool, and what lets one pool be retired without "+
				"touching another", first.Username)
		}
		if first.Password == second.Password {
			t.Error("two issues returned the same password")
		}
		if first.LeaseID == second.LeaseID {
			t.Errorf("two issues returned the same lease id, so releasing one would release the other")
		}

		// Both have to work, not merely differ: an issuer that returned a
		// fresh name for a credential it never created would pass the
		// assertions above.
		for _, cred := range []tenancy.Credential{first, second} {
			db := e.connect(ctx, t, cred)
			if err := db.Ping(ctx); err != nil {
				t.Errorf("ping as %s: %v", cred.Username, err)
			}
		}
	}
}

func testIssuedCredentialInherits(newSource func(t *testing.T) CredentialSource) func(*testing.T) {
	return func(t *testing.T) {
		src := newSource(t)
		skipUnlessDynamic(t, src)
		e := setupCredentials(t, src)
		ctx := context.Background()

		cred := e.issue(ctx, t)
		db := e.connect(ctx, t, cred)

		var usage, member, inherits bool
		err := db.QueryRow(ctx, `
			SELECT pg_has_role(current_user, $1, 'USAGE'),
			       pg_has_role(current_user, $1, 'MEMBER'),
			       coalesce((SELECT rolinherit FROM pg_roles WHERE rolname = current_user), false)
		`, src.Deployment.AppRole).Scan(&usage, &member, &inherits)
		if err != nil {
			t.Fatalf("read the issued credential's membership of %s: %v", src.Deployment.AppRole, err)
		}

		if !usage {
			t.Errorf("pg_has_role(current_user, %q, 'USAGE') is false for the issued credential "+
				"(MEMBER=%v, rolinherit=%v). USAGE is what a policy's TO clause is resolved with, so a "+
				"policy written against %s does not cover this credential at all — and it holds none of "+
				"that role's privileges either. The usual cause is NOINHERIT in the issuing role's "+
				"creation statements",
				src.Deployment.AppRole, member, inherits, src.Deployment.AppRole)
		}

		// Corroboration, because 'USAGE' being true is a statement about
		// the catalog and this is a statement about what the credential can
		// actually do. A privilege granted to the application role has to
		// be reachable through the membership, or the membership is not
		// doing the work the design assigns to it.
		var canSelect bool
		if err := db.QueryRow(ctx, "SELECT has_table_privilege(current_user, $1, 'SELECT')", credsTable).Scan(&canSelect); err != nil {
			t.Fatalf("read the issued credential's privileges on %s: %v", credsTable, err)
		}
		if !canSelect {
			t.Errorf("the issued credential cannot SELECT %s, which was granted to %s: it inherits none of "+
				"that role's privileges", credsTable, src.Deployment.AppRole)
		}

		// Stated rather than asserted, because it is the trap this subtest
		// exists to avoid rather than a property of a correct credential:
		// 'MEMBER' answers true for a NOINHERIT credential that holds
		// nothing at all, so a suite written against it would pass a
		// completely non-functional credential. Measured in the spike.
		if member && !usage {
			t.Error("the issued credential is a MEMBER of the application role but has no USAGE on it, " +
				"which is precisely the state a membership check written against 'MEMBER' would report as " +
				"healthy while every statement is denied")
		}
	}
}

func testIssuedCredentialIsSubjectToRLS(newSource func(t *testing.T) CredentialSource) func(*testing.T) {
	return func(t *testing.T) {
		src := newSource(t)
		skipUnlessDynamic(t, src)
		e := setupCredentials(t, src)
		ctx := context.Background()

		cred := e.issue(ctx, t)
		db := e.connect(ctx, t, cred)

		// One: Postgres's own answer to whether this credential's
		// statements are filtered. It is read first because every
		// assertion below would pass vacuously against a credential it
		// says no for — a credential that sees nothing because it is
		// filtered and one that sees nothing because it has no privileges
		// are indistinguishable from the row counts alone.
		var active bool
		if err := db.QueryRow(ctx, "SELECT row_security_active($1)", credsTable).Scan(&active); err != nil {
			t.Fatalf("read row_security_active(%s) as the issued credential: %v", credsTable, err)
		}
		if !active {
			var super, bypass bool
			_ = db.QueryRow(ctx, `
				SELECT coalesce(rolsuper, false), coalesce(rolbypassrls, false)
				FROM pg_roles WHERE rolname = current_user
			`).Scan(&super, &bypass)
			t.Fatalf("row_security_active(%s) is false for the issued credential (superuser=%v, "+
				"bypassrls=%v): the policy does not filter its statements, so the fail-closed backstop is "+
				"not armed for it", credsTable, super, bypass)
		}

		// Two: no tenant context sees nothing. Zero rows AND no error —
		// a predicate that raised would be a failure a caller can
		// distinguish, where the contract is a quiet denial.
		var unscoped int
		if err := db.QueryRow(ctx, "SELECT count(*) FROM "+credsTable).Scan(&unscoped); err != nil {
			t.Fatalf("count rows with no tenant context: %v, want a quiet zero", err)
		}
		if unscoped != 0 {
			t.Errorf("the issued credential sees %d rows with no tenant context, want 0: this is the "+
				"fail-closed claim, and it is not holding", unscoped)
		}

		// Three: a tenant context sees exactly its own rows.
		tx, err := db.Begin(ctx)
		if err != nil {
			t.Fatalf("begin as the issued credential: %v", err)
		}
		defer func() { _ = tx.Rollback(ctx) }()

		if _, err := tx.Exec(ctx, "SELECT set_config($1, $2, true)", tenancy.TenantGUC, fixtureTenantAID); err != nil {
			t.Fatalf("set %s: %v", tenancy.TenantGUC, err)
		}

		var scoped int
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM "+credsTable).Scan(&scoped); err != nil {
			t.Fatalf("count rows for tenant A: %v", err)
		}
		if scoped != 2 {
			t.Errorf("the issued credential sees %d of tenant A's 2 rows (of 3 in the table); the policy "+
				"matches this credential by membership, so it must see exactly its tenant's rows", scoped)
		}

		// Four: a cross-tenant write is refused by the policy and not by
		// something else that also raises 42501.
		_, err = tx.Exec(ctx,
			"INSERT INTO "+credsTable+" (id, tenant_id) VALUES ($1, $2)", "cross-tenant", fixtureTenantBID)
		assertPolicyRefusal(t, err, "an INSERT for another tenant through the issued credential")
	}
}

func testIssuedCredentialCannotCreateObjects(newSource func(t *testing.T) CredentialSource) func(*testing.T) {
	return func(t *testing.T) {
		src := newSource(t)
		skipUnlessDynamic(t, src)
		e := setupCredentials(t, src)
		ctx := context.Background()

		cred := e.issue(ctx, t)
		db := e.connect(ctx, t, cred)

		// The statement is deliberately a CREATE TABLE in the public
		// schema: it is the cheapest thing a credential with any object
		// creation right at all would succeed at, and the one the spike
		// measured as denied.
		_, err := db.Exec(ctx, "CREATE TABLE public.tenancytest_should_not_exist (id text)")
		if err == nil {
			_, _ = e.admin.Exec(ctx, "DROP TABLE IF EXISTS public.tenancytest_should_not_exist")
			t.Fatalf("the issued credential (%s) created a table. A credential that owns an object cannot "+
				"be dropped — Postgres refuses with SQLSTATE 2BP01 and the default revocation statements "+
				"carry no REASSIGN OWNED — so it becomes a role left in Postgres and a lease left in the "+
				"issuer that only manual intervention clears. Remove every object-creation right from the "+
				"issuing role's creation statements", cred.Username)
		}

		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) {
			t.Fatalf("CREATE TABLE as the issued credential failed with %v, want a Postgres privilege error", err)
		}
		if pgErr.Code != tenancy.RLSViolationCode {
			t.Errorf("CREATE TABLE as the issued credential was refused with SQLSTATE %s (%s), want %s "+
				"(insufficient_privilege). A refusal from some other mechanism — a name collision, a read-only "+
				"transaction — would mean this subtest is not measuring the privilege at all",
				pgErr.Code, pgErr.Message, tenancy.RLSViolationCode)
		}
	}
}

func testReleasedCredentialIsRefused(newSource func(t *testing.T) CredentialSource) func(*testing.T) {
	return func(t *testing.T) {
		src := newSource(t)
		skipUnlessDynamic(t, src)
		e := setupCredentials(t, src)
		ctx := context.Background()

		cred, err := src.Credentials.Issue(ctx, e.pool)
		if err != nil {
			t.Fatalf("Issue: %v", err)
		}

		// It worked before the release, so that what is asserted after it
		// is the release's effect and not a credential that never worked.
		working := e.connect(ctx, t, cred)
		if err := working.Ping(ctx); err != nil {
			t.Fatalf("ping before release: %v", err)
		}

		if err := src.Credentials.Release(ctx, cred); err != nil {
			t.Fatalf("Release(%s): %v", cred.Username, err)
		}

		// A *new* pool, which is the thing a release has to stop. Note
		// what is deliberately not asserted: that connections already open
		// stop working. They do not — a revocation is a privilege removal
		// and not a disconnection, nothing closes, and a transaction
		// holding a lock keeps that relation's privileges until it ends
		// (measured: a write committed 16 seconds after its role was
		// dropped). That is exactly why a pool is retired on a lead time
		// and drained rather than cut off, and it is why this subtest
		// asserts the half that is actually true.
		released, err := e.open(ctx, cred)
		if err == nil {
			released.Close()
			t.Fatalf("a new pool opened successfully as %s after its credential was released; handing a "+
				"credential back has to stop it being usable, or the issuer's record of what is live is "+
				"not what is live", cred.Username)
		}
	}
}

func testRenderingsOfAnIssuedCredential(newSource func(t *testing.T) CredentialSource) func(*testing.T) {
	return func(t *testing.T) {
		src := newSource(t)
		skipUnlessDynamic(t, src)
		e := setupCredentials(t, src)
		ctx := context.Background()

		cred := e.issue(ctx, t)
		if len(cred.Password) < minMaterialLen {
			t.Fatalf("the issued password is %d bytes; this subtest cannot say anything useful about a "+
				"secret that short, and nor can anything else", len(cred.Password))
		}

		// The credential itself, and the Credentials value that issued it:
		// a source holds whatever it authenticates to its issuer with, and
		// it is in scope wherever its own error handling is.
		NoSecretLeaksInAnyRendering(t, cred, []byte(cred.Password))

		for _, missing := range missingRedactionInterfaces(src.Credentials) {
			t.Errorf("%T does not implement %s, so %s is not redacted. A credential source holds the "+
				"material it authenticates to its issuer with, and it is the value an Open failure prints",
				src.Credentials, missing.iface, missing.controls)
		}
		rendered := fmt.Sprintf("%v %+v %#v %s", src.Credentials, src.Credentials, src.Credentials, src.Credentials)
		if strings.Contains(rendered, cred.Password) {
			t.Errorf("%T disclosed an issued password in its own rendering", src.Credentials)
		}
	}
}
