package openbao_test

// The tests that need a real OpenBao and a real Postgres, because what they
// assert is a property of those two and not of this package's code.
//
// The clock is injected throughout, so none of this waits for a lease: the
// roles the harness creates issue a 30-minute lease in wall-clock terms,
// while the resolver and the adapter share a FixedClock that a test advances.
// A real TTL short enough to observe would make every test here a race
// against the server, and the spike already measured what happens when the
// retirement is late — which is the one thing a test must never have to
// discover by accident.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/laenenai/tenancy"
	"github.com/laenenai/tenancy/credentials/openbao"
	"github.com/laenenai/tenancy/tenancytest"
	"github.com/laenenai/tenancy/testdb"
)

// TestCredentialsConformance runs the port's conformance suite against this
// adapter, a real OpenBao and a real Postgres.
//
// It is the same function a consumer calls, which is the point of the suite
// living in a sibling package. The factory is called once per subtest with
// that subtest's own *T, so every subtest gets a fresh database, a fresh
// mount and a fresh database role, and the subtests are independent.
func TestCredentialsConformance(t *testing.T) {
	tenancytest.RunCredentialsSuite(t, func(t *testing.T) tenancytest.CredentialSource {
		db := testdb.Start(t)
		cfg := baoFor(t, db.DSN(), testdb.AppRole, tenancy.SystemClock{})

		source, err := openbao.Open(context.Background(), cfg)
		if err != nil {
			t.Fatalf("openbao.Open: %v", err)
		}
		return tenancytest.CredentialSource{
			Credentials: source,
			Deployment: tenancytest.Deployment{
				MigrationDSN: db.DSN(),
				AppRole:      testdb.AppRole,
			},
			Dynamic: true,
		}
	})
}

// TestCheckRoleAcceptsTheRoleThisModulePrescribes closes the loop between
// CreationStatements and CheckRole against the real server.
//
// Both halves are this module's own, so a test of either alone proves little:
// the thing worth knowing is that the statements this module tells an
// operator to configure survive a round trip through OpenBao and are then
// recognised as correct. A server that normalised them, or a check that read
// the wrong field, would show up here and nowhere else.
func TestCheckRoleAcceptsTheRoleThisModulePrescribes(t *testing.T) {
	db := testdb.Start(t)
	cfg := baoFor(t, db.DSN(), testdb.AppRole, tenancy.SystemClock{})

	source, err := openbao.Open(context.Background(), cfg)
	if err != nil {
		t.Fatalf("openbao.Open: %v", err)
	}

	check, err := source.CheckRole(context.Background(), cfg.Role)
	if err != nil {
		t.Fatalf("CheckRole(%s): %v", cfg.Role, err)
	}
	if !check.Usable() {
		t.Fatalf("the role this module's own CreationStatements configured is reported as unusable: %v",
			check.Findings())
	}
	if check.DefaultTTL != roleDefaultTTL {
		t.Errorf("CheckRole read default_ttl=%s, want %s", check.DefaultTTL, roleDefaultTTL)
	}
}

// TestIssuedCredentialIsFailClosedUnderEnforcement reads the deployment's own
// enforcement report through a handle backed by a dynamically issued
// credential.
//
// This is the positive check the spike recommends, and it is the answer to
// the worry that motivated the whole investigation: the policy names the
// application role and the session is some ephemeral `v-token-…` user, so
// does the backstop still apply? Postgres resolves a policy's TO clause with
// pg_has_role(current_user, …, 'USAGE'), so it does — and
// row_security_active, read as that very session, is the direct confirmation
// rather than an inference.
//
// Note that AppRole is deliberately left empty here. With a static DSN it is
// what drops a superuser connection's bypass; with an issued credential there
// is nothing left to narrow, because the credential is already a
// least-privileged member of the application role. That is the configuration
// tenancy.Config.AppRole's own doc comment describes as the goal, and this is
// the first test in the module that is actually in it.
func TestIssuedCredentialIsFailClosedUnderEnforcement(t *testing.T) {
	e := newEndToEnd(t, 5*time.Minute)
	ctx := context.Background()

	scoped, err := e.tenancy.Scope(ctx, e.tenant.ID)
	if err != nil {
		t.Fatalf("Scope: %v", err)
	}

	report, err := scoped.CheckEnforcement(ctx, fixtureTable)
	if err != nil {
		t.Fatalf("CheckEnforcement: %v", err)
	}
	if !report.FailClosed() {
		t.Fatalf("a deployment on dynamically issued credentials is not fail-closed: %v", report.Findings())
	}

	// The role running the statements is the issued one, with no narrowing
	// in between. If this were the application role the report would be
	// about something other than the credential.
	if !strings.HasPrefix(report.Role, "v-") {
		t.Errorf("statements run as %q, want the issued v-token-… role: the enforcement report is not about "+
			"the credential at all", report.Role)
	}
	if report.SessionRole != report.Role {
		t.Errorf("current_user=%q session_user=%q, want them equal with no AppRole configured",
			report.Role, report.SessionRole)
	}
	if report.Superuser || report.BypassRLS {
		t.Fatalf("the issued credential is superuser=%v bypassrls=%v; either one makes every policy inert",
			report.Superuser, report.BypassRLS)
	}
	if len(report.Tables) != 1 || !report.Tables[0].RowSecurityActive {
		t.Fatalf("row_security_active is not true for the issued credential: %+v", report.Tables)
	}
}

// TestPoolRetiresBeforeItsLeaseExpiresAndInFlightWorkCommits is the test the
// whole feature exists to pass, and it is the spike's worst finding turned
// into an assertion.
//
// A transaction is opened on a pool, it writes a row, and the credential's
// retirement falls due while it is still open. The failure mode this must not
// reproduce is not an error: it is a transaction that keeps running with the
// privileges it had, then fails 42501 on the first relation it touches
// afresh, poisons itself with 25P02, and has its COMMIT silently turned into
// a ROLLBACK — a write the application believes succeeded and which is not
// there. So the assertions are, in order: the in-flight transaction reads and
// commits without error, the row it wrote is actually readable afterwards,
// and the resolution that happened in the middle came back on a *different*
// issued credential.
//
// The last one is what proves the retirement happened at all. It is observed
// through session_user, which is the public surface a consumer can see it in
// too.
func TestPoolRetiresBeforeItsLeaseExpiresAndInFlightWorkCommits(t *testing.T) {
	const longestTransaction = 5 * time.Minute
	e := newEndToEnd(t, longestTransaction)

	// The borrower's context is separate and cancellable, because the
	// retired pool must stay open until it finishes — that is the drain —
	// and the end of this test is where we let it go.
	borrowerCtx, releaseBorrower := context.WithCancel(context.Background())
	defer releaseBorrower()

	scoped, err := e.tenancy.Scope(borrowerCtx, e.tenant.ID)
	if err != nil {
		t.Fatalf("Scope: %v", err)
	}

	firstCredential := e.sessionUser(borrowerCtx, t, scoped)
	if !strings.HasPrefix(firstCredential, "v-") {
		t.Fatalf("the pool connected as %q, want a dynamically issued v-token-… role", firstCredential)
	}

	var secondCredential string
	var visibleDuringRetirement int

	err = scoped.Tx(borrowerCtx, func(ctx context.Context, tx tenancy.TenantTx) error {
		// Write first, so this transaction holds RowExclusiveLock on the
		// table. That is the spike's `locked` scenario, the one that
		// committed a row 16 seconds after its role had been dropped, and
		// it is the shape most likely to hide a problem rather than report
		// one.
		if _, execErr := tx.Exec(ctx,
			"INSERT INTO "+fixtureTable+" (id, tenant_id) VALUES ($1, $2)",
			"in-flight", string(tx.Tenant()),
		); execErr != nil {
			return execErr
		}

		// Retirement falls due while this transaction is open.
		e.clock.Advance(roleDefaultTTL - longestTransaction + time.Minute)

		// A second resolution, on its own context so that its borrow is
		// accounted separately. It must come back on a new pool built on a
		// new credential.
		replacementCtx, releaseReplacement := context.WithCancel(context.Background())
		defer releaseReplacement()

		replacement, scopeErr := e.tenancy.Scope(replacementCtx, e.tenant.ID)
		if scopeErr != nil {
			return scopeErr
		}
		secondCredential = e.sessionUser(replacementCtx, t, replacement)

		// And back in the still-open transaction: a read of a relation it
		// has already locked, which is exactly what the spike measured as
		// still succeeding, and a count that must therefore not raise.
		return tx.QueryRow(ctx, "SELECT count(*) FROM "+fixtureTable).Scan(&visibleDuringRetirement)
	})
	if err != nil {
		t.Fatalf("a transaction open across its pool's retirement failed: %v\n"+
			"This is the failure the lead time exists to prevent: the pool must stop being handed to new "+
			"callers while this transaction drains, not have its credential pulled out from under it", err)
	}

	if secondCredential == firstCredential {
		t.Fatalf("the resolution during retirement came back on the same credential (%s), so the pool was "+
			"never retired and nothing here was tested", firstCredential)
	}
	if !strings.HasPrefix(secondCredential, "v-") {
		t.Errorf("the replacement pool connected as %q, want a freshly issued v-token-… role", secondCredential)
	}
	if visibleDuringRetirement == 0 {
		t.Error("the in-flight transaction saw no rows, including the one it had just written")
	}

	// The commit has to have been a commit. A COMMIT that silently became a
	// ROLLBACK is the outcome a caller cannot detect from the error — there
	// is no error — so the only way to assert it is to read the row back.
	var written int
	fresh, err := e.tenancy.Scope(context.Background(), e.tenant.ID)
	if err != nil {
		t.Fatalf("Scope after the retirement: %v", err)
	}
	err = fresh.Tx(context.Background(), func(ctx context.Context, tx tenancy.TenantTx) error {
		return tx.QueryRow(ctx,
			"SELECT count(*) FROM "+fixtureTable+" WHERE id = $1", "in-flight").Scan(&written)
	})
	if err != nil {
		t.Fatalf("read back the row written across the retirement: %v", err)
	}
	if written != 1 {
		t.Fatalf("the row written by the transaction that spanned the retirement is not there. Its COMMIT " +
			"returned no error, so this is the silent rollback: a write the application believes succeeded")
	}

	// Letting the borrower go drains the retired pool, which closes it,
	// which hands its credential back — and OpenBao's revocation drops the
	// role. That chain is only observable from the other side, in
	// pg_roles.
	releaseBorrower()
	e.awaitRoleGone(t, firstCredential)
}

// TestResolutionRefusesALeaseTooShortToDrainIn is the TTL floor against a
// real lease duration rather than a fabricated one.
//
// The role the harness creates issues a 30-minute lease; this deployment
// declares a 20-minute longest transaction, so a pool would have to be
// retired 20 minutes into a 30-minute credential and would spend more of its
// life draining than serving. The resolution is refused, and the error names
// what was issued, what was configured and the floor — because the thing an
// operator has to change is the issuing role's TTL, and an error that only
// said "too short" would not say what to change it to.
func TestResolutionRefusesALeaseTooShortToDrainIn(t *testing.T) {
	e := newEndToEnd(t, 20*time.Minute)

	_, err := e.tenancy.Scope(context.Background(), e.tenant.ID)
	if !errors.Is(err, tenancy.ErrInvalidConfig) {
		t.Fatalf("Scope error = %v, want ErrInvalidConfig", err)
	}
	for _, want := range []string{"20m", "40m", "LongestTransaction"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not mention %q, so it does not say what to change:\n%v", want, err)
		}
	}
}

// ---------------------------------------------------------------------------
// The end-to-end fixture
// ---------------------------------------------------------------------------

// The fixture schema and table these tests scope against. They are this
// package's own so that nothing here depends on the conformance suite's.
const (
	fixtureSchema = "openbao_fixture"
	fixtureTable  = fixtureSchema + ".scoped"
	fixtureOwner  = "openbao_fixture_owner"
)

// endToEnd is a migrated database, a tenant-scoped table, and a *tenancy.Tenancy
// wired to issue every tenant pool's credential from OpenBao.
type endToEnd struct {
	admin   *pgxpool.Pool
	clock   *tenancy.FixedClock
	tenancy *tenancy.Tenancy
	tenant  tenancy.Tenant
}

func newEndToEnd(t *testing.T, longestTransaction time.Duration) *endToEnd {
	t.Helper()
	ctx := context.Background()

	db := testdb.Start(t)
	clock := tenancy.NewFixedClock(time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC))
	cfg := baoFor(t, db.DSN(), testdb.AppRole, clock)

	source, err := openbao.Open(ctx, cfg)
	if err != nil {
		t.Fatalf("openbao.Open: %v", err)
	}

	// Migrate first: it is what ensures the application role exists, and
	// the credential OpenBao issues is created IN ROLE that role, so a
	// credential issued before this would fail at CREATE ROLE.
	if err := tenancy.Migrate(ctx, tenancy.MigrateConfig{DSN: db.DSN(), AppRole: testdb.AppRole}); err != nil {
		t.Fatalf("tenancy.Migrate: %v", err)
	}

	admin, err := pgxpool.New(ctx, string(db.DSN()))
	if err != nil {
		t.Fatal("open the administrative pool")
	}
	t.Cleanup(admin.Close)

	// The fixture table, owned by a separate non-superuser role and FORCEd
	// through tenancy.EnableRLS, for the reason the conformance suite's own
	// fixture gives: a table owned by the role under test is not bound by
	// its own policy unless FORCE is set, and the resulting pass would mean
	// nothing.
	for _, stmt := range []string{
		"CREATE SCHEMA IF NOT EXISTS " + fixtureSchema,
		"DO $$ BEGIN BEGIN CREATE ROLE " + fixtureOwner +
			" NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOLOGIN NOBYPASSRLS;" +
			" EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END; END $$",
		"GRANT USAGE, CREATE ON SCHEMA " + fixtureSchema + " TO " + fixtureOwner,
		"GRANT USAGE ON SCHEMA " + fixtureSchema + " TO " + testdb.AppRole,
		"CREATE TABLE IF NOT EXISTS " + fixtureTable + " (id text PRIMARY KEY, tenant_id text NOT NULL)",
		"ALTER TABLE " + fixtureTable + " OWNER TO " + fixtureOwner,
		"GRANT SELECT, INSERT ON " + fixtureTable + " TO " + testdb.AppRole,
	} {
		if _, err := admin.Exec(ctx, stmt); err != nil {
			t.Fatalf("exec %q: %v", stmt, err)
		}
	}
	if err := tenancy.EnableRLS(ctx, admin, fixtureTable); err != nil {
		t.Fatalf("tenancy.EnableRLS(%s): %v", fixtureTable, err)
	}

	// AppRole is left empty on purpose; see
	// TestIssuedCredentialIsFailClosedUnderEnforcement for why that is the
	// stronger configuration rather than a missing setting.
	ten, err := tenancy.Open(ctx, tenancy.Config{
		RegistryDSN: db.DSN(),
		Clock:       clock,
		Credentials: source,
		Postgres:    tenancy.PoolConfig{MaxConns: 4, ApplicationName: "openbao-integration"},
		Cache: tenancy.CacheOptions{
			TTL:                time.Hour,
			NegativeTTL:        time.Hour,
			LongestTransaction: longestTransaction,
		},
	})
	if err != nil {
		t.Fatalf("tenancy.Open: %v", err)
	}
	t.Cleanup(func() { _ = ten.Close() })

	p, err := ten.Control().CreatePool(ctx, tenancy.NewPool{
		Name:           "pool-openbao",
		Region:         "test-region",
		MetadataDSN:    db.DSN(),
		BlobConfigRef:  "blob-pool-openbao",
		WorkerCapacity: 4,
	})
	if err != nil {
		t.Fatalf("CreatePool: %v", err)
	}
	tenant, err := ten.Control().CreateTenant(ctx, tenancy.NewTenant{
		PoolID:       p.ID,
		Name:         "tenant-openbao",
		SecurityMode: tenancy.SecurityModeManaged,
	})
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}

	return &endToEnd{admin: admin, clock: clock, tenancy: ten, tenant: tenant}
}

// sessionUser reads the role the handle's pool actually authenticated as,
// which is how a replacement pool is told from the one it replaced.
func (e *endToEnd) sessionUser(ctx context.Context, t *testing.T, scoped tenancy.Scoped) string {
	t.Helper()

	var user string
	err := scoped.Tx(ctx, func(ctx context.Context, tx tenancy.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT session_user").Scan(&user)
	})
	if err != nil {
		t.Fatalf("read session_user through the handle: %v", err)
	}
	return user
}

// awaitRoleGone polls pg_roles until role is gone, which is the only place
// the close-then-release chain is observable: the pool drains, closes, hands
// its credential back, and OpenBao's revocation drops the role.
//
// It polls in wall-clock time rather than on the injected clock, because what
// it is waiting for is a background goroutine and two network round trips
// rather than anything this module schedules.
func (e *endToEnd) awaitRoleGone(t *testing.T, role string) {
	t.Helper()

	ctx := context.Background()
	deadline := time.Now().Add(30 * time.Second)
	for {
		var exists bool
		if err := e.admin.QueryRow(ctx,
			"SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)", role).Scan(&exists); err != nil {
			t.Fatalf("read pg_roles: %v", err)
		}
		if !exists {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the credential %s still exists in pg_roles after its pool drained and closed. "+
				"A credential nothing is using any more should be handed back rather than waited out — "+
				"and one that cannot be revoked at all is the unrevocable-lease failure, which happens "+
				"when the credential owns an object", role)
		}
		time.Sleep(250 * time.Millisecond)
	}
}
