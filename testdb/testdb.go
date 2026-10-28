// Package testdb is the shared container harness for every
// database-backed test in this set of modules: Start gives a test its own
// uniquely named, isolated Postgres database, migrated fresh, so tests run
// in parallel with no shared state and nothing to truncate between them.
//
// # Why it lives here, and why it is exported
//
// `cas` and `audit` each grew their own copy of this pattern, identically,
// and CONVENTIONS.md settles that the shared one belongs in `tenancy`:
// tenant scoping and row-level security are what the harness exists to
// test, and a second consumer now needs it. So this is a public package
// rather than an internal one, and its API is public surface listed in
// api.txt — a change here breaks other modules' test suites.
//
// `cas/internal/testdb` and `audit/internal/testdb` keep their copies
// until the post-alpha swap. That is the agreed staged migration, not
// divergence, and this package is deliberately shaped to make the swap
// mechanical: Start's signature is the whole of the contract.
//
// # What it settles, each for a reason found in practice
//
//   - The image is pgvector/pgvector:pg18, not stock postgres:18. Vector
//     columns exist in this system and the stock image lacks the
//     extension, so a harness built on it passes locally and fails where
//     it matters. This module has no vector columns of its own; matching
//     the image is about every module's tests running on the same Postgres
//     as the deployment.
//   - Each test gets its own database, created and migrated fresh. Not one
//     shared database with truncation between tests: there is nothing
//     shared to reset, which is what lets tests use t.Parallel freely.
//   - TEST_DATABASE_URL, when set, is used instead of starting a
//     container — and a unique database is still created on it rather than
//     reusing a shared one.
//   - Start skips under testing.Short(). This is the single chokepoint for
//     that convention, so every database test inherits it without its
//     author remembering a gate, and -short wins even when
//     TEST_DATABASE_URL is set: "no databases in the inner loop" is the
//     rule, and a reachable server is not an exception to it. The skip
//     happens before any container or database work, so a skipped test
//     pays no setup cost.
//
// # The harness connects as a superuser, and that is the whole problem
//
// A container's default role is a superuser, and a superuser bypasses row
// security unconditionally — FORCE ROW LEVEL SECURITY does not change
// that. So a row-level-security test that runs its statements on
// DB.Pool() directly passes while proving absolutely nothing: nothing was
// filtered, because nothing was ever enforced.
//
// This package does not hide that; it makes it usable. DB.Pool's doc
// comment states it, AppRole names the non-superuser role tests must
// narrow into, and the conformance suite in tenancytest asserts the
// superuser bypass is real before it relies on the role switch being the
// operative difference. If that assertion ever starts failing, the
// harness's connecting role has changed and every RLS test in every
// consumer needs re-examining.
package testdb

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/laenenai/tenancy/internal/domain"
)

// PostgresImage is the container image Start uses when TEST_DATABASE_URL
// is not set. See the package doc comment for why it is not stock
// postgres.
const PostgresImage = "pgvector/pgvector:pg18"

// AppRole is the application role name this harness's default migrator
// creates and grants the registry to, and the role a test narrows into
// with SET LOCAL ROLE before asserting anything about privileges or row
// security.
//
// It is a fixed, test-only name rather than a per-test one because roles
// are cluster-wide while one container serves the whole run: a role per
// test would leave hundreds behind on a long-lived TEST_DATABASE_URL
// server, and there is nothing a test can learn from a unique role name
// that it cannot learn from a unique database.
const AppRole = "tenancy_app_test"

// adminConnectTimeout bounds every administrative connection Start makes:
// to create or drop a database, and to open the per-test pool.
const adminConnectTimeout = 10 * time.Second

// Migrator applies a schema to the database at dsn. Start calls it exactly
// once, against a freshly created, empty database, before handing the
// handle back.
//
// It takes a DSN rather than a pool because that is what the two-pool
// model needs: a migrator holds the migration credential and opens and
// closes its own short-lived pool, and handing it a long-lived one would
// defeat the point. `cas` and `audit`'s harnesses both passed a pool,
// which is the one place this harness deliberately differs from the copies
// it replaces.
type Migrator func(ctx context.Context, dsn domain.DSN) error

// NoMigrations is a Migrator that leaves the database untouched. It is how
// a test gets a database that exists but is not yet migrated, which is the
// only way to test migrating.
func NoMigrations(context.Context, domain.DSN) error { return nil }

// Option configures Start.
type Option func(*options)

type options struct {
	migrator Migrator
}

// WithMigrator overrides the Migrator Start runs against the freshly
// created database.
func WithMigrator(m Migrator) Option {
	return func(o *options) { o.migrator = m }
}

// DB is an isolated database created for a single test by Start.
type DB struct {
	pool *pgxpool.Pool
	dsn  domain.DSN
	name string
}

// Pool returns a connection pool opened against this test's database.
//
// It connects as the container's superuser (or as whatever role
// TEST_DATABASE_URL names, which is also normally a superuser). That
// matters and is the reason every row-level-security assertion in this set
// of modules explicitly narrows into AppRole first: a superuser bypasses
// privilege checks and row security unconditionally, so a test that did
// not switch roles would be proving nothing while appearing to pass.
//
// Use it for DDL, for fixtures, and for the deliberate control assertions
// that establish the bypass is real. Do not use it for the assertion
// itself.
func (d *DB) Pool() *pgxpool.Pool { return d.pool }

// DSN returns this test database's connection string, as the superuser.
//
// It is what a test passes to tenancy.Migrate as the migration
// credential, and what it registers as a pool's metadata DSN.
func (d *DB) DSN() domain.DSN { return d.dsn }

// Name returns this test database's name.
func (d *DB) Name() string { return d.name }

// String names this test database and redacts its connection string.
//
// A *DB holds its DSN in an unexported field, which is the shape fmt renders
// most dangerously: a value reached through an unexported field fails
// reflect.Value.CanInterface, so fmt abandons the method path for the whole
// subtree and prints it by raw reflection — the DSN type's own redaction
// included. Before these four methods, %+v on a *DB printed the container's
// superuser credential. See CONVENTIONS.md's "Rendering a secret".
func (d *DB) String() string {
	return fmt.Sprintf("testdb.DB{name: %q, dsn: %s}", d.name, domain.Redacted)
}

// Format implements fmt.Formatter, the only interface fmt consults for every
// verb.
func (d *DB) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, d.String()) }

// MarshalJSON renders the redacted summary.
func (d *DB) MarshalJSON() ([]byte, error) { return json.Marshal(d.String()) }

// LogValue renders the database as a slog group with the DSN redacted.
func (d *DB) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("name", d.name),
		slog.String("dsn", domain.Redacted),
	)
}

var (
	containerOnce sync.Once
	containerDSN  string
	containerErr  error
)

// Start creates a uniquely named Postgres database, runs the configured
// Migrator against it, and registers a t.Cleanup that closes the pool and
// drops the database.
//
// Each call gets its own database, so tests using Start may run in
// parallel without interfering. The default Migrator is NoMigrations: this
// package is shared, and a default that applied `tenancy`'s own schema
// would be a default no other consumer wants. A consumer passes
// WithMigrator with its own.
//
// It skips the test under testing.Short(). See the package doc comment.
func Start(t *testing.T, opts ...Option) *DB {
	t.Helper()

	if testing.Short() {
		t.Skip("testdb: skipping database-backed test in -short mode; run `mise run test-all` for the full suite")
	}

	cfg := options{migrator: NoMigrations}
	for _, opt := range opts {
		opt(&cfg)
	}

	ctx := context.Background()
	serverDSN := adminDSN(ctx, t)
	dbName := newDatabaseName()

	adminConn, err := pgx.Connect(ctx, serverDSN)
	if err != nil {
		t.Fatalf("testdb: connect to the admin database: %v", err)
	}
	defer func() { _ = adminConn.Close(ctx) }()

	if _, err := adminConn.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{dbName}.Sanitize()); err != nil {
		t.Fatalf("testdb: create database %s: %v", dbName, err)
	}

	// The drop is registered now, immediately after the database exists,
	// rather than after the pool and migrator steps below: both of those
	// can fail via t.Fatalf, which never returns (it calls
	// runtime.Goexit), so a Cleanup registered after them would simply
	// never run on that path — orphaning the database permanently, which
	// is especially damaging against a long-lived TEST_DATABASE_URL server
	// where nothing else ever drops it.
	//
	// The closure closes over the variable rather than a snapshot, so by
	// the time it runs it sees whatever pool holds: nil if the open never
	// got that far, open if it did. It closes it first so the drop does
	// not find the database still in use.
	var pool *pgxpool.Pool
	t.Cleanup(func() {
		if pool != nil {
			closePoolBounded(t, pool)
		}
		dropDatabase(t, serverDSN, dbName)
	})

	rawTestDSN, err := withDatabaseName(serverDSN, dbName)
	if err != nil {
		t.Fatalf("testdb: build a dsn for database %s: %v", dbName, err)
	}

	if err := cfg.migrator(ctx, domain.DSN(rawTestDSN)); err != nil {
		t.Fatalf("testdb: run the migrator against database %s: %v", dbName, err)
	}

	pool, err = openPool(ctx, domain.DSN(rawTestDSN))
	if err != nil {
		t.Fatalf("testdb: open a pool for database %s: %v", dbName, err)
	}

	return &DB{pool: pool, dsn: domain.DSN(rawTestDSN), name: dbName}
}

// openPool opens a pool against dsn and verifies it with one ping, so a
// failure to connect is reported where it happened rather than inside the
// first test assertion.
func openPool(ctx context.Context, dsn domain.DSN) (*pgxpool.Pool, error) {
	poolCfg, err := pgxpool.ParseConfig(string(dsn))
	if err != nil {
		// The DSN is not forwarded: pgx's parse error can carry an
		// embedded credential verbatim. It is the harness's own DSN here,
		// but the rule is uniform.
		return nil, fmt.Errorf("parse dsn")
	}
	poolCfg.ConnConfig.ConnectTimeout = adminConnectTimeout

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("build pool: %w", err)
	}

	pingCtx, cancel := context.WithTimeout(ctx, adminConnectTimeout)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping: %w", err)
	}
	return pool, nil
}

// dropDatabase connects to serverDSN and drops name, forcibly
// disconnecting any session still attached — Start's pool was just closed,
// but pgxpool's close does not guarantee every socket is already torn down
// server-side. It logs rather than fails: best-effort cleanup is
// preferable to masking the test's real result.
// poolCloseTimeout bounds the wait for a pool to close during cleanup. It is
// generous because a healthy close is immediate, so anything approaching this
// is a leak rather than slowness.
const poolCloseTimeout = 10 * time.Second

// closePoolBounded closes the pool but refuses to wait forever for it.
//
// pgxpool.Pool.Close blocks until every connection is returned, so a subtest
// that fails while holding a transaction — t.Fatalf calls runtime.Goexit, which
// runs deferred functions but cannot roll back a transaction nobody deferred —
// leaves a connection checked out and this cleanup waiting on it. The symptom
// is not a failing test but the whole package timing out, with the real
// assertion failure scrolled off above it. That happened: a one-line assertion
// error in a consumer presented as a ten-minute hang.
//
// Waiting is bounded instead, and exceeding the bound is reported rather than
// swallowed, because a leaked connection is a defect in the test that leaked it
// and the author should see it named. Dropping the database afterwards is safe
// regardless: dropDatabase uses WITH (FORCE), which terminates whatever is
// still attached.
func closePoolBounded(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()

	closed := make(chan struct{})
	go func() {
		pool.Close()
		close(closed)
	}()

	select {
	case <-closed:
	case <-time.After(poolCloseTimeout):
		t.Logf("testdb: cleanup: the pool did not close within %s, so a connection is still "+
			"checked out — most likely a transaction left open by a subtest that failed while "+
			"holding one. Dropping the database with FORCE anyway.", poolCloseTimeout)
	}
}

func dropDatabase(t *testing.T, serverDSN, name string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), adminConnectTimeout)
	defer cancel()

	conn, err := pgx.Connect(ctx, serverDSN)
	if err != nil {
		t.Logf("testdb: cleanup: connect to drop database %s: %v", name, err)
		return
	}
	defer func() { _ = conn.Close(ctx) }()

	if _, err := conn.Exec(ctx, "DROP DATABASE IF EXISTS "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)"); err != nil {
		t.Logf("testdb: cleanup: drop database %s: %v", name, err)
	}
}

// adminDSN returns the DSN of a Postgres server to create test databases
// on: TEST_DATABASE_URL when set, otherwise a container started once per
// test binary run through testcontainers-go.
func adminDSN(ctx context.Context, t *testing.T) string {
	t.Helper()

	if dsn := os.Getenv("TEST_DATABASE_URL"); dsn != "" {
		return dsn
	}

	containerOnce.Do(func() {
		containerDSN, containerErr = startContainer(ctx)
	})
	if containerErr != nil {
		t.Fatalf("testdb: start a postgres container: %v", containerErr)
	}
	return containerDSN
}

func startContainer(ctx context.Context) (string, error) {
	const (
		user     = "postgres"
		password = "postgres"
		database = "postgres"
	)

	container, err := tcpostgres.Run(ctx, PostgresImage,
		tcpostgres.WithDatabase(database),
		tcpostgres.WithUsername(user),
		tcpostgres.WithPassword(password),
		tcpostgres.BasicWaitStrategies(),
	)
	if err != nil {
		return "", fmt.Errorf("run postgres container: %w", err)
	}

	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		return "", fmt.Errorf("container connection string: %w", err)
	}
	return dsn, nil
}

// newDatabaseName returns a database name unique enough to run in parallel
// across the whole test binary: a ULID carries a millisecond timestamp
// plus 80 bits of randomness, lowercased because Postgres folds unquoted
// identifiers to lowercase and this harness has no reason to fight that.
func newDatabaseName() string {
	return "tenancytestdb_" + strings.ToLower(string(domain.NewPoolID(domain.SystemClock{})))
}

// withDatabaseName returns dsn with its path replaced by name, so the
// returned DSN points at the newly created per-test database on the same
// server dsn names.
func withDatabaseName(dsn, name string) (string, error) {
	u, err := url.Parse(dsn)
	if err != nil {
		return "", fmt.Errorf("parse dsn")
	}
	u.Path = "/" + name
	return u.String(), nil
}
