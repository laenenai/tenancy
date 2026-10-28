// Package tenancy answers who the tenants are, where their data lives,
// and hands back a pgx connection already scoped to exactly one of them —
// failing closed if it is not.
//
// # The asymmetry this module exists to handle
//
// There are two kinds of connection here, and conflating them is a
// cross-tenant disclosure:
//
//   - The **control plane** reads the registry. Resolving tenant → pool
//     happens *before* any tenant scope exists, so it necessarily runs
//     unscoped against the registry tables — it is what establishes that
//     scope for everything downstream, not a consumer of it. Those tables
//     therefore carry no row-level-security policy, which means there is
//     nothing behind them to catch a mistake. So this path must never be
//     reachable with caller-supplied predicates: Control has no Exec, no
//     Query, no QueryRow and no Begin. Every one of its methods takes
//     typed domain values and runs one of seven statements fixed at
//     generation time by sqlc.
//
//   - The **data plane** is scoped to one resolved tenant. Scoped is the
//     only type in this module that accepts arbitrary SQL, and every
//     statement it runs is inside a transaction whose tenant session
//     context is already set. A caller cannot forget the predicate,
//     because a caller never sets it.
//
// Neither type can stand where the other is expected: they are distinct
// structs with unexported fields, so no conversion exists in either
// direction and no package outside this module can construct either one.
// Running a data-plane query on a control-plane handle is not an
// expressible program, and that is checked by a test which hands the
// compiler the attempt and requires it to be rejected —
// testdata/control_plane_is_not_a_data_plane_handle.go.
//
// # The central claim: RLS is a fail-closed backstop
//
// Application-level scoping is the primary mechanism. Postgres row-level
// security is the backstop behind it, so that a query which forgets its
// tenant predicate returns nothing instead of another tenant's data. That
// is a cross-tenant disclosure control, which is why it is one
// implementation here rather than three in three systems.
//
// It is also unprovable without a real Postgres, and worse: it is
// trivially *vacuously* provable. A superuser bypasses row security
// unconditionally, regardless of FORCE ROW LEVEL SECURITY. A table's owner
// bypasses it unless FORCE is set. A role with BYPASSRLS bypasses it by
// name. In any of those configurations a test asserting "the other
// tenant's rows are not visible" passes against a database with no
// policies at all, because nothing was ever filtered — there was simply
// nothing to see from the other side.
//
// Two things in this module exist for that reason:
//
//   - AppRole, and Scoped's SET LOCAL ROLE. Every data-plane transaction
//     narrows itself into the application role before it runs anything,
//     which drops a superuser connection's bypass for exactly that
//     transaction. It is production code rather than test scaffolding, so
//     the conformance suite exercises the real path.
//   - Scoped.CheckEnforcement. It reads the live catalog, as the role
//     statements actually run as, and reports whether a cross-tenant
//     statement would in fact be refused: role attributes, enabled,
//     FORCEd, policy present, ownership, and whether any tenant context
//     has leaked onto a pooled connection. A deployment calls it at
//     startup and refuses to serve if FailClosed is false. The conformance
//     suite calls it to establish that its own assertions are being made
//     under enforcement, before it makes them.
//
// # Who the connection authenticates as, and for how long
//
// Both of the pools above connect on a credential this module is handed:
// the connection string in a pool's registry row, or — opt-in, and never
// required — one issued per pool by Config.Credentials. The default is the
// first, unchanged.
//
// The second is not a configuration flag with a different string in it. A
// credential that expires cannot be swapped underneath a live pool, because
// expiry is a privilege removal rather than a disconnection: nothing closes,
// the pool reports itself healthy, and the failure surfaces inside a
// caller's transaction as a mid-statement refusal followed by a COMMIT that
// silently becomes a ROLLBACK. So an expiring credential makes a pool's
// lifetime the module's problem — each pool is retired a configured lead
// time before its credential expires, stops being handed to new callers,
// drains the transactions already running on it, and is replaced on a fresh
// credential. That lead time is the longest transaction a deployment serves,
// it is required rather than defaulted, and a credential too short-lived for
// it is refused with both numbers named. See Config.LongestTransaction
// and credentials/openbao, whose package doc carries the measurements.
//
// # The two-pool model
//
// Migration rights and runtime rights are different credentials, not two
// states of one session. Migrate opens a short-lived pool from its own
// DSN, applies the registry schema, and closes it before returning — the
// handle never escapes. Open connects on the runtime credential, which
// does not possess the mutating rights at all.
//
// `SET ROLE` is explicitly not the mechanism for that split, because
// `RESET ROLE` reverses it: one owner connection narrowing itself makes
// privilege separation per-session and dependent-on-remembering, and
// forgetting to narrow it is a silent escalation. Note that this is the
// opposite conclusion from the RLS role switch above, and the difference
// is direction — narrowing within a transaction is defence in depth on top
// of a credential boundary; widening within a session would *be* the
// boundary, and a reversible one is not a boundary.
//
// # Where the contract is written down
//
// The conformance suite in tenancytest, not this doc comment and not any
// interface here, is the authoritative description of the edge-case
// behaviour: that resolution is correct and cached, that a cache entry
// does not outlive a pool retirement, that a handle borrowed after close
// is refused, that session context is reset on handle reuse, that a
// partial borrow during retirement is accounted for, and the four RLS
// claims. A consumer counts as having adopted this module when that suite
// runs green in its CI against its own wiring.
//
// This file carries the module's aliases, sentinel errors, exported
// constants and entry points — and no logic. Every function here is a
// one-line forward to an internal package; the reason they are here at all
// is that Go's internal rule makes anything not re-exported here
// unreachable from outside the module, and a facade that hides what the
// module is for is not a facade.
package tenancy

import (
	"context"
	"time"

	"github.com/laenenai/tenancy/internal/domain"
	"github.com/laenenai/tenancy/internal/migrate"
	"github.com/laenenai/tenancy/internal/pg"
	"github.com/laenenai/tenancy/internal/pool"
	"github.com/laenenai/tenancy/internal/registry"
	"github.com/laenenai/tenancy/internal/scope"
)

// The module's one object, and what it is built from.
type (
	// Tenancy is the control plane, the resolver, and the conversion from
	// a resolved tenant to a data-plane handle. See scope.Tenancy.
	Tenancy = scope.Tenancy
	// Stats is the resolver snapshot returned by Tenancy.Stats.
	Stats = pool.Stats
	// Config is everything a deployment supplies to Open. See
	// scope.Config, and read AppRole's comment before leaving it empty.
	Config = scope.Config
	// PoolConfig tunes every connection pool this module opens, and
	// carries the tracing and after-connect seams. See pg.PoolConfig.
	PoolConfig = pg.PoolConfig
	// CacheOptions configures tenant→pool resolution caching. See
	// pool.Options: a zero MaxPools and a zero MaxTenants mean different
	// things, on purpose.
	CacheOptions = pool.Options
	// Opener replaces how a pool's connection pool is opened. See
	// pool.Opener and Config.Opener.
	Opener = pool.Opener
)

// Credentials: what a pool's connections authenticate as, which is a port
// with two shipping answers.
type (
	// Credentials issues the credential each tenant pool's connections
	// authenticate with. See domain.Credentials — in particular, why it
	// reports an expiry rather than offering a renew, which is the whole
	// shape of this feature.
	Credentials = domain.Credentials
	// Credential is one issued database login: who to connect as, the
	// secret to connect with, and when it stops working. It holds material
	// and redacts itself in every rendering. See domain.Credential.
	Credential = domain.Credential
	// StaticDSNCredentials is the default: every pool connects on the
	// credential its registry row's MetadataDSN already carries, and no
	// pool is ever retired for credential age. See
	// domain.StaticDSNCredentials, which also states plainly what a
	// deployment gives up by staying here.
	StaticDSNCredentials = domain.StaticDSNCredentials
)

// The control plane: the registry, reachable with no SQL of a caller's own.
type (
	// Control is the control-plane handle. See registry.Control for why it
	// exposes no method that takes SQL.
	Control = registry.Control
	// PoolSpec is the input to Control.CreatePool. See registry.PoolSpec.
	PoolSpec = registry.PoolSpec
	// TenantSpec is the input to Control.CreateTenant. See
	// registry.TenantSpec.
	TenantSpec = registry.TenantSpec
)

// The data plane: one tenant, with its session context already set.
type (
	// Scoped is the data-plane handle, and the only type here that accepts
	// arbitrary SQL. See pg.Scoped.
	Scoped = pg.Scoped
	// TenantTx is a transaction that already carries one tenant's session
	// context. Its three statement methods are exactly sqlc's generated
	// DBTX interface for pgx/v5, so a consumer hands one straight to its
	// own generated Queries constructor. See pg.TenantTx.
	TenantTx = pg.TenantTx
	// DDL is the narrow handle EnableRLS and AssertRLSCoverage apply their
	// statements through, which a *pgxpool.Pool, a *pgx.Conn and a pgx.Tx
	// all satisfy unwrapped — so a consumer can call either from inside
	// its own migration reconciler. See pg.DDL.
	DDL = pg.DDL
	// Enforcement is what Postgres will actually do to a tenant-scoped
	// statement, read from the live catalog. See pg.Enforcement.
	Enforcement = pg.Enforcement
	// TableEnforcement is one table's row-security state. See
	// pg.TableEnforcement.
	TableEnforcement = pg.TableEnforcement
)

// The registry's domain: tenants, pools, and the closed enums they carry.
type (
	// TenantID identifies a tenant: the top-level unit of isolation.
	TenantID = domain.TenantID
	// DSN is a Postgres connection string. It is a distinct type because a
	// DSN carries a password and is simultaneously the most tempting thing
	// in this module to print: it redacts itself through fmt.Stringer,
	// fmt.Formatter, json.Marshaler, encoding.TextMarshaler and
	// slog.LogValuer, so reading the actual string requires writing
	// string(dsn) — a deliberate, greppable act rather than the accidental
	// default. See CONVENTIONS.md's "Rendering a secret".
	DSN = domain.DSN

	// PoolID identifies a pool: one physical Postgres database hosting the
	// metadata of one or more tenants.
	PoolID = domain.PoolID
	// Tenant is a registry row: which pool hosts this tenant, and its
	// immutable security mode and lifecycle status.
	Tenant = domain.Tenant
	// Pool is a registry row: where a cohort of tenants' metadata lives,
	// in which region, with what capacity. It carries MetadataDSN and is
	// only returned on the control plane.
	Pool = domain.Pool
	// PoolRef is the credential-free part of a pool row: identity,
	// placement and capacity. It is what a data-plane handle and a
	// Credentials implementation may see.
	PoolRef = domain.PoolRef
	// SecurityMode names how a tenant's content is encrypted at rest. It
	// is immutable after the tenant's first write, enforced by the schema.
	SecurityMode = domain.SecurityMode
	// TenantStatus names a tenant's lifecycle state, which resolution maps
	// to three different outcomes.
	TenantStatus = domain.TenantStatus
)

// Time, as a convention rather than a dependency: these are declared here
// so a consumer can satisfy Config.Clock without importing anything.
type (
	// Clock abstracts "now". Any identically shaped interface satisfies
	// it, at zero coupling.
	Clock = domain.Clock
	// SystemClock is the production Clock.
	SystemClock = domain.SystemClock
	// FixedClock is a test Clock that returns a fixed instant until
	// advanced.
	FixedClock = domain.FixedClock
)

// Migrations: this module's own registry tables, and nothing else.
type (
	// MigrateConfig is what Migrate needs: the migration credential, and
	// the application role whose registry grants are asserted on every
	// run. See migrate.Config.
	MigrateConfig = migrate.Config
	// Applied describes one migration's state as the version table knows
	// it.
	Applied = migrate.Applied
)

// The error taxonomy. Every function in this module returns one of these
// across its boundary, and a caller branches on them with errors.Is.
var (
	// ErrInvalidConfig means this module was wired up wrongly and retrying
	// will not help.
	ErrInvalidConfig = domain.ErrInvalidConfig
	// ErrNotAuthorizedOrNotFound covers a tenant or pool that does not
	// exist, is malformed, or is being deleted. The cases are deliberately
	// one error: a caller able to tell them apart has an existence oracle
	// on the tenant id space.
	ErrNotAuthorizedOrNotFound = domain.ErrNotAuthorizedOrNotFound
	// ErrUnavailable means not reachable right now: Postgres refused, the
	// resolver is closed, or the tenant is suspended. A retry is worth
	// making, in two of those cases after an operator acts.
	ErrUnavailable = domain.ErrUnavailable
	// ErrPermission means the deployment's role lacks a privilege the
	// operation requires. Retrying will not help; change the role or its
	// grants.
	ErrPermission = domain.ErrPermission
	// ErrConflict means a registry write conflicts with existing state: a
	// duplicate name, a pool that does not exist, or a refused change to
	// an immutable column.
	ErrConflict = domain.ErrConflict
	// ErrNoTenantScope means a data-plane operation was attempted through
	// a handle no resolution produced — the zero Scoped. It is the
	// charter's "a missing predicate denies rather than leaking", applied
	// to the one data-plane shape Go cannot forbid.
	ErrNoTenantScope = domain.ErrNoTenantScope
	// ErrMalformedID means an id is not a well-formed ULID. It is returned
	// at a write boundary only: on any lookup-by-id path a malformed id
	// surfaces as ErrNotAuthorizedOrNotFound instead, for the reason given
	// there.
	ErrMalformedID = domain.ErrMalformedID
)

// RegistryTablesExemptFromRLS returns a copy of the registry tables that
// deliberately carry no policy, each with the reason, and AssertRLSCoverage
// honours it. See pg.RegistryTablesExemptFromRLS for why the exemption is
// named rather than implied.
func RegistryTablesExemptFromRLS() map[string]string { return pg.RegistryTablesExemptFromRLS() }

// The row-level-security convention, as constants, because a consumer's
// own migrations and its own catalog assertions have to name them.
const (
	// Schema is the Postgres schema this module owns.
	Schema = migrate.Schema
	// Redacted is the fixed placeholder every secret-holding type renders.
	Redacted = domain.Redacted
	// MigrationIdentity is the module identity the advisory lock key
	// derives from. It is exported because it is operational surface, and
	// it is pinned by a test because it contains a module path.
	MigrationIdentity = migrate.Identity
	// TenantGUC is the session variable every policy keys off.
	TenantGUC = pg.TenantGUC
	// TenantPolicyName is the fixed name EnableRLS gives the restrictive
	// tenant policy.
	TenantPolicyName = pg.TenantPolicyName
	// TenantAccessPolicyName is the permissive companion EnableRLS creates.
	TenantAccessPolicyName = pg.TenantAccessPolicyName
	// TenantPredicate is the single source of truth for the policy
	// expression, used as both USING and WITH CHECK. Read its doc comment
	// before copying it: the absence of a cast is load-bearing.
	TenantPredicate = pg.TenantPredicate
	// RLSViolationCode is the SQLSTATE Postgres raises when a policy's
	// WITH CHECK refuses a write: 42501. Assert on it rather than on "an
	// error happened", so a test cannot pass because a CHECK constraint or
	// a trigger refused instead.
	RLSViolationCode = pg.RLSViolationCode
	// DefaultMaxTenants is the bound CacheOptions.MaxTenants takes when it
	// is zero or negative. It is deliberately not "unbounded".
	DefaultMaxTenants = pool.DefaultMaxTenants
	// DefaultMaxPools is the bound CacheOptions.MaxPools takes when it is
	// zero. A negative value explicitly means unbounded.
	DefaultMaxPools = pool.DefaultMaxPools
)

// The security modes. Immutable after a tenant's first write.
const (
	SecurityModeManaged   = domain.SecurityModeManaged
	SecurityModeTenantKey = domain.SecurityModeTenantKey
	SecurityModeVault     = domain.SecurityModeVault
)

// The tenant lifecycle states. Resolution maps each to a different
// outcome; see domain.TenantStatus.
const (
	TenantStatusActive    = domain.TenantStatusActive
	TenantStatusSuspended = domain.TenantStatusSuspended
	TenantStatusDeleting  = domain.TenantStatusDeleting
)

// Open connects the control plane and builds the resolver. See
// scope.Open — in particular, that it deliberately does not migrate.
func Open(ctx context.Context, cfg Config) (*Tenancy, error) {
	return scope.Open(ctx, cfg)
}

// Migrate applies this module's registry schema and asserts its
// declarative state, on a short-lived migration pool whose handle never
// escapes. See migrate.Up.
func Migrate(ctx context.Context, cfg MigrateConfig) error {
	return migrate.Up(ctx, cfg)
}

// MigrationStatus reports the state of every registry migration. See
// migrate.Status.
func MigrationStatus(ctx context.Context, cfg MigrateConfig) ([]Applied, error) {
	return migrate.Status(ctx, cfg)
}

// MigrationLockKey returns the advisory lock key this module migrates
// under — what an operator sees in pg_locks during a deployment. See
// migrate.LockKey.
func MigrationLockKey() int64 { return migrate.LockKey() }

// EnableRLS enables and FORCEs row-level security on each table and
// creates the one tenant-isolation policy on it. It is idempotent, so a
// consumer calls it from a migration reconciler that runs on every start.
// See pg.EnableRLS.
func EnableRLS(ctx context.Context, db DDL, tables ...string) error {
	return pg.EnableRLS(ctx, db, tables...)
}

// AssertRLSCoverage reports every table in schema carrying a tenant_id
// column but no policy. An empty slice is the passing answer; wire it into
// CI as a test. See pg.AssertRLSCoverage.
func AssertRLSCoverage(ctx context.Context, db DDL, schema string) ([]string, error) {
	return pg.AssertRLSCoverage(ctx, db, schema)
}

// NewOpener returns the Opener this module uses when Config.Opener is
// empty: it hands a pool row's MetadataDSN and the credential issued for it
// to the one function audited never to let either reach an error.
//
// It is exported for two callers. A consumer wrapping the default — to count
// pools, to add a dial-time hook — needs the default to wrap. And the
// conformance suite opens a connection as an issued credential, which has to
// go through the production path or it would be asserting things about its
// own five lines of pgx setup instead. See pool.NewOpener.
func NewOpener(cfg PoolConfig) Opener { return pool.NewOpener(cfg) }

// IsInsufficientPrivilege reports whether err is Postgres refusing a
// statement for lack of privilege. SQLSTATE 42501 covers both a missing
// grant and an RLS policy refusal. See pg.IsInsufficientPrivilege.
func IsInsufficientPrivilege(err error) bool { return pg.IsInsufficientPrivilege(err) }

// IsRLSPolicyViolation reports whether err is specifically an RLS policy
// refusal, not a missing grant or another 42501. See pg.IsRLSPolicyViolation.
func IsRLSPolicyViolation(err error) bool { return pg.IsRLSPolicyViolation(err) }

// NewTenantID returns a fresh TenantID minted from clock. It panics only if
// the process cannot read crypto/rand; NewTenantIDErr is the error-returning
// form for a boundary that can report the failure.
func NewTenantID(clock Clock) TenantID { return domain.NewTenantID(clock) }

// NewTenantIDErr is the error-returning form of NewTenantID.
func NewTenantIDErr(clock Clock) (TenantID, error) { return domain.NewTenantIDErr(clock) }

// ParseTenantID parses s as a TenantID, rejecting malformed input with
// ErrMalformedID. See that sentinel for when it may be surfaced.
func ParseTenantID(s string) (TenantID, error) { return domain.ParseTenantID(s) }

// NewPoolID returns a fresh PoolID minted from clock. It panics only if the
// process cannot read crypto/rand; NewPoolIDErr is the error-returning form
// for a boundary that can report the failure.
func NewPoolID(clock Clock) PoolID { return domain.NewPoolID(clock) }

// NewPoolIDErr is the error-returning form of NewPoolID.
func NewPoolIDErr(clock Clock) (PoolID, error) { return domain.NewPoolIDErr(clock) }

// ParsePoolID parses s as a PoolID, rejecting malformed input.
func ParsePoolID(s string) (PoolID, error) { return domain.ParsePoolID(s) }

// NewFixedClock returns a FixedClock starting at t.
func NewFixedClock(t time.Time) *FixedClock { return domain.NewFixedClock(t) }

// CanonicalTime truncates t to UTC microseconds, which is the precision
// Postgres timestamptz holds. Anything that enters an equality comparison
// goes through it first. See domain.CanonicalTime.
func CanonicalTime(t time.Time) time.Time { return domain.CanonicalTime(t) }
