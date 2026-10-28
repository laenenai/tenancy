// Package scope is the composition: it holds the control plane and the
// resolver, and it is where a resolved tenant becomes a data-plane handle.
//
// It exists as its own package for one reason. The two planes must be
// separate types that cannot stand in for each other, which means neither
// can own the other, and something has to hold both — the facade cannot,
// because CONVENTIONS.md forbids logic there. This package is that
// something, and it is deliberately thin: thirty lines of wiring and one
// conversion.
//
// The conversion is the interesting line. pool.Resolve returns a
// pool.Handle, which carries a raw *pgxpool.Pool because the resolver's
// whole job is lifecycle accounting on those pools. Scope turns it into a
// pg.Scoped, which carries no pool and offers no unscoped statement path.
// Go's internal rule keeps pool.Handle unreachable from outside this
// module, so that raw pool exists only between the resolver and this
// function — which is how the resolver gets to keep the exact shape its
// regression tests were written against while a consumer never sees a
// handle it could forget to scope.
package scope

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/laenenai/pgmigrate"

	"github.com/laenenai/tenancy/internal/domain"
	"github.com/laenenai/tenancy/internal/pg"
	"github.com/laenenai/tenancy/internal/pool"
	"github.com/laenenai/tenancy/internal/registry"
)

// Config is everything a deployment supplies to Open.
type Config struct {
	// RegistryDSN is the control plane's connection to the registry
	// database, on the *runtime* credential. It must not be the migration
	// credential: see internal/migrate's package doc comment for why the
	// two are different credentials rather than two states of one session.
	//
	// Required.
	RegistryDSN domain.DSN

	// AppRole, when set, is the role every data-plane transaction narrows
	// itself to with SET LOCAL ROLE before running any statement.
	//
	// Set it. It is optional only because a deployment whose runtime
	// credential is already a non-superuser, non-owning role has nothing
	// left to narrow — and that deployment is the goal, not this field. In
	// every other case, including every deployment whose connection is a
	// superuser, leaving it empty means row-level security enforces
	// nothing at all: a superuser bypasses row security unconditionally,
	// FORCE or not. Scoped.CheckEnforcement reports exactly that, and a
	// deployment should refuse to serve if it says so.
	//
	// SET LOCAL ROLE is the right mechanism here and the wrong one for the
	// migration/runtime split, and the difference is direction. Narrowing
	// a session for one transaction is defence in depth on top of a
	// credential boundary. Widening one would be the credential boundary,
	// and RESET ROLE makes that reversible — which is why migration rights
	// live on a separate credential instead.
	AppRole string

	// Postgres tunes every connection pool this module opens: the control
	// plane's, and each pool the resolver opens for a tenant's metadata
	// database. One setting for both is deliberate — a deployment that
	// genuinely needs different limits per pool is describing a per-pool
	// configuration the registry does not carry, and should say so by
	// supplying an Opener.
	Postgres pg.PoolConfig

	// Cache configures tenant→pool resolution caching. Read
	// pool.Options's doc comment before setting MaxPools and MaxTenants.
	Cache pool.Options

	// LongestTransaction is the longest a single transaction on a tenant
	// pool may run. It is required whenever Credentials issues expiring
	// credentials, because a pool on such a credential is retired this long
	// before expiry so its outstanding transactions can drain.
	LongestTransaction time.Duration

	// Clock reads "now" for minted ids, canonicalized timestamps, cache
	// expiry and retirement. Zero means domain.SystemClock.
	Clock domain.Clock

	// OnCredentialReleaseError, when non-nil, is called after a best-effort
	// credential release fails. It may be called concurrently during Close;
	// the hook must be safe for concurrent use. The resolver has no logger of
	// its own; wire this to your logger or metric.
	OnCredentialReleaseError func(domain.PoolRef, error)

	// Opener, when non-nil, replaces how a pool's connection pool is
	// opened. Zero means the production opener, which hands the pool row's
	// MetadataDSN and the issued credential straight to pg.OpenAs.
	//
	// It is the seam a consumer that manages its own connections uses, and
	// the seam this module's own tests use to assert pool lifecycle
	// without a database. A consumer supplying one takes on the
	// obligations pool.NewOpener's doc comment describes — in particular,
	// that the DSN's text must never reach a returned error, and that the
	// credential it is handed is the one it must connect with.
	Opener pool.Opener

	// Credentials, when non-nil, issues the credential each tenant pool's
	// connections authenticate with, instead of connecting on the
	// credential that pool's registry row already carries.
	//
	// Zero means domain.StaticDSNCredentials: every pool connects as its
	// MetadataDSN says and no pool is ever retired for credential age.
	// That is this module's default and is unchanged from before this
	// field existed — a deployment that wants nothing to change sets
	// nothing.
	//
	// The shipping alternative is credentials/openbao, which issues a
	// per-pool credential from OpenBao's database secrets engine with a
	// lease, and whose package doc comment is where the measurements and
	// the operational requirements are written down. Setting this requires
	// LongestTransaction, because a credential that expires forces a
	// decision about how long a transaction may run — see Open, which
	// refuses the configuration rather than discovering it later.
	//
	// It applies to tenant pools only. The control plane's own pool and
	// the migration pool keep their static DSNs, and that is a limit
	// rather than an omission: neither of those is reference counted, so
	// there is no moment at which replacing one is known to be safe. What
	// the spike established about those two credentials is a property of
	// the roles they name — members of an owning role, never superusers,
	// which keeps even the control plane inside the fail-closed backstop —
	// and Scoped.CheckEnforcement is what reports whether that holds.
	Credentials domain.Credentials
}

// Tenancy is this module's one object: the control plane, the resolver,
// and the conversion from a resolved tenant to a data-plane handle.
//
// It is safe for concurrent use. Close releases everything it opened.
type Tenancy struct {
	control  *registry.Control
	resolver *pool.CachingResolver
	appRole  string
}

// Open connects the control plane and builds the resolver.
//
// It does not migrate, and it must not: applying the registry schema runs
// on the migration credential (Migrate), and doing it here would mean this
// process held the migration rights for its whole life. A deployment calls
// Migrate once at startup, on a credential this Config never sees, and
// then Open.
func Open(ctx context.Context, cfg Config) (*Tenancy, error) {
	if cfg.RegistryDSN.IsZero() {
		return nil, fmt.Errorf(
			"%w: RegistryDSN is required: it is the control plane's connection to the registry database",
			domain.ErrInvalidConfig)
	}
	if cfg.AppRole != "" && !pgmigrate.IsPlainIdentifier(cfg.AppRole) {
		// Checked here, once, because SET LOCAL ROLE takes no bound
		// parameter: the role name has to reach Postgres as SQL text, so
		// it gets more than one reason to be safe (this check, and
		// pgx.Identifier quoting at the call site).
		return nil, fmt.Errorf(
			"%w: AppRole %q is not a plain identifier: letters, digits and underscore, not starting with a digit",
			domain.ErrInvalidConfig, cfg.AppRole)
	}

	if cfg.Cache.TTL < 0 || cfg.Cache.NegativeTTL < 0 {
		return nil, fmt.Errorf("%w: Cache.TTL and Cache.NegativeTTL must not be negative", domain.ErrInvalidConfig)
	}
	if cfg.Postgres.MaxConns > 0 && cfg.Postgres.MinConns > cfg.Postgres.MaxConns {
		return nil, fmt.Errorf("%w: Postgres.MinConns must not exceed Postgres.MaxConns", domain.ErrInvalidConfig)
	}
	if cfg.LongestTransaction < 0 {
		return nil, fmt.Errorf("%w: LongestTransaction must not be negative", domain.ErrInvalidConfig)
	}
	if cfg.Credentials != nil && cfg.LongestTransaction <= 0 {
		return nil, fmt.Errorf(
			"%w: LongestTransaction is required when Credentials is set: it is the longest "+
				"transaction this deployment serves, and a pool on an expiring credential is retired "+
				"that long before the credential expires so its outstanding transactions can finish",
			domain.ErrInvalidConfig)
	}

	clock := cfg.Clock
	if clock == nil {
		clock = domain.SystemClock{}
	}

	control, err := registry.Open(ctx, registry.Config{
		DSN:      cfg.RegistryDSN,
		Postgres: cfg.Postgres,
		Clock:    clock,
	})
	if err != nil {
		return nil, err
	}

	opener := cfg.Opener
	if opener == nil {
		opener = pool.NewOpener(cfg.Postgres)
	}

	resolver := pool.NewResolver(control, opener, cfg.Cache, pool.LifecycleOptions{
		Credentials:              cfg.Credentials,
		LongestTransaction:       cfg.LongestTransaction,
		Clock:                    clock,
		OnCredentialReleaseError: cfg.OnCredentialReleaseError,
	})
	control.SetTenantStatusObserver(func(id domain.TenantID, _ domain.TenantStatus) {
		resolver.InvalidateTenant(id)
	})

	return &Tenancy{
		control:  control,
		resolver: resolver,
		appRole:  cfg.AppRole,
	}, nil
}

// Control returns the control-plane handle: the registry, and nothing
// else. It exposes no method that takes SQL — see internal/registry's
// package doc comment for why that is a type-level guarantee rather than a
// convention.
func (t *Tenancy) Control() *registry.Control { return t.control }

// Scope resolves id and returns the data-plane handle for it: one tenant,
// on the pool that hosts it, with row-level-security session context
// established for every statement it runs.
//
// The errors are the resolver's, which are the ones a caller can act on:
//
//   - domain.ErrNotAuthorizedOrNotFound for a tenant that does not exist,
//     is malformed, or is being deleted — the three are deliberately
//     indistinguishable.
//   - domain.ErrUnavailable for a suspended tenant, an unreachable pool,
//     or a closed Tenancy. All three are worth a retry, two of them after
//     an operator does something.
//
// The returned handle's lifetime is tied to ctx: the pool behind it is
// reference-counted and released when ctx finishes. A caller that passes a
// context which never finishes keeps that pool open, conservatively,
// rather than having it closed from under an in-flight query.
func (t *Tenancy) Scope(ctx context.Context, id domain.TenantID) (pg.Scoped, error) {
	handle, err := t.resolver.Resolve(ctx, id)
	if err != nil {
		return pg.Scoped{}, err
	}
	return pg.NewScoped(handle.Tenant, handle.Pool.Ref(), handle.DB, t.appRole), nil
}

// Stats returns a point-in-time snapshot of resolver state: open pools,
// retired/closing entries, cache sizes, and credential issue/release counters.
// It is intended for an operator's metrics endpoint; the module has no metrics
// dependency of its own.
func (t *Tenancy) Stats() pool.Stats { return t.resolver.Stats() }

// Close closes every pool the resolver opened and the control plane's own.
// It is idempotent.
//
// It blocks until every pool is actually torn down, which is the correct
// behaviour for a shutdown path: the caller is whoever owns this object's
// lifetime, not a request goroutine resolving an unrelated tenant. A
// handle used after Close is refused with domain.ErrUnavailable rather
// than reaching a closed pool — see pg.Scoped's begin.
func (t *Tenancy) Close() error {
	err := t.resolver.Close()
	t.control.Close()
	return err
}

// String names the configuration's non-credential fields and redacts its
// RegistryDSN.
//
// Config is the single most likely place for the registry credential to
// escape: logging or serializing your configuration at startup is the normal
// thing to do, and before these four methods that wrote the password to the
// log. RegistryDSN is an exported field of a type that redacts itself, so fmt
// would reach DSN's own methods here — but json.Marshal of a Config would
// also have emitted AppRole and the pool limits, and a reader cannot tell at
// a glance which containers are safe by construction. See CONVENTIONS.md's
// "Rendering a secret".
func (cfg Config) String() string {
	return fmt.Sprintf("tenancy.Config{RegistryDSN: %s, AppRole: %q, Postgres: %s, Cache: {TTL: %s, NegativeTTL: %s, MaxPools: %d, MaxTenants: %d}, LongestTransaction: %s, Clock: %T, Opener: %s, Credentials: %T, OnCredentialReleaseError: %t}",
		cfg.RegistryDSN, cfg.AppRole, poolConfigDescription(cfg.Postgres),
		cfg.Cache.TTL, cfg.Cache.NegativeTTL, cfg.Cache.MaxPools, cfg.Cache.MaxTenants,
		cfg.LongestTransaction, cfg.Clock, openerDescription(cfg.Opener), cfg.Credentials,
		cfg.OnCredentialReleaseError != nil)
}

// poolConfigDescription names the non-secret pool fields and the types of the
// two extension seams. It deliberately does not reflect a custom Tracer or
// AfterConnect value: either can hold material a consumer should have redacted.
func poolConfigDescription(c pg.PoolConfig) string {
	return fmt.Sprintf("{MaxConns: %d, MinConns: %d, MaxConnLifetime: %s, MaxConnIdleTime: %s, ConnectTimeout: %s, ApplicationName: %q, Tracer: %T, AfterConnect: %t}",
		c.MaxConns, c.MinConns, c.MaxConnLifetime, c.MaxConnIdleTime, c.ConnectTimeout,
		c.ApplicationName, c.Tracer, c.AfterConnect != nil)
}

// Format implements fmt.Formatter, the only interface fmt consults for every
// verb.
func (cfg Config) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, cfg.String()) }

// MarshalJSON renders the same summary as a JSON string.
func (cfg Config) MarshalJSON() ([]byte, error) { return json.Marshal(cfg.String()) }

// LogValue renders the configuration as a slog group with the registry DSN
// redacted, so slog.Any("config", cfg) is safe under every handler.
func (cfg Config) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("registry_dsn", domain.Redacted),
		slog.String("app_role", cfg.AppRole),
		slog.String("clock", fmt.Sprintf("%T", cfg.Clock)),
		slog.String("opener", openerDescription(cfg.Opener)),
		slog.Duration("cache_ttl", cfg.Cache.TTL),
		slog.Duration("cache_negative_ttl", cfg.Cache.NegativeTTL),
		slog.Int("cache_max_pools", cfg.Cache.MaxPools),
		slog.Int("cache_max_tenants", cfg.Cache.MaxTenants),
		slog.Duration("longest_transaction", cfg.LongestTransaction),
		// The type name, not the value: a Credentials implementation holds
		// the material it authenticates to its issuer with, and %T is the
		// one rendering that reaches no interface and discloses nothing
		// (CONVENTIONS.md's "Rendering a secret").
		slog.String("credentials", fmt.Sprintf("%T", cfg.Credentials)),
		slog.Bool("on_credential_release_error", cfg.OnCredentialReleaseError != nil),
	)
}

// openerDescription names whether a custom Opener was supplied, which is the
// part worth logging. The function value itself renders as an address, and an
// address in a log line is noise.
func openerDescription(o pool.Opener) string {
	if o == nil {
		return "default"
	}
	return "custom"
}
