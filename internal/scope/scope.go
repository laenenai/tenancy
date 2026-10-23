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
	"fmt"

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
	RegistryDSN string

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
	// pool.Options's doc comment before setting MaxPools and MaxTenants:
	// a zero value means something different for each, on purpose.
	Cache pool.Options

	// Clock reads "now" for minted ids, canonicalized timestamps and
	// cache expiry. Zero means domain.SystemClock.
	Clock domain.Clock

	// Opener, when non-nil, replaces how a pool's connection pool is
	// opened. Zero means the production opener, which hands the pool row's
	// MetadataDSN straight to pg.Open.
	//
	// It is the seam a consumer that manages its own connections uses, and
	// the seam this module's own tests use to assert pool lifecycle
	// without a database. A consumer supplying one takes on the
	// obligations pool.NewOpener's doc comment describes — in particular,
	// that the DSN's text must never reach a returned error.
	Opener pool.Opener
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
	if cfg.RegistryDSN == "" {
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

	cache := cfg.Cache
	if cache.Clock == nil {
		cache.Clock = clock
	}

	return &Tenancy{
		control:  control,
		resolver: pool.NewResolver(control, opener, cache),
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
	return pg.NewScoped(handle.Tenant, handle.Pool, handle.DB, t.appRole), nil
}

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
