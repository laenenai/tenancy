// Package pool resolves a tenant id to the physical Postgres pool hosting
// its metadata: the lookup every tenant-scoped request makes before it
// ever touches a database connection.
//
// # Provenance, because this code was not written here
//
// It is extracted from cas/internal/pool, where two concurrency bugs were
// found by review and fixed: a logical TOCTOU between looking a pool entry
// up and reserving a reference to it, and a bookkeeping gap in which an
// entry evicted from the cache was accounted for in neither the cache nor
// the retired set, so Close could return having left a pool open. Both
// fixes are here, and so are both regression tests — see getAndBorrow and
// openNewPool for the fixes, toctou_internal_test.go and
// TestClose_AccountsForEntryWithPartiallyReleasedBorrowers for the tests.
//
// Those tests are the reason this module exists rather than three
// implementations existing. The TOCTOU in particular is invisible to the
// race detector and to probabilistic concurrency tests alike — it is
// entirely inside mutex-protected sections — and the only way to test it
// is an unexported seam a test can pause on. Nobody re-derives that.
//
// # Credential-driven retirement reuses that same machinery
//
// A pool opened on a credential that expires has to be replaced before it
// does. The mechanism is not new: "stop handing this entry out, let the
// transactions already running on it finish, then close it" is exactly what
// the reference counting above already does for an evicted entry, and
// poolEntry's doc comment was describing it before any credential here
// could expire. Credential expiry is one more reason to set retired, and
// the refcount is what makes it safe — see poolEntry.retireAt for the
// measurements that decide how far ahead of expiry that happens, and
// Options.LongestTransaction for the one number a deployment must supply.
//
// Retirement is checked when an entry is looked up, not driven by a timer,
// which is the same lazy, clock-injected shape the TTL caches here already
// use. The cost is stated rather than hidden: an idle pool nobody resolves
// again is not retired until somebody does. That is a resource held open,
// bounded by Options.MaxPools, and not a privilege held open — the
// credential behind it loses every privilege the moment its lease expires
// (measured: inside the spike's 2s probe resolution), so an unretired idle
// pool holds connections that can no longer do anything.
//
// See CachingResolver's doc comment for the caching and lifetime rules.
package pool

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/sync/singleflight"

	"github.com/laenenai/tenancy/internal/domain"
	"github.com/laenenai/tenancy/internal/pg"
)

// Handle is the result of resolving a tenant: the pool and tenant rows
// that named it, and the shared *pgxpool.Pool connected to that pool's
// Postgres database.
//
// DB may be shared with every other tenant hosted in the same pool — it is
// owned by the resolver that returned it; never close it directly.
//
// It is NOT what a consumer of this module sees. The facade hands back
// internal/pg.Scoped, which exposes no pool and no unscoped statement
// path; this type is the internal carrier that the composition layer
// converts. Go's internal rule keeps it unreachable from outside the
// module, which is what lets the resolver keep the shape its regression
// tests were written against while the public surface keeps the
// control-plane/data-plane separation.
type Handle struct {
	Pool   domain.Pool
	Tenant domain.Tenant
	DB     *pgxpool.Pool
}

// Resolver resolves a tenant id to the Handle for the pool hosting it.
type Resolver interface {
	Resolve(ctx context.Context, id domain.TenantID) (Handle, error)
}

// Registry is the subset of the control plane a Resolver needs: looking up
// a tenant and the pool that hosts it.
//
// It is declared here, rather than consuming *registry.Control directly,
// for two reasons. Tests substitute a fake that counts queries instead of
// talking to Postgres — which is the only way to assert single-flighting,
// since a timing-based test would be flaky. And it states, in two methods,
// the whole of the resolver's authority over the registry: resolution is
// read-only end to end, by construction, because there is no write method
// here to call. *registry.Control satisfies it with no change on that side.
type Registry interface {
	// TenantByID returns domain.ErrNotAuthorizedOrNotFound for an unknown
	// tenant.
	TenantByID(ctx context.Context, id domain.TenantID) (domain.Tenant, error)
	// PoolByID returns domain.ErrNotAuthorizedOrNotFound for an unknown
	// pool.
	PoolByID(ctx context.Context, id domain.PoolID) (domain.Pool, error)
}

// Opener opens the *pgxpool.Pool backing p, connecting as cred. NewOpener
// builds the production implementation; tests substitute a fake that never
// dials a real network.
//
// cred is whatever Options.Credentials issued for p, and the zero
// Credential means "connect as p.MetadataDSN already says" — which is the
// default and was the only behaviour before this parameter existed. An
// implementation that ignores cred silently connects on the pool row's
// long-lived credential while this resolver schedules retirements against
// an issued one it is not using, so an Opener must apply it: pass it to
// pg.OpenAs, which is the one function here that knows how.
type Opener func(ctx context.Context, p domain.Pool, cred domain.Credential) (*pgxpool.Pool, error)

// NewOpener returns the production Opener: it hands p.MetadataDSN and cred
// straight to pg.OpenAs with cfg and does nothing else with either.
//
// Doing nothing else is the contract, not an implementation detail.
// pg.OpenAs is the one function audited never to let a DSN's text reach a
// returned error (see its doc comment), and the one place that applies a
// credential to an already-parsed configuration rather than by rewriting a
// connection string; parsing, validating or interpolating either of them
// here would reopen exactly those leaks in this package instead. See
// TestResolve_NeverLeaksMetadataDSN.
func NewOpener(cfg pg.PoolConfig) Opener {
	return func(ctx context.Context, p domain.Pool, cred domain.Credential) (*pgxpool.Pool, error) {
		return pg.OpenAs(ctx, p.MetadataDSN, cred, cfg)
	}
}

// Options configures a CachingResolver.
//
// MaxPools and MaxTenants deliberately treat a zero value differently —
// read both before assuming they behave alike:
//
//   - MaxPools <= 0 means UNBOUNDED. A pool entry only ever exists because
//     some tenant's tenancy.tenants.pool_id, a row an operator controls,
//     named it; an attacker cannot make this cache grow by sending
//     requests, so leaving it unbounded by default is low-risk.
//   - MaxTenants <= 0 means "use DefaultMaxTenants", NOT unbounded. The
//     negative half of the tenant cache is reachable by anyone who can
//     resolve any tenant id at all, known or not, so a caller who simply
//     forgot to set this must not silently get the unbounded,
//     request-rate-governed growth the option exists to prevent.
type Options struct {
	// TTL bounds how long a successful resolution is served from cache
	// before the registry is consulted again. A consumer that changes a
	// tenant's pool assignment or status must expect the change to take up
	// to TTL to be seen — with one exception, suspension, which is never
	// cached at all.
	TTL time.Duration
	// NegativeTTL bounds how long an unknown-or-deleting tenant is served
	// from cache. It is a separate, normally shorter, setting than TTL: a
	// negative cache that outlived a newly-created tenant by minutes would
	// make that tenant invisible for no good reason.
	NegativeTTL time.Duration
	// MaxPools bounds how many distinct *pgxpool.Pool the cache holds open
	// at once. Zero or negative means unbounded — see the struct comment
	// above for why that default differs from MaxTenants.
	MaxPools int
	// MaxTenants bounds how many tenant ids the positive cache, and
	// separately the negative cache, each hold at once (two independent
	// bounds, not a shared budget — see CachingResolver's doc comment for
	// why). Zero or negative means "use DefaultMaxTenants".
	MaxTenants int
	// Clock reads "now" for cache expiry. Zero means domain.SystemClock.
	//
	// It is configurable, which cas's version was not: expiry driven by
	// time.Now can only be tested by sleeping, and a conformance suite
	// that a consumer runs should not spend wall-clock time proving that a
	// TTL elapses. A test pins an instant and advances it.
	Clock domain.Clock

	// Credentials issues the credential each pool's connections
	// authenticate with. Nil means domain.StaticDSNCredentials — connect
	// as the pool row's MetadataDSN says, and never retire a pool for
	// credential age — which is this module's default and what every
	// deployment that sets nothing gets.
	//
	// A Credentials that issues expiring credentials requires
	// LongestTransaction to be set. See credentials/openbao.
	Credentials domain.Credentials

	// LongestTransaction is the longest a single transaction on a tenant
	// pool may run, and it is required whenever Credentials issues
	// credentials that expire.
	//
	// It is the lead time a pool is retired by: a pool built on a
	// credential expiring at T stops being handed to new callers at T
	// minus this, and the transactions already running on it have until T
	// to finish. That window is a drain window, not a safety margin, so
	// the number is a fact about this deployment's slowest query rather
	// than a security preference — and getting it wrong in the small
	// direction is not a slow query, it is a transaction that loses its
	// privileges mid-statement and a COMMIT that silently becomes a
	// ROLLBACK (see poolEntry.retireAt).
	//
	// It is validated against what is actually issued, not only at
	// configuration time: a credential whose whole lifetime is less than
	// twice this is refused at resolution with domain.ErrInvalidConfig,
	// because a pool retired that early would spend more of its life
	// draining than serving. The error names both numbers and the floor —
	// see openNewPool.
	LongestTransaction time.Duration
}

// DefaultMaxTenants is used for Options.MaxTenants when it is zero or
// negative. It is deliberately not "unbounded": the negative half of this
// cache is reachable by anyone who can resolve an arbitrary tenant id, so
// leaving it unbounded by default would reopen the exact
// memory-growth-by-request-rate problem MaxTenants exists to close.
const DefaultMaxTenants = 10_000

// CachingResolver resolves tenant ids to pool Handles. It caches the
// tenant→pool lookup and the *pgxpool.Pool opened for each distinct
// domain.Pool, in three independent bounded caches:
//
//   - positiveTenants: "this pool hosts this tenant", for Options.TTL.
//   - negativeTenants: "unknown or deleting" — which this module requires
//     to be indistinguishable — for the shorter Options.NegativeTTL.
//   - pools: at most one *pgxpool.Pool per domain.Pool, shared across
//     every tenant hosted there, bounded by Options.MaxPools.
//
// positiveTenants and negativeTenants are deliberately separate caches
// with separate eviction budgets, not one cache with a "negative" flag: an
// unknown tenant id costs nothing to reject, by design, and is reachable
// by any caller at all (an attacker probing, or a buggy client looping) —
// a shared budget would let a flood of distinct unknown ids evict a real,
// actively-used tenant's positive entry, turning a cheap rejection into a
// latency attack on legitimate traffic. See
// TestResolve_TenantCacheIsBoundedAndNegativeFloodDoesNotEvictLiveTenants.
//
// It never creates or mutates a pool or tenant row: resolution is
// read-only end to end, by construction — the Registry interface it holds
// has two read methods and no write method to call. A cold cache hit by
// many concurrent callers for the same tenant id runs the registry lookup,
// and the pool open it may require, at most once: single-flighted by
// tenant id, and separately by pool id so two different tenants landing on
// the same new pool cannot race to open it twice.
//
// A suspended tenant's result is never cached, in either direction:
// unsuspending a tenant is an operator action a caller should see take
// effect on the very next call, not after a cache TTL recorded a point in
// time before it happened.
type CachingResolver struct {
	registry Registry
	open     Opener
	creds    domain.Credentials
	ttl      time.Duration
	negTTL   time.Duration
	lead     time.Duration
	clock    domain.Clock

	tenantGroup singleflight.Group
	poolGroup   singleflight.Group

	mu              sync.Mutex
	closed          bool
	positiveTenants *lru[domain.TenantID, *positiveTenantEntry]
	negativeTenants *lru[domain.TenantID, *negativeTenantEntry]
	pools           *lru[domain.PoolID, *poolEntry]
	retiredPending  map[*poolEntry]struct{} // evicted pool entries not yet closeable (refs > 0)
}

// NewResolver returns a CachingResolver backed by registry, using open to
// open each pool's *pgxpool.Pool. Pass NewOpener(cfg) for open in
// production.
func NewResolver(registry Registry, open Opener, opts Options) *CachingResolver {
	maxTenants := opts.MaxTenants
	if maxTenants <= 0 {
		maxTenants = DefaultMaxTenants
	}
	clock := opts.Clock
	if clock == nil {
		clock = domain.SystemClock{}
	}
	creds := opts.Credentials
	if creds == nil {
		creds = domain.StaticDSNCredentials{}
	}
	return &CachingResolver{
		registry:        registry,
		open:            open,
		creds:           creds,
		ttl:             opts.TTL,
		negTTL:          opts.NegativeTTL,
		lead:            opts.LongestTransaction,
		clock:           clock,
		positiveTenants: newLRU[domain.TenantID, *positiveTenantEntry](maxTenants),
		negativeTenants: newLRU[domain.TenantID, *negativeTenantEntry](maxTenants),
		pools:           newLRU[domain.PoolID, *poolEntry](opts.MaxPools),
		retiredPending:  make(map[*poolEntry]struct{}),
	}
}

var _ Resolver = (*CachingResolver)(nil)

// errResolverClosed is returned once Close has been called. It wraps
// domain.ErrUnavailable: the resolver itself is gone, not any particular
// dependency, but ErrUnavailable is the taxonomy's honest "not reachable
// right now" signal and a caller treating it as retryable — against a new
// resolver, in a restarted process — is the correct reaction.
var errResolverClosed = fmt.Errorf("%w: resolver is closed", domain.ErrUnavailable)

// Resolve resolves id to the Handle for the pool hosting it. See
// CachingResolver's doc comment for caching, suspension, and
// single-flight behaviour.
func (r *CachingResolver) Resolve(ctx context.Context, id domain.TenantID) (Handle, error) {
	now := r.clock.Now()

	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return Handle{}, errResolverClosed
	}
	if neg, ok := r.negativeTenants.get(id); ok && now.Before(neg.expiresAt) {
		r.mu.Unlock()
		return Handle{}, domain.ErrNotAuthorizedOrNotFound
	}
	if pos, ok := r.positiveTenants.get(id); ok && now.Before(pos.expiresAt) {
		tenant := pos.tenant
		r.mu.Unlock()
		return r.resolveHandle(ctx, tenant)
	}
	r.mu.Unlock()

	outcomeAny, err, _ := r.tenantGroup.Do(string(id), func() (any, error) {
		return r.fetch(ctx, id)
	})
	if err != nil {
		return Handle{}, err
	}
	outcome, _ := outcomeAny.(resolveOutcome) //nolint:forcetypeassert // tenantGroup.Do only ever returns resolveOutcome here

	switch outcome.kind {
	case outcomeActive:
		r.mu.Lock()
		if r.closed {
			r.mu.Unlock()
			return Handle{}, errResolverClosed
		}
		r.positiveTenants.put(id, &positiveTenantEntry{expiresAt: now.Add(r.ttl), tenant: outcome.tenant})
		r.mu.Unlock()
		return r.resolveHandle(ctx, outcome.tenant)

	case outcomeNegative:
		r.mu.Lock()
		if !r.closed {
			r.negativeTenants.put(id, &negativeTenantEntry{expiresAt: now.Add(r.negTTL)})
		}
		r.mu.Unlock()
		return Handle{}, domain.ErrNotAuthorizedOrNotFound

	case outcomeSuspended:
		return Handle{}, fmt.Errorf("%w: tenant is suspended", domain.ErrUnavailable)

	default:
		// Unreachable: outcomeKind's three values are exhaustively handled
		// above, and fetch never returns a nil error paired with anything
		// else. Kept as a safety net rather than a compiler-checked
		// guarantee, since Go does not enforce switch exhaustiveness.
		return Handle{}, fmt.Errorf("%w: unexpected resolve outcome %d", domain.ErrUnavailable, outcome.kind)
	}
}

// outcomeKind names what fetch discovered about a tenant id, for the cases
// where that is not already fully captured by a non-nil error return.
type outcomeKind int

const (
	outcomeActive outcomeKind = iota
	outcomeNegative
	outcomeSuspended
)

// resolveOutcome is the result of one (possibly single-flighted) registry
// fetch, shared across every caller that was waiting on it. It is only
// meaningful when fetch returns a nil error: a non-nil error always takes
// precedence and short-circuits Resolve before outcome.kind is read.
//
// It deliberately carries no *poolEntry: fetch may be shared by many
// concurrent callers, each of which must independently, atomically reserve
// its own reference on the pool entry (see getAndBorrow) rather than have
// one reservation, taken once inside fetch, handed out to all of them.
// resolveHandle is what each sharing caller does that in.
type resolveOutcome struct {
	kind   outcomeKind
	tenant domain.Tenant
}

// fetch performs the registry lookup underlying one single-flighted
// Resolve call.
//
// It never returns a Go error for an outcome this module's taxonomy
// already has a sentinel for — unknown, deleting, suspended. Those are
// reported through resolveOutcome.kind instead, so a transient registry
// failure (which must propagate, unmasked, to every waiting caller) stays
// distinguishable from a definitive business outcome (which must not be
// treated as an error by the singleflight group's error-sharing path).
func (r *CachingResolver) fetch(ctx context.Context, id domain.TenantID) (resolveOutcome, error) {
	tenant, err := r.registry.TenantByID(ctx, id)
	if err != nil {
		if errors.Is(err, domain.ErrNotAuthorizedOrNotFound) {
			return resolveOutcome{kind: outcomeNegative}, nil
		}
		return resolveOutcome{}, err
	}

	switch tenant.Status {
	case domain.TenantStatusDeleting:
		// A deleting tenant must be indistinguishable from one that never
		// existed: see domain.ErrNotAuthorizedOrNotFound.
		return resolveOutcome{kind: outcomeNegative}, nil

	case domain.TenantStatusSuspended:
		return resolveOutcome{kind: outcomeSuspended, tenant: tenant}, nil

	case domain.TenantStatusActive:
		return resolveOutcome{kind: outcomeActive, tenant: tenant}, nil

	default:
		// domain.TenantStatus is a closed set of three values; an
		// unrecognized one is not supposed to reach this code. Fail closed
		// rather than guess at what it means.
		return resolveOutcome{kind: outcomeNegative}, nil
	}
}

// resolveHandle returns the Handle for tenant's pool, opening and caching
// it if needed, with a reference reserved on behalf of ctx. See
// ensurePool/getAndBorrow for how that reservation is made race-free
// against a concurrent eviction.
func (r *CachingResolver) resolveHandle(ctx context.Context, tenant domain.Tenant) (Handle, error) {
	entry, err := r.ensurePool(ctx, tenant.PoolID)
	if err != nil {
		return Handle{}, err
	}
	return r.borrow(ctx, entry, tenant), nil
}

// getAndBorrow looks up poolID in the pool cache and, if it is cached and
// not already closed, reserves a reference to it. The lookup and the
// refs++ happen inside one locked critical section — there is no window
// between "found" and "reserved" for a concurrent eviction (see
// retireLocked) to close the entry in before this caller gets to use it.
//
// That window is exactly the Critical review finding this closes: a prior
// version looked the entry up, released the lock, and only later
// (separately, after re-acquiring the lock) incremented its reference
// count — during which a concurrent eviction of a different pool could
// close this one, and the later increment would hand out a handle to an
// already-closed *pgxpool.Pool. See
// TestGetAndBorrow_HoldsMutexAcrossLookupAndReserve
// (toctou_internal_test.go).
//
// The entry.closed check below should be unreachable: retireLocked removes
// an entry from the pool cache (via lru.put's eviction, or Close's clear)
// in the same critical section that can eventually mark it closed, so
// pools.get should never find a closed entry still sitting in the cache.
// It costs nothing to check anyway, and documents the invariant.
//
// ctx is not consulted here and is only carried through: a lookup that
// retires an entry may be the one that closes it, and closing hands the
// credential back (see closeInBackground).
func (r *CachingResolver) getAndBorrow(ctx context.Context, poolID domain.PoolID) (*poolEntry, bool) {
	now := r.clock.Now()

	r.mu.Lock()
	entry, ok := r.pools.get(poolID)
	if !ok || entry.closed {
		r.mu.Unlock()
		return nil, false
	}
	// The one place credential-driven retirement enters: an entry whose
	// credential is coming up for expiry stops being handed out here, and
	// the caller's ensurePool loop opens its replacement on a fresh
	// credential. Deliberately checked on the lookup path rather than from
	// a timer — see the package doc comment for what that costs.
	if retired, closeNow := r.retireIfDueLocked(poolID, entry, now); retired {
		r.mu.Unlock()
		if closeNow {
			r.closeInBackground(ctx, entry)
		}
		return nil, false
	}

	if testHookDuringGetAndBorrow != nil {
		// Test-only (see its own doc comment): lets a white-box test pause
		// here, still holding r.mu, exactly where a prior, since-fixed
		// version of this code had already released the lock — and then
		// prove a concurrent eviction attempt (which also needs r.mu)
		// genuinely blocks rather than racing in.
		testHookDuringGetAndBorrow()
	}
	entry.refs++
	r.mu.Unlock()
	return entry, true
}

// retireIfDueLocked retires entry if its credential's retirement is due,
// removing it from the pool cache so no further caller can be handed it,
// and reports whether it did and whether the caller must now close it.
//
// The caller must already hold r.mu, and must call closeInBackground(entry)
// outside the lock when closeNow is true — the same contract retireLocked
// has, for the same reason.
//
// An entry with no retireAt is never due: that is every pool connected on
// its registry row's own DSN, which is the default, so this costs one
// IsZero check on the hot resolution path and changes nothing for a
// deployment that has not configured a credential issuer.
func (r *CachingResolver) retireIfDueLocked(poolID domain.PoolID, entry *poolEntry, now time.Time) (retired, closeNow bool) {
	if entry.retireAt.IsZero() || now.Before(entry.retireAt) {
		return false, false
	}
	// Removing it from the cache here is what makes this a retirement
	// rather than a leak: retireLocked drops the cache's own reference on
	// the assumption that the cache no longer holds the entry, and an
	// entry left in r.pools after that would be handed out with a
	// reference count one lower than the number of holders.
	r.pools.remove(poolID)
	return true, r.retireLocked(entry)
}

// testHookDuringGetAndBorrow, when non-nil, is called by getAndBorrow
// while it still holds r.mu, after finding the entry but before reserving
// it. Production code never sets this; only
// TestGetAndBorrow_HoldsMutexAcrossLookupAndReserve
// (toctou_internal_test.go) does, to deterministically force and verify
// the interleaving the Critical review finding was about — see that test's
// doc comment for the full reasoning.
var testHookDuringGetAndBorrow func()

// ensurePool returns a poolEntry for poolID with a reference already
// reserved on behalf of the caller (see getAndBorrow), opening and caching
// a *pgxpool.Pool for poolID if none is cached yet (single-flighted by
// poolID across concurrent callers — see openNewPool — so it is opened at
// most once). The caller must eventually release the reservation (see
// borrow).
//
// Looping here is not "papering over" getAndBorrow's window — there is no
// window left to paper over, since getAndBorrow's lookup and reservation
// are already atomic. It exists only for the case where openNewPool's
// single-flighted result is shared by several concurrent callers, each of
// which must still independently, atomically reserve its own reference: by
// the time a given sharing caller runs its own getAndBorrow, the entry
// openNewPool just ensured was cached could — vanishingly rarely — have
// already been evicted and fully closed again by someone else faster.
// getAndBorrow detects that (poolID no longer found) and this loop simply
// resolves/opens again, rather than ever handing out a stale reference.
func (r *CachingResolver) ensurePool(ctx context.Context, poolID domain.PoolID) (*poolEntry, error) {
	for {
		if entry, ok := r.getAndBorrow(ctx, poolID); ok {
			return entry, nil
		}
		if err := r.openNewPool(ctx, poolID); err != nil {
			return nil, err
		}
	}
}

// openNewPool ensures poolID has a cached, valid poolEntry, opening one
// via r.open if none exists yet. Concurrent callers for the same poolID
// are single-flighted so it is opened at most once. It does not reserve a
// reference for any particular caller — every caller, including every one
// sharing this single-flighted call, reserves its own via getAndBorrow
// (see ensurePool).
func (r *CachingResolver) openNewPool(ctx context.Context, poolID domain.PoolID) error {
	_, err, _ := r.poolGroup.Do(string(poolID), func() (any, error) {
		r.mu.Lock()
		if _, ok := r.pools.get(poolID); ok {
			r.mu.Unlock()
			return nil, nil
		}
		if r.closed {
			r.mu.Unlock()
			return nil, errResolverClosed
		}
		r.mu.Unlock()

		p, err := r.registry.PoolByID(ctx, poolID)
		if err != nil {
			return nil, err
		}
		cred, err := r.creds.Issue(ctx, p)
		if err != nil {
			return nil, err
		}
		retireAt, err := r.retirementInstant(cred)
		if err != nil {
			// The credential is unusable for this deployment, so it is
			// handed straight back rather than left to expire on its own:
			// an issuer that counts live credentials should not be made to
			// count one this resolver refused to connect with.
			_ = r.creds.Release(ctx, cred)
			return nil, err
		}
		db, err := r.open(ctx, p, cred)
		if err != nil {
			_ = r.creds.Release(ctx, cred)
			return nil, err
		}

		// refs starts at 1: the cache's own reference.
		entry := &poolEntry{pool: p, db: db, cred: cred, retireAt: retireAt, refs: 1}

		r.mu.Lock()
		if r.closed {
			r.mu.Unlock()
			db.Close()
			_ = r.creds.Release(ctx, cred)
			return nil, errResolverClosed
		}
		// put's eviction decision and retireLocked's state update (marking
		// the evicted entry retired, dropping its ref, deciding whether to
		// close it now or park it in retiredPending) happen in this one
		// locked section — see the Important review finding this fixes:
		// releasing the lock between them left a window in which an
		// evicted entry was accounted for in neither r.pools nor
		// r.retiredPending, so Close could return without having actually
		// closed it. Only the real db.Close() call, which can block (see
		// closeInBackground), goes to the background, after this unlock.
		_, evicted, wasEvicted := r.pools.put(poolID, entry)
		var shouldCloseEvicted bool
		if wasEvicted {
			shouldCloseEvicted = r.retireLocked(evicted)
		}
		r.mu.Unlock()

		if wasEvicted && shouldCloseEvicted {
			r.closeInBackground(ctx, evicted)
		}
		return nil, nil
	})
	return err
}

// retirementInstant returns when a pool opened on cred must stop being
// handed to new callers, or the zero time for a credential that does not
// expire — which is the default and costs nothing.
//
// It is also where the one configuration constraint this feature adds is
// enforced, against what was actually issued rather than against what was
// configured. Two things have to hold, and both are refused here rather
// than discovered later as a 42501 in a caller's transaction:
//
//   - LongestTransaction must be set at all. There is no defensible
//     default: the number is a fact about the deployment's slowest query,
//     and a library guessing it would be guessing how long another
//     system's transactions run.
//   - The credential must have at least twice that long left to live. The
//     lead time is a drain window, so a credential with less than two
//     lead times remaining would produce a pool that spends more of its
//     life draining than serving — and one with less than one lead time
//     remaining would have to be retired before it was opened.
//
// Both report domain.ErrInvalidConfig, naming both numbers and the floor,
// because both are a deployment mistake that retrying cannot fix: the
// issuing role's TTL is what has to change.
func (r *CachingResolver) retirementInstant(cred domain.Credential) (time.Time, error) {
	if !cred.Expires() {
		return time.Time{}, nil
	}
	if r.lead <= 0 {
		return time.Time{}, fmt.Errorf(
			"%w: a credential was issued that expires, but LongestTransaction is not set: "+
				"a pool on an expiring credential has to be retired early enough for the transactions "+
				"already running on it to finish, and this module cannot guess how long that is — "+
				"set it to the longest transaction this deployment serves",
			domain.ErrInvalidConfig)
	}

	remaining := cred.ExpiresAt.Sub(r.clock.Now())
	if remaining < 2*r.lead {
		return time.Time{}, fmt.Errorf(
			"%w: the credential issued for this pool has %s left to live, but LongestTransaction is %s: "+
				"a pool stops being handed to new callers %s before its credential expires so that the "+
				"transactions already running on it can finish, because a transaction still open at expiry "+
				"loses its privileges mid-statement (SQLSTATE 42501) and its COMMIT then silently becomes a "+
				"ROLLBACK — so a credential issued for less than twice that would spend more of its life "+
				"draining than serving. Raise the issuing role's TTL to at least %s, or lower "+
				"LongestTransaction to at most %s",
			domain.ErrInvalidConfig, remaining.Round(time.Second), r.lead, r.lead,
			(2 * r.lead), (remaining / 2).Round(time.Second))
	}

	return cred.ExpiresAt.Add(-r.lead), nil
}

// borrow schedules the release of entry's already-reserved reference (see
// getAndBorrow/ensurePool) for when ctx finishes — or never, if ctx never
// does; see poolEntry's doc comment for why that is the conservative,
// correct default — and returns the Handle for it.
func (r *CachingResolver) borrow(ctx context.Context, entry *poolEntry, tenant domain.Tenant) Handle {
	context.AfterFunc(ctx, func() { r.release(ctx, entry) })
	return Handle{Pool: entry.pool, Tenant: tenant, DB: entry.db}
}

// release drops one reference from entry, closing its *pgxpool.Pool if
// that was the last one and entry has already been retired.
//
// The actual Close call is backgrounded (closeInBackground), not run on
// this goroutine: see retireLocked's doc comment for why. ctx is the
// borrower's, already finished by the time this runs — releaseCredential is
// where that is dealt with.
func (r *CachingResolver) release(ctx context.Context, entry *poolEntry) {
	r.mu.Lock()
	entry.refs--
	shouldClose := entry.refs == 0 && entry.retired && !entry.closed
	if shouldClose {
		entry.closed = true
		// Only remove it here, exactly when we are the one actually
		// closing it. Deleting it unconditionally — as an earlier version
		// did — would drop an entry that is still retired with other
		// outstanding borrowers out of retiredPending early, and Close
		// could then miss it entirely. See
		// TestClose_AccountsForEntryWithPartiallyReleasedBorrowers.
		delete(r.retiredPending, entry)
	}
	r.mu.Unlock()

	if shouldClose {
		r.closeInBackground(ctx, entry)
	}
}

// retireLocked marks entry as no longer reachable through the pool cache
// (evicted by the LRU, or the resolver closing) and releases the cache's
// own reference to it. The caller must already hold r.mu — see
// openNewPool's call site for why eviction and this state transition must
// share one critical section — and, if retireLocked returns true, must
// call closeInBackground(entry.db) afterward, outside the lock.
//
// If no other reference is outstanding, it reports that the pool should be
// closed now; otherwise it tracks entry in retiredPending until the last
// borrower's context finishes and release closes it.
//
// Closing itself must never run inline on whatever goroutine triggered the
// eviction — typically a resolution for a different, unrelated tenant.
// Confirmed by reading puddle's (pgx's connection-pool library) Pool.Close:
// it increments a WaitGroup once per connection ever constructed, idle or
// acquired, and only ever decrements it when that connection is actually
// destructed; Close defers waiting on that WaitGroup. So if any connection
// this *pgxpool.Pool ever opened is still checked out by some other,
// unrelated goroutine's in-flight query at the moment Close runs, Close
// blocks until that query finishes and releases it. The refs bookkeeping
// here, tied to a borrower's context lifetime, does not guarantee that
// borrower's actual query has finished and its connection been released by
// the time refs reaches zero, so this case is reachable rather than merely
// hypothetical — hence closeInBackground.
func (r *CachingResolver) retireLocked(entry *poolEntry) (shouldCloseNow bool) {
	entry.retired = true
	entry.refs--
	if entry.refs == 0 && !entry.closed {
		entry.closed = true
		return true
	}
	r.retiredPending[entry] = struct{}{}
	return false
}

// closeInBackground closes entry's pool, and then hands its credential
// back, on a dedicated goroutine rather than the caller's — since
// *pgxpool.Pool.Close can block waiting for a connection some unrelated
// goroutine still has checked out (see retireLocked's doc comment). Used
// for the eviction, retirement and release paths that run on a request
// goroutine; Close itself stays synchronous (see its own doc comment for
// why that is a deliberate difference, not an oversight).
//
// The order is forced: the credential is released only after the pool is
// actually closed, because releasing it first would revoke the login under
// connections still finishing their work — which is precisely the
// mid-transaction 42501 this whole arrangement exists to avoid.
func (r *CachingResolver) closeInBackground(ctx context.Context, entry *poolEntry) {
	go func() {
		entry.db.Close()
		r.releaseCredential(ctx, entry.cred)
	}()
}

// releaseCredential hands cred back to whatever issued it, and discards the
// error.
//
// Discarding it is deliberate and is the honest shape rather than a
// swallowed failure. There is no caller to report it to — this runs after
// the last borrower's context has already finished — and this module has no
// logger to report it through; adding one so that a best-effort cleanup
// could complain would put a logging decision into every consumer of a
// library whose job is to be boring. An implementation that needs a failed
// release to be visible reports it itself, which is why the port says so.
//
// Nothing depends on it succeeding, either. A credential this resolver
// stops using expires on its own schedule, and Postgres enforces VALID
// UNTIL independently of whether the issuer's revocation worked — measured,
// and the one backstop in this arrangement that always holds. Releasing is
// an optimization that returns the credential early and keeps the number of
// live logins bounded by what is in use rather than by what has ever been
// issued.
//
// ctx is detached rather than inherited, with context.WithoutCancel: the
// trigger for this call is that the last borrower's context has *finished*,
// so a release that inherited its cancellation would never be attempted at
// all — while anything else ctx carries, a trace span in particular, is
// exactly what makes the release attributable to the resolution that caused
// it.
func (r *CachingResolver) releaseCredential(ctx context.Context, cred domain.Credential) {
	if cred.IsZero() {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), credentialReleaseTimeout)
	defer cancel()
	_ = r.creds.Release(ctx, cred)
}

// credentialReleaseTimeout bounds one best-effort credential release. It is
// short because nothing waits on the result and the credential expires
// anyway; it exists so that an unreachable issuer leaks a goroutine for
// seconds rather than for the life of the process.
const credentialReleaseTimeout = 10 * time.Second

// Close closes every *pgxpool.Pool this resolver has ever opened,
// including ones already evicted from the cache but still awaiting a
// borrower's context to finish — shutdown overrides that wait, since once
// the resolver itself is going away there is no later moment to close them
// in.
//
// Unlike retireLocked and release, Close runs every pgxpool.Pool.Close
// call on its own calling goroutine rather than backgrounding them: Close
// is called by whoever owns the resolver's shutdown, not by a request
// goroutine resolving an unrelated tenant, so blocking that one caller
// until every pool is actually torn down is the correct, expected
// behaviour for a shutdown path, not the cross-tenant latency problem
// backgrounding exists to avoid.
//
// The credentials those pools were connected on are handed back too, and
// that part is bounded as a whole rather than per pool. Serially, with one
// timeout each, an unreachable issuer would make shutdown take that timeout
// times the number of pools ever opened — which is unbounded by default
// (Options.MaxPools) and would turn a best-effort cleanup into minutes of
// hang in exactly the situation where nobody is watching. So the releases
// run concurrently under one shared deadline: a reachable issuer finishes
// them in a round trip, and an unreachable one costs
// credentialReleaseTimeout once.
//
// Close is idempotent: calling it more than once, including concurrently
// with Resolve, is safe and the second call is a no-op.
func (r *CachingResolver) Close() error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true

	entries := r.pools.all()
	for entry := range r.retiredPending {
		entries = append(entries, entry)
	}
	r.pools.clear()
	r.retiredPending = make(map[*poolEntry]struct{})
	r.positiveTenants.clear()
	r.negativeTenants.clear()
	r.mu.Unlock()

	// Shutdown has no caller context to detach from: whoever owns this
	// resolver's lifetime is the caller, and it is already blocked here on
	// purpose (see this method's doc comment). One deadline covers every
	// release.
	releaseCtx, cancelReleases := context.WithTimeout(context.Background(), credentialReleaseTimeout)
	defer cancelReleases()

	var releases sync.WaitGroup
	for _, entry := range entries {
		r.mu.Lock()
		alreadyClosed := entry.closed
		entry.closed = true
		r.mu.Unlock()

		if alreadyClosed {
			continue
		}
		entry.db.Close()
		if entry.cred.IsZero() {
			continue
		}
		releases.Add(1)
		go func(cred domain.Credential) {
			defer releases.Done()
			_ = r.creds.Release(releaseCtx, cred)
		}(entry.cred)
	}
	releases.Wait()
	return nil
}
