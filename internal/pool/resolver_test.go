package pool_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/puddle/v2"

	"github.com/laenenai/tenancy/internal/domain"
	"github.com/laenenai/tenancy/internal/pg"
	"github.com/laenenai/tenancy/internal/pool"
)

// These tests came across from cas/internal/pool/resolver_test.go with the
// code. None of them needs a database: a *pgxpool.Pool does not dial until
// something acquires a connection from it, so a syntactically valid but
// unreachable DSN gives a real pool object whose lifecycle can be asserted
// without a container. That is why this whole file runs in the inner loop.

// fakeRegistry is a pool.Registry that never touches Postgres: it lets
// tests count exactly how many registry lookups a resolution (or a storm
// of concurrent resolutions) actually performs, which is the only way to
// test single-flighting — a timing-based test would be flaky.
type fakeRegistry struct {
	mu      sync.Mutex
	tenants map[domain.TenantID]domain.Tenant
	pools   map[domain.PoolID]domain.Pool

	tenantCalls int32
	poolCalls   int32
	tenantDelay time.Duration
}

func newFakeRegistry() *fakeRegistry {
	return &fakeRegistry{
		tenants: make(map[domain.TenantID]domain.Tenant),
		pools:   make(map[domain.PoolID]domain.Pool),
	}
}

func (f *fakeRegistry) setTenant(t domain.Tenant) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tenants[t.ID] = t
}

func (f *fakeRegistry) setPool(p domain.Pool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pools[p.ID] = p
}

func (f *fakeRegistry) TenantByID(_ context.Context, id domain.TenantID) (domain.Tenant, error) {
	atomic.AddInt32(&f.tenantCalls, 1)
	if f.tenantDelay > 0 {
		time.Sleep(f.tenantDelay)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	t, ok := f.tenants[id]
	if !ok {
		return domain.Tenant{}, domain.ErrNotAuthorizedOrNotFound
	}
	return t, nil
}

func (f *fakeRegistry) PoolByID(_ context.Context, id domain.PoolID) (domain.Pool, error) {
	atomic.AddInt32(&f.poolCalls, 1)
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.pools[id]
	if !ok {
		return domain.Pool{}, domain.ErrNotAuthorizedOrNotFound
	}
	return p, nil
}

var _ pool.Registry = (*fakeRegistry)(nil)

// fakeDSN builds a syntactically valid, deliberately unreachable DSN:
// pgxpool.ParseConfig accepts it (so countingOpener can build a real
// *pgxpool.Pool), but pgxpool never dials until something acquires a
// connection, so these tests never touch a real network.
func fakeDSN(label string) domain.DSN {
	return domain.DSN("postgres://user:pass@127.0.0.1:1/" + label)
}

func activeTenant(id domain.TenantID, poolID domain.PoolID) domain.Tenant {
	return domain.Tenant{
		ID:           id,
		PoolID:       poolID,
		Name:         "tenant-" + string(id),
		SecurityMode: domain.SecurityModeManaged,
		Status:       domain.TenantStatusActive,
		CreatedAt:    domain.CanonicalTime(time.Now()),
	}
}

func testPool(id domain.PoolID, dsn domain.DSN) domain.Pool {
	return domain.Pool{
		ID:             id,
		Name:           "pool-" + string(id),
		Region:         "test",
		MetadataDSN:    dsn,
		BlobConfigRef:  "ref",
		WorkerCapacity: 4,
	}
}

// countingOpener returns a pool.Opener that counts how many times it is
// called and builds a real, lazily-connecting *pgxpool.Pool, so tests can
// assert "one *pgxpool.Pool per domain.Pool" without a real database.
func countingOpener(calls *int32) pool.Opener {
	return func(ctx context.Context, p domain.Pool, _ domain.Credential) (*pgxpool.Pool, error) {
		atomic.AddInt32(calls, 1)
		cfg, err := pgxpool.ParseConfig(string(p.MetadataDSN))
		if err != nil {
			return nil, err
		}
		return pgxpool.NewWithConfig(ctx, cfg)
	}
}

func mustResolve(ctx context.Context, t *testing.T, r *pool.CachingResolver, id domain.TenantID) pool.Handle {
	t.Helper()
	h, err := r.Resolve(ctx, id)
	if err != nil {
		t.Fatalf("Resolve(%s) error = %v, want nil", id, err)
	}
	return h
}

// assertNotClosed fails the test if db is already closed.
func assertNotClosed(t *testing.T, db *pgxpool.Pool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err := db.Acquire(ctx)
	if errors.Is(err, puddle.ErrClosedPool) {
		t.Fatal("pool is closed, want it still open")
	}
}

// assertEventuallyClosed polls db until it reports closed or the deadline
// passes.
func assertEventuallyClosed(t *testing.T, db *pgxpool.Pool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		_, err := db.Acquire(ctx)
		cancel()
		if errors.Is(err, puddle.ErrClosedPool) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("pool was never closed")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// checkClosed reports a non-nil error if db does not report itself closed.
func checkClosed(db *pgxpool.Pool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := db.Acquire(ctx)
	if !errors.Is(err, puddle.ErrClosedPool) {
		return fmt.Errorf("Acquire() error = %w, want puddle.ErrClosedPool", err)
	}
	return nil
}

func assertClosed(t *testing.T, db *pgxpool.Pool) {
	t.Helper()
	if err := checkClosed(db); err != nil {
		t.Fatalf("Acquire() after Close(): %v", err)
	}
}

func TestResolve_UnknownTenantReturnsNotAuthorizedOrNotFound(t *testing.T) {
	reg := newFakeRegistry()
	var opens int32
	r := pool.NewResolver(reg, countingOpener(&opens), pool.Options{TTL: time.Minute, NegativeTTL: time.Minute, MaxPools: 10})
	t.Cleanup(func() { _ = r.Close() })

	unknown := domain.NewTenantID(domain.SystemClock{})
	_, err := r.Resolve(context.Background(), unknown)
	if !errors.Is(err, domain.ErrNotAuthorizedOrNotFound) {
		t.Fatalf("Resolve() error = %v, want ErrNotAuthorizedOrNotFound", err)
	}
	if got := atomic.LoadInt32(&reg.poolCalls); got != 0 {
		t.Errorf("PoolByID called %d times for an unknown tenant, want 0", got)
	}
	if got := atomic.LoadInt32(&opens); got != 0 {
		t.Errorf("pool opener called %d times for an unknown tenant, want 0 (no pool may be created)", got)
	}
}

// TestResolve_MalformedTenantIDIsIndistinguishableFromUnknown is the
// existence-oracle assertion at the resolver's own boundary: a caller must
// not be able to tell a syntactically invalid id apart from a valid one it
// cannot see.
//
// The resolver itself does not parse ids — it passes whatever the registry
// answers straight through, and registry.Control is where the mapping from
// a malformed id to ErrNotAuthorizedOrNotFound is made (see its PoolByID
// doc comment). This test pins the behaviour a caller observes at the end
// of that chain, which is where it matters, so neither half can be changed
// to leak the distinction without a failure here.
func TestResolve_MalformedTenantIDIsIndistinguishableFromUnknown(t *testing.T) {
	reg := newFakeRegistry()
	r := pool.NewResolver(reg, countingOpener(new(int32)), pool.Options{TTL: time.Minute, NegativeTTL: time.Minute})
	t.Cleanup(func() { _ = r.Close() })

	_, err := r.Resolve(context.Background(), domain.TenantID("not-a-ulid"))
	if !errors.Is(err, domain.ErrNotAuthorizedOrNotFound) {
		t.Fatalf("Resolve(malformed id) error = %v, want ErrNotAuthorizedOrNotFound", err)
	}
	if errors.Is(err, domain.ErrMalformedID) {
		t.Fatalf("Resolve(malformed id) error = %v, must not report ErrMalformedID on a lookup path: "+
			"a caller able to tell \"nonsense\" from \"invisible\" has an existence oracle on the id space", err)
	}
}

func TestResolve_DeletingTenantIsIndistinguishableFromUnknown(t *testing.T) {
	reg := newFakeRegistry()
	tenantID := domain.NewTenantID(domain.SystemClock{})
	poolID := domain.NewPoolID(domain.SystemClock{})
	tenant := activeTenant(tenantID, poolID)
	tenant.Status = domain.TenantStatusDeleting
	reg.setTenant(tenant)
	reg.setPool(testPool(poolID, fakeDSN("deleting")))

	var opens int32
	r := pool.NewResolver(reg, countingOpener(&opens), pool.Options{TTL: time.Minute, NegativeTTL: time.Minute, MaxPools: 10})
	t.Cleanup(func() { _ = r.Close() })

	_, err := r.Resolve(context.Background(), tenantID)
	if !errors.Is(err, domain.ErrNotAuthorizedOrNotFound) {
		t.Fatalf("Resolve() error = %v, want ErrNotAuthorizedOrNotFound", err)
	}
	if got := atomic.LoadInt32(&opens); got != 0 {
		t.Errorf("pool opener called %d times for a deleting tenant, want 0", got)
	}
}

func TestResolve_SuspendedTenantIsRefused(t *testing.T) {
	reg := newFakeRegistry()
	tenantID := domain.NewTenantID(domain.SystemClock{})
	poolID := domain.NewPoolID(domain.SystemClock{})
	tenant := activeTenant(tenantID, poolID)
	tenant.Status = domain.TenantStatusSuspended
	reg.setTenant(tenant)
	reg.setPool(testPool(poolID, fakeDSN("suspended")))

	var opens int32
	r := pool.NewResolver(reg, countingOpener(&opens), pool.Options{TTL: time.Minute, NegativeTTL: time.Minute, MaxPools: 10})
	t.Cleanup(func() { _ = r.Close() })

	_, err := r.Resolve(context.Background(), tenantID)
	if !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("Resolve() error = %v, want ErrUnavailable", err)
	}
	if errors.Is(err, domain.ErrNotAuthorizedOrNotFound) {
		t.Fatalf("Resolve() error = %v, must not also be ErrNotAuthorizedOrNotFound (suspended is a distinct outcome)", err)
	}
	if got := atomic.LoadInt32(&opens); got != 0 {
		t.Errorf("pool opener called %d times for a suspended tenant, want 0", got)
	}
}

// TestResolve_SuspendedTenantIsNeverCached is the behaviour the status
// enum's doc comment promises: unsuspending is an operator action and must
// take effect on the very next resolution, not after a TTL.
func TestResolve_SuspendedTenantIsNeverCached(t *testing.T) {
	reg := newFakeRegistry()
	tenantID := domain.NewTenantID(domain.SystemClock{})
	poolID := domain.NewPoolID(domain.SystemClock{})
	tenant := activeTenant(tenantID, poolID)
	tenant.Status = domain.TenantStatusSuspended
	reg.setTenant(tenant)
	reg.setPool(testPool(poolID, fakeDSN("suspended-uncached")))

	r := pool.NewResolver(reg, countingOpener(new(int32)), pool.Options{TTL: time.Hour, NegativeTTL: time.Hour})
	t.Cleanup(func() { _ = r.Close() })

	ctx := context.Background()
	if _, err := r.Resolve(ctx, tenantID); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("Resolve(suspended) error = %v, want ErrUnavailable", err)
	}

	// Unsuspend. With a one-hour TTL, a cached suspension would make this
	// fail.
	reg.setTenant(activeTenant(tenantID, poolID))
	if _, err := r.Resolve(ctx, tenantID); err != nil {
		t.Fatalf("Resolve() immediately after unsuspending = %v, want nil: a suspension must never be cached", err)
	}
}

func TestResolve_CachesPositiveResultsWithinTTL(t *testing.T) {
	reg := newFakeRegistry()
	tenantID := domain.NewTenantID(domain.SystemClock{})
	poolID := domain.NewPoolID(domain.SystemClock{})
	reg.setTenant(activeTenant(tenantID, poolID))
	reg.setPool(testPool(poolID, fakeDSN("positive-ttl")))

	var opens int32
	r := pool.NewResolver(reg, countingOpener(&opens), pool.Options{TTL: time.Minute, NegativeTTL: time.Minute, MaxPools: 10})
	t.Cleanup(func() { _ = r.Close() })

	ctx := context.Background()
	mustResolve(ctx, t, r, tenantID)
	mustResolve(ctx, t, r, tenantID)

	if got := atomic.LoadInt32(&reg.tenantCalls); got != 1 {
		t.Errorf("TenantByID called %d times across two resolutions within TTL, want 1", got)
	}
	if got := atomic.LoadInt32(&reg.poolCalls); got != 1 {
		t.Errorf("PoolByID called %d times across two resolutions within TTL, want 1", got)
	}
}

// TestResolve_PositiveEntryExpiresAtTTL uses the injected clock rather
// than a sleep, which is the one behavioural addition to cas's version of
// this package: expiry driven by time.Now can only be tested by spending
// wall-clock time, and a conformance suite a consumer runs should not.
func TestResolve_PositiveEntryExpiresAtTTL(t *testing.T) {
	reg := newFakeRegistry()
	tenantID := domain.NewTenantID(domain.SystemClock{})
	poolID := domain.NewPoolID(domain.SystemClock{})
	reg.setTenant(activeTenant(tenantID, poolID))
	reg.setPool(testPool(poolID, fakeDSN("ttl-expiry")))

	clock := domain.NewFixedClock(time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC))
	r := pool.NewResolver(reg, countingOpener(new(int32)), pool.Options{
		TTL: time.Minute, NegativeTTL: time.Minute, MaxPools: 10,
	}, pool.LifecycleOptions{Clock: clock})
	t.Cleanup(func() { _ = r.Close() })

	ctx := context.Background()
	mustResolve(ctx, t, r, tenantID)
	mustResolve(ctx, t, r, tenantID)
	if got := atomic.LoadInt32(&reg.tenantCalls); got != 1 {
		t.Fatalf("TenantByID called %d times before the TTL elapsed, want 1", got)
	}

	clock.Advance(time.Minute + time.Second)
	mustResolve(ctx, t, r, tenantID)
	if got := atomic.LoadInt32(&reg.tenantCalls); got != 2 {
		t.Errorf("TenantByID called %d times after the TTL elapsed, want 2", got)
	}
}

func TestResolve_NegativeResultExpires(t *testing.T) {
	reg := newFakeRegistry()
	tenantID := domain.NewTenantID(domain.SystemClock{})
	poolID := domain.NewPoolID(domain.SystemClock{})

	clock := domain.NewFixedClock(time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC))
	r := pool.NewResolver(reg, countingOpener(new(int32)), pool.Options{
		TTL: time.Minute, NegativeTTL: 20 * time.Millisecond, MaxPools: 10,
	}, pool.LifecycleOptions{Clock: clock})
	t.Cleanup(func() { _ = r.Close() })

	ctx := context.Background()
	if _, err := r.Resolve(ctx, tenantID); !errors.Is(err, domain.ErrNotAuthorizedOrNotFound) {
		t.Fatalf("Resolve() before the tenant exists: error = %v, want ErrNotAuthorizedOrNotFound", err)
	}

	reg.setTenant(activeTenant(tenantID, poolID))
	reg.setPool(testPool(poolID, fakeDSN("negative-expires")))

	clock.Advance(60 * time.Millisecond) // > NegativeTTL

	if _, err := r.Resolve(ctx, tenantID); err != nil {
		t.Fatalf("Resolve() after NegativeTTL and tenant creation: error = %v, want nil", err)
	}
}

func TestResolve_ReusesOnePgxPoolPerPool(t *testing.T) {
	reg := newFakeRegistry()
	poolID := domain.NewPoolID(domain.SystemClock{})
	reg.setPool(testPool(poolID, fakeDSN("shared-pool")))
	tenantA := domain.NewTenantID(domain.SystemClock{})
	tenantB := domain.NewTenantID(domain.SystemClock{})
	reg.setTenant(activeTenant(tenantA, poolID))
	reg.setTenant(activeTenant(tenantB, poolID))

	var opens int32
	r := pool.NewResolver(reg, countingOpener(&opens), pool.Options{TTL: time.Minute, NegativeTTL: time.Minute, MaxPools: 10})
	t.Cleanup(func() { _ = r.Close() })

	ctx := context.Background()
	hA := mustResolve(ctx, t, r, tenantA)
	hB := mustResolve(ctx, t, r, tenantB)

	if hA.DB != hB.DB {
		t.Fatal("two tenants hosted in the same pool got different *pgxpool.Pool instances")
	}
	if got := atomic.LoadInt32(&opens); got != 1 {
		t.Errorf("pool opener called %d times for two tenants sharing one pool, want 1", got)
	}
}

func TestClose_ClosesEveryPool(t *testing.T) {
	reg := newFakeRegistry()
	poolA := domain.NewPoolID(domain.SystemClock{})
	poolB := domain.NewPoolID(domain.SystemClock{})
	reg.setPool(testPool(poolA, fakeDSN("close-a")))
	reg.setPool(testPool(poolB, fakeDSN("close-b")))
	tenantA := domain.NewTenantID(domain.SystemClock{})
	tenantB := domain.NewTenantID(domain.SystemClock{})
	reg.setTenant(activeTenant(tenantA, poolA))
	reg.setTenant(activeTenant(tenantB, poolB))

	r := pool.NewResolver(reg, countingOpener(new(int32)), pool.Options{TTL: time.Minute, NegativeTTL: time.Minute, MaxPools: 10})

	ctx := context.Background()
	hA := mustResolve(ctx, t, r, tenantA)
	hB := mustResolve(ctx, t, r, tenantB)

	if err := r.Close(); err != nil {
		t.Fatalf("Close() error = %v, want nil", err)
	}
	assertClosed(t, hA.DB)
	assertClosed(t, hB.DB)

	if err := r.Close(); err != nil {
		t.Fatalf("second Close() error = %v, want nil (Close must be idempotent)", err)
	}
}

// TestResolve_AfterCloseIsRefused is the "cache entry does not outlive the
// resolver" half of the retirement claim: Close clears every cache, so a
// resolution afterwards cannot be served from one.
func TestResolve_AfterCloseIsRefused(t *testing.T) {
	reg := newFakeRegistry()
	poolID := domain.NewPoolID(domain.SystemClock{})
	tenantID := domain.NewTenantID(domain.SystemClock{})
	reg.setPool(testPool(poolID, fakeDSN("resolve-after-close")))
	reg.setTenant(activeTenant(tenantID, poolID))

	r := pool.NewResolver(reg, countingOpener(new(int32)), pool.Options{TTL: time.Hour, NegativeTTL: time.Hour})

	ctx := context.Background()
	mustResolve(ctx, t, r, tenantID) // warm the cache
	if err := r.Close(); err != nil {
		t.Fatalf("Close() error = %v, want nil", err)
	}

	if _, err := r.Resolve(ctx, tenantID); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("Resolve() after Close() error = %v, want ErrUnavailable: a warm cache entry must not "+
			"survive the resolver that produced it", err)
	}
}

// TestResolve_SingleFlightsConcurrentLookups drives a thundering herd of
// concurrent cold resolutions for the same tenant and asserts the registry
// and the pool opener are each hit exactly once. tenantDelay widens the
// race window so the goroutines are likely to overlap even on a fast
// machine.
func TestResolve_SingleFlightsConcurrentLookups(t *testing.T) {
	reg := newFakeRegistry()
	reg.tenantDelay = 30 * time.Millisecond
	tenantID := domain.NewTenantID(domain.SystemClock{})
	poolID := domain.NewPoolID(domain.SystemClock{})
	reg.setTenant(activeTenant(tenantID, poolID))
	reg.setPool(testPool(poolID, fakeDSN("single-flight")))

	var opens int32
	r := pool.NewResolver(reg, countingOpener(&opens), pool.Options{TTL: time.Minute, NegativeTTL: time.Minute, MaxPools: 10})
	t.Cleanup(func() { _ = r.Close() })

	const n = 25
	var wg sync.WaitGroup
	start := make(chan struct{})
	dbs := make([]*pgxpool.Pool, n)
	errs := make([]error, n)
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			h, err := r.Resolve(context.Background(), tenantID)
			dbs[i] = h.DB
			errs[i] = err
		}(i)
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: Resolve() error = %v", i, err)
		}
		if dbs[i] != dbs[0] {
			t.Fatalf("goroutine %d got a different *pgxpool.Pool than goroutine 0", i)
		}
	}
	if got := atomic.LoadInt32(&reg.tenantCalls); got != 1 {
		t.Errorf("TenantByID called %d times for %d concurrent cold resolutions, want 1", got, n)
	}
	if got := atomic.LoadInt32(&reg.poolCalls); got != 1 {
		t.Errorf("PoolByID called %d times for %d concurrent cold resolutions, want 1", got, n)
	}
	if got := atomic.LoadInt32(&opens); got != 1 {
		t.Errorf("pool opener called %d times for %d concurrent cold resolutions, want 1", got, n)
	}
}

// TestResolve_MaxPoolsEvictsLeastRecentlyUsed exercises the LRU bound: with
// MaxPools=2, the pool resolved least recently is the one pushed out when
// a third distinct pool is resolved.
func TestResolve_MaxPoolsEvictsLeastRecentlyUsed(t *testing.T) {
	reg := newFakeRegistry()
	poolA := domain.NewPoolID(domain.SystemClock{})
	poolB := domain.NewPoolID(domain.SystemClock{})
	poolC := domain.NewPoolID(domain.SystemClock{})
	reg.setPool(testPool(poolA, fakeDSN("lru-a")))
	reg.setPool(testPool(poolB, fakeDSN("lru-b")))
	reg.setPool(testPool(poolC, fakeDSN("lru-c")))
	tenantA := domain.NewTenantID(domain.SystemClock{})
	tenantB := domain.NewTenantID(domain.SystemClock{})
	tenantC := domain.NewTenantID(domain.SystemClock{})
	reg.setTenant(activeTenant(tenantA, poolA))
	reg.setTenant(activeTenant(tenantB, poolB))
	reg.setTenant(activeTenant(tenantC, poolC))

	var opens int32
	r := pool.NewResolver(reg, countingOpener(&opens), pool.Options{TTL: time.Minute, NegativeTTL: time.Minute, MaxPools: 2})
	t.Cleanup(func() { _ = r.Close() })
	ctx := context.Background()

	mustResolve(ctx, t, r, tenantA) // cache (MRU..LRU): [A]
	mustResolve(ctx, t, r, tenantB) // [B, A]
	mustResolve(ctx, t, r, tenantA) // bump A: [A, B]
	atomic.StoreInt32(&opens, 0)

	mustResolve(ctx, t, r, tenantC) // over MaxPools: evicts B (LRU); [C, A]
	if got := atomic.LoadInt32(&opens); got != 1 {
		t.Fatalf("resolving a third pool over MaxPools opened %d pools, want 1 (just the new one)", got)
	}

	mustResolve(ctx, t, r, tenantA) // still cached
	if got := atomic.LoadInt32(&opens); got != 1 {
		t.Errorf("resolving tenant A again opened %d pools total, want 1 (A must still be cached)", got)
	}

	mustResolve(ctx, t, r, tenantB) // was evicted, must reopen
	if got := atomic.LoadInt32(&opens); got != 2 {
		t.Errorf("resolving tenant B again opened %d pools total, want 2 (B was evicted and must reopen)", got)
	}
}

// TestResolve_TenantCacheIsBoundedAndNegativeFloodDoesNotEvictLiveTenants
// covers cas's coordinator review finding: the tenant cache must be
// bounded (a flood of distinct unknown tenant ids is the cheapest possible
// request to make, so without a bound it is memory growth by request
// rate), and bounding it must not let that flood evict a real, actively
// used tenant's positive entry (which would turn the same flood into a
// latency attack on legitimate traffic instead). This proves both halves:
// the live tenant survives the flood untouched, and the flood itself is
// provably bounded — its own oldest entries get evicted too.
func TestResolve_TenantCacheIsBoundedAndNegativeFloodDoesNotEvictLiveTenants(t *testing.T) {
	reg := newFakeRegistry()
	tenantID := domain.NewTenantID(domain.SystemClock{})
	poolID := domain.NewPoolID(domain.SystemClock{})
	reg.setTenant(activeTenant(tenantID, poolID))
	reg.setPool(testPool(poolID, fakeDSN("tenant-cache-bound")))

	const maxTenants = 3
	r := pool.NewResolver(reg, countingOpener(new(int32)), pool.Options{
		TTL: time.Minute, NegativeTTL: time.Minute, MaxPools: 10, MaxTenants: maxTenants,
	})
	t.Cleanup(func() { _ = r.Close() })
	ctx := context.Background()

	// Resolve a real, live tenant first: one positive cache entry.
	mustResolve(ctx, t, r, tenantID)

	// Flood with far more distinct unknown ids than MaxTenants. Each flood
	// resolution calls TenantByID once for its own id, so reg.tenantCalls
	// necessarily rises by floodSize regardless of whether the live
	// tenant's entry survives — the assertion below must compare against
	// the count taken *after* the flood, not before it.
	const floodSize = 20
	unknownIDs := make([]domain.TenantID, floodSize)
	for i := range unknownIDs {
		unknownIDs[i] = domain.NewTenantID(domain.SystemClock{})
		if _, err := r.Resolve(ctx, unknownIDs[i]); !errors.Is(err, domain.ErrNotAuthorizedOrNotFound) {
			t.Fatalf("Resolve(unknown id %d) error = %v, want ErrNotAuthorizedOrNotFound", i, err)
		}
	}
	tenantCallsAfterFlood := atomic.LoadInt32(&reg.tenantCalls)

	// Half one: the flood must not have evicted the live tenant's positive
	// entry. A resolution for it must still be served from cache.
	mustResolve(ctx, t, r, tenantID)
	if got := atomic.LoadInt32(&reg.tenantCalls); got != tenantCallsAfterFlood {
		t.Errorf("TenantByID called %d more time(s) for the live tenant after a %d-id negative flood, want 0 more (its positive entry must survive)",
			got-tenantCallsAfterFlood, floodSize)
	}

	// Half two: the negative cache itself is bounded, not merely "doesn't
	// touch positives". The earliest flooded id, long since pushed out by
	// MaxTenants, must cause a fresh registry query if resolved again.
	before := atomic.LoadInt32(&reg.tenantCalls)
	if _, err := r.Resolve(ctx, unknownIDs[0]); !errors.Is(err, domain.ErrNotAuthorizedOrNotFound) {
		t.Fatalf("Resolve(unknownIDs[0]) error = %v, want ErrNotAuthorizedOrNotFound", err)
	}
	if got := atomic.LoadInt32(&reg.tenantCalls); got != before+1 {
		t.Errorf("TenantByID called %d time(s) re-resolving the oldest flooded id, want 1 more (its negative entry should have been evicted by the flood itself, not left cached forever)",
			got-before)
	}
}

// TestResolve_EvictionDoesNotCloseAPoolStillInUse is this package's answer
// to "can a cached pool handle be closed while a caller still holds it?":
// evicting tenant A's pool from a MaxPools=1 cache must not close the
// *pgxpool.Pool a handle already returned to a caller whose context has
// not finished — and once that context does finish, the pool must
// eventually close so it is not leaked forever.
func TestResolve_EvictionDoesNotCloseAPoolStillInUse(t *testing.T) {
	reg := newFakeRegistry()
	poolA := domain.NewPoolID(domain.SystemClock{})
	poolB := domain.NewPoolID(domain.SystemClock{})
	reg.setPool(testPool(poolA, fakeDSN("evict-a")))
	reg.setPool(testPool(poolB, fakeDSN("evict-b")))
	tenantA := domain.NewTenantID(domain.SystemClock{})
	tenantB := domain.NewTenantID(domain.SystemClock{})
	reg.setTenant(activeTenant(tenantA, poolA))
	reg.setTenant(activeTenant(tenantB, poolB))

	r := pool.NewResolver(reg, countingOpener(new(int32)), pool.Options{TTL: time.Minute, NegativeTTL: time.Minute, MaxPools: 1})
	t.Cleanup(func() { _ = r.Close() })

	holdCtx, cancelHold := context.WithCancel(context.Background())
	hA := mustResolve(holdCtx, t, r, tenantA)

	// Resolving a second, different pool evicts A's cache slot (MaxPools=1).
	mustResolve(context.Background(), t, r, tenantB)

	// tenantA's context has not finished: the eviction must not have
	// closed the pool it is holding a handle to.
	assertNotClosed(t, hA.DB)

	// Finishing tenantA's context releases the last reference; the pool
	// must eventually close so evicted pools do not leak forever.
	cancelHold()
	assertEventuallyClosed(t, hA.DB)
}

// The Critical review finding about ensurePool/borrow handing out a handle
// to an already-closed pool (a TOCTOU between a lock-released lookup and a
// separately-locked reservation) is regression-tested in
// toctou_internal_test.go, not here. An earlier version of this test tried
// to force that interleaving with a gated Opener and a continuously racing
// goroutine, entirely through this package's public, black-box surface —
// but run against the pre-fix code, it passed 5/5 times: the real window
// was only a few instructions wide, between one function returning and the
// next acquiring a lock, far too narrow for ordinary goroutine scheduling
// to reliably land in without something pinning the exact interleaving.
// That is exactly why the fix needed a seam a test can pause on, confirmed
// deliberately rather than assumed.

// TestClose_AccountsForEntriesEvictedBeforeClose is a regression test for
// an Important review finding paired with the Critical one above: Close
// used to snapshot the pool cache plus the retired set under one lock, but
// an entry could be evicted from the cache and not yet added to the
// retired set (retirement re-acquired the lock separately, after put had
// already released it) — present in neither snapshot, so Close returned
// success while that pool stayed open. The fix makes eviction and the
// retired-set bookkeeping happen in the exact same locked section as the
// cache mutation that evicts (see openNewPool), so an entry is never in a
// gap between the two data structures.
//
// It uses MaxPools=1 and contexts that never complete to deterministically
// force every earlier pool into the retired set — each gets evicted by the
// next resolution, but its borrow is never released, so it cannot
// self-close — and then asserts Close synchronously closes every single
// one, not just the one pool still live in the cache when Close ran.
func TestClose_AccountsForEntriesEvictedBeforeClose(t *testing.T) {
	reg := newFakeRegistry()
	const numPools = 5
	poolIDs := make([]domain.PoolID, numPools)
	tenantIDs := make([]domain.TenantID, numPools)
	for i := range poolIDs {
		poolIDs[i] = domain.NewPoolID(domain.SystemClock{})
		tenantIDs[i] = domain.NewTenantID(domain.SystemClock{})
		reg.setPool(testPool(poolIDs[i], fakeDSN("close-evicted-"+string(poolIDs[i]))))
		reg.setTenant(activeTenant(tenantIDs[i], poolIDs[i]))
	}

	var mu sync.Mutex
	var opened []*pgxpool.Pool
	recordingOpener := func(ctx context.Context, p domain.Pool, _ domain.Credential) (*pgxpool.Pool, error) {
		db, err := countingOpener(new(int32))(ctx, p, domain.Credential{})
		if err != nil {
			return nil, err
		}
		mu.Lock()
		opened = append(opened, db)
		mu.Unlock()
		return db, nil
	}

	r := pool.NewResolver(reg, recordingOpener, pool.Options{TTL: time.Minute, NegativeTTL: time.Minute, MaxPools: 1})

	ctx := context.Background()
	for i := range tenantIDs {
		mustResolve(ctx, t, r, tenantIDs[i])
	}

	if err := r.Close(); err != nil {
		t.Fatalf("Close() error = %v, want nil", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(opened) != numPools {
		t.Fatalf("opened %d pools, want %d", len(opened), numPools)
	}
	for i, db := range opened {
		if err := checkClosed(db); err != nil {
			t.Errorf("pool %d: %v (Close must close every pool it ever opened, including ones evicted before Close ran)", i, err)
		}
	}
}

// TestClose_AccountsForEntryWithPartiallyReleasedBorrowers is a regression
// test for a bug found, and fixed, while fixing the one above: release used
// to unconditionally delete an evicted entry from the retired set on every
// call, even when another borrower's reference was still outstanding. That
// reopened the exact "accounted for in neither structure" gap Close's
// completeness depends on, just reached a different way — not a window
// between put and retirement, but release dropping bookkeeping for an entry
// it did not actually close.
//
// This forces two independent, live borrowers (two tenants hosted in the
// same pool) onto one entry, evicts it, releases only one of the two, and
// asserts the entry is still correctly tracked: still open, because the
// second borrower is still live, and still closed by a subsequent Close.
// Under the bug, the partial release would have dropped the entry from the
// retired set and Close would have returned without ever closing it.
func TestClose_AccountsForEntryWithPartiallyReleasedBorrowers(t *testing.T) {
	reg := newFakeRegistry()
	poolA := domain.NewPoolID(domain.SystemClock{})
	poolB := domain.NewPoolID(domain.SystemClock{})
	tenantA1 := domain.NewTenantID(domain.SystemClock{})
	tenantA2 := domain.NewTenantID(domain.SystemClock{})
	tenantB := domain.NewTenantID(domain.SystemClock{})
	reg.setPool(testPool(poolA, fakeDSN("partial-release-a")))
	reg.setPool(testPool(poolB, fakeDSN("partial-release-b")))
	reg.setTenant(activeTenant(tenantA1, poolA))
	reg.setTenant(activeTenant(tenantA2, poolA))
	reg.setTenant(activeTenant(tenantB, poolB))

	r := pool.NewResolver(reg, countingOpener(new(int32)), pool.Options{TTL: time.Minute, NegativeTTL: time.Minute, MaxPools: 1})

	// Two independent, live borrowers on the same pool: two different
	// tenants both hosted in pool A, each resolved with its own cancelable
	// context so each borrow can be released independently.
	ctx1, cancel1 := context.WithCancel(context.Background())
	h1 := mustResolve(ctx1, t, r, tenantA1)
	ctx2, cancel2 := context.WithCancel(context.Background())
	t.Cleanup(cancel2)
	h2 := mustResolve(ctx2, t, r, tenantA2)
	if h1.DB != h2.DB {
		t.Fatalf("tenantA1 and tenantA2 (same pool) got different *pgxpool.Pool instances")
	}

	// Force pool A's eviction: MaxPools=1, so resolving pool B evicts it.
	// Pool A's entry is retired but must not close outright — both borrows
	// above are still live.
	mustResolve(context.Background(), t, r, tenantB)
	assertNotClosed(t, h1.DB)

	// Release ONLY tenantA1's borrow (cancel its context and give
	// context.AfterFunc's goroutine time to run release). tenantA2's
	// borrow remains outstanding.
	cancel1()
	time.Sleep(50 * time.Millisecond)
	assertNotClosed(t, h1.DB)

	// The crucial check: Close must still close this pool even though only
	// one of its two borrowers released. Under the bug, the partial
	// release above would have already dropped this entry from the retired
	// set, and Close's snapshot would have missed it entirely.
	if err := r.Close(); err != nil {
		t.Fatalf("Close() error = %v, want nil", err)
	}
	assertClosed(t, h1.DB)
}

// TestResolve_NeverLeaksMetadataDSN is the canary test this package's
// decisions require: a pool row's MetadataDSN carries a sentinel value,
// every reachable error path from opening it is forced, and no returned
// error's text may contain the sentinel. It uses the real, production
// opener (backed by pg.Open) rather than a fake, since the decision this
// guards is specifically about what pg.Open-via-resolution leaks.
func TestResolve_NeverLeaksMetadataDSN(t *testing.T) {
	const canary = "SUPERSECRET_POOL_DSN_CANARY" //nolint:gosec // canary value, not a real credential
	cases := []struct {
		name string
		dsn  domain.DSN
	}{
		{"malformed DSN", "not-a-connection-string-at-all " + canary},
		{"unreachable DSN", "postgres://alice:" + canary + "@127.0.0.1:1/tenancy"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reg := newFakeRegistry()
			poolID := domain.NewPoolID(domain.SystemClock{})
			tenantID := domain.NewTenantID(domain.SystemClock{})
			reg.setPool(testPool(poolID, tc.dsn))
			reg.setTenant(activeTenant(tenantID, poolID))

			r := pool.NewResolver(reg, pool.NewOpener(pg.PoolConfig{ConnectTimeout: time.Second}),
				pool.Options{TTL: time.Minute, NegativeTTL: time.Minute, MaxPools: 10})
			t.Cleanup(func() { _ = r.Close() })

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, err := r.Resolve(ctx, tenantID)
			if err == nil {
				t.Fatal("Resolve() error = nil, want a non-nil error for an unreachable/malformed DSN")
			}
			if strings.Contains(err.Error(), canary) {
				t.Fatalf("Resolve() error leaks the canary secret: %v", err)
			}
		})
	}
}

// TestClose_IsIdempotentAndRaceSafeDuringResolve exercises shutdown under
// -race: Close is called, twice to also cover idempotency, while other
// goroutines are concurrently resolving.
func TestClose_IsIdempotentAndRaceSafeDuringResolve(t *testing.T) {
	reg := newFakeRegistry()
	reg.tenantDelay = 2 * time.Millisecond
	poolID := domain.NewPoolID(domain.SystemClock{})
	tenantID := domain.NewTenantID(domain.SystemClock{})
	reg.setPool(testPool(poolID, fakeDSN("close-race")))
	reg.setTenant(activeTenant(tenantID, poolID))

	r := pool.NewResolver(reg, countingOpener(new(int32)), pool.Options{
		TTL: time.Millisecond, NegativeTTL: time.Millisecond, MaxPools: 4,
	})

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_, _ = r.Resolve(context.Background(), tenantID)
			}
		}()
	}

	time.Sleep(20 * time.Millisecond)
	if err := r.Close(); err != nil {
		t.Fatalf("first Close() error = %v, want nil", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("second Close() error = %v, want nil (idempotent)", err)
	}
	close(stop)
	wg.Wait()
}

func TestResolve_InvalidateTenantDropsAWarmEntry(t *testing.T) {
	reg := newFakeRegistry()
	tenantID := domain.NewTenantID(domain.SystemClock{})
	poolID := domain.NewPoolID(domain.SystemClock{})
	reg.setTenant(activeTenant(tenantID, poolID))
	reg.setPool(testPool(poolID, fakeDSN("invalidate")))

	r := pool.NewResolver(reg, countingOpener(new(int32)), pool.Options{TTL: time.Hour, NegativeTTL: time.Hour})
	t.Cleanup(func() { _ = r.Close() })

	ctx := context.Background()
	mustResolve(ctx, t, r, tenantID)
	if got := atomic.LoadInt32(&reg.tenantCalls); got != 1 {
		t.Fatalf("TenantByID called %d times before invalidation, want 1", got)
	}

	r.InvalidateTenant(tenantID)
	mustResolve(ctx, t, r, tenantID)
	if got := atomic.LoadInt32(&reg.tenantCalls); got != 2 {
		t.Fatalf("TenantByID called %d times after invalidation, want 2", got)
	}

	stats := r.Stats()
	if stats.OpenPools != 1 || stats.PositiveTenants != 1 {
		t.Errorf("Stats() = %+v, want one open pool and one positive tenant", stats)
	}
}
