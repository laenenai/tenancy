package pool

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/puddle/v2"

	"github.com/laenenai/tenancy/internal/domain"
)

// This file is white-box (package pool, not pool_test) on purpose, unlike
// every other test in this package: it needs testHookDuringGetAndBorrow,
// an unexported seam that exists solely so this test can deterministically
// force the exact interleaving a Critical review finding in `cas` was
// about, instead of hoping concurrent goroutines happen to race into it.
//
// A first attempt at this regression test (see resolver_test.go's comment
// where it used to live) tried to force the interleaving entirely through
// the public API: gate a pool's Opener on a channel, and race a
// continuously-resolving goroutine against the resulting eviction. Run
// against the pre-fix code, it passed 5 times out of 5 — the real window
// was only the handful of instructions between ensurePool's cache-hit
// lookup returning and borrow's separate call re-acquiring the lock to
// increment refs, far too narrow for ordinary goroutine scheduling to
// reliably land in. That is exactly the point: this bug is a logical
// TOCTOU entirely inside mutex-protected sections, invisible to -race and
// to probabilistic concurrency tests alike, and it needed a real seam.
//
// It is also the single clearest reason this module exists rather than
// three copies of this code existing. Nobody re-derives this test.

func toctouTestPool(id domain.PoolID, dsn string) domain.Pool {
	return domain.Pool{
		ID:             id,
		Name:           "pool-" + string(id),
		Region:         "test",
		MetadataDSN:    dsn,
		BlobConfigRef:  "ref",
		WorkerCapacity: 4,
	}
}

func toctouActiveTenant(id domain.TenantID, poolID domain.PoolID) domain.Tenant {
	return domain.Tenant{
		ID:           id,
		PoolID:       poolID,
		Name:         "tenant-" + string(id),
		SecurityMode: domain.SecurityModeManaged,
		Status:       domain.TenantStatusActive,
		CreatedAt:    domain.CanonicalTime(time.Now()),
	}
}

type toctouFakeRegistry struct {
	pools   map[domain.PoolID]domain.Pool
	tenants map[domain.TenantID]domain.Tenant
}

func (f *toctouFakeRegistry) TenantByID(_ context.Context, id domain.TenantID) (domain.Tenant, error) {
	t, ok := f.tenants[id]
	if !ok {
		return domain.Tenant{}, domain.ErrNotAuthorizedOrNotFound
	}
	return t, nil
}

func (f *toctouFakeRegistry) PoolByID(_ context.Context, id domain.PoolID) (domain.Pool, error) {
	p, ok := f.pools[id]
	if !ok {
		return domain.Pool{}, domain.ErrNotAuthorizedOrNotFound
	}
	return p, nil
}

func toctouOpener(ctx context.Context, p domain.Pool) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(p.MetadataDSN)
	if err != nil {
		return nil, err
	}
	return pgxpool.NewWithConfig(ctx, cfg)
}

// TestGetAndBorrow_HoldsMutexAcrossLookupAndReserve is the deterministic
// regression test the Critical review finding demanded: it pauses
// getAndBorrow, via testHookDuringGetAndBorrow, exactly at the point where
// a prior version of this code had already released r.mu (having found the
// entry) and not yet reserved it. While paused there — still holding r.mu
// — it starts a concurrent eviction of that same pool entry (forced by
// resolving a second tenant under MaxPools=1) and proves that eviction
// attempt is genuinely blocked (cannot complete within a generous timeout)
// rather than merely unlikely to race in, because it needs the very same
// mutex. Only then does it let getAndBorrow proceed, and confirms the
// entry it reserved is the one that gets evicted afterward — retired, not
// immediately closed, since this reservation is still outstanding — i.e.
// exactly the ordering getAndBorrow's atomicity guarantees, never the
// reverse.
func TestGetAndBorrow_HoldsMutexAcrossLookupAndReserve(t *testing.T) {
	poolA := domain.PoolID("01ARZ3NDEKTSV4RRFFQ69G5FAA")
	poolB := domain.PoolID("01ARZ3NDEKTSV4RRFFQ69G5FAB")
	tenantA := domain.TenantID("01ARZ3NDEKTSV4RRFFQ69G5FAC")
	tenantB := domain.TenantID("01ARZ3NDEKTSV4RRFFQ69G5FAD")

	reg := &toctouFakeRegistry{
		pools: map[domain.PoolID]domain.Pool{
			poolA: toctouTestPool(poolA, "postgres://user:pass@127.0.0.1:1/toctou-a"),
			poolB: toctouTestPool(poolB, "postgres://user:pass@127.0.0.1:1/toctou-b"),
		},
		tenants: map[domain.TenantID]domain.Tenant{
			tenantA: toctouActiveTenant(tenantA, poolA),
			tenantB: toctouActiveTenant(tenantB, poolB),
		},
	}

	r := NewResolver(reg, toctouOpener, Options{TTL: time.Minute, NegativeTTL: time.Minute, MaxPools: 1})
	t.Cleanup(func() { _ = r.Close() })

	// Prime the cache: pool A is now the sole entry (MaxPools=1).
	if _, err := r.Resolve(context.Background(), tenantA); err != nil {
		t.Fatalf("priming Resolve(tenantA) error = %v, want nil", err)
	}

	pausedAt := make(chan struct{})
	resume := make(chan struct{})
	var hookFired int32
	testHookDuringGetAndBorrow = func() {
		if atomic.AddInt32(&hookFired, 1) == 1 {
			close(pausedAt)
			<-resume
		}
	}
	t.Cleanup(func() { testHookDuringGetAndBorrow = nil })

	// Goroutine 1: resolve tenant A again (a warm positive-tenant-cache
	// hit), which calls getAndBorrow(poolA) and pauses inside it, still
	// holding r.mu, right after finding the entry but before reserving it.
	type resolveResult struct {
		h   Handle
		err error
	}
	resolveADone := make(chan resolveResult, 1)
	go func() {
		h, err := r.Resolve(context.Background(), tenantA)
		resolveADone <- resolveResult{h, err}
	}()
	<-pausedAt

	// While goroutine 1 is paused there, holding r.mu, try to evict pool A
	// by resolving tenant B (MaxPools=1 forces the eviction). This needs
	// r.mu too (see openNewPool), so it must genuinely block, not merely
	// be unlikely to race in — assert it does not complete within a
	// generous window.
	evictionDone := make(chan error, 1)
	go func() {
		_, err := r.Resolve(context.Background(), tenantB)
		evictionDone <- err
	}()

	select {
	case err := <-evictionDone:
		t.Fatalf("Resolve(tenantB) (the evicting call) completed = %v while goroutine 1 was paused inside "+
			"getAndBorrow holding r.mu; it must block until the mutex is released, not race ahead", err)
	case <-time.After(200 * time.Millisecond):
		// Expected: still blocked on r.mu.
	}

	// Let goroutine 1 finish reserving its reference, then let the
	// eviction proceed.
	close(resume)

	res := <-resolveADone
	if res.err != nil {
		t.Fatalf("Resolve(tenantA) error = %v, want nil", res.err)
	}
	if err := <-evictionDone; err != nil {
		t.Fatalf("Resolve(tenantB) error = %v, want nil", err)
	}

	// The crucial check: goroutine 1's reservation happened-before the
	// eviction (the eviction's own locked section could not even start
	// until resume was closed, since it needs the same r.mu goroutine 1
	// was holding), so pool A's entry must have been retired with an
	// outstanding reference, not closed outright. Check the exact *Pool
	// goroutine 1 was handed — not a fresh Resolve, which (since pool A
	// was just evicted from the cache) would trivially open a brand new
	// pool and pass regardless of whether this fix works.
	acquireCtx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, err := res.h.DB.Acquire(acquireCtx); errors.Is(err, puddle.ErrClosedPool) {
		t.Fatal("pool A's handle (the one goroutine 1 reserved) is already closed; getAndBorrow's atomic " +
			"lookup-and-reserve did not actually prevent the eviction from closing an entry just reserved")
	}
}
