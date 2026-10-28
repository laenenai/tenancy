package pool_test

// Credential-driven pool retirement, tested without a database and without
// sleeping: the resolver's clock is injected, so "the lease is nearly up" is
// an advance of a FixedClock rather than a wait, and a *pgxpool.Pool over an
// unreachable DSN is a real pool object whose lifecycle can be asserted
// (see resolver_test.go's comment).
//
// What is deliberately NOT here is whether a credential issued by OpenBao
// actually works, stops working, or is subject to row-level security. That
// is a property of a real server and a real Postgres, and it is asserted
// against both in credentials/openbao's tests and in the conformance suite.
// These tests are about the mechanism: that an entry stops being handed out
// at the right moment, that its outstanding borrows drain first, that the
// credential is handed back only after the pool is actually closed, and that
// a credential too short-lived to drain inside is refused with an error that
// names the numbers.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/puddle/v2"

	"github.com/laenenai/tenancy/internal/domain"
	"github.com/laenenai/tenancy/internal/pool"
)

// fakeCredentials issues credentials with a fixed TTL off a test clock, and
// records what it issued and released.
//
// It also answers the one question about ordering that matters: whether the
// pool opened with a credential was already closed by the time that
// credential was released. Releasing first would revoke the login out from
// under connections still finishing their work, which is precisely the
// mid-transaction failure the whole arrangement exists to avoid, so the
// ordering is an invariant rather than an implementation detail.
type fakeCredentials struct {
	ttl   time.Duration
	clock domain.Clock

	mu       sync.Mutex
	n        int
	issued   []domain.Credential
	released []domain.Credential
	// poolFor maps a lease id to the *pgxpool.Pool opened with it, filled
	// in by the test's opener.
	poolFor map[string]*pgxpool.Pool
	// openAtRelease records lease ids whose pool was still open when
	// Release was called. It must stay empty.
	openAtRelease []string
	issueErr      error

	// releaseGate, when non-nil, blocks every Release until it is closed,
	// and inFlight/maxInFlight record how many were blocked at once. It is
	// how the shutdown test observes that releases overlap without having
	// to wait out a timeout to prove it.
	releaseGate chan struct{}
	inFlight    int
	maxInFlight int
}

func newFakeCredentials(ttl time.Duration, clock domain.Clock) *fakeCredentials {
	return &fakeCredentials{ttl: ttl, clock: clock, poolFor: make(map[string]*pgxpool.Pool)}
}

func (f *fakeCredentials) Issue(_ context.Context, _ domain.PoolRef) (domain.Credential, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.issueErr != nil {
		return domain.Credential{}, f.issueErr
	}
	if f.ttl <= 0 {
		// The static shape: no override, no expiry.
		return domain.Credential{}, nil
	}

	f.n++
	now := f.clock.Now()
	cred := domain.Credential{
		Username: fmt.Sprintf("v-token-test-%d", f.n),
		// Long enough that tenancytest's rendering subtest would accept
		// it, so this fake does not quietly differ from a real one.
		Password:  fmt.Sprintf("password-%d-aaaaaaaaaaaaaaaa", f.n),
		LeaseID:   fmt.Sprintf("lease-%d", f.n),
		IssuedAt:  domain.CanonicalTime(now),
		ExpiresAt: domain.CanonicalTime(now.Add(f.ttl)),
	}
	f.issued = append(f.issued, cred)
	return cred, nil
}

func (f *fakeCredentials) Release(ctx context.Context, cred domain.Credential) error {
	f.mu.Lock()
	db := f.poolFor[cred.LeaseID]
	f.mu.Unlock()

	stillOpen := false
	if db != nil {
		// Bounded tightly: against an open pool over an unreachable DSN
		// this Acquire would dial until the deadline, and the answer the
		// probe needs — puddle.ErrClosedPool or not — comes back
		// immediately when the pool is closed, which is the expected case.
		probeCtx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
		_, err := db.Acquire(probeCtx)
		cancel()
		stillOpen = !errors.Is(err, puddle.ErrClosedPool)
	}

	f.mu.Lock()
	f.released = append(f.released, cred)
	if stillOpen {
		f.openAtRelease = append(f.openAtRelease, cred.LeaseID)
	}
	gate := f.releaseGate
	if gate != nil {
		f.inFlight++
		if f.inFlight > f.maxInFlight {
			f.maxInFlight = f.inFlight
		}
	}
	f.mu.Unlock()

	if gate != nil {
		<-gate
		f.mu.Lock()
		f.inFlight--
		f.mu.Unlock()
	}
	return nil
}

func (f *fakeCredentials) counts() (issued, released int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.issued), len(f.released)
}

func (f *fakeCredentials) recordPool(cred domain.Credential, db *pgxpool.Pool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.poolFor[cred.LeaseID] = db
}

var _ domain.Credentials = (*fakeCredentials)(nil)

// retirementOpener builds a real lazily-connecting pool and tells creds which
// credential it was opened with, so the release-ordering invariant can be
// checked.
func retirementOpener(creds *fakeCredentials) pool.Opener {
	return func(ctx context.Context, p domain.Pool, cred domain.Credential) (*pgxpool.Pool, error) {
		cfg, err := pgxpool.ParseConfig(string(p.MetadataDSN))
		if err != nil {
			return nil, err
		}
		db, err := pgxpool.NewWithConfig(ctx, cfg)
		if err != nil {
			return nil, err
		}
		creds.recordPool(cred, db)
		return db, nil
	}
}

// retirementFixture wires one tenant on one pool with a credential source.
func retirementFixture(t *testing.T, ttl, lead time.Duration) (*pool.CachingResolver, *fakeCredentials, *domain.FixedClock, domain.TenantID) {
	t.Helper()

	clock := domain.NewFixedClock(time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC))
	creds := newFakeCredentials(ttl, clock)

	poolID := domain.NewPoolID(clock)
	tenantID := domain.NewTenantID(clock)
	reg := newFakeRegistry()
	reg.setPool(testPool(poolID, fakeDSN("retirement")))
	reg.setTenant(activeTenant(tenantID, poolID))

	r := pool.NewResolver(reg, retirementOpener(creds), pool.Options{
		TTL: time.Hour, NegativeTTL: time.Hour,
	}, pool.LifecycleOptions{
		Clock: clock, Credentials: creds, LongestTransaction: lead,
	})
	t.Cleanup(func() { _ = r.Close() })

	return r, creds, clock, tenantID
}

// TestResolve_RetiresAPoolBeforeItsCredentialExpires is the core of the
// mechanism: the entry stops being handed out one LongestTransaction before
// the credential expires, not at expiry and not after it.
//
// Expiry itself is no use as the deadline. Measured against real OpenBao and
// real Postgres, a credential's revocation closes no connection and the pool
// reports nothing; what happens instead is that a transaction touching a
// relation it had not already locked fails with 42501, poisons itself with
// 25P02, and has its COMMIT silently turned into a ROLLBACK. The lead time
// is the window that prevents that, so this test asserts both edges of it.
func TestResolve_RetiresAPoolBeforeItsCredentialExpires(t *testing.T) {
	const (
		ttl  = 60 * time.Second
		lead = 10 * time.Second
	)
	r, creds, clock, tenantID := retirementFixture(t, ttl, lead)
	ctx := context.Background()

	first := mustResolve(ctx, t, r, tenantID)

	// One second before the retirement is due, the same pool is still the
	// one being handed out: a resolver that retired early would churn a
	// pool per resolution.
	clock.Advance(ttl - lead - time.Second)
	stillFirst := mustResolve(ctx, t, r, tenantID)
	if stillFirst.DB != first.DB {
		t.Fatalf("the pool was replaced %s into a %s credential, with %s still to run before retirement is "+
			"due: a pool retired early serves nothing", ttl-lead-time.Second, ttl, time.Second)
	}
	if issued, _ := creds.counts(); issued != 1 {
		t.Errorf("%d credentials were issued, want 1: the pool was rebuilt before it had to be", issued)
	}

	// One second past it, the next resolution is on a new pool built on a
	// new credential.
	clock.Advance(2 * time.Second)
	second := mustResolve(ctx, t, r, tenantID)
	if second.DB == first.DB {
		t.Fatalf("the same pool was handed out %s into a %s credential, with only %s left before it expires. "+
			"A transaction starting now could still be running when the credential is revoked, and its "+
			"COMMIT would silently become a ROLLBACK", ttl-lead+time.Second, ttl, lead-time.Second)
	}

	issued, _ := creds.counts()
	if issued != 2 {
		t.Errorf("%d credentials were issued, want 2: the replacement pool must be built on a fresh "+
			"credential, not on the expiring one", issued)
	}
}

// TestResolve_RetiredPoolDrainsItsBorrowersBeforeClosing is the half that
// makes retirement safe rather than merely early.
//
// A resolution hands a caller a handle with no "I'm done" signal, so the
// retired pool cannot be closed when it is retired — only when the last
// borrower's context has finished. Closing it at retirement would cut off
// exactly the transactions the lead time exists to let finish.
func TestResolve_RetiredPoolDrainsItsBorrowersBeforeClosing(t *testing.T) {
	const (
		ttl  = 60 * time.Second
		lead = 10 * time.Second
	)
	r, creds, clock, tenantID := retirementFixture(t, ttl, lead)

	borrowerCtx, releaseBorrower := context.WithCancel(context.Background())
	defer releaseBorrower()

	first := mustResolve(borrowerCtx, t, r, tenantID)

	// Retirement falls due while that borrower is still holding its handle.
	clock.Advance(ttl - lead + time.Second)
	second := mustResolve(context.Background(), t, r, tenantID)
	if second.DB == first.DB {
		t.Fatal("the retired pool was handed out again")
	}

	// The retired pool is still open, because its borrower has not
	// finished. This is the assertion a caller's in-flight transaction
	// depends on.
	assertNotClosed(t, first.DB)
	if _, released := creds.counts(); released != 0 {
		t.Errorf("%d credentials were released while a borrower was still holding the pool: revoking the "+
			"login under a running transaction is the failure the drain window exists to prevent", released)
	}

	// Once it finishes, the pool closes and only then is the credential
	// handed back.
	releaseBorrower()
	assertEventuallyClosed(t, first.DB)

	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, released := creds.counts(); released == 1 {
			break
		}
		if time.Now().After(deadline) {
			_, released := creds.counts()
			t.Fatalf("%d credentials were released after the retired pool closed, want 1: a credential "+
				"nothing is using any more should be handed back rather than waited out", released)
		}
		time.Sleep(10 * time.Millisecond)
	}

	creds.mu.Lock()
	openAtRelease := append([]string(nil), creds.openAtRelease...)
	creds.mu.Unlock()
	if len(openAtRelease) != 0 {
		t.Errorf("credentials %v were released while their pool was still open: the order is forced, "+
			"because revoking first would revoke the login under connections still finishing their work",
			openAtRelease)
	}
}

// TestResolve_RefusesACredentialTooShortLivedToDrainIn is the TTL floor, and
// it is a validated configuration constraint rather than a doc comment
// because the consequence of getting it wrong is a write the application
// believes succeeded.
func TestResolve_RefusesACredentialTooShortLivedToDrainIn(t *testing.T) {
	// 15s of life against a 10s drain window: the pool would be retired 5s
	// after it was built, having served new work for a third of its
	// credential's life.
	r, _, _, tenantID := retirementFixture(t, 15*time.Second, 10*time.Second)

	_, err := r.Resolve(context.Background(), tenantID)
	if !errors.Is(err, domain.ErrInvalidConfig) {
		t.Fatalf("Resolve error = %v, want ErrInvalidConfig: a credential that cannot be drained inside is "+
			"a deployment mistake, and retrying will not fix it", err)
	}

	// The error has to be actionable, not merely typed: an operator reading
	// it needs to know what was issued, what this deployment requires, and
	// which of the two to change.
	for _, want := range []string{"15s", "10s", "20s", "LongestTransaction"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not mention %q, so it does not say what to change:\n%v", want, err)
		}
	}
}

// TestResolve_RefusesAnExpiringCredentialWithNoLeadTimeConfigured covers the
// other half of the same constraint, for a resolver built directly rather
// than through tenancy.Open — which refuses this at configuration time.
func TestResolve_RefusesAnExpiringCredentialWithNoLeadTimeConfigured(t *testing.T) {
	r, _, _, tenantID := retirementFixture(t, time.Hour, 0)

	_, err := r.Resolve(context.Background(), tenantID)
	if !errors.Is(err, domain.ErrInvalidConfig) {
		t.Fatalf("Resolve error = %v, want ErrInvalidConfig", err)
	}
	if !strings.Contains(err.Error(), "LongestTransaction") {
		t.Errorf("the error does not name the missing setting:\n%v", err)
	}
}

// TestResolve_AnIssuerFailureIsNotCached asserts that a credential source
// that is down fails the resolution and leaves nothing behind: the next
// resolution must try again rather than serve a cached refusal.
func TestResolve_AnIssuerFailureIsNotCached(t *testing.T) {
	r, creds, _, tenantID := retirementFixture(t, time.Hour, time.Minute)
	ctx := context.Background()

	creds.mu.Lock()
	creds.issueErr = fmt.Errorf("%w: openbao is not reachable", domain.ErrUnavailable)
	creds.mu.Unlock()

	if _, err := r.Resolve(ctx, tenantID); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("Resolve error = %v, want the issuer's ErrUnavailable to propagate unmasked", err)
	}

	creds.mu.Lock()
	creds.issueErr = nil
	creds.mu.Unlock()

	if _, err := r.Resolve(ctx, tenantID); err != nil {
		t.Fatalf("Resolve after the issuer recovered error = %v, want nil: a failure to issue must not be "+
			"remembered as a fact about the tenant", err)
	}
}

// TestResolve_StaticCredentialsNeverRetireAPool is the default path, and the
// assertion is that it is unchanged: no expiry, so no retirement, however
// much time passes.
func TestResolve_StaticCredentialsNeverRetireAPool(t *testing.T) {
	// ttl == 0 makes the fake issue the zero Credential, which is what
	// domain.StaticDSNCredentials returns. lead is left unset too, because
	// a deployment with no expiring credential is not required to declare
	// one.
	r, creds, clock, tenantID := retirementFixture(t, 0, 0)
	ctx := context.Background()

	first := mustResolve(ctx, t, r, tenantID)
	clock.Advance(365 * 24 * time.Hour)
	again := mustResolve(ctx, t, r, tenantID)

	if again.DB != first.DB {
		t.Fatal("a pool connected on its registry row's own credential was retired after a year. There is " +
			"no expiry to retire it against, and replacing it would be churning pools for nothing")
	}
	if issued, released := creds.counts(); issued != 0 || released != 0 {
		t.Errorf("issued=%d released=%d for a static source, want 0 and 0", issued, released)
	}
}

// TestClose_HandsBackEveryCredentialConcurrently covers the shutdown path.
//
// Two things are asserted and the second is the one that needed the code to
// change. Every credential is handed back, because a process going away
// should not leave live logins behind for their leases to time out. And the
// releases overlap, because serially — with one timeout each — an
// unreachable issuer would make shutdown take that timeout times the number
// of pools ever opened, which is unbounded by default. That turns a
// best-effort cleanup into minutes of hang in exactly the situation nobody
// is watching.
//
// The overlap is observed by blocking every Release and waiting for two to
// be in flight at once, rather than by timing a shutdown against an
// unreachable issuer — which would mean waiting out a real timeout to prove
// a point about waiting out real timeouts.
func TestClose_HandsBackEveryCredentialConcurrently(t *testing.T) {
	clock := domain.NewFixedClock(time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC))
	creds := newFakeCredentials(time.Hour, clock)
	creds.releaseGate = make(chan struct{})

	reg := newFakeRegistry()
	var tenantIDs [2]domain.TenantID
	for i := range tenantIDs {
		poolID := domain.NewPoolID(clock)
		tenantIDs[i] = domain.NewTenantID(clock)
		reg.setPool(testPool(poolID, fakeDSN("close-release")))
		reg.setTenant(activeTenant(tenantIDs[i], poolID))
	}

	r := pool.NewResolver(reg, retirementOpener(creds), pool.Options{
		TTL: time.Hour, NegativeTTL: time.Hour,
	}, pool.LifecycleOptions{
		Clock: clock, Credentials: creds, LongestTransaction: time.Minute,
	})

	ctx := context.Background()
	for _, id := range tenantIDs {
		mustResolve(ctx, t, r, id)
	}

	closed := make(chan error, 1)
	go func() { closed <- r.Close() }()

	deadline := time.Now().Add(2 * time.Second)
	for {
		creds.mu.Lock()
		peak := creds.maxInFlight
		creds.mu.Unlock()
		if peak >= 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("at most %d credential release was in flight at a time while closing two pools. "+
				"Serially, with one timeout each, an unreachable issuer makes shutdown take that timeout "+
				"times the number of pools", peak)
		}
		time.Sleep(5 * time.Millisecond)
	}

	close(creds.releaseGate)
	if err := <-closed; err != nil {
		t.Fatalf("Close: %v", err)
	}

	if _, released := creds.counts(); released != 2 {
		t.Errorf("%d credentials were handed back on shutdown, want 2", released)
	}
}

func TestClose_WaitsForAnInFlightBackgroundClose(t *testing.T) {
	clock := domain.NewFixedClock(time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC))
	creds := newFakeCredentials(time.Hour, clock)
	creds.releaseGate = make(chan struct{})

	reg := newFakeRegistry()
	poolA := domain.NewPoolID(clock)
	poolB := domain.NewPoolID(clock)
	tenantA := domain.NewTenantID(clock)
	tenantB := domain.NewTenantID(clock)
	reg.setPool(testPool(poolA, fakeDSN("close-a")))
	reg.setPool(testPool(poolB, fakeDSN("close-b")))
	reg.setTenant(activeTenant(tenantA, poolA))
	reg.setTenant(activeTenant(tenantB, poolB))

	r := pool.NewResolver(reg, retirementOpener(creds), pool.Options{
		TTL: time.Hour, NegativeTTL: time.Hour, MaxPools: 1,
	}, pool.LifecycleOptions{Clock: clock, Credentials: creds, LongestTransaction: time.Minute})

	ctxA, cancelA := context.WithCancel(context.Background())
	mustResolve(ctxA, t, r, tenantA)
	mustResolve(context.Background(), t, r, tenantB) // evicts A
	cancelA()                                        // A's last borrow release starts a background close

	deadline := time.Now().Add(2 * time.Second)
	for {
		creds.mu.Lock()
		inFlight := creds.inFlight
		creds.mu.Unlock()
		if inFlight > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the background close did not start")
		}
		time.Sleep(time.Millisecond)
	}

	closed := make(chan error, 1)
	go func() { closed <- r.Close() }()
	select {
	case err := <-closed:
		t.Fatalf("Close returned while a background close was still blocked: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	close(creds.releaseGate)
	if err := <-closed; err != nil {
		t.Fatalf("Close: %v", err)
	}
}
