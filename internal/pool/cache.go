package pool

import (
	"container/list"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/laenenai/tenancy/internal/domain"
)

// poolEntry is one cached *pgxpool.Pool, shared by every tenant whose
// tenancy.tenants.pool_id names the same domain.Pool. It is reference
// counted because a resolution hands a caller a handle with no "I'm done"
// signal: a handle can outlive the LRU slot that produced it, so eviction
// must never close a pool a caller might still be querying.
//
// refs starts at 1, owned by the cache's own slot in lru. Each resolution
// that hands this entry to a caller adds one more ref, tied to that
// caller's context (see CachingResolver.borrow): the ref is released when
// the caller's context finishes, or never, if the caller passes a context
// that never does — in that case the pool is conservatively kept open
// rather than guessed to be safe to close.
//
// retired is set once the entry falls out of the LRU (evicted, or the
// resolver closed). The underlying *pgxpool.Pool is only actually closed
// once retired is true AND refs has dropped to zero: every ref — the
// cache's own and every outstanding borrow — must be released first.
//
// All fields are guarded by the owning CachingResolver's mutex.
type poolEntry struct {
	pool domain.Pool
	db   *pgxpool.Pool

	refs    int
	retired bool
	closed  bool
}

// positiveTenantEntry is a cached "this pool hosts this tenant"
// resolution, expiring after Options.TTL.
type positiveTenantEntry struct {
	expiresAt time.Time
	tenant    domain.Tenant
}

// negativeTenantEntry is a cached "unknown or deleting" resolution,
// expiring after the shorter Options.NegativeTTL. It carries no tenant
// data: there is nothing to cache beyond the fact, and the expiry.
type negativeTenantEntry struct {
	expiresAt time.Time
}

// lru is a least-recently-used cache bounded by maxLen (maxLen <= 0 means
// unbounded). It holds no lock of its own: every method here is called
// only while the owning CachingResolver's mutex is held.
//
// It is used for three independent caches in this package — pools by
// PoolID, and positive and negative tenant resolutions by TenantID, each
// in its own lru instance — specifically so that pressure in one can never
// evict entries from another. See CachingResolver's doc comment for why
// positive and negative tenant entries in particular must never share an
// eviction budget.
type lru[K comparable, V any] struct {
	maxLen int
	byKey  map[K]*list.Element // Value is *lruItem[K, V]
	order  *list.List          // front = most recently used
}

type lruItem[K comparable, V any] struct {
	key K
	val V
}

func newLRU[K comparable, V any](maxLen int) *lru[K, V] {
	return &lru[K, V]{
		maxLen: maxLen,
		byKey:  make(map[K]*list.Element),
		order:  list.New(),
	}
}

// get returns the cached value for key, bumping it to most-recently-used.
func (c *lru[K, V]) get(key K) (V, bool) {
	elem, ok := c.byKey[key]
	if !ok {
		var zero V
		return zero, false
	}
	c.order.MoveToFront(elem)
	return elem.Value.(*lruItem[K, V]).val, true //nolint:forcetypeassert // only *lruItem[K, V] is ever stored
}

// put inserts val under key. If that would put the cache over maxLen, it
// evicts the least-recently-used entry and returns it; otherwise ok is
// false.
//
// Eviction policy: least-recently-used. An entry nothing has asked for
// recently is the one a sudden burst of new keys is least likely to need
// again immediately, so LRU bounds memory without having to guess at
// per-key traffic.
func (c *lru[K, V]) put(key K, val V) (evictedKey K, evictedVal V, ok bool) {
	elem := c.order.PushFront(&lruItem[K, V]{key: key, val: val})
	c.byKey[key] = elem

	if c.maxLen <= 0 || c.order.Len() <= c.maxLen {
		return evictedKey, evictedVal, false
	}

	back := c.order.Back()
	item, _ := back.Value.(*lruItem[K, V]) //nolint:forcetypeassert // only *lruItem[K, V] is ever stored
	c.order.Remove(back)
	delete(c.byKey, item.key)
	return item.key, item.val, true
}

// all returns every value currently cached, most-recently-used first.
func (c *lru[K, V]) all() []V {
	values := make([]V, 0, c.order.Len())
	for e := c.order.Front(); e != nil; e = e.Next() {
		values = append(values, e.Value.(*lruItem[K, V]).val) //nolint:forcetypeassert // only *lruItem[K, V] is ever stored
	}
	return values
}

// clear empties the cache without doing anything to the values it held;
// the caller is responsible for anything that needs releasing in what all
// returned beforehand.
func (c *lru[K, V]) clear() {
	c.byKey = make(map[K]*list.Element)
	c.order.Init()
}
