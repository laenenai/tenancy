package domain

import "time"

// Pool identifies one physical Postgres database that hosts the metadata
// of one or more tenants, together with the region it lives in and the
// capacity its workers have.
//
// A pool's name is globally unique and never derived from tenant data, so
// listing or resolving a pool never carries tenant information across the
// pool/tenant boundary.
//
// The pool is what makes "pooled", "isolated" and "pool set" one mechanism
// rather than three code paths (CAS design §14.1): a pool holds one tenant
// (isolated), many tenants (pooled), or a cohort grouped by something that
// matters — region, compliance regime, service tier, one large customer
// and its subsidiaries. Residency lands here too: "this tenant's bytes
// never leave the EU" becomes "this tenant lives in an EU pool", enforced
// by construction rather than by policy checks scattered through callers.
type Pool struct {
	// ID identifies this pool.
	ID PoolID
	// Name is the pool's human-assigned, globally unique name.
	Name string
	// Region names the deployment region this pool's Postgres instance
	// lives in, which is what makes residency a placement decision.
	Region string
	// MetadataDSN is the connection string for this pool's Postgres
	// database, on the *application* role — not the migration role. See
	// the package doc comment of internal/migrate for the two-pool model.
	//
	// Like any DSN it may carry a password. It must never be logged or
	// embedded in an error: internal/pg.Open is the one place that
	// touches it, and it is audited for exactly that. See
	// TestResolve_NeverLeaksMetadataDSN.
	MetadataDSN string
	// BlobConfigRef names the blob store configuration this pool's
	// tenants use — a reference, not the configuration itself, because
	// blob storage is no business of this module's.
	BlobConfigRef string
	// WorkerCapacity bounds how many concurrent background jobs this
	// pool's workers may run. `tenancy` records it and never reads it:
	// noisy-neighbour control belongs to whoever runs the jobs.
	WorkerCapacity int
	// CreatedAt is when the pool was created, canonicalized to UTC
	// microseconds (see CanonicalTime).
	CreatedAt time.Time
}
