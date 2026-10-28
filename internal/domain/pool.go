package domain

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"time"
)

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
	//
	// Its type carries half of that rule — DSN redacts itself through every
	// rendering — and Pool's own four methods below carry the other half,
	// for the case the type cannot reach.
	MetadataDSN DSN
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

// PoolRef is the part of a pool row a data-plane caller may see: identity,
// placement and capacity, but never MetadataDSN. It is the return type of
// pg.Scoped.Pool and the argument to a Credentials source, so neither a
// request handler nor a credential-extension implementation receives the
// long-lived password that dynamic credentials are meant to remove from the
// process.
type PoolRef struct {
	ID             PoolID
	Name           string
	Region         string
	BlobConfigRef  string
	WorkerCapacity int
	CreatedAt      time.Time
}

// Ref returns the credential-free view of p.
func (p Pool) Ref() PoolRef {
	return PoolRef{
		ID:             p.ID,
		Name:           p.Name,
		Region:         p.Region,
		BlobConfigRef:  p.BlobConfigRef,
		WorkerCapacity: p.WorkerCapacity,
		CreatedAt:      p.CreatedAt,
	}
}

// String renders the credential-free reference.
func (p PoolRef) String() string {
	return fmt.Sprintf("tenancy.PoolRef{ID: %s, Name: %q, Region: %q, BlobConfigRef: %q, WorkerCapacity: %d}",
		p.ID, p.Name, p.Region, p.BlobConfigRef, p.WorkerCapacity)
}

// Format honours every fmt verb through String.
func (p PoolRef) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, p.String()) }

// MarshalJSON renders String, so a PoolRef embedded in a response cannot
// accidentally grow a credential field later without updating this method.
func (p PoolRef) MarshalJSON() ([]byte, error) { return json.Marshal(p.String()) }

// LogValue is the structured-logging form.
func (p PoolRef) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("id", string(p.ID)),
		slog.String("name", p.Name),
		slog.String("region", p.Region),
		slog.String("blob_config_ref", p.BlobConfigRef),
		slog.Int("worker_capacity", p.WorkerCapacity),
	)
}

// String names the pool's id, name, region, blob configuration reference and
// worker capacity, and redacts its MetadataDSN. Those first five fields are
// the whole reason a pool row is worth logging; the sixth is a credential.
//
// Pool carries these four methods itself rather than leaving the redaction to
// the DSN type, and that is not belt-and-braces. A Pool reached through an
// *unexported* field — which is exactly how pg.Scoped and pool.poolEntry hold
// one — is a value fmt cannot take an interface of, so fmt abandons the method
// path for the whole subtree and prints it by raw reflection, DSN's own
// methods included. Measured: %+v on a struct holding a Pool unexported
// printed the password. See CONVENTIONS.md's "Rendering a secret".
func (p Pool) String() string {
	return fmt.Sprintf("tenancy.Pool{ID: %s, Name: %q, Region: %q, MetadataDSN: %s, BlobConfigRef: %q, WorkerCapacity: %d}",
		p.ID, p.Name, p.Region, p.MetadataDSN, p.BlobConfigRef, p.WorkerCapacity)
}

// Format implements fmt.Formatter, the only interface fmt consults for every
// verb. Without it, %#v, %d and %c reflect this struct and print the DSN.
func (p Pool) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, p.String()) }

// MarshalJSON renders the same summary as a JSON string. MetadataDSN is an
// exported field, so encoding/json reaches it directly, and slog's
// JSONHandler is built on encoding/json.
func (p Pool) MarshalJSON() ([]byte, error) { return json.Marshal(p.String()) }

// LogValue renders the pool as a slog group with the DSN redacted, so
// slog.Any("pool", p) is safe under every handler.
func (p Pool) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("pool_id", string(p.ID)),
		slog.String("name", p.Name),
		slog.String("region", p.Region),
		slog.String("metadata_dsn", Redacted),
		slog.String("blob_config_ref", p.BlobConfigRef),
		slog.Int("worker_capacity", p.WorkerCapacity),
		slog.Time("created_at", p.CreatedAt),
	)
}
