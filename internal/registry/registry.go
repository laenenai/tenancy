// Package registry is the control plane: the only code in this module that
// reads or writes the tenant and pool tables, and the one path that runs
// unscoped SQL against them.
//
// # Why Control exposes no method that takes SQL
//
// Resolution has to read a tenancy.tenants row *before* any tenant session
// context exists — it is what establishes that context for everything
// downstream, not a consumer of it. So the registry tables carry no
// row-level-security policy (see db/migrations/00001_registry.sql), and
// there is therefore nothing behind them to catch a mistake. The charter's
// answer is that this path must be small, auditable, and never reachable
// with caller-supplied predicates.
//
// "Never reachable with caller-supplied predicates" is made true by the
// type rather than by review: Control has no Exec, no Query, no QueryRow
// and no Begin. Every one of its methods takes typed domain values and
// runs one of the seven statements in db/queries, which are fixed at
// generation time by sqlc. There is no way to express a different
// predicate through it.
//
// The data plane is the mirror image: internal/pg.Scoped takes arbitrary
// SQL and nothing else, and every statement it runs is inside a
// transaction whose tenant context is already set. Neither type can stand
// where the other is expected — they are distinct structs with unexported
// fields, so no conversion exists in either direction. See
// testdata/control_plane_is_not_a_data_plane_handle.go, which the compiler
// is required to reject.
//
// # Why the generated layer is sqlc rather than hand-written SQL
//
// The SQL is the load-bearing artefact here, which is the case *for* sqlc
// and not against it: db/queries/*.sql is where a reviewer reads it as
// SQL, with the reasoning for each statement beside it, checked against
// the schema at generation time. The two places this module hand-writes
// SQL are the catalog probes in internal/pg, which sqlc cannot generate at
// all, and they say so where they are written.
package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/laenenai/tenancy/internal/domain"
	"github.com/laenenai/tenancy/internal/pg"
	"github.com/laenenai/tenancy/internal/registry/gen"
)

// Control is the control-plane handle: the registry, and nothing else.
//
// It is safe for concurrent use. Close releases the connection pool behind
// it; a method called afterwards is refused with domain.ErrUnavailable
// rather than panicking.
type Control struct {
	pool           *pgxpool.Pool
	queries        *gen.Queries
	clock          domain.Clock
	onStatusChange func(domain.TenantID, domain.TenantStatus)
}

// Config is what Open needs to reach the registry.
type Config struct {
	// DSN is the registry database's connection string, on the *runtime*
	// credential — the application role — and not on the migration one.
	// See internal/migrate's package doc comment for the two-pool model.
	//
	// Required.
	DSN domain.DSN

	// Postgres tunes the control-plane pool. The control plane is
	// read-mostly and low-volume, so a small MaxConns is appropriate; the
	// field exists because a deployment knows its own shape.
	Postgres pg.PoolConfig

	// Clock is used to canonicalize the timestamps rows carry. Zero means
	// domain.SystemClock. It is here rather than read from time.Now so a
	// test can pin an instant.
	Clock domain.Clock
}

// Open connects to the registry and returns the control-plane handle.
//
// It does not migrate. Applying the registry schema is a separate activity
// on a separate credential (internal/migrate.Up), and conflating the two
// would mean this pool held the migration rights for the life of the
// process.
func Open(ctx context.Context, cfg Config) (*Control, error) {
	if cfg.DSN.IsZero() {
		return nil, fmt.Errorf(
			"%w: registry: DSN is required: it is the control plane's connection to the registry database",
			domain.ErrInvalidConfig)
	}

	pool, err := pg.Open(ctx, cfg.DSN, cfg.Postgres)
	if err != nil {
		return nil, err
	}

	clock := cfg.Clock
	if clock == nil {
		clock = domain.SystemClock{}
	}

	return &Control{pool: pool, queries: gen.New(pool), clock: clock}, nil
}

// SetTenantStatusObserver installs the callback invoked after a successful
// status change. The composition layer uses it to invalidate the resolver's
// positive cache immediately; a Control used standalone may leave it nil.
func (c *Control) SetTenantStatusObserver(fn func(domain.TenantID, domain.TenantStatus)) {
	c.onStatusChange = fn
}

// Close releases the control-plane connection pool. It is idempotent.
func (c *Control) Close() {
	if c.pool != nil {
		c.pool.Close()
	}
}

// PoolSpec is the input to CreatePool: everything about a pool that is not
// derived.
type PoolSpec struct {
	// ID, when empty, is minted from the configured clock. A caller
	// supplies one only when it is reconstructing a known pool.
	ID domain.PoolID
	// Name is the pool's globally unique, human-assigned name.
	Name string
	// Region names the deployment region, which is what makes residency a
	// placement decision rather than a policy check.
	Region string
	// MetadataDSN is the pool's Postgres connection string on the
	// application role. It is never logged and never embedded in an error.
	MetadataDSN domain.DSN
	// BlobConfigRef names the blob store configuration, as a reference.
	BlobConfigRef string
	// WorkerCapacity bounds concurrent background jobs in this pool.
	WorkerCapacity int
}

// TenantSpec is the input to CreateTenant.
type TenantSpec struct {
	// ID, when empty, is minted from the configured clock.
	ID domain.TenantID
	// PoolID names the pool that will host this tenant's metadata. It
	// must already exist: the foreign key refuses otherwise, as
	// domain.ErrConflict.
	PoolID domain.PoolID
	// Name is the tenant's globally unique, human-assigned name.
	Name string
	// SecurityMode is immutable after this write. There is no method in
	// this module that could change it, and the schema carries a trigger
	// that refuses any statement that tries.
	SecurityMode domain.SecurityMode
	// Status is the tenant's initial lifecycle state. Zero means
	// domain.TenantStatusActive.
	Status domain.TenantStatus
}

// CreatePool registers a pool.
func (c *Control) CreatePool(ctx context.Context, in PoolSpec) (domain.Pool, error) {
	if in.ID == "" {
		id, err := domain.NewPoolIDErr(c.clock)
		if err != nil {
			return domain.Pool{}, err
		}
		in.ID = id
	} else if _, err := domain.ParsePoolID(string(in.ID)); err != nil {
		// A write boundary, so ErrMalformedID is the honest answer: the
		// caller is supplying a new id, not asking the registry to resolve
		// one, so no existence question is being answered. Contrast
		// PoolByID. See internal/domain/errors.go.
		return domain.Pool{}, err
	}
	if in.Name == "" {
		return domain.Pool{}, fmt.Errorf("%w: registry: a pool needs a name", domain.ErrInvalidConfig)
	}
	if in.Region == "" {
		return domain.Pool{}, fmt.Errorf("%w: registry: a pool needs a region: it is what makes residency a placement decision", domain.ErrInvalidConfig)
	}
	if in.MetadataDSN.IsZero() {
		return domain.Pool{}, fmt.Errorf("%w: registry: a pool needs a metadata DSN", domain.ErrInvalidConfig)
	}
	if in.WorkerCapacity < 0 {
		return domain.Pool{}, fmt.Errorf("%w: registry: worker capacity must not be negative", domain.ErrInvalidConfig)
	}
	const maxInt32 = int(^uint32(0) >> 1)
	if in.WorkerCapacity > maxInt32 {
		return domain.Pool{}, fmt.Errorf("%w: registry: worker capacity %d exceeds the PostgreSQL integer range", domain.ErrInvalidConfig, in.WorkerCapacity)
	}

	row, err := c.queries.CreatePool(ctx, gen.CreatePoolParams{
		ID:             in.ID,
		Name:           in.Name,
		Region:         in.Region,
		MetadataDsn:    string(in.MetadataDSN),
		BlobConfigRef:  in.BlobConfigRef,
		WorkerCapacity: int32(in.WorkerCapacity), //nolint:gosec // bounded above by the non-negative check and by the column's integer width
	})
	if err != nil {
		return domain.Pool{}, mapErr("create pool", err)
	}
	return c.poolFrom(row), nil
}

// PoolByID returns the pool with this id.
//
// An unknown id, and a malformed one, are both
// domain.ErrNotAuthorizedOrNotFound. The malformed case matters: this is a
// lookup-by-id path, and a caller able to tell "well-formed but invisible"
// apart from "nonsense" has an existence oracle on the id space.
func (c *Control) PoolByID(ctx context.Context, id domain.PoolID) (domain.Pool, error) {
	if _, err := domain.ParsePoolID(string(id)); err != nil {
		return domain.Pool{}, domain.ErrNotAuthorizedOrNotFound
	}

	row, err := c.queries.PoolByID(ctx, id)
	if err != nil {
		return domain.Pool{}, mapErr("read pool", err)
	}
	return c.poolFrom(row), nil
}

// PoolByName returns the pool with this name. It is an operator path: a
// name is something a human typed, so an unknown one is still
// domain.ErrNotAuthorizedOrNotFound rather than a distinguishable "no such
// pool".
func (c *Control) PoolByName(ctx context.Context, name string) (domain.Pool, error) {
	row, err := c.queries.PoolByName(ctx, name)
	if err != nil {
		return domain.Pool{}, mapErr("read pool by name", err)
	}
	return c.poolFrom(row), nil
}

// CreateTenant registers a tenant in a pool that must already exist.
func (c *Control) CreateTenant(ctx context.Context, in TenantSpec) (domain.Tenant, error) {
	if in.ID == "" {
		id, err := domain.NewTenantIDErr(c.clock)
		if err != nil {
			return domain.Tenant{}, err
		}
		in.ID = id
	} else if _, err := domain.ParseTenantID(string(in.ID)); err != nil {
		return domain.Tenant{}, err
	}
	if _, err := domain.ParsePoolID(string(in.PoolID)); err != nil {
		return domain.Tenant{}, fmt.Errorf("%w: registry: a tenant needs the pool that hosts it: %w", domain.ErrInvalidConfig, err)
	}
	if in.Name == "" {
		return domain.Tenant{}, fmt.Errorf("%w: registry: a tenant needs a name", domain.ErrInvalidConfig)
	}
	if !in.SecurityMode.Valid() {
		return domain.Tenant{}, fmt.Errorf("%w: registry: %q is not a security mode: it is immutable after this write, so it is checked before it is stored",
			domain.ErrInvalidConfig, in.SecurityMode)
	}
	if in.Status == "" {
		in.Status = domain.TenantStatusActive
	}
	if !in.Status.Valid() {
		return domain.Tenant{}, fmt.Errorf("%w: registry: %q is not a tenant status", domain.ErrInvalidConfig, in.Status)
	}

	row, err := c.queries.CreateTenant(ctx, gen.CreateTenantParams{
		ID:           in.ID,
		PoolID:       in.PoolID,
		Name:         in.Name,
		SecurityMode: in.SecurityMode,
		Status:       in.Status,
	})
	if err != nil {
		return domain.Tenant{}, mapErr("create tenant", err)
	}
	return c.tenantFrom(row), nil
}

// TenantByID returns the tenant with this id. It is the query every
// tenant-scoped request makes before it touches a connection.
//
// An unknown id and a malformed one are both
// domain.ErrNotAuthorizedOrNotFound; see PoolByID.
func (c *Control) TenantByID(ctx context.Context, id domain.TenantID) (domain.Tenant, error) {
	if _, err := domain.ParseTenantID(string(id)); err != nil {
		return domain.Tenant{}, domain.ErrNotAuthorizedOrNotFound
	}

	row, err := c.queries.TenantByID(ctx, id)
	if err != nil {
		return domain.Tenant{}, mapErr("read tenant", err)
	}
	return c.tenantFrom(row), nil
}

// TenantByName returns the tenant with this name.
func (c *Control) TenantByName(ctx context.Context, name string) (domain.Tenant, error) {
	row, err := c.queries.TenantByName(ctx, name)
	if err != nil {
		return domain.Tenant{}, mapErr("read tenant by name", err)
	}
	return c.tenantFrom(row), nil
}

// SetTenantStatus moves a tenant between lifecycle states: suspending it,
// restoring it, or marking it for deletion.
//
// It is the only UPDATE in this module, and it cannot reach security_mode
// — see db/queries/tenants.sql, where that is visible in the statement
// itself rather than inferred from this method.
//
// A caller that has a resolver in front of this must expect a cached
// resolution to outlive the change by up to its configured TTL. That is
// the documented contract, with one exception: a suspended tenant's result
// is never cached in either direction, because unsuspending is an operator
// action that should take effect on the very next call.
func (c *Control) SetTenantStatus(ctx context.Context, id domain.TenantID, status domain.TenantStatus) (domain.Tenant, error) {
	if _, err := domain.ParseTenantID(string(id)); err != nil {
		return domain.Tenant{}, domain.ErrNotAuthorizedOrNotFound
	}
	if !status.Valid() {
		return domain.Tenant{}, fmt.Errorf("%w: registry: %q is not a tenant status", domain.ErrInvalidConfig, status)
	}

	row, err := c.queries.SetTenantStatus(ctx, gen.SetTenantStatusParams{ID: id, Status: status})
	if err != nil {
		return domain.Tenant{}, mapErr("set tenant status", err)
	}
	if c.onStatusChange != nil {
		c.onStatusChange(id, status)
	}
	return c.tenantFrom(row), nil
}

// poolFrom converts a generated row into the domain value, canonicalizing
// its timestamp. The typed ids arrive already typed, which is what the
// sqlc overrides are for.
func (c *Control) poolFrom(row gen.TenancyPool) domain.Pool {
	return domain.Pool{
		ID:             row.ID,
		Name:           row.Name,
		Region:         row.Region,
		MetadataDSN:    domain.DSN(row.MetadataDsn),
		BlobConfigRef:  row.BlobConfigRef,
		WorkerCapacity: int(row.WorkerCapacity),
		CreatedAt:      domain.CanonicalTime(row.CreatedAt),
	}
}

func (c *Control) tenantFrom(row gen.TenancyTenant) domain.Tenant {
	return domain.Tenant{
		ID:           row.ID,
		PoolID:       row.PoolID,
		Name:         row.Name,
		SecurityMode: row.SecurityMode,
		Status:       row.Status,
		CreatedAt:    domain.CanonicalTime(row.CreatedAt),
	}
}

// mapErr maps what Postgres and pgx report onto this module's taxonomy.
//
// It never forwards the underlying error's own text. That rule exists for
// one concrete reason here: tenancy.pools.metadata_dsn is a credential,
// and a constraint violation's Detail carries the offending row's values.
// A mapper that appended the Postgres message would turn any conflict on
// that table into a credential disclosure in a log line. The same rule
// costs nothing on the other paths, so it is applied uniformly rather than
// per-column, and what is in `what` is this module's own fixed string.
func mapErr(what string, err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrNotAuthorizedOrNotFound
	}

	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505": // unique_violation: a duplicate pool or tenant name
			return fmt.Errorf("%w: %s: that name is already taken", domain.ErrConflict, what)
		case "23503": // foreign_key_violation: a tenant naming a pool that does not exist
			return fmt.Errorf("%w: %s: the pool it refers to does not exist", domain.ErrConflict, what)
		case "23514": // check_violation: a value outside a closed set reached the column
			return fmt.Errorf("%w: %s: a value was rejected by the schema's own constraint", domain.ErrInvalidConfig, what)
		case "P0001": // raise_exception: the security_mode or status-transition trigger
			return fmt.Errorf("%w: %s: the schema refused the change", domain.ErrConflict, what)
		case "42501": // insufficient_privilege
			return fmt.Errorf("%w: %s: the role does not hold the privilege for this statement", domain.ErrPermission, what)
		}
	}

	return fmt.Errorf("%w: %s", domain.ErrUnavailable, what)
}

// String names the pool being created and redacts its MetadataDSN. PoolSpec is
// the value a consumer builds by hand and is therefore the value most likely
// to appear in its own logging around CreatePool — see CONVENTIONS.md's
// "Rendering a secret".
func (in PoolSpec) String() string {
	return fmt.Sprintf("tenancy.PoolSpec{ID: %s, Name: %q, Region: %q, MetadataDSN: %s, BlobConfigRef: %q, WorkerCapacity: %d}",
		in.ID, in.Name, in.Region, in.MetadataDSN, in.BlobConfigRef, in.WorkerCapacity)
}

// Format implements fmt.Formatter, the only interface fmt consults for every
// verb.
func (in PoolSpec) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, in.String()) }

// MarshalJSON renders the same summary as a JSON string.
func (in PoolSpec) MarshalJSON() ([]byte, error) { return json.Marshal(in.String()) }

// LogValue renders the request as a slog group with the metadata DSN
// redacted.
func (in PoolSpec) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("pool_id", string(in.ID)),
		slog.String("name", in.Name),
		slog.String("region", in.Region),
		slog.String("metadata_dsn", domain.Redacted),
		slog.String("blob_config_ref", in.BlobConfigRef),
		slog.Int("worker_capacity", in.WorkerCapacity),
	)
}
