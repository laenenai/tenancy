// Package pg is the only place in this module that opens a Postgres
// connection, and the only place that establishes row-level-security
// session context. It owns both sides of the charter's asymmetry at the
// level of connection mechanics:
//
//   - Open builds a *pgxpool.Pool. It is used for the short-lived
//     migration pool, for the control-plane pool behind the registry, and
//     for each pool the resolver opens. The pool itself is just a pool.
//   - Scoped is the data-plane handle: one resolved tenant, and the only
//     path in this module through which caller-supplied SQL can reach a
//     database. Every statement it runs is inside a transaction that has
//     already set the tenant GUC, and optionally narrowed itself to the
//     application role.
//
// The control-plane handle is deliberately NOT in this package: it is
// internal/registry.Control, and it exposes no method that takes SQL at
// all. That is what makes the charter's "must never be reachable with
// caller-supplied predicates" a property of the type rather than of
// reviewer attention — there is no row security behind the registry tables
// to catch a mistake, because resolution has to read them before any
// tenant context exists.
package pg

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/laenenai/tenancy/internal/domain"
)

// defaultConnectTimeout bounds Open's initial connect-and-ping when the
// caller does not set one.
const defaultConnectTimeout = 5 * time.Second

// PoolConfig tunes a connection pool. Every field is optional: the zero
// value opens a pool with pgx's own defaults and a five-second connect
// timeout.
type PoolConfig struct {
	// MaxConns and MinConns bound the pool. Zero means pgx's own default
	// for each.
	MaxConns int32
	MinConns int32

	// MaxConnLifetime and MaxConnIdleTime bound how long a pooled
	// connection is kept before being recycled. Zero means pgx's own
	// default for each.
	MaxConnLifetime time.Duration
	MaxConnIdleTime time.Duration

	// ConnectTimeout bounds how long Open waits to establish and verify
	// the initial connection. Zero means defaultConnectTimeout.
	ConnectTimeout time.Duration

	// ApplicationName is reported to Postgres as application_name, visible
	// in pg_stat_activity and the server log. Worth setting: it is how an
	// operator tells a tenancy-opened connection from a consumer's own.
	ApplicationName string

	// Tracer, when non-nil, is installed as the pgx.QueryTracer on every
	// connection this pool opens — which is this module's whole answer to
	// "tracing on the connection".
	//
	// It is a seam rather than a built-in OpenTelemetry tracer, and that
	// is a deliberate departure from `cas`, which hard-wired
	// github.com/exaring/otelpgx. A library that picks a tracing
	// implementation picks an OpenTelemetry version for every consumer
	// that imports it, and this module is imported by three systems that
	// have no reason to agree on one. A consumer that wants OTel passes
	// otelpgx.NewTracer() here in one line; one that wants nothing passes
	// nothing and links nothing.
	Tracer pgx.QueryTracer

	// AfterConnect, when non-nil, runs once per physical connection the
	// pool opens, before that connection is used.
	//
	// It is the other seam `cas` hard-wired: its Open registered pgvector's
	// Go type codecs on every connection. Registering a consumer's type
	// codecs is the consumer's business, and the extension it needs is a
	// fact about the consumer's schema, not about tenancy's. A consumer
	// that needs pgvector registers it here.
	AfterConnect func(ctx context.Context, conn *pgx.Conn) error
}

// Open builds a connection pool for dsn, applying cfg, and verifies
// connectivity with a single ping bounded by cfg.ConnectTimeout.
//
// It never retries internally. A malformed DSN fails immediately wrapping
// domain.ErrInvalidConfig; a syntactically valid DSN that cannot be
// reached fails within the connect timeout wrapping
// domain.ErrUnavailable — the dependency may be reachable in principle,
// just not right now, and only one of those two is worth a retry.
//
// # Why the parse error's text is thrown away
//
// pgxpool.ParseConfig's error is a *pgconn.ParseConfigError. Its Error()
// text tries to redact a recognizable password — reliably in URL form, and
// by matching a literal "password=" token in keyword/value form — but that
// redaction depends on the secret appearing in a shape it recognizes.
// Confirmed by hand against this pinned pgx version: a malformed,
// unparseable DSN, which is exactly the input that reaches this branch,
// can carry an embedded secret through verbatim, and even when redaction
// succeeds the URL form still leaks the username, host, port and database
// name. Its only other public surface is the ConnString field — the same
// unredacted string — and Unwrap.
//
// None of that is safe to forward at a package boundary, so none of it is
// used: losing the parse detail is the correct trade against ever leaking
// a credential. This matters more here than it did in `cas`, because the
// DSN reaching this function is often a pool row's MetadataDSN, read out
// of the registry by the resolver on behalf of a request. See
// TestResolve_NeverLeaksMetadataDSN.
func Open(ctx context.Context, dsn string, cfg PoolConfig) (*pgxpool.Pool, error) {
	poolCfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("%w: the connection string is not valid", domain.ErrInvalidConfig)
	}

	connectTimeout := cfg.ConnectTimeout
	if connectTimeout <= 0 {
		connectTimeout = defaultConnectTimeout
	}
	poolCfg.ConnConfig.ConnectTimeout = connectTimeout

	if cfg.ApplicationName != "" {
		poolCfg.ConnConfig.RuntimeParams["application_name"] = cfg.ApplicationName
	}
	if cfg.MaxConns > 0 {
		poolCfg.MaxConns = cfg.MaxConns
	}
	if cfg.MinConns > 0 {
		poolCfg.MinConns = cfg.MinConns
	}
	if cfg.MaxConnLifetime > 0 {
		poolCfg.MaxConnLifetime = cfg.MaxConnLifetime
	}
	if cfg.MaxConnIdleTime > 0 {
		poolCfg.MaxConnIdleTime = cfg.MaxConnIdleTime
	}
	if cfg.Tracer != nil {
		poolCfg.ConnConfig.Tracer = cfg.Tracer
	}
	if cfg.AfterConnect != nil {
		poolCfg.AfterConnect = cfg.AfterConnect
	}

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		// Also deliberately unwrapped: the only errors
		// pgxpool.NewWithConfig returns past a successful parse are about
		// the config it was handed, which carries the DSN.
		return nil, fmt.Errorf("%w: the connection pool could not be built from this configuration", domain.ErrInvalidConfig)
	}

	pingCtx, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		// The ping error comes from the network and the server, not from
		// the DSN's text, so it is safe to keep — and it is the one a
		// deployment actually needs in order to diagnose a refused
		// connection.
		return nil, fmt.Errorf("%w: postgres is not reachable: %w", domain.ErrUnavailable, err)
	}

	return pool, nil
}
