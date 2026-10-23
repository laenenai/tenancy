// Package migrate applies this module's own registry schema through
// pgmigrate, and nothing else. It owns no migration belonging to any
// consumer: a consumer's tenant-scoped tables are that consumer's to
// create, and the charter forbids this module growing into their migrator.
//
// # The two-pool model, which is the reason Up takes a DSN and not a pool
//
// Up opens a short-lived migration pool from the DSN it is given, applies
// the schema, and closes it before returning. The handle never escapes
// this function, and that is the whole point.
//
// The migration credential holds the rights to create schemas, tables,
// roles and grants. The runtime credential — the one the control plane and
// every resolved pool connect on — does not possess those rights at all.
// `SET ROLE` is explicitly not the mechanism for that separation, because
// `RESET ROLE` reverses it: one owner connection narrowing itself makes
// privilege separation per-session and dependent-on-remembering, and
// forgetting to narrow it is a silent escalation. Two credentials make it
// structural.
//
// Migration is a startup activity, so there is no benefit to a long-lived
// owner pool in the process and a standing escalation target is the whole
// cost. Open it, migrate, close it.
//
// Note the asymmetry with the RLS role switch in internal/pg: there,
// `SET LOCAL ROLE` IS the right mechanism, because it narrows a session
// that already holds too much for exactly one transaction and is gone at
// its end. The difference is direction. Narrowing within a transaction is
// defence in depth on top of a credential boundary; widening within a
// session would be the credential boundary, and a reversible one is not a
// boundary.
//
// # Versioned versus reconciled
//
// The tables, the domain, the trigger and the index are versioned: chosen
// once, in db/migrations/00001_registry.sql.
//
// The application role and its privileges are reconciled — asserted on
// every Up, recording no version of their own. A GRANT in a versioned
// migration is the trap pgmigrate was extracted to close: the migration
// records itself as applied, so a deployment that later renames its
// application role comes up with no privilege separation at all while the
// migrator reports everything applied. That failure is silent, which is
// what makes it worth a whole module.
package migrate

import (
	"context"
	"errors"
	"fmt"

	"github.com/laenenai/pgmigrate"

	"github.com/laenenai/tenancy/db/migrations"
	"github.com/laenenai/tenancy/internal/domain"
	"github.com/laenenai/tenancy/internal/pg"
)

// Schema is the Postgres schema this module owns. Every object the
// registry creates lives in it, including goose's version table, so two
// consumers of one database never share a version table and nothing this
// module migrates lands in `public`.
//
// It is a constant rather than configuration deliberately. The schema name
// appears in the row-level-security exemption list, in the sqlc-generated
// queries and in every consumer's own grants; making it configurable would
// make all three configurable, for no deployment that has ever wanted a
// different name.
const Schema = "tenancy"

// Identity is the module identity pgmigrate derives the advisory lock key
// from: the import path of this package.
//
// # Why this constant is pinned by a test
//
// It textually contains the module path, and the lock key is a CRC32 of
// it, so a module rename silently moves the key. That is not hypothetical:
// on 2026-10-23 a rename of this organisation's module path moved both
// extracted consumers' keys (pgmigrate's LockKey doc comment records the
// before and after values), and on the same day the same class of change
// rewrote a hash function's domain-separation tag in another module and
// invalidated its committed test vectors.
//
// Two builds of this module either side of a rename hash two different
// identities, take two different advisory locks, and therefore do not
// serialize against each other — which is precisely the race the lock
// exists to prevent. TestLockKeyIsPinned asserts the literal key, so the
// rename shows up as a failing test instead of as a concurrent migration
// during a rollout.
const Identity = "github.com/laenenai/tenancy/internal/migrate"

// Config is what a deployment supplies to migrate the registry.
type Config struct {
	// DSN is the migration pool's connection string: the credential
	// holding the migration rights. It is distinct from the runtime
	// credential by construction — see the package doc comment.
	//
	// Required.
	DSN string

	// AppRole is the Postgres role the control plane and every resolved
	// pool connect as at run time. Up ensures it exists as a NOLOGIN role
	// and asserts exactly the registry privileges it must hold, on every
	// run.
	//
	// Required: there is no sensible default, and defaulting it would mean
	// granting the registry to a role nobody chose. A deployment that
	// genuinely runs everything as the owner is a deployment with no
	// privilege separation, and it should have to say so.
	AppRole string

	// Postgres tunes the short-lived migration pool. Its ApplicationName
	// and ConnectTimeout are the fields worth setting; the connection
	// limits matter little for a pool that exists for one startup.
	Postgres pg.PoolConfig
}

// Applied describes one migration's state as the version table knows it.
// It is pgmigrate's type, aliased rather than re-declared so that a value
// this package returns and a value a consumer holds are identical.
type Applied = pgmigrate.Applied

// LockKey returns the advisory lock key this module migrates under. It is
// operational surface: it is what an operator sees in pg_locks while a
// deployment is migrating.
func LockKey() int64 { return pgmigrate.LockKey(Identity) }

// Up applies the registry schema and asserts its declarative state.
//
// It opens a migration pool from cfg.DSN, runs pgmigrate.Up against it
// inside pgmigrate's advisory lock, and closes the pool before returning —
// on every path, including every error path. See the package doc comment
// for why the handle does not escape.
func Up(ctx context.Context, cfg Config) error {
	resolved, err := cfg.resolve()
	if err != nil {
		return err
	}

	pool, err := pg.Open(ctx, resolved.dsn, resolved.postgres)
	if err != nil {
		return err
	}
	defer pool.Close()

	if err := pgmigrate.Up(ctx, pool, resolved.pgmigrateConfig()); err != nil {
		return mapErr("apply the registry schema", err)
	}
	return nil
}

// Status reports the state of every registry migration: applied ones with
// the time they were applied, and pending ones not yet run.
//
// It opens and closes its own migration pool, exactly as Up does. Reading
// the version table requires the schema to exist, which pgmigrate creates,
// so Status is a migration-credential operation and not a runtime one.
func Status(ctx context.Context, cfg Config) ([]Applied, error) {
	resolved, err := cfg.resolve()
	if err != nil {
		return nil, err
	}

	pool, err := pg.Open(ctx, resolved.dsn, resolved.postgres)
	if err != nil {
		return nil, err
	}
	defer pool.Close()

	applied, err := pgmigrate.Status(ctx, pool, resolved.pgmigrateConfig())
	if err != nil {
		return nil, mapErr("read the registry migration status", err)
	}
	return applied, nil
}

// resolvedConfig is Config validated, so nothing downstream re-checks it.
type resolvedConfig struct {
	dsn      string
	appRole  string
	postgres pg.PoolConfig
}

func (c Config) resolve() (resolvedConfig, error) {
	if c.DSN == "" {
		return resolvedConfig{}, fmt.Errorf(
			"%w: migrate: DSN is required: it is the migration credential, which is deliberately not the runtime one",
			domain.ErrInvalidConfig)
	}
	if c.AppRole == "" {
		return resolvedConfig{}, fmt.Errorf(
			"%w: migrate: AppRole is required: the registry grants are asserted against it on every run, and a deployment with no privilege separation should have to say so",
			domain.ErrInvalidConfig)
	}
	if !pgmigrate.IsPlainIdentifier(c.AppRole) {
		return resolvedConfig{}, fmt.Errorf(
			"%w: migrate: AppRole %q is not a plain identifier: letters, digits and underscore, not starting with a digit",
			domain.ErrInvalidConfig, c.AppRole)
	}
	return resolvedConfig{dsn: c.DSN, appRole: c.AppRole, postgres: c.Postgres}, nil
}

// pgmigrateConfig is the whole of what this module tells pgmigrate.
//
// It passes no VersionTable, so the version table is goose's default name
// inside Schema — distinct from any consumer's by virtue of the schema,
// which is the decision pgmigrate's charter records.
func (c resolvedConfig) pgmigrateConfig() pgmigrate.Config {
	return pgmigrate.Config{
		Schema:      Schema,
		Identity:    Identity,
		Migrations:  migrations.FS,
		Reconcilers: []pgmigrate.Reconciler{registryPrivileges(c.appRole)},
	}
}

// registryPrivileges is this module's one reconciler: the application role
// exists, and holds exactly the registry privileges it needs and no more.
//
// The grant set is small and each line is a decision:
//
//   - SELECT on both tables, because resolution reads them. This is the
//     control plane and it is read-mostly.
//   - INSERT and UPDATE, because registering a tenant or a pool, and
//     moving a tenant's status to suspended or deleting, are control-plane
//     operations a deployment performs through its own runtime credential.
//   - DELETE and TRUNCATE revoked. A tenant is never hard-deleted: it
//     moves to status 'deleting', which resolution reports
//     indistinguishably from unknown. A registry row that could be removed
//     would make a tenant's pool assignment — and therefore the location
//     of its data — forgettable.
//   - REFERENCES and TRIGGER revoked. Either would let the application
//     role attach something of its own to the registry: a foreign key that
//     constrains what an operator may change, or a trigger that runs on
//     every registry write. Neither is the application role's business.
//   - PUBLIC revoked from the schema, so a role nobody granted anything to
//     does not reach the registry through the default.
func registryPrivileges(appRole string) pgmigrate.Reconciler {
	return pgmigrate.Reconciler{
		Name: "registry-privileges",
		Reconcile: func(ctx context.Context, tx pgmigrate.Tx) error {
			if err := pgmigrate.EnsureRole(ctx, tx, appRole); err != nil {
				return err
			}

			readWrite := []pgmigrate.Privilege{
				pgmigrate.PrivilegeSelect, pgmigrate.PrivilegeInsert, pgmigrate.PrivilegeUpdate,
			}
			revoked := []pgmigrate.Privilege{
				pgmigrate.PrivilegeDelete, pgmigrate.PrivilegeTruncate,
				pgmigrate.PrivilegeReferences, pgmigrate.PrivilegeTrigger,
			}

			return pgmigrate.AssertPrivileges(ctx, tx, pgmigrate.Privileges{
				Schema:      Schema,
				Role:        appRole,
				SchemaUsage: true,
				Tables: []pgmigrate.TablePrivileges{
					{Table: "pools", Grant: readWrite, Revoke: revoked},
					{Table: "tenants", Grant: readWrite, Revoke: revoked},
				},
				RevokeFromPublic: true,
			})
		},
	}
}

// mapErr maps pgmigrate's two sentinels onto this module's taxonomy, so a
// caller branches on tenancy's errors and never has to know that pgmigrate
// is underneath. The underlying error is kept with %w, so a caller who does
// know can still reach it.
func mapErr(what string, err error) error {
	switch {
	case errors.Is(err, pgmigrate.ErrInvalidConfig):
		return fmt.Errorf("%w: %s: %w", domain.ErrInvalidConfig, what, err)
	case errors.Is(err, pgmigrate.ErrUnavailable):
		return fmt.Errorf("%w: %s: %w", domain.ErrUnavailable, what, err)
	default:
		return fmt.Errorf("%w: %s: %w", domain.ErrUnavailable, what, err)
	}
}
