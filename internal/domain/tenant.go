package domain

import "time"

// SecurityMode names how a tenant's content is encrypted at rest: who
// holds the key and where it lives.
//
// It is immutable after a tenant's first write (see
// db/migrations/00001_registry.sql, which enforces that with a trigger
// rather than trusting the application layer) because switching modes
// would require migrating already-stored content under a different key
// hierarchy. Nothing in this system implements that migration, so a
// mid-flight change would silently orphan ciphertext under the wrong
// assumption.
//
// `tenancy` holds no key material and makes no encryption decision — that
// is `keyring`'s and `seal`'s. This enum is here because the *placement*
// decision is a registry attribute: it is recorded next to the tenant's
// pool, immutably, and read by whoever does hold the keys.
type SecurityMode string

const (
	// SecurityModeManaged means the deployment holds and manages the
	// tenant's encryption key itself.
	SecurityModeManaged SecurityMode = "managed"
	// SecurityModeTenantKey means the tenant supplies and controls its
	// own encryption key.
	SecurityModeTenantKey SecurityMode = "tenant-key"
	// SecurityModeVault means content is addressed and encrypted
	// convergently through an external key vault.
	SecurityModeVault SecurityMode = "vault"
)

// Valid reports whether m is one of the three security modes this module
// recognizes. A registry write rejects any other value before it reaches
// Postgres; the schema's CHECK constraint is a backstop, not the primary
// guard.
func (m SecurityMode) Valid() bool {
	switch m {
	case SecurityModeManaged, SecurityModeTenantKey, SecurityModeVault:
		return true
	default:
		return false
	}
}

// TenantStatus names a tenant's lifecycle state. The three values are a
// closed set, and resolution maps each one to a different outcome — see
// Resolve's doc comment for why deleting and unknown must look identical
// and suspended must not.
type TenantStatus string

const (
	// TenantStatusActive is the normal, fully-operational state, and the
	// only one resolution will hand back a connection for.
	TenantStatusActive TenantStatus = "active"
	// TenantStatusSuspended means the tenant is temporarily refused
	// service — for non-payment or abuse — without its data being
	// removed. Resolution refuses it as ErrUnavailable, which is honest:
	// unsuspending is an operator action, not a change to this
	// deployment.
	TenantStatusSuspended TenantStatus = "suspended"
	// TenantStatusDeleting means the tenant is being torn down and its
	// data erased. Resolution refuses it as ErrNotAuthorizedOrNotFound,
	// indistinguishably from a tenant that never existed.
	TenantStatusDeleting TenantStatus = "deleting"
)

// Valid reports whether s is one of the three lifecycle states.
func (s TenantStatus) Valid() bool {
	switch s {
	case TenantStatusActive, TenantStatusSuspended, TenantStatusDeleting:
		return true
	default:
		return false
	}
}

// Tenant is the top-level unit of isolation: every tenant-scoped row in
// every pool is reachable only through the tenant id this record names,
// and every row-level-security policy keys off it.
//
// The registry tables themselves carry no policy, and that is deliberate
// rather than an omission — see db/migrations/00001_registry.sql, and
// internal/pg.RegistryTablesExemptFromRLS, which names them so that the
// coverage sweep reports a genuinely missing policy without ever
// reporting these two.
type Tenant struct {
	// ID identifies this tenant.
	ID TenantID
	// PoolID names the pool hosting this tenant's metadata.
	PoolID PoolID
	// Name is the tenant's human-assigned, globally unique name.
	Name string
	// SecurityMode is immutable after the tenant's first write.
	SecurityMode SecurityMode
	// Status is the tenant's current lifecycle state.
	Status TenantStatus
	// CreatedAt is when the tenant was created, canonicalized to UTC
	// microseconds (see CanonicalTime).
	CreatedAt time.Time
}
