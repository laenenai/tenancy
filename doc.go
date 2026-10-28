// Package tenancy is the tenant and pool registry and the scoped
// Postgres connection that goes with it.
//
// The facade re-exports the internal types as aliases, so this page is the
// place to look for the field lists and method sets that aliases do not show.
//
// # Roles
//
// Two roles are deliberately separate:
//
//   - AppRole is the data-plane grantee. It receives no registry privileges;
//     every tenant transaction runs SET LOCAL ROLE AppRole.
//   - ControlRole is the registry grantee. It receives SELECT, INSERT and
//     UPDATE on tenancy.pools and tenancy.tenants.
//
// Migrate creates both as NOLOGIN roles. The deployment creates the LOGIN
// identities and makes each a member of the appropriate grantee. The DSN in
// Config.RegistryDSN must be a control-plane login with INHERIT membership in
// ControlRole; it is never the data role.
//
// # Config
//
// Config has these fields:
//
//	RegistryDSN        DSN        required; control-plane login
//	AppRole            string     required; data-plane grantee for SET LOCAL ROLE
//	Postgres           PoolConfig optional; control pool sizing and hooks
//	Cache              CacheOptions optional; TTL, NegativeTTL, MaxPools, MaxTenants
//	LongestTransaction time.Duration required with Credentials
//	Clock              Clock      optional; defaults to SystemClock
//	Opener             Opener     optional; defaults to NewOpener(Postgres)
//	Credentials        Credentials optional; defaults to StaticDSNCredentials
//	OnCredentialReleaseError func(PoolRef, error) optional observability hook
//
// MigrateConfig has DSN, AppRole, ControlRole and Postgres. Status needs only
// DSN. PoolSpec is the input to Control.CreatePool; TenantSpec is the input to
// Control.CreateTenant.
//
// # Tenancy and Scoped
//
// Tenancy has Control, Scope, Stats and Close. Control has CreatePool,
// PoolByID, PoolByName, CreateTenant, TenantByID, TenantByName,
// SetTenantStatus, SetTenantStatusObserver and Close. Scoped has Tenant, Pool
// (a credential-free PoolRef), Valid, AppRole, Tx, CheckEnforcement and the
// redaction methods. TenantTx embeds pgx.Tx and adds Tenant, AppRole and the
// redaction methods.
//
// # RLS and failure modes
//
// RLS is a backstop against forgotten predicates and application bugs, not a
// containment boundary for SQL injection or DDL-capable roles. EnableRLS
// creates a restrictive tenant_isolation policy and a permissive tenant_access
// companion; both are required. AssertRLSCoverage and CheckEnforcement inspect
// the policy's predicate, WITH CHECK and companion, and report ownership even
// when FORCE is set.
//
// A suspended or deleted tenant is refused on the next Scope: SetTenantStatus
// invalidates the positive cache. deleting is terminal. Credential releases
// are best-effort; failed releases are counted in Stats and can be reported
// through OnCredentialReleaseError.
package tenancy
