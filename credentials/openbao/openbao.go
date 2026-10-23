// Package openbao issues each tenant pool's Postgres credential from
// OpenBao's database secrets engine, so that the long-lived password in a
// pool's registry row stops being what the application connects with.
//
// It is opt-in and it is not the default: a deployment that sets nothing
// keeps connecting on the credential each pool row already carries. See
// tenancy.Config.Credentials.
//
// # No SDK, and no new dependency
//
// The database engine is a plain JSON HTTP API, so this package speaks it
// with the standard library's net/http. That is the same choice
// keyring/keymanager/openbaotransit's package doc states and for the same
// reason: an SDK for a service whose whole surface here is three endpoints
// would add a dependency tree, and a second opinion about retries, timeouts
// and error shapes, to a module whose job is to be boring — and it would add
// them to the module graph of every consumer of `tenancy`, including the ones
// that will never issue a dynamic credential.
//
//	Issue      -> GET  <mount>/creds/<role>
//	Release    -> PUT  sys/leases/revoke
//	CheckRole  -> GET  <mount>/roles/<role>
//
// Only the first is on the resolution path. Release is best-effort cleanup,
// and CheckRole is a startup check a deployment calls once (and the only one
// of the three that needs a capability beyond reading credentials).
//
// # Why dynamic credentials and not a static role
//
// This adapter deliberately does not read `database/static-creds/<role>`,
// and the refusal is a measurement rather than a preference. From
// docs/superpowers/spikes/2026-10-23-openbao-db-credentials.md, against
// OpenBao 2.2.1 and Postgres 18.6:
//
//	                               | Dynamic                  | Static
//	-------------------------------|--------------------------|---------------------------------------
//	Pool learns of the change      | the lease TTL, at issue  | only by polling static-creds.ttl
//	An unannounced change possible | no — the TTL is the       | yes — a manual rotate-role arrives
//	                               | contract                 | with zero notice
//	If the pool misses it          | 42501 on new statements  | 28P01 on new *connections*, up to
//	                               |                          | MaxConnLifetime later
//	A health check detects it      | —                        | no: pool.Ping returns nil
//	Blast radius of one credential | one pool                 | every pool and process sharing the role
//
// The decisive row is the health check. After a static rotation the measured
// pool served every query from its four existing connections for the whole
// 25-second watch window, `pool.Ping` returned nil throughout, and
// `Stat().NewConnsCount()` climbed from 5 to 13 while every single new
// connection failed with `28P01 password authentication failed` — an error
// indistinguishable from a typo. With pgx's default one-hour
// MaxConnLifetime, such a pool works for up to an hour and then dies all at
// once, and the failure is attributed to a password an hour after the event
// that caused it.
//
// A deployment that wants a static role anyway can still have one: it is a
// Credentials implementation of its own, and the contract it would have to
// meet is in the port's doc comment. What it must do, from the same spike, is
// set MaxConnLifetime well below the role's rotation_period, poll
// static-creds and rebuild on a last_vault_rotation change, and never treat
// Ping as a liveness signal. That is not shipped here because this module
// would be shipping a credential source whose own health check lies.
//
// # What the OpenBao role must be configured as
//
// This adapter reads credentials; it does not create roles, because creating
// one needs privileges the process serving requests must not hold. The role
// configuration is an operator's, and CreationStatements is this module's
// answer for what goes in it — call it rather than copying SQL, and call
// CheckRole at startup to find out whether the server agrees. Four
// requirements, each one a measured failure mode rather than hygiene:
//
//   - **VALID UNTIL '{{expiration}}' in the creation statement.** Postgres
//     enforces it independently of whether OpenBao's revocation succeeded,
//     which makes it the one backstop in this arrangement that always holds.
//     Measured: a role still present in pg_roles with the correct password
//     was refused at login purely by an elapsed VALID UNTIL.
//   - **IN ROLE <app role>, with inheritance.** A policy's TO clause is
//     resolved with pg_has_role(current_user, …, 'USAGE'), so a policy
//     written against the application role covers the ephemeral `v-token-…`
//     member even though the names differ, and privileges granted to that
//     role later are picked up without reconnecting. NOINHERIT fails closed
//     — everything is denied — so it is not a leak, but it is a deployment
//     that does not work. IN ROLE rather than a separate GRANT is one
//     statement fewer and cannot half-succeed.
//   - **No ability to create objects.** A dynamic credential that owns
//     anything cannot be dropped: Postgres refuses with SQLSTATE 2BP01 and
//     the default revocation statements contain no REASSIGN OWNED, so the
//     role stays in Postgres, the lease stays in OpenBao, and only a manual
//     REASSIGN OWNED / DROP OWNED / DROP ROLE clears it. Measured, and found
//     by accident. The runtime credential's inability to do DDL is therefore
//     what keeps revocation working, not merely least privilege.
//   - **No SUPERUSER and no BYPASSRLS.** A superuser is not constrained by
//     row-level security even with FORCE ROW LEVEL SECURITY, so a credential
//     with either attribute makes the whole fail-closed backstop inert while
//     every test still passes.
//
// # The TTL the role issues is not a free choice
//
// A pool built on a credential expiring at T stops being handed to new
// callers at T minus tenancy.CacheOptions.LongestTransaction, and the
// transactions already running on it have until T to finish. So the role's
// default_ttl has a floor set by the slowest transaction the deployment
// serves — not by a security preference — and a credential with less than
// twice that left to live is refused at resolution with a message naming
// both numbers. The spike's own 10-second TTL is unusable for anything real.
//
// # What a lease does not do
//
// A lease is not a security boundary on work already in flight. Expiry is a
// privilege removal, not a disconnection: the measured revocation is five
// REVOKE/DROP ROLE statements and no pg_terminate_backend, no connection
// closes, and `conn.IsClosed()` stays false. A transaction that had already
// read a table kept reading it and committed successfully 10 seconds after
// its role was dropped; one holding an uncommitted INSERT committed its row
// 16 seconds after. The lead time above is what makes that irrelevant, and
// it is the reason this adapter reports an expiry instead of offering a renew.
//
// # Token policy
//
// Within the mount: `read` on `creds/<role>` for every role this adapter
// issues from. Outside it: `update` on `sys/leases/revoke`, without which
// Release fails and credentials are left to expire on their own schedule.
// `read` on `roles/<role>` is needed only by CheckRole, which is why that is
// a separate call a deployment makes at startup rather than something Issue
// does on every pool.
//
// # Errors
//
// No error returned by this package contains the token, the issued password,
// or a pool's connection string. A credential-issuing failure is the single
// most likely thing to be logged in full, which is why that is stated here
// and asserted in this package's tests.
package openbao

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/laenenai/tenancy/internal/domain"
)

// DefaultMountPath is the path the database secrets engine is mounted at
// when Config.MountPath is empty, and is OpenBao's own default.
const DefaultMountPath = "database"

// DefaultTimeout bounds a single request when Config.HTTPClient is not
// supplied. A credential issuer that hangs forever on a half-open connection
// takes every resolution that needs a new pool with it, so there is a
// timeout by default rather than only when a caller remembers a deadline.
const DefaultTimeout = 30 * time.Second

// maxResponseBytes bounds how much of a response this adapter reads. Every
// response it expects is a few hundred bytes; the limit is what stops a
// misconfigured address pointing at something that streams.
const maxResponseBytes = 1 << 20

// Config configures the OpenBao database-credentials adapter.
type Config struct {
	// Address is the base URL of the OpenBao (or Vault) server, for
	// example "https://openbao.internal:8200".
	Address string

	// Token authenticates this process to OpenBao. It is a secret: it
	// never appears in an error returned by this package, and Config and
	// Credentials both redact it in every rendering, because logging the
	// configuration at startup is the obvious way for it to escape.
	Token string

	// MountPath is where the database secrets engine is mounted, without
	// leading or trailing slashes. Empty means DefaultMountPath. A nested
	// mount ("platform/database") is allowed.
	MountPath string

	// Role is the database role credentials are issued from, for every
	// pool. Required unless RoleFor is set.
	Role string

	// RoleFor, when set, chooses the role per pool and takes precedence
	// over Role.
	//
	// It exists because an OpenBao database role is bound server-side to
	// one connection configuration, which is one Postgres database — so a
	// deployment with pools in several databases necessarily has several
	// roles, and only the deployment knows which is which. Returning an
	// error refuses the resolution; the error must not carry the pool's
	// connection string.
	RoleFor func(p domain.Pool) (string, error)

	// HTTPClient, when set, is used for every request, so a deployment can
	// supply its own TLS configuration, proxy, connection pooling or
	// timeout. Nil means a client with DefaultTimeout.
	HTTPClient *http.Client

	// Clock reads "now", which is what an issued credential's IssuedAt and
	// ExpiresAt are computed from — OpenBao reports a lease duration in
	// seconds, not an instant.
	//
	// It is injectable for the same reason tenancy.CacheOptions.Clock is:
	// a test that proves a pool retires before its lease expires would
	// otherwise have to spend the lease's length sleeping. Zero means
	// domain.SystemClock.
	Clock domain.Clock
}

// String renders the configuration with the token redacted.
func (c Config) String() string {
	return fmt.Sprintf("openbao.Config{Address: %q, Token: %s, MountPath: %q, Role: %q, RoleFor: %s, Clock: %T}",
		c.Address, domain.Redacted, c.MountPath, c.Role, roleForDescription(c.RoleFor), c.Clock)
}

// Format implements fmt.Formatter. String and LogValue are not enough on
// their own: fmt consults Stringer for %v, %s, %q, %x and %X and for no
// other verb, so %#v, %d and %c would reflect this struct and print Token in
// full. See CONVENTIONS.md's "Rendering a secret".
func (c Config) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, c.String()) }

// MarshalJSON renders the same redacted summary as a JSON string. Token is
// an exported field, so encoding/json reaches it directly — and slog's
// JSONHandler, which marshals a non-LogValuer attribute with encoding/json,
// does the same.
func (c Config) MarshalJSON() ([]byte, error) { return json.Marshal(c.String()) }

// LogValue renders the configuration as a slog group with the token
// redacted, so slog.Any("config", cfg) is safe under every handler.
func (c Config) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("address", c.Address),
		slog.String("token", domain.Redacted),
		slog.String("mount_path", c.MountPath),
		slog.String("role", c.Role),
		slog.String("role_for", roleForDescription(c.RoleFor)),
	)
}

// roleForDescription names whether a per-pool role function was supplied,
// which is the part worth logging; the function value itself renders as an
// address, and an address in a log line is noise.
func roleForDescription(f func(p domain.Pool) (string, error)) string {
	if f == nil {
		return "unset"
	}
	return "set"
}

// Credentials issues Postgres credentials from OpenBao's database secrets
// engine. Open returns one; it is safe for concurrent use and satisfies the
// port tenancy.Config.Credentials takes.
type Credentials struct {
	// base is the server's base URL with no trailing slash.
	base string
	// mount is the mount path, each segment escaped for use in a URL.
	mount string
	// token is the X-Vault-Token header value.
	token string
	// role and roleFor decide which database role to issue from.
	role    string
	roleFor func(p domain.Pool) (string, error)

	client *http.Client
	clock  domain.Clock
}

// Open validates cfg and returns a credential source over it.
//
// It does not contact the server. A reachability check here would report a
// configuration mistake and an outage as the same symptom, and a check that
// passed at startup would imply a guarantee that does not survive the first
// network partition. CheckRole is the startup check worth making, and it is
// separate because it needs a capability Issue does not.
//
// It returns domain.ErrInvalidConfig for a configuration that cannot produce
// a working credential source: no address, an address that is not an
// absolute http or https URL, no token, no role, or a mount path that is not
// usable as one. The error never contains the token.
func Open(ctx context.Context, cfg Config) (*Credentials, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("tenancy/credentials/openbao: open: %w", err)
	}

	address := strings.TrimSpace(cfg.Address)
	if address == "" {
		return nil, fmt.Errorf("%w: Address is required, for example \"https://openbao.internal:8200\"", domain.ErrInvalidConfig)
	}
	parsed, err := url.Parse(address)
	if err != nil {
		return nil, fmt.Errorf("%w: Address %q is not a URL: %w", domain.ErrInvalidConfig, cfg.Address, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("%w: Address %q must be an absolute http or https URL", domain.ErrInvalidConfig, cfg.Address)
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("%w: Address %q has no host", domain.ErrInvalidConfig, cfg.Address)
	}
	if cfg.Token == "" {
		return nil, fmt.Errorf("%w: Token is required", domain.ErrInvalidConfig)
	}
	if cfg.Role == "" && cfg.RoleFor == nil {
		return nil, fmt.Errorf(
			"%w: Role or RoleFor is required: it names the database role credentials are issued from, "+
				"and an OpenBao database role is bound to one connection configuration, so a deployment "+
				"whose pools live in different databases needs RoleFor",
			domain.ErrInvalidConfig)
	}
	mount, err := mountPath(cfg.MountPath)
	if err != nil {
		return nil, err
	}

	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: DefaultTimeout}
	}
	clock := cfg.Clock
	if clock == nil {
		clock = domain.SystemClock{}
	}

	return &Credentials{
		base:    strings.TrimSuffix(parsed.String(), "/"),
		mount:   mount,
		token:   cfg.Token,
		role:    cfg.Role,
		roleFor: cfg.RoleFor,
		client:  client,
		clock:   clock,
	}, nil
}

// Issue implements the Credentials port: it asks OpenBao for a credential
// from p's role and reports when that credential stops working.
//
// ExpiresAt is computed from the lease duration the server reports, read at
// the moment of the response rather than taken from any field in it — a lease
// is a duration in seconds, and the instant it is relative to is the one this
// process observed the answer at. IssuedAt is the same instant, so the
// credential's whole lifetime is readable from the value, which is what the
// drain-window validation in internal/pool is made against.
//
// A credential with no lease is refused. OpenBao answers a static role's
// read with an empty lease_id and a zero lease_duration, which is the shape
// this adapter will not build a pool on: there would be nothing to schedule
// a retirement against, and the pool would then be replaced only when its
// password had already been rotated out from under it. See the package doc
// comment.
func (c *Credentials) Issue(ctx context.Context, p domain.Pool) (domain.Credential, error) {
	if err := ctx.Err(); err != nil {
		return domain.Credential{}, fmt.Errorf("tenancy/credentials/openbao: issue a credential: %w", err)
	}

	role, err := c.roleName(p)
	if err != nil {
		return domain.Credential{}, err
	}

	res, err := c.call(ctx, http.MethodGet, c.mount+"/creds/"+url.PathEscape(role), nil)
	if err != nil {
		return domain.Credential{}, classify(err, "issue a credential from role "+role)
	}

	issuedAt := domain.CanonicalTime(c.clock.Now())

	if res.Data.Username == "" || res.Data.Password == "" {
		return domain.Credential{}, fmt.Errorf(
			"%w: role %q returned no username or password: it is not a database role that issues credentials",
			domain.ErrInvalidConfig, role)
	}
	if res.LeaseID == "" || res.LeaseDuration <= 0 {
		return domain.Credential{}, fmt.Errorf(
			"%w: role %q returned a credential with no lease (lease_duration=%d): this adapter issues "+
				"dynamic credentials only, and a static role's credential carries no expiry to retire a "+
				"pool against — a rotation would then be discovered as a failure to open new connections, "+
				"which pool.Ping reports as healthy",
			domain.ErrInvalidConfig, role, res.LeaseDuration)
	}

	return domain.Credential{
		Username:  res.Data.Username,
		Password:  res.Data.Password,
		LeaseID:   res.LeaseID,
		IssuedAt:  issuedAt,
		ExpiresAt: domain.CanonicalTime(issuedAt.Add(time.Duration(res.LeaseDuration) * time.Second)),
	}, nil
}

// Release implements the Credentials port: it revokes the lease, which is
// what OpenBao would otherwise do on a timer.
//
// Revoking is measured not to block — 0.02s against a session holding
// RowExclusiveLock from an uncommitted INSERT, with no back-pressure from
// Postgres at all — so this is a fast call and not a reason to defer
// shutdown. It is also measured to be able to fail permanently: a credential
// that owns any object cannot be dropped (SQLSTATE 2BP01) and leaves both a
// role in Postgres and a stuck lease in OpenBao. That failure is returned
// here rather than hidden, even though internal/pool discards it, so that a
// deployment calling Release itself can see it.
func (c *Credentials) Release(ctx context.Context, cred domain.Credential) error {
	if cred.LeaseID == "" {
		// Includes the zero Credential, which the port requires to be a
		// no-op: there is nothing to hand back.
		return nil
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("tenancy/credentials/openbao: release a credential: %w", err)
	}

	// sys/leases/revoke is not under the mount: a lease id is a server-wide
	// identifier, so this is the one call here that does not take the mount
	// path.
	_, err := c.call(ctx, http.MethodPut, "sys/leases/revoke", &revokeRequest{LeaseID: cred.LeaseID})
	if err != nil {
		// The lease id is deliberately not named in the error. It is a
		// capability — whoever holds it can revoke the credential — and
		// this error is the one most likely to be logged.
		return classify(err, "revoke the lease for "+credentialName(cred))
	}
	return nil
}

// The adapter is held to the port at compile time.
var _ domain.Credentials = (*Credentials)(nil)

// roleName returns the database role to issue p's credential from.
func (c *Credentials) roleName(p domain.Pool) (string, error) {
	if c.roleFor == nil {
		return c.role, nil
	}
	role, err := c.roleFor(p)
	if err != nil {
		// Wrapped without the pool row: a Pool redacts its own DSN, but
		// the id is the only part of it that identifies anything an
		// operator can act on.
		return "", fmt.Errorf("%w: no database role for pool %s: %w", domain.ErrInvalidConfig, p.ID, err)
	}
	if role == "" {
		return "", fmt.Errorf("%w: RoleFor returned no database role for pool %s", domain.ErrInvalidConfig, p.ID)
	}
	return role, nil
}

// credentialName names an issued credential in an error without disclosing
// anything: the username is the ephemeral role Postgres knows the session
// by, visible to every session in the cluster through pg_stat_activity, and
// it is the identifier that ties this module's errors to a Postgres log line.
func credentialName(cred domain.Credential) string {
	if cred.Username == "" {
		return "an unnamed credential"
	}
	return "credential " + cred.Username
}

// CreationStatements returns the `creation_statements` an OpenBao database
// role must be configured with for this module, for the application role
// appRole.
//
// It exists so that an operator's role configuration comes from this module
// rather than from a copy of some SQL, because every clause in it is
// load-bearing and three of them are load-bearing in ways that do not show
// up until something has already gone wrong. See the package doc comment for
// the measurement behind each:
//
//   - LOGIN PASSWORD '{{password}}' — the issued secret.
//   - VALID UNTIL '{{expiration}}' — enforced by Postgres independently of
//     whether OpenBao's revocation ever runs. The one backstop that holds.
//   - IN ROLE <appRole> — inheritance, which is how a policy written against
//     appRole covers this ephemeral member, and how grants added later are
//     picked up without reconnecting.
//
// What it does *not* contain is as deliberate: no NOINHERIT, no SUPERUSER,
// no BYPASSRLS, no CREATEDB, no CREATEROLE, and no GRANT of any kind. The
// credential inherits exactly what appRole holds and can create nothing —
// which is what keeps it revocable, because a dynamic credential that owns
// an object cannot be dropped at all.
//
// It is one statement rather than a CREATE followed by a GRANT, which is one
// fewer thing to go wrong: a two-statement form can half-succeed, and a
// separate GRANT was measured to be byte-for-byte equivalent in effect.
//
// appRole must be a plain identifier (letters, digits and underscore, not
// starting with a digit), because it reaches Postgres as SQL text inside a
// template OpenBao expands server-side — there is no bound parameter
// available on that path.
func CreationStatements(appRole string) ([]string, error) {
	if !isPlainIdentifier(appRole) {
		return nil, fmt.Errorf(
			"%w: appRole %q is not a plain identifier: letters, digits and underscore, not starting with a digit",
			domain.ErrInvalidConfig, appRole)
	}
	return []string{
		`CREATE ROLE "{{name}}" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}' IN ROLE ` + appRole + `;`,
	}, nil
}

// isPlainIdentifier reports whether s is safe to interpolate into SQL as an
// identifier: ASCII letters, digits and underscore, not starting with a
// digit, and not empty.
//
// It is the same check internal/scope makes on AppRole, declared again here
// rather than imported, because this package is one a consumer imports
// directly and the check is four lines.
func isPlainIdentifier(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r == '_':
		case r >= '0' && r <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

// RoleCheck is what a role's configuration on the server says, measured
// against what this module requires of it.
//
// It is shaped like tenancy.Enforcement on purpose: a struct of measured
// facts, a Findings method that turns them into prose an operator can act
// on, and an empty Findings as the passing answer. A deployment calls
// CheckRole at startup and refuses to serve, or shouts, if Usable is false.
type RoleCheck struct {
	// Role is the role that was asked about.
	Role string
	// Exists is false if the server has no such database role, in which
	// case nothing else here means anything.
	Exists bool

	// DefaultTTL and MaxTTL are the lease durations the role issues.
	// DefaultTTL is the one to compare against
	// tenancy.CacheOptions.LongestTransaction; see the package doc comment
	// for the floor.
	DefaultTTL time.Duration
	MaxTTL     time.Duration

	// HasValidUntil reports whether the creation statements set VALID
	// UNTIL, which is the only part of this arrangement Postgres enforces
	// without OpenBao's cooperation.
	HasValidUntil bool
	// GrantsInheritance reports whether the creation statements make the
	// issued role a member of another role at all, by IN ROLE or by a
	// GRANT. Without it the credential holds nothing and no policy covers
	// it.
	GrantsInheritance bool
	// DeclaresNoInherit reports whether the creation statements say
	// NOINHERIT, which was measured to deny everything — fail closed, so
	// not a leak, but a deployment that does not work.
	DeclaresNoInherit bool
	// GrantsRLSBypass reports whether the creation statements give the
	// credential SUPERUSER or BYPASSRLS, either of which makes row-level
	// security inert for it while every test still passes.
	GrantsRLSBypass bool
	// GrantsObjectCreation reports whether the creation statements let the
	// credential create objects (CREATEDB, CREATEROLE, or a GRANT of
	// CREATE). A credential that owns an object cannot be revoked.
	GrantsObjectCreation bool
}

// Usable reports whether this role can be used by this module: it is derived
// from Findings rather than stored, so the verdict and the reasons cannot
// disagree.
func (rc RoleCheck) Usable() bool { return len(rc.Findings()) == 0 }

// Findings names every way this role departs from what this module requires,
// and an empty result is the passing answer.
func (rc RoleCheck) Findings() []string {
	if !rc.Exists {
		return []string{"the database role " + rc.Role + " does not exist on this server"}
	}

	var out []string
	if rc.GrantsRLSBypass {
		out = append(out, rc.Role+" creates credentials with SUPERUSER or BYPASSRLS, which are not constrained "+
			"by row-level security at all — not even with FORCE ROW LEVEL SECURITY — so the fail-closed backstop "+
			"this module exists to provide would enforce nothing")
	}
	if rc.GrantsObjectCreation {
		out = append(out, rc.Role+" creates credentials that can create objects (CREATEDB, CREATEROLE or a GRANT "+
			"of CREATE). A credential that owns an object cannot be dropped — Postgres refuses with SQLSTATE 2BP01 "+
			"and the default revocation statements contain no REASSIGN OWNED — so it becomes a role in Postgres and "+
			"a stuck lease in OpenBao that only manual intervention clears")
	}
	if !rc.HasValidUntil {
		out = append(out, rc.Role+" does not set VALID UNTIL '{{expiration}}' in its creation statements. It is the "+
			"only part of a credential's expiry that Postgres enforces by itself, independently of whether "+
			"OpenBao's revocation ever runs — see CreationStatements")
	}
	if rc.DeclaresNoInherit {
		out = append(out, rc.Role+" creates credentials with NOINHERIT, so they hold none of the application "+
			"role's privileges and every statement is denied")
	}
	if !rc.GrantsInheritance {
		out = append(out, rc.Role+" does not make the issued credential a member of an application role (IN ROLE, "+
			"or a GRANT), so it inherits no privileges and no policy written against that role covers it")
	}
	if rc.DefaultTTL <= 0 {
		out = append(out, rc.Role+" has no default_ttl, so its credentials carry no expiry for a pool to be "+
			"retired against")
	}
	return out
}

// CheckRole reads role's configuration from the server and reports how it
// measures against what this module requires. An empty Findings is the
// passing answer; see RoleCheck.
//
// It needs the `read` capability on `<mount>/roles/<role>`, which Issue does
// not, and it is a separate call for exactly that reason: a deployment that
// would rather not grant it can skip this check instead of being unable to
// issue credentials.
//
// It is a text check against the role's own configuration, and it is honest
// about being one: it catches the misconfigurations that were actually
// measured to matter, and it is not a proof. The proof is positive and comes
// from the issued credential itself — pg_has_role(current_user, <app role>,
// 'USAGE') and row_security_active(<table>) — which is what the conformance
// suite in tenancytest asserts, and what tenancy.Scoped.CheckEnforcement
// reports for a running deployment. Note 'USAGE' and not 'MEMBER': a
// NOINHERIT credential holding no privileges at all still reports true for
// 'MEMBER', so a check written that way would pass a completely
// non-functional credential.
func (c *Credentials) CheckRole(ctx context.Context, role string) (RoleCheck, error) {
	if err := ctx.Err(); err != nil {
		return RoleCheck{}, fmt.Errorf("tenancy/credentials/openbao: check role: %w", err)
	}
	if role == "" {
		return RoleCheck{}, fmt.Errorf("%w: CheckRole was given no role name", domain.ErrInvalidConfig)
	}

	res, err := c.call(ctx, http.MethodGet, c.mount+"/roles/"+url.PathEscape(role), nil)
	if err != nil {
		var apiErr *apiError
		if errors.As(err, &apiErr) && apiErr.status == http.StatusNotFound {
			return RoleCheck{Role: role}, nil
		}
		return RoleCheck{}, classify(err, "read the configuration of role "+role)
	}

	statements := normalizeStatements(res.Data.CreationStatements)
	return RoleCheck{
		Role:                 role,
		Exists:               true,
		DefaultTTL:           time.Duration(res.Data.DefaultTTL) * time.Second,
		MaxTTL:               time.Duration(res.Data.MaxTTL) * time.Second,
		HasValidUntil:        strings.Contains(statements, "VALID UNTIL"),
		GrantsInheritance:    strings.Contains(statements, "IN ROLE") || strings.Contains(statements, "GRANT "),
		DeclaresNoInherit:    strings.Contains(statements, "NOINHERIT"),
		GrantsRLSBypass:      grantsRLSBypass(statements),
		GrantsObjectCreation: grantsObjectCreation(statements),
	}, nil
}

// normalizeStatements folds a role's creation statements into one uppercase
// string with single-spaced whitespace, so the checks above can be written as
// plain substring tests rather than as a parser. Uppercasing is safe because
// every needle is a SQL keyword.
func normalizeStatements(statements []string) string {
	return strings.ToUpper(strings.Join(strings.Fields(strings.Join(statements, " ")), " "))
}

// grantsRLSBypass reports whether normalized statements give the credential
// an attribute that defeats row security.
//
// The negative forms are removed first: NOSUPERUSER contains SUPERUSER as a
// substring, so a role explicitly spelling out the safe form would otherwise
// be reported as the dangerous one.
func grantsRLSBypass(statements string) bool {
	s := strings.NewReplacer("NOSUPERUSER", "", "NOBYPASSRLS", "").Replace(statements)
	return strings.Contains(s, "SUPERUSER") || strings.Contains(s, "BYPASSRLS")
}

// grantsObjectCreation reports whether normalized statements let the
// credential create objects.
//
// It deliberately does not look for "CREATE" on its own: every creation
// statement there is begins with CREATE ROLE, so that needle would report
// every role in existence. The forms that matter are the role attributes and
// a GRANT of the CREATE privilege.
func grantsObjectCreation(statements string) bool {
	s := strings.NewReplacer("NOCREATEDB", "", "NOCREATEROLE", "").Replace(statements)
	return strings.Contains(s, "CREATEDB") ||
		strings.Contains(s, "CREATEROLE") ||
		strings.Contains(s, "GRANT CREATE")
}

// call performs one request and decodes its response.
//
// The response buffer is this package's own and the decoded body carries an
// issued password, so neither is ever rendered: a non-2xx becomes an
// *apiError holding only the status and the server's own messages, and the
// request body is never included in any error. The one request body this
// adapter sends carries a lease id, which is a capability.
func (c *Credentials) call(ctx context.Context, method, path string, body any) (*response, error) {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			// Rendered without the body, which carries a lease id.
			return nil, fmt.Errorf("encode a %s request: %w", method, err)
		}
		reader = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.base+"/v1/"+path, reader)
	if err != nil {
		return nil, fmt.Errorf("build a %s request: %w", method, err)
	}
	req.Header.Set("X-Vault-Token", c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.client.Do(req)
	if err != nil {
		// A *url.Error wraps the context's error, so errors.Is sees a
		// cancellation or a deadline through this. It can also carry the
		// request URL, which is this adapter's address and mount and
		// carries no credential — the token travels in a header.
		return nil, fmt.Errorf("%s: %w", method, err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("read the response to %s: %w", method, err)
	}

	ok := resp.StatusCode >= 200 && resp.StatusCode <= 299
	var decoded response
	if len(bytes.TrimSpace(raw)) > 0 {
		if err := json.Unmarshal(raw, &decoded); err != nil {
			if !ok {
				// A non-2xx whose body is not the usual JSON: a proxy, or
				// a server that is not OpenBao. The status is all there is.
				return nil, &apiError{status: resp.StatusCode}
			}
			// Deliberately without the body: a 2xx body carries the
			// issued password.
			return nil, fmt.Errorf("decode the response to %s: the server's answer is not the expected JSON", method)
		}
	}
	if !ok {
		return nil, &apiError{status: resp.StatusCode, messages: decoded.Errors}
	}
	return &decoded, nil
}

// response is the union of the fields this adapter reads from OpenBao's
// envelope.
type response struct {
	LeaseID       string `json:"lease_id"`
	LeaseDuration int    `json:"lease_duration"`
	Data          struct {
		Username string `json:"username"`
		Password string `json:"password"`

		// The role-configuration fields, read only by CheckRole.
		CreationStatements []string `json:"creation_statements"`
		DefaultTTL         int      `json:"default_ttl"`
		MaxTTL             int      `json:"max_ttl"`
	} `json:"data"`
	Errors []string `json:"errors"`
}

// revokeRequest is the one request body this adapter sends.
type revokeRequest struct {
	LeaseID string `json:"lease_id"`
}

// apiError is a non-2xx response: its status and the messages the server
// returned. It deliberately carries neither the request nor the token.
type apiError struct {
	status   int
	messages []string
}

// Error renders the status and the server's messages.
func (e *apiError) Error() string {
	if len(e.messages) == 0 {
		return "openbao returned HTTP " + strconv.Itoa(e.status)
	}
	return "openbao returned HTTP " + strconv.Itoa(e.status) + ": " + strings.Join(e.messages, "; ")
}

// classify maps a transport or API failure onto this module's taxonomy,
// which is what a caller branches on.
//
// The split is "would retrying help": a refused token, a missing role or a
// missing mount are a deployment that is wired wrongly and will stay wrong
// (domain.ErrInvalidConfig), while a connection that could not be made, a
// deadline, and any 5xx are this dependency not being reachable right now
// (domain.ErrUnavailable). A resolution that fails with the first should not
// be retried in a loop against a server that will keep saying no.
func classify(err error, what string) error {
	var apiErr *apiError
	if errors.As(err, &apiErr) {
		switch apiErr.status {
		case http.StatusBadRequest, http.StatusForbidden, http.StatusNotFound, http.StatusMethodNotAllowed:
			return fmt.Errorf("%w: openbao refused to %s: %w", domain.ErrInvalidConfig, what, err)
		}
		return fmt.Errorf("%w: openbao could not %s: %w", domain.ErrUnavailable, what, err)
	}
	return fmt.Errorf("%w: openbao could not %s: %w", domain.ErrUnavailable, what, err)
}

// mountPath validates and escapes a mount path, defaulting to
// DefaultMountPath. A nested mount is allowed; an empty segment, a relative
// element and a control character are not.
func mountPath(configured string) (string, error) {
	trimmed := strings.Trim(strings.TrimSpace(configured), "/")
	if trimmed == "" {
		trimmed = DefaultMountPath
	}
	segments := strings.Split(trimmed, "/")
	escaped := make([]string, 0, len(segments))
	for _, segment := range segments {
		if segment == "" || segment == "." || segment == ".." {
			return "", fmt.Errorf("%w: MountPath %q is not a usable mount path", domain.ErrInvalidConfig, configured)
		}
		for _, r := range segment {
			if r < 0x20 || r == 0x7F {
				return "", fmt.Errorf("%w: MountPath %q contains a control character", domain.ErrInvalidConfig, configured)
			}
		}
		escaped = append(escaped, url.PathEscape(segment))
	}
	return strings.Join(escaped, "/"), nil
}

// String renders the credential source without its token. A *Credentials is
// what Open returns, so it is in scope wherever Open's error handling is, and
// its token field is the credential that authenticates this process to
// OpenBao.
func (c *Credentials) String() string {
	return fmt.Sprintf("openbao.Credentials{base: %q, mount: %q, token: %s, role: %q, roleFor: %s}",
		c.base, c.mount, domain.Redacted, c.role, roleForDescription(c.roleFor))
}

// Format implements fmt.Formatter so that every verb yields the redacted
// summary rather than only the five fmt routes through Stringer.
func (c *Credentials) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, c.String()) }

// MarshalJSON renders the redacted summary. encoding/json skips unexported
// fields, so a *Credentials already marshalled to "{}" — safety by accident,
// which ends the moment a field is exported.
func (c *Credentials) MarshalJSON() ([]byte, error) { return json.Marshal(c.String()) }

// LogValue renders the source as a slog group with the token redacted.
func (c *Credentials) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("address", c.base),
		slog.String("mount_path", c.mount),
		slog.String("token", domain.Redacted),
		slog.String("role", c.role),
		slog.String("role_for", roleForDescription(c.roleFor)),
	)
}
