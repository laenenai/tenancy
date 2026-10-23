package domain

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"time"
)

// Credentials issues the credential a tenant pool's connections
// authenticate with, and hands it back when the pool that used it is gone.
//
// It exists because a connection string in a registry row is one answer to
// "what does this pool connect as", and a dynamically issued, expiring
// credential is another. The default answer is the first one —
// StaticDSNCredentials, below, which performs no I/O and never expires — so
// a deployment that wants nothing to change wires nothing.
//
// # Why the port is shaped around an expiry rather than a refresh
//
// An expiring credential cannot be swapped underneath a live *pgxpool.Pool.
// Measured against real OpenBao and real Postgres (see
// docs/superpowers/spikes/2026-10-23-openbao-db-credentials.md): revoking a
// credential does not close a single connection, `conn.IsClosed()` stays
// false, and the pool notices nothing at all. What changes is that
// statements start failing — and not even uniformly, because a transaction
// that already holds a lock on a relation keeps that relation's cached
// privileges until it ends. One scenario in that spike committed a write 16
// seconds after its role had been dropped.
//
// So there is no refresh hook here and no renew. The only safe response to
// a credential approaching expiry is to stop handing its pool to new
// callers, let the transactions already running on it finish, close it, and
// build a replacement on a freshly issued credential. That is what
// internal/pool does with ExpiresAt, and it is why this interface reports an
// expiry instead of offering a way to extend one.
//
// # What an implementation must guarantee
//
// Issue must return a credential that is usable now and stays usable until
// ExpiresAt. It must never return an error whose text carries the
// credential, the pool's connection string, or the implementation's own
// authentication material — a resolution error is the single most likely
// place for any of those to reach a log. See CONVENTIONS.md's "Rendering a
// secret", and the conformance suite in tenancytest, which is the
// authoritative description of this contract.
//
// Release is best-effort and is called after the pool built on cred has
// been closed. Its error is deliberately discarded by internal/pool — there
// is no request left to fail, and no logger in this module to report it
// through — so an implementation that needs a failed release to be visible
// reports it itself. Nothing depends on Release succeeding: a credential
// this module stops using expires on its own schedule, and Postgres
// enforces `VALID UNTIL` independently of whether the issuer's revocation
// worked, which is the one backstop in this whole arrangement that always
// holds.
type Credentials interface {
	// Issue returns the credential p's connections should authenticate
	// with. The zero Credential means "connect as p.MetadataDSN already
	// says, and never retire the pool for credential age".
	Issue(ctx context.Context, p Pool) (Credential, error)
	// Release hands cred back to whatever issued it. It is best-effort;
	// see the interface comment. Releasing the zero Credential is a no-op
	// and must not be an error.
	Release(ctx context.Context, cred Credential) error
}

// Credential is one issued database login: who to connect as, the secret to
// connect with, and when it stops working.
//
// The host, port, database and TLS settings are NOT here. They come from the
// pool row's MetadataDSN, and only the user and the password are overridden
// — which is why nothing in this module ever has to take a connection string
// apart and put it back together. internal/pg.OpenAs applies the override to
// pgx's already-parsed configuration, so the DSN's text is never rewritten.
//
// # The zero value means "static"
//
// A zero Credential carries no username, so there is nothing to override and
// no expiry to schedule against: the pool connects exactly as its registry
// row says and lives until it is evicted or the resolver closes. That is
// this module's default behaviour and the shape every existing deployment is
// already in.
//
// # Rendering
//
// Password is security-relevant material and LeaseID is a capability for
// revoking the credential, so every rendering of this type yields a
// placeholder for both: see the four methods below. %p is the one hole no
// method can close (CONVENTIONS.md records it), and it is not closed here
// because holding the password behind a pointer field would make the struct
// hostile to the consumers who have to fill it in.
type Credential struct {
	// Username is the database role to connect as. Empty means "do not
	// override the DSN's own user", which is what makes the zero value
	// static.
	Username string
	// Password is the secret to connect with. It is material: never log
	// it, never put it in an error, and never interpolate it into a
	// connection string.
	Password string
	// LeaseID, when set, identifies the issued credential to whatever
	// issued it, so Release can hand it back. It is treated as material
	// because it is a capability: whoever holds it can revoke the
	// credential.
	LeaseID string
	// IssuedAt is when the credential was issued, canonicalized to UTC
	// microseconds (see CanonicalTime).
	IssuedAt time.Time
	// ExpiresAt is when the credential stops working, canonicalized the
	// same way. Zero means it does not expire.
	//
	// It is a deadline on *new* work and not a security boundary on work
	// already running: a transaction open at expiry finishes with the
	// privileges it had. See the Credentials interface comment, and
	// internal/pool for how far ahead of this instant a pool is retired
	// and why that lead time is set by the slowest transaction a
	// deployment serves.
	ExpiresAt time.Time
}

// IsZero reports whether this is the zero Credential: no override, no
// expiry, connect as the pool row's DSN says. It is the static case.
func (c Credential) IsZero() bool {
	return c.Username == "" && c.Password == "" && c.LeaseID == "" && c.ExpiresAt.IsZero()
}

// Expires reports whether this credential has an expiry to schedule a pool
// retirement against.
func (c Credential) Expires() bool { return !c.ExpiresAt.IsZero() }

// TTL is how long this credential was issued for: ExpiresAt minus IssuedAt.
// It is zero for a credential that does not expire, and it is read from the
// credential rather than from a clock so that the validation it feeds —
// whether the lease is long enough for this deployment's transactions to
// drain inside it — is a property of what was issued rather than of when the
// check happened to run.
func (c Credential) TTL() time.Duration {
	if !c.Expires() || c.IssuedAt.IsZero() {
		return 0
	}
	return c.ExpiresAt.Sub(c.IssuedAt)
}

// String names the username and the validity window, and redacts the
// password and the lease id.
//
// The username is deliberately not redacted. For a dynamically issued
// credential it is the ephemeral role name Postgres knows the session by —
// the one thing that lets an operator match a pg_stat_activity row, a server
// log line and an issuer's audit entry to each other — and it is not a
// secret: it is visible to every session in the cluster through
// pg_stat_activity. The validity window is printed for the same reason, and
// because a pool retired too early or too late is diagnosed from exactly
// those two instants.
func (c Credential) String() string {
	return fmt.Sprintf("tenancy.Credential{Username: %q, Password: %s, LeaseID: %s, IssuedAt: %s, ExpiresAt: %s}",
		c.Username, Redacted, Redacted, renderInstant(c.IssuedAt), renderInstant(c.ExpiresAt))
}

// Format implements fmt.Formatter, the only interface fmt consults for every
// verb. Without it, %#v, %d and %c reflect this struct and print the password
// — %#v as a quoted Go literal, which is the most copy-pasteable form there
// is.
func (c Credential) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, c.String()) }

// MarshalJSON renders the same summary as a JSON string. Password is an
// exported field of a plain string type, so without this method
// encoding/json — and slog's JSONHandler, which is built on it — emitted the
// issued password verbatim.
func (c Credential) MarshalJSON() ([]byte, error) { return json.Marshal(c.String()) }

// LogValue renders the credential as a slog group with the password and the
// lease id redacted, so slog.Any("credential", c) is safe under every
// handler.
//
// The two instants are strings rather than slog.Time values, which is a real
// cost — a handler can no longer reformat them — paid for the reason
// instantLayout gives: slog renders a time as extended-format RFC3339, which
// is a row of standalone two-digit numbers, and one of them collides with the
// length of the password this value holds.
func (c Credential) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("username", c.Username),
		slog.String("password", Redacted),
		slog.String("lease_id", Redacted),
		slog.String("issued_at", renderInstant(c.IssuedAt)),
		slog.String("expires_at", renderInstant(c.ExpiresAt)),
	)
}

// instantLayout renders an instant as ISO 8601 *basic* format — no hyphens
// and no colons — at the microsecond precision CanonicalTime truncates to.
//
// The separators are left out for a reason that took a CI failure to find,
// and it generalises past this type. tenancytest's
// NoSecretLeaksInAnyRendering treats the material's length in decimal as a
// leak, which is right: knowing a password is 20 characters rather than 64
// removes most of a search space. It matches that number only as a whole
// token, bounded by non-alphanumeric characters — and an extended-format
// timestamp is a row of two-digit numbers bounded by exactly that. So
// "2026-10-23T15:20:08Z" contains a standalone "20", and a credential whose
// password happened to be 20 characters long — which is what OpenBao issues
// by default — failed the subtest at 15:20 and passed at 15:21.
//
// The subtest already drops slog's own timestamp for this reason; what it
// did not anticipate is a *value* that carries instants of its own. Basic
// format makes each one a single alphanumeric run, so no substring of it is
// a standalone token and no password length can collide with it. The
// information is identical and no less diagnosable.
//
// This is not specific to credentials, and it is worth knowing elsewhere:
// any type whose safe rendering prints a small integer — a port, a
// capacity, a version — can collide with the length of a secret it holds.
// Pool.String prints WorkerCapacity, which is the same hazard with a
// smaller surface.
const instantLayout = "20060102T150405.000000Z"

// renderInstant formats an instant for the renderings above, naming the zero
// time as "never" rather than printing Go's zero date — a pool that is never
// retired for credential age is the normal, default case, and "never" is what
// an operator needs to read there.
func renderInstant(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return t.UTC().Format(instantLayout)
}

// StaticDSNCredentials is the default Credentials implementation: every pool
// connects on the credential its registry row's MetadataDSN already carries,
// and no pool is ever retired because of credential age.
//
// It performs no I/O and holds nothing, which is the point — it is declared
// here beside the port, in the same shape and for the same reason as
// SystemClock beside Clock, because a module whose default behaviour needs a
// package and a constructor has made the default the exception.
//
// What a deployment gives up by staying here is stated plainly: the
// connection string in each pool row is a long-lived shared secret, it is
// the same secret for every process that resolves that pool, and rotating it
// is a fleet-wide event that this module cannot schedule against because
// nothing announces it. The alternative, and the measurements behind it, are
// in credentials/openbao.
type StaticDSNCredentials struct{}

// Issue returns the zero Credential: connect as the pool row says.
func (StaticDSNCredentials) Issue(context.Context, Pool) (Credential, error) {
	return Credential{}, nil
}

// Release is a no-op: nothing was issued, so there is nothing to hand back.
func (StaticDSNCredentials) Release(context.Context, Credential) error { return nil }

// The default is held to the port at compile time.
var _ Credentials = StaticDSNCredentials{}
