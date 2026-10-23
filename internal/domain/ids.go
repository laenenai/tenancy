// Package domain is the single home for every domain entity and value
// object in `tenancy`: the typed ids, the clock, the error taxonomy, the
// tenant and pool records, and the closed enums each carries.
//
// Two invariants live here, and both are type-system facts rather than
// review conventions.
//
// The first is that an id of one kind can never stand where an id of
// another kind is expected. TenantID and PoolID are distinct named string
// types, so a resolver that took a PoolID where a TenantID belongs does
// not compile.
//
// The second is the one this module exists for, and it is stronger. A
// *control-plane* handle reads the registry before any tenant scope
// exists; a *data-plane* handle is scoped to one resolved tenant with
// row-level-security session context set. Conflating the two is a
// cross-tenant disclosure, so the separation is carried by types that
// cannot be converted into one another: see internal/pg.Scoped and
// internal/pg.TenantTx, each a struct with unexported fields, and
// testdata/control_plane_is_not_a_data_plane_handle.go, which the compiler
// is required to reject.
package domain

import (
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/oklog/ulid/v2"
)

// ErrMalformedID is returned by the Parse*ID functions when the input is
// not a syntactically valid ULID string. It is a parse/validation error
// rather than a business-rule outcome, so it is declared here and not in
// the taxonomy in errors.go.
//
// On a lookup-by-id path it must never reach a caller: resolving an id the
// caller asked the registry to find surfaces ErrNotAuthorizedOrNotFound
// instead, because a caller able to tell "well-formed but invisible" apart
// from "nonsense" has an existence oracle on the id space. See errors.go.
var ErrMalformedID = errors.New("malformed id")

// TenantID identifies a tenant: the top-level unit of isolation. Every
// tenant-scoped row and every row-level-security policy in every pool keys
// off this id.
type TenantID string

// PoolID identifies a pool: one physical Postgres database that hosts the
// metadata of one or more tenants.
type PoolID string

// newID mints a fresh id of type T from the current time of clock, using
// cryptographically random entropy for the non-timestamp bits. Values sort
// lexicographically by creation time because a ULID's 48-bit millisecond
// timestamp occupies its leading, fixed-width characters.
//
// ulid.MustNew panics if entropy fails to supply enough random bytes. That
// is inherited deliberately from `cas`, not overlooked: a crypto/rand read
// failure here means this process has lost its entropy source, so its
// identifiers and its encryption are both already broken, and there is
// nothing a returned error at this call site could do better than failing
// loudly.
func newID[T ~string](clock Clock) T {
	id := ulid.MustNew(ulid.Timestamp(clock.Now()), rand.Reader)
	return T(id.String())
}

// parseID validates that s is a syntactically well-formed ULID string and
// returns it as T, or a wrapped ErrMalformedID if it is not.
func parseID[T ~string](label, s string) (T, error) {
	if _, err := ulid.ParseStrict(s); err != nil {
		return T(""), fmt.Errorf("%w: %s %q: %w", ErrMalformedID, label, s, err)
	}
	return T(s), nil
}

// NewTenantID returns a fresh TenantID minted from clock.
func NewTenantID(clock Clock) TenantID { return newID[TenantID](clock) }

// ParseTenantID parses s as a TenantID, rejecting malformed input.
func ParseTenantID(s string) (TenantID, error) { return parseID[TenantID]("tenant id", s) }

// NewPoolID returns a fresh PoolID minted from clock.
func NewPoolID(clock Clock) PoolID { return newID[PoolID](clock) }

// ParsePoolID parses s as a PoolID, rejecting malformed input.
func ParsePoolID(s string) (PoolID, error) { return parseID[PoolID]("pool id", s) }
