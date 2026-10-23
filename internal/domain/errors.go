// This file declares the complete error taxonomy for `tenancy`: every
// package returns one of these across its boundary instead of a bare
// error, and the facade re-exports all of them so a consumer can branch on
// them with errors.Is.
//
// No sentinel here wraps another. In particular
// ErrNotAuthorizedOrNotFound's message names neither "forbidden" nor "not
// found", so a caller can never infer from an error which of the two
// applies — see its own doc comment for why that matters more here than
// anywhere else in the system.
//
// ErrMalformedID (ids.go) is deliberately NOT part of this taxonomy: it is
// a precondition failure asked before any business decision is made, not
// an authorization or existence outcome. That distinction is
// security-relevant and must not be collapsed in the other direction. On
// any lookup-by-id path — resolving an id a caller asked the registry to
// find — a malformed id MUST surface as ErrNotAuthorizedOrNotFound, never
// as ErrMalformedID, because a caller able to distinguish the two has an
// existence oracle on the tenant id space. Validation at a write boundary,
// where the caller is supplying a new id rather than asking the registry
// to resolve one, may surface ErrMalformedID directly: no existence
// question is being answered there.

package domain

import "errors"

// ErrInvalidConfig indicates that a configuration value failed validation
// and retrying will not help. Callers wrap it with fmt.Errorf("%w: ...")
// so the offending field is named in the resulting error string.
var ErrInvalidConfig = errors.New("tenancy: invalid config")

// ErrNotAuthorizedOrNotFound is returned for any registry read where the
// tenant or pool either does not exist or must not be served. The cases
// are deliberately one error.
//
// This is the sentinel resolution returns for an unknown tenant AND for a
// tenant being deleted, and the two must stay indistinguishable: a caller
// probing tenant ids must not be able to learn that an id was real but is
// being torn down. It is also what a malformed tenant id becomes on the
// resolution path (see ids.go).
var ErrNotAuthorizedOrNotFound = errors.New("tenancy: not authorized or not found")

// ErrUnavailable indicates a dependency is reachable in principle but not
// reachable right now: Postgres refused the connection, the resolver has
// been closed, or the tenant is suspended and will be servable again
// without any change to this deployment's configuration. A caller may
// retry.
//
// It is deliberately distinct from ErrInvalidConfig, which means the
// configuration itself is wrong, and from ErrNotAuthorizedOrNotFound,
// which is a definitive answer about existence.
var ErrUnavailable = errors.New("tenancy: unavailable")

// ErrConflict indicates a registry write could not complete because it
// conflicts with existing state: a duplicate tenant or pool name, a
// tenant naming a pool that does not exist, or an attempt to change a
// tenant's security mode after its first write.
var ErrConflict = errors.New("tenancy: conflict")

// ErrNoTenantScope is returned when a data-plane operation is attempted
// through a handle that carries no resolved tenant — the zero Scoped
// value, which no resolution produced.
//
// It exists because the charter's data-plane rule is that a missing
// predicate denies rather than leaking, and "deny" has to be a specific,
// testable answer rather than a nil-pointer panic. The type system stops a
// control-plane handle being used here at all; this sentinel is what
// catches the one data-plane shape Go cannot forbid, which is a zero
// value.
var ErrNoTenantScope = errors.New("tenancy: no tenant scope")
