package domain

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
)

// Redacted is the placeholder every rendering of security-relevant material
// in this module yields. It is exported so a consumer's own log scrubbing,
// and its own tests, can assert against the same literal this package writes.
const Redacted = "[REDACTED]"

// DSN is a Postgres connection string.
//
// It is a distinct type rather than a string for one reason: a DSN carries a
// password, and it is simultaneously the single most tempting thing in this
// module to print. It names a host and a database, so a developer debugging a
// connection failure reaches for it, and every form of reaching for it —
// fmt.Errorf("connect to %s", dsn), a %+v on the config that holds it, a
// configuration struct marshalled by a diagnostics endpoint, slog.Any on a
// pool row — would previously have written the password to a log.
//
// Every rendering therefore yields Redacted: see the four methods below, and
// CONVENTIONS.md's "Rendering a secret" for which rendering each one
// controls. Reading the actual connection string requires writing
// string(dsn), which is a deliberate, greppable act at a boundary rather than
// the accidental default.
//
// It is deliberately not validated here and not parsed here. internal/pg.Open
// is the one place in this module that hands a DSN to pgx, and it is audited
// for exactly that — including throwing away pgx's own parse error, whose
// text can carry the connection string through verbatim.
//
// Note the limit of giving the material its own type: it protects an
// *exported* field of a struct, because fmt consults an exported field's own
// methods, and it protects nothing reached through an unexported field, where
// reflect.Value.CanInterface is false and fmt abandons the method path for
// the whole subtree. Pool, pg.Scoped and pool.Handle therefore carry these
// four methods themselves rather than relying on this type.
type DSN string

// IsZero reports whether no connection string has been set. It exists so a
// caller can validate a configuration without converting the DSN back to a
// string and thereby reintroducing the thing this type prevents.
func (d DSN) IsZero() bool { return d == "" }

// String returns Redacted. A connection string has no safe rendering: there
// is no prefix, suffix or length of it that is both useful in a log line and
// free of the credential, and the host and database name it would otherwise
// disclose are not worth the password.
func (d DSN) String() string { return "tenancy.DSN(" + Redacted + ")" }

// Format implements fmt.Formatter, which is the only interface fmt consults
// for every verb. Stringer covers %v, %s, %q, %x and %X and nothing else, so
// without this method %#v, %d and %c would print the connection string in
// full — %#v as a quoted Go literal, which is the most copy-pasteable form
// there is.
//
// Every verb, flag, width and precision yields the same placeholder: a verb
// is a request about presentation, and this value has no presentation to
// vary. The one verb no method can cover is %p, whose bad-verb path skips
// every interface and reflects the operand; CONVENTIONS.md records that hole.
func (d DSN) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, d.String()) }

// MarshalJSON returns Redacted as a JSON string. A named string type
// marshals to its own value by default, so without this method
// json.Marshal of any struct holding a DSN — and slog's JSONHandler, which
// is built on encoding/json and therefore never consults String — emitted the
// password verbatim.
//
// It redacts rather than returning an error, because an error here would turn
// a logging mistake into a failed request.
func (d DSN) MarshalJSON() ([]byte, error) { return json.Marshal(d.String()) }

// MarshalText returns Redacted, for the libraries that reach for
// encoding.TextMarshaler rather than for json.Marshaler.
func (d DSN) MarshalText() ([]byte, error) { return []byte(d.String()), nil }

// LogValue returns Redacted, so slog.Any("dsn", dsn), the variadic
// "key", value form, and a DSN nested in an exported field of a logged struct
// all render the placeholder rather than the credential.
func (d DSN) LogValue() slog.Value { return slog.StringValue(d.String()) }
