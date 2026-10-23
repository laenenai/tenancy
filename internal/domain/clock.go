package domain

import "time"

// Clock abstracts the current time so id generation, cache expiry and
// anything else that reads "now" can be driven deterministically in tests.
//
// It is declared here rather than imported from a shared module on
// purpose: returning the current time is not a thing you get subtly wrong,
// so it is a convention and not a module (see CONVENTIONS.md). Go's
// structural typing makes this interface interchangeable with every other
// module's identically shaped one at zero coupling.
type Clock interface {
	Now() time.Time
}

// SystemClock is the production Clock, backed by the real wall clock.
type SystemClock struct{}

// Now returns the current wall-clock time.
func (SystemClock) Now() time.Time { return time.Now() }

var _ Clock = SystemClock{}

// FixedClock is a test Clock that returns a fixed instant until advanced.
// It is not safe for concurrent use.
type FixedClock struct {
	now time.Time
}

// NewFixedClock returns a FixedClock starting at t.
func NewFixedClock(t time.Time) *FixedClock {
	return &FixedClock{now: t}
}

// Now returns the clock's current fixed instant.
func (c *FixedClock) Now() time.Time { return c.now }

// Advance moves the clock's fixed instant forward by d.
func (c *FixedClock) Advance(d time.Duration) { c.now = c.now.Add(d) }

var _ Clock = (*FixedClock)(nil)

// CanonicalTime truncates t to UTC microseconds.
//
// Postgres timestamptz holds microseconds. A value carrying nanoseconds
// round-trips equal in memory and unequal through the database, so every
// instant that enters an equality comparison — a cache expiry read back
// out of a row, a created_at a caller compares — is canonicalized first.
//
// These are deliberately the same three lines, with the same test, as
// `audit`'s domain.CanonicalTime: the order of UTC conversion versus
// truncation changes the result, which makes it the one piece of time
// handling that is shared *logic* rather than a shared interface. Copied
// rather than reinvented, per CONVENTIONS.md.
func CanonicalTime(t time.Time) time.Time {
	return t.UTC().Truncate(time.Microsecond)
}
