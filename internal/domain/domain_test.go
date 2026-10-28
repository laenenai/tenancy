package domain_test

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/laenenai/tenancy/internal/domain"
)

func TestNewIDsAreWellFormedAndSortByCreationTime(t *testing.T) {
	t.Parallel()

	clock := domain.NewFixedClock(time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC))

	first := domain.NewTenantID(clock)
	clock.Advance(time.Second)
	second := domain.NewTenantID(clock)

	if len(string(first)) != 26 {
		t.Fatalf("NewTenantID() = %q, want a 26-character ULID", first)
	}
	if string(first) >= string(second) {
		t.Fatalf("ids do not sort by creation time: %q >= %q", first, second)
	}

	if _, err := domain.ParseTenantID(string(first)); err != nil {
		t.Fatalf("ParseTenantID(%q) = %v, want nil", first, err)
	}
	if _, err := domain.ParsePoolID(string(domain.NewPoolID(clock))); err != nil {
		t.Fatalf("ParsePoolID(a fresh pool id) = %v, want nil", err)
	}
}

func TestParseIDsRejectMalformedInput(t *testing.T) {
	t.Parallel()

	cases := []string{
		"",
		"not-a-ulid",
		"01ARZ3NDEKTSV4RRFFQ69G5FA",   // 25 characters
		"01ARZ3NDEKTSV4RRFFQ69G5FAVX", // 27 characters
		"01ARZ3NDEKTSV4RRFFQ69G5FAU",  // U is not in Crockford base32
	}

	for _, s := range cases {
		t.Run(s, func(t *testing.T) {
			t.Parallel()

			if _, err := domain.ParseTenantID(s); !errors.Is(err, domain.ErrMalformedID) {
				t.Errorf("ParseTenantID(%q) error = %v, want ErrMalformedID", s, err)
			}
			if _, err := domain.ParsePoolID(s); !errors.Is(err, domain.ErrMalformedID) {
				t.Errorf("ParsePoolID(%q) error = %v, want ErrMalformedID", s, err)
			}
		})
	}
}

// TestErrNotAuthorizedOrNotFoundNamesNeitherCause is the taxonomy's one
// security-relevant assertion: a caller must not be able to read which of
// the two cases applies out of the message, because that would be an
// existence oracle on the tenant id space.
func TestErrNotAuthorizedOrNotFoundNamesNeitherCause(t *testing.T) {
	t.Parallel()

	msg := domain.ErrNotAuthorizedOrNotFound.Error()
	for _, forbidden := range []string{"forbidden", "does not exist", "no such", "deleting", "suspended"} {
		if strings.Contains(msg, forbidden) {
			t.Errorf("ErrNotAuthorizedOrNotFound says %q, which tells a caller which of the two cases applies: %q",
				forbidden, msg)
		}
	}
}

// TestSentinelsAreIndependent guards the taxonomy's shape: a caller
// branching on one sentinel must never match another. ErrUnavailable in
// particular is the suspended-tenant answer and must not also satisfy
// ErrNotAuthorizedOrNotFound.
func TestSentinelsAreIndependent(t *testing.T) {
	t.Parallel()

	all := map[string]error{
		"ErrInvalidConfig":           domain.ErrInvalidConfig,
		"ErrNotAuthorizedOrNotFound": domain.ErrNotAuthorizedOrNotFound,
		"ErrUnavailable":             domain.ErrUnavailable,
		"ErrPermission":              domain.ErrPermission,
		"ErrConflict":                domain.ErrConflict,
		"ErrNoTenantScope":           domain.ErrNoTenantScope,
		"ErrMalformedID":             domain.ErrMalformedID,
	}

	for nameA, a := range all {
		for nameB, b := range all {
			if nameA == nameB {
				continue
			}
			if errors.Is(a, b) {
				t.Errorf("errors.Is(%s, %s) is true: the sentinels must be independent", nameA, nameB)
			}
		}
	}
}

func TestSecurityModeValid(t *testing.T) {
	t.Parallel()

	for _, m := range []domain.SecurityMode{
		domain.SecurityModeManaged, domain.SecurityModeTenantKey, domain.SecurityModeVault,
	} {
		if !m.Valid() {
			t.Errorf("SecurityMode(%q).Valid() = false, want true", m)
		}
	}
	for _, m := range []domain.SecurityMode{"", "Managed", "tenant_key", "kms"} {
		if m.Valid() {
			t.Errorf("SecurityMode(%q).Valid() = true, want false", m)
		}
	}
}

func TestTenantStatusValid(t *testing.T) {
	t.Parallel()

	for _, s := range []domain.TenantStatus{
		domain.TenantStatusActive, domain.TenantStatusSuspended, domain.TenantStatusDeleting,
	} {
		if !s.Valid() {
			t.Errorf("TenantStatus(%q).Valid() = false, want true", s)
		}
	}
	for _, s := range []domain.TenantStatus{"", "Active", "deleted", "archived"} {
		if s.Valid() {
			t.Errorf("TenantStatus(%q).Valid() = true, want false", s)
		}
	}
}

func TestTenantStatusTransitions(t *testing.T) {
	t.Parallel()

	cases := []struct {
		from, to domain.TenantStatus
		want     bool
	}{
		{domain.TenantStatusActive, domain.TenantStatusActive, true},
		{domain.TenantStatusActive, domain.TenantStatusSuspended, true},
		{domain.TenantStatusActive, domain.TenantStatusDeleting, true},
		{domain.TenantStatusSuspended, domain.TenantStatusActive, true},
		{domain.TenantStatusSuspended, domain.TenantStatusSuspended, true},
		{domain.TenantStatusSuspended, domain.TenantStatusDeleting, true},
		{domain.TenantStatusDeleting, domain.TenantStatusDeleting, true},
		{domain.TenantStatusDeleting, domain.TenantStatusActive, false},
		{domain.TenantStatusDeleting, domain.TenantStatusSuspended, false},
		{"", domain.TenantStatusActive, false},
		{domain.TenantStatusActive, "", false},
	}
	for _, tc := range cases {
		if got := tc.from.CanTransitionTo(tc.to); got != tc.want {
			t.Errorf("%q.CanTransitionTo(%q) = %v, want %v", tc.from, tc.to, got, tc.want)
		}
	}
}

func TestPoolRefDoesNotCarryCredentialMaterial(t *testing.T) {
	t.Parallel()

	typ := reflect.TypeOf(domain.PoolRef{})
	for i := range typ.NumField() {
		if name := typ.Field(i).Name; strings.Contains(strings.ToLower(name), "dsn") {
			t.Errorf("PoolRef has a %s field; it must not carry connection material", name)
		}
	}

	created := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	pool := domain.Pool{ //nolint:gosec // test fixture, not a credential
		ID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Name: "pool-a", Region: "eu-west-1",
		MetadataDSN:   "postgres://user:password@db.invalid/db",
		BlobConfigRef: "blob-a", WorkerCapacity: 4, CreatedAt: created,
	}
	ref := pool.Ref()
	if ref.ID != pool.ID || ref.Name != pool.Name || ref.Region != pool.Region ||
		ref.BlobConfigRef != pool.BlobConfigRef || ref.WorkerCapacity != pool.WorkerCapacity ||
		!ref.CreatedAt.Equal(pool.CreatedAt) {
		t.Fatalf("Pool.Ref() = %+v, want the non-credential fields of %+v", ref, pool)
	}
}

func TestCredentialMarshalTextIsRedacted(t *testing.T) {
	t.Parallel()

	cred := domain.Credential{
		Username: "v-token-app-role-1",
		Password: "CANARY-PASSWORD",
		LeaseID:  "database/creds/app/lease",
	}
	b, err := cred.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText: %v", err)
	}
	if strings.Contains(string(b), cred.Password) || strings.Contains(string(b), cred.LeaseID) {
		t.Fatalf("MarshalText leaked credential material: %s", b)
	}
	if !strings.Contains(string(b), "tenancy.Credential") {
		t.Fatalf("MarshalText = %q, want it to name the type", b)
	}
}

// TestCanonicalTime is `audit`'s test, copied with the function (see
// CONVENTIONS.md: the same three lines with the same test in every module
// that compares an instant). Both halves matter — truncate rather than
// round, and convert to UTC before truncating, since doing it the other
// way round gives a different answer for a zone whose offset is not a
// whole number of microseconds past the second.
func TestCanonicalTime(t *testing.T) {
	t.Parallel()

	in := time.Date(2026, 10, 23, 14, 30, 45, 123456789, time.FixedZone("plus-two", 2*60*60))
	got := domain.CanonicalTime(in)

	if got.Location() != time.UTC {
		t.Errorf("CanonicalTime() location = %v, want UTC", got.Location())
	}
	if got.Nanosecond() != 123456000 {
		t.Errorf("CanonicalTime() nanosecond = %d, want 123456000 (truncated, not rounded)", got.Nanosecond())
	}
	if !got.Equal(in.Truncate(0).Add(-789 * time.Nanosecond)) {
		t.Errorf("CanonicalTime(%v) = %v, want the same instant truncated to microseconds", in, got)
	}
	if again := domain.CanonicalTime(got); !again.Equal(got) {
		t.Errorf("CanonicalTime is not idempotent: %v then %v", got, again)
	}
}

func TestFixedClockAdvances(t *testing.T) {
	t.Parallel()

	start := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	clock := domain.NewFixedClock(start)

	if !clock.Now().Equal(start) {
		t.Fatalf("Now() = %v, want %v", clock.Now(), start)
	}
	clock.Advance(90 * time.Minute)
	if want := start.Add(90 * time.Minute); !clock.Now().Equal(want) {
		t.Fatalf("Now() after Advance = %v, want %v", clock.Now(), want)
	}
}

func FuzzParseTenantID(f *testing.F) {
	for _, seed := range []string{"", "not-a-ulid", "01ARZ3NDEKTSV4RRFFQ69G5FAV"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		id, err := domain.ParseTenantID(s)
		if err == nil && string(id) != s {
			t.Fatalf("ParseTenantID(%q) returned %q; a successful parse must be lossless", s, id)
		}
	})
}

func FuzzParsePoolID(f *testing.F) {
	for _, seed := range []string{"", "not-a-ulid", "01ARZ3NDEKTSV4RRFFQ69G5FAV"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		id, err := domain.ParsePoolID(s)
		if err == nil && string(id) != s {
			t.Fatalf("ParsePoolID(%q) returned %q; a successful parse must be lossless", s, id)
		}
	})
}
