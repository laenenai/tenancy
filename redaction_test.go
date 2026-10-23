package tenancy_test

// Every type in this module that holds a Postgres connection string, held to
// CONVENTIONS.md's "Rendering a secret" convention by the named subtest
// tenancytest.NoSecretLeaksInAnyRendering.
//
// A DSN is the most likely real leak in this set of modules, and the reason is
// that it is simultaneously a credential and a diagnostic: it names a host and
// a database, so a developer debugging a connection failure reaches for it,
// and it carries a password. internal/pg.Open already threw away pgx's parse
// error for exactly that reason; this file holds the other half, which is
// every way Go can render the value without anyone deciding to.
//
// These tests need no database, so they run in the -short inner loop: the
// values are all constructible by hand, including pg.Scoped, which is why
// this file imports internal/pg directly rather than going through resolution.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/laenenai/tenancy"
	"github.com/laenenai/tenancy/credentials/openbao"
	"github.com/laenenai/tenancy/internal/domain"
	"github.com/laenenai/tenancy/internal/pg"
	"github.com/laenenai/tenancy/tenancytest"
)

// canaryMark is a sentinel no other part of this module produces, so a match
// in a rendering is a leak and not a coincidence.
const canaryMark = "CANARY-4f19b7e3"

// canaryDSN is a well-formed connection string carrying canaryMark where the
// password goes. It is well-formed on purpose: a malformed DSN takes different
// code paths, and the leak under test here is the ordinary one.
//
// It is assembled rather than written as a single literal because gosec's
// G101 flags a password in a URL literal — correctly, everywhere except the
// one file whose job is to prove such a URL never renders.
var canaryDSN = "postgres://app:" + canaryMark + "@db.invalid:5432/metadata?sslmode=require"

func TestNoTenancyTypeRendersADSN(t *testing.T) {
	t.Parallel()

	material := []byte(canaryDSN)

	pool := tenancy.Pool{
		ID:             tenancy.NewPoolID(tenancy.SystemClock{}),
		Name:           "pool-a",
		Region:         "eu-west-1",
		MetadataDSN:    tenancy.DSN(canaryDSN),
		BlobConfigRef:  "blob-pool-a",
		WorkerCapacity: 4,
		CreatedAt:      time.Now().UTC(),
	}

	tenant := tenancy.Tenant{
		ID:           tenancy.NewTenantID(tenancy.SystemClock{}),
		PoolID:       pool.ID,
		Name:         "tenant-a",
		Status:       tenancy.TenantStatusActive,
		SecurityMode: tenancy.SecurityModeManaged,
	}

	cases := []struct {
		name  string
		value any
	}{
		// The material's own type. Everything else below is a container.
		{"DSN", tenancy.DSN(canaryDSN)},

		// Pool is the one that crosses the boundary most often: it is
		// returned by CreatePool and PoolByID, and it is held inside
		// Scoped.
		{"Pool", pool},

		// The two configuration structs. Logging your configuration at
		// startup is the normal thing to do, which is what makes these the
		// leaks that would actually have happened.
		{"Config", tenancy.Config{RegistryDSN: tenancy.DSN(canaryDSN), AppRole: "app"}},
		{"MigrateConfig", tenancy.MigrateConfig{DSN: tenancy.DSN(canaryDSN), AppRole: "app"}},

		// NewPool is the value a consumer builds by hand.
		{"NewPool", tenancy.NewPool{
			Name:           "pool-b",
			Region:         "eu-west-1",
			MetadataDSN:    tenancy.DSN(canaryDSN),
			BlobConfigRef:  "blob-pool-b",
			WorkerCapacity: 4,
		}},

		// Scoped is the type that forced the rule: it holds its pool row —
		// and therefore the DSN — in an unexported field, where fmt cannot
		// call a method and reflects the whole subtree instead. Before
		// Scoped had its own four methods, %+v on one printed the password
		// even though domain.DSN redacts perfectly on its own.
		{"Scoped", pg.NewScoped(tenant, pool, nil, "app")},

		// The zero Scoped denies rather than panicking, and it must render
		// safely too — a handle that denied is a handle something is about
		// to log.
		{"ZeroScoped", pg.Scoped{}},

		// The conformance suite's own input struct, which holds two
		// credentials.
		{"Deployment", tenancytest.Deployment{
			MigrationDSN: tenancy.DSN(canaryDSN),
			RuntimeDSN:   tenancy.DSN(canaryDSN),
			AppRole:      "app",
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tenancytest.NoSecretLeaksInAnyRendering(t, tc.value, material)
		})
	}
}

// TestRedactedRenderingsStillSayWhatTheyAre is the other half of the
// convention: a placeholder that identifies nothing is a log line an operator
// cannot act on. Every rendering above must name its type, and a Pool must
// still report the fields that are not credentials — which is the whole
// reason a pool row is worth logging.
func TestRedactedRenderingsStillSayWhatTheyAre(t *testing.T) {
	t.Parallel()

	dsn := tenancy.DSN(canaryDSN)
	if got := dsn.String(); got != "tenancy.DSN("+domain.Redacted+")" {
		t.Errorf("DSN.String() = %q, want it to name the type and the redaction", got)
	}

	pool := tenancy.Pool{
		ID:             tenancy.NewPoolID(tenancy.SystemClock{}),
		Name:           "pool-a",
		Region:         "eu-west-1",
		MetadataDSN:    dsn,
		BlobConfigRef:  "blob-pool-a",
		WorkerCapacity: 4,
	}
	rendered := pool.String()
	for _, want := range []string{"tenancy.Pool", string(pool.ID), "pool-a", "eu-west-1", "blob-pool-a", domain.Redacted} {
		if !strings.Contains(rendered, want) {
			t.Errorf("Pool.String() = %q, want it to contain %q", rendered, want)
		}
	}
}

// canaryPassword stands in for an issued database password: a sentinel no
// other part of this module produces, long enough that a match cannot be a
// coincidence.
const canaryPassword = "CANARY-PASSWORD-8a3f21d0"

// canaryIssuerMark stands in for the bearer string a credential source
// authenticates to its own issuer with. It is named for the sentinel it is
// rather than for what it stands in for, because gosec's G101 flags a literal
// whose *name* says credential — correctly, everywhere except the one file
// whose job is to prove such a literal never renders.
const canaryIssuerMark = "CANARY-TOKEN-4b7e90ca"

// TestNoTenancyTypeRendersAnIssuedCredential is the DSN convention applied to
// the material a credential source deals in, which is new surface and the
// same class of secret: an issued password is a database password, and the
// token a source holds is a capability to mint more of them.
//
// Both are more exposed than a DSN rather than less. An issued credential is
// constructed on the resolution path, so it is in scope in every error a
// failed resolution can produce; and a Config holding the token is the value
// a deployment logs at startup.
func TestNoTenancyTypeRendersAnIssuedCredential(t *testing.T) {
	t.Parallel()

	// The instants are fixed rather than taken from the clock, and that is
	// not tidiness: NoSecretLeaksInAnyRendering treats the material's length
	// in decimal as a leak, because knowing a password is 6 characters
	// rather than 64 removes most of a search space — and a time of day is
	// a run of two-digit numbers with non-alphanumeric separators, so a
	// wall-clock timestamp in the value under test makes this subtest fail
	// at 14:43 for a 43-byte secret and pass at 14:44. Pinning the instants
	// is what makes the assertion about the value.
	cred := tenancy.Credential{
		Username:  "v-token-app-role-1792727407",
		Password:  canaryPassword,
		LeaseID:   "database/creds/app/wBdUbo7iBqD0W6KmM8IuYrXh",
		IssuedAt:  time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC),
		ExpiresAt: time.Date(2026, 10, 23, 13, 0, 0, 0, time.UTC),
	}

	t.Run("Credential", func(t *testing.T) {
		t.Parallel()
		tenancytest.NoSecretLeaksInAnyRendering(t, cred, []byte(canaryPassword))
	})

	// The lease id is material too, and for a reason worth stating: it is
	// not a secret in the sense of being hard to guess, it is a capability
	// — whoever holds it can revoke the credential out from under every
	// pool using it.
	t.Run("CredentialLeaseID", func(t *testing.T) {
		t.Parallel()
		tenancytest.NoSecretLeaksInAnyRendering(t, cred, []byte(cred.LeaseID))
	})

	t.Run("OpenBaoConfig", func(t *testing.T) {
		t.Parallel()
		tenancytest.NoSecretLeaksInAnyRendering(t, openbao.Config{
			Address:   "https://openbao.invalid:8200",
			Token:     canaryIssuerMark,
			MountPath: "database",
			Role:      "app",
		}, []byte(canaryIssuerMark))
	})

	t.Run("OpenBaoCredentials", func(t *testing.T) {
		t.Parallel()
		source, err := openbao.Open(context.Background(), openbao.Config{
			Address: "https://openbao.invalid:8200",
			Token:   canaryIssuerMark,
			Role:    "app",
		})
		if err != nil {
			t.Fatalf("openbao.Open: %v", err)
		}
		// A *Credentials holds the token in an unexported field, which is
		// the shape fmt renders most dangerously: a value reached through
		// one fails reflect.Value.CanInterface, so fmt abandons the method
		// path for the whole subtree and prints it by raw reflection.
		tenancytest.NoSecretLeaksInAnyRendering(t, source, []byte(canaryIssuerMark))
	})
}

// TestIssuedCredentialRenderingStillSaysWhatItIs is the other half of the
// convention: a placeholder that identifies nothing is a log line an operator
// cannot act on.
//
// The username is deliberately NOT redacted, and that is a decision rather
// than an omission. For a dynamically issued credential it is the ephemeral
// role name Postgres knows the session by, it is visible to every session in
// the cluster through pg_stat_activity, and it is the only identifier that
// ties one of this module's log lines to a Postgres server log line and to
// the issuer's own audit entry. The same goes for the validity window: a pool
// retired too early or too late is diagnosed from exactly those two instants.
func TestIssuedCredentialRenderingStillSaysWhatItIs(t *testing.T) {
	t.Parallel()

	cred := tenancy.Credential{
		Username:  "v-token-app-role-1792727407",
		Password:  canaryPassword,
		LeaseID:   "database/creds/app/wBdUbo7iBqD0W6KmM8IuYrXh",
		IssuedAt:  time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC),
		ExpiresAt: time.Date(2026, 10, 23, 13, 0, 0, 0, time.UTC),
	}
	rendered := cred.String()
	for _, want := range []string{
		"tenancy.Credential", "v-token-app-role-1792727407",
		"2026-10-23T12:00:00Z", "2026-10-23T13:00:00Z", domain.Redacted,
	} {
		if !strings.Contains(rendered, want) {
			t.Errorf("Credential.String() = %q, want it to contain %q", rendered, want)
		}
	}

	// A credential that does not expire renders its window as "never"
	// rather than as Go's zero date, because no retirement for credential
	// age is the normal, default case and that is what an operator needs to
	// read there.
	if got := (tenancy.Credential{}).String(); !strings.Contains(got, "never") {
		t.Errorf("the zero Credential renders as %q, want it to say its expiry is \"never\"", got)
	}
}
