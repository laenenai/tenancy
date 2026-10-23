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
	"strings"
	"testing"
	"time"

	"github.com/laenenai/tenancy"
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
