package pg_test

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"testing"

	"github.com/laenenai/tenancy/internal/domain"
	"github.com/laenenai/tenancy/internal/pg"
	"github.com/laenenai/tenancy/testdb"
)

// TestTenantTxNeverRendersTheConnectionsPassword asserts two things about
// TenantTx's renderings, and the first one is not the defect it was reported
// as.
//
// CAS's adoption reported that TenantTx reaches the connection's password
// through its unexported pgx.Tx. Checked by removing Format and re-running:
// fmt prints *pgxpool.Tx as &{0xc0003…} — pointer values, not pointee contents,
// since fmt dereferences only at the top level — and nothing disclosed the
// password. The chain exists; fmt does not walk it. Scoped was a real leak
// because it holds its pool row by value, and that difference is the whole
// distinction.
//
// The test is kept, with its name, because the property is worth holding even
// though it currently holds for a reason outside this package's control: pgx
// could embed a config by value in a future version, and this fails the moment
// it does. The second assertion — that a rendering names the type — is the one
// that fails today without Format, and it is the one the four methods are
// actually for.
//
// It runs against a live transaction rather than a zero value: a zero TenantTx
// has a nil tx and would pass while proving nothing.
func TestTenantTxNeverRendersTheConnectionsPassword(t *testing.T) {
	t.Parallel()

	// The DSN testdb hands back carries the container's real password, so the
	// canary is whatever that password actually is — a fabricated one would
	// prove nothing, since it is not what the connection holds.
	db := testdb.Start(t)
	password := passwordFromDSN(t, string(db.DSN()))

	tenant := domain.Tenant{ID: domain.NewTenantID(domain.SystemClock{})}
	scoped := pg.NewScoped(tenant, domain.PoolRef{}, db.Pool(), "")

	err := scoped.Tx(context.Background(), func(_ context.Context, tx pg.TenantTx) error {
		renderings := map[string]string{"String()": tx.String()}
		// The verbs are a variable rather than literal format strings, for
		// the same reason sealtest's leakVerbs is: go vet's printf analyzer
		// only inspects constant formats, and a literal Sprintf("%d", tx)
		// here is a vet failure in CI for code whose entire purpose is to
		// provoke that case. It also means removing a redaction method to
		// check this test has teeth does not simply break the build.
		for _, verb := range leakVerbs {
			renderings["fmt "+verb] = fmt.Sprintf(verb, tx)
		}
		if b, merr := json.Marshal(tx); merr != nil {
			t.Errorf("json.Marshal(TenantTx): %v", merr)
		} else {
			renderings["json.Marshal"] = string(b)
		}
		for _, h := range []string{"text", "json"} {
			var sb strings.Builder
			var handler slog.Handler
			if h == "text" {
				handler = slog.NewTextHandler(&sb, nil)
			} else {
				handler = slog.NewJSONHandler(&sb, nil)
			}
			slog.New(handler).Info("rendering", "tx", tx)
			renderings["slog "+h] = sb.String()
		}

		for name, out := range renderings {
			if strings.Contains(out, password) {
				t.Errorf("%s disclosed the connection's password: %s", name, out)
			}
			// The tenant must survive: a rendering that says nothing is not
			// diagnosable, and omitting the transaction is the redaction.
			if !strings.Contains(out, "TenantTx") {
				t.Errorf("%s = %q, want it to name the type", name, out)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Tx: %v", err)
	}
}

// leakVerbs is every verb this test renders through. %v, %s, %q, %x and %X are
// the five fmt consults fmt.Stringer for; the rest reach a value only through
// fmt.Formatter, which is why that is the load-bearing interface.
var leakVerbs = []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%c", "%U", "%b", "%o"}

// passwordFromDSN extracts the password a DSN carries, so the canary is the
// credential the connection actually holds rather than one this test made up.
func passwordFromDSN(t *testing.T, dsn string) string {
	t.Helper()

	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("parse the test dsn: %v", err)
	}
	pw, ok := u.User.Password()
	if !ok || pw == "" {
		t.Skip("the test database's DSN carries no password, so there is no credential to leak")
	}
	return pw
}
