package tenancy_test

import (
	"testing"

	"github.com/laenenai/tenancy"
	"github.com/laenenai/tenancy/tenancytest"
	"github.com/laenenai/tenancy/testdb"
)

// TestConformance runs this module's own conformance suite against this
// module's own harness.
//
// It is the same function a consumer calls, which is the point of the suite
// living in a sibling package: `cas`, `kgs` and `acre` each run it against
// their own database and their own roles, and a deployment that cannot pass
// it is a deployment whose tenant isolation does not hold — which is worth
// finding out in that project's CI rather than in production.
//
// The factory is called once per subtest with that subtest's own *T, so
// every subtest gets a freshly created, empty database and the subtests are
// independent. testdb.Start registers its own cleanup and skips under
// -short, so this test needs no gate of its own.
//
// Both DSNs are the same string here, and that is the honest shape for a
// container harness: one superuser credential, with AppRole doing the
// narrowing. It is also the weaker of the two configurations the suite
// supports, which makes it the right one for this module to test itself
// against — the superuser bypass is real on this harness, so the suite's
// bypass-is-real control assertions actually run instead of being skipped
// as inapplicable.
func TestConformance(t *testing.T) {
	tenancytest.RunTenancySuite(t, func(t *testing.T) tenancytest.Deployment {
		db := testdb.Start(t)
		return tenancytest.Deployment{
			MigrationDSN: db.DSN(),
			AppRole:      testdb.AppRole,
			ControlRole:  testdb.ControlRole,
		}
	})
}

// TestStaticDSNCredentialsConformance runs the credentials suite against the
// default credential source: the one that hands back the credential a pool
// row already carries.
//
// Most of that suite does not apply to it and skips with the reason, which is
// the honest outcome rather than a thin pass — a source that performs no I/O
// and returns the zero Credential is making exactly two promises, that the
// credential it hands back connects and that it declares no expiry, and both
// are asserted. The suite's other half is run against the OpenBao adapter in
// credentials/openbao, which is where the claims about what an *issued*
// credential may do belong.
//
// It runs here and not only there because the default is the implementation
// every deployment gets, and "the default satisfies the port" is a claim worth
// a test rather than an inspection.
func TestStaticDSNCredentialsConformance(t *testing.T) {
	tenancytest.RunCredentialsSuite(t, func(t *testing.T) tenancytest.CredentialSource {
		db := testdb.Start(t)
		return tenancytest.CredentialSource{
			Credentials: tenancy.StaticDSNCredentials{},
			Deployment: tenancytest.Deployment{
				MigrationDSN: db.DSN(),
				AppRole:      testdb.AppRole,
			},
		}
	})
}
