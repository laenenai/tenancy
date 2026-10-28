package openbao_test

// Unit tests for the adapter: everything that can be decided without a real
// OpenBao, which is more than it sounds. The wire protocol is plain JSON over
// HTTP, so an httptest server in the same process can stand in for the
// server's *answers* — the shapes a real server returns, including the ones a
// real server is awkward to coax into returning — and these run in the
// no-container inner loop.
//
// What is left for openbao_integration_test.go is everything that is a
// property of the server and of Postgres rather than of this code.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/laenenai/tenancy"
	"github.com/laenenai/tenancy/credentials/openbao"
)

// stubToken is the token the stub server expects. It is a fixture for an
// in-process server, not a credential, and it is also the needle every test
// below checks is absent from an error.
const stubToken = "stub-token-6f2a91c4e7" //nolint:gosec // the whole point is that it is a known value these tests look for

func fixedClock() tenancy.Clock {
	return tenancy.NewFixedClock(time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC))
}

func stubPool() tenancy.PoolRef {
	return tenancy.PoolRef{
		ID:     tenancy.NewPoolID(tenancy.SystemClock{}),
		Name:   "pool-a",
		Region: "test",
	}
}

// stubServer serves one canned response for every request and records the
// paths it was asked for.
type stubServer struct {
	status int
	body   string

	srv   *httptest.Server
	paths []string
	auth  []string
}

func newStubServer(t *testing.T, status int, body string) *stubServer {
	t.Helper()

	s := &stubServer{status: status, body: body}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.paths = append(s.paths, r.URL.Path)
		s.auth = append(s.auth, r.Header.Get("X-Vault-Token"))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(s.status)
		_, _ = w.Write([]byte(s.body))
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *stubServer) source(t *testing.T, cfg openbao.Config) *openbao.Credentials {
	t.Helper()

	if cfg.Address == "" {
		cfg.Address = s.srv.URL
	}
	if cfg.Token == "" {
		cfg.Token = stubToken
	}
	if cfg.Clock == nil {
		cfg.Clock = fixedClock()
	}
	source, err := openbao.Open(context.Background(), cfg)
	if err != nil {
		t.Fatalf("openbao.Open: %v", err)
	}
	return source
}

func TestOpenRejectsAnUnusableConfiguration(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		cfg  openbao.Config
	}{
		{"no address", openbao.Config{Token: stubToken, Role: "app"}},
		{"a relative address", openbao.Config{Address: "openbao.internal:8200", Token: stubToken, Role: "app"}},
		{"a non-http scheme", openbao.Config{Address: "unix:///var/run/bao.sock", Token: stubToken, Role: "app"}},
		{"no host", openbao.Config{Address: "https://", Token: stubToken, Role: "app"}},
		{"no token", openbao.Config{Address: "https://openbao.invalid:8200", Role: "app"}},
		{"neither Role nor RoleFor", openbao.Config{Address: "https://openbao.invalid:8200", Token: stubToken}},
		{"a relative mount", openbao.Config{
			Address: "https://openbao.invalid:8200", Token: stubToken, Role: "app", MountPath: "database/../sys",
		}},
		{"a mount with an empty segment", openbao.Config{
			Address: "https://openbao.invalid:8200", Token: stubToken, Role: "app", MountPath: "a//b",
		}},
		{"a mount with a control character", openbao.Config{
			Address: "https://openbao.invalid:8200", Token: stubToken, Role: "app", MountPath: "data\x00base",
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := openbao.Open(context.Background(), tc.cfg)
			if !errors.Is(err, tenancy.ErrInvalidConfig) {
				t.Fatalf("Open error = %v, want ErrInvalidConfig", err)
			}
			if strings.Contains(err.Error(), stubToken) {
				t.Errorf("the error discloses the token: %v", err)
			}
		})
	}
}

// TestOpenDoesNotContactTheServer pins the decision in Open's doc comment: a
// reachability check there would report a configuration mistake and an outage
// as the same symptom, and a check that passed at startup would imply a
// guarantee that does not survive the first network partition.
func TestOpenDoesNotContactTheServer(t *testing.T) {
	t.Parallel()

	stub := newStubServer(t, http.StatusOK, `{}`)
	_ = stub.source(t, openbao.Config{Role: "app"})

	if len(stub.paths) != 0 {
		t.Errorf("Open made %d requests (%v), want none", len(stub.paths), stub.paths)
	}
}

func TestCreationStatementsCarryEveryClauseThatIsLoadBearing(t *testing.T) {
	t.Parallel()

	statements, err := openbao.CreationStatements("app_role")
	if err != nil {
		t.Fatalf("CreationStatements: %v", err)
	}

	// One statement, because a two-statement form can half-succeed: a
	// CREATE that worked followed by a GRANT that did not leaves a login
	// holding nothing, and the credential still looks issued.
	if len(statements) != 1 {
		t.Fatalf("CreationStatements returned %d statements, want 1: a form that can half-succeed leaves a "+
			"credential that logs in and holds nothing.\n%v", len(statements), statements)
	}
	stmt := statements[0]

	for _, want := range []string{
		`CREATE ROLE "{{name}}"`,
		`PASSWORD '{{password}}'`,
		// Postgres enforces this one independently of whether the issuer's
		// revocation ever runs, which makes it the only part of a
		// credential's expiry that always holds.
		`VALID UNTIL '{{expiration}}'`,
		// Inheritance, which is how a policy written against the
		// application role covers the ephemeral member.
		`IN ROLE "app_role"`,
	} {
		if !strings.Contains(stmt, want) {
			t.Errorf("the creation statement does not contain %q:\n%s", want, stmt)
		}
	}

	// What it must not contain, each for a measured reason. NOINHERIT denies
	// everything; SUPERUSER and BYPASSRLS make row security inert; the
	// object-creation attributes make the credential unrevocable, because
	// Postgres refuses to drop a role that owns anything.
	for _, forbidden := range []string{"NOINHERIT", "SUPERUSER", "BYPASSRLS", "CREATEDB", "CREATEROLE", "GRANT"} {
		if strings.Contains(strings.ToUpper(stmt), forbidden) {
			t.Errorf("the creation statement contains %q:\n%s", forbidden, stmt)
		}
	}
}

func TestCreationStatementsRejectARoleNameThatIsNotAnIdentifier(t *testing.T) {
	t.Parallel()

	// The role name reaches Postgres as SQL text inside a template the
	// server expands, where no bound parameter is available — so the check
	// is the only thing standing between a configuration value and
	// injected SQL.
	for _, role := range []string{"", "app role", "app-role", `app";DROP ROLE x;--`, "1app", "appрole"} {
		if _, err := openbao.CreationStatements(role); !errors.Is(err, tenancy.ErrInvalidConfig) {
			t.Errorf("CreationStatements(%q) error = %v, want ErrInvalidConfig", role, err)
		}
	}
}

func TestIssueReadsTheCredentialAndItsLease(t *testing.T) {
	t.Parallel()

	clock := fixedClock()
	stub := newStubServer(t, http.StatusOK, `{
		"lease_id": "database/creds/app/wBdUbo7iBqD0W6KmM8IuYrXh",
		"lease_duration": 1800,
		"data": {"username": "v-token-app-1792727407", "password": "A1a-rrOYvn2fUMHqCtbi"}
	}`)
	source := stub.source(t, openbao.Config{Role: "app", MountPath: "db", Clock: clock})

	cred, err := source.Issue(context.Background(), stubPool())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	if cred.Username != "v-token-app-1792727407" || cred.Password != "A1a-rrOYvn2fUMHqCtbi" {
		t.Errorf("Issue returned %s, want the username and password the server sent", cred)
	}
	if cred.LeaseID != "database/creds/app/wBdUbo7iBqD0W6KmM8IuYrXh" {
		t.Error("Issue did not carry the lease id through, so Release would have nothing to hand back")
	}

	// The expiry is the lease duration measured from the instant the request
	// started. A lease is a duration in seconds and nothing in the response
	// says what it is relative to; using the request start is deliberately
	// conservative, so retirement is never later than the server's expiry.
	if want := clock.Now(); !cred.IssuedAt.Equal(tenancy.CanonicalTime(want)) {
		t.Errorf("IssuedAt = %s, want %s", cred.IssuedAt, want)
	}
	if want := 30 * time.Minute; cred.TTL() != want {
		t.Errorf("TTL() = %s, want %s", cred.TTL(), want)
	}

	// The mount is where it was configured, not OpenBao's default.
	if got := stub.paths[0]; got != "/v1/db/creds/app" {
		t.Errorf("Issue requested %q, want %q", got, "/v1/db/creds/app")
	}
	if stub.auth[0] != stubToken {
		t.Errorf("the request authenticated with %q, want the configured token", stub.auth[0])
	}
}

// TestIssueRefusesAStaticRolesAnswer is the adapter's refusal of static
// credentials, at the one place it can be observed: OpenBao answers a static
// role's read with an empty lease_id and a zero lease_duration, so a
// deployment that points this adapter at one gets a refusal naming the reason
// rather than a pool with no expiry to be retired against.
func TestIssueRefusesAStaticRolesAnswer(t *testing.T) {
	t.Parallel()

	stub := newStubServer(t, http.StatusOK, `{
		"lease_id": "",
		"lease_duration": 0,
		"data": {
			"username": "app_runtime",
			"password": "ega2Pkg3BchnsjZGOkt-",
			"last_vault_rotation": "2026-10-23T03:57:07.271889384Z",
			"rotation_period": 600,
			"ttl": 261
		}
	}`)
	source := stub.source(t, openbao.Config{Role: "app-runtime"})

	_, err := source.Issue(context.Background(), stubPool())
	if !errors.Is(err, tenancy.ErrInvalidConfig) {
		t.Fatalf("Issue error = %v, want ErrInvalidConfig for a credential with no lease", err)
	}
	for _, want := range []string{"lease", "static"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not mention %q, so it does not say what is wrong:\n%v", want, err)
		}
	}
}

func TestIssueRefusesAnAnswerWithNoCredentialInIt(t *testing.T) {
	t.Parallel()

	stub := newStubServer(t, http.StatusOK, `{"lease_id": "x", "lease_duration": 60, "data": {}}`)
	source := stub.source(t, openbao.Config{Role: "app"})

	if _, err := source.Issue(context.Background(), stubPool()); !errors.Is(err, tenancy.ErrInvalidConfig) {
		t.Fatalf("Issue error = %v, want ErrInvalidConfig", err)
	}
}

// TestIssueClassifiesFailuresByWhetherRetryingWouldHelp is the error taxonomy
// at this boundary. A resolution that failed because the token was refused
// must not be retried in a loop against a server that will keep saying no,
// and one that failed because the server was unreachable must be.
func TestIssueClassifiesFailuresByWhetherRetryingWouldHelp(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		status int
		body   string
		want   error
	}{
		{"a refused token", http.StatusForbidden, `{"errors":["permission denied"]}`, tenancy.ErrPermission},
		{"a missing role", http.StatusNotFound, `{"errors":[]}`, tenancy.ErrInvalidConfig},
		{"a refused request", http.StatusBadRequest, `{"errors":["unknown role"]}`, tenancy.ErrInvalidConfig},
		{"a server error", http.StatusInternalServerError, `{"errors":["internal error"]}`, tenancy.ErrUnavailable},
		{"a sealed server", http.StatusServiceUnavailable, `{"errors":["Vault is sealed"]}`, tenancy.ErrUnavailable},
		{"something that is not OpenBao", http.StatusBadGateway, `<html>proxy error</html>`, tenancy.ErrUnavailable},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			stub := newStubServer(t, tc.status, tc.body)
			source := stub.source(t, openbao.Config{Role: "app"})

			_, err := source.Issue(context.Background(), stubPool())
			if !errors.Is(err, tc.want) {
				t.Fatalf("Issue error = %v, want %v", err, tc.want)
			}
			if strings.Contains(err.Error(), stubToken) {
				t.Errorf("the error discloses the token: %v", err)
			}
			if strings.Contains(err.Error(), "metadata") {
				t.Errorf("the error discloses the pool's connection string: %v", err)
			}
		})
	}
}

func TestIssueUsesRoleForWhenItIsSet(t *testing.T) {
	t.Parallel()

	stub := newStubServer(t, http.StatusOK, `{
		"lease_id":"x","lease_duration":60,"data":{"username":"u","password":"p"}
	}`)
	source := stub.source(t, openbao.Config{
		Role: "ignored",
		RoleFor: func(p tenancy.PoolRef) (string, error) {
			return "role-for-" + p.Name, nil
		},
	})

	if _, err := source.Issue(context.Background(), stubPool()); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if got, want := stub.paths[0], "/v1/database/creds/role-for-pool-a"; got != want {
		t.Errorf("Issue requested %q, want %q: RoleFor must take precedence over Role", got, want)
	}
}

func TestIssueRefusesWhenRoleForCannotChooseARole(t *testing.T) {
	t.Parallel()

	stub := newStubServer(t, http.StatusOK, `{}`)
	cases := map[string]func(tenancy.PoolRef) (string, error){
		"RoleFor returns an error": func(tenancy.PoolRef) (string, error) {
			return "", errors.New("no role is configured for this region")
		},
		"RoleFor returns nothing": func(tenancy.PoolRef) (string, error) { return "", nil },
	}

	for name, roleFor := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			source := stub.source(t, openbao.Config{RoleFor: roleFor})
			_, err := source.Issue(context.Background(), stubPool())
			if !errors.Is(err, tenancy.ErrInvalidConfig) {
				t.Fatalf("Issue error = %v, want ErrInvalidConfig", err)
			}
			if strings.Contains(err.Error(), "metadata") {
				t.Errorf("the error discloses the pool's connection string: %v", err)
			}
		})
	}
}

// TestReleaseOfTheZeroCredentialMakesNoRequest is the port's requirement, and
// it matters here rather than only in the suite because the resolver calls
// Release for every pool it closes — including every pool connected on a
// registry row's own DSN, where there is nothing to hand back.
func TestReleaseOfTheZeroCredentialMakesNoRequest(t *testing.T) {
	t.Parallel()

	stub := newStubServer(t, http.StatusOK, `{}`)
	source := stub.source(t, openbao.Config{Role: "app"})

	if err := source.Release(context.Background(), tenancy.Credential{}); err != nil {
		t.Fatalf("Release(zero Credential) = %v, want nil", err)
	}
	if len(stub.paths) != 0 {
		t.Errorf("Release made %d requests (%v), want none", len(stub.paths), stub.paths)
	}
}

func TestReleaseRevokesTheLeaseOutsideTheMount(t *testing.T) {
	t.Parallel()

	stub := newStubServer(t, http.StatusOK, `{}`)
	source := stub.source(t, openbao.Config{Role: "app", MountPath: "db"})

	cred := tenancy.Credential{Username: "v-token-app-1", LeaseID: "db/creds/app/abc"}
	if err := source.Release(context.Background(), cred); err != nil {
		t.Fatalf("Release: %v", err)
	}

	// A lease id is a server-wide identifier, so this is the one call that
	// is not under the mount. Getting it wrong would make every release
	// fail silently against a real server.
	if got, want := stub.paths[0], "/v1/sys/leases/revoke"; got != want {
		t.Errorf("Release requested %q, want %q", got, want)
	}
}

// TestReleaseNeverNamesTheLeaseInItsError guards a deliberate omission: a
// lease id is a capability, and this error is the one most likely to be
// logged, since it is the one a deployment sees when revocation is refused.
func TestReleaseNeverNamesTheLeaseInItsError(t *testing.T) {
	t.Parallel()

	const lease = "db/creds/app/wBdUbo7iBqD0W6KmM8IuYrXh"
	stub := newStubServer(t, http.StatusBadRequest, fmt.Sprintf(
		`{"errors":["failed to revoke entry: %s"]}`, "role cannot be dropped because some objects depend on it"))
	source := stub.source(t, openbao.Config{Role: "app"})

	err := source.Release(context.Background(), tenancy.Credential{Username: "v-token-app-1", LeaseID: lease})
	if err == nil {
		t.Fatal("Release of a lease the server refused returned nil")
	}
	if strings.Contains(err.Error(), lease) {
		t.Errorf("the error discloses the lease id, which is a capability to revoke the credential: %v", err)
	}
	// The username is deliberately there: it is the ephemeral role name
	// Postgres knows the session by, visible to the whole cluster through
	// pg_stat_activity, and the only thing that ties this error to a
	// Postgres log line.
	if !strings.Contains(err.Error(), "v-token-app-1") {
		t.Errorf("the error does not name the credential, so it cannot be matched to a Postgres session: %v", err)
	}
}

// TestCheckRoleReportsEveryMisconfigurationThatWasMeasured is the startup
// check, and the cases are the spike's findings one for one. The role
// configurations below are the real shapes: each is a creation statement an
// operator could plausibly write.
func TestCheckRoleReportsEveryMisconfigurationThatWasMeasured(t *testing.T) {
	t.Parallel()

	good, err := openbao.CreationStatements("app_role")
	if err != nil {
		t.Fatalf("CreationStatements: %v", err)
	}

	roleBody := func(statements []string, defaultTTL int) string {
		quoted := make([]string, len(statements))
		for i, s := range statements {
			quoted[i] = fmt.Sprintf("%q", s)
		}
		return fmt.Sprintf(`{"data":{"creation_statements":[%s],"default_ttl":%d,"max_ttl":3600}}`,
			strings.Join(quoted, ","), defaultTTL)
	}

	cases := []struct {
		name       string
		statements []string
		defaultTTL int
		wantSaid   string
	}{
		{
			name:       "no VALID UNTIL",
			statements: []string{`CREATE ROLE "{{name}}" WITH LOGIN PASSWORD '{{password}}' IN ROLE app_role;`},
			defaultTTL: 1800,
			wantSaid:   "VALID UNTIL",
		},
		{
			name: "NOINHERIT",
			statements: []string{
				`CREATE ROLE "{{name}}" WITH LOGIN NOINHERIT PASSWORD '{{password}}' VALID UNTIL '{{expiration}}' IN ROLE app_role;`,
			},
			defaultTTL: 1800,
			wantSaid:   "NOINHERIT",
		},
		{
			name: "no membership of anything",
			statements: []string{
				`CREATE ROLE "{{name}}" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';`,
			},
			defaultTTL: 1800,
			wantSaid:   "member of an application role",
		},
		{
			name: "SUPERUSER",
			statements: []string{
				`CREATE ROLE "{{name}}" WITH LOGIN SUPERUSER PASSWORD '{{password}}' VALID UNTIL '{{expiration}}' IN ROLE app_role;`,
			},
			defaultTTL: 1800,
			wantSaid:   "row-level security",
		},
		{
			name: "BYPASSRLS",
			statements: []string{
				`CREATE ROLE "{{name}}" WITH LOGIN BYPASSRLS PASSWORD '{{password}}' VALID UNTIL '{{expiration}}' IN ROLE app_role;`,
			},
			defaultTTL: 1800,
			wantSaid:   "row-level security",
		},
		{
			name: "CREATEROLE",
			statements: []string{
				`CREATE ROLE "{{name}}" WITH LOGIN CREATEROLE PASSWORD '{{password}}' VALID UNTIL '{{expiration}}' IN ROLE app_role;`,
			},
			defaultTTL: 1800,
			wantSaid:   "cannot be dropped",
		},
		{
			name: "a GRANT of CREATE on the schema",
			statements: append(append([]string{}, good...),
				`GRANT CREATE ON SCHEMA public TO "{{name}}";`),
			defaultTTL: 1800,
			wantSaid:   "cannot be dropped",
		},
		{
			name:       "no default TTL",
			statements: good,
			defaultTTL: 0,
			wantSaid:   "no default_ttl",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			stub := newStubServer(t, http.StatusOK, roleBody(tc.statements, tc.defaultTTL))
			source := stub.source(t, openbao.Config{Role: "app"})

			check, err := source.CheckRole(context.Background(), "app")
			if err != nil {
				t.Fatalf("CheckRole: %v", err)
			}
			if check.Usable() {
				t.Fatalf("CheckRole reports this role as usable: %s\n%v", tc.name, tc.statements)
			}
			findings := strings.Join(check.Findings(), "\n")
			if !strings.Contains(findings, tc.wantSaid) {
				t.Fatalf("the findings do not mention %q, so they would send an operator to fix the wrong "+
					"thing:\n%s", tc.wantSaid, findings)
			}
		})
	}

	// And the passing answer, which has to actually pass: a check that
	// reported a finding for the configuration this module itself tells
	// operators to use would be worse than no check.
	t.Run("the configuration this module prescribes", func(t *testing.T) {
		t.Parallel()

		stub := newStubServer(t, http.StatusOK, roleBody(good, 1800))
		source := stub.source(t, openbao.Config{Role: "app"})

		check, err := source.CheckRole(context.Background(), "app")
		if err != nil {
			t.Fatalf("CheckRole: %v", err)
		}
		if !check.Usable() {
			t.Fatalf("CheckRole rejects openbao.CreationStatements's own output: %v", check.Findings())
		}
		if check.DefaultTTL != 30*time.Minute || check.MaxTTL != time.Hour {
			t.Errorf("CheckRole read default_ttl=%s max_ttl=%s, want 30m and 1h: the default TTL is what a "+
				"deployment compares against its longest transaction", check.DefaultTTL, check.MaxTTL)
		}
	})

	// A role the server does not have. It is a finding rather than an
	// error, because "you configured a role that does not exist" is
	// something a startup check should report in the same place as
	// everything else it found.
	t.Run("a role that does not exist", func(t *testing.T) {
		t.Parallel()

		stub := newStubServer(t, http.StatusNotFound, `{"errors":[]}`)
		source := stub.source(t, openbao.Config{Role: "app"})

		check, err := source.CheckRole(context.Background(), "missing")
		if err != nil {
			t.Fatalf("CheckRole: %v", err)
		}
		if check.Exists || check.Usable() {
			t.Fatalf("CheckRole reports a missing role as exists=%v usable=%v", check.Exists, check.Usable())
		}
		if !strings.Contains(strings.Join(check.Findings(), "\n"), "does not exist") {
			t.Errorf("the findings do not say the role does not exist: %v", check.Findings())
		}
	})
}

// TestNoSuperuserFalsePositive is the one case the text check could plausibly
// get backwards: NOSUPERUSER contains SUPERUSER as a substring, and a role
// spelling out the safe form must not be reported as the dangerous one.
func TestNoSuperuserFalsePositive(t *testing.T) {
	t.Parallel()

	stub := newStubServer(t, http.StatusOK, `{"data":{"creation_statements":[
		"CREATE ROLE \"{{name}}\" WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD '{{password}}' VALID UNTIL '{{expiration}}' IN ROLE app_role;"
	],"default_ttl":1800,"max_ttl":3600}}`)
	source := stub.source(t, openbao.Config{Role: "app"})

	check, err := source.CheckRole(context.Background(), "app")
	if err != nil {
		t.Fatalf("CheckRole: %v", err)
	}
	if !check.Usable() {
		t.Fatalf("a role that explicitly spells out the safe attributes is reported as unusable: %v", check.Findings())
	}
}

func TestCreationStatementsQuoteAMixedCaseRole(t *testing.T) {
	t.Parallel()

	statements, err := openbao.CreationStatements("MyApp")
	if err != nil {
		t.Fatalf("CreationStatements: %v", err)
	}
	if !strings.Contains(statements[0], `IN ROLE "MyApp"`) {
		t.Fatalf("mixed-case role was not quoted: %s", statements[0])
	}
}

func TestOpenRejectsUnsafeAddresses(t *testing.T) {
	t.Parallel()

	cases := map[string]string{ //nolint:gosec // test fixtures, not credentials
		"non-loopback http": "http://openbao.example:8200",
		"userinfo":          "https://user:password@openbao.example:8200",
		"query":             "https://openbao.example:8200?token=secret",
		"fragment":          "https://openbao.example:8200#fragment",
		"no scheme":         "openbao.example:8200",
	}
	for name, address := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := openbao.Open(context.Background(), openbao.Config{Address: address, Token: stubToken, Role: "app"})
			if !errors.Is(err, tenancy.ErrInvalidConfig) {
				t.Fatalf("Open(%q) error = %v, want ErrInvalidConfig", address, err)
			}
			if strings.Contains(err.Error(), "password") || strings.Contains(err.Error(), "secret") {
				t.Fatalf("Open error leaked address material: %v", err)
			}
		})
	}
}

func TestOpenAllowsLoopbackHTTP(t *testing.T) {
	t.Parallel()

	stub := newStubServer(t, http.StatusOK, `{"data":{"keys":["app"]}}`)
	source := stub.source(t, openbao.Config{Address: stub.srv.URL, Token: stubToken, Role: "app"})
	if source == nil {
		t.Fatal("Open returned nil source")
	}
}

func TestRedirectDoesNotForwardTheTokenToAnotherHost(t *testing.T) {
	t.Parallel()

	var receivedToken bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "" {
			receivedToken = true
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+r.URL.Path, http.StatusTemporaryRedirect) //nolint:gosec // deliberate redirect fixture
	}))
	defer origin.Close()

	source, err := openbao.Open(context.Background(), openbao.Config{
		Address: origin.URL, Token: stubToken, Role: "app",
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := source.Issue(context.Background(), stubPool()); err == nil {
		t.Fatal("Issue followed a cross-host redirect, want an error")
	}
	if receivedToken {
		t.Fatal("the vault token was forwarded to a different host")
	}
}

func TestConfigStringRedactsAddressUserinfo(t *testing.T) {
	t.Parallel()

	cfg := openbao.Config{Address: "https://user:password@openbao.example:8200", Token: stubToken} //nolint:gosec // test fixture
	rendered := fmt.Sprintf("%v %+v %#v", cfg, cfg, cfg)
	if strings.Contains(rendered, "password") || strings.Contains(rendered, "user:") {
		t.Fatalf("Config rendering leaked address userinfo: %s", rendered)
	}
}
