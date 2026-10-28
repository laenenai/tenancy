package openbao_test

// The container harness for this package's integration tests: a real OpenBao
// with its database secrets engine configured against the real Postgres
// `tenancy`'s own harness starts.
//
// It follows the same shape CONVENTIONS.md settles for Postgres and
// keyring/keymanager/openbaotransit's testbao_test.go already implements for
// OpenBao: one server per test binary run; a uniquely named, isolated unit of
// state per test, created fresh and torn down afterwards, so tests run in
// parallel with nothing to truncate between them; an environment override
// that uses an already-running server; and a run-time skip under
// testing.Short(), never a build tag.
//
// The isolated unit here is a *mount*, as it is there: a database secrets
// engine mounted at its own path, with its own connection configuration and
// its own roles, invisible to every other mount and destroyed by one call.
//
// # The one genuinely awkward part
//
// OpenBao runs in a container and has to reach Postgres, which runs in
// another container with its port published on the host. testcontainers'
// host-port access is what bridges that: HostAccessPorts starts an SSH
// sidecar and the OpenBao container reaches the published port at
// host.testcontainers.internal. So the Postgres container has to exist
// before the OpenBao container is created, which is why baoFor takes the
// database's DSN rather than finding one itself.
//
// It lives in a _test.go file in this package rather than in an exported one
// because this is its only consumer. Promoting it is the right move when
// there is a second one, and doing it in advance would add a package to this
// module's public surface for nobody.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/laenenai/tenancy"
	"github.com/laenenai/tenancy/credentials/openbao"
)

// Environment variables that point these tests at a real OpenBao, following
// CONVENTIONS.md's TEST_DATABASE_URL pattern: when they are set, no container
// is started and the tests run against that server, in their own mounts.
//
// Note that such a server must be able to reach the Postgres these tests use,
// which in practice means setting TEST_DATABASE_URL as well.
const (
	addressEnv = "TEST_OPENBAO_ADDR"
	// authEnv names the variable holding the OpenBao token. It is named for
	// what it is for rather than for the secret it points at, so that a
	// credential-scanning linter is not asked to tell a variable name from
	// a credential.
	authEnv = "TEST_OPENBAO_TOKEN"
)

// baoImage is the image CONVENTIONS.md pins for this project's OpenBao
// adapters, and the one the 2026-10-23 spike measured against. The version is
// exact: a floating tag would make a green run say nothing about what it ran
// against.
const baoImage = "openbao/openbao:2.2.1@sha256:62f582f85e405ef00d48f678c19863d096a2bc0c05e0e5a9bbccd676a1c7316c"

// devRootToken is the root token of the dev-mode server this harness starts.
// It is a test fixture for an ephemeral container that lives for one test
// binary run, not a credential: a deployment's token comes from Config.Token
// and a developer's from the environment override above.
//
// G101 is expected and is the finding working correctly — a literal named
// "token" is exactly what it should flag — so it is silenced here, at the one
// value in this module that is deliberately not a secret, rather than by
// giving the constant a name that hides what it is.
const devRootToken = "tenancy-test-root-token" //nolint:gosec

// containerStartupTimeout bounds the wait for the server to report healthy.
// It is generous because the first run on a machine may be pulling the image.
const containerStartupTimeout = 3 * time.Minute

// The lease window every role this harness creates issues.
//
// It is long in wall-clock terms and that is deliberate: nothing in these
// tests waits for a lease to expire, because the resolver's retirement is
// driven by an injected clock. A real TTL short enough to observe would make
// every test a race against the server.
const (
	roleDefaultTTL = 30 * time.Minute
	roleMaxTTL     = time.Hour
)

// baoServer is a reachable OpenBao: either the container this harness started
// or the one an operator pointed it at.
type baoServer struct {
	address string
	token   string
}

var (
	serverOnce sync.Once
	server     baoServer
	serverErr  error
)

// baoFor returns a Config addressing a database secrets engine mounted for
// this test alone, with one role in it whose creation statements come from
// openbao.CreationStatements, and registers the unmount with t.Cleanup.
//
// dsn names the Postgres the engine issues credentials for. clock is the one
// the issued credentials' instants are computed on, so that a test driving
// retirement can share it with the resolver.
func baoFor(t *testing.T, dsn tenancy.DSN, appRole string, clock tenancy.Clock) openbao.Config {
	t.Helper()

	if testing.Short() {
		t.Skip("openbao: skipping container-backed test in -short mode; run `mise run test-all` for the full suite")
	}

	target := parseTarget(t, dsn)
	srv := sharedServer(t, target.port)

	ctx := context.Background()
	mount := "database-" + randomHex(t)
	role := "app-" + randomHex(t)

	if err := srv.do(ctx, http.MethodPost, "sys/mounts/"+mount, map[string]string{"type": "database"}); err != nil {
		t.Fatalf("openbao: mount the database engine at %s: %v", mount, err)
	}
	t.Cleanup(func() {
		// Best-effort and logged rather than failed: a cleanup failure must
		// not mask the test's own result. Against the container it does not
		// matter at all, and against a long-lived server it leaves one
		// mount named after a test run.
		if err := srv.do(context.Background(), http.MethodDelete, "sys/mounts/"+mount, nil); err != nil {
			t.Logf("openbao: cleanup: unmount %s: %v", mount, err)
		}
	})

	// The connection configuration. OpenBao reaches Postgres at
	// host.testcontainers.internal; the tests reach the same server at
	// localhost. password_authentication is scram-sha-256 so that the
	// password OpenBao sets is never sent or stored in the clear, which is
	// also what the spike measured against.
	connectionURL := fmt.Sprintf("postgresql://{{username}}:{{password}}@%s:%d/%s?sslmode=disable",
		testcontainers.HostInternal, target.port, target.database)
	// G101 fires on the "password" key below and is the finding working
	// correctly: a literal map carrying a password is exactly what it should
	// flag. It is silenced here because this is the one place in this project
	// where a database's root credential genuinely has to be sent in the
	// clear — OpenBao cannot manage a database it cannot log in to — and it
	// is the ephemeral container's, not a deployment's.
	err := srv.do(ctx, http.MethodPost, mount+"/config/target", map[string]any{ //nolint:gosec // see above
		"plugin_name":              "postgresql-database-plugin",
		"allowed_roles":            "*",
		"connection_url":           connectionURL,
		"username":                 target.user,
		"password":                 target.password,
		"password_authentication":  "scram-sha-256",
		"verify_connection":        true,
		"max_open_connections":     4,
		"max_connection_lifetime":  "5m",
		"root_rotation_statements": []string{},
	})
	if err != nil {
		t.Fatalf("openbao: configure the connection to the test database: %v", err)
	}

	// The role, built from the module's own answer for what a creation
	// statement must contain rather than from a copy of some SQL. That is
	// the point of CreationStatements being exported, and it means these
	// tests exercise the configuration this module tells operators to use.
	statements, err := openbao.CreationStatements(appRole)
	if err != nil {
		t.Fatalf("openbao.CreationStatements(%q): %v", appRole, err)
	}
	err = srv.do(ctx, http.MethodPost, mount+"/roles/"+role, map[string]any{
		"db_name":             "target",
		"creation_statements": statements,
		"default_ttl":         roleDefaultTTL.String(),
		"max_ttl":             roleMaxTTL.String(),
	})
	if err != nil {
		t.Fatalf("openbao: create the database role %s: %v", role, err)
	}

	return openbao.Config{
		Address:   srv.address,
		Token:     srv.token,
		MountPath: mount,
		Role:      role,
		Clock:     clock,
	}
}

// target is the Postgres these tests point OpenBao at, taken apart from the
// harness's own DSN.
//
// Converting the DSN to a string is a deliberate, greppable act, which is
// exactly what domain.DSN's redaction is designed to force — and this is one
// of the few places it is correct: OpenBao has to be told the root credential
// of the database it manages, and it has to be told it in the clear.
type target struct {
	user     string
	password string
	port     int
	database string
}

func parseTarget(t *testing.T, dsn tenancy.DSN) target {
	t.Helper()

	u, err := url.Parse(string(dsn))
	if err != nil {
		// Without the error, which can carry the connection string.
		t.Fatal("openbao: the test database's DSN is not a URL")
	}
	password, _ := u.User.Password()
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatalf("openbao: the test database's DSN has no usable port: %v", err)
	}
	return target{
		user:     u.User.Username(),
		password: password,
		port:     port,
		database: strings.TrimPrefix(u.Path, "/"),
	}
}

// sharedServer returns the OpenBao every test in this binary run uses: the
// server named by the environment when it is set, and otherwise a container
// started once per run (not once per test) and shared.
//
// pgPort is the published Postgres port the container must be able to reach.
// Every test in a run shares one Postgres container, so the first caller's
// port is every caller's port; a second, different port would mean a second
// Postgres, which this harness does not support and says so.
func sharedServer(t *testing.T, pgPort int) baoServer {
	t.Helper()

	serverOnce.Do(func() {
		if address := os.Getenv(addressEnv); address != "" {
			token := os.Getenv(authEnv)
			if token == "" {
				serverErr = fmt.Errorf("%s is set but %s is not", addressEnv, authEnv)
				return
			}
			server = baoServer{address: address, token: token}
			return
		}
		server, serverErr = startContainer(context.Background(), pgPort)
	})
	if serverErr != nil {
		t.Fatalf("openbao: start an OpenBao to test against: %v", serverErr)
	}
	return server
}

// startContainer runs OpenBao in dev mode, with access to the host port
// Postgres is published on, and returns its address.
//
// Dev mode is the right choice for a test server and only for a test server:
// it is unsealed, in-memory and has a known root token, so a test needs no
// unseal ceremony and nothing it holds outlives the run.
func startContainer(ctx context.Context, pgPort int) (baoServer, error) {
	container, err := testcontainers.Run(ctx, baoImage,
		testcontainers.WithExposedPorts("8200/tcp"),
		testcontainers.WithCmd("server", "-dev"),
		testcontainers.WithEnv(map[string]string{
			"BAO_DEV_ROOT_TOKEN_ID":  devRootToken,
			"BAO_DEV_LISTEN_ADDRESS": "0.0.0.0:8200",
		}),
		// The bridge to Postgres: this starts an SSH sidecar and makes the
		// host's published port reachable inside the container at
		// testcontainers.HostInternal.
		testcontainers.WithHostPortAccess(pgPort),
		testcontainers.WithWaitStrategy(
			wait.ForHTTP("/v1/sys/health").
				WithPort("8200/tcp").
				WithStartupTimeout(containerStartupTimeout),
		),
	)
	if err != nil {
		return baoServer{}, fmt.Errorf("run %s: %w", baoImage, err)
	}

	address, err := container.PortEndpoint(ctx, "8200/tcp", "http")
	if err != nil {
		return baoServer{}, fmt.Errorf("container endpoint: %w", err)
	}
	// The container is shared across the whole binary run, so there is no
	// test whose Cleanup could own it; testcontainers' reaper removes it
	// when the run ends. This is the same arrangement testdb has.
	return baoServer{address: address, token: devRootToken}, nil
}

// do performs one administrative request with the standard library, which is
// all this harness needs and keeps the adapter's own no-SDK rule true of its
// tests as well.
func (s baoServer) do(ctx context.Context, method, path string, body any) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode a %s request: %w", method, err)
		}
		reader = strings.NewReader(string(encoded))
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(s.address, "/")+"/v1/"+path, reader)
	if err != nil {
		return fmt.Errorf("build a %s request: %w", method, err)
	}
	req.Header.Set("X-Vault-Token", s.token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		message, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("%s %s: HTTP %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(message)))
	}
	return nil
}

// randomHex returns 16 hex characters of cryptographically random text, so
// two mounts never collide — including two runs against the same long-lived
// server.
func randomHex(t *testing.T) string {
	t.Helper()
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("read random bytes for a mount name: %v", err)
	}
	return hex.EncodeToString(b)
}
