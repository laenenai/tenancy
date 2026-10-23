// Command q1own measures the revocation failure mode Q1 turned up by
// accident: Postgres refuses DROP ROLE for a role that owns objects
// (SQLSTATE 2BP01), and the postgresql plugin's default revocation
// statements contain no REASSIGN OWNED / DROP OWNED. So if a dynamic user
// ever creates anything, its lease cannot be revoked.
//
// This matters because it is the one way a dynamic-credential scheme leaves
// state behind in the database, and because the failure is on OpenBao's
// side, asynchronous, and invisible to the application that caused it.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"spike/openbaodbcreds/baospike"
)

var (
	baoAddr  = flag.String("bao", "http://localhost:58200", "OpenBao address")
	baoToken = flag.String("token", "spike-root", "OpenBao token")
	role     = flag.String("role", "q1-owner", "database role to issue from")
	pgHost   = flag.String("pghost", "localhost", "Postgres host")
	pgPort   = flag.Int("pgport", 55432, "Postgres port")
	pgDB     = flag.String("pgdb", "spike", "Postgres database")
)

func main() {
	flag.Parse()
	ctx := context.Background()
	bao := baospike.New(*baoAddr, *baoToken)

	// A role with CREATE on the schema, so it can own something.
	if _, err := bao.Do(ctx, http.MethodPost, "database/roles/"+*role, map[string]any{
		"db_name": "spike-pg",
		"creation_statements": []string{
			`CREATE ROLE "{{name}}" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';`,
			`GRANT CREATE, USAGE ON SCHEMA public TO "{{name}}";`,
		},
		"default_ttl": "10s",
		"max_ttl":     "30s",
	}); err != nil {
		log.Fatalf("define the role: %v", err)
	}

	cred, resp, err := bao.Creds(ctx, *role)
	if err != nil {
		log.Fatalf("issue: %v", err)
	}
	fmt.Printf("issued user=%s lease=%s ttl=%ds\n", cred.Username, resp.LeaseID, resp.LeaseDuration)

	conn, err := pgx.Connect(ctx, fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable",
		cred.Username, cred.Password, *pgHost, *pgPort, *pgDB))
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	if _, err := conn.Exec(ctx, `CREATE TABLE q1own_scratch (id int)`); err != nil {
		log.Fatalf("create a table it will own: %v", err)
	}
	fmt.Println("the dynamic user now OWNS public.q1own_scratch")
	_ = conn.Close(ctx)

	fmt.Println("revoking the lease explicitly ...")
	start := time.Now()
	errRevoke := bao.RevokeLease(ctx, resp.LeaseID)
	fmt.Printf("revoke returned after %.2fs err=%v\n", time.Since(start).Seconds(), errRevoke)

	admin, err := pgx.Connect(ctx, fmt.Sprintf("postgres://root:rootpass@%s:%d/%s?sslmode=disable", *pgHost, *pgPort, *pgDB))
	if err != nil {
		log.Fatalf("admin connect: %v", err)
	}
	defer func() { _ = admin.Close(context.Background()) }()

	for _, wait := range []time.Duration{0, 5 * time.Second, 15 * time.Second} {
		time.Sleep(wait)
		var exists bool
		_ = admin.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=$1)`, cred.Username).Scan(&exists)
		leaseState := "gone"
		if _, err := bao.LeaseLookup(ctx, resp.LeaseID); err == nil {
			leaseState = "STILL KNOWN to OpenBao"
		}
		fmt.Printf("  +%4s role_exists_in_pg=%t lease=%s\n", wait, exists, leaseState)
	}

	// What does OpenBao's own list of leases it has given up on say?
	if r, err := bao.Do(ctx, http.MethodGet, "sys/leases/lookup/database/creds/"+*role+"/?list=true", nil); err == nil {
		fmt.Printf("leases still listed under this role: %s\n", string(r.Data))
	} else {
		fmt.Printf("listing leases under this role: %v\n", err)
	}

	// Clean up by hand, which is exactly the operator burden this measures.
	_, _ = admin.Exec(ctx, `DROP TABLE IF EXISTS q1own_scratch`)
	_, _ = admin.Exec(ctx, fmt.Sprintf(`REASSIGN OWNED BY %q TO root`, cred.Username))
	_, _ = admin.Exec(ctx, fmt.Sprintf(`DROP OWNED BY %q`, cred.Username))
	_, _ = admin.Exec(ctx, fmt.Sprintf(`DROP ROLE IF EXISTS %q`, cred.Username))
	_, _ = admin.Exec(ctx, `REVOKE CREATE ON SCHEMA public FROM PUBLIC`)
	fmt.Println("cleaned up by hand (DROP TABLE / REASSIGN OWNED / DROP OWNED / DROP ROLE)")
}
