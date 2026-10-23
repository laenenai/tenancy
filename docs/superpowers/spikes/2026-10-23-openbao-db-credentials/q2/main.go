// Command q2 measures whether a dynamically issued Postgres user can inherit
// an existing named role's privileges, and — the part that could silently
// fail open — whether a Row Level Security policy written against that NAMED
// role still applies to the ephemeral member.
//
// Three creation shapes are compared:
//
//	q2-inrole    CREATE ROLE "{{name}}" ... IN ROLE app_role
//	q2-grant     CREATE ROLE "{{name}}" ...; GRANT app_role TO "{{name}}"
//	q2-noinherit CREATE ROLE "{{name}}" ... NOINHERIT IN ROLE app_role
//
// For each, it reports current_user vs session_user vs the role the policy
// names, then exercises the policy from both tenants' points of view and
// from no tenant at all, and confirms the write privileges the design says
// the runtime credential must NOT have.
package main

import (
	"context"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"spike/openbaodbcreds/baospike"
)

var (
	baoAddr  = flag.String("bao", "http://localhost:58200", "OpenBao address")
	baoToken = flag.String("token", "spike-root", "OpenBao token")
	pgHost   = flag.String("pghost", "localhost", "Postgres host")
	pgPort   = flag.Int("pgport", 55432, "Postgres port")
	pgDB     = flag.String("pgdb", "spike", "Postgres database")
)

func main() {
	flag.Parse()
	ctx := context.Background()
	bao := baospike.New(*baoAddr, *baoToken)

	for _, role := range []string{"q2-inrole", "q2-grant", "q2-noinherit"} {
		fmt.Printf("\n================ database role: %s ================\n", role)
		if err := inspect(ctx, bao, role); err != nil {
			fmt.Printf("!! %s: %v\n", role, err)
		}
	}
}

func inspect(ctx context.Context, bao *baospike.Client, role string) error {
	cred, resp, err := bao.Creds(ctx, role)
	if err != nil {
		return fmt.Errorf("issue: %w", err)
	}
	fmt.Printf("issued user=%s lease_ttl=%ds\n", cred.Username, resp.LeaseDuration)

	conn, err := pgx.Connect(ctx, fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable",
		cred.Username, cred.Password, *pgHost, *pgPort, *pgDB))
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer func() { _ = conn.Close(context.Background()) }()

	// --- identity ---
	section("identity")
	scalar(ctx, conn, "current_user", `SELECT current_user`)
	scalar(ctx, conn, "session_user", `SELECT session_user`)
	scalar(ctx, conn, "current_setting('role')", `SELECT current_setting('role')`)
	scalar(ctx, conn, "rolinherit", `SELECT rolinherit::text FROM pg_roles WHERE rolname = current_user`)
	scalar(ctx, conn, "rolbypassrls", `SELECT rolbypassrls::text FROM pg_roles WHERE rolname = current_user`)
	scalar(ctx, conn, "rolsuper", `SELECT rolsuper::text FROM pg_roles WHERE rolname = current_user`)
	// pg_has_role with USAGE is exactly the test Postgres applies when it
	// decides whether a policy's TO clause matches the current user, so this
	// is the direct answer to "does the policy see me".
	scalar(ctx, conn, "pg_has_role(current_user,'app_role','USAGE')", `SELECT pg_has_role(current_user,'app_role','USAGE')::text`)
	scalar(ctx, conn, "pg_has_role(current_user,'app_role','MEMBER')", `SELECT pg_has_role(current_user,'app_role','MEMBER')::text`)
	scalar(ctx, conn, "has_table_privilege SELECT items", `SELECT has_table_privilege('items','SELECT')::text`)
	scalar(ctx, conn, "has_table_privilege INSERT items", `SELECT has_table_privilege('items','INSERT')::text`)
	scalar(ctx, conn, "has_table_privilege UPDATE items", `SELECT has_table_privilege('items','UPDATE')::text`)
	scalar(ctx, conn, "has_table_privilege DELETE items", `SELECT has_table_privilege('items','DELETE')::text`)
	scalar(ctx, conn, "has_table_privilege TRUNCATE items", `SELECT has_table_privilege('items','TRUNCATE')::text`)
	// row_security_active answers "is RLS being enforced for me on this
	// table right now" — the single most important fail-open check.
	scalar(ctx, conn, "row_security_active('items')", `SELECT row_security_active('items')::text`)

	// --- RLS, from each vantage point ---
	section("RLS enforcement")
	for _, tenant := range []string{"", "tenant-a", "tenant-b", "' OR true --"} {
		label := tenant
		if tenant == "" {
			label = "(unset)"
			exec(ctx, conn, `RESET tenancy.tenant_id`)
		} else {
			if _, err := conn.Exec(ctx, `SELECT set_config('tenancy.tenant_id', $1, false)`, tenant); err != nil {
				fmt.Printf("  set tenant %q: %v\n", label, err)
				continue
			}
		}
		var n int
		err := conn.QueryRow(ctx, `SELECT count(*) FROM items`).Scan(&n)
		if err != nil {
			fmt.Printf("  tenant=%-12s SELECT count(*) -> ERROR %s\n", label, short(err))
		} else {
			fmt.Printf("  tenant=%-12s SELECT count(*) -> %d rows visible\n", label, n)
		}
	}

	section("writes")
	exec(ctx, conn, `SELECT set_config('tenancy.tenant_id','tenant-a',false)`)
	tryExec(ctx, conn, "INSERT matching tenant (expect OK)", `INSERT INTO items (tenant_id,payload) VALUES ('tenant-a','q2-ok')`)
	tryExec(ctx, conn, "INSERT other tenant (expect WITH CHECK violation)", `INSERT INTO items (tenant_id,payload) VALUES ('tenant-b','q2-leak')`)
	tryExec(ctx, conn, "UPDATE (expect privilege denied)", `UPDATE items SET payload='x' WHERE tenant_id='tenant-a'`)
	tryExec(ctx, conn, "DELETE (expect privilege denied)", `DELETE FROM items WHERE tenant_id='tenant-a'`)
	tryExec(ctx, conn, "TRUNCATE (expect privilege denied)", `TRUNCATE items`)
	tryExec(ctx, conn, "DDL: CREATE TABLE (expect denied)", `CREATE TABLE q2_ddl (id int)`)
	tryExec(ctx, conn, "SET ROLE app_role", `SET ROLE app_role`)
	scalar(ctx, conn, "after SET ROLE: current_user", `SELECT current_user`)
	scalar(ctx, conn, "after SET ROLE: session_user", `SELECT session_user`)
	tryExec(ctx, conn, "RESET ROLE", `RESET ROLE`)
	scalar(ctx, conn, "after RESET ROLE: current_user", `SELECT current_user`)

	// --- does the member pick up grants the reconciler adds LATER? ---
	section("privileges granted to app_role AFTER this user existed")
	admin, err := pgx.Connect(ctx, fmt.Sprintf("postgres://root:rootpass@%s:%d/%s?sslmode=disable", *pgHost, *pgPort, *pgDB))
	if err != nil {
		return fmt.Errorf("admin connect: %w", err)
	}
	defer func() { _ = admin.Close(context.Background()) }()
	table := "late_" + strings.ReplaceAll(fmt.Sprint(time.Now().UnixNano()), "-", "")
	for _, stmt := range []string{
		fmt.Sprintf(`CREATE TABLE %s (id int)`, table),
		fmt.Sprintf(`GRANT SELECT ON %s TO app_role`, table),
	} {
		if _, err := admin.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("%s: %w", stmt, err)
		}
	}
	scalar(ctx, conn, "has_table_privilege on the new table", fmt.Sprintf(`SELECT has_table_privilege('%s','SELECT')::text`, table))
	tryExec(ctx, conn, "SELECT from the new table", fmt.Sprintf(`SELECT count(*) FROM %s`, table))
	_, _ = admin.Exec(ctx, fmt.Sprintf(`DROP TABLE %s`, table))
	return nil
}

func section(name string) { fmt.Printf("-- %s --\n", name) }

func scalar(ctx context.Context, conn *pgx.Conn, label, sql string) {
	var v *string
	if err := conn.QueryRow(ctx, sql).Scan(&v); err != nil {
		fmt.Printf("  %-46s ERROR %s\n", label, short(err))
		return
	}
	out := "<null>"
	if v != nil {
		out = *v
	}
	fmt.Printf("  %-46s %s\n", label, out)
}

func exec(ctx context.Context, conn *pgx.Conn, sql string) {
	_, _ = conn.Exec(ctx, sql)
}

func tryExec(ctx context.Context, conn *pgx.Conn, label, sql string) {
	tag, err := conn.Exec(ctx, sql)
	if err != nil {
		fmt.Printf("  %-46s DENIED %s\n", label, short(err))
		return
	}
	fmt.Printf("  %-46s OK (%s)\n", label, tag.String())
}

func short(err error) string {
	s := strings.ReplaceAll(err.Error(), "\n", " ")
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	return s
}
