// Command q2rls is the adversarial half of Q2. Q2 establishes that an
// inheriting dynamic user IS covered by a policy written against the named
// role. This asks the opposite question: what would make that coverage fail
// OPEN, given that the policy is attached to a role the ephemeral user only
// belongs to?
//
// Three vectors, each measured rather than reasoned about:
//
//  1. A second PERMISSIVE policy. Postgres ORs permissive policies together,
//     so any later policy that also matches the member — including one TO
//     PUBLIC — widens what the tenant policy was meant to restrict.
//  2. The same, with the tenant predicate as AS RESTRICTIVE, which is ANDed
//     and so cannot be widened by anything added later.
//  3. The migration credential. A DDL-capable role is typically the table
//     owner or a superuser, both of which bypass RLS; FORCE ROW LEVEL
//     SECURITY closes the owner case but not the superuser one.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"strings"

	"github.com/jackc/pgx/v5"

	"spike/openbaodbcreds/baospike"
)

var (
	baoAddr  = flag.String("bao", "http://localhost:58200", "OpenBao address")
	baoToken = flag.String("token", "spike-root", "OpenBao token")
	role     = flag.String("role", "q2-inrole", "database role to issue from")
	pgHost   = flag.String("pghost", "localhost", "Postgres host")
	pgPort   = flag.Int("pgport", 55432, "Postgres port")
	pgDB     = flag.String("pgdb", "spike", "Postgres database")
)

func main() {
	flag.Parse()
	ctx := context.Background()
	bao := baospike.New(*baoAddr, *baoToken)

	admin, err := pgx.Connect(ctx, fmt.Sprintf("postgres://root:rootpass@%s:%d/%s?sslmode=disable", *pgHost, *pgPort, *pgDB))
	if err != nil {
		log.Fatalf("admin connect: %v", err)
	}
	defer func() { _ = admin.Close(context.Background()) }()

	cred, _, err := bao.Creds(ctx, *role)
	if err != nil {
		log.Fatalf("issue: %v", err)
	}
	conn, err := pgx.Connect(ctx, fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable",
		cred.Username, cred.Password, *pgHost, *pgPort, *pgDB))
	if err != nil {
		log.Fatalf("connect as the dynamic user: %v", err)
	}
	defer func() { _ = conn.Close(context.Background()) }()
	fmt.Printf("dynamic user: %s (member of app_role)\n\n", cred.Username)

	total := count(ctx, admin, "root (table owner, superuser)")

	fmt.Println("-- 1. baseline: only the PERMISSIVE tenant policy --")
	setTenant(ctx, conn, "tenant-a")
	count(ctx, conn, "dynamic user, tenant-a")

	fmt.Println("\n-- 2. a second PERMISSIVE policy is added (TO PUBLIC USING (true)) --")
	mustExec(ctx, admin, `CREATE POLICY items_oops ON items FOR SELECT TO PUBLIC USING (true)`)
	n := count(ctx, conn, "dynamic user, tenant-a")
	if n == total {
		fmt.Printf("   !! FAIL OPEN: the member now sees all %d rows; permissive policies OR\n", total)
	}

	fmt.Println("\n-- 3. the tenant predicate is made AS RESTRICTIVE instead --")
	mustExec(ctx, admin, `DROP POLICY items_tenant_isolation ON items`)
	mustExec(ctx, admin, `CREATE POLICY items_tenant_isolation ON items AS RESTRICTIVE TO app_role
		USING (tenant_id = current_setting('tenancy.tenant_id', true))
		WITH CHECK (tenant_id = current_setting('tenancy.tenant_id', true))`)
	n = count(ctx, conn, "dynamic user, tenant-a")
	fmt.Printf("   restrictive policies AND, so the stray permissive policy cannot widen it: %d rows\n", n)
	setTenant(ctx, conn, "")
	count(ctx, conn, "dynamic user, tenant UNSET (restrictive, must be 0)")

	// Restore the original shape so q2 stays reproducible.
	mustExec(ctx, admin, `DROP POLICY items_oops ON items`)
	mustExec(ctx, admin, `DROP POLICY items_tenant_isolation ON items`)
	mustExec(ctx, admin, `CREATE POLICY items_tenant_isolation ON items TO app_role
		USING (tenant_id = current_setting('tenancy.tenant_id', true))
		WITH CHECK (tenant_id = current_setting('tenancy.tenant_id', true))`)

	fmt.Println("\n-- 4. the migration credential's relationship to RLS --")
	for _, q := range []struct{ label, sql string }{
		{"root rolsuper", `SELECT rolsuper::text FROM pg_roles WHERE rolname='root'`},
		{"root rolbypassrls", `SELECT rolbypassrls::text FROM pg_roles WHERE rolname='root'`},
		{"root row_security_active('items')", `SELECT row_security_active('items')::text`},
		{"items relrowsecurity", `SELECT relrowsecurity::text FROM pg_class WHERE relname='items'`},
		{"items relforcerowsecurity", `SELECT relforcerowsecurity::text FROM pg_class WHERE relname='items'`},
	} {
		var v *string
		if err := admin.QueryRow(ctx, q.sql).Scan(&v); err != nil {
			fmt.Printf("  %-38s ERROR %v\n", q.label, err)
			continue
		}
		out := "<null>"
		if v != nil {
			out = *v
		}
		fmt.Printf("  %-38s %s\n", q.label, out)
	}
	fmt.Printf("  root sees %d rows with no tenant set — RLS does not constrain a superuser at all\n", total)

	// Would a non-superuser DDL role be constrained? Measure it rather than
	// assume: a plain role with CREATE on the schema, not the table owner.
	fmt.Println("\n-- 5. a non-superuser, non-owner DDL role (what a migration credential should be) --")
	for _, stmt := range []string{
		`DROP ROLE IF EXISTS mig_role`,
		`CREATE ROLE mig_role WITH LOGIN PASSWORD 'migpass'`,
		`GRANT CREATE, USAGE ON SCHEMA public TO mig_role`,
		`GRANT ALL ON items TO mig_role`,
	} {
		mustExec(ctx, admin, stmt)
	}
	mig, err := pgx.Connect(ctx, fmt.Sprintf("postgres://mig_role:migpass@%s:%d/%s?sslmode=disable", *pgHost, *pgPort, *pgDB))
	if err != nil {
		log.Fatalf("connect as mig_role: %v", err)
	}
	defer func() { _ = mig.Close(context.Background()) }()
	var active *string
	_ = mig.QueryRow(ctx, `SELECT row_security_active('items')::text`).Scan(&active)
	fmt.Printf("  mig_role row_security_active('items')   %s\n", deref(active))
	count(ctx, mig, "mig_role, no tenant set, ALL privileges on items")
	tryExec(ctx, mig, "mig_role DDL: ALTER TABLE items ADD COLUMN", `ALTER TABLE items ADD COLUMN spike_col int`)
	tryExec(ctx, mig, "mig_role: DROP the column again", `ALTER TABLE items DROP COLUMN spike_col`)
	// 6. DDL in Postgres is gated on OWNERSHIP, not on a grantable
	// privilege, so a migration credential has to be (a member of) the
	// owning role. Does FORCE ROW LEVEL SECURITY still constrain it then?
	// That is the question that decides whether the migration credential is
	// also a cross-tenant read capability.
	fmt.Println("\n-- 6. a migration credential that is a MEMBER OF the owning role --")
	for _, stmt := range []string{
		`DROP TABLE IF EXISTS items2`,
		`DROP ROLE IF EXISTS tbl_owner`,
		`CREATE ROLE tbl_owner NOLOGIN`,
		`GRANT CREATE, USAGE ON SCHEMA public TO tbl_owner`,
		`GRANT tbl_owner TO mig_role`,
		`SET ROLE tbl_owner`,
		`CREATE TABLE items2 (id bigserial PRIMARY KEY, tenant_id text NOT NULL, payload text NOT NULL)`,
		// Seeded BEFORE FORCE is enabled: under FORCE ROW LEVEL SECURITY
		// even the owner is subject to policy, and no policy here names
		// tbl_owner, so the owner's own INSERT would be denied. That is
		// itself the measurement in section 6 — FORCE really does reach the
		// owner.
		`INSERT INTO items2 (tenant_id, payload) VALUES ('tenant-a','x'),('tenant-b','y')`,
		`ALTER TABLE items2 ENABLE ROW LEVEL SECURITY`,
		`ALTER TABLE items2 FORCE ROW LEVEL SECURITY`,
		`CREATE POLICY items2_tenant ON items2 AS RESTRICTIVE TO app_role USING (tenant_id = current_setting('tenancy.tenant_id', true))`,
		`CREATE POLICY items2_app ON items2 TO app_role USING (true)`,
		`RESET ROLE`,
	} {
		mustExec(ctx, admin, stmt)
	}
	mig2, err := pgx.Connect(ctx, fmt.Sprintf("postgres://mig_role:migpass@%s:%d/%s?sslmode=disable", *pgHost, *pgPort, *pgDB))
	if err != nil {
		log.Fatalf("connect as mig_role again: %v", err)
	}
	defer func() { _ = mig2.Close(context.Background()) }()
	scalar(ctx, mig2, "mig_role pg_has_role(tbl_owner,'USAGE')", `SELECT pg_has_role(current_user,'tbl_owner','USAGE')::text`)
	scalar(ctx, mig2, "mig_role row_security_active('items2')", `SELECT row_security_active('items2')::text`)
	tryExec(ctx, mig2, "mig_role DDL on items2 (owned by tbl_owner)", `ALTER TABLE items2 ADD COLUMN spike_col int`)
	var n2 int
	if err := mig2.QueryRow(ctx, `SELECT count(*) FROM items2`).Scan(&n2); err != nil {
		fmt.Printf("  %-46s ERROR %s\n", "mig_role SELECT items2, no tenant set", strings.ReplaceAll(err.Error(), "\n", " "))
	} else {
		fmt.Printf("  %-46s %d rows visible (items2 holds 2)\n", "mig_role SELECT items2, no tenant set", n2)
	}
	_ = mig2.Close(ctx)

	_, _ = admin.Exec(ctx, `DROP TABLE IF EXISTS items2`)
	_, _ = admin.Exec(ctx, `REVOKE ALL ON items FROM mig_role`)
	_, _ = admin.Exec(ctx, `REVOKE ALL ON SCHEMA public FROM mig_role`)
	_, _ = admin.Exec(ctx, `DROP ROLE IF EXISTS mig_role`)
	_, _ = admin.Exec(ctx, `REVOKE ALL ON SCHEMA public FROM tbl_owner`)
	_, _ = admin.Exec(ctx, `DROP ROLE IF EXISTS tbl_owner`)
}

func scalar(ctx context.Context, conn *pgx.Conn, label, sql string) {
	var v *string
	if err := conn.QueryRow(ctx, sql).Scan(&v); err != nil {
		fmt.Printf("  %-46s ERROR %s\n", label, strings.ReplaceAll(err.Error(), "\n", " "))
		return
	}
	fmt.Printf("  %-46s %s\n", label, deref(v))
}

func count(ctx context.Context, conn *pgx.Conn, label string) int {
	var n int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM items`).Scan(&n); err != nil {
		fmt.Printf("  %-46s ERROR %s\n", label, strings.ReplaceAll(err.Error(), "\n", " "))
		return -1
	}
	fmt.Printf("  %-46s %d rows visible\n", label, n)
	return n
}

func setTenant(ctx context.Context, conn *pgx.Conn, tenant string) {
	if tenant == "" {
		_, _ = conn.Exec(ctx, `RESET tenancy.tenant_id`)
		return
	}
	if _, err := conn.Exec(ctx, `SELECT set_config('tenancy.tenant_id',$1,false)`, tenant); err != nil {
		log.Fatalf("set the tenant: %v", err)
	}
}

func mustExec(ctx context.Context, conn *pgx.Conn, sql string) {
	if _, err := conn.Exec(ctx, sql); err != nil {
		log.Fatalf("%s: %v", sql, err)
	}
}

func tryExec(ctx context.Context, conn *pgx.Conn, label, sql string) {
	if _, err := conn.Exec(ctx, sql); err != nil {
		fmt.Printf("  %-46s DENIED %s\n", label, strings.ReplaceAll(err.Error(), "\n", " "))
		return
	}
	fmt.Printf("  %-46s OK\n", label)
}

func deref(s *string) string {
	if s == nil {
		return "<null>"
	}
	return *s
}
