// Command q1 measures what happens to an ALREADY-OPEN Postgres connection
// when the OpenBao lease that minted its credential expires.
//
// Four scenarios, because the answer could plausibly differ between them:
//
//	idle          — a connection that does nothing across the expiry
//	txn           — an open transaction that has ALREADY read items (and so
//	                holds AccessShareLock on it) when the lease expires
//	txn-untouched — an open transaction that has NOT yet touched items when
//	                the lease expires, and reads it for the first time
//	                afterwards. The pair isolates whether a transaction is
//	                immune to revocation, or only a relation it already
//	                holds a lock on is.
//	prepared      — a connection with a named prepared statement on it
//	locked        — a connection holding RowExclusiveLock (an uncommitted
//	                INSERT) when the lease is revoked. Aimed at OpenBao's
//	                side: does its revocation block behind a live writer?
//
// Everything is timestamped relative to issuance so the report can state
// lead times rather than adjectives.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/jackc/pgx/v5"

	"spike/openbaodbcreds/baospike"
)

var (
	baoAddr  = flag.String("bao", "http://localhost:58200", "OpenBao address")
	baoToken = flag.String("token", "spike-root", "OpenBao token")
	role     = flag.String("role", "q1-short", "database role to issue from")
	// The locked scenario must actually succeed at an INSERT, which under
	// FORCE ROW LEVEL SECURITY needs a role the policy applies to — so it
	// uses the app_role-inheriting variant and sets the tenant first.
	lockRole = flag.String("lockrole", "q1-short-inrole", "database role for the locked scenario")
	pgHost   = flag.String("pghost", "localhost", "Postgres host as reachable from here")
	pgPort   = flag.Int("pgport", 55432, "Postgres port as reachable from here")
	pgDB     = flag.String("pgdb", "spike", "Postgres database")
	watch    = flag.Duration("watch", 45*time.Second, "how long to keep probing after issuance")
	probe    = flag.Duration("probe", 2*time.Second, "interval between probes")
)

var start time.Time

func stamp(format string, args ...any) {
	fmt.Printf("[t+%6.2fs] %s\n", time.Since(start).Seconds(), fmt.Sprintf(format, args...))
}

func main() {
	flag.Parse()
	ctx := context.Background()
	bao := baospike.New(*baoAddr, *baoToken)

	scenarios := []string{"idle", "txn", "txn-untouched", "prepared", "locked"}
	for _, scenario := range scenarios {
		fmt.Printf("\n================ scenario: %s ================\n", scenario)
		if err := run(ctx, bao, scenario); err != nil {
			log.Printf("scenario %s: %v", scenario, err)
		}
	}
}

func run(ctx context.Context, bao *baospike.Client, scenario string) error {
	start = time.Now()

	issueRole := *role
	if scenario == "locked" {
		issueRole = *lockRole
	}
	cred, resp, err := bao.Creds(ctx, issueRole)
	if err != nil {
		return fmt.Errorf("issue a credential: %w", err)
	}
	stamp("role=%s issued user=%s lease=%s ttl=%ds renewable=%t", issueRole, cred.Username, resp.LeaseID, resp.LeaseDuration, resp.Renewable)

	// VALID UNTIL is part of the creation statement; read it back so the
	// report can distinguish "Postgres thinks the password expired" from
	// "OpenBao dropped the role".
	admin, err := pgx.Connect(ctx, dsn("root", "rootpass"))
	if err != nil {
		return fmt.Errorf("connect as the admin: %w", err)
	}
	defer func() { _ = admin.Close(context.Background()) }()
	var validUntil *time.Time
	if err := admin.QueryRow(ctx, `SELECT rolvaliduntil FROM pg_roles WHERE rolname=$1`, cred.Username).Scan(&validUntil); err != nil {
		stamp("read rolvaliduntil: %v", err)
	} else if validUntil != nil {
		stamp("pg_roles.rolvaliduntil=%s (%.0fs from now)", validUntil.UTC().Format(time.RFC3339), time.Until(*validUntil).Seconds())
	}

	conn, err := pgx.Connect(ctx, dsn(cred.Username, cred.Password))
	if err != nil {
		return fmt.Errorf("connect with the issued credential: %w", err)
	}
	defer func() { _ = conn.Close(context.Background()) }()
	var backendPID int
	if err := conn.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&backendPID); err != nil {
		return fmt.Errorf("read the backend pid: %w", err)
	}
	stamp("connected, backend pid=%d", backendPID)

	var tx pgx.Tx
	switch scenario {
	case "txn-untouched":
		if tx, err = conn.Begin(ctx); err != nil {
			return fmt.Errorf("begin: %w", err)
		}
		var one int
		if err := tx.QueryRow(ctx, `SELECT 1`).Scan(&one); err != nil {
			return fmt.Errorf("open the transaction's snapshot: %w", err)
		}
		stamp("transaction open, items NOT yet touched (no lock held on it)")
	case "txn":
		if tx, err = conn.Begin(ctx); err != nil {
			return fmt.Errorf("begin: %w", err)
		}
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM items`).Scan(&n); err != nil {
			return fmt.Errorf("first read inside the transaction: %w", err)
		}
		stamp("transaction open, first read saw %d rows", n)
	case "prepared":
		if _, err := conn.Prepare(ctx, "q1_count", `SELECT count(*) FROM items`); err != nil {
			return fmt.Errorf("prepare: %w", err)
		}
		stamp("named prepared statement q1_count created")
	case "locked":
		if tx, err = conn.Begin(ctx); err != nil {
			return fmt.Errorf("begin: %w", err)
		}
		if _, err := tx.Exec(ctx, `SELECT set_config('tenancy.tenant_id','tenant-a',false)`); err != nil {
			return fmt.Errorf("set the tenant: %w", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO items (tenant_id, payload) VALUES ('tenant-a','q1-locked')`); err != nil {
			return fmt.Errorf("insert inside the transaction: %w", err)
		}
		stamp("transaction holds RowExclusiveLock on items (uncommitted INSERT)")
	}

	// For "locked" the revocation is forced early and timed, because the
	// question is whether OpenBao's own call blocks.
	revokeAt := time.Duration(-1)
	if scenario == "locked" {
		revokeAt = 4 * time.Second
	}

	deadline := time.Now().Add(*watch)
	revoked := false
	leaseGone := false
	roleGone := false
	firstFailure := ""

	// txn-untouched must not probe before the expiry, or its first probe
	// takes the lock it is meant to be missing and it becomes "txn".
	firstProbeAfter := time.Duration(0)
	if scenario == "txn-untouched" {
		firstProbeAfter = 13 * time.Second
	}

	for time.Now().Before(deadline) {
		time.Sleep(*probe)

		if !revoked && revokeAt > 0 && time.Since(start) >= revokeAt {
			stamp("calling sys/leases/revoke ...")
			revokeStart := time.Now()
			errRevoke := bao.RevokeLease(ctx, resp.LeaseID)
			stamp("revoke returned after %.2fs err=%v", time.Since(revokeStart).Seconds(), errRevoke)
			revoked = true
		}

		// Does OpenBao still know the lease?
		if !leaseGone {
			if _, err := bao.LeaseLookup(ctx, resp.LeaseID); err != nil {
				leaseGone = true
				stamp("LEASE GONE from OpenBao: %s", short(err))
			}
		}
		// Did Postgres actually lose the role?
		if !roleGone {
			var exists bool
			if err := admin.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=$1)`, cred.Username).Scan(&exists); err == nil && !exists {
				roleGone = true
				stamp("ROLE DROPPED in Postgres (pg_roles no longer has %s)", cred.Username)
			}
		}

		if time.Since(start) < firstProbeAfter {
			stamp("(holding off the first probe so no lock is taken on items yet)")
			continue
		}

		// Probe the open connection.
		probeErr := probeConn(ctx, conn, tx, scenario)
		state := "OK"
		if probeErr != nil {
			state = "FAIL: " + short(probeErr)
			if firstFailure == "" {
				firstFailure = fmt.Sprintf("t+%.2fs %v", time.Since(start).Seconds(), probeErr)
			}
		}
		alive := !conn.IsClosed()
		stamp("probe=%s conn.IsClosed=%t lease_known=%t role_exists=%t", state, !alive, !leaseGone, !roleGone)

		if probeErr != nil && !alive {
			break
		}
	}

	// Can a NEW login still be made with the same credential?
	newConn, err := pgx.Connect(ctx, dsn(cred.Username, cred.Password))
	if err != nil {
		stamp("NEW login with the same credential REFUSED: %s", short(err))
	} else {
		stamp("NEW login with the same credential still SUCCEEDS")
		_ = newConn.Close(ctx)
	}

	if tx != nil {
		// Can the transaction still commit?
		if err := tx.Commit(ctx); err != nil {
			stamp("COMMIT failed: %s", short(err))
		} else {
			stamp("COMMIT succeeded")
		}
	}

	fmt.Printf("--- summary(%s): first open-connection failure: %s ---\n", scenario, orNone(firstFailure))
	return nil
}

func probeConn(ctx context.Context, conn *pgx.Conn, tx pgx.Tx, scenario string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var n int
	switch scenario {
	case "prepared":
		return conn.QueryRow(ctx, "q1_count").Scan(&n)
	case "txn", "txn-untouched", "locked":
		if tx == nil {
			return errors.New("no transaction")
		}
		return tx.QueryRow(ctx, `SELECT count(*) FROM items`).Scan(&n)
	default:
		return conn.QueryRow(ctx, `SELECT count(*) FROM items`).Scan(&n)
	}
}

func dsn(user, password string) string {
	return fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable", user, password, *pgHost, *pgPort, *pgDB)
}

func short(err error) string {
	s := err.Error()
	if len(s) > 220 {
		s = s[:220] + "..."
	}
	return s
}

func orNone(s string) string {
	if s == "" {
		return "NONE — it never failed"
	}
	return s
}
