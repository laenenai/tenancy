// Command q3 measures what a static role's password rotation does to a live
// *pgxpool.Pool, and whether a pool can learn that a rotation is coming
// BEFORE it happens rather than discovering it as a connection failure.
//
// It builds a pool on the current static credential, warms it to a known
// number of live connections, then triggers rotate-role and watches three
// things separately:
//
//  1. queries served by connections that were already open
//  2. a query that forces the pool to open a NEW connection
//  3. what sys/static-creds reports before and after — the candidate signal
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"spike/openbaodbcreds/baospike"
)

var (
	baoAddr  = flag.String("bao", "http://localhost:58200", "OpenBao address")
	baoToken = flag.String("token", "spike-root", "OpenBao token")
	role     = flag.String("role", "app-runtime", "static role name")
	pgHost   = flag.String("pghost", "localhost", "Postgres host")
	pgPort   = flag.Int("pgport", 55432, "Postgres port")
	pgDB     = flag.String("pgdb", "spike", "Postgres database")
	warm     = flag.Int("warm", 4, "connections to warm before rotating")
	watch    = flag.Duration("watch", 30*time.Second, "how long to probe after rotating")
	// lifetime sets pool_max_conn_lifetime. The default 0 leaves pgxpool's
	// own default in place; a small value is how this measures the thing
	// that actually kills a rotated-out pool: pgxpool recycling healthy
	// connections it can no longer replace.
	lifetime = flag.Duration("lifetime", 0, "pool_max_conn_lifetime; 0 leaves pgxpool's default")
)

var start time.Time

func stamp(format string, args ...any) {
	fmt.Printf("[t+%6.2fs] %s\n", time.Since(start).Seconds(), fmt.Sprintf(format, args...))
}

func main() {
	flag.Parse()
	ctx := context.Background()
	bao := baospike.New(*baoAddr, *baoToken)
	start = time.Now()

	// --- the candidate signal, before anything happens ---
	cred, resp, err := bao.StaticCreds(ctx, *role)
	if err != nil {
		log.Fatalf("read static-creds: %v", err)
	}
	stamp("static-creds BEFORE: user=%s lease_duration=%d data=%s", cred.Username, resp.LeaseDuration, string(resp.Data))

	dsn := fmt.Sprintf(
		"postgres://%s:%s@%s:%d/%s?sslmode=disable&pool_max_conns=10&pool_min_conns=0",
		cred.Username, cred.Password, *pgHost, *pgPort, *pgDB)
	if *lifetime > 0 {
		dsn += "&pool_max_conn_lifetime=" + lifetime.String() + "&pool_health_check_period=1s"
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		log.Fatalf("build the pool: %v", err)
	}
	defer pool.Close()

	// Warm exactly *warm connections by holding that many at once.
	held := make([]*pgxpool.Conn, 0, *warm)
	pids := make([]int, 0, *warm)
	for range *warm {
		c, err := pool.Acquire(ctx)
		if err != nil {
			log.Fatalf("warm the pool: %v", err)
		}
		var pid int
		if err := c.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
			log.Fatalf("read the backend pid: %v", err)
		}
		held = append(held, c)
		pids = append(pids, pid)
	}
	for _, c := range held {
		c.Release()
	}
	stamp("pool warmed: %d idle connections, backend pids=%v stat=%s", *warm, pids, statLine(pool))

	// --- rotate ---
	stamp("POST database/rotate-role/%s ...", *role)
	rotateStart := time.Now()
	_, err = bao.Do(ctx, http.MethodPost, "database/rotate-role/"+*role, nil)
	stamp("rotate-role returned after %.3fs err=%v", time.Since(rotateStart).Seconds(), err)

	after, resp2, err := bao.StaticCreds(ctx, *role)
	if err != nil {
		stamp("read static-creds after: %v", err)
	} else {
		stamp("static-creds AFTER: user=%s password_changed=%t data=%s", after.Username, after.Password != cred.Password, string(resp2.Data))
	}

	// --- 1. existing pooled connections ---
	deadline := time.Now().Add(*watch)
	firstPooledFailure := ""
	firstNewConnFailure := ""
	newConnEverOK := false
	for time.Now().Before(deadline) {
		// Acquire the warmed connections again (pgxpool hands back the same
		// backends while they are healthy), and query on each.
		okPids, failures := queryEach(ctx, pool, *warm)
		if len(failures) > 0 && firstPooledFailure == "" {
			firstPooledFailure = fmt.Sprintf("t+%.2fs %v", time.Since(start).Seconds(), failures[0])
		}

		// Force a genuinely NEW backend: hold everything the pool has, then
		// ask for one more.
		newErr := forceNewConn(ctx, pool, *warm)
		switch {
		case newErr == nil:
			newConnEverOK = true
		case firstNewConnFailure == "":
			firstNewConnFailure = fmt.Sprintf("t+%.2fs %s", time.Since(start).Seconds(), short(newErr))
		}

		stamp("pooled: %d/%d ok pids=%v | new connection: %s | %s",
			len(okPids), *warm, okPids, okOrErr(newErr), statLine(pool))
		if pool.Stat().TotalConns() == 0 {
			stamp("POOL IS DEAD: every connection recycled, none replaceable")
			break
		}
		time.Sleep(3 * time.Second)
	}

	// --- 4. and what pool.Ping says, since that is the obvious thing a
	// health check would call: it can be served by an existing connection
	// and so say nothing about whether the pool can still GROW.
	stamp("pool.Ping (may reuse an existing connection) -> %v", pool.Ping(ctx))

	fmt.Printf("\n--- summary ---\n")
	fmt.Printf("existing pooled connections, first failure: %s\n", orNone(firstPooledFailure))
	fmt.Printf("new connections, first failure:             %s\n", orNone(firstNewConnFailure))
	fmt.Printf("a new connection ever succeeded after rotation: %t\n", newConnEverOK)
}

// queryEach holds n connections at once and runs a query on each, so every
// warmed backend is exercised rather than whichever one the pool hands out
// first n times.
func queryEach(ctx context.Context, pool *pgxpool.Pool, n int) (okPids []int, failures []error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var (
		mu   sync.Mutex
		wg   sync.WaitGroup
		held []*pgxpool.Conn
	)
	for range n {
		c, err := pool.Acquire(ctx)
		if err != nil {
			failures = append(failures, err)
			break
		}
		held = append(held, c)
	}
	for _, c := range held {
		wg.Add(1)
		go func(c *pgxpool.Conn) {
			defer wg.Done()
			var pid int
			err := c.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				failures = append(failures, err)
				return
			}
			okPids = append(okPids, pid)
		}(c)
	}
	wg.Wait()
	for _, c := range held {
		c.Release()
	}
	return okPids, failures
}

// forceNewConn pins every connection the pool currently has and then asks
// for one more, which pgxpool can only satisfy by dialing Postgres again.
func forceNewConn(ctx context.Context, pool *pgxpool.Pool, n int) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	held := make([]*pgxpool.Conn, 0, n)
	defer func() {
		for _, c := range held {
			c.Release()
		}
	}()
	for range n {
		c, err := pool.Acquire(ctx)
		if err != nil {
			return fmt.Errorf("pin an existing connection: %w", err)
		}
		held = append(held, c)
	}
	extra, err := pool.Acquire(ctx)
	if err != nil {
		return err
	}
	var pid int
	err = extra.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid)
	extra.Release()
	return err
}

func statLine(pool *pgxpool.Pool) string {
	s := pool.Stat()
	return fmt.Sprintf("stat{total=%d idle=%d acquired=%d new=%d}", s.TotalConns(), s.IdleConns(), s.AcquiredConns(), s.NewConnsCount())
}

func okOrErr(err error) string {
	if err == nil {
		return "OK"
	}
	return "FAIL " + short(err)
}

func short(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return fmt.Sprintf("SQLSTATE %s: %s", pgErr.Code, pgErr.Message)
	}
	s := err.Error()
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	return s
}

func orNone(s string) string {
	if s == "" {
		return "NONE in the watch window"
	}
	return s
}
