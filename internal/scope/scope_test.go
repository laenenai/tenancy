package scope_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/laenenai/tenancy/internal/domain"
	"github.com/laenenai/tenancy/internal/scope"
)

func TestOpenRejectsInvalidConfig(t *testing.T) {
	t.Parallel()

	base := scope.Config{
		RegistryDSN: domain.DSN("postgres://user:password@127.0.0.1:1/tenancy"),
		AppRole:     "app",
	}
	cases := map[string]func(*scope.Config){
		"negative ttl":             func(c *scope.Config) { c.Cache.TTL = -time.Second },
		"negative negative ttl":    func(c *scope.Config) { c.Cache.NegativeTTL = -time.Second },
		"min greater than max":     func(c *scope.Config) { c.Postgres.MinConns = 2; c.Postgres.MaxConns = 1 },
		"negative lead":            func(c *scope.Config) { c.LongestTransaction = -time.Second },
		"credentials without lead": func(c *scope.Config) { c.Credentials = domain.StaticDSNCredentials{}; c.LongestTransaction = 0 },
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cfg := base
			mutate(&cfg)
			_, err := scope.Open(context.Background(), cfg)
			if !errors.Is(err, domain.ErrInvalidConfig) {
				t.Fatalf("Open() error = %v, want ErrInvalidConfig", err)
			}
		})
	}
}
