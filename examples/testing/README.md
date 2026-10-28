# Testing with `testdb` and the conformance suites

`tenancy/testdb` is a nested module that gives each test an isolated Postgres
database. It starts empty; pass `WithMigrator` when the test needs this module's
schema.

```go
func TestTenantScopedWrite(t *testing.T) {
    db := testdb.Start(t, testdb.WithMigrator(func(ctx context.Context, dsn tenancy.DSN) error {
        return tenancy.Migrate(ctx, tenancy.MigrateConfig{
            DSN:         dsn,
            AppRole:     testdb.AppRole,
            ControlRole: testdb.ControlRole,
        })
    }))

    ctx := context.Background()
    ten, err := tenancy.Open(ctx, tenancy.Config{
        RegistryDSN: db.DSN(),
        AppRole:     testdb.AppRole,
    })
    if err != nil { t.Fatal(err) }
    t.Cleanup(func() { _ = ten.Close() })
    _ = ten
}
```

`Start` skips under `-short`, so `mise run test` is a genuine no-container loop;
`mise run test-all` runs the full suite. When `TEST_DATABASE_URL` is set, it is
used instead of starting a container, and a unique database is still created on
it.

## Run the contract against your own wiring

`tenancytest.RunTenancySuite` is the authoritative tenancy contract. Run it in
your module against your database and roles:

```go
func TestTenancyContract(t *testing.T) {
    tenancytest.RunTenancySuite(t, func(t *testing.T) tenancytest.Deployment {
        db := testdb.Start(t, testdb.WithMigrator(/* your migration */))
        return tenancytest.Deployment{
            MigrationDSN: db.DSN(),
            RuntimeDSN:   db.DSN(), // a control login in a real deployment
            AppRole:      "myapp_data",
            ControlRole:  "myapp_control",
        }
    })
}
```

The factory is called once per subtest with that subtest's own `*testing.T`, so
each subtest gets a fresh database. A consumer counts as adopted when this suite
runs green against its own wiring.

## Best practices

- Do not share one database across parallel tests or truncate between them; use
  the isolated database `Start` returns.
- Assert enforcement through `AppRole`, never the container's superuser. The
  suite checks that the superuser bypass is real before relying on the role
  switch.
- Give the data role no registry privileges and do not make it a table owner.
- Keep the test harness in the `testdb` module; do not copy testcontainers into
  production code.
- Run `mise run test-all` before release; `-short` is not a substitute for the
  container suite.
