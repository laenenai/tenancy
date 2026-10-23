// Standalone module: this spike is deliberately NOT part of the tenancy
// module. It pins its own pgx and depends on nothing in the parent, so
// `go build ./...` at the repo root skips it (Go excludes subdirectories
// that contain their own go.mod) and the spike can never affect the
// module's dependency graph or public API surface.
module spike/openbaodbcreds

go 1.25

require github.com/jackc/pgx/v5 v5.7.6

require (
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	golang.org/x/crypto v0.37.0 // indirect
	golang.org/x/sync v0.13.0 // indirect
	golang.org/x/text v0.24.0 // indirect
)
