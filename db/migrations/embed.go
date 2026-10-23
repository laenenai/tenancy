// Package migrations embeds this module's registry migrations into the
// binary, so a process applying them never depends on a SQL file existing
// on disk beside it.
//
// Embedding is a requirement of the deployment model rather than a
// convenience: a library whose tables live in its consumer's database
// cannot ask that consumer to run a migration tool. pgmigrate takes an
// fs.FS for exactly this reason.
package migrations

import "embed"

// FS holds every *.sql migration file embedded at build time.
//
//go:embed *.sql
var FS embed.FS
