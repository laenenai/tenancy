# Charter: `tenancy`

**It does this one thing:** Which database, bucket and region a tenant's data lives in: tenant and pool registry, resolution, residency attributes.

**It must not contain:** Authorization. Quota enforcement — it stores the pool, not the rules.

## Why this file exists

A shared module with no stated boundary accretes until it is the dependency
every project has and nobody can reason about. This charter is the boundary.
Two mechanisms enforce it rather than merely stating it:

1. **`api.txt`** in this repo is the module's public API as a golden file,
   diffed in CI. Growing the public surface requires a reviewed diff, so a new
   responsibility cannot slip in quietly.
2. **The conformance suite** (`suite.go`, following the pattern of
   `cas/internal/blob/suite.go`) is the contract. A consumer counts as
   *adopted* when this module's suite runs green in that consumer's CI against
   its own wiring — not when someone says it is adopted.

A change that does not fit the charter belongs in a different module. A module
is created when a **second** consumer needs it, not in anticipation.

## Adoption

| Consumer | State |
|---|---|
| cas | extraction pending (internal/pool + domain/{tenant,pool}.go, ~1700 lines, built) |
| kgs | pending (phase 0) |
| acre | pending (no code yet; adopts from birth) |

## Provenance

Extracted per `kgs/docs/superpowers/specs/2026-10-23-knowledge-graph-store-design.md`
§6.1 (the six-module decomposition) and §6.2 (authority and projections).
