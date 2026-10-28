#!/usr/bin/env python3
"""Merge Go text coverage profiles from several modules.

Go's text profile is line-oriented; blocks are keyed by file:start,end and
carry a statement count and a hit count. Summing hit counts for identical
blocks is the same operation `go tool cover` does internally when it merges a
package's profiles. The first `mode:` line wins; the modules use the same mode.
"""

import sys
from collections import OrderedDict

blocks: "OrderedDict[str, tuple[int, int]]" = OrderedDict()
mode = "mode: set"
skip_prefixes = (
    "github.com/laenenai/tenancy/testdb/",
    "github.com/laenenai/tenancy/integration/",
    "github.com/laenenai/tenancy/credentials/openbao/integration/",
    "github.com/laenenai/tenancy/internal/pg/integration/",
)

for path in sys.argv[1:]:
    with open(path, encoding="utf-8") as source:
        for line in source:
            line = line.strip()
            if not line:
                continue
            if line.startswith("mode:"):
                mode = line
                continue
            scope, statements, count = line.rsplit(" ", 2)
            if scope.startswith(skip_prefixes):
                continue
            stmts = int(statements)
            hits = int(count)
            if scope in blocks:
                stmts = blocks[scope][0]
                hits += blocks[scope][1]
            blocks[scope] = (stmts, hits)

print(mode)
for scope, (stmts, hits) in sorted(blocks.items()):
    print(f"{scope} {stmts} {hits}")
