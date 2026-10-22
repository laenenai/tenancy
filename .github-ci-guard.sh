#!/usr/bin/env bash
# Duplication guard. Run in every CONSUMER's CI, not here.
# Fails the build if a consumer has reintroduced a local copy of a shared
# module's responsibility. Add banned paths per consumer.
set -euo pipefail
banned=("$@")
fail=0
for p in "${banned[@]}"; do
  if [ -e "$p" ]; then echo "FORBIDDEN: $p was extracted to a shared module" >&2; fail=1; fi
done
exit $fail
