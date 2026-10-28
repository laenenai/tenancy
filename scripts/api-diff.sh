#!/usr/bin/env bash
# Compare the current module's exported API with the last root release tag.
#
# apidiff is the Go team's export-data comparison tool. It compares the
# importable packages (internal packages are ignored unless -allow-internal is
# set), which is the surface Go's compatibility promise and a module's SemVer
# contract actually cover. It works from a dirty tree, unlike gorelease, so it
# can run in the ordinary check.
#
# Breaking changes are allowed before 1.0. This task reports them and exits 0;
# set API_DIFF_STRICT=1 to make an incompatible change fail the gate instead.
set -euo pipefail

base="$(git describe --tags --abbrev=0 --match 'v[0-9]*' 2>/dev/null || true)"
if [[ -z "${base}" ]]; then
  echo "api-diff: no root tag yet; skipping comparison"
  exit 0
fi

apidiff_version="v0.0.0-20261014143641-f0251eb4aa3e"
tool="golang.org/x/exp/cmd/apidiff@${apidiff_version}"
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

git archive "${base}" | tar -x -C "${work}"
base_export="${work}/base.export"
new_export="${work}/new.export"

(
  cd "${work}"
  GOFLAGS=-mod=mod go run "${tool}" -m -w "${base_export}" github.com/laenenai/tenancy
)
go run "${tool}" -m -w "${new_export}" github.com/laenenai/tenancy

set +e
report="$(go run "${tool}" -m "${base_export}" "${new_export}" 2>&1)"
status=$?
set -e
printf '%s\n' "${report}"
if [[ ${status} -ne 0 ]]; then
  echo "api-diff: apidiff failed (exit ${status})" >&2
  exit "${status}"
fi

if grep -q '^Incompatible changes:' <<<"${report}"; then
  echo "api-diff: incompatible changes detected against ${base}."
  echo "api-diff: pre-1.0 allows this; record it in CHANGELOG.md and UPGRADING.md."
  if [[ "${API_DIFF_STRICT:-0}" == "1" ]]; then
    exit 1
  fi
fi

# The harness is a separately versioned module. Compare it against its own tag
# when one exists; integration modules are test-only and are not published.
testdb_base="$(git describe --tags --abbrev=0 --match 'testdb/v*' 2>/dev/null || true)"
if [[ -n "${testdb_base}" ]]; then
  testdb_base_export="${work}/testdb-base.export"
  testdb_new_export="${work}/testdb-new.export"
  (
    cd "${work}/testdb"
    GOFLAGS=-mod=mod go run "${tool}" -m -w "${testdb_base_export}" github.com/laenenai/tenancy/testdb
  )
  (
    cd testdb
    go run "${tool}" -m -w "${testdb_new_export}" github.com/laenenai/tenancy/testdb
  )
  set +e
  testdb_report="$(go run "${tool}" -m "${testdb_base_export}" "${testdb_new_export}" 2>&1)"
  status=$?
  set -e
  printf '%s\n' "${testdb_report}"
  if [[ ${status} -ne 0 ]]; then
    echo "api-diff: testdb apidiff failed (exit ${status})" >&2
    exit "${status}"
  fi
  if grep -q '^Incompatible changes:' <<<"${testdb_report}"; then
    echo "api-diff: incompatible testdb changes against ${testdb_base}; document the harness release."
    if [[ "${API_DIFF_STRICT:-0}" == "1" ]]; then
      exit 1
    fi
  fi
fi
