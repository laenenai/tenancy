# Security

## Reporting a vulnerability

Please report security issues privately through GitHub's
[private vulnerability reporting](https://docs.github.com/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability)
on this repository, rather than opening a public issue.

## Supported versions

| Version | Supported |
|---|---|
| `main` (unreleased) | security fixes land here first |
| `v0.3.x` | best effort; upgrade to `main` for the production-readiness fixes |
| `< v0.3` | not supported |

The module is **pre-1.0**. The API may change, and it has not had an external
security review. Do not deploy it where a failure would be material without
reading `CHARTER.md` and `THREAT_MODEL.md` — in particular their stated
non-contents, which are the guarantees this module explicitly does **not** make.

## Security posture

- RLS is a backstop against application bugs, not containment for SQL injection
  or DDL-capable roles. See `THREAT_MODEL.md`.
- The control-plane and data-plane roles must be separate; the data role must
  have no registry grants and no DDL/ownership rights.
- Report a suspected cross-tenant disclosure privately even if you are unsure
  whether RLS or application scoping failed.
- Go strings cannot be reliably zeroized. The OpenBao adapter clears the raw
  response buffer it decodes, but the token and parsed password necessarily
  exist as strings for the life of the operation; treat a process dump as
  credential material.

## What the conformance suite proves, and what it does not

Each port in this module ships a conformance suite that every adapter must
pass, and the suite — not the interface — is the authoritative description of
the contract. Security invariants have their own named subtests, so an adapter
cannot quietly skip one.

The suite proves the *contract*. It cannot prove *enforcement* that belongs to
something outside this process: a database's row-level security, a key
manager's access policy, an operator's privilege separation. Those are verified
by integration tests against the real dependency where one exists, and are
otherwise the deployment's responsibility. Where that line falls is stated in
the package documentation rather than left to be assumed.
