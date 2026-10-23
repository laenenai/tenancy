# Security

## Reporting a vulnerability

Please report security issues privately through GitHub's
[private vulnerability reporting](https://docs.github.com/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability)
on this repository, rather than opening a public issue.

## Scope and status

This module is **pre-1.0**. The API may change, and it has not had an external
security review. Do not deploy it where a failure would be material without
reading `CHARTER.md` — in particular its stated non-contents, which are the
guarantees this module explicitly does **not** make.

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
