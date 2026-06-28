# Security Policy

`nessie-identity` is identity-plane software for a self-hosted fleet. Security and
privacy are first-order concerns, enforced in CI before any feature code lands.

## Reporting a vulnerability

Open a private security advisory on this repository, or contact the maintainers
out-of-band. Please do not file public issues for undisclosed vulnerabilities.

## Public-repository privacy rules (enforced)

This repo is public. It must never contain operational specifics of any real
deployment. The following are **prohibited in code, docs, tests, fixtures,
comments, and commit messages**:

- Real hostnames, IP addresses (RFC1918 / CGNAT / link-local), domains, DNS names,
  or overlay-network names.
- Real Kerberos realms, AD domains, LDAP base DNs, or NetBIOS names.
- Real usernames, email addresses, or group names.
- Any secret: passwords, API keys, tokens, OAuth client secrets, private keys,
  certificates' private halves, signing seeds, or escrow material.
- Internal network topology, port maps, or service-discovery details that map an
  attack surface.

Use **placeholders only**: `idp.example.lan`, `store.example.lan`, `EXAMPLE.LAN`,
`dc=example,dc=lan`, `192.0.2.0/24` (TEST-NET-1), `198.51.100.0/24`,
`203.0.113.0/24`, `user@example.com`, `<OVERLAY-NETWORK>`,
`secret/path/to/value` (reference form, never a value).

## Enforcement

- **`security-audit` CI** (`.github/workflows/security-audit.yml`): gitleaks secret
  scan + the internal-specifics linter (`scripts/check-internal-specifics.sh`) +
  dependency audit. A finding **blocks the merge**.
- **Pre-commit** (`.pre-commit-config.yaml`): the same checks run locally before a
  commit is created.
- **Design source of truth is private.** Detailed, deployment-specific design lives
  in a private repository; anything published here is **derived and sanitized**,
  authored placeholder-first.

## Secret handling in code (when code lands)

- Secrets are delivered at runtime (e.g., via a secrets operator / vault), never
  committed, never written to durable disk, never logged.
- Use a redacting secret type that refuses to `Display`/`Serialize`.
- Least-privilege scopes for any third-party (e.g., Google) integration; tokens are
  stored in the secrets backend and are revocable.
