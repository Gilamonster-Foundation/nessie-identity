# nessie-identity

**A Google-first identity layer for a self-hosted fleet and family.**

`nessie-identity` composes best-in-class building blocks — an OIDC provider, an
Active Directory directory (Kerberos/LDAP), and a secrets/PKI backend — into one
unified single-sign-on plane for people *and* machines, plus identity-aware
storage access. It is the connective tissue, not a re-implementation of any of
those components.

It pairs with two sibling projects:

- **nessie-store** — an ONTAP-faithful storage daemon (NFS/CIFS over pluggable
  backends).
- **newt-agent** — a local-first agentic coder that consumes fleet identity.

## What it is (and is not)

- **It IS:** a small set of Rust services + a shared crate that (a) mint and verify
  attenuation-only **capability tokens** for machine/agent identity, (b) orchestrate
  **onboarding / role assignment** across the underlying directory + OIDC provider,
  and (c) present a **unified web portal** where a user sees their SSO apps and
  their file-share mounts in one view.
- **It is NOT** a new OIDC/SAML provider or a new Kerberos KDC. Those are delegated
  to mature, audited software. Owning the human-auth protocols is a non-goal.

## Status

**Pre-implementation.** The architecture and a phased plan are under **adversarial
design review**. This repository currently contains only the project's **privacy
and secret-leak guardrails** (see below) — code lands after the design review
settles.

## Privacy & security guardrails (enforced first)

This is a **public** repository for a **self-hosted** system. To avoid handing an
attacker a map of any specific deployment, **no real hostnames, IP addresses,
domains, realms, usernames, emails, or secrets may appear here** — only
documentation placeholders (`idp.example.lan`, `EXAMPLE.LAN`, `192.0.2.0/24`,
`user@example.com`). This is enforced by CI:

- `security-audit` workflow runs secret scanning (gitleaks) and a custom
  internal-specifics linter on every push and pull request.
- A pre-commit hook mirrors the CI checks locally.

See [`docs/PRIVACY.md`](docs/PRIVACY.md) and [`SECURITY.md`](SECURITY.md).

## Contributing

Changes land via pull request with green CI. Do not push to the default branch.

## License

Dual-licensed under either of [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT)
at your option — the Gilamonster Foundation convention.
