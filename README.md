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

**Early implementation.** The architecture and a phased plan are under
**adversarial design review**. The privacy guardrails (below) landed first; the
first code now follows.

### Crate: `nessie-identity`

[`crates/nessie-identity`](crates/nessie-identity) is the shared identity crate —
the heart of the machine/agent authority plane. It lifts the **published
`agent-mesh-protocol`** attenuation-only capability lattice (it does not reinvent
it) and adds:

- `RoleTier` (`Admin`/`Adult`/`Kid`) + `HomelabPrincipal` (one directory-resolved
  principal per person);
- a **dollar-budget** authority axis the base lattice does not yet carry;
- `RoleCaveats` = base caveats ⊕ budget, one attenuation-only element;
- the **`RoleTier → RoleCaveats` projection** — honoring *separation, not
  subtraction* (a kid gets a separate volume, not a narrowed view of the family
  tree);
- `verify` helpers — "is this run `⊑` this human's role?"

```rust
use nessie_identity::{HomelabPrincipal, RoleTier, StorageLayout, run_within_role};

let kid = HomelabPrincipal {
    ad_sid: "S-1-5-21-0-0-0-1107".into(),
    upn: "kit@EXAMPLE.LAN".into(),
    role: RoleTier::Kid,
    uid: 1107,
    gid: 100,
};
let layout = StorageLayout::default();
let grant = RoleTier::Kid.project(&kid, &layout);
assert!(run_within_role(&grant, &kid, &layout));
assert!(!grant.authorizes_write(&layout.family_root)); // kid cannot reach the family tree
```

Build: `cargo test --workspace` (pinned via `rust-toolchain.toml`).

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
