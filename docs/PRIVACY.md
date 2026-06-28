# Privacy & the public/private split

`nessie-identity` is **public** software for a **self-hosted** system. A public
repo that leaks the operational specifics of a real deployment hands an attacker a
map. This document defines the boundary and how it is enforced.

## The rule

- **Public (this repo):** generic, reusable code and documentation. Every
  example uses a **placeholder**, never a real value.
- **Private (operator-controlled):** the actual deployment — real hostnames,
  addresses, directory realm, domains, accounts, topology, and all secrets. This
  lives in a private operator repository and **never** flows here.
- **Direction of authorship:** public docs are **derived and sanitized** from the
  private design, authored **placeholder-first**. Never copy-paste from private to
  public.

## Approved placeholders

| Category | Use this | Never this |
|---|---|---|
| Web host | `idp.example.lan`, `store.example.lan`, `portal.example.lan` | your real hostnames |
| IP / CIDR | `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` (RFC 5737 TEST-NET) | real RFC1918 / CGNAT addresses |
| DNS domain | `example.lan`, `example.com` | your real internal domain |
| Directory realm | `EXAMPLE.LAN`, base DN `dc=example,dc=lan` | your real realm / base DN |
| Overlay network | `<OVERLAY-NETWORK>` | your real mesh/tailnet name |
| User / email | `user@example.com`, `alice`, `bob` | real people / personal email providers |
| Secret reference | `secret/path/to/value` (a *reference*, not a value) | any real secret value |

## Forbidden categories (blocked by CI)

Real values in any of these categories must never appear in code, docs, tests,
fixtures, comments, or commit messages:

1. Hostnames, IP addresses (private/CGNAT/link-local), DNS names, overlay-network
   names.
2. Directory realm, AD domain, LDAP base DN, NetBIOS name.
3. Usernames, email addresses, group names.
4. Any secret material (passwords, API keys, tokens, OAuth client secrets, private
   keys, signing seeds, escrow material).
5. Network topology, port maps, or service-discovery detail that maps an attack
   surface.

## Enforcement

- **CI** (`.github/workflows/security-audit.yml`): a secret scanner (gitleaks) and
  an **internal-specifics linter** (`scripts/check-internal-specifics.sh`, generic
  pattern set) run on every push and pull request. A finding blocks the merge.
- **Local** (`.pre-commit-config.yaml`): the same checks run before a commit is
  created, so leaks are caught before they leave a workstation.
- The linter uses **generic patterns** (RFC1918 ranges, common internal TLD
  shapes, personal-email shapes, realm shapes) and intentionally allows the
  approved placeholders above through.

## If CI flags you

Replace the flagged value with the appropriate placeholder from the table above
and re-push. If you believe it is a false positive on a genuine documentation
example, prefer switching the example to RFC 5737 / `example.*` ranges rather than
widening the linter.
