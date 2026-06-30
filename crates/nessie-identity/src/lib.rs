//! `nessie-identity` — the shared homelab identity crate.
//!
//! It turns a person's **role tier** into a **capability** the storage daemon
//! and the agent fleet can both verify. The cryptographic attenuation lattice
//! (`UserKey → AgentKey` delegation, `CertChain::verify`, and the [`Caveats`]
//! meet-semilattice) is **lifted from the published `agent-mesh-protocol`
//! crate** — the same types `newt-identity` uses; this crate does not reinvent
//! the lattice (architecture doc 01 §4/§8).
//!
//! What this crate adds on top:
//!
//! - [`RoleTier`] (`Admin`/`Adult`/`Kid`, from the three AD groups) and
//!   [`HomelabPrincipal`] (the one AD-resolved principal per person);
//! - the [`DollarBudget`] axis agent-mesh's `Caveats` does not yet carry;
//! - [`RoleCaveats`] = base `Caveats` ⊕ budget, one attenuation-only lattice;
//! - the **`RoleTier → RoleCaveats` projection** (architecture §3), honoring
//!   *separation, not subtraction* — a kid gets a *separate* volume, not a
//!   narrowed view of the family tree;
//! - [`verify`] helpers: "is this run `⊑` this human's role?"
//!
//! ```
//! use nessie_identity::{HomelabPrincipal, RoleTier, StorageLayout, run_within_role};
//!
//! let kid = HomelabPrincipal {
//!     ad_sid: "S-1-5-21-0-0-0-1107".into(),
//!     upn: "kit@EXAMPLE.LAN".into(),
//!     role: RoleTier::Kid,
//!     uid: 1107,
//!     gid: 100,
//! };
//! let layout = StorageLayout::default();
//! let grant = RoleTier::Kid.project(&kid, &layout);
//!
//! // The kid's own grant fits its role; it cannot reach the family tree.
//! assert!(run_within_role(&grant, &kid, &layout));
//! assert!(!grant.authorizes_write(&layout.family_root));
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod budget;
pub mod caveats;
pub mod principal;
pub mod verify;

pub use budget::DollarBudget;
pub use caveats::{
    RoleCaveats, StorageLayout, DEFAULT_ADULT_BUDGET, DEFAULT_KID_BUDGET, DEFAULT_KID_MAX_CALLS,
};
pub use principal::{HomelabPrincipal, RoleTier};
pub use verify::{enforce, run_within_role, DenyReason};

// Re-export the agent-mesh primitives so consumers get the SAME lattice types
// without a direct `agent-mesh-protocol` dependency (the newt-identity pattern).
pub use agent_mesh_protocol::{AgentKey, Caveats, CertChain, MeshError, UserKey};
