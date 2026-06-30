//! `RoleCaveats` and the `RoleTier → RoleCaveats` projection.
//!
//! [`RoleCaveats`] is one element of the homelab authority lattice: the
//! agent-mesh [`Caveats`] (fs / exec / net / `max_calls` / generation) **plus**
//! the added [`DollarBudget`] axis. Every operation (`top`/`leq`/`meet`) reduces
//! to the per-axis lattice op, so it is **attenuation-only**: a delegated child
//! can never amplify either the base caveats or the budget.
//!
//! The projection turns a [`RoleTier`] into the authority an agent run as that
//! person may hold. It honors architecture doc 01 §3's **"separation, not
//! subtraction"**: a kid's storage scope is a *separate* volume, never a subset
//! of the family tree. So `Admin = ⊤` (every tier is `⊑` it), but a kid's
//! caveats are deliberately **not** `⊑` an adult's on the filesystem axis — they
//! point at a disjoint volume.

use agent_mesh_protocol::{Caveats, CountBound, Scope};
use serde::{Deserialize, Serialize};

use crate::budget::DollarBudget;
use crate::principal::{HomelabPrincipal, RoleTier};

/// Default spend ceiling for adults (tunable policy, not a protocol constant).
pub const DEFAULT_ADULT_BUDGET: DollarBudget = DollarBudget::Cents(5_000);
/// Default spend ceiling for kids — deliberately small.
pub const DEFAULT_KID_BUDGET: DollarBudget = DollarBudget::Cents(200);
/// Default tool-call cap for a kid's agent run.
pub const DEFAULT_KID_MAX_CALLS: u64 = 200;

/// A homelab authority element: agent-mesh [`Caveats`] + the [`DollarBudget`]
/// axis, composed as one meet-semilattice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleCaveats {
    /// The signed/enforced base caveats (fs/exec/net/calls/generation).
    pub base: Caveats,
    /// The added spend ceiling (see [`crate::budget`]).
    pub budget: DollarBudget,
}

impl RoleCaveats {
    /// `⊤` — unrestricted on every axis (admin authority).
    #[must_use]
    pub fn top() -> Self {
        Self {
            base: Caveats::top(),
            budget: DollarBudget::top(),
        }
    }

    /// `self ⊑ other` — no more authority than `other` on *every* axis,
    /// including the budget. This is the attenuation check used to decide
    /// whether a requested run is within a role's grant.
    #[must_use]
    pub fn leq(&self, other: &Self) -> bool {
        self.base.leq(&other.base) && self.budget.leq(&other.budget)
    }

    /// `self ⊓ other` — the greatest lower bound on every axis. Composing along
    /// a delegation chain can only narrow; it never amplifies.
    #[must_use]
    pub fn meet(&self, other: &Self) -> Self {
        Self {
            base: self.base.meet(&other.base),
            budget: self.budget.meet(&other.budget),
        }
    }

    /// Does this authority permit **writing** `path`? (Is `{path}` within the
    /// `fs_write` scope?) Used to prove kid/family separation.
    #[must_use]
    pub fn authorizes_write(&self, path: &str) -> bool {
        Scope::only([path.to_string()]).leq(&self.base.fs_write)
    }

    /// Does this authority permit **reading** `path`?
    #[must_use]
    pub fn authorizes_read(&self, path: &str) -> bool {
        Scope::only([path.to_string()]).leq(&self.base.fs_read)
    }
}

/// Where the nessie-store NFS/CIFS plane mounts each tier's storage. These are
/// **export-relative** roots (under the server's `srv_root`), generic defaults a
/// deployment overrides — never real deployment paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageLayout {
    /// Shared family tree (gid `homelab-users`).
    pub family_root: String,
    /// Per-user home parent (`{home_root}/{username}`).
    pub home_root: String,
    /// Per-kid volume parent (`{kids_root}/{username}`) — a *separate* volume.
    pub kids_root: String,
}

impl Default for StorageLayout {
    fn default() -> Self {
        Self {
            family_root: "/srv/family".to_string(),
            home_root: "/srv/home".to_string(),
            kids_root: "/srv/kids".to_string(),
        }
    }
}

impl StorageLayout {
    fn home_of(&self, p: &HomelabPrincipal) -> String {
        format!("{}/{}", self.home_root, p.username())
    }
    fn kid_volume_of(&self, p: &HomelabPrincipal) -> String {
        format!("{}/{}", self.kids_root, p.username())
    }
}

impl RoleTier {
    /// Project this tier onto the homelab authority an agent run as `principal`
    /// may hold, scoped by `layout`.
    ///
    /// - **Admin** ≈ `⊤` — full authority (every other tier is `⊑` this).
    /// - **Adult** — read/write the family tree + their own home; generous
    ///   budget; unrestricted calls/exec/net (a trusted human).
    /// - **Kid** — read/write *only* their own kid volume (a separate tree, not
    ///   a subset of the family tree); **no** exec, **no** net by default (a
    ///   deployment supplies the curated allow-list); capped calls + small
    ///   budget.
    #[must_use]
    pub fn project(&self, principal: &HomelabPrincipal, layout: &StorageLayout) -> RoleCaveats {
        match self {
            RoleTier::Admin => RoleCaveats::top(),
            RoleTier::Adult => {
                let scope = Scope::only([layout.family_root.clone(), layout.home_of(principal)]);
                RoleCaveats {
                    base: Caveats {
                        fs_read: scope.clone(),
                        fs_write: scope,
                        exec: Scope::top(),
                        net: Scope::top(),
                        max_calls: CountBound::Unlimited,
                        valid_for_generation: Scope::top(),
                    },
                    budget: DEFAULT_ADULT_BUDGET,
                }
            }
            RoleTier::Kid => {
                let scope = Scope::only([layout.kid_volume_of(principal)]);
                RoleCaveats {
                    base: Caveats {
                        fs_read: scope.clone(),
                        fs_write: scope,
                        // Curated by separation: no command exec, and net is
                        // deny-all by default (deployment adds the allow-list).
                        exec: Scope::none(),
                        net: Scope::none(),
                        max_calls: CountBound::AtMost(DEFAULT_KID_MAX_CALLS),
                        valid_for_generation: Scope::top(),
                    },
                    budget: DEFAULT_KID_BUDGET,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn principal(role: RoleTier, uid: u32) -> HomelabPrincipal {
        HomelabPrincipal {
            ad_sid: format!("S-1-5-21-0-0-0-{uid}"),
            upn: format!("user{uid}@EXAMPLE.LAN"),
            role,
            uid,
            gid: 100,
        }
    }

    #[test]
    fn admin_projects_to_top() {
        let p = principal(RoleTier::Admin, 1000);
        assert_eq!(
            RoleTier::Admin.project(&p, &StorageLayout::default()),
            RoleCaveats::top()
        );
    }

    #[test]
    fn every_tier_is_within_admin() {
        // Admin is ⊤, so adult and kid grants are both ⊑ it.
        let layout = StorageLayout::default();
        let admin = RoleTier::Admin.project(&principal(RoleTier::Admin, 1), &layout);
        let adult = RoleTier::Adult.project(&principal(RoleTier::Adult, 2), &layout);
        let kid = RoleTier::Kid.project(&principal(RoleTier::Kid, 3), &layout);
        assert!(adult.leq(&admin), "adult ⊑ admin");
        assert!(kid.leq(&admin), "kid ⊑ admin");
    }

    #[test]
    fn kid_is_separated_from_the_family_tree() {
        // The keystone: separation, not subtraction. A kid can write its own
        // volume but NOT the family tree; an adult can write the family tree.
        let layout = StorageLayout::default();
        let kid = RoleTier::Kid.project(&principal(RoleTier::Kid, 3), &layout);
        let adult = RoleTier::Adult.project(&principal(RoleTier::Adult, 2), &layout);

        assert!(
            kid.authorizes_write("/srv/kids/user3"),
            "kid owns its volume"
        );
        assert!(
            !kid.authorizes_write(&layout.family_root),
            "kid must NOT reach the family tree"
        );
        assert!(
            adult.authorizes_write(&layout.family_root),
            "adult owns family"
        );
        // And the kid grant is NOT ⊑ the adult grant — disjoint volumes, not a
        // narrowing of the same surface.
        assert!(
            !kid.leq(&adult),
            "kid scope is separate, not a subset of adult"
        );
    }

    #[test]
    fn kid_is_tightly_bounded() {
        let layout = StorageLayout::default();
        let kid = RoleTier::Kid.project(&principal(RoleTier::Kid, 3), &layout);
        let adult = RoleTier::Adult.project(&principal(RoleTier::Adult, 2), &layout);
        assert!(kid.budget.leq(&adult.budget), "kid budget ⊑ adult budget");
        assert_ne!(kid.budget, DollarBudget::Unlimited, "kid budget is finite");
        assert_eq!(kid.base.exec, Scope::none(), "kid has no exec authority");
        assert_eq!(kid.base.net, Scope::none(), "kid has no net by default");
        assert!(
            kid.base.max_calls.leq(&adult.base.max_calls),
            "kid calls ⊑ adult calls"
        );
    }

    #[test]
    fn meet_never_amplifies() {
        // operating_key_cannot_widen, at the RoleCaveats level: meet(a, b) ⊑ a.
        let layout = StorageLayout::default();
        let adult = RoleTier::Adult.project(&principal(RoleTier::Adult, 2), &layout);
        let kid = RoleTier::Kid.project(&principal(RoleTier::Kid, 3), &layout);
        let m = adult.meet(&kid);
        assert!(m.leq(&adult) && m.leq(&kid), "meet is ⊑ both operands");
        assert_eq!(adult.meet(&adult), adult, "meet is idempotent");
    }
}
