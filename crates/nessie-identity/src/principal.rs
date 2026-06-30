//! The homelab principal and its role tier.
//!
//! Exactly one principal per person (the AD object). [`RoleTier`] is the single
//! axis the rest of the system projects — into web SSO group claims, NFS/SMB
//! ACLs, and the agent capability token. See architecture doc 01 §2–§3.

use serde::{Deserialize, Serialize};

/// The three homelab role tiers, sourced from the three AD groups.
///
/// Variants are ordered low→high authority (`Kid < Adult < Admin`) so the
/// derived [`Ord`] matches the authority order. **Note (separation, not
/// subtraction):** a higher tier is *more* authoritative, but a kid's projected
/// storage scope is a *separate* volume, not a subset of an adult's — see
/// [`crate::caveats`]. So `Ord` ranks authority, it does not imply the kid's
/// caveats are `⊑` an adult's on every axis (they are both `⊑` Admin, which is
/// `⊤`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoleTier {
    /// Kids — curated apps, their own storage volume, capped budget, no admin.
    Kid,
    /// Adults — family storage + their home, generous budget.
    Adult,
    /// Admins — full authority across the homelab.
    Admin,
}

impl RoleTier {
    /// The AD group that carries this tier.
    #[must_use]
    pub fn ad_group(&self) -> &'static str {
        match self {
            RoleTier::Admin => "homelab-admins",
            RoleTier::Adult => "homelab-users",
            RoleTier::Kid => "homelab-kids",
        }
    }

    /// Resolve a tier from an AD group name (the inverse of [`Self::ad_group`]).
    /// Unknown groups yield `None` — callers decide the default (typically deny).
    #[must_use]
    pub fn from_ad_group(group: &str) -> Option<Self> {
        match group {
            "homelab-admins" => Some(RoleTier::Admin),
            "homelab-users" => Some(RoleTier::Adult),
            "homelab-kids" => Some(RoleTier::Kid),
            _ => None,
        }
    }

    /// Resolve a tier from a set of AD group memberships, taking the **highest**
    /// tier present (a user in both `users` and `admins` is an admin). `None`
    /// if no homelab tier group is present.
    pub fn highest_of<'a, I: IntoIterator<Item = &'a str>>(groups: I) -> Option<Self> {
        groups.into_iter().filter_map(Self::from_ad_group).max()
    }
}

/// One person, resolved from Active Directory: the single principal every
/// protocol face describes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HomelabPrincipal {
    /// AD `objectSid` — the stable identity anchor.
    pub ad_sid: String,
    /// User principal name, e.g. `ada@EXAMPLE.LAN`.
    pub upn: String,
    /// The role tier (from AD group membership).
    pub role: RoleTier,
    /// POSIX uid (RFC2307) — what NFS ownership keys on.
    pub uid: u32,
    /// POSIX primary gid (RFC2307).
    pub gid: u32,
}

impl HomelabPrincipal {
    /// The local part of the UPN (`ada` from `ada@EXAMPLE.LAN`) — used to scope
    /// per-user storage roots without leaking the realm into a path.
    #[must_use]
    pub fn username(&self) -> &str {
        self.upn.split('@').next().unwrap_or(&self.upn)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ad_group_round_trips() {
        for tier in [RoleTier::Admin, RoleTier::Adult, RoleTier::Kid] {
            assert_eq!(RoleTier::from_ad_group(tier.ad_group()), Some(tier));
        }
        assert_eq!(RoleTier::from_ad_group("nope"), None);
    }

    #[test]
    fn ord_ranks_authority() {
        assert!(RoleTier::Kid < RoleTier::Adult);
        assert!(RoleTier::Adult < RoleTier::Admin);
    }

    #[test]
    fn highest_of_picks_the_strongest_tier() {
        assert_eq!(
            RoleTier::highest_of(["homelab-users", "homelab-admins"]),
            Some(RoleTier::Admin)
        );
        assert_eq!(RoleTier::highest_of(["homelab-kids"]), Some(RoleTier::Kid));
        assert_eq!(RoleTier::highest_of(["unrelated-group"]), None);
    }

    #[test]
    fn username_strips_the_realm() {
        let p = HomelabPrincipal {
            ad_sid: "S-1-5-21-0-0-0-1104".into(),
            upn: "ada@EXAMPLE.LAN".into(),
            role: RoleTier::Adult,
            uid: 1001,
            gid: 100,
        };
        assert_eq!(p.username(), "ada");
    }
}
