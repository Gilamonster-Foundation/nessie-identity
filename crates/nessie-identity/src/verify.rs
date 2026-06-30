//! Verification — "is this run `⊑` the human's role?"
//!
//! The storage and agent daemons call these to decide whether an agent run,
//! carrying a capability token, stays within the authority its launching human's
//! [`RoleTier`](crate::RoleTier) grants.

use agent_mesh_protocol::AgentKey;

use crate::budget::DollarBudget;
use crate::caveats::{RoleCaveats, StorageLayout};
use crate::principal::{HomelabPrincipal, RoleTier};

/// Why a run was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DenyReason {
    /// The requested authority is not `⊑` the role grant on some axis.
    #[error("requested authority exceeds the {0:?} role grant")]
    ExceedsRole(RoleTier),
    /// The capability token's cert chain failed verification.
    #[error("capability token failed verification: {0}")]
    BadToken(String),
}

/// Pure decision: is `requested ⊑ principal.role.project(principal, layout)` on
/// every axis (including the dollar budget)?
#[must_use]
pub fn run_within_role(
    requested: &RoleCaveats,
    principal: &HomelabPrincipal,
    layout: &StorageLayout,
) -> bool {
    requested.leq(&principal.role.project(principal, layout))
}

/// Enforce a **verified** agent-mesh capability token against a principal's role.
///
/// The base caveats come from the cert chain *after* [`AgentKey`] verification,
/// so attenuation is re-checked cryptographically at every link. On success the
/// effective [`RoleCaveats`] (the verified base + the requested budget) is
/// returned for the caller to apply.
///
/// **Honesty note (budget axis).** agent-mesh's signed [`Caveats`] does not yet
/// carry a dollar budget (see [`crate::budget`]), so `requested_budget` is a
/// nessie-identity-enforced caveat, **not** a cryptographically signed one. Until
/// the budget is folded into the signed envelope (a follow-up in this epic), a
/// holder of the operating key could under-report its budget; the spend broker
/// must therefore treat the budget as advisory-until-signed. This is stated
/// rather than silently assumed — never claim the budget is signed when it is not.
pub fn enforce(
    key: &AgentKey,
    requested_budget: DollarBudget,
    principal: &HomelabPrincipal,
    layout: &StorageLayout,
) -> Result<RoleCaveats, DenyReason> {
    key.cert()
        .verify()
        .map_err(|e| DenyReason::BadToken(e.to_string()))?;
    let requested = RoleCaveats {
        base: key.cert().metadata.caveats.clone(),
        budget: requested_budget,
    };
    if run_within_role(&requested, principal, layout) {
        Ok(requested)
    } else {
        Err(DenyReason::ExceedsRole(principal.role))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_mesh_protocol::{AgentKey, AgentMetadata, Caveats, UserKey};

    fn principal(role: RoleTier, uid: u32) -> HomelabPrincipal {
        HomelabPrincipal {
            ad_sid: format!("S-1-5-21-0-0-0-{uid}"),
            upn: format!("user{uid}@EXAMPLE.LAN"),
            role,
            uid,
            gid: 100,
        }
    }

    fn meta(caveats: Caveats) -> AgentMetadata {
        AgentMetadata {
            role: "nessie-session".to_string(),
            host: "local".to_string(),
            capabilities: Vec::new(),
            // A claim in a signed cert, never a coordination primitive.
            issued_at: "1970-01-01T00:00:00Z".to_string(),
            expires_at: None,
            caveats,
        }
    }

    /// Mint a session root (`⊤`) then attenuate to `caveats` — the same shape
    /// newt-identity uses, exercised here to prove the crate enforces against a
    /// real signed, verified cert chain.
    fn signed_key(user: &UserKey, caveats: Caveats) -> AgentKey {
        let root = AgentKey::issue(user, meta(Caveats::top()));
        root.delegate(meta(caveats))
            .expect("attenuation ⊑ ⊤ always succeeds")
    }

    #[test]
    fn run_within_role_accepts_a_grant_and_rejects_an_overreach() {
        let layout = StorageLayout::default();
        let kid_p = principal(RoleTier::Kid, 3);
        let kid_grant = RoleTier::Kid.project(&kid_p, &layout);
        assert!(
            run_within_role(&kid_grant, &kid_p, &layout),
            "the grant itself fits"
        );

        // An adult-shaped request does not fit a kid's role.
        let adult_grant = RoleTier::Adult.project(&principal(RoleTier::Adult, 2), &layout);
        assert!(
            !run_within_role(&adult_grant, &kid_p, &layout),
            "an adult-scoped request must not pass as a kid"
        );
    }

    #[test]
    fn enforce_accepts_a_verified_token_within_role() {
        let layout = StorageLayout::default();
        let p = principal(RoleTier::Kid, 3);
        let grant = RoleTier::Kid.project(&p, &layout);
        let user = UserKey::generate();
        let key = signed_key(&user, grant.base.clone());

        let effective = enforce(&key, grant.budget, &p, &layout).expect("kid token within role");
        assert_eq!(effective, grant);
    }

    #[test]
    fn enforce_rejects_a_token_that_exceeds_role() {
        let layout = StorageLayout::default();
        let kid_p = principal(RoleTier::Kid, 3);
        // Sign an adult-scoped base (a forged/over-broad token) and present it as
        // the kid: the cert verifies, but it exceeds the kid role grant.
        let adult_base = RoleTier::Adult
            .project(&principal(RoleTier::Adult, 2), &layout)
            .base;
        let user = UserKey::generate();
        let key = signed_key(&user, adult_base);

        let err = enforce(&key, DollarBudget::dollars(1), &kid_p, &layout)
            .expect_err("an over-broad token must be refused");
        assert_eq!(err, DenyReason::ExceedsRole(RoleTier::Kid));
    }
}
