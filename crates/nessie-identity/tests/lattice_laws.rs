//! Property tests for the authority lattice — the laws an attenuation-only
//! system depends on. If a future `agent-mesh-protocol` bump or a projection
//! change breaks any of these, an agent could amplify its authority, so they are
//! pinned as proptests rather than a handful of examples.

use nessie_identity::{DollarBudget, HomelabPrincipal, RoleCaveats, RoleTier, StorageLayout};
use proptest::prelude::*;

fn budget_strategy() -> impl Strategy<Value = DollarBudget> {
    prop_oneof![
        Just(DollarBudget::Unlimited),
        any::<u64>().prop_map(DollarBudget::Cents),
    ]
}

proptest! {
    /// `meet` is a lower bound: `a ⊓ b ⊑ a` and `⊑ b`. This is the attenuation
    /// guarantee — composing budgets never amplifies either operand.
    #[test]
    fn budget_meet_is_a_lower_bound(a in budget_strategy(), b in budget_strategy()) {
        let m = a.meet(&b);
        prop_assert!(m.leq(&a));
        prop_assert!(m.leq(&b));
    }

    /// `meet` is commutative and `leq` is reflexive.
    #[test]
    fn budget_meet_commutes_and_leq_is_reflexive(a in budget_strategy(), b in budget_strategy()) {
        prop_assert_eq!(a.meet(&b), b.meet(&a));
        prop_assert!(a.leq(&a));
    }
}

fn tier_strategy() -> impl Strategy<Value = RoleTier> {
    prop_oneof![
        Just(RoleTier::Admin),
        Just(RoleTier::Adult),
        Just(RoleTier::Kid),
    ]
}

fn role_caveats_strategy() -> impl Strategy<Value = RoleCaveats> {
    (tier_strategy(), any::<u16>()).prop_map(|(tier, uid)| {
        let p = HomelabPrincipal {
            ad_sid: format!("S-1-5-21-0-0-0-{uid}"),
            upn: format!("user{uid}@EXAMPLE.LAN"),
            role: tier,
            uid: uid.into(),
            gid: 100,
        };
        tier.project(&p, &StorageLayout::default())
    })
}

proptest! {
    /// The headline ocap property at the `RoleCaveats` level: `meet(a, b)` is
    /// `⊑` both — an operating key cannot meet its way to wider authority.
    #[test]
    fn role_caveats_meet_never_amplifies(
        a in role_caveats_strategy(),
        b in role_caveats_strategy(),
    ) {
        let m = a.meet(&b);
        prop_assert!(m.leq(&a));
        prop_assert!(m.leq(&b));
    }

    /// Every projected grant is within itself (reflexivity) and within Admin
    /// (which is `⊤`).
    #[test]
    fn every_grant_is_within_itself_and_admin(g in role_caveats_strategy()) {
        prop_assert!(g.leq(&g));
        prop_assert!(g.leq(&RoleCaveats::top()));
    }
}
