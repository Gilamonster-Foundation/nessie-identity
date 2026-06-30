//! The dollar-budget authority axis.
//!
//! `agent-mesh-protocol`'s [`Caveats`](agent_mesh_protocol::Caveats) bounds an
//! agent's *tool calls* (`max_calls: CountBound`) but not its *spend*. This
//! program needs a spend ceiling that attenuates exactly like every other axis —
//! a delegated child (e.g. a kid's agent) can be granted a *smaller* budget but
//! never a larger one. [`DollarBudget`] is that axis, deliberately shaped to
//! mirror `CountBound` so it composes the same way.

use serde::{Deserialize, Serialize};

/// A spend ceiling, in whole US cents.
///
/// Forms the same one-dimensional meet-semilattice as
/// [`CountBound`](agent_mesh_protocol::CountBound): `Unlimited` is `⊤`,
/// `Cents(a) ⊑ Cents(b) ⟺ a ≤ b`, and the meet is the **tighter** (smaller)
/// ceiling. Because the meet can only shrink the bound, composing budgets along
/// a delegation chain is attenuation-only — you cannot meet your way to a bigger
/// allowance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DollarBudget {
    /// No spend ceiling — the `⊤` of this axis (admin authority).
    Unlimited,
    /// At most this many cents.
    Cents(u64),
}

impl DollarBudget {
    /// The top of this axis (`Unlimited`).
    #[must_use]
    pub fn top() -> Self {
        Self::Unlimited
    }

    /// A ceiling expressed in whole dollars (saturating at `u64::MAX` cents).
    #[must_use]
    pub fn dollars(dollars: u64) -> Self {
        Self::Cents(dollars.saturating_mul(100))
    }

    /// `self ⊑ other` — is `self` at least as tight a ceiling as `other`?
    #[must_use]
    pub fn leq(&self, other: &Self) -> bool {
        match (self, other) {
            (_, Self::Unlimited) => true,
            (Self::Unlimited, Self::Cents(_)) => false,
            (Self::Cents(a), Self::Cents(b)) => a <= b,
        }
    }

    /// `self ⊓ other` — the tighter (smaller) ceiling.
    #[must_use]
    pub fn meet(&self, other: &Self) -> Self {
        match (self, other) {
            (Self::Unlimited, x) | (x, Self::Unlimited) => *x,
            (Self::Cents(a), Self::Cents(b)) => Self::Cents((*a).min(*b)),
        }
    }
}

impl Default for DollarBudget {
    /// Absence of a declared budget is `⊤` (unlimited) — back-compatible with
    /// the agent-mesh convention that absence of a caveat means unrestricted.
    fn default() -> Self {
        Self::Unlimited
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dollars_converts_to_cents() {
        assert_eq!(DollarBudget::dollars(5), DollarBudget::Cents(500));
        // Saturates rather than overflowing.
        assert_eq!(
            DollarBudget::dollars(u64::MAX),
            DollarBudget::Cents(u64::MAX)
        );
    }

    #[test]
    fn leq_orders_by_tightness() {
        let five = DollarBudget::dollars(5);
        let ten = DollarBudget::dollars(10);
        assert!(five.leq(&ten), "a smaller ceiling is ⊑ a larger one");
        assert!(!ten.leq(&five), "a larger ceiling is not ⊑ a smaller one");
        assert!(
            five.leq(&DollarBudget::Unlimited),
            "any ceiling is ⊑ unlimited"
        );
        assert!(
            !DollarBudget::Unlimited.leq(&five),
            "unlimited is not ⊑ a finite ceiling"
        );
        assert!(five.leq(&five), "reflexive");
    }

    #[test]
    fn meet_takes_the_tighter_bound_and_never_amplifies() {
        let five = DollarBudget::dollars(5);
        let ten = DollarBudget::dollars(10);
        assert_eq!(five.meet(&ten), five);
        assert_eq!(ten.meet(&five), five, "commutative");
        assert_eq!(
            DollarBudget::Unlimited.meet(&ten),
            ten,
            "unlimited is the identity"
        );
        // The meet is always ⊑ both operands — the attenuation guarantee.
        let m = five.meet(&ten);
        assert!(m.leq(&five) && m.leq(&ten));
    }
}
