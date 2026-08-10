//! Cooperative cancellation primitive for the L1 detection path.
//!
//! [`detect_l1_cancellable`](crate::redact_l1::detect_l1_cancellable) and the
//! base-scan [`match_patterns_cancellable`](crate::patterns::match_patterns_cancellable)
//! accept an `Option<&CancelFlag>` and poll it at coarse boundaries (the top of the
//! per-pattern scan loop and between the six person-family phases). A tripped flag
//! turns the next poll into a [`DetectError::Aborted`] **error return** — never a
//! partial `Ok`. `None` means "never cancel": every poll compiles to a no-op, so the
//! output is byte-identical to the pre-cancellation code path.
//!
//! This module is CORE-ONLY: it carries no PyO3 `#[pyclass]` and no server wiring.
//! A binding layer holds a [`CancelFlag`] (it is [`Clone`], sharing one underlying
//! atomic), hands `Some(&flag)` to the core, and trips it from another thread via
//! [`CancelFlag::cancel`].

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::patterns::PatternError;

/// A cheap, lock-free, `Send + Sync` cancellation signal readable inside the
/// GIL-released detection region.
///
/// The flag is a **pure signal**: nothing but the boolean itself is published
/// through it — no other memory is read or written on the strength of having seen
/// the flag set — so [`Ordering::Relaxed`] is sufficient for both the store
/// ([`cancel`](Self::cancel)) and the load ([`is_cancelled`](Self::is_cancelled)).
/// There is no happens-before relationship to establish; the reader only needs the
/// most-recent-ish value of a single boolean, and worst case a poll observes the
/// trip one boundary later, which is harmless for cooperative cancellation.
///
/// [`Clone`] shares the same underlying [`AtomicBool`] (it is an `Arc`), so a
/// cloned handle observes and can raise the same signal.
#[derive(Clone, Debug)]
pub struct CancelFlag(Arc<AtomicBool>);

impl CancelFlag {
    /// A fresh, un-cancelled flag.
    pub fn new() -> Self {
        CancelFlag(Arc::new(AtomicBool::new(false)))
    }

    /// Raise the signal. Idempotent; any subsequent poll returns `true`.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Relaxed);
    }

    /// `true` once [`cancel`](Self::cancel) has been called on this flag (or any
    /// clone of it).
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

impl Default for CancelFlag {
    fn default() -> Self {
        Self::new()
    }
}

/// The error algebra of the cancellable detection path.
///
/// [`From<PatternError>`](From) auto-converts every existing `?`-propagated
/// [`PatternError`] into [`DetectError::Pattern`], so the pattern-scan code needs no
/// per-site rewiring. [`Display`](std::fmt::Display) is load-bearing: the
/// `.map_err(|e| e.to_string())` sites in `redact_l1` and the wasm binding render
/// through it. [`Aborted`](DetectError::Aborted) renders a fixed, PII-free string —
/// it never echoes any scanned text.
#[derive(Debug)]
pub enum DetectError {
    /// The scan observed a tripped [`CancelFlag`] at a poll boundary and returned
    /// early. Fail-closed: no partial result accompanies this variant.
    Aborted,
    /// A genuine pattern / input error from the underlying scan.
    Pattern(PatternError),
}

impl From<PatternError> for DetectError {
    fn from(e: PatternError) -> Self {
        DetectError::Pattern(e)
    }
}

impl std::fmt::Display for DetectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // Fixed, PII-free message — never the scanned text.
            DetectError::Aborted => write!(f, "detection cancelled"),
            DetectError::Pattern(e) => write!(f, "{e}"),
        }
    }
}

/// Err-ONLY cancellation poll. Expands to a bare `if`-guard that can do exactly one
/// thing — `return Err(DetectError::Aborted)` — so `Ok(partial)` is unrepresentable
/// at any poll boundary by construction. This is the fail-closed guarantee as a code
/// property, and it is CI-greppable (`poll_abort!`).
///
/// `None` (the never-cancel case) makes the whole expansion a no-op, preserving the
/// byte-identical no-cancel path.
macro_rules! poll_abort {
    ($cancel:expr) => {
        if let ::core::option::Option::Some(__flag) = $cancel {
            if $crate::cancel::CancelFlag::is_cancelled(__flag) {
                return ::core::result::Result::Err($crate::cancel::DetectError::Aborted);
            }
        }
    };
}

pub(crate) use poll_abort;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_flag_is_not_cancelled() {
        let f = CancelFlag::new();
        assert!(!f.is_cancelled());
    }

    #[test]
    fn cancel_trips_the_flag_and_clones_share_it() {
        let f = CancelFlag::new();
        let clone = f.clone();
        assert!(!clone.is_cancelled());
        f.cancel();
        assert!(f.is_cancelled());
        // The clone shares the same underlying atomic.
        assert!(clone.is_cancelled());
    }

    #[test]
    fn aborted_display_is_fixed_and_pii_free() {
        // The Aborted rendering must be a constant string, never echo scanned text.
        assert_eq!(DetectError::Aborted.to_string(), "detection cancelled");
    }

    #[test]
    fn pattern_display_delegates_to_inner() {
        let e = DetectError::from(PatternError("boom: bad regex".to_string()));
        assert_eq!(e.to_string(), "boom: bad regex");
        // From<PatternError> wraps into the Pattern variant.
        assert!(matches!(e, DetectError::Pattern(_)));
    }
}
