//! A failed required listener must never acknowledge replacement readiness.
use std::sync::atomic::{AtomicBool, Ordering};
static FAILED: AtomicBool = AtomicBool::new(false);
/// Records an irreversible startup failure for this process generation.
pub fn mark_failed() {
    FAILED.store(true, Ordering::SeqCst);
}
/// Whether a required listener failed to initialize.
pub fn failed() -> bool {
    FAILED.load(Ordering::SeqCst)
}
