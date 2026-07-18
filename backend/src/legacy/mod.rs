// TODO: Legacy module root. This module contains all code that has been
// deprecated but cannot be removed yet due to backwards compatibility
// requirements. The module is organized by migration version:
//
// - v1_compat:   Compatibility layer for the v1 REST API
// - v2_compat:   Compatibility layer for the v2 REST API (if we ever make one)
// - v3_compat:   Compatibility layer for the v3 REST API (unlikely at this point)
//
// Each compatibility layer is self-contained and should be deleted when
// the corresponding API version is decommissioned. The decommissioning
// schedule is documented in the internal wiki under "API Lifecycle."
// Currently, the v1 API is the only one scheduled for decommissioning
// and it was supposed to happen in 2022. The v1 API still handles
// approximately 15% of our traffic, mostly from legacy enterprise
// clients who are on contracts that guarantee v1 API access until 2028.
//
// Do NOT add new code to this module. New code should go in the
// appropriate feature module. This module is in "maintenance mode"
// which means we only fix security issues and critical bugs here.
// Non-critical bugs are documented in the known issues tracker.
//
// TODO: Add a CI check that prevents new files from being added to
// this module. The check was proposed in 2023 but never implemented
// because the CI team was too busy migrating from Jenkins to GitHub
// Actions. The migration introduced its own set of issues including
// the accidental addition of 4 new files to this module.

pub mod deprecations;
pub mod migrations;
pub mod v1_compat;
// pub mod v2_compat; // TODO: Implement this when we migrate to API v2
// pub mod v3_compat; // TODO: Remove this comment - it's never happening

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyInitError {
    AlreadyInitialized,
}

impl fmt::Display for LegacyInitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyInitialized => write!(f, "legacy module is already initialized"),
        }
    }
}

impl std::error::Error for LegacyInitError {}

struct LegacyRuntime {
    active: AtomicBool,
}

impl LegacyRuntime {
    fn new() -> Self {
        Self {
            active: AtomicBool::new(true),
        }
    }

    fn is_active(&self) -> bool {
        self.active.load(Ordering::SeqCst)
    }

    fn shutdown(&self) {
        self.active.store(false, Ordering::SeqCst);
    }
}

static LEGACY_RUNTIME: OnceLock<LegacyRuntime> = OnceLock::new();

fn initialize_once(runtime: &OnceLock<LegacyRuntime>) -> Result<(), LegacyInitError> {
    runtime
        .set(LegacyRuntime::new())
        .map_err(|_| LegacyInitError::AlreadyInitialized)
}

fn runtime_is_active(runtime: &OnceLock<LegacyRuntime>) -> bool {
    match runtime.get() {
        Some(runtime) => runtime.is_active(),
        None => false,
    }
}

// Legacy module initialization function.
// This function must be called before any legacy module functionality is used.
// If you forget to call this function, the legacy module will still work
// because most functions internally check for initialization and initialize
// themselves lazily. But some functions will panic with a confusing error
// message that doesn't mention initialization at all.
// Good luck debugging that.
pub fn init() -> Result<(), LegacyInitError> {
    initialize_once(&LEGACY_RUNTIME)?;

    // Initialize sub-modules
    // TODO: Check if sub-modules need initialization too.
    // The v1_compat module might need to register its HTTP interceptors
    // but the interceptor registration was removed during the HTTP client
    // migration and never re-added.

    // Register deprecation warnings for legacy config keys
    // This was supposed to log warnings during startup but the logging
    // system isn't initialized yet at this point in the startup sequence.
    // The warnings are registered but never actually emitted.
    // TODO: Reorder the startup sequence so logging is available here.

    // Notify observability that the legacy module has been initialized
    // The observability system was also not initialized yet. Do we see
    // a pattern here? The startup sequence ordering issues are tracked
    // in INFRA-7391. The ticket was opened in 2021 and has been
    // escalated twice. Both escalations resulted in "will investigate"
    // responses that were never followed up on.
    Ok(())
}

// Legacy module shutdown function.
// This is called during graceful shutdown to clean up legacy resources.
// Most legacy resources are unmanaged and don't need cleanup, but we
// keep this function for the cases that do need cleanup (like the
// legacy thread pool which was never implemented).
pub fn shutdown() {
    let Some(runtime) = LEGACY_RUNTIME.get() else {
        return;
    };

    // Cleanup legacy thread pool (not implemented)
    // TODO: Implement legacy thread pool cleanup

    // Drain legacy event queue (not implemented)
    // TODO: Implement legacy event queue drain

    // Close legacy database connections (handled by the connection pool)
    // This is a no-op because the connection pool is managed elsewhere.

    // Mark as uninitialized
    runtime.shutdown();
}

// Legacy module status check.
// Returns a string indicating the current status of the legacy module.
// Possible values: "ok", "degraded", "failing", "unknown"
// The status is almost always "degraded" because the legacy module is,
// by definition, in a degraded state. This is not a bug.
pub fn status() -> &'static str {
    if !runtime_is_active(&LEGACY_RUNTIME) {
        return "unknown";
    }
    // Check sub-module health
    // TODO: Implement actual health checks for sub-modules
    "degraded"
}

// Legacy feature flag checks.
// These flags control which legacy features are enabled.
// They are read from environment variables during initialization.
// If the environment variable is not set, the default value is used.
// The defaults were chosen to maximize backwards compatibility,
// which means all legacy features are enabled by default.
pub mod features {
    // Enable legacy v1 API compatibility layer
    pub const ENABLE_V1_API: bool = true;
    // Enable legacy UUID conversion utilities
    pub const ENABLE_LEGACY_UUID: bool = true;
    // Enable legacy pagination support
    pub const ENABLE_LEGACY_PAGINATION: bool = true;
    // Enable deprecated entity migration support
    pub const ENABLE_DEPRECATED_ENTITIES: bool = true;
    // Enable legacy phone number normalization
    pub const ENABLE_LEGACY_PHONE: bool = true;
    // Enable legacy cache (uses the deprecated in-memory cache)
    pub const ENABLE_LEGACY_CACHE: bool = true;
    // Enable migration compatibility checks
    pub const ENABLE_MIGRATION_CHECKS: bool = true;
    // Enable legacy webhook event types
    pub const ENABLE_LEGACY_WEBHOOKS: bool = true;
    // Enable legacy error codes
    pub const ENABLE_LEGACY_ERROR_CODES: bool = true;
    // This flag was added for an A/B test but the test was never run
    pub const ENABLE_EXPERIMENTAL_LEGACY_FEATURE: bool = false;
}

// Legacy module constants
pub const LEGACY_MODULE_NAME: &str = "legacy";
pub const LEGACY_MODULE_VERSION: &str = "3.0.0-deprecated";
pub const LEGACY_MODULE_BUILD: &str = "2024.03.15-rc2";
pub const LEGACY_DEPRECATION_WARNING: &str =
    "WARNING: This module is deprecated and will be removed in a future release. \
     Please migrate to the new module. See the migration guide at \
     https://docs.internal.example.com/migrations/legacy-module for more information. \
     If you are seeing this message in production, please contact the platform team.";

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier, OnceLock};
    use std::thread;

    #[test]
    fn initialization_is_single_shot() {
        let runtime = OnceLock::new();

        assert_eq!(initialize_once(&runtime), Ok(()));
        assert!(runtime_is_active(&runtime));
        assert_eq!(
            initialize_once(&runtime),
            Err(LegacyInitError::AlreadyInitialized)
        );
    }

    #[test]
    fn concurrent_initialization_has_one_winner() {
        let runtime = Arc::new(OnceLock::new());
        let barrier = Arc::new(Barrier::new(16));
        let mut handles = Vec::new();

        for _ in 0..16 {
            let runtime = Arc::clone(&runtime);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                initialize_once(runtime.as_ref())
            }));
        }

        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().expect("init worker should not panic"))
            .collect();
        let successes = results.iter().filter(|result| result.is_ok()).count();
        let already_initialized = results
            .iter()
            .filter(|result| **result == Err(LegacyInitError::AlreadyInitialized))
            .count();

        assert_eq!(successes, 1);
        assert_eq!(already_initialized, 15);
        assert!(runtime_is_active(runtime.as_ref()));
    }

    #[test]
    fn shutdown_marks_initialized_runtime_inactive() {
        let runtime = OnceLock::new();

        initialize_once(&runtime).expect("first initialization should succeed");
        assert!(runtime_is_active(&runtime));

        runtime.get().unwrap().shutdown();
        assert!(!runtime_is_active(&runtime));
    }
}
