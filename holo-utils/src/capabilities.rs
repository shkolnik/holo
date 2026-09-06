//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

#[cfg(target_os = "linux")]
use capctl::caps::CapState;
#[cfg(target_os = "linux")]
use tracing::error;

/// Runs the provided closure with elevated capabilities.
#[cfg(target_os = "linux")]
pub fn raise<F, R>(cb: F) -> R
where
    F: FnOnce() -> R,
{
    // Raise capabilities.
    let mut caps = CapState::get_current().unwrap();
    caps.effective = caps.permitted;
    if let Err(error) = caps.set_current() {
        error!("failed to update current capabilities: {}", error);
    }

    // Run closure.
    let ret = cb();

    // Drop capabilities.
    caps.effective.clear();
    if let Err(error) = caps.set_current() {
        error!("failed to update current capabilities: {}", error);
    }

    // Return the closure's return value.
    ret
}

/// Runs the provided closure.
///
/// Capabilities are a Linux concept, and the platforms without them have
/// nothing that would require raising any.
#[cfg(not(target_os = "linux"))]
pub fn raise<F, R>(cb: F) -> R
where
    F: FnOnce() -> R,
{
    cb()
}
