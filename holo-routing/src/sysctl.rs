//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use holo_utils::capabilities;
use sysctl::{Ctl, Sysctl, SysctlError};

// ===== global functions =====

pub(crate) fn mpls_platform_labels(max: &str) -> Result<(), SysctlError> {
    capabilities::raise(|| {
        let ctl = Ctl::new("net.mpls.platform_labels")?;
        ctl.set_value_string(max)?;
        Ok(())
    })
}
