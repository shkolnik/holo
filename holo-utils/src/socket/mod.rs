//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

// Real Linux sockets.
#[cfg(all(target_os = "linux", not(feature = "testing")))]
mod linux;
// Stubs with the same names, for test builds and WebAssembly.
#[cfg(any(target_family = "wasm", feature = "testing"))]
mod mock;

#[cfg(all(target_os = "linux", not(feature = "testing")))]
pub use crate::socket::linux::*;
#[cfg(any(target_family = "wasm", feature = "testing"))]
pub use crate::socket::mock::*;

// Maximum TTL for IPv4 or Hop Limit for IPv6.
pub const TTL_MAX: u8 = 255;

// TCP connection information.
#[derive(Debug)]
#[derive(Deserialize, Serialize)]
pub struct TcpConnInfo {
    pub local_addr: IpAddr,
    pub local_port: u16,
    pub remote_addr: IpAddr,
    pub remote_port: u16,
}
