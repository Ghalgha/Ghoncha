#![no_std]

extern crate alloc;

//! Sans-I/O UDP TURN client adapter.
//!
//! This crate owns TURN protocol state only. The caller owns and drives the UDP
//! socket, including Android network binding and VpnService.protect().
//! Packet buffers are supplied by the caller; no socket or async runtime is
//! created here.

mod manager;
pub use manager::*;

mod tcp;
pub use tcp::*;

use core::convert::TryFrom;
use core::net::{IpAddr, SocketAddr};

use ghoncha_transport_api::MonotonicTime;