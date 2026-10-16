// SPDX-License-Identifier: MIT

//! This crate provides methods to manage L2TP tunnels and sessions via the
//! generic netlink protocol, as the `ip l2tp` command of
//! [iproute2](https://git.kernel.org/pub/scm/network/iproute2/iproute2.git)
//! does.
//!
//! To add a UDP tunnel which connects two IPv4 addresses:
//!
//! ```no_run
//! use std::net::Ipv4Addr;
//!
//! use nl_l2tp::L2tpTunnel;
//!
//! async fn add_l2tp_tunnel() -> Result<(), Box<dyn std::error::Error>> {
//!     let (conn, mut handle, _) = nl_l2tp::new_connection()?;
//!     tokio::spawn(conn);
//!
//!     let mut config = L2tpTunnel::new(1000);
//!     config.peer_tunnel_id = Some(2000);
//!     config.local = Some(Ipv4Addr::new(10, 0, 0, 1).into());
//!     config.peer = Some(Ipv4Addr::new(10, 0, 0, 2).into());
//!     config.local_udp_port = Some(1701);
//!     config.peer_udp_port = Some(1702);
//!     handle.add_tunnel(&config).await?;
//!     Ok(())
//! }
//! ```
//!
//! To list all tunnels, [L2tpHandle::get_tunnels] turns every tunnel of
//! the kernel reply into a [L2tpTunnel]:
//!
//! ```no_run
//! use nl_l2tp::L2tpTunnel;
//!
//! async fn show_l2tp_tunnels() -> Result<(), Box<dyn std::error::Error>> {
//!     let (conn, mut handle, _) = nl_l2tp::new_connection()?;
//!     tokio::spawn(conn);
//!
//!     for tunnel in handle.get_tunnels(&L2tpTunnel::default()).await? {
//!         println!("{tunnel:?}");
//!     }
//!     Ok(())
//! }
//! ```

mod config;
mod connection;
mod error;
mod handle;

#[doc(no_inline)]
pub use netlink_packet_l2tp::{
    L2tpAttribute, L2tpCmd, L2tpEncapType, L2tpMessage, L2tpPwType,
    L2tpStatsAttribute,
};

#[cfg(feature = "tokio_socket")]
pub use self::connection::new_connection;
pub use self::{
    config::{L2tpSession, L2tpTunnel},
    connection::new_connection_with_socket,
    error::{ErrorKind, L2tpError},
    handle::L2tpHandle,
};

// Compile the examples of the README as doc tests.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;
