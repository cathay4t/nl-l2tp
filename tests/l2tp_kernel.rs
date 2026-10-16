// SPDX-License-Identifier: MIT

//! Integration tests exercising the kernel L2TP generic netlink API.
//!
//! These tests need `CAP_NET_ADMIN` and the `l2tp_netlink` kernel module,
//! they add and remove L2TP tunnels and sessions in the current network
//! namespace. Therefore they are `#[ignore]`d by default. Build the test
//! binary as an unprivileged user and run it as root, for example:
//!
//! ```bash
//! cargo test --test l2tp_kernel --no-run
//! sudo ./target/debug/deps/l2tp_kernel-* --ignored --nocapture
//! ```

use std::{
    net::Ipv4Addr,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use nl_l2tp::{L2tpHandle, L2tpSession, L2tpTunnel};

/// Tunnel and session IDs unlikely to be used by another process. Every
/// test run uses fresh IDs so that a leftover tunnel does not break it.
fn unique_id() -> u32 {
    (SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos()
        % 100000) as u32
        + 1000
}

/// The `l2tp_netlink` generic netlink family does not auto-load when the
/// family is resolved, load the modules explicitly.
fn load_l2tp_modules() {
    for module in ["l2tp_netlink", "l2tp_eth"] {
        let status = Command::new("modprobe")
            .arg(module)
            .status()
            .expect("failed to run modprobe");
        assert!(status.success(), "modprobe {module} failed");
    }
}

async fn connect() -> L2tpHandle {
    let (connection, handle, _) =
        nl_l2tp::new_connection().expect("failed to open netlink socket");
    tokio::spawn(connection);
    handle
}

/// A UDP tunnel between the loopback addresses, the config of
/// `ip l2tp add tunnel tunnel_id ID peer_tunnel_id ID+1 encap udp local
/// 127.0.0.1 remote 127.0.0.2 udp_sport PORT udp_dport PORT+1`.
///
/// The local UDP port is bound exclusively, every test uses its own port so
/// that the tests can run in parallel.
fn tunnel_config(tunnel_id: u32, udp_port: u16) -> L2tpTunnel {
    let mut config = L2tpTunnel::new(tunnel_id);
    config.peer_tunnel_id = Some(tunnel_id + 1);
    config.local = Some(Ipv4Addr::new(127, 0, 0, 1).into());
    config.peer = Some(Ipv4Addr::new(127, 0, 0, 2).into());
    config.local_udp_port = Some(udp_port);
    config.peer_udp_port = Some(udp_port + 1);
    config
}

fn session_config(tunnel_id: u32, session_id: u32) -> L2tpSession {
    let mut config = L2tpSession::new(tunnel_id, session_id);
    config.peer_session_id = Some(session_id + 1);
    config
}

fn find_tunnel(tunnels: &[L2tpTunnel], id: u32) -> Option<&L2tpTunnel> {
    tunnels.iter().find(|tunnel| tunnel.tunnel_id == Some(id))
}

fn find_session(
    sessions: &[L2tpSession],
    tunnel_id: u32,
    session_id: u32,
) -> Option<&L2tpSession> {
    sessions.iter().find(|session| {
        session.tunnel_id == Some(tunnel_id)
            && session.session_id == Some(session_id)
    })
}

#[tokio::test]
#[ignore = "needs root and the l2tp_netlink kernel module"]
async fn add_get_delete_tunnel() {
    load_l2tp_modules();
    let mut handle = connect().await;
    let tunnel_id = unique_id();
    let config = tunnel_config(tunnel_id, 1701);

    let _ = handle.delete_tunnel(&config).await;
    handle
        .add_tunnel(&config)
        .await
        .expect("failed to add tunnel");

    let tunnels = handle
        .get_tunnels(&L2tpTunnel::default())
        .await
        .expect("failed to dump tunnels");
    let tunnel = find_tunnel(&tunnels, tunnel_id).expect("tunnel not dumped");
    assert_eq!(tunnel.peer_tunnel_id, Some(tunnel_id + 1));
    assert_eq!(tunnel.local, Some(Ipv4Addr::new(127, 0, 0, 1).into()));
    assert_eq!(tunnel.peer, Some(Ipv4Addr::new(127, 0, 0, 2).into()));
    assert_eq!(tunnel.local_udp_port, Some(1701));
    assert_eq!(tunnel.peer_udp_port, Some(1702));

    handle
        .delete_tunnel(&config)
        .await
        .expect("failed to delete tunnel");
    let tunnels = handle
        .get_tunnels(&L2tpTunnel::default())
        .await
        .expect("failed to dump tunnels");
    assert!(find_tunnel(&tunnels, tunnel_id).is_none());
}

#[tokio::test]
#[ignore = "needs root and the l2tp_netlink kernel module"]
async fn add_get_delete_session() {
    load_l2tp_modules();
    let mut handle = connect().await;
    let tunnel_id = unique_id();
    let session_id = unique_id();
    let tunnel = tunnel_config(tunnel_id, 1703);
    let session = session_config(tunnel_id, session_id);

    let _ = handle.delete_session(&session).await;
    let _ = handle.delete_tunnel(&tunnel).await;
    handle
        .add_tunnel(&tunnel)
        .await
        .expect("failed to add tunnel");
    handle
        .add_session(&session)
        .await
        .expect("failed to add session");

    let sessions = handle
        .get_sessions(&L2tpSession::default())
        .await
        .expect("failed to dump sessions");
    let found = find_session(&sessions, tunnel_id, session_id)
        .expect("session not dumped");
    assert_eq!(found.peer_session_id, Some(session_id + 1));

    handle
        .delete_session(&session)
        .await
        .expect("failed to delete session");
    let sessions = handle
        .get_sessions(&L2tpSession::default())
        .await
        .expect("failed to dump sessions");
    assert!(find_session(&sessions, tunnel_id, session_id).is_none());

    handle
        .delete_tunnel(&tunnel)
        .await
        .expect("failed to delete tunnel");
}
