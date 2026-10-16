// SPDX-License-Identifier: MIT

use std::net::IpAddr;

use netlink_packet_l2tp::{
    L2tpAttribute, L2tpCmd, L2tpEncapType, L2tpMessage, L2tpPwType,
};

use crate::{ErrorKind, L2tpError};

/// Default layer2 specific header type, `L2TP_L2SPECTYPE_DEFAULT`.
const L2SPECTYPE_DEFAULT: u8 = 1;
/// Length of the default layer2 specific header.
const L2SPECTYPE_DEFAULT_LEN: u8 = 4;

/// Configuration of a L2TP tunnel, as accepted by `ip l2tp add tunnel` and
/// `ip l2tp del tunnel`, and as `ip l2tp show tunnel` reports it.
///
/// Use [L2tpTunnel::build] to turn the configuration into a
/// [L2tpMessage].
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct L2tpTunnel {
    /// The local tunnel ID, `L2TP_ATTR_CONN_ID`.
    pub tunnel_id: Option<u32>,
    /// The tunnel ID of the peer, `L2TP_ATTR_PEER_CONN_ID`.
    pub peer_tunnel_id: Option<u32>,
    /// The encapsulation type, UDP by default.
    pub encap: Option<L2tpEncapType>,
    /// The local address of the tunnel.
    pub local: Option<IpAddr>,
    /// The address of the peer.
    pub peer: Option<IpAddr>,
    /// The local UDP source port, only used by UDP tunnels.
    pub local_udp_port: Option<u16>,
    /// The peer UDP destination port, only used by UDP tunnels.
    pub peer_udp_port: Option<u16>,
    /// Whether UDP checksums are enabled, only used by IPv4 UDP tunnels.
    pub udp_csum: bool,
    /// Whether UDP checksums are enabled on transmit for IPv6, only used by
    /// IPv6 UDP tunnels.
    pub udp6_csum_tx: bool,
    /// Whether UDP checksums are enabled on receive for IPv6, only used by
    /// IPv6 UDP tunnels.
    pub udp6_csum_rx: bool,
}

impl Default for L2tpTunnel {
    fn default() -> Self {
        Self {
            tunnel_id: None,
            peer_tunnel_id: None,
            encap: None,
            local: None,
            peer: None,
            local_udp_port: None,
            peer_udp_port: None,
            udp_csum: false,
            udp6_csum_tx: true,
            udp6_csum_rx: true,
        }
    }
}

impl L2tpTunnel {
    /// Create a UDP tunnel config with the given local tunnel ID.
    pub fn new(tunnel_id: u32) -> Self {
        Self {
            tunnel_id: Some(tunnel_id),
            encap: Some(L2tpEncapType::Udp),
            ..Default::default()
        }
    }

    /// Build the [L2tpMessage] of the `cmd` request for this configuration.
    pub fn build(&self, cmd: L2tpCmd) -> Result<L2tpMessage, L2tpError> {
        match cmd {
            L2tpCmd::TunnelCreate => self.build_create(),
            L2tpCmd::TunnelDelete => self.build_delete(),
            L2tpCmd::TunnelGet => Ok(self.build_get()),
            _ => Err(invalid_input(
                "only tunnel create, delete and get are supported",
            )),
        }
    }

    fn build_create(&self) -> Result<L2tpMessage, L2tpError> {
        let tunnel_id = self
            .tunnel_id
            .ok_or_else(|| invalid_input("tunnel_id is required"))?;
        let peer_tunnel_id = self
            .peer_tunnel_id
            .ok_or_else(|| invalid_input("peer_tunnel_id is required"))?;
        let local = self
            .local
            .ok_or_else(|| invalid_input("local address is required"))?;
        let peer = self
            .peer
            .ok_or_else(|| invalid_input("remote address is required"))?;
        let encap = self.encap.unwrap_or(L2tpEncapType::Udp);

        let mut attributes = vec![
            L2tpAttribute::ConnId(tunnel_id),
            L2tpAttribute::PeerConnId(peer_tunnel_id),
            L2tpAttribute::ProtoVersion(3),
            L2tpAttribute::EncapType(encap),
        ];

        match (local, peer) {
            (IpAddr::V4(local), IpAddr::V4(peer)) => {
                attributes.push(L2tpAttribute::IpSaddr(local));
                attributes.push(L2tpAttribute::IpDaddr(peer));
            }
            (IpAddr::V6(local), IpAddr::V6(peer)) => {
                attributes.push(L2tpAttribute::Ip6Saddr(local));
                attributes.push(L2tpAttribute::Ip6Daddr(peer));
            }
            (_, _) => {
                return Err(invalid_input(
                    "local and remote address families do not match",
                ));
            }
        }

        if encap == L2tpEncapType::Udp {
            let local_udp_port = self.local_udp_port.ok_or_else(|| {
                invalid_input("udp_sport is required for UDP tunnels")
            })?;
            let peer_udp_port = self
                .peer_udp_port
                .ok_or_else(|| invalid_input("udp_dport is required"))?;
            attributes.push(L2tpAttribute::UdpSport(local_udp_port));
            attributes.push(L2tpAttribute::UdpDport(peer_udp_port));
            if self.udp_csum {
                attributes.push(L2tpAttribute::UdpCsum(1));
            }
            if !self.udp6_csum_tx {
                attributes.push(L2tpAttribute::UdpZeroCsum6Tx);
            }
            if !self.udp6_csum_rx {
                attributes.push(L2tpAttribute::UdpZeroCsum6Rx);
            }
        }

        Ok(L2tpMessage {
            cmd: L2tpCmd::TunnelCreate,
            attributes,
        })
    }

    fn build_delete(&self) -> Result<L2tpMessage, L2tpError> {
        let tunnel_id = self
            .tunnel_id
            .ok_or_else(|| invalid_input("tunnel_id is required"))?;
        Ok(L2tpMessage {
            cmd: L2tpCmd::TunnelDelete,
            attributes: vec![L2tpAttribute::ConnId(tunnel_id)],
        })
    }

    fn build_get(&self) -> L2tpMessage {
        let mut attributes = Vec::new();
        if let Some(tunnel_id) = self.tunnel_id {
            attributes.push(L2tpAttribute::ConnId(tunnel_id));
        }
        L2tpMessage {
            cmd: L2tpCmd::TunnelGet,
            attributes,
        }
    }
}

impl From<L2tpMessage> for L2tpTunnel {
    fn from(msg: L2tpMessage) -> Self {
        let mut ret = Self::default();
        for attr in msg.attributes {
            match attr {
                L2tpAttribute::ConnId(v) => ret.tunnel_id = Some(v),
                L2tpAttribute::PeerConnId(v) => ret.peer_tunnel_id = Some(v),
                L2tpAttribute::EncapType(v) => ret.encap = Some(v),
                L2tpAttribute::IpSaddr(v) => ret.local = Some(IpAddr::V4(v)),
                L2tpAttribute::IpDaddr(v) => ret.peer = Some(IpAddr::V4(v)),
                L2tpAttribute::Ip6Saddr(v) => ret.local = Some(IpAddr::V6(v)),
                L2tpAttribute::Ip6Daddr(v) => ret.peer = Some(IpAddr::V6(v)),
                L2tpAttribute::UdpSport(v) => ret.local_udp_port = Some(v),
                L2tpAttribute::UdpDport(v) => ret.peer_udp_port = Some(v),
                L2tpAttribute::UdpCsum(v) => ret.udp_csum = v != 0,
                L2tpAttribute::UdpZeroCsum6Tx => ret.udp6_csum_tx = false,
                L2tpAttribute::UdpZeroCsum6Rx => ret.udp6_csum_rx = false,
                _ => log::debug!("Unsupported tunnel L2tpAttribute {attr:?}"),
            }
        }
        ret
    }
}

/// Configuration of a L2TP session, as accepted by `ip l2tp add session`
/// and `ip l2tp del session`, and as `ip l2tp show session` reports it.
///
/// Use [L2tpSession::build] to turn the configuration into a
/// [L2tpMessage].
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct L2tpSession {
    /// The ID of the tunnel the session belongs to, `L2TP_ATTR_CONN_ID`.
    pub tunnel_id: Option<u32>,
    /// The tunnel ID of the peer, `L2TP_ATTR_PEER_CONN_ID`.
    pub peer_tunnel_id: Option<u32>,
    /// The local session ID, `L2TP_ATTR_SESSION_ID`.
    pub session_id: Option<u32>,
    /// The session ID of the peer, `L2TP_ATTR_PEER_SESSION_ID`.
    pub peer_session_id: Option<u32>,
    /// The name of the network interface the kernel creates, only used
    /// when the session is created.
    pub ifname: Option<String>,
    /// The optional session cookie, 0, 4 or 8 bytes.
    pub cookie: Option<Vec<u8>>,
    /// The optional peer session cookie, 0, 4 or 8 bytes.
    pub peer_cookie: Option<Vec<u8>>,
    /// Enable sequence numbers on receive.
    pub recv_seq: bool,
    /// Enable sequence numbers on transmit.
    pub send_seq: bool,
    /// The reorder timeout in milliseconds.
    pub reorder_timeout: Option<u64>,
    /// The layer2 specific header type, `L2TP_L2SPECTYPE_DEFAULT` by
    /// default.
    pub l2spec_type: u8,
    /// The length of the layer2 specific header, 4 for the default type.
    pub l2spec_len: u8,
}

impl Default for L2tpSession {
    fn default() -> Self {
        Self {
            tunnel_id: None,
            peer_tunnel_id: None,
            session_id: None,
            peer_session_id: None,
            ifname: None,
            cookie: None,
            peer_cookie: None,
            recv_seq: false,
            send_seq: false,
            reorder_timeout: None,
            l2spec_type: L2SPECTYPE_DEFAULT,
            l2spec_len: L2SPECTYPE_DEFAULT_LEN,
        }
    }
}

impl L2tpSession {
    /// Create a session config for the given tunnel and session IDs.
    pub fn new(tunnel_id: u32, session_id: u32) -> Self {
        Self {
            tunnel_id: Some(tunnel_id),
            session_id: Some(session_id),
            ..Default::default()
        }
    }

    /// Build the [L2tpMessage] of the `cmd` request for this configuration.
    pub fn build(&self, cmd: L2tpCmd) -> Result<L2tpMessage, L2tpError> {
        match cmd {
            L2tpCmd::SessionCreate => self.build_create(),
            L2tpCmd::SessionDelete => self.build_delete(),
            L2tpCmd::SessionGet => Ok(self.build_get()),
            _ => Err(invalid_input(
                "only session create, delete and get are supported",
            )),
        }
    }

    fn build_create(&self) -> Result<L2tpMessage, L2tpError> {
        let tunnel_id = self
            .tunnel_id
            .ok_or_else(|| invalid_input("tunnel_id is required"))?;
        let session_id = self
            .session_id
            .ok_or_else(|| invalid_input("session_id is required"))?;
        let peer_session_id = self
            .peer_session_id
            .ok_or_else(|| invalid_input("peer_session_id is required"))?;

        let mut attributes = vec![
            L2tpAttribute::ConnId(tunnel_id),
            L2tpAttribute::PeerConnId(self.peer_tunnel_id.unwrap_or_default()),
            L2tpAttribute::SessionId(session_id),
            L2tpAttribute::PeerSessionId(peer_session_id),
            L2tpAttribute::PwType(L2tpPwType::Eth),
            L2tpAttribute::L2SpecType(self.l2spec_type),
            L2tpAttribute::L2SpecLen(self.l2spec_len),
        ];

        if self.recv_seq {
            attributes.push(L2tpAttribute::RecvSeq(1));
        }
        if self.send_seq {
            attributes.push(L2tpAttribute::SendSeq(1));
        }
        if let Some(timeout) = self.reorder_timeout {
            attributes.push(L2tpAttribute::RecvTimeout(timeout));
        }
        if let Some(cookie) = self.cookie.as_ref() {
            attributes.push(L2tpAttribute::Cookie(cookie.clone()));
        }
        if let Some(peer_cookie) = self.peer_cookie.as_ref() {
            attributes.push(L2tpAttribute::PeerCookie(peer_cookie.clone()));
        }
        if let Some(ifname) = self.ifname.as_ref() {
            attributes.push(L2tpAttribute::IfName(ifname.clone()));
        }

        Ok(L2tpMessage {
            cmd: L2tpCmd::SessionCreate,
            attributes,
        })
    }

    fn build_delete(&self) -> Result<L2tpMessage, L2tpError> {
        let tunnel_id = self
            .tunnel_id
            .ok_or_else(|| invalid_input("tunnel_id is required"))?;
        let session_id = self
            .session_id
            .ok_or_else(|| invalid_input("session_id is required"))?;
        Ok(L2tpMessage {
            cmd: L2tpCmd::SessionDelete,
            attributes: vec![
                L2tpAttribute::ConnId(tunnel_id),
                L2tpAttribute::SessionId(session_id),
            ],
        })
    }

    fn build_get(&self) -> L2tpMessage {
        let mut attributes = Vec::new();
        if let Some(tunnel_id) = self.tunnel_id {
            attributes.push(L2tpAttribute::ConnId(tunnel_id));
        }
        if let Some(session_id) = self.session_id {
            attributes.push(L2tpAttribute::SessionId(session_id));
        }
        L2tpMessage {
            cmd: L2tpCmd::SessionGet,
            attributes,
        }
    }
}

impl From<L2tpMessage> for L2tpSession {
    fn from(msg: L2tpMessage) -> Self {
        let mut ret = Self::default();
        for attr in msg.attributes {
            match attr {
                L2tpAttribute::ConnId(v) => ret.tunnel_id = Some(v),
                L2tpAttribute::PeerConnId(v) => ret.peer_tunnel_id = Some(v),
                L2tpAttribute::SessionId(v) => ret.session_id = Some(v),
                L2tpAttribute::PeerSessionId(v) => {
                    ret.peer_session_id = Some(v)
                }
                L2tpAttribute::IfName(v) => {
                    // The kernel reports an empty name for a session which
                    // has no network interface, hide it.
                    if !v.is_empty() {
                        ret.ifname = Some(v);
                    }
                }
                L2tpAttribute::Cookie(v) if !v.is_empty() => {
                    ret.cookie = Some(v);
                }
                L2tpAttribute::PeerCookie(v) if !v.is_empty() => {
                    ret.peer_cookie = Some(v);
                }
                L2tpAttribute::RecvSeq(v) => ret.recv_seq = v != 0,
                L2tpAttribute::SendSeq(v) => ret.send_seq = v != 0,
                L2tpAttribute::RecvTimeout(v) if v != 0 => {
                    ret.reorder_timeout = Some(v)
                }
                L2tpAttribute::L2SpecType(v) => ret.l2spec_type = v,
                L2tpAttribute::L2SpecLen(v) => ret.l2spec_len = v,
                _ => log::debug!("Unsupported session L2tpAttribute {attr:?}"),
            }
        }
        ret
    }
}

fn invalid_input(msg: &str) -> L2tpError {
    L2tpError::new(ErrorKind::InvalidInput, msg.to_string(), None)
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use netlink_packet_l2tp::L2tpEncapType;
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn build_ipv4_udp_tunnel() {
        let config = L2tpTunnel {
            peer_tunnel_id: Some(2000),
            local: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            peer: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
            local_udp_port: Some(1701),
            peer_udp_port: Some(1702),
            ..L2tpTunnel::new(1000)
        };

        assert_eq!(
            config.build(L2tpCmd::TunnelCreate).unwrap(),
            L2tpMessage {
                cmd: L2tpCmd::TunnelCreate,
                attributes: vec![
                    L2tpAttribute::ConnId(1000),
                    L2tpAttribute::PeerConnId(2000),
                    L2tpAttribute::ProtoVersion(3),
                    L2tpAttribute::EncapType(L2tpEncapType::Udp),
                    L2tpAttribute::IpSaddr(Ipv4Addr::new(10, 0, 0, 1)),
                    L2tpAttribute::IpDaddr(Ipv4Addr::new(10, 0, 0, 2)),
                    L2tpAttribute::UdpSport(1701),
                    L2tpAttribute::UdpDport(1702),
                ],
            }
        );
    }

    #[test]
    fn build_ipv6_udp_tunnel_with_zero_checksums() {
        let config = L2tpTunnel {
            peer_tunnel_id: Some(2000),
            local: Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            peer: Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            local_udp_port: Some(1701),
            peer_udp_port: Some(1702),
            udp6_csum_tx: false,
            ..L2tpTunnel::new(1000)
        };

        assert_eq!(
            config.build(L2tpCmd::TunnelCreate).unwrap(),
            L2tpMessage {
                cmd: L2tpCmd::TunnelCreate,
                attributes: vec![
                    L2tpAttribute::ConnId(1000),
                    L2tpAttribute::PeerConnId(2000),
                    L2tpAttribute::ProtoVersion(3),
                    L2tpAttribute::EncapType(L2tpEncapType::Udp),
                    L2tpAttribute::Ip6Saddr(Ipv6Addr::LOCALHOST),
                    L2tpAttribute::Ip6Daddr(Ipv6Addr::LOCALHOST),
                    L2tpAttribute::UdpSport(1701),
                    L2tpAttribute::UdpDport(1702),
                    L2tpAttribute::UdpZeroCsum6Tx,
                ],
            }
        );
    }

    #[test]
    fn build_ip_tunnel_has_no_udp_ports() {
        let config = L2tpTunnel {
            encap: Some(L2tpEncapType::Ip),
            peer_tunnel_id: Some(2000),
            local: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            peer: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
            ..L2tpTunnel::new(1000)
        };

        let message = config.build(L2tpCmd::TunnelCreate).unwrap();
        assert!(
            !message
                .attributes
                .iter()
                .any(|attr| matches!(attr, L2tpAttribute::UdpSport(_)))
        );
    }

    #[test]
    fn reject_udp_tunnel_without_ports() {
        let config = L2tpTunnel {
            peer_tunnel_id: Some(2000),
            local: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            peer: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
            ..L2tpTunnel::new(1000)
        };
        assert!(config.build(L2tpCmd::TunnelCreate).is_err());
    }

    #[test]
    fn reject_mismatched_address_family() {
        let config = L2tpTunnel {
            peer_tunnel_id: Some(2000),
            local: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            peer: Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            local_udp_port: Some(1701),
            peer_udp_port: Some(1702),
            ..L2tpTunnel::new(1000)
        };
        assert!(config.build(L2tpCmd::TunnelCreate).is_err());
    }

    #[test]
    fn build_tunnel_delete() {
        assert_eq!(
            L2tpTunnel::new(1000).build(L2tpCmd::TunnelDelete).unwrap(),
            L2tpMessage {
                cmd: L2tpCmd::TunnelDelete,
                attributes: vec![L2tpAttribute::ConnId(1000)],
            }
        );
    }

    #[test]
    fn build_session_create() {
        let config = L2tpSession {
            peer_session_id: Some(6),
            ifname: Some("l2tpeth0".to_string()),
            ..L2tpSession::new(1000, 5)
        };

        assert_eq!(
            config.build(L2tpCmd::SessionCreate).unwrap(),
            L2tpMessage {
                cmd: L2tpCmd::SessionCreate,
                attributes: vec![
                    L2tpAttribute::ConnId(1000),
                    L2tpAttribute::PeerConnId(0),
                    L2tpAttribute::SessionId(5),
                    L2tpAttribute::PeerSessionId(6),
                    L2tpAttribute::PwType(L2tpPwType::Eth),
                    L2tpAttribute::L2SpecType(1),
                    L2tpAttribute::L2SpecLen(4),
                    L2tpAttribute::IfName("l2tpeth0".to_string()),
                ],
            }
        );
    }

    #[test]
    fn build_session_delete() {
        assert_eq!(
            L2tpSession::new(1000, 5)
                .build(L2tpCmd::SessionDelete)
                .unwrap(),
            L2tpMessage {
                cmd: L2tpCmd::SessionDelete,
                attributes: vec![
                    L2tpAttribute::ConnId(1000),
                    L2tpAttribute::SessionId(5),
                ],
            }
        );
    }

    #[test]
    fn parse_tunnel_message() {
        let config = L2tpTunnel::from(L2tpMessage {
            cmd: L2tpCmd::TunnelGet,
            attributes: vec![
                L2tpAttribute::ProtoVersion(3),
                L2tpAttribute::ConnId(1000),
                L2tpAttribute::PeerConnId(2000),
                L2tpAttribute::EncapType(L2tpEncapType::Udp),
                L2tpAttribute::IpSaddr(Ipv4Addr::new(127, 0, 0, 1)),
                L2tpAttribute::IpDaddr(Ipv4Addr::new(127, 0, 0, 2)),
                L2tpAttribute::UdpCsum(1),
                L2tpAttribute::UdpSport(1701),
                L2tpAttribute::UdpDport(1702),
            ],
        });

        assert_eq!(
            config,
            L2tpTunnel {
                tunnel_id: Some(1000),
                peer_tunnel_id: Some(2000),
                encap: Some(L2tpEncapType::Udp),
                local: Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
                peer: Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))),
                local_udp_port: Some(1701),
                peer_udp_port: Some(1702),
                udp_csum: true,
                ..Default::default()
            }
        );
    }

    #[test]
    fn parse_session_message() {
        let config = L2tpSession::from(L2tpMessage {
            cmd: L2tpCmd::SessionGet,
            attributes: vec![
                L2tpAttribute::ConnId(1000),
                L2tpAttribute::PeerConnId(2000),
                L2tpAttribute::SessionId(5),
                L2tpAttribute::PeerSessionId(6),
                L2tpAttribute::IfName("l2tpeth0".to_string()),
                L2tpAttribute::RecvSeq(0),
                L2tpAttribute::SendSeq(1),
            ],
        });

        assert_eq!(
            config,
            L2tpSession {
                tunnel_id: Some(1000),
                peer_tunnel_id: Some(2000),
                session_id: Some(5),
                peer_session_id: Some(6),
                ifname: Some("l2tpeth0".to_string()),
                send_seq: true,
                ..Default::default()
            }
        );
    }
}
