// SPDX-License-Identifier: MIT

use std::{io, sync::Arc};

use futures_util::{Stream, StreamExt, future::ready};
use genetlink::GenetlinkHandle;
use netlink_packet_core::{
    DecodeError, ErrorMessage, NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST,
    NetlinkMessage, NetlinkPayload,
};
use netlink_packet_generic::GenlMessage;
use netlink_packet_l2tp::{L2tpCmd, L2tpMessage};

use crate::{ErrorKind, L2tpError, L2tpSession, L2tpTunnel};

#[derive(Clone, Debug)]
pub struct L2tpHandle {
    handle: GenetlinkHandle,
}

impl L2tpHandle {
    pub(crate) fn new(handle: GenetlinkHandle) -> Self {
        Self { handle }
    }

    /// Create the tunnel defined by `config`.
    pub async fn add_tunnel(
        &mut self,
        config: &L2tpTunnel,
    ) -> Result<(), L2tpError> {
        self.do_request(config.build(L2tpCmd::TunnelCreate)?).await
    }

    /// Delete the tunnel defined by `config`.
    pub async fn delete_tunnel(
        &mut self,
        config: &L2tpTunnel,
    ) -> Result<(), L2tpError> {
        self.do_request(config.build(L2tpCmd::TunnelDelete)?).await
    }

    /// Create the session defined by `config`.
    pub async fn add_session(
        &mut self,
        config: &L2tpSession,
    ) -> Result<(), L2tpError> {
        self.do_request(config.build(L2tpCmd::SessionCreate)?).await
    }

    /// Delete the session defined by `config`.
    pub async fn delete_session(
        &mut self,
        config: &L2tpSession,
    ) -> Result<(), L2tpError> {
        self.do_request(config.build(L2tpCmd::SessionDelete)?).await
    }

    /// Dump the tunnels of the current network namespace.
    ///
    /// The filter of `config` is applied by the kernel, an unset
    /// [L2tpTunnel::tunnel_id] dumps every tunnel.
    pub async fn get_tunnels(
        &mut self,
        config: &L2tpTunnel,
    ) -> Result<Vec<L2tpTunnel>, L2tpError> {
        let message = config.build(L2tpCmd::TunnelGet)?;
        let mut stream =
            self.request(NLM_F_REQUEST | NLM_F_DUMP, message).await?;

        let mut tunnels = Vec::new();
        while let Some(reply) = stream.next().await {
            tunnels.push(L2tpTunnel::from(reply?));
        }
        Ok(tunnels)
    }

    /// Dump the sessions of the current network namespace.
    ///
    /// The filter of `config` is applied by the kernel, unset IDs dump
    /// every session.
    pub async fn get_sessions(
        &mut self,
        config: &L2tpSession,
    ) -> Result<Vec<L2tpSession>, L2tpError> {
        let message = config.build(L2tpCmd::SessionGet)?;
        let mut stream =
            self.request(NLM_F_REQUEST | NLM_F_DUMP, message).await?;

        let mut sessions = Vec::new();
        while let Some(reply) = stream.next().await {
            sessions.push(L2tpSession::from(reply?));
        }
        Ok(sessions)
    }

    /// Send an arbitrary [L2tpMessage] and manually handle the replies from
    /// the kernel.
    pub async fn request(
        &mut self,
        nl_header_flags: u16,
        message: L2tpMessage,
    ) -> Result<impl Stream<Item = Result<L2tpMessage, L2tpError>>, L2tpError>
    {
        let mut nl_msg =
            NetlinkMessage::from(GenlMessage::from_payload(message));
        nl_msg.header.flags = nl_header_flags;

        match self.handle.request(nl_msg.clone()).await {
            Ok(stream) => Ok(parse_nl_msg_stream(nl_msg, stream)),
            Err(e) => Err(L2tpError::new(
                ErrorKind::NetlinkError,
                format!("Netlink request failed: {e}"),
                Some(nl_msg),
            )),
        }
    }

    async fn do_request(
        &mut self,
        message: L2tpMessage,
    ) -> Result<(), L2tpError> {
        // A successful request is acknowledged with an `NLMSG_ERROR`
        // message without an error code, which ends the reply stream
        // without yielding an item, therefore an error is the only way a
        // request fails.
        let mut stream =
            self.request(NLM_F_REQUEST | NLM_F_ACK, message).await?;
        while let Some(reply) = stream.next().await {
            reply?;
        }
        Ok(())
    }
}

fn parse_nl_msg_stream(
    nl_msg: NetlinkMessage<GenlMessage<L2tpMessage>>,
    stream: impl Stream<
        Item = Result<NetlinkMessage<GenlMessage<L2tpMessage>>, DecodeError>,
    >,
) -> impl Stream<Item = Result<L2tpMessage, L2tpError>> {
    let nl_msg = Arc::new(nl_msg);

    stream.filter_map(move |reply| {
        let nl_msg = Arc::clone(&nl_msg);
        ready(match reply {
            Ok(reply_msg) => {
                let (header, payload) = reply_msg.into_parts();
                match payload {
                    NetlinkPayload::InnerMessage(genl_msg) => {
                        let (_genl_hdr, l2tp_msg) = genl_msg.into_parts();
                        Some(Ok(l2tp_msg))
                    }
                    // An acknowledgement holds no error code and completes
                    // the request.
                    NetlinkPayload::Error(err) if err.code.is_none() => None,
                    NetlinkPayload::Error(err) => Some(Err(L2tpError::new(
                        ErrorKind::KernelError,
                        netlink_error_message(&err),
                        Some((*nl_msg).clone()),
                    ))),
                    // A dump reports its error code in the message which
                    // ends the dump.
                    NetlinkPayload::Done(done) => {
                        if done.code == 0 {
                            None
                        } else {
                            Some(Err(L2tpError::new(
                                ErrorKind::KernelError,
                                format!(
                                    "Netlink dump failed: {}",
                                    io::Error::from_raw_os_error(-done.code)
                                ),
                                Some((*nl_msg).clone()),
                            )))
                        }
                    }
                    NetlinkPayload::Noop => None,
                    // An overrun message holds raw bytes of a message which
                    // could not be read, attach the request instead.
                    NetlinkPayload::Overrun(_) => Some(Err(L2tpError::new(
                        ErrorKind::Bug,
                        "Netlink message overrun, messages were lost"
                            .to_string(),
                        Some((*nl_msg).clone()),
                    ))),
                    payload => Some(Err(L2tpError::new(
                        ErrorKind::Bug,
                        format!(
                            "Unexpected NetlinkPayload type: {}",
                            payload_type(&payload)
                        ),
                        Some(NetlinkMessage::new(header, payload)),
                    ))),
                }
            }
            Err(e) => Some(Err(L2tpError::new(
                ErrorKind::DecodeError,
                format!("netlink decode error: {e}"),
                Some((*nl_msg).clone()),
            ))),
        })
    })
}

/// Describe a netlink error by its errno.
fn netlink_error_message(err: &ErrorMessage) -> String {
    match err.code {
        Some(code) => format!(
            "Netlink error: {}",
            io::Error::from_raw_os_error(-code.get())
        ),
        None => "Netlink error: no error code".to_string(),
    }
}

/// Name the type of `payload` without rendering its content.
fn payload_type<I>(payload: &NetlinkPayload<I>) -> &'static str {
    match payload {
        NetlinkPayload::Done(_) => "Done",
        NetlinkPayload::Error(_) => "Error",
        NetlinkPayload::Noop => "Noop",
        NetlinkPayload::Overrun(_) => "Overrun",
        NetlinkPayload::InnerMessage(_) => "InnerMessage",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroI32;

    use futures_util::stream;
    use netlink_packet_core::{DoneMessage, ErrorMessage, NetlinkHeader};
    use netlink_packet_l2tp::L2tpAttribute;

    use super::*;

    type NetlinkMsg = NetlinkMessage<GenlMessage<L2tpMessage>>;

    fn inner_message() -> NetlinkMsg {
        NetlinkMessage::from(GenlMessage::from_payload(L2tpMessage {
            cmd: L2tpCmd::TunnelGet,
            attributes: vec![L2tpAttribute::ConnId(1000)],
        }))
    }

    fn acknowledgement() -> NetlinkMsg {
        NetlinkMessage::new(
            NetlinkHeader::default(),
            NetlinkPayload::Error(ErrorMessage::default()),
        )
    }

    fn error(code: i32) -> NetlinkMsg {
        let mut error_message = ErrorMessage::default();
        error_message.code = NonZeroI32::new(code);
        NetlinkMessage::new(
            NetlinkHeader::default(),
            NetlinkPayload::Error(error_message),
        )
    }

    fn done(code: i32) -> NetlinkMsg {
        let mut done_message = DoneMessage::default();
        done_message.code = code;
        NetlinkMessage::new(
            NetlinkHeader::default(),
            NetlinkPayload::Done(done_message),
        )
    }

    async fn parse_replies(
        replies: Vec<NetlinkMsg>,
    ) -> Vec<Result<L2tpMessage, L2tpError>> {
        let replies: Vec<Result<NetlinkMsg, DecodeError>> =
            replies.into_iter().map(Ok).collect();
        parse_nl_msg_stream(inner_message(), stream::iter(replies))
            .collect()
            .await
    }

    #[tokio::test]
    async fn acknowledgement_and_done_are_not_errors() {
        let replies =
            parse_replies(vec![inner_message(), done(0), acknowledgement()])
                .await;

        assert_eq!(replies.len(), 1);
        assert!(replies[0].is_ok());
    }

    #[tokio::test]
    async fn netlink_error_is_reported() {
        let replies = parse_replies(vec![error(-22)]).await;

        assert_eq!(replies.len(), 1);
        let err = replies[0].as_ref().expect_err("expected an error");
        assert_eq!(err.kind, ErrorKind::KernelError);
        assert!(
            err.msg.contains("Invalid argument"),
            "unexpected error message: {}",
            err.msg
        );
    }

    #[tokio::test]
    async fn dump_error_is_reported() {
        let replies = parse_replies(vec![done(-19)]).await;

        assert_eq!(replies.len(), 1);
        let err = replies[0].as_ref().expect_err("expected an error");
        assert_eq!(err.kind, ErrorKind::KernelError);
        assert!(
            err.msg.contains("No such device"),
            "unexpected error message: {}",
            err.msg
        );
    }

    #[tokio::test]
    async fn overrun_is_reported() {
        let replies = parse_replies(vec![NetlinkMessage::new(
            NetlinkHeader::default(),
            NetlinkPayload::Overrun(Vec::new()),
        )])
        .await;

        assert_eq!(replies.len(), 1);
        let err = replies[0].as_ref().expect_err("expected an error");
        assert_eq!(err.kind, ErrorKind::Bug);
    }
}
