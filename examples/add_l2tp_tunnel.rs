// SPDX-License-Identifier: MIT

use std::{env::args, net::Ipv4Addr};

use nl_l2tp::L2tpTunnel;

#[tokio::main]
async fn main() {
    env_logger::init();

    let argv: Vec<String> = args().collect();
    if argv.len() < 2 {
        eprintln!("Usage: add_l2tp_tunnel <tunnel_id>");
        return;
    }
    let tunnel_id: u32 = argv[1].parse().expect("invalid tunnel id");

    let mut config = L2tpTunnel::new(tunnel_id);
    config.peer_tunnel_id = Some(tunnel_id + 1);
    config.local = Some(Ipv4Addr::new(127, 0, 0, 1).into());
    config.peer = Some(Ipv4Addr::new(127, 0, 0, 2).into());
    config.local_udp_port = Some(1701);
    config.peer_udp_port = Some(1702);

    let (connection, mut handle, _) = nl_l2tp::new_connection().unwrap();
    tokio::spawn(connection);
    handle.add_tunnel(&config).await.unwrap();

    println!("Added tunnel {config:?}");
    for tunnel in handle.get_tunnels(&L2tpTunnel::default()).await.unwrap() {
        println!("{tunnel:?}");
    }
}
