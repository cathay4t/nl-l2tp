# Rust crate for linux L2TP netlink management

## To add a tunnel

```rust
use std::net::Ipv4Addr;

use nl_l2tp::L2tpTunnel;

async fn add_l2tp_tunnel() -> Result<(), Box<dyn std::error::Error>> {
    let (conn, mut handle, _) = nl_l2tp::new_connection()?;
    tokio::spawn(conn);

    let mut config = L2tpTunnel::new(1000);
    config.peer_tunnel_id = Some(2000);
    config.local = Some(Ipv4Addr::new(10, 0, 0, 1).into());
    config.peer = Some(Ipv4Addr::new(10, 0, 0, 2).into());
    config.local_udp_port = Some(1701);
    config.peer_udp_port = Some(1702);
    handle.add_tunnel(&config).await?;
    Ok(())
}
```

## To list all tunnels

`L2tpHandle::get_tunnels()` returns one `L2tpTunnel` per tunnel:

```rust
use nl_l2tp::L2tpTunnel;

async fn show_l2tp_tunnels() -> Result<(), Box<dyn std::error::Error>> {
    let (conn, mut handle, _) = nl_l2tp::new_connection()?;
    tokio::spawn(conn);

    for tunnel in handle.get_tunnels(&L2tpTunnel::default()).await? {
        println!("{tunnel:?}");
    }
    Ok(())
}
```

## To delete a tunnel

A tunnel is identified by its local tunnel ID, `L2tpTunnel::new()` sets it:

```rust
use nl_l2tp::L2tpTunnel;

async fn delete_l2tp_tunnel() -> Result<(), Box<dyn std::error::Error>> {
    let (conn, mut handle, _) = nl_l2tp::new_connection()?;
    tokio::spawn(conn);

    handle.delete_tunnel(&L2tpTunnel::new(1000)).await?;
    Ok(())
}
```

## Notes

- `L2tpTunnel::new(tunnel_id)` creates a UDP tunnel config, the
  encapsulation of `ip l2tp add tunnel`.
- A UDP tunnel needs `local_udp_port` and `peer_udp_port`, an IP tunnel
  must not set them.
- Use `L2tpSession` and `L2tpHandle::add_session()`,
  `L2tpHandle::get_sessions()` and `L2tpHandle::delete_session()` to
  manage the sessions of a tunnel.

License: MIT
