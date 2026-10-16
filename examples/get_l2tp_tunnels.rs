// SPDX-License-Identifier: MIT

use nl_l2tp::L2tpTunnel;

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("debug"),
    )
    .init();

    let (connection, mut handle, _) = nl_l2tp::new_connection().unwrap();
    tokio::spawn(connection);

    for tunnel in handle.get_tunnels(&L2tpTunnel::default()).await.unwrap() {
        println!("{tunnel:?}");
    }
}
