use std::time::Duration;

use eyre::Context;
use mcpersist_relay::{Config, Relay, system_clock};

fn env(name: &str) -> eyre::Result<String> {
    std::env::var(name).with_context(|| format!("Reading {name}"))
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    env_logger::init();
    let relay = Relay::bind(Config {
        cert_path: env("QUICLIME_CERT_PATH")?.into(),
        key_path: env("QUICLIME_KEY_PATH")?.into(),
        base_domain: env("QUICLIME_BASE_DOMAIN")?,
        db_path: env("QUICLIME_DB_PATH")?.into(),
        bind_quic: env("QUICLIME_BIND_ADDR_QUIC")?.parse()?,
        bind_web: env("QUICLIME_BIND_ADDR_WEB")?.parse()?,
        bind_mc: env("QUICLIME_BIND_ADDR_MC")?.parse()?,
        bind_voice: std::env::var("QUICLIME_BIND_ADDR_VOICE")
            .unwrap_or_else(|_| "0.0.0.0:24454".into())
            .parse()?,
        clock: system_clock(),
        startup_grace: Duration::from_secs(match std::env::var("QUICLIME_STARTUP_GRACE_SECS") {
            Ok(secs) => secs.parse()?,
            Err(_) => 25,
        }),
    })
    .await?;
    relay.serve().await
}
