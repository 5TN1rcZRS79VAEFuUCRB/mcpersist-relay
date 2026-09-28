#![warn(clippy::pedantic)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]

use std::{
    convert::Infallible,
    net::SocketAddr,
    path::{Path as FsPath, PathBuf},
    sync::Arc,
    time::Duration,
};

use axum::{
    extract::Path,
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use eyre::{Context, eyre};
use log::{error, info, warn};
use netty::{Handshake, ReadError};
use quinn::{
    ConnectionError, Endpoint, Incoming, RecvStream, SendStream, ServerConfig, TransportConfig,
    VarInt,
    crypto::rustls::QuicServerConfig,
    rustls::pki_types::{CertificateDer, PrivateKeyDer},
};
use routing::{RoutingError, RoutingTable};
use rustls_pki_types::pem::PemObject;
use tokio::net::TcpListener;
use tokio::{
    io::AsyncWriteExt,
    net::TcpStream,
};

use crate::{
    netty::{ReadExt, WriteExt, read_varint},
    proto::{ClientboundControlMessage, ServerboundControlMessage},
    routing::RouterRequest,
};

mod names;
pub use names::{Clock, EXPIRY_SECS, system_clock};
mod netty;
mod proto;
mod routing;
mod voice;
mod wordlist;

use voice::VoiceRouter;

fn get_certs(
    cert_path: &FsPath,
    key_path: &FsPath,
) -> eyre::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let certs = CertificateDer::pem_file_iter(cert_path)
        .context("Opening certificate")?
        .filter_map(Result::ok)
        .collect();
    let key = PrivateKeyDer::from_pem_file(key_path)?;
    Ok((certs, key))
}

async fn create_server_config(config: &'static Config) -> eyre::Result<ServerConfig> {
    let (cert_chain, key_der) =
        tokio::task::spawn_blocking(|| get_certs(&config.cert_path, &config.key_path)).await??;
    let mut rustls_config = quinn::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key_der)?;
    rustls_config.alpn_protocols = vec![b"quiclime".to_vec()];
    let quic_rustls_config = QuicServerConfig::try_from(rustls_config)?;
    let mut config = ServerConfig::with_crypto(Arc::new(quic_rustls_config));
    let mut transport = TransportConfig::default();
    transport
        .max_concurrent_bidi_streams(1u32.into())
        .max_concurrent_uni_streams(0u32.into())
        .keep_alive_interval(Some(Duration::from_secs(5)));
    config.transport_config(Arc::new(transport));
    Ok(config)
}

pub struct Config {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub base_domain: String,
    pub db_path: PathBuf,
    pub bind_quic: SocketAddr,
    pub bind_web: SocketAddr,
    pub bind_mc: SocketAddr,
    /// UDP, for Simple Voice Chat players.
    pub bind_voice: SocketAddr,
    pub clock: Clock,
    /// How long a joining player waits for an offline persistent world to come back, e.g.
    /// while it restarts in the background after its host left. Keep it under the
    /// Minecraft client's 30-second read timeout.
    pub startup_grace: Duration,
}

/// A relay whose sockets are bound; `serve` runs it.
pub struct Relay {
    config: &'static Config,
    endpoint: &'static Endpoint,
    routing_table: &'static RoutingTable,
    voice: &'static VoiceRouter,
    web: TcpListener,
    mc: TcpListener,
}

impl Relay {
    pub async fn bind(config: Config) -> eyre::Result<Self> {
        // The control endpoints (stop, broadcast, cert reload) have no authentication.
        if !config.bind_web.ip().is_loopback() {
            return Err(eyre!(
                "QUICLIME_BIND_ADDR_WEB must be a loopback address, got {}",
                config.bind_web
            ));
        }
        // JUSTIFICATION: these live until the end of the entire program
        let config: &'static Config = Box::leak(Box::new(config));
        let endpoint = Box::leak(Box::new(Endpoint::server(
            create_server_config(config).await?,
            config.bind_quic,
        )?));
        let routing_table = Box::leak(Box::new(RoutingTable::new(
            config.base_domain.clone(),
            names::Names::open(&config.db_path, config.clock.clone())
                .context("Opening name database")?,
            config.startup_grace,
        )));
        let voice = Box::leak(Box::new(VoiceRouter::bind(config.bind_voice).await?));
        Ok(Self {
            config,
            endpoint,
            routing_table,
            voice,
            web: TcpListener::bind(config.bind_web).await?,
            mc: TcpListener::bind(config.bind_mc).await?,
        })
    }

    pub fn quic_addr(&self) -> std::io::Result<SocketAddr> {
        self.endpoint.local_addr()
    }

    pub fn web_addr(&self) -> std::io::Result<SocketAddr> {
        self.web.local_addr()
    }

    pub fn mc_addr(&self) -> std::io::Result<SocketAddr> {
        self.mc.local_addr()
    }

    pub fn voice_port(&self) -> std::io::Result<u16> {
        self.voice.port()
    }

    pub async fn serve(self) -> eyre::Result<()> {
        #[allow(unreachable_code)]
        tokio::try_join!(
            listen_quic(self.endpoint, self.routing_table, self.voice),
            async { self.voice.listen().await.map_err(eyre::Report::from) },
            listen_control(self.config, self.endpoint, self.routing_table, self.web),
            listen_minecraft(self.routing_table, self.mc)
        )?;
        Ok(())
    }
}

/// A control message to the host: its JSON's length as a varint, then the JSON.
async fn write_message(
    stream: &mut SendStream,
    message: &ClientboundControlMessage,
) -> eyre::Result<()> {
    let json = serde_json::to_vec(message)?;
    let mut framed = Vec::with_capacity(json.len() + 5);
    framed.write_varint(json.len() as i32).await?;
    framed.extend_from_slice(&json);
    stream.write_all(&framed).await?;
    Ok(())
}

/// The host's next control message, framed like `write_message`; `None` for one this relay
/// doesn't understand. A length out of bounds ends the connection.
async fn read_message(stream: &mut RecvStream) -> eyre::Result<Option<ServerboundControlMessage>> {
    let len = read_varint(&mut *stream).await?;
    if !(0..=8192).contains(&len) {
        return Err(eyre!("control message of {len} bytes"));
    }
    let mut buf = vec![0u8; len as usize];
    stream.read_exact(&mut buf).await?;
    Ok(serde_json::from_slice(&buf).ok())
}

async fn try_handle_quic(
    connection: Incoming,
    routing_table: &RoutingTable,
    voice: &VoiceRouter,
) -> eyre::Result<()> {
    let connection = connection.await?;
    let _voice_session = voice.session(&connection);
    info!(
        "QUIClime connection established to: {}",
        connection.remote_address()
    );
    let (mut send_control, mut recv_control) = connection.accept_bi().await?;
    info!("Control channel open: {}", connection.remote_address());

    let mut dialtone_ticket = None;

    let (mut handle, sender) = loop {
        if let Some(message) = read_message(&mut recv_control).await? {
            match message {
                ServerboundControlMessage::ProbeCapabilities => {
                    write_message(
                        &mut send_control,
                        &ClientboundControlMessage::HasCapabilities {
                            caps: vec!["dialtone_sidecar".to_string(), "voice".to_string()],
                            voice_port: Some(voice.port()?),
                        },
                    )
                    .await?;
                    continue;
                }
                ServerboundControlMessage::RequestDomainAssignment { key } => {
                    let handle = match routing_table.register(key.as_deref()) {
                        Ok(handle) => handle,
                        Err(e) => {
                            warn!(
                                "Domain assignment for {} refused: {:?}",
                                connection.remote_address(),
                                e
                            );
                            write_message(
                                &mut send_control,
                                &ClientboundControlMessage::DomainAssignmentFailed {
                                    reason: e.to_string(),
                                },
                            )
                            .await?;
                            send_control.finish()?;
                            _ = send_control.stopped().await;
                            connection.close(VarInt::from_u32(0), b"domain assignment failed");
                            return Ok(());
                        }
                    };
                    info!(
                        "Domain assigned to {}: {}",
                        connection.remote_address(),
                        handle.0.domain()
                    );
                    write_message(
                        &mut send_control,
                        &ClientboundControlMessage::DomainAssignmentComplete {
                            domain: handle.0.domain().to_string(),
                        },
                    )
                    .await?;
                    break handle;
                }
                ServerboundControlMessage::DialtoneRegisterTicket { ticket } => {
                    dialtone_ticket = Some(ticket);
                    write_message(
                        &mut send_control,
                        &ClientboundControlMessage::TicketRegistered,
                    )
                    .await?;
                }
                // Nothing routes here yet, so there's nothing to hand off, and no players
                // to talk.
                ServerboundControlMessage::VoiceRegisterPlayer { .. } => {}
                ServerboundControlMessage::HandingOff => {
                    write_message(&mut send_control, &ClientboundControlMessage::HandedOff).await?;
                }
            }
        }
        write_message(
            &mut send_control,
            &ClientboundControlMessage::UnknownMessage,
        )
        .await?;
    };

    tokio::select! {
        e = connection.closed() => {
            match e {
                ConnectionError::ConnectionClosed(_)
                | ConnectionError::ApplicationClosed(_)
                | ConnectionError::LocallyClosed => Ok(()),
                e => Err(e.into()),
            }
        },
        r = async {
            while let Some(remote) = handle.next().await {
                match remote {
                    routing::RouterRequest::RouteRequest(remote) => {
                        let pair = connection.open_bi().await;
                        if let Err(ConnectionError::ApplicationClosed(_)) = pair {
                            break;
                        } else if let Err(ConnectionError::ConnectionClosed(_)) = pair {
                            break;
                        }
                        remote.send(pair?).map_err(|e| eyre!("{:?}", e))?;
                    }
                    routing::RouterRequest::BroadcastRequest(message) => {
                        write_message(&mut send_control, &ClientboundControlMessage::RequestMessageBroadcast {
                                message,
                            }).await?;
                    },
                    routing::RouterRequest::ServerboundControlMessage(message) => {
                        match message {
                            ServerboundControlMessage::DialtoneRegisterTicket { ticket } => {
                                info!("registering ticket {ticket:?}");
                                dialtone_ticket = Some(ticket);
                                write_message(&mut send_control, &ClientboundControlMessage::TicketRegistered).await?;
                            },
                            ServerboundControlMessage::VoiceRegisterPlayer { uuid } => {
                                voice.register(&uuid, &connection);
                            },
                            ServerboundControlMessage::HandingOff => {
                                info!("{} is handing off", handle.domain());
                                handle.detach();
                                write_message(&mut send_control, &ClientboundControlMessage::HandedOff).await?;
                            },
                            _ => {
                                write_message(&mut send_control, &ClientboundControlMessage::UnknownMessage).await?;
                            }
                        }
                    },
                    routing::RouterRequest::TicketRequest(callback) => {
                        _ = callback.send(dialtone_ticket.clone());
                    }
                }
            }
            Ok(())
        } => r,
        r = async {
            loop {
                if let Some(message) = read_message(&mut recv_control).await? {
                    sender.send(RouterRequest::ServerboundControlMessage(message))?;
                }
            }
        } => r,
        never = voice.serve_host(&connection) => match never {}
    }
}

async fn handle_quic(connection: Incoming, routing_table: &RoutingTable, voice: &VoiceRouter) {
    if let Err(e) = try_handle_quic(connection, routing_table, voice).await {
        error!("Error handling QUIClime connection: {:#}", e);
    };
    info!("Finished handling QUIClime connection");
}

async fn listen_quic(
    endpoint: &'static Endpoint,
    routing_table: &'static RoutingTable,
    voice: &'static VoiceRouter,
) -> eyre::Result<Infallible> {
    while let Some(connection) = endpoint.accept().await {
        tokio::spawn(handle_quic(connection, routing_table, voice));
    }
    Err(eyre!("quiclime endpoint closed"))
}

async fn listen_control(
    config: &'static Config,
    endpoint: &'static Endpoint,
    routing_table: &'static RoutingTable,
    listener: TcpListener,
) -> eyre::Result<Infallible> {
    let app = axum::Router::new()
        .route(
            "/.well-known/dialtone_ticket/{domain}",
            get(async |Path(addr): Path<String>, headers: HeaderMap| {
                // The player's address, as Caddy (in front of this) appends it.
                let Some(ip) = headers
                    .get("x-forwarded-for")
                    .and_then(|value| value.to_str().ok()?.rsplit(',').next()?.trim().parse().ok())
                else {
                    return (StatusCode::BAD_REQUEST, String::new());
                };
                let Some(addr) = netty::validate_and_normalize_domain(&addr) else {
                    return (StatusCode::NOT_FOUND, String::new());
                };
                match routing_table.check_ticket(&addr, ip).await {
                    Some(ticket) => (StatusCode::OK, ticket),
                    None => (StatusCode::NOT_FOUND, String::new()),
                }
            }),
        )
        .route(
            "/metrics",
            get(async || format!("host_count {}", routing_table.size())),
        )
        .route(
            "/reload-certs",
            post(async || match create_server_config(config).await {
                Ok(config) => {
                    endpoint.set_server_config(Some(config));
                    (StatusCode::OK, "Success".to_string())
                }
                Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")),
            }),
        )
        .route(
            "/broadcast",
            post(async move |body: String| routing_table.broadcast(&body)),
        )
        .route(
            "/stop",
            post(async || endpoint.close(0u32.into(), b"e4mc closing")),
        );
    axum::serve(listener, app).await?;
    Err(eyre!("control endpoint closed"))
}

async fn try_handle_minecraft(
    mut connection: TcpStream,
    routing_table: &'static RoutingTable,
) -> eyre::Result<()> {
    let peer = connection.peer_addr()?;
    info!("Minecraft client connected from: {}", peer);
    let handshake = netty::read_packet(&mut connection, 512).await;
    if let Err(ReadError::LegacyServerListPing) = handshake {
        connection
            .write_all(include_bytes!("legacy_serverlistping_response.bin"))
            .await?;
        return Ok(());
    }
    let handshake = Handshake::new(&handshake?)?;
    let Some(address) = handshake.normalized_address() else {
        return disconnect(connection, handshake, UNKNOWN).await;
    };
    // Server-list pings don't wait for a restarting world; joining players do.
    if matches!(handshake.next_state, netty::HandshakeType::Status)
        && routing_table.is_offline_persistent(&address)
    {
        return disconnect(connection, handshake, STARTING).await;
    }
    let (mut send_host, mut recv_host) =
        match routing_table.route_limited(&address, peer.ip()).await {
            Ok(val) => val,
            Err(RoutingError::InvalidDomain) => {
                return disconnect(connection, handshake, UNKNOWN).await;
            }
            Err(RoutingError::Starting) => {
                return disconnect(connection, handshake, STARTING).await;
            }
            Err(RoutingError::RateLimited) => {
                warn!("Connection from {} has been rate limited!", peer);
                return disconnect(connection, handshake, RATE_LIMITED).await;
            }
        };
    handshake.send(&mut send_host).await?;
    let (mut recv_client, mut send_client) = connection.split();
    tokio::select! {
        _ = tokio::io::copy(&mut recv_client, &mut send_host) => (),
        _ = tokio::io::copy(&mut recv_host, &mut send_client) => ()
    }
    _ = connection.shutdown().await;
    // Reset rather than finish: the mod's QUIC library (quiche via netty) never reports a FIN
    // that arrives without data, so the host kept the player until its 30 s timeout.
    // ponytail: drops the player's last bytes if they're still in flight; they're leaving anyway.
    _ = send_host.reset(0u32.into());
    _ = recv_host.stop(0u32.into());
    info!("Minecraft client disconnected from: {}", peer);
    Ok(())
}

/// What a player is told when they can't be routed: in the server list, and on joining.
struct Refusal {
    status: &'static str,
    login: &'static str,
}

const UNKNOWN: Refusal = Refusal {
    status: include_str!("./serverlistping_response.json"),
    login: include_str!("./disconnect_response.json"),
};
const RATE_LIMITED: Refusal = Refusal {
    status: include_str!("./serverlistping_response_rate.json"),
    login: include_str!("./disconnect_response_rate.json"),
};
const STARTING: Refusal = Refusal {
    status: include_str!("./serverlistping_response_starting.json"),
    login: include_str!("./disconnect_response_starting.json"),
};

async fn disconnect(
    mut connection: TcpStream,
    handshake: Handshake,
    refusal: Refusal,
) -> eyre::Result<()> {
    match handshake.next_state {
        netty::HandshakeType::Status => {
            let packet = netty::read_packet(&mut connection, 1).await?;
            let mut packet = packet.as_slice();
            let id = packet.read_varint()?;
            if id != 0 {
                return Err(eyre!(
                    "Packet isn't a Status Request(0x00), but {:#04x}",
                    id
                ));
            }
            let mut buf = vec![];
            buf.write_varint(0).await?;
            buf.write_string(refusal.status).await?;
            connection.write_varint(buf.len() as i32).await?;
            connection.write_all(&buf).await?;
            let packet = netty::read_packet(&mut connection, 9).await?;
            let mut packet = packet.as_slice();
            let id = packet.read_varint()?;
            if id != 1 {
                return Err(eyre!("Packet isn't a Ping Request(0x01), but {:#04x}", id));
            }
            let payload = packet.read_long()?;
            let mut buf = Vec::with_capacity(1 + 8);
            buf.write_varint(1).await?;
            buf.write_u64(payload).await?;
            connection.write_varint(buf.len() as i32).await?;
            connection.write_all(&buf).await?;
        }
        netty::HandshakeType::Login | netty::HandshakeType::Transfer => {
            let _ = netty::read_packet(&mut connection, 128).await?;
            let mut buf = vec![];
            buf.write_varint(0).await?;
            buf.write_string(refusal.login).await?;
            connection.write_varint(buf.len() as i32).await?;
            connection.write_all(&buf).await?;
        }
    }
    Ok(())
}

async fn handle_minecraft(connection: TcpStream, routing_table: &'static RoutingTable) {
    if let Err(e) = try_handle_minecraft(connection, routing_table).await {
        error!("Error handling Minecraft connection: {:#}", e);
    };
}

async fn listen_minecraft(
    routing_table: &'static RoutingTable,
    server: TcpListener,
) -> eyre::Result<Infallible> {
    loop {
        match server.accept().await {
            Ok((connection, _)) => {
                tokio::spawn(handle_minecraft(connection, routing_table));
            }
            Err(e) => {
                error!("Error accepting minecraft connection: {:#}", e);
            }
        }
    }
}
