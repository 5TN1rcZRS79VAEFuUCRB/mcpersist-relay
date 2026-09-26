//! Black-box tests of the relay: a fake host over QUIC, fake players over TCP.

use std::{
    net::SocketAddr,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicI64, Ordering},
    },
    time::Duration,
};

use mcpersist_relay::{Config, EXPIRY_SECS, Relay};
use quinn::{
    Connection, Endpoint, RecvStream,
    crypto::rustls::QuicClientConfig,
    rustls::{self, RootCertStore, pki_types::CertificateDer},
};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

const BASE: &str = "relay.test";

struct TestRelay {
    quic: SocketAddr,
    mc: SocketAddr,
    web: SocketAddr,
    cert: CertificateDer<'static>,
}

/// A relay whose clock reads `now`; tests move it forward.
async fn start_relay_at(dir: &Path, now: Arc<AtomicI64>) -> TestRelay {
    start_relay_with(dir, now, "127.0.0.1:0".parse().unwrap())
        .await
        .unwrap()
}

async fn start_relay(dir: &Path) -> TestRelay {
    start_relay_at(dir, Arc::new(AtomicI64::new(1_000_000_000))).await
}

async fn start_relay_with(
    dir: &Path,
    now: Arc<AtomicI64>,
    bind_web: SocketAddr,
) -> eyre::Result<TestRelay> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    std::fs::write(dir.join("cert.pem"), cert.cert.pem()).unwrap();
    std::fs::write(dir.join("key.pem"), cert.signing_key.serialize_pem()).unwrap();
    let any = "127.0.0.1:0".parse().unwrap();
    let relay = Relay::bind(Config {
        cert_path: dir.join("cert.pem"),
        key_path: dir.join("key.pem"),
        base_domain: BASE.into(),
        db_path: dir.join("names.sqlite"),
        bind_quic: any,
        bind_web,
        bind_mc: any,
        clock: Arc::new(move || now.load(Ordering::SeqCst)),
        startup_grace: GRACE,
    })
    .await?;
    let started = TestRelay {
        quic: relay.quic_addr().unwrap(),
        mc: relay.mc_addr().unwrap(),
        web: relay.web_addr().unwrap(),
        cert: cert.cert.der().clone(),
    };
    tokio::spawn(relay.serve());
    Ok(started)
}

/// Connects as a host and requests a domain; returns the connection and the reply.
async fn host(relay: &TestRelay, key: Option<&str>) -> (Connection, Value) {
    let (conn, reply, send, recv) = host_with_control(relay, key).await;
    // Keep the control stream open for the life of the connection.
    std::mem::forget((send, recv));
    (conn, reply)
}

/// A host session plus its control stream, for sending further control messages.
async fn host_with_control(
    relay: &TestRelay,
    key: Option<&str>,
) -> (Connection, Value, quinn::SendStream, RecvStream) {
    let mut roots = RootCertStore::empty();
    roots.add(relay.cert.clone()).unwrap();
    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"quiclime".to_vec()];
    let mut endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(tls).unwrap(),
    )));
    let conn = endpoint
        .connect(relay.quic, "localhost")
        .unwrap()
        .await
        .unwrap();
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let mut request = json!({"kind": "request_domain_assignment"});
    if let Some(key) = key {
        request["key"] = key.into();
    }
    let request = serde_json::to_vec(&request).unwrap();
    send.write_all(&varint(request.len() as i32)).await.unwrap();
    send.write_all(&request).await.unwrap();
    let reply = read_control(&mut recv).await;
    (conn, reply, send, recv)
}

async fn send_control(send: &mut quinn::SendStream, message: Value) {
    let message = serde_json::to_vec(&message).unwrap();
    send.write_all(&varint(message.len() as i32)).await.unwrap();
    send.write_all(&message).await.unwrap();
}

async fn read_control(recv: &mut RecvStream) -> Value {
    let len = recv.read_u8().await.unwrap();
    let mut reply = vec![0; len as usize];
    recv.read_exact(&mut reply).await.unwrap();
    serde_json::from_slice(&reply).unwrap()
}

fn domain(reply: &Value) -> String {
    assert_eq!(reply["kind"], "domain_assignment_complete", "{reply}");
    reply["domain"].as_str().unwrap().to_string()
}

/// Closes a host session and waits until the relay has released its name.
async fn close(relay: &TestRelay, conn: Connection, key: &str) -> String {
    conn.close(0u32.into(), b"bye");
    for _ in 0..50 {
        let (conn, reply) = host(relay, Some(key)).await;
        if reply["kind"] == "domain_assignment_complete" {
            conn.close(0u32.into(), b"bye");
            tokio::time::sleep(Duration::from_millis(100)).await;
            return domain(&reply);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("relay never released the name");
}

fn varint(mut v: i32) -> Vec<u8> {
    let mut out = vec![];
    loop {
        if v & !0x7F == 0 {
            out.push(v as u8);
            return out;
        }
        out.push((v & 0x7F | 0x80) as u8);
        v = ((v as u32) >> 7) as i32;
    }
}

fn handshake(domain: &str, next_state: i32) -> Vec<u8> {
    let mut body = varint(0);
    body.extend(varint(772));
    body.extend(varint(domain.len() as i32));
    body.extend(domain.as_bytes());
    body.extend(25565u16.to_be_bytes());
    body.extend(varint(next_state));
    let mut packet = varint(body.len() as i32);
    packet.extend(body);
    packet
}

/// Reads one length-prefixed packet, as the host sees it.
async fn read_packet(recv: &mut RecvStream) -> Vec<u8> {
    let mut len = 0i32;
    for shift in (0..35).step_by(7) {
        let b = recv.read_u8().await.unwrap();
        len |= i32::from(b & 0x7F) << shift;
        if b & 0x80 == 0 {
            break;
        }
    }
    let mut buf = vec![0; len as usize];
    recv.read_exact(&mut buf).await.unwrap();
    buf
}

/// The relay-opened stream carrying one player; fails instead of hanging.
async fn accept(conn: &Connection) -> (quinn::SendStream, RecvStream) {
    tokio::time::timeout(Duration::from_secs(5), conn.accept_bi())
        .await
        .expect("relay never forwarded the player")
        .unwrap()
}

const GRACE: Duration = Duration::from_secs(2);

/// Reads the relay's refusal: a login Disconnect, or a status response.
async fn read_refusal(player: &mut TcpStream) -> String {
    let mut len = 0i32;
    for shift in (0..35).step_by(7) {
        let b = player.read_u8().await.unwrap();
        len |= i32::from(b & 0x7F) << shift;
        if b & 0x80 == 0 {
            break;
        }
    }
    let mut buf = vec![0; len as usize];
    player.read_exact(&mut buf).await.unwrap();
    String::from_utf8_lossy(&buf).into_owned()
}

/// A login start packet; the relay reads (and discards) it before refusing.
fn login_start() -> Vec<u8> {
    let mut body = varint(0);
    body.extend(varint(5));
    body.extend(b"Steve");
    body.extend([0; 16]);
    let mut packet = varint(body.len() as i32);
    packet.extend(body);
    packet
}

fn status_request() -> Vec<u8> {
    vec![1, 0]
}

const KEY_A: &str = "world-key-aaaaaaaaaaaaaaaaaaaaaaaa";
const KEY_B: &str = "world-key-bbbbbbbbbbbbbbbbbbbbbbbb";

#[tokio::test]
async fn same_key_gets_same_name_across_reconnects_and_restarts() {
    let dir = tempfile::tempdir().unwrap();
    let relay = start_relay(dir.path()).await;
    let (conn, reply) = host(&relay, Some(KEY_A)).await;
    let name = domain(&reply);
    assert!(name.ends_with(&format!(".{BASE}")), "{name}");
    assert_eq!(close(&relay, conn, KEY_A).await, name);

    let restarted = start_relay(dir.path()).await;
    let (_conn, reply) = host(&restarted, Some(KEY_A)).await;
    assert_eq!(domain(&reply), name);
}

#[tokio::test]
async fn different_keys_and_keyless_hosts_get_different_names() {
    let dir = tempfile::tempdir().unwrap();
    let relay = start_relay(dir.path()).await;
    let (_a, a) = host(&relay, Some(KEY_A)).await;
    let (_b, b) = host(&relay, Some(KEY_B)).await;
    let (_c, c) = host(&relay, None).await;
    let names = [domain(&a), domain(&b), domain(&c)];
    assert_ne!(names[0], names[1]);
    assert_ne!(names[0], names[2]);
    assert_ne!(names[1], names[2]);
}

#[tokio::test]
async fn second_live_session_for_a_name_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let relay = start_relay(dir.path()).await;
    let (_first, reply) = host(&relay, Some(KEY_A)).await;
    domain(&reply);
    let (_second, reply) = host(&relay, Some(KEY_A)).await;
    assert_eq!(reply["kind"], "domain_assignment_failed");
    assert_eq!(reply["reason"], "name_in_use");
}

#[tokio::test]
async fn malformed_key_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let relay = start_relay(dir.path()).await;
    let (_conn, reply) = host(&relay, Some("short")).await;
    assert_eq!(reply["kind"], "domain_assignment_failed");
    assert_eq!(reply["reason"], "invalid_key");
}

#[tokio::test]
async fn player_bytes_flow_both_ways_through_a_stable_name() {
    let dir = tempfile::tempdir().unwrap();
    let relay = start_relay(dir.path()).await;
    let (conn, reply) = host(&relay, Some(KEY_A)).await;
    let name = domain(&reply);

    let mut player = TcpStream::connect(relay.mc).await.unwrap();
    player.write_all(&handshake(&name, 2)).await.unwrap();
    player.write_all(b"ping").await.unwrap();

    let (mut to_player, mut from_player) = accept(&conn).await;
    let forwarded = read_packet(&mut from_player).await;
    assert_eq!(forwarded, handshake(&name, 2)[1..]);
    let mut got = [0; 4];
    from_player.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"ping");

    to_player.write_all(b"pong").await.unwrap();
    player.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"pong");
}

#[tokio::test]
async fn a_player_leaving_resets_the_hosts_stream() {
    let dir = tempfile::tempdir().unwrap();
    let relay = start_relay(dir.path()).await;
    let (conn, reply) = host(&relay, Some(KEY_A)).await;
    let name = domain(&reply);

    let mut player = TcpStream::connect(relay.mc).await.unwrap();
    player.write_all(&handshake(&name, 2)).await.unwrap();
    let (_to_player, mut from_player) = accept(&conn).await;
    read_packet(&mut from_player).await;
    drop(player);

    // A reset, not a FIN: the mod's QUIC library never notices a FIN that arrives without data.
    let read = tokio::time::timeout(Duration::from_secs(5), from_player.read_to_end(1024)).await;
    assert!(matches!(read, Ok(Err(_))), "expected the stream to be reset, got {read:?}");
}

#[tokio::test]
async fn control_endpoint_serves_metrics() {
    let dir = tempfile::tempdir().unwrap();
    let relay = start_relay(dir.path()).await;
    let (_conn, _) = host(&relay, Some(KEY_A)).await;
    let mut http = TcpStream::connect(relay.web).await.unwrap();
    http.write_all(b"GET /metrics HTTP/1.0\r\n\r\n").await.unwrap();
    let mut body = String::new();
    http.read_to_string(&mut body).await.unwrap();
    assert!(body.ends_with("host_count 1"), "{body}");
}

#[tokio::test]
async fn transfer_handshake_is_routed_to_the_host() {
    let dir = tempfile::tempdir().unwrap();
    let relay = start_relay(dir.path()).await;
    let (conn, reply) = host(&relay, Some(KEY_A)).await;
    let name = domain(&reply);

    let mut player = TcpStream::connect(relay.mc).await.unwrap();
    player.write_all(&handshake(&name, 3)).await.unwrap();

    let (_to_player, mut from_player) = accept(&conn).await;
    assert_eq!(read_packet(&mut from_player).await, handshake(&name, 3)[1..]);
}

const DAY: i64 = 24 * 60 * 60;

#[tokio::test]
async fn names_unused_for_90_days_are_freed() {
    let dir = tempfile::tempdir().unwrap();
    let now = Arc::new(AtomicI64::new(1_000_000_000));
    let relay = start_relay_at(dir.path(), now.clone()).await;
    let (conn, reply) = host(&relay, Some(KEY_A)).await;
    let name = domain(&reply);
    close(&relay, conn, KEY_A).await;

    now.fetch_add(EXPIRY_SECS - DAY, Ordering::SeqCst);
    let (conn, reply) = host(&relay, Some(KEY_A)).await;
    assert_eq!(domain(&reply), name, "freed before 90 days");
    close(&relay, conn, KEY_A).await;

    now.fetch_add(EXPIRY_SECS + DAY, Ordering::SeqCst);
    let (_conn, reply) = host(&relay, Some(KEY_A)).await;
    assert_ne!(domain(&reply), name, "not freed after 90 days");
}

#[tokio::test]
async fn a_name_in_use_is_never_freed() {
    let dir = tempfile::tempdir().unwrap();
    let now = Arc::new(AtomicI64::new(1_000_000_000));
    let relay = start_relay_at(dir.path(), now.clone()).await;
    let (_online_for_months, reply) = host(&relay, Some(KEY_A)).await;
    domain(&reply);

    now.fetch_add(EXPIRY_SECS + DAY, Ordering::SeqCst);
    // Any registration runs expiry.
    let (_b, reply) = host(&relay, Some(KEY_B)).await;
    domain(&reply);
    let (_second, reply) = host(&relay, Some(KEY_A)).await;
    assert_eq!(reply["reason"], "name_in_use");
}

#[tokio::test]
async fn control_endpoints_refuse_a_public_bind_address() {
    let dir = tempfile::tempdir().unwrap();
    let result = start_relay_with(
        dir.path(),
        Arc::new(AtomicI64::new(0)),
        "0.0.0.0:0".parse().unwrap(),
    )
    .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn joining_player_waits_for_a_restarting_persistent_world() {
    let dir = tempfile::tempdir().unwrap();
    let relay = start_relay(dir.path()).await;
    let (conn, reply) = host(&relay, Some(KEY_A)).await;
    let name = domain(&reply);
    close(&relay, conn, KEY_A).await;

    // Transferred as the host leaves, before the background server is up.
    let mut player = TcpStream::connect(relay.mc).await.unwrap();
    player.write_all(&handshake(&name, 3)).await.unwrap();
    player.write_all(b"ping").await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;

    let (conn, reply) = host(&relay, Some(KEY_A)).await;
    assert_eq!(domain(&reply), name);
    let (mut to_player, mut from_player) = accept(&conn).await;
    assert_eq!(read_packet(&mut from_player).await, handshake(&name, 3)[1..]);
    let mut got = [0; 4];
    from_player.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"ping");
    to_player.write_all(b"pong").await.unwrap();
    player.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"pong");
}

#[tokio::test]
async fn player_is_told_a_world_is_starting_if_it_does_not_come_back() {
    let dir = tempfile::tempdir().unwrap();
    let relay = start_relay(dir.path()).await;
    let (conn, reply) = host(&relay, Some(KEY_A)).await;
    let name = domain(&reply);
    close(&relay, conn, KEY_A).await;

    let started = tokio::time::Instant::now();
    let mut player = TcpStream::connect(relay.mc).await.unwrap();
    player.write_all(&handshake(&name, 2)).await.unwrap();
    player.write_all(&login_start()).await.unwrap();
    let refusal = read_refusal(&mut player).await;
    assert!(refusal.contains("starting up"), "{refusal}");
    assert!(started.elapsed() >= GRACE, "didn't wait for the world");
}

#[tokio::test]
async fn server_list_ping_for_a_restarting_world_answers_at_once() {
    let dir = tempfile::tempdir().unwrap();
    let relay = start_relay(dir.path()).await;
    let (conn, reply) = host(&relay, Some(KEY_A)).await;
    let name = domain(&reply);
    close(&relay, conn, KEY_A).await;

    let started = tokio::time::Instant::now();
    let mut player = TcpStream::connect(relay.mc).await.unwrap();
    player.write_all(&handshake(&name, 1)).await.unwrap();
    player.write_all(&status_request()).await.unwrap();
    let status = read_refusal(&mut player).await;
    assert!(status.contains("starting up"), "{status}");
    assert!(started.elapsed() < GRACE);
}

#[tokio::test]
async fn unknown_names_are_refused_at_once() {
    let dir = tempfile::tempdir().unwrap();
    let relay = start_relay(dir.path()).await;
    let started = tokio::time::Instant::now();
    let mut player = TcpStream::connect(relay.mc).await.unwrap();
    player.write_all(&handshake(&format!("nobody-here.{BASE}"), 2)).await.unwrap();
    player.write_all(&login_start()).await.unwrap();
    let refusal = read_refusal(&mut player).await;
    assert!(refusal.contains("Unknown server"), "{refusal}");
    assert!(started.elapsed() < GRACE);
}

#[tokio::test]
async fn a_host_handing_off_gets_no_new_players_but_keeps_its_own() {
    let dir = tempfile::tempdir().unwrap();
    let relay = start_relay(dir.path()).await;
    let (old, reply, mut control, mut replies) = host_with_control(&relay, Some(KEY_A)).await;
    let name = domain(&reply);
    let mut staying = TcpStream::connect(relay.mc).await.unwrap();
    staying.write_all(&handshake(&name, 2)).await.unwrap();
    let (mut to_staying, mut from_staying) = accept(&old).await;
    assert_eq!(read_packet(&mut from_staying).await, handshake(&name, 2)[1..]);

    send_control(&mut control, json!({"kind": "handing_off"})).await;
    let ack = tokio::time::timeout(Duration::from_secs(5), read_control(&mut replies))
        .await
        .expect("no reply to handing_off");
    assert_eq!(ack["kind"], "handed_off", "{ack}");

    // A player transferred now waits for the background server, not the leaving host.
    let mut moved = TcpStream::connect(relay.mc).await.unwrap();
    moved.write_all(&handshake(&name, 3)).await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    let (new, reply) = host(&relay, Some(KEY_A)).await;
    assert_eq!(domain(&reply), name);
    let (_to_moved, mut from_moved) = accept(&new).await;
    assert_eq!(read_packet(&mut from_moved).await, handshake(&name, 3)[1..]);

    // Players still on the leaving host keep their connection.
    to_staying.write_all(b"pong").await.unwrap();
    let mut got = [0; 4];
    staying.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"pong");

    // The leaving host closing doesn't take the name from the background server.
    old.close(0u32.into(), b"bye");
    tokio::time::sleep(Duration::from_millis(300)).await;
    let (_again, reply) = host(&relay, Some(KEY_A)).await;
    assert_eq!(reply["kind"], "domain_assignment_failed", "{reply}");
    assert_eq!(reply["reason"], "name_in_use");
}
