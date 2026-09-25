//! Black-box tests of the relay: a fake host over QUIC, fake players over TCP.

use std::{net::SocketAddr, path::Path, sync::Arc, time::Duration};

use mcpersist_relay::{Config, Relay};
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

async fn start_relay(dir: &Path) -> TestRelay {
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
        bind_web: any,
        bind_mc: any,
    })
    .await
    .unwrap();
    let started = TestRelay {
        quic: relay.quic_addr().unwrap(),
        mc: relay.mc_addr().unwrap(),
        web: relay.web_addr().unwrap(),
        cert: cert.cert.der().clone(),
    };
    tokio::spawn(relay.serve());
    started
}

/// Connects as a host and requests a domain; returns the connection and the reply.
async fn host(relay: &TestRelay, key: Option<&str>) -> (Connection, Value) {
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
    let len = recv.read_u8().await.unwrap();
    let mut reply = vec![0; len as usize];
    recv.read_exact(&mut reply).await.unwrap();
    // Keep the control stream open for the life of the connection.
    std::mem::forget((send, recv));
    (conn, serde_json::from_slice(&reply).unwrap())
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

    let (mut to_player, mut from_player) = conn.accept_bi().await.unwrap();
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
