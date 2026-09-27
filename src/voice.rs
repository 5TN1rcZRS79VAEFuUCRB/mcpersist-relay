//! Simple Voice Chat traffic. Players send UDP to one shared port; each packet starts with
//! its player's UUID in the clear, and goes to the host that registered that player as a
//! QUIC datagram. The host's replies come back as datagrams naming the player's address.
//!
//! A datagram between the relay and a host is the player's address (16-byte IPv6, IPv4
//! mapped, then a 2-byte port) followed by the voice packet.

use std::{
    collections::HashMap,
    convert::Infallible,
    net::{IpAddr, Ipv6Addr, SocketAddr},
};

use bytes::Bytes;
use log::debug;
use parking_lot::Mutex;
use quinn::Connection;
use tokio::net::UdpSocket;

const MAGIC: u8 = 0xFF;
const ADDR_LEN: usize = 18;

pub struct VoiceRouter {
    socket: UdpSocket,
    /// Which host each player's voice goes to, by UUID.
    players: Mutex<HashMap<[u8; 16], Connection>>,
    /// Which host each player address belongs to, so a host only ever sends to its own
    /// players and can't make the relay send UDP anywhere else.
    clients: Mutex<HashMap<SocketAddr, usize>>,
}

impl VoiceRouter {
    pub async fn bind(addr: SocketAddr) -> std::io::Result<Self> {
        Ok(Self {
            socket: UdpSocket::bind(addr).await?,
            players: Mutex::default(),
            clients: Mutex::default(),
        })
    }

    pub fn port(&self) -> std::io::Result<u16> {
        Ok(self.socket.local_addr()?.port())
    }

    /// Voice for `uuid` goes to `host` from now on (the newest host wins, as after a handoff).
    pub fn register(&self, uuid: &str, host: &Connection) {
        if let Some(uuid) = parse_uuid(uuid) {
            self.players.lock().insert(uuid, host.clone());
        }
    }

    /// Stops routing to `host`; the returned guard does this when the host's session ends.
    pub fn session(&self, host: &Connection) -> Session<'_> {
        Session {
            router: self,
            host: host.stable_id(),
        }
    }

    /// Players to hosts.
    pub async fn listen(&self) -> std::io::Result<()> {
        let mut buf = vec![0u8; 65536];
        loop {
            let (len, from) = self.socket.recv_from(&mut buf).await?;
            let packet = &buf[..len];
            if len < 17 || packet[0] != MAGIC {
                continue;
            }
            let uuid: [u8; 16] = packet[1..17].try_into().unwrap();
            let Some(host) = self.players.lock().get(&uuid).cloned() else {
                continue;
            };
            self.clients.lock().insert(from, host.stable_id());
            let mut datagram = Vec::with_capacity(ADDR_LEN + len);
            datagram.extend_from_slice(&encode_addr(from));
            datagram.extend_from_slice(packet);
            if let Err(e) = host.send_datagram(Bytes::from(datagram)) {
                debug!("Dropped voice packet for {from}: {e}");
            }
        }
    }

    /// Hosts to players. Never returns: when the host's connection ends, its session does.
    pub async fn serve_host(&self, host: &Connection) -> Infallible {
        while let Ok(datagram) = host.read_datagram().await {
            if datagram.len() <= ADDR_LEN {
                continue;
            }
            let to = decode_addr(datagram[..ADDR_LEN].try_into().unwrap());
            if self.clients.lock().get(&to) != Some(&host.stable_id()) {
                continue;
            }
            if let Err(e) = self.socket.send_to(&datagram[ADDR_LEN..], to).await {
                debug!("Failed to send voice to {to}: {e}");
            }
        }
        std::future::pending().await
    }
}

pub struct Session<'a> {
    router: &'a VoiceRouter,
    host: usize,
}

impl Drop for Session<'_> {
    fn drop(&mut self) {
        self.router
            .players
            .lock()
            .retain(|_, host| host.stable_id() != self.host);
        self.router.clients.lock().retain(|_, host| *host != self.host);
    }
}

fn parse_uuid(uuid: &str) -> Option<[u8; 16]> {
    let hex: String = uuid.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(hex.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(bytes)
}

fn encode_addr(addr: SocketAddr) -> [u8; ADDR_LEN] {
    let ip = match addr.ip() {
        IpAddr::V4(ip) => ip.to_ipv6_mapped(),
        IpAddr::V6(ip) => ip,
    };
    let mut out = [0u8; ADDR_LEN];
    out[..16].copy_from_slice(&ip.octets());
    out[16..].copy_from_slice(&addr.port().to_be_bytes());
    out
}

fn decode_addr(bytes: [u8; ADDR_LEN]) -> SocketAddr {
    let ip = Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[..16]).unwrap());
    let port = u16::from_be_bytes([bytes[16], bytes[17]]);
    let ip = ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4);
    SocketAddr::new(ip, port)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_round_trip() {
        for addr in ["203.0.113.7:24454", "[2001:db8::1]:61000"] {
            let addr: SocketAddr = addr.parse().unwrap();
            assert_eq!(decode_addr(encode_addr(addr)), addr);
        }
    }

    #[test]
    fn uuids_parse_with_or_without_dashes() {
        let with = parse_uuid("0f3d2c1b-aaaa-4bbb-8ccc-0123456789ab").unwrap();
        assert_eq!(with, parse_uuid("0f3d2c1baaaa4bbb8ccc0123456789ab").unwrap());
        assert_eq!(with[0], 0x0f);
        assert!(parse_uuid("not-a-uuid").is_none());
    }
}
