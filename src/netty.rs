#![allow(clippy::cast_sign_loss)]

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use log::error;

#[derive(Debug)]
pub enum ReadError {
    IoError(std::io::Error),
    LegacyServerListPing,
    PacketTooLarge,
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IoError(e) => write!(f, "{e}"),
            Self::LegacyServerListPing => f.write_str("Was not a netty packet, but a Legacy ServerListPing"),
            Self::PacketTooLarge => f.write_str("Packet was too large"),
        }
    }
}

impl std::error::Error for ReadError {}

impl From<std::io::Error> for ReadError {
    fn from(value: std::io::Error) -> Self {
        Self::IoError(value)
    }
}

impl From<std::io::ErrorKind> for ReadError {
    fn from(value: std::io::ErrorKind) -> Self {
        Self::IoError(value.into())
    }
}

pub async fn read_packet(
    mut reader: impl AsyncReadExt + Unpin,
    max_size: usize,
) -> Result<Vec<u8>, ReadError> {
    let len = read_varint(&mut reader).await?;
    let mut first = [0u8];
    if len == 254 {
        // FE 01 FA: a Legacy ServerListPing reads as a 254-byte packet starting 0xFA.
        reader.read_exact(&mut first).await?;
        if first[0] == 0xFA {
            return Err(ReadError::LegacyServerListPing);
        }
    }
    if len < 0 || (len as usize) > max_size {
        return Err(ReadError::PacketTooLarge);
    }
    let mut buf = vec![0u8; len as usize];
    if len == 254 {
        buf[0] = first[0];
        reader.read_exact(&mut buf[1..]).await?;
    } else {
        reader.read_exact(&mut buf).await?;
    }
    Ok(buf)
}

pub async fn read_varint(mut reader: impl AsyncReadExt + Unpin) -> Result<i32, ReadError> {
    let mut res = 0i32;
    for i in 0..5 {
        let part = reader.read_u8().await?;
        res |= (i32::from(part) & 0x7F) << (7 * i);
        if part & 0x80 == 0 {
            return Ok(res);
        }
    }
    error!("Varint is invalid");
    Err(std::io::ErrorKind::InvalidData.into())
}

async fn read_string(mut reader: impl AsyncReadExt + Unpin) -> Result<String, ReadError> {
    let len = read_varint(&mut reader).await?;
    let mut buf = vec![0u8; len as usize];
    reader.read_exact(&mut buf).await?;
    String::from_utf8(buf).map_err(|_| std::io::ErrorKind::InvalidData.into())
}

pub trait WriteExt: AsyncWriteExt + Unpin {
    async fn write_varint(&mut self, mut val: i32) -> std::io::Result<()> {
        for _ in 0..5 {
            if val & !0x7F == 0 {
                self.write_all(&[val as u8]).await?;
                return Ok(());
            }
            self.write_all(&[(val & 0x7F | 0x80) as u8]).await?;
            val >>= 7;
        }
        Err(std::io::ErrorKind::InvalidData.into())
    }

    async fn write_string(&mut self, s: &str) -> std::io::Result<()> {
        self.write_varint(s.len() as i32).await?;
        self.write_all(s.as_bytes()).await?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct Handshake {
    protocol_version: i32,
    server_address: String,
    server_port: u16,
    pub next_state: HandshakeType,
}

#[derive(Debug, Clone, Copy)]
#[repr(i32)]
pub enum HandshakeType {
    Status = 1,
    Login = 2,
    /// Sent by a client following a server's Transfer packet (1.20.5+); proceeds like Login.
    Transfer = 3,
}

impl Handshake {
    pub async fn new(mut packet: &[u8]) -> eyre::Result<Self> {
        if read_varint(&mut packet).await? != 0 {
            return Err(eyre::eyre!("Not a Handshake packet"));
        }
        let protocol_version = read_varint(&mut packet).await?;
        let server_address = read_string(&mut packet).await?;
        let server_port = packet.read_u16().await?;
        let next_state = match read_varint(&mut packet).await? {
            1 => HandshakeType::Status,
            2 => HandshakeType::Login,
            3 => HandshakeType::Transfer,
            _ => return Err(eyre::eyre!("Invalid next state")),
        };
        Ok(Self {
            protocol_version,
            server_address,
            server_port,
            next_state,
        })
    }

    pub async fn send(
        &self,
        mut writer: impl AsyncWriteExt + Unpin + Send,
    ) -> tokio::io::Result<()> {
        let mut buf = vec![];
        buf.write_varint(0).await?;
        buf.write_varint(self.protocol_version).await?;
        buf.write_string(&self.server_address).await?;
        buf.write_all(&self.server_port.to_be_bytes()).await?;
        buf.write_varint(self.next_state as i32).await?;
        writer.write_varint(buf.len() as i32).await?;
        writer.write_all(&buf).await?;
        Ok(())
    }

    pub fn normalized_address(&self) -> Option<String> {
        validate_and_normalize_domain(
            // yes, Forge has three different suffixes that they attach to the server address
            ["\0FML3\0", "\0FML2\0", "\0FML\0"]
                .iter()
                .find_map(|suffix| self.server_address.strip_suffix(suffix))
                .unwrap_or(&self.server_address),
        )
    }
}

impl<T: AsyncWriteExt + Unpin> WriteExt for T {}

pub(crate) fn validate_and_normalize_domain(domain: &str) -> Option<String> {
    // yes, this madness is how you actually validate domains
    // https://url.spec.whatwg.org/#host-writing
    // I don't do any more normalisation because domain_to_ascii already does nameprep
    let domain = idna::domain_to_ascii_strict(domain).ok()?;
    let (domain, err) = idna::domain_to_unicode(&domain);
    if err.is_err() { None } else { Some(domain) }
}
