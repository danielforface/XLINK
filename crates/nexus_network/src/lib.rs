use anyhow::{anyhow, bail, Context, Result};
use quinn::{ClientConfig, Connection, Endpoint, ServerConfig, TransportConfig};
use rcgen::generate_simple_self_signed;
use rustls::client::{ServerCertVerified, ServerCertVerifier};
use rustls::{Certificate, PrivateKey, ServerName};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tracing::info;

const SHA256_LEN_BYTES: usize = 32;
const MIN_FINGERPRINT_BYTES: usize = 16;

#[derive(Debug)]
pub struct ServerEndpoint {
    endpoint: Endpoint,
    pub certificate_der: Vec<u8>,
    pub certificate_key: Vec<u8>,
    pub certificate_fingerprint: String,
}

impl ServerEndpoint {
    pub async fn accept(&self) -> Result<Connection> {
        let incoming = self
            .endpoint
            .accept()
            .await
            .context("server endpoint closed before any incoming connection")?;
        let connection = incoming
            .await
            .context("failed to complete QUIC handshake")?;
        info!(remote = %connection.remote_address(), "accepted QUIC connection");
        Ok(connection)
    }
}

#[derive(Debug)]
pub struct ClientEndpoint {
    endpoint: Endpoint,
}

impl ClientEndpoint {
    pub async fn connect(&self, remote: SocketAddr, server_name: &str) -> Result<Connection> {
        let connection = self
            .endpoint
            .connect(remote, server_name)
            .context("failed to start QUIC connection")?
            .await
            .context("failed to establish QUIC connection")?;
        info!(remote = %connection.remote_address(), "connected to QUIC server");
        Ok(connection)
    }
}

pub async fn bind_server(socket: std::net::UdpSocket) -> Result<(ServerEndpoint, std::net::UdpSocket)> {
    let (server_config, certificate_der, certificate_key) = build_server_config()?;
    let socket_clone = socket.try_clone().context("failed to clone server UDP socket")?;

    let endpoint = Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(server_config),
        socket,
        Arc::new(quinn::TokioRuntime),
    ).context("failed to create server QUIC endpoint")?;
    let certificate_fingerprint = sha256_hex(&certificate_der);

    Ok((
        ServerEndpoint {
            endpoint,
            certificate_der,
            certificate_key,
            certificate_fingerprint,
        },
        socket_clone,
    ))
}

pub async fn bind_client(bind_addr: SocketAddr, expected_fingerprint: String) -> Result<(ClientEndpoint, std::net::UdpSocket)> {
    let socket = std::net::UdpSocket::bind(bind_addr).context("failed to bind UDP socket for client")?;
    let socket_clone = socket.try_clone().context("failed to clone client UDP socket")?;

    let mut endpoint = Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        socket,
        Arc::new(quinn::TokioRuntime),
    ).context("failed to create client QUIC endpoint")?;
    endpoint.set_default_client_config(build_pinned_client_config(expected_fingerprint)?);

    Ok((
        ClientEndpoint { endpoint },
        socket_clone,
    ))
}

pub fn normalize_fingerprint_hex(input: &str) -> Result<String> {
    let bytes = parse_fingerprint_hex(input)?;
    Ok(hex::encode(bytes))
}

pub fn build_server_config() -> Result<(ServerConfig, Vec<u8>, Vec<u8>)> {
    let certificate = generate_simple_self_signed(vec!["localhost".to_string()])
        .context("failed to generate self-signed certificate")?;
    let certificate_der = certificate
        .serialize_der()
        .context("failed to serialize certificate")?;
    let private_key_der = certificate.serialize_private_key_der();

    let mut server_config = ServerConfig::with_single_cert(
        vec![Certificate(certificate_der.clone())],
        PrivateKey(private_key_der.clone()),
    )
    .context("failed to assemble QUIC server config")?;

    let transport = Arc::get_mut(&mut server_config.transport)
        .context("failed to access QUIC server transport configuration")?;
    transport.max_concurrent_uni_streams(8_u32.into());
    transport.max_concurrent_bidi_streams(8_u32.into());
    transport.keep_alive_interval(Some(Duration::from_secs(3)));

    Ok((server_config, certificate_der, private_key_der))
}

pub fn build_pinned_client_config(expected_fingerprint: String) -> Result<ClientConfig> {
    let expected = parse_fingerprint_hex(&expected_fingerprint)?;
    let expected_hex = hex::encode(&expected);

    let crypto = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(Arc::new(FingerprintVerifier {
            expected_prefix: expected,
            expected_hex,
        }))
        .with_no_client_auth();
    let mut client_config = ClientConfig::new(Arc::new(crypto));

    let mut transport = TransportConfig::default();
    transport.max_concurrent_uni_streams(8_u32.into());
    transport.max_concurrent_bidi_streams(8_u32.into());
    transport.keep_alive_interval(Some(Duration::from_secs(3)));
    client_config.transport_config(Arc::new(transport));

    Ok(client_config)
}

pub fn build_rustls_server_config() -> Result<(rustls::ServerConfig, Vec<u8>)> {
    let certificate = generate_simple_self_signed(vec!["localhost".to_string()])
        .context("failed to generate self-signed certificate")?;
    let certificate_der = certificate
        .serialize_der()
        .context("failed to serialize certificate")?;
    let private_key_der = certificate.serialize_private_key_der();

    let server_config = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(
            vec![Certificate(certificate_der.clone())],
            PrivateKey(private_key_der),
        )
        .context("failed to assemble rustls server config")?;
    Ok((server_config, certificate_der))
}

pub fn build_pinned_rustls_client_config(expected_fingerprint: String) -> Result<rustls::ClientConfig> {
    let expected = parse_fingerprint_hex(&expected_fingerprint)?;
    let expected_hex = hex::encode(&expected);

    let crypto = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(Arc::new(FingerprintVerifier {
            expected_prefix: expected,
            expected_hex,
        }))
        .with_no_client_auth();
    Ok(crypto)
}

#[derive(Debug)]
struct FingerprintVerifier {
    expected_prefix: Vec<u8>,
    expected_hex: String,
}

impl ServerCertVerifier for FingerprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: SystemTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let actual = Sha256::digest(&end_entity.0);
        if actual.as_slice().starts_with(self.expected_prefix.as_slice()) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "certificate fingerprint mismatch: expected prefix {}, got {}",
                self.expected_hex,
                hex::encode(actual)
            )))
        }
    }
}

fn parse_fingerprint_hex(input: &str) -> Result<Vec<u8>> {
    let normalized: String = input
        .chars()
        .filter(|ch| ch.is_ascii_hexdigit())
        .map(|ch| ch.to_ascii_lowercase())
        .collect();

    if normalized.len() % 2 != 0 {
        bail!(
            "fingerprint hex length must be even, got {}",
            normalized.len()
        );
    }

    let min_hex_len = MIN_FINGERPRINT_BYTES * 2;
    let max_hex_len = SHA256_LEN_BYTES * 2;
    if normalized.len() < min_hex_len || normalized.len() > max_hex_len {
        bail!(
            "expected between {} and {} hex characters for fingerprint pinning, got {}",
            min_hex_len,
            max_hex_len,
            normalized.len()
        );
    }

    let bytes = hex::decode(&normalized)
        .with_context(|| format!("failed to decode fingerprint: {normalized}"))?;
    if bytes.len() < MIN_FINGERPRINT_BYTES || bytes.len() > SHA256_LEN_BYTES {
        return Err(anyhow!(
            "decoded fingerprint byte length was {}, expected {}..={}",
            bytes.len(),
            MIN_FINGERPRINT_BYTES,
            SHA256_LEN_BYTES
        ));
    }

    Ok(bytes)
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum NetworkTopology {
    #[default]
    Undetermined,
    OpenInternet,
    ConeNatFriendly,
    SymmetricNatRestrictive,
    UdpBlockedStrict,
}

pub fn parse_stun_mapped_address(buf: &[u8]) -> Option<SocketAddr> {
    let response_len = buf.len();
    let mut offset = 20;
    while offset + 4 <= response_len {
        let attr_type = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        let attr_len = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]) as usize;
        offset += 4;
        if offset + attr_len > response_len {
            break;
        }
        let attr_val = &buf[offset..offset + attr_len];

        if attr_type == 0x0020 { // XOR-MAPPED-ADDRESS
            if attr_len >= 8 {
                let family = attr_val[1];
                if family == 0x01 { // IPv4
                    let x_port = u16::from_be_bytes([attr_val[2], attr_val[3]]);
                    let port = x_port ^ 0x2112;
                    let mut ip_bytes = [0u8; 4];
                    ip_bytes.copy_from_slice(&attr_val[4..8]);
                    let ip_u32 = u32::from_be_bytes(ip_bytes) ^ 0x2112A442;
                    let ip = IpAddr::V4(Ipv4Addr::from(ip_u32));
                    return Some(SocketAddr::new(ip, port));
                }
            }
        } else if attr_type == 0x0001 { // MAPPED-ADDRESS
            if attr_len >= 8 {
                let family = attr_val[1];
                if family == 0x01 { // IPv4
                    let port = u16::from_be_bytes([attr_val[2], attr_val[3]]);
                    let ip = IpAddr::V4(Ipv4Addr::new(attr_val[4], attr_val[5], attr_val[6], attr_val[7]));
                    return Some(SocketAddr::new(ip, port));
                }
            }
        }

        offset += (attr_len + 3) & !3;
    }
    None
}

pub fn detect_local_ip() -> Option<IpAddr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    Some(socket.local_addr().ok()?.ip())
}

pub async fn run_diagnostics(local_port: u16) -> (NetworkTopology, Option<SocketAddr>) {
    let socket = match UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), local_port)) {
        Ok(s) => s,
        Err(_) => {
            match UdpSocket::bind("0.0.0.0:0") {
                Ok(s) => s,
                Err(_) => return (NetworkTopology::UdpBlockedStrict, None),
            }
        }
    };

    if socket.set_nonblocking(true).is_err() {
        return (NetworkTopology::UdpBlockedStrict, None);
    }
    let async_socket = match tokio::net::UdpSocket::from_std(socket) {
        Ok(s) => s,
        Err(_) => return (NetworkTopology::UdpBlockedStrict, None),
    };

    let resolve_a = tokio::net::lookup_host("stun.l.google.com:19302");
    let resolve_b = tokio::net::lookup_host("stun.vydia.com:3478");

    let (addrs_a, addrs_b) = tokio::join!(resolve_a, resolve_b);

    let mut target_a = None;
    if let Ok(addrs) = addrs_a {
        for addr in addrs {
            if addr.is_ipv4() {
                target_a = Some(addr);
                break;
            }
        }
    }

    let mut target_b = None;
    if let Ok(addrs) = addrs_b {
        for addr in addrs {
            if addr.is_ipv4() {
                target_b = Some(addr);
                break;
            }
        }
    }

    if target_a.is_none() && target_b.is_none() {
        return (NetworkTopology::UdpBlockedStrict, None);
    }

    let mut request_a = [0u8; 20];
    request_a[0..2].copy_from_slice(&[0x00, 0x01]);
    request_a[2..4].copy_from_slice(&[0x00, 0x00]);
    request_a[4..8].copy_from_slice(&[0x21, 0x12, 0xA4, 0x42]);
    let mut tx_id_a = [0u8; 12];
    for i in 0..12 {
        tx_id_a[i] = rand::random::<u8>();
    }
    request_a[8..20].copy_from_slice(&tx_id_a);

    let mut request_b = [0u8; 20];
    request_b[0..2].copy_from_slice(&[0x00, 0x01]);
    request_b[2..4].copy_from_slice(&[0x00, 0x00]);
    request_b[4..8].copy_from_slice(&[0x21, 0x12, 0xA4, 0x42]);
    let mut tx_id_b = [0u8; 12];
    for i in 0..12 {
        tx_id_b[i] = rand::random::<u8>();
    }
    request_b[8..20].copy_from_slice(&tx_id_b);

    if let Some(addr) = target_a {
        let _ = async_socket.send_to(&request_a, addr).await;
    }
    if let Some(addr) = target_b {
        let _ = async_socket.send_to(&request_b, addr).await;
    }

    let start_time = Instant::now();
    let timeout_dur = Duration::from_secs(2);
    let mut buf = [0u8; 512];

    let mut mapped_a = None;
    let mut mapped_b = None;

    while start_time.elapsed() < timeout_dur {
        if mapped_a.is_some() && mapped_b.is_some() {
            break;
        }

        let remaining = timeout_dur.saturating_sub(start_time.elapsed());
        if remaining.is_zero() {
            break;
        }

        let recv_result = tokio::time::timeout(
            remaining,
            async_socket.recv_from(&mut buf)
        ).await;

        if let Ok(Ok((len, _))) = recv_result {
            if len >= 20 && buf[0..2] == [0x01, 0x01] && buf[4..8] == [0x21, 0x12, 0xA4, 0x42] {
                let id = &buf[8..20];
                if id == tx_id_a {
                    mapped_a = parse_stun_mapped_address(&buf[..len]);
                } else if id == tx_id_b {
                    mapped_b = parse_stun_mapped_address(&buf[..len]);
                }
            }
        }
    }

    let topology = match (mapped_a, mapped_b) {
        (Some(addr_a), Some(addr_b)) => {
            if addr_a.ip() == addr_b.ip() {
                if addr_a.port() == addr_b.port() {
                    let local_ip = detect_local_ip();
                    if Some(addr_a.ip()) == local_ip {
                        NetworkTopology::OpenInternet
                    } else {
                        NetworkTopology::ConeNatFriendly
                    }
                } else {
                    NetworkTopology::SymmetricNatRestrictive
                }
            } else {
                NetworkTopology::SymmetricNatRestrictive
            }
        }
        (Some(_), None) | (None, Some(_)) => {
            NetworkTopology::ConeNatFriendly
        }
        (None, None) => {
            NetworkTopology::UdpBlockedStrict
        }
    };
    (topology, mapped_a.or(mapped_b))
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex::encode(digest)
}

#[cfg(test)]
mod tests {
    use super::{normalize_fingerprint_hex, sha256_hex, SHA256_LEN_BYTES};

    #[test]
    fn normalize_fingerprint_accepts_colons_and_case() {
        let normalized = normalize_fingerprint_hex(
            "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99",
        )
        .expect("normalize fingerprint");

        assert_eq!(normalized.len(), SHA256_LEN_BYTES * 2);
        assert_eq!(normalized, normalized.to_ascii_lowercase());
    }

    #[test]
    fn normalize_fingerprint_rejects_invalid_length() {
        let error = normalize_fingerprint_hex("abcd").expect_err("invalid fingerprint length should fail");
        assert!(
            error
                .to_string()
                .contains("expected between 32 and 64 hex characters")
        );
    }

    #[test]
    fn sha256_hex_has_expected_size() {
        let hash = sha256_hex(b"nexus-test");
        assert_eq!(hash.len(), SHA256_LEN_BYTES * 2);
    }
}