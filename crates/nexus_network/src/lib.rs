use anyhow::{anyhow, bail, Context, Result};
use quinn::{ClientConfig, Connection, Endpoint, ServerConfig, TransportConfig};
use rcgen::generate_simple_self_signed;
use rustls::client::{ServerCertVerified, ServerCertVerifier};
use rustls::{Certificate, PrivateKey, ServerName};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tracing::info;

const SHA256_LEN_BYTES: usize = 32;

#[derive(Debug)]
pub struct ServerEndpoint {
    endpoint: Endpoint,
    pub certificate_der: Vec<u8>,
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

pub async fn bind_server(bind_addr: SocketAddr) -> Result<ServerEndpoint> {
    let (server_config, certificate_der) = build_server_config()?;
    let endpoint = Endpoint::server(server_config, bind_addr)
        .context("failed to bind QUIC server endpoint")?;
    let certificate_fingerprint = sha256_hex(&certificate_der);

    Ok(ServerEndpoint {
        endpoint,
        certificate_der,
        certificate_fingerprint,
    })
}

pub async fn bind_client(bind_addr: SocketAddr, expected_fingerprint: String) -> Result<ClientEndpoint> {
    let mut endpoint = Endpoint::client(bind_addr).context("failed to bind QUIC client endpoint")?;
    endpoint.set_default_client_config(build_pinned_client_config(expected_fingerprint)?);
    Ok(ClientEndpoint { endpoint })
}

pub fn normalize_fingerprint_hex(input: &str) -> Result<String> {
    let bytes = parse_fingerprint_hex(input)?;
    Ok(hex::encode(bytes))
}

fn build_server_config() -> Result<(ServerConfig, Vec<u8>)> {
    let certificate = generate_simple_self_signed(vec!["localhost".to_string()])
        .context("failed to generate self-signed certificate")?;
    let certificate_der = certificate
        .serialize_der()
        .context("failed to serialize certificate")?;
    let private_key_der = certificate.serialize_private_key_der();

    let mut server_config = ServerConfig::with_single_cert(
        vec![Certificate(certificate_der.clone())],
        PrivateKey(private_key_der),
    )
    .context("failed to assemble QUIC server config")?;

    let transport = Arc::get_mut(&mut server_config.transport)
        .context("failed to access QUIC server transport configuration")?;
    transport.max_concurrent_uni_streams(8_u32.into());
    transport.max_concurrent_bidi_streams(8_u32.into());
    transport.keep_alive_interval(Some(Duration::from_secs(3)));

    Ok((server_config, certificate_der))
}

fn build_pinned_client_config(expected_fingerprint: String) -> Result<ClientConfig> {
    let expected = parse_fingerprint_hex(&expected_fingerprint)?;
    let expected_hex = hex::encode(expected);

    let crypto = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(Arc::new(FingerprintVerifier {
            expected,
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

#[derive(Debug)]
struct FingerprintVerifier {
    expected: [u8; SHA256_LEN_BYTES],
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
        if actual.as_slice() == self.expected {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "certificate fingerprint mismatch: expected {}, got {}",
                self.expected_hex,
                hex::encode(actual)
            )))
        }
    }
}

fn parse_fingerprint_hex(input: &str) -> Result<[u8; SHA256_LEN_BYTES]> {
    let normalized: String = input
        .chars()
        .filter(|ch| ch.is_ascii_hexdigit())
        .map(|ch| ch.to_ascii_lowercase())
        .collect();

    if normalized.len() != SHA256_LEN_BYTES * 2 {
        bail!(
            "expected {} hex characters for a SHA-256 fingerprint, got {}",
            SHA256_LEN_BYTES * 2,
            normalized.len()
        );
    }

    let bytes = hex::decode(&normalized)
        .with_context(|| format!("failed to decode fingerprint: {normalized}"))?;

    let mut output = [0_u8; SHA256_LEN_BYTES];
    if bytes.len() != SHA256_LEN_BYTES {
        return Err(anyhow!(
            "decoded fingerprint length was {}, expected {}",
            bytes.len(),
            SHA256_LEN_BYTES
        ));
    }

    output.copy_from_slice(&bytes);
    Ok(output)
}

fn sha256_hex(bytes: &[u8]) -> String {
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
                .contains("expected 64 hex characters for a SHA-256 fingerprint")
        );
    }

    #[test]
    fn sha256_hex_has_expected_size() {
        let hash = sha256_hex(b"nexus-test");
        assert_eq!(hash.len(), SHA256_LEN_BYTES * 2);
    }
}