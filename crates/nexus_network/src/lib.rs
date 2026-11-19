use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::info;

/// ALPN protocol identifier for NexusP2P sessions.
pub const NEXUS_ALPN: &[u8] = b"nexus-p2p/5";

/// Re-export iroh types used by the application layer.
pub use iroh::endpoint::{Connection, RecvStream, SendStream, VarInt};
pub use iroh::{Endpoint, EndpointAddr, EndpointId, PublicKey, SecretKey};

/// Connection mode reported by iroh.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum ConnectionMode {
    #[default]
    Unknown,
    Direct,
    Relay,
    Mixed,
}

impl std::fmt::Display for ConnectionMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectionMode::Unknown => write!(f, "Unknown"),
            ConnectionMode::Direct => write!(f, "Direct P2P"),
            ConnectionMode::Relay => write!(f, "Relay"),
            ConnectionMode::Mixed => write!(f, "Mixed (Relay+Direct)"),
        }
    }
}

/// Create an iroh endpoint configured for NexusP2P.
///
/// The endpoint automatically:
/// - Discovers and connects to public relay servers
/// - Performs NAT hole-punching when possible
/// - Falls back to relay when direct P2P is blocked
pub async fn create_endpoint() -> Result<Endpoint> {
    let endpoint = Endpoint::builder(iroh::endpoint::presets::N0)
        .alpns(vec![NEXUS_ALPN.to_vec()])
        .bind()
        .await
        .context("failed to create iroh endpoint")?;

    let node_id = endpoint.id();
    info!(%node_id, "iroh endpoint created");

    Ok(endpoint)
}

/// Create an iroh endpoint for the client side (no ALPN acceptance needed).
pub async fn create_client_endpoint() -> Result<Endpoint> {
    let endpoint = Endpoint::builder(iroh::endpoint::presets::N0)
        .bind()
        .await
        .context("failed to create iroh client endpoint")?;

    let node_id = endpoint.id();
    info!(%node_id, "iroh client endpoint created");

    Ok(endpoint)
}

/// A stable client key permits future connections to be authorized by the
/// remote computer's explicit public-key allowlist.
pub async fn create_client_endpoint_with_secret(secret: SecretKey) -> Result<Endpoint> {
    let endpoint = Endpoint::builder(iroh::endpoint::presets::N0)
        .secret_key(secret)
        .bind()
        .await
        .context("failed to create stable authenticated technician endpoint")?;
    info!(identity = %endpoint.id(), "stable technician QUIC endpoint created");
    Ok(endpoint)
}

/// Get the full EndpointAddr for an endpoint (includes relay URLs and direct addresses).
pub async fn get_node_addr(endpoint: &Endpoint) -> Result<EndpointAddr> {
    Ok(endpoint.addr())
}

/// Accept an incoming connection on the endpoint.
pub async fn accept_connection(endpoint: &Endpoint) -> Result<Connection> {
    let incoming = endpoint
        .accept()
        .await
        .context("endpoint closed before any incoming connection")?;

    let accepting = incoming.accept().context("failed to accept incoming connection")?;
    let connection = accepting
        .await
        .context("failed to complete QUIC handshake")?;

    let remote_node_id = connection.remote_id();
    info!(%remote_node_id, "accepted iroh connection");

    Ok(connection)
}

/// Connect to a remote peer using their EndpointAddr.
pub async fn connect_to_peer(
    endpoint: &Endpoint,
    remote: EndpointAddr,
) -> Result<Connection> {
    let connection = endpoint
        .connect(remote, NEXUS_ALPN)
        .await
        .context("failed to connect to remote peer via iroh")?;

    let remote_node_id = connection.remote_id();
    info!(%remote_node_id, "connected to remote peer via iroh");

    Ok(connection)
}

#[cfg(test)]
mod tests {
    use super::NEXUS_ALPN;

    #[test]
    fn alpn_is_valid() {
        assert!(!NEXUS_ALPN.is_empty());
        assert!(NEXUS_ALPN.len() < 256);
    }

    /// Explicit two-endpoint QUIC smoke test. Ignored in regular CI because
    /// relay discovery and local UDP policy depend on the environment.
    /// Run with: cargo test -p nexus_network -- --ignored --nocapture
    #[tokio::test]
    #[ignore = "requires local UDP and functional iroh relay/discovery"]
    async fn two_endpoints_exchange_bidirectional_data() {
        use super::{
            accept_connection, connect_to_peer, create_client_endpoint_with_secret,
            create_endpoint, SecretKey,
        };
        use tokio::time::{timeout, Duration};

        let server = create_endpoint().await.expect("server endpoint");
        let technician_key = SecretKey::generate();
        let expected_identity = technician_key.public();
        let client = create_client_endpoint_with_secret(technician_key)
            .await.expect("stable client endpoint");
        assert_eq!(client.id(), expected_identity);
        let address = server.addr();
        let server_task = tokio::spawn(async move {
            let connection = timeout(Duration::from_secs(20), accept_connection(&server))
                .await.expect("server accept deadline").expect("accepted");
            assert_eq!(connection.remote_id(), expected_identity,
                "trusted identity must be authenticated by QUIC");
            let (mut tx, mut rx) = connection.accept_bi().await.expect("control stream");
            let mut received = [0_u8; 4];
            rx.read_exact(&mut received).await.expect("read request");
            assert_eq!(&received, b"ping");
            tx.write_all(b"pong").await.expect("auth response");
            // This simulates remote human approval. Only after control consent
            // does the server publish its video stream.
            let mut video = connection.open_uni().await.expect("open video");
            video.write_all(b"frame").await.expect("send video");
            video.finish().expect("finish video");
            tx.finish().expect("finish response");
            let _ = timeout(Duration::from_secs(2), connection.closed()).await;
        });

        let connection = timeout(Duration::from_secs(20), connect_to_peer(&client, address))
            .await.expect("client deadline").expect("connected");
        let (mut tx, mut rx) = connection.open_bi().await.expect("client stream");
        tx.write_all(b"ping").await.expect("send");
        let mut received = [0_u8; 4];
        rx.read_exact(&mut received).await.expect("response");
        assert_eq!(&received, b"pong");
        // Waiting for the video BEFORE writing ping would deadlock.
        let mut video = timeout(Duration::from_secs(20), connection.accept_uni())
            .await.expect("video deadline").expect("video stream");
        let mut frame = [0_u8; 5];
        video.read_exact(&mut frame).await.expect("video payload");
        assert_eq!(&frame, b"frame");
        connection.close(0u32.into(), b"test complete");
        server_task.await.expect("server task");
        client.close().await;
    }
}
