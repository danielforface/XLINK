use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::info;

/// ALPN protocol identifier for NexusP2P sessions.
pub const NEXUS_ALPN: &[u8] = b"nexus-p2p/2";

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
}
