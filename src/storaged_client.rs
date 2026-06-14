//! StoragedClient — T04 byte-read Unix domain socket client.
//!
//! The GriotQL engine's ONLY data-access path is through T04's storaged
//! byte-read socket. This module implements the client side of that protocol.
//!
//! # Socket protocol
//!
//! T04 storaged socket is bind-mounted into the pod at runtime by Talos
//! admission (after binary attestation verification per DEC-0028 / ADR-0002).
//! Path: `GRIOT_T04_SOCKET` env var, default `/run/griot/t04.sock`.
//!
//! ## Wire format (X02 §T04 byte-read opcodes 0x30–0x3F)
//!
//! Each request is a length-prefixed JSON frame:
//! ```text
//! [4 bytes big-endian length][JSON payload bytes]
//! ```
//!
//! Opcode `0x30` — `storaged_byte_read`:
//! ```json
//! {
//!   "opcode": "0x30",
//!   "asset_id": "<uuid>",
//!   "offset": 0,
//!   "length": 65536,
//!   "tenant_id": "<tenant>",
//!   "principal_jwt": "<jwt>"
//! }
//! ```
//!
//! Response: `[4 bytes big-endian length][raw bytes OR error JSON]`
//!
//! # Semantic Law invariants
//!
//! * INV-2 (No read without satisfaction): T04 enforces contract constraints
//!   on every byte-read. If the principal does not satisfy the constraint,
//!   T04 returns an error; StoragedClient surfaces it as `StoragedError::AccessDenied`.
//! * INV-5 (No bypass from above trust line): this module makes no direct
//!   filesystem access. All data comes through T04.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tracing::{debug, warn};

// ─── Errors ───────────────────────────────────────────────────────────────────

/// Errors returned by the storaged client.
#[derive(Debug, Error)]
pub enum StoragedError {
    /// T04 denied the read request (principal does not satisfy contract constraints).
    /// INV-2: No read without satisfaction.
    #[error("storaged access denied for asset '{asset_id}': {reason}")]
    AccessDenied { asset_id: String, reason: String },

    /// The requested byte range is out of bounds for the asset.
    #[error("storaged range error for asset '{asset_id}': offset={offset}, length={length}")]
    RangeError {
        asset_id: String,
        offset: u64,
        length: u64,
    },

    /// The storaged socket is not reachable.
    #[error("storaged socket unreachable at '{path}': {source}")]
    SocketUnreachable {
        path: String,
        source: std::io::Error,
    },

    /// Protocol framing error.
    #[error("storaged protocol error: {0}")]
    Protocol(String),

    /// Unexpected I/O error.
    #[error("storaged I/O error: {0}")]
    Io(#[from] std::io::Error),
}

// ─── Wire types ───────────────────────────────────────────────────────────────

/// X02 storaged_byte_read request (opcode 0x30).
#[derive(Debug, Serialize)]
struct ByteReadRequest<'a> {
    opcode: &'static str,
    asset_id: &'a str,
    offset: u64,
    length: u64,
    tenant_id: &'a str,
    principal_jwt: &'a str,
}

/// X02 storaged_byte_read response header.
/// If `error` is Some, `bytes` is absent.
#[derive(Debug, Deserialize)]
struct ByteReadResponseHeader {
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    error_code: Option<String>,
    #[serde(default)]
    byte_count: Option<u64>,
}

/// X02 asset_stat request (opcode 0x31).
#[derive(Debug, Serialize)]
struct AssetStatRequest<'a> {
    opcode: &'static str,
    asset_id: &'a str,
    tenant_id: &'a str,
    principal_jwt: &'a str,
}

/// X02 asset_stat response.
#[derive(Debug, Deserialize)]
pub struct AssetStatResponse {
    /// Total byte size of the asset.
    pub size: u64,
    /// Content type (e.g., "application/vnd.apache.parquet", "application/x-lance").
    pub content_type: String,
    /// Asset format version string.
    pub format_version: String,
}

// ─── Client ───────────────────────────────────────────────────────────────────

/// T04 storaged byte-read client.
///
/// Opens a new UDS connection per request (stateless per request, suitable for
/// the pool-manager model where each pool worker has its own client instance).
/// Connection pooling can be added in a future wave.
#[derive(Debug, Clone)]
pub struct StoragedClient {
    socket_path: String,
}

impl StoragedClient {
    /// Create a new StoragedClient pointed at the given socket path.
    ///
    /// # Arguments
    ///
    /// * `socket_path` — path to the T04 storaged Unix domain socket.
    ///   Typically `GRIOT_T04_SOCKET` env var or `/run/griot/t04.sock`.
    pub fn new(socket_path: impl Into<String>) -> Self {
        Self {
            socket_path: socket_path.into(),
        }
    }

    /// Read a byte range from an asset through T04.
    ///
    /// # Arguments
    ///
    /// * `asset_id` — the griotfs asset UUID.
    /// * `offset` — byte offset within the asset.
    /// * `length` — number of bytes to read.
    /// * `tenant_id` — tenant context for contract enforcement.
    /// * `principal_jwt` — scoped JWT for the requesting principal.
    ///
    /// # Returns
    ///
    /// The raw bytes of the requested range.
    ///
    /// # Errors
    ///
    /// * `StoragedError::AccessDenied` — T04 contract check failed.
    /// * `StoragedError::RangeError` — offset + length exceeds asset size.
    /// * `StoragedError::SocketUnreachable` — socket not bound-mounted yet.
    pub async fn read_bytes(
        &self,
        asset_id: &str,
        offset: u64,
        length: u64,
        tenant_id: &str,
        principal_jwt: &str,
    ) -> Result<bytes::Bytes, StoragedError> {
        let mut stream = self.connect().await?;

        let request = ByteReadRequest {
            opcode: "0x30",
            asset_id,
            offset,
            length,
            tenant_id,
            principal_jwt,
        };

        let request_json = serde_json::to_vec(&request)
            .map_err(|e| StoragedError::Protocol(format!("request serialization: {e}")))?;

        // Write length-prefixed frame.
        let len_bytes = (request_json.len() as u32).to_be_bytes();
        stream.write_all(&len_bytes).await?;
        stream.write_all(&request_json).await?;
        stream.flush().await?;

        // Read the response header length.
        let mut header_len_bytes = [0u8; 4];
        stream.read_exact(&mut header_len_bytes).await?;
        let header_len = u32::from_be_bytes(header_len_bytes) as usize;

        if header_len == 0 || header_len > 4 * 1024 * 1024 {
            return Err(StoragedError::Protocol(format!(
                "invalid response header length: {header_len}"
            )));
        }

        let mut header_bytes = vec![0u8; header_len];
        stream.read_exact(&mut header_bytes).await?;

        let header: ByteReadResponseHeader =
            serde_json::from_slice(&header_bytes).map_err(|e| {
                StoragedError::Protocol(format!("response header deserialization: {e}"))
            })?;

        if let Some(error_msg) = header.error {
            let code = header.error_code.as_deref().unwrap_or("UNKNOWN");
            if code == "ACCESS_DENIED" {
                return Err(StoragedError::AccessDenied {
                    asset_id: asset_id.to_string(),
                    reason: error_msg,
                });
            }
            if code == "RANGE_ERROR" {
                return Err(StoragedError::RangeError {
                    asset_id: asset_id.to_string(),
                    offset,
                    length,
                });
            }
            return Err(StoragedError::Protocol(format!(
                "T04 error [{code}]: {error_msg}"
            )));
        }

        let byte_count = header.byte_count.unwrap_or(length);

        // Read the payload bytes.
        let mut payload = vec![0u8; byte_count as usize];
        stream.read_exact(&mut payload).await?;

        debug!(
            asset_id,
            offset,
            length,
            actual_bytes = byte_count,
            "storaged_byte_read completed"
        );

        Ok(bytes::Bytes::from(payload))
    }

    /// Stat an asset — returns size, content type, format version.
    ///
    /// Used by the Lance IO layer to discover the asset size before issuing
    /// positional read requests.
    pub async fn stat_asset(
        &self,
        asset_id: &str,
        tenant_id: &str,
        principal_jwt: &str,
    ) -> Result<AssetStatResponse, StoragedError> {
        let mut stream = self.connect().await?;

        let request = AssetStatRequest {
            opcode: "0x31",
            asset_id,
            tenant_id,
            principal_jwt,
        };

        let request_json = serde_json::to_vec(&request)
            .map_err(|e| StoragedError::Protocol(format!("stat request serialization: {e}")))?;

        let len_bytes = (request_json.len() as u32).to_be_bytes();
        stream.write_all(&len_bytes).await?;
        stream.write_all(&request_json).await?;
        stream.flush().await?;

        let mut resp_len_bytes = [0u8; 4];
        stream.read_exact(&mut resp_len_bytes).await?;
        let resp_len = u32::from_be_bytes(resp_len_bytes) as usize;

        if resp_len == 0 || resp_len > 65536 {
            return Err(StoragedError::Protocol(format!(
                "invalid stat response length: {resp_len}"
            )));
        }

        let mut resp_bytes = vec![0u8; resp_len];
        stream.read_exact(&mut resp_bytes).await?;

        // Try parsing as an error first.
        #[derive(Deserialize)]
        struct MaybeError {
            #[serde(default)]
            error: Option<String>,
            #[serde(default)]
            error_code: Option<String>,
            #[serde(flatten)]
            stat: Option<AssetStatResponse>,
        }

        // We parse the response two ways to reuse code. Direct Deserialize works here.
        let stat: AssetStatResponse = serde_json::from_slice(&resp_bytes).map_err(|e| {
            // Try to parse as error envelope.
            if let Ok(maybe) = serde_json::from_slice::<serde_json::Value>(&resp_bytes) {
                if let Some(err_msg) = maybe.get("error").and_then(|v| v.as_str()) {
                    let code = maybe
                        .get("error_code")
                        .and_then(|v| v.as_str())
                        .unwrap_or("UNKNOWN");
                    if code == "ACCESS_DENIED" {
                        return StoragedError::AccessDenied {
                            asset_id: asset_id.to_string(),
                            reason: err_msg.to_string(),
                        };
                    }
                    return StoragedError::Protocol(format!("T04 stat error [{code}]: {err_msg}"));
                }
            }
            StoragedError::Protocol(format!("stat response deserialization: {e}"))
        })?;

        Ok(stat)
    }

    /// Open a Unix domain socket connection to T04.
    async fn connect(&self) -> Result<UnixStream, StoragedError> {
        let path = Path::new(&self.socket_path);
        UnixStream::connect(path).await.map_err(|e| {
            warn!(
                socket = %self.socket_path,
                error = %e,
                "failed to connect to T04 storaged socket"
            );
            StoragedError::SocketUnreachable {
                path: self.socket_path.clone(),
                source: e,
            }
        })
    }
}
