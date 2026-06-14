//! T05Client — T05 GDCP Notary attestation-signing UDS client.
//!
//! The GriotQL engine submits attestation envelopes to T05 for ES256 JWS signing
//! instead of computing a self-hash. This upholds ADR-0002 wave-10 requirement:
//! "AttestationExec submits to T05 over UDS for real JWS signing."
//!
//! # Opcode
//!
//! T05 `attest_envelope_sign` — opcode `0x42` (T05 GDCP range 0x40–0x4F,
//! per cross-cutting-prerequisites.md §1).
//!
//! # Wire format
//!
//! Same length-prefixed JSON framing as StoragedClient (X02 standard).
//!
//! Request:
//! ```json
//! {
//!   "opcode": "0x42",
//!   "envelope_json": "<canonical JSON of AttestationEnvelope (excluding signature field)>",
//!   "engine_version": "<semver>",
//!   "tenant_id": "<tenant>",
//!   "correlation_id": "<uuid>"
//! }
//! ```
//!
//! Response:
//! ```json
//! {
//!   "jws": "<JWS compact serialization ES256>",
//!   "kid": "<T05 key ID used for signing>"
//! }
//! ```
//!
//! # Trust model
//!
//! The engine binary holds NO private key. T05 holds the platform ES256 keypair
//! (managed by subcomponents #13 + #14, DEC-0028 Option 1). The engine submits
//! the canonical attestation JSON; T05 signs it and returns the JWS compact
//! serialization. The engine attaches this JWS to the result stream.
//!
//! # Semantic Law
//!
//! * INV-4 (No AI without provenance): the JWS IS the provenance certificate.
//! * INV-5 (No bypass from above trust line): we call T05 over UDS; we never
//!   hold or generate private key material.

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tracing::{debug, warn};

// ─── Errors ───────────────────────────────────────────────────────────────────

/// Errors returned by the T05 signing client.
#[derive(Debug, Error)]
pub enum T05Error {
    /// T05 refused to sign the envelope (e.g., unknown engine version, CRL hit).
    #[error("T05 signing refused: {reason}")]
    SigningRefused { reason: String },

    /// T05 socket unreachable.
    #[error("T05 socket unreachable at '{path}': {source}")]
    SocketUnreachable {
        path: String,
        source: std::io::Error,
    },

    /// Protocol framing error.
    #[error("T05 protocol error: {0}")]
    Protocol(String),

    /// I/O error.
    #[error("T05 I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization error.
    #[error("T05 serialization error: {0}")]
    Serialization(String),
}

// ─── Wire types ───────────────────────────────────────────────────────────────

/// Request to sign an attestation envelope via T05 opcode 0x42.
#[derive(Debug, Serialize)]
struct SignEnvelopeRequest<'a> {
    opcode: &'static str,
    /// Canonical JSON of the AttestationEnvelope (without the `signature` field).
    envelope_json: &'a str,
    /// Semver of the engine binary (from `env!("CARGO_PKG_VERSION")`).
    engine_version: &'a str,
    /// Tenant context for T05 audit logging.
    tenant_id: &'a str,
    /// Correlation ID for distributed tracing.
    correlation_id: &'a str,
}

/// T05 signing response.
#[derive(Debug, Deserialize)]
pub struct SignEnvelopeResponse {
    /// JWS compact serialization of the attestation envelope, ES256-signed by T05.
    /// Format: `<base64url-header>.<base64url-payload>.<base64url-signature>`.
    pub jws: String,
    /// T05 key ID used for signing (for JWKS lookup at `.well-known/gdcp/engine-release-keys.jwks`).
    pub kid: String,
}

/// Error frame returned by T05.
#[derive(Debug, Deserialize)]
struct T05ErrorFrame {
    error: String,
    #[serde(default)]
    error_code: Option<String>,
}

// ─── Client ───────────────────────────────────────────────────────────────────

/// T05 GDCP Notary client for attestation envelope signing.
#[derive(Debug, Clone)]
pub struct T05Client {
    socket_path: String,
}

impl T05Client {
    /// Create a new T05Client pointed at the given socket path.
    ///
    /// # Arguments
    ///
    /// * `socket_path` — path to the T05 UDS socket.
    ///   Typically `GRIOT_T05_ATTEST_SOCKET` env var or `/run/griot/sockets/gdcp.sock`.
    pub fn new(socket_path: impl Into<String>) -> Self {
        Self {
            socket_path: socket_path.into(),
        }
    }

    /// Submit an attestation envelope JSON to T05 for ES256 JWS signing.
    ///
    /// # Arguments
    ///
    /// * `envelope_json` — canonical JSON of the AttestationEnvelope struct,
    ///   EXCLUDING the `signature` field. The caller must serialize the envelope
    ///   without the signature, pass it here, then set the returned JWS as the
    ///   signature field.
    /// * `engine_version` — semver of the engine binary.
    /// * `tenant_id` — tenant context for T05 audit.
    /// * `correlation_id` — distributed trace ID.
    ///
    /// # Returns
    ///
    /// A `SignEnvelopeResponse` containing the JWS and the key ID used.
    ///
    /// # Errors
    ///
    /// * `T05Error::SigningRefused` — T05 rejected the request (CRL hit, unknown version).
    /// * `T05Error::SocketUnreachable` — T05 socket not available.
    pub async fn sign_envelope(
        &self,
        envelope_json: &str,
        engine_version: &str,
        tenant_id: &str,
        correlation_id: &str,
    ) -> Result<SignEnvelopeResponse, T05Error> {
        let mut stream = self.connect().await?;

        let request = SignEnvelopeRequest {
            opcode: "0x42",
            envelope_json,
            engine_version,
            tenant_id,
            correlation_id,
        };

        let request_json = serde_json::to_vec(&request)
            .map_err(|e| T05Error::Serialization(format!("request serialization: {e}")))?;

        let len_bytes = (request_json.len() as u32).to_be_bytes();
        stream.write_all(&len_bytes).await?;
        stream.write_all(&request_json).await?;
        stream.flush().await?;

        // Read response length.
        let mut resp_len_bytes = [0u8; 4];
        stream.read_exact(&mut resp_len_bytes).await?;
        let resp_len = u32::from_be_bytes(resp_len_bytes) as usize;

        if resp_len == 0 || resp_len > 1024 * 1024 {
            return Err(T05Error::Protocol(format!(
                "invalid T05 response length: {resp_len}"
            )));
        }

        let mut resp_bytes = vec![0u8; resp_len];
        stream.read_exact(&mut resp_bytes).await?;

        // Try to parse as success first, then fall back to error.
        if let Ok(success) = serde_json::from_slice::<SignEnvelopeResponse>(&resp_bytes) {
            if !success.jws.is_empty() {
                debug!(
                    kid = %success.kid,
                    tenant_id,
                    correlation_id,
                    "T05 attestation envelope signed"
                );
                return Ok(success);
            }
        }

        // Try parsing as error.
        let error: T05ErrorFrame = serde_json::from_slice(&resp_bytes)
            .map_err(|e| T05Error::Protocol(format!("T05 response deserialization failed: {e}")))?;

        Err(T05Error::SigningRefused {
            reason: error.error,
        })
    }

    /// Open a UDS connection to T05.
    async fn connect(&self) -> Result<UnixStream, T05Error> {
        UnixStream::connect(&self.socket_path).await.map_err(|e| {
            warn!(
                socket = %self.socket_path,
                error = %e,
                "failed to connect to T05 GDCP socket"
            );
            T05Error::SocketUnreachable {
                path: self.socket_path.clone(),
                source: e,
            }
        })
    }
}
