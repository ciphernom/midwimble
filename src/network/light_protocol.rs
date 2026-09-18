//! Light-client protocol (browser wallets over WebRTC, or any libp2p client).
//!
//! Ported from midstate `src/network/light_protocol.rs`: JSON bodies with a
//! 4-byte little-endian length prefix on a raw `libp2p-stream` stream, plus a
//! push protocol for new-tip notifications. The request set is reduced to what
//! a MimbleWimble wallet needs: headers and filters to follow the chain, whole
//! blocks to scan with a view key, UTXO proofs, and transaction submission.

use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::StreamProtocol;
use serde::{Deserialize, Serialize};
use std::io;

pub const LIGHT_PROTOCOL: StreamProtocol = StreamProtocol::new("/midwimble/light/1.0.0");
pub const LIGHT_PUSH_PROTOCOL: StreamProtocol = StreamProtocol::new("/midwimble/light-push/1.0.0");

const MAX_LIGHT_MSG_SIZE: usize = 2_000_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum LightNotification {
    NewBlockTip {
        height: u64,
        target: String,
        filter_hex: String,
        block_hash: String,
        element_count: u64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "method", content = "params")]
pub enum LightRequest {
    #[serde(rename = "get_state")]
    GetState,
    /// Headers let a light client check proof of work and the state-root chain.
    #[serde(rename = "get_headers")]
    GetHeaders { start_height: u64, count: u64 },
    /// Whole block as hex-encoded bincode, for view-key scanning.
    #[serde(rename = "get_block")]
    GetBlock { height: u64 },
    #[serde(rename = "get_filters")]
    GetFilters { start_height: u64, end_height: u64 },
    #[serde(rename = "get_mempool")]
    GetMempool,
    /// Hex-encoded bincode `Transaction`, entered via Dandelion++.
    #[serde(rename = "submit_transaction")]
    SubmitTransaction { tx_hex: String },
    /// Membership proof for an unspent output against the current state root.
    #[serde(rename = "get_utxo_proof")]
    GetUtxoProof { commitment: String },
}

impl LightRequest {
    /// Requests that cost the node real work and get a tighter rate limit.
    pub fn is_expensive(&self) -> bool {
        matches!(
            self,
            LightRequest::GetFilters { .. }
                | LightRequest::GetHeaders { .. }
                | LightRequest::SubmitTransaction { .. }
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl LightResponse {
    pub fn success(data: serde_json::Value) -> Self {
        Self {
            ok: true,
            data: Some(data),
            error: None,
        }
    }

    pub fn error(msg: impl Into<String>) -> Self {
        Self {
            ok: false,
            data: None,
            error: Some(msg.into()),
        }
    }
}

pub async fn read_request_raw<T: AsyncRead + Unpin + Send>(io: &mut T) -> io::Result<LightRequest> {
    let bytes = read_length_prefixed(io).await?;
    serde_json::from_slice(&bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

pub async fn write_response_raw<T: AsyncWrite + Unpin + Send>(
    io: &mut T,
    res: LightResponse,
) -> io::Result<()> {
    let bytes =
        serde_json::to_vec(&res).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    write_length_prefixed(io, &bytes).await
}

pub async fn write_request_raw<T: AsyncWrite + Unpin + Send>(
    io: &mut T,
    req: &LightRequest,
) -> io::Result<()> {
    let bytes =
        serde_json::to_vec(req).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    write_length_prefixed(io, &bytes).await
}

pub async fn read_response_raw<T: AsyncRead + Unpin + Send>(
    io: &mut T,
) -> io::Result<LightResponse> {
    let bytes = read_length_prefixed(io).await?;
    serde_json::from_slice(&bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

async fn read_length_prefixed<T: AsyncRead + Unpin + Send>(io: &mut T) -> io::Result<Vec<u8>> {
    let mut len_bytes = [0u8; 4];
    io.read_exact(&mut len_bytes).await?;
    let len = u32::from_le_bytes(len_bytes) as usize;
    if len > MAX_LIGHT_MSG_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "light message too large",
        ));
    }
    let mut buf = Vec::with_capacity(len.min(65_536));
    let mut handle = io.take(len as u64);
    handle.read_to_end(&mut buf).await?;
    if buf.len() != len {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "incomplete light message",
        ));
    }
    Ok(buf)
}

async fn write_length_prefixed<T: AsyncWrite + Unpin + Send>(
    io: &mut T,
    data: &[u8],
) -> io::Result<()> {
    io.write_all(&(data.len() as u32).to_le_bytes()).await?;
    io.write_all(data).await?;
    // Closes our write half only (libp2p streams are half-closable), so a
    // client can still read the response after sending its request.
    io.close().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_json_shape() {
        let json = serde_json::to_string(&LightRequest::GetBlock { height: 5 }).unwrap();
        assert_eq!(json, r#"{"method":"get_block","params":{"height":5}}"#);
        let parsed: LightRequest = serde_json::from_str(r#"{"method":"get_state"}"#).unwrap();
        assert!(matches!(parsed, LightRequest::GetState));
    }
}
