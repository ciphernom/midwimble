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

pub const LIGHT_PROTOCOL: StreamProtocol = StreamProtocol::new("/midwimble/light/2.0.0");
pub const LIGHT_PUSH_PROTOCOL: StreamProtocol = StreamProtocol::new("/midwimble/light-push/2.0.0");

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
    /// Consecutive whole blocks from `start_height`, as one hex-encoded
    /// bincode `Vec<Batch>`: what a wallet scanning a long stretch of chain
    /// asks for instead of one `get_block` per height. The node may return
    /// fewer than `count` (it caps the count and the response size), never
    /// zero unless `start_height` is past its tip.
    #[serde(rename = "get_blocks")]
    GetBlocks { start_height: u64, count: u64 },
    /// One page of the unspent outputs, as the RPC's `/utxos` gives it: for
    /// a wallet restoring from a node that has pruned the blocks it would
    /// otherwise scan (`docs/PRUNING.md`). `after` is the last commitment of
    /// the page before; `limit` defaults to 256, at most 1000.
    #[serde(rename = "get_utxos")]
    GetUtxos {
        #[serde(default)]
        after: Option<String>,
        #[serde(default)]
        limit: Option<u64>,
    },
    #[serde(rename = "get_filters")]
    GetFilters { start_height: u64, end_height: u64 },
    /// The mempool's size, and the hashes of its transactions (at most
    /// [`MAX_LIGHT_MEMPOOL_HASHES`]; `truncated` says there were more).
    /// Transactions still in their Dandelion++ stem phase are not listed.
    #[serde(rename = "get_mempool")]
    GetMempool,
    /// Transactions waiting in the mempool, by hash, as one hex-encoded
    /// bincode `Vec<Transaction>`: a wallet scans their outputs with its
    /// view key to see payments to it before a block confirms them. At most
    /// [`MAX_LIGHT_MEMPOOL_TXS`] are asked for; any that left the mempool
    /// are left out, and so are any past the response's size limit.
    #[serde(rename = "get_mempool_txs")]
    GetMempoolTxs { hashes: Vec<String> },
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
                | LightRequest::GetBlocks { .. }
                | LightRequest::GetUtxos { .. }
                | LightRequest::SubmitTransaction { .. }
        )
    }
}

/// Most blocks one `get_blocks` returns.
pub const MAX_LIGHT_BLOCKS: u64 = 200;
/// Most transaction hashes one `get_mempool` lists.
pub const MAX_LIGHT_MEMPOOL_HASHES: usize = 4_096;
/// Most transactions one `get_mempool_txs` may ask for.
pub const MAX_LIGHT_MEMPOOL_TXS: usize = 64;
/// `get_blocks` stops adding blocks once their bincode reaches this, so the
/// hex response stays well inside [`MAX_LIGHT_MSG_SIZE`] (which browser
/// clients mirror).
pub const LIGHT_BLOCKS_BYTE_LIMIT: usize = 900_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// The request's `id`, echoed: a client that numbers its requests can
    /// tell an answer that reached the wrong stream (a WebRTC data channel's
    /// id is reused quickly) from its own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<u64>,
}

impl LightResponse {
    pub fn success(data: serde_json::Value) -> Self {
        Self {
            ok: true,
            data: Some(data),
            error: None,
            id: None,
        }
    }

    pub fn error(msg: impl Into<String>) -> Self {
        Self {
            ok: false,
            data: None,
            error: Some(msg.into()),
            id: None,
        }
    }
}

pub async fn read_request_raw<T: AsyncRead + Unpin + Send>(io: &mut T) -> io::Result<LightRequest> {
    Ok(read_request_with_id(io).await?.1)
}

/// A request and the `id` its client gave it, if any: the answer echoes it.
pub async fn read_request_with_id<T: AsyncRead + Unpin + Send>(
    io: &mut T,
) -> io::Result<(Option<u64>, LightRequest)> {
    let bytes = read_length_prefixed(io).await?;
    parse_request(&bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

fn parse_request(bytes: &[u8]) -> serde_json::Result<(Option<u64>, LightRequest)> {
    let mut value: serde_json::Value = serde_json::from_slice(bytes)?;
    let id = value
        .as_object_mut()
        .and_then(|m| m.remove("id"))
        .and_then(|v| v.as_u64());
    Ok((id, serde_json::from_value(value)?))
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
        let parsed: LightRequest = serde_json::from_str(
            r#"{"method":"get_blocks","params":{"start_height":7,"count":64}}"#,
        )
        .unwrap();
        assert!(matches!(
            parsed,
            LightRequest::GetBlocks {
                start_height: 7,
                count: 64
            }
        ));
        assert!(parsed.is_expensive());
        let parsed: LightRequest =
            serde_json::from_str(r#"{"method":"get_utxos","params":{}}"#).unwrap();
        assert!(matches!(
            parsed,
            LightRequest::GetUtxos {
                after: None,
                limit: None
            }
        ));
        let parsed: LightRequest =
            serde_json::from_str(r#"{"method":"get_mempool_txs","params":{"hashes":["ab","cd"]}}"#)
                .unwrap();
        assert!(matches!(parsed, LightRequest::GetMempoolTxs { ref hashes } if hashes.len() == 2));
        // Old clients' bare get_mempool still parses.
        let parsed: LightRequest = serde_json::from_str(r#"{"method":"get_mempool"}"#).unwrap();
        assert!(matches!(parsed, LightRequest::GetMempool));

        // Numbered requests: the id comes back in the answer, and nodes that
        // predate it parse the request anyway (they ignore the field).
        let (id, parsed) = parse_request(br#"{"id":7,"method":"get_state"}"#).unwrap();
        assert_eq!(id, Some(7));
        assert!(matches!(parsed, LightRequest::GetState));
        let old: LightRequest =
            serde_json::from_str(r#"{"id":7,"method":"get_block","params":{"height":3}}"#).unwrap();
        assert!(matches!(old, LightRequest::GetBlock { height: 3 }));
        let (id, _) = parse_request(br#"{"method":"get_state"}"#).unwrap();
        assert_eq!(id, None);
        let mut answer = LightResponse::success(serde_json::json!({}));
        answer.id = Some(7);
        let json = serde_json::to_string(&answer).unwrap();
        assert!(json.contains(r#""id":7"#), "{json}");
        let unnumbered = serde_json::to_string(&LightResponse::error("x")).unwrap();
        assert!(!unnumbered.contains("id"), "{unnumbered}");
    }
}
