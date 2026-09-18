//! Node-to-node wire protocol.
//!
//! Ported from midstate `src/network/protocol.rs`: the same length-prefixed
//! bincode framing, size caps, 60-second read deadline and panic-isolated
//! decoding. Changes:
//!
//! * Protocol id `/midwimble/1.0.0`, so the two networks never talk.
//! * `Transaction` / `Batch` / `BatchHeader` are the MimbleWimble types.
//! * CoinJoin (`Mix*`) and chat variants are gone. MimbleWimble aggregates
//!   every block, which is the privacy property CoinJoin was approximating,
//!   and chat is out of scope for a payment chain.
//! * `GetBatches` is capped by response size as well as count: a full
//!   MimbleWimble block can approach half a megabyte, so midstate's
//!   1,000-batch responses would blow the 10 MB frame limit.
//!
//! Variant order is the bincode discriminant. **Append only.**

use crate::anchor::AnchorRecord;
use crate::core::mw::Transaction;
use crate::core::{Batch, BatchHeader};
use async_trait::async_trait;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::StreamProtocol;
use serde::{Deserialize, Serialize};
use std::io;

pub const MAX_GETBATCHES_COUNT: u64 = 64;
pub const MAX_GETHEADERS_COUNT: u64 = 5000;
/// Responders stop adding batches once a response reaches this size.
pub const BATCH_RESPONSE_SOFT_LIMIT: usize = 8_000_000;
pub const MAX_MSG_SIZE: usize = 10_000_000;

pub const MIDWIMBLE_PROTOCOL: StreamProtocol = StreamProtocol::new("/midwimble/1.0.0");

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Message {
    /// Fluff-phase transaction: validate, add to mempool, gossip.
    Transaction(Transaction),
    /// Dandelion++ stem phase: forward to one peer (10% chance to fluff).
    StemTransaction(Transaction),
    Batch(Batch),
    GetState,
    StateInfo {
        height: u64,
        depth: u128,
        mw_midstate: [u8; 32],
    },
    GetAddr,
    /// Peer exchange: multiaddr strings.
    Addr(Vec<String>),
    Ping {
        nonce: u64,
    },
    /// Also used as the generic acknowledgement (midstate's `ack`).
    Pong {
        nonce: u64,
    },
    GetBatches {
        start_height: u64,
        count: u64,
    },
    Batches {
        start_height: u64,
        batches: Vec<Batch>,
    },
    GetHeaders {
        start_height: u64,
        count: u64,
    },
    Headers {
        start_height: u64,
        headers: Vec<BatchHeader>,
    },
    /// Anchored checkpoints the peer knows (`docs/PRUNING.md` §3).
    GetAnchors,
    Anchors(Vec<AnchorRecord>),
    /// A state snapshot at a checkpoint, in parts (`docs/PRUNING.md` §4).
    GetSnapshot {
        checkpoint_id: [u8; 32],
        part: u32,
    },
    SnapshotPart {
        checkpoint_id: [u8; 32],
        part: u32,
        total: u32,
        data: Vec<u8>,
    },
}

pub const MAX_ANCHORS_PER_MESSAGE: usize = 64;
pub const SNAPSHOT_PART_BYTES: usize = 4_000_000;

impl Message {
    pub fn serialize_bin(&self) -> Vec<u8> {
        use bincode::Options;
        bincode::DefaultOptions::new()
            .with_limit(MAX_MSG_SIZE as u64)
            .serialize(self)
            .expect("message exceeds MAX_MSG_SIZE")
    }

    pub fn serialized_size(&self) -> u64 {
        use bincode::Options;
        bincode::DefaultOptions::new()
            .serialized_size(self)
            .unwrap_or(u64::MAX)
    }

    pub fn deserialize_bin(bytes: &[u8]) -> anyhow::Result<Self> {
        use bincode::Options;
        let msg: Message = bincode::DefaultOptions::new()
            .with_limit(MAX_MSG_SIZE as u64)
            .reject_trailing_bytes()
            .deserialize(bytes)?;
        match &msg {
            Message::Headers { headers, .. } if headers.len() > MAX_GETHEADERS_COUNT as usize => {
                anyhow::bail!(
                    "Headers count {} exceeds max {}",
                    headers.len(),
                    MAX_GETHEADERS_COUNT
                )
            }
            Message::Batches { batches, .. } if batches.len() > MAX_GETBATCHES_COUNT as usize => {
                anyhow::bail!(
                    "Batches count {} exceeds max {}",
                    batches.len(),
                    MAX_GETBATCHES_COUNT
                )
            }
            Message::Addr(addrs) if addrs.len() > 1000 => {
                anyhow::bail!("Addr count {} exceeds max 1000", addrs.len())
            }
            Message::Anchors(list) if list.len() > MAX_ANCHORS_PER_MESSAGE => {
                anyhow::bail!(
                    "Anchors count {} exceeds max {}",
                    list.len(),
                    MAX_ANCHORS_PER_MESSAGE
                )
            }
            Message::SnapshotPart { data, .. } if data.len() > SNAPSHOT_PART_BYTES => {
                anyhow::bail!("snapshot part too large")
            }
            _ => {}
        }
        Ok(msg)
    }
}

#[derive(Debug, Clone, Default)]
pub struct MidwimbleCodec;

#[async_trait]
impl libp2p::request_response::Codec for MidwimbleCodec {
    type Protocol = StreamProtocol;
    type Request = Message;
    type Response = Message;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        read_message(io).await
    }

    async fn read_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        read_message(io).await
    }

    async fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_message(io, &req).await
    }

    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        res: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_message(io, &res).await
    }
}

async fn read_message<T: AsyncRead + Unpin + Send>(io: &mut T) -> io::Result<Message> {
    let read_future = async {
        let mut len_bytes = [0u8; 4];
        io.read_exact(&mut len_bytes).await?;
        let len = u32::from_le_bytes(len_bytes) as usize;
        if len > MAX_MSG_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "message too large",
            ));
        }
        let mut buf = Vec::with_capacity(len.min(65_536));
        let mut handle = io.take(len as u64);
        handle.read_to_end(&mut buf).await?;
        if buf.len() != len {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "incomplete message",
            ));
        }
        match std::panic::catch_unwind(|| Message::deserialize_bin(&buf)) {
            Ok(result) => result.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e)),
            Err(_) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "malformed message caused a panic",
            )),
        }
    };
    tokio::time::timeout(std::time::Duration::from_secs(60), read_future)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "stream read timed out"))?
}

async fn write_message<T: AsyncWrite + Unpin + Send>(io: &mut T, msg: &Message) -> io::Result<()> {
    let bytes = msg.serialize_bin();
    io.write_all(&(bytes.len() as u32).to_le_bytes()).await?;
    io.write_all(&bytes).await?;
    io.close().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_state_info_and_genesis_batch() {
        let msg = Message::StateInfo {
            height: 7,
            depth: 99,
            mw_midstate: [3; 32],
        };
        match Message::deserialize_bin(&msg.serialize_bin()).unwrap() {
            Message::StateInfo {
                height,
                depth,
                mw_midstate,
            } => assert_eq!((height, depth, mw_midstate), (7, 99, [3; 32])),
            _ => panic!("wrong variant"),
        }
        let msg = Message::Batches {
            start_height: 0,
            batches: vec![Batch::genesis().clone()],
        };
        match Message::deserialize_bin(&msg.serialize_bin()).unwrap() {
            Message::Batches { batches, .. } => assert_eq!(&batches[0], Batch::genesis()),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn trailing_bytes_and_garbage_are_rejected() {
        let mut bytes = Message::GetState.serialize_bin();
        bytes.push(0);
        assert!(Message::deserialize_bin(&bytes).is_err());
        assert!(Message::deserialize_bin(&[0xff; 16]).is_err());
    }
}
