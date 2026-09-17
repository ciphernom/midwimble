//! midwimble: midstate's networking and consensus carrying Pluribit-style
//! MimbleWimble transactions, with receiver-only spend authority.
//!
//! * [`core`]: consensus rules and cryptography (no I/O; always built).
//! * `node` feature (default): libp2p networking, storage, mempool, sync,
//!   miner, wallet, RPC.

pub mod core;

#[cfg(feature = "node")]
pub mod anchor;
#[cfg(feature = "node")]
pub mod finality;
#[cfg(feature = "node")]
pub mod mempool;
#[cfg(feature = "node")]
pub mod merge_mine;
#[cfg(feature = "node")]
pub mod miner;
#[cfg(feature = "node")]
pub mod network;
#[cfg(feature = "node")]
pub mod node;
#[cfg(feature = "node")]
pub mod pool;
#[cfg(feature = "node")]
pub mod rpc;
#[cfg(feature = "node")]
pub mod storage;
#[cfg(feature = "node")]
pub mod sync;
#[cfg(feature = "node")]
pub mod wallet;
