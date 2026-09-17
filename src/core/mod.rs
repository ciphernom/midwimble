//! Consensus core: pure functions over chain state, no I/O.

pub mod anchor;
pub mod auxpow;
pub mod extension;
pub mod filter;
pub mod finality;
#[cfg(feature = "gpu")]
pub mod gpu_mining;
pub mod mmr;
pub mod mss;
pub mod mw;
pub mod recovery;
pub mod simd_mining;
pub mod snapshot;
pub mod state;
pub mod template;
pub mod types;
pub mod wots;
pub mod wots_simd;

pub use state::{apply_batch, apply_batch_skip_pow, apply_batch_trusted, choose_best_state};
pub use types::{Batch, BatchHeader, Extension, State};

#[cfg(all(test, feature = "fast-mining"))]
mod chain_tests;
