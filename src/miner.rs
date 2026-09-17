//! Mining coordinator.
//!
//! Midstate's `mining.rs` runs `mine_extension` (its multi-threaded, SIMD
//! grinder) on a dedicated OS thread and cancels it through an `AtomicBool`
//! whenever the tip or the template changes. Same here.

use crate::core::extension::MiningResult;
use crate::core::template::BlockTemplate;
use crate::core::Batch;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;

/// midstate's backend switch: GPU (when built with `gpu` and a device passes
/// self-test) or the SIMD CPU miner.
fn search(
    mining_hash: [u8; 32],
    target: [u8; 32],
    threads: usize,
    cancel: Arc<AtomicBool>,
    counter: Arc<AtomicU64>,
) -> Option<MiningResult> {
    #[cfg(feature = "gpu")]
    {
        crate::core::gpu_mining::mine(mining_hash, target, None, threads, cancel, counter)
    }
    #[cfg(not(feature = "gpu"))]
    {
        crate::core::extension::mine_extension(mining_hash, target, None, threads, cancel, counter)
    }
}

pub struct MinedBlock {
    pub job: u64,
    pub batch: Batch,
}

pub struct Miner {
    threads: usize,
    cancel: Option<Arc<AtomicBool>>,
    job: u64,
    result_tx: mpsc::UnboundedSender<MinedBlock>,
    pub hashes: Arc<AtomicU64>,
}

impl Miner {
    /// `threads == 0` uses every available core.
    pub fn new(threads: usize) -> (Self, mpsc::UnboundedReceiver<MinedBlock>) {
        let (result_tx, rx) = mpsc::unbounded_channel();
        (
            Self {
                threads,
                cancel: None,
                job: 0,
                result_tx,
                hashes: Arc::new(AtomicU64::new(0)),
            },
            rx,
        )
    }

    pub fn start(&mut self, template: BlockTemplate) {
        self.stop();
        self.job += 1;
        let cancel = Arc::new(AtomicBool::new(false));
        self.cancel = Some(cancel.clone());
        let (job, threads, counter, tx) = (
            self.job,
            self.threads,
            self.hashes.clone(),
            self.result_tx.clone(),
        );
        std::thread::Builder::new()
            .name(format!("miner-{job}"))
            .spawn(move || {
                let target = template.batch.target;
                if let Some(MiningResult::Block(ext)) =
                    search(template.mining_hash, target, threads, cancel, counter)
                {
                    let _ = tx.send(MinedBlock {
                        job,
                        batch: template.seal(ext),
                    });
                }
            })
            .expect("spawning miner thread");
    }

    pub fn stop(&mut self) {
        if let Some(c) = self.cancel.take() {
            c.store(true, Ordering::Relaxed);
        }
    }

    pub fn is_running(&self) -> bool {
        self.cancel.is_some()
    }

    pub fn current_job(&self) -> u64 {
        self.job
    }
}

impl Drop for Miner {
    fn drop(&mut self) {
        self.stop();
    }
}
