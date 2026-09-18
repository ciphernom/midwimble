//! Shared test support: a stand-in midstate node built from midstate's own
//! types (see `merge_mining.rs` for provenance) with its commit rules.
#![allow(dead_code)]

use midwimble::core::extension::create_extension;
use std::sync::{Arc, Mutex};

pub mod midstate_ref {
    //! Verbatim shapes from midstate `src/core/types.rs`.
    use serde::{Deserialize, Serialize};

    pub fn hash(data: &[u8]) -> [u8; 32] {
        *blake3::hash(data).as_bytes()
    }
    pub fn hash_concat(a: &[u8], b: &[u8]) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(a);
        h.update(b);
        *h.finalize().as_bytes()
    }
    pub fn compute_coin_id(address: &[u8; 32], value: u64, salt: &[u8; 32]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(address);
        hasher.update(&value.to_le_bytes());
        hasher.update(salt);
        *hasher.finalize().as_bytes()
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct Extension {
        pub nonce: u64,
        pub final_hash: [u8; 32],
    }
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub enum Predicate {
        Script { bytecode: Vec<u8> },
    }
    impl Predicate {
        pub fn address(&self) -> [u8; 32] {
            match self {
                Predicate::Script { bytecode } => hash(bytecode),
            }
        }
    }
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub enum Witness {
        ScriptInputs(Vec<Vec<u8>>),
    }
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub enum OutputData {
        Standard {
            address: [u8; 32],
            value: u64,
            salt: [u8; 32],
        },
        Confidential {
            address: [u8; 32],
            commitment: [u8; 32],
            salt: [u8; 32],
        },
        DataBurn {
            payload: Vec<u8>,
            value_burned: u64,
        },
    }
    impl OutputData {
        pub fn hash_for_commitment(&self) -> [u8; 32] {
            match self {
                OutputData::Standard {
                    address,
                    value,
                    salt,
                } => compute_coin_id(address, *value, salt),
                OutputData::Confidential {
                    address,
                    commitment,
                    salt,
                } => {
                    let mut hasher = blake3::Hasher::new();
                    hasher.update(b"CONFIDENTIAL");
                    hasher.update(address);
                    hasher.update(commitment);
                    hasher.update(salt);
                    *hasher.finalize().as_bytes()
                }
                OutputData::DataBurn {
                    payload,
                    value_burned,
                } => {
                    let mut hasher = blake3::Hasher::new();
                    hasher.update(b"DATABURN");
                    hasher.update(&value_burned.to_le_bytes());
                    hasher.update(payload);
                    *hasher.finalize().as_bytes()
                }
            }
        }
    }
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct InputReveal {
        pub predicate: Predicate,
        pub value: u64,
        pub salt: [u8; 32],
        #[serde(default)]
        pub commitment: Option<[u8; 32]>,
    }
    impl InputReveal {
        pub fn coin_id(&self) -> [u8; 32] {
            match self.commitment {
                Some(ref c) => {
                    let mut hasher = blake3::Hasher::new();
                    hasher.update(b"CONFIDENTIAL");
                    hasher.update(&self.predicate.address());
                    hasher.update(c);
                    hasher.update(&self.salt);
                    *hasher.finalize().as_bytes()
                }
                None => compute_coin_id(&self.predicate.address(), self.value, &self.salt),
            }
        }
    }
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub enum Transaction {
        Commit {
            commitment: [u8; 32],
            spam_nonce: u64,
        },
        Reveal {
            inputs: Vec<InputReveal>,
            witnesses: Vec<Witness>,
            outputs: Vec<OutputData>,
            salt: [u8; 32],
        },
        Consolidate {
            inputs: Vec<InputReveal>,
            witness: Witness,
            outputs: Vec<OutputData>,
            salt: [u8; 32],
        },
    }
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct CoinbaseOutput {
        pub address: [u8; 32],
        pub value: u64,
        pub salt: [u8; 32],
    }
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct Batch {
        pub prev_midstate: [u8; 32],
        pub transactions: Vec<Transaction>,
        pub extension: Extension,
        #[serde(default)]
        pub coinbase: Vec<CoinbaseOutput>,
        pub timestamp: u64,
        pub target: [u8; 32],
        #[serde(default)]
        pub state_root: [u8; 32],
        pub prev_header_hash: [u8; 32],
    }
    impl Batch {
        /// midstate `Batch::header` + `compute_header_hash`.
        pub fn mining_hash(&self) -> ([u8; 32], [u8; 32]) {
            let mut midstate = self.prev_midstate;
            for tx in &self.transactions {
                match tx {
                    Transaction::Commit { commitment, .. } => {
                        midstate = hash_concat(&midstate, commitment)
                    }
                    Transaction::Reveal {
                        inputs,
                        outputs,
                        salt,
                        ..
                    }
                    | Transaction::Consolidate {
                        inputs,
                        outputs,
                        salt,
                        ..
                    } => {
                        let mut hasher = blake3::Hasher::new();
                        for i in inputs {
                            hasher.update(&i.coin_id());
                        }
                        for o in outputs {
                            hasher.update(&o.hash_for_commitment());
                        }
                        hasher.update(salt);
                        midstate = hash_concat(&midstate, hasher.finalize().as_bytes());
                    }
                }
            }
            for cb in &self.coinbase {
                midstate =
                    hash_concat(&midstate, &compute_coin_id(&cb.address, cb.value, &cb.salt));
            }
            if self.state_root != [0u8; 32] {
                midstate = hash_concat(&midstate, &self.state_root);
            }
            let mut hasher = blake3::Hasher::new();
            hasher.update(&self.prev_header_hash);
            hasher.update(&midstate);
            hasher.update(&self.state_root);
            hasher.update(&self.timestamp.to_le_bytes());
            hasher.update(&self.target);
            (*hasher.finalize().as_bytes(), midstate)
        }
    }
}

pub use midstate_ref::*;

pub const REWARD: u64 = 1_000_003; // several power-of-two outputs

#[derive(Default)]
pub struct MockChain {
    pub height: u64,
    pub prev_midstate: [u8; 32],
    pub prev_header_hash: [u8; 32],
    pub accepted: u64,
    pub blocks: Vec<Batch>,
    pub pending_commits: Vec<([u8; 32], u64)>,
}

pub type Mock = Arc<Mutex<MockChain>>;

fn sample_transactions(height: u64) -> Vec<Transaction> {
    vec![
        Transaction::Commit {
            commitment: hash(&height.to_le_bytes()),
            spam_nonce: 7,
        },
        Transaction::Reveal {
            inputs: vec![
                InputReveal {
                    predicate: Predicate::Script {
                        bytecode: vec![1, 2, 3],
                    },
                    value: 8,
                    salt: [3; 32],
                    commitment: None,
                },
                InputReveal {
                    predicate: Predicate::Script { bytecode: vec![4] },
                    value: 0,
                    salt: [4; 32],
                    commitment: Some([5; 32]),
                },
            ],
            witnesses: vec![Witness::ScriptInputs(vec![vec![9; 4]])],
            outputs: vec![
                OutputData::Standard {
                    address: [6; 32],
                    value: 4,
                    salt: [7; 32],
                },
                OutputData::Confidential {
                    address: [8; 32],
                    commitment: [9; 32],
                    salt: [10; 32],
                },
                OutputData::DataBurn {
                    payload: vec![1, 1],
                    value_burned: 2,
                },
            ],
            salt: hash(&(height + 1).to_le_bytes()),
        },
    ]
}

pub async fn start_mock_midstate() -> (String, Mock) {
    use axum::{
        extract::State,
        http::StatusCode,
        routing::{get, post},
        Json, Router,
    };
    use serde_json::{json, Value};

    let chain: Mock = Arc::new(Mutex::new(MockChain {
        prev_midstate: [1; 32],
        prev_header_hash: [2; 32],
        ..Default::default()
    }));

    async fn state(State(c): State<Mock>) -> Json<Value> {
        let c = c.lock().unwrap();
        Json(json!({ "height": c.height, "header_hash": hex::encode(c.prev_header_hash) }))
    }

    async fn template(State(c): State<Mock>, Json(req): Json<Value>) -> (StatusCode, Json<Value>) {
        let c = c.lock().unwrap();
        let mut coinbase = Vec::new();
        let mut total = 0u64;
        for cb in req["coinbase"].as_array().unwrap() {
            let mut address = [0u8; 32];
            let mut salt = [0u8; 32];
            hex::decode_to_slice(cb["address"].as_str().unwrap(), &mut address).unwrap();
            hex::decode_to_slice(cb["salt"].as_str().unwrap(), &mut salt).unwrap();
            let value = cb["value"].as_u64().unwrap();
            assert!(value.is_power_of_two());
            total += value;
            coinbase.push(CoinbaseOutput {
                address,
                value,
                salt,
            });
        }
        if total != REWARD {
            // midstate's actual error shape.
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": format!("Coinbase mismatch. Expected: {}", REWARD) })),
            );
        }
        let mut transactions = sample_transactions(c.height);
        for (commitment, spam_nonce) in &c.pending_commits {
            transactions.push(Transaction::Commit {
                commitment: *commitment,
                spam_nonce: *spam_nonce,
            });
        }
        let batch = Batch {
            prev_midstate: c.prev_midstate,
            transactions,
            extension: Extension {
                nonce: 0,
                final_hash: [0; 32],
            },
            coinbase,
            timestamp: 1_800_000_000 + c.height,
            target: [0xff; 32],
            state_root: hash(&[c.height as u8; 8]),
            prev_header_hash: c.prev_header_hash,
        };
        let (mining, _) = batch.mining_hash();
        (
            StatusCode::OK,
            Json(json!({
                "mining_midstate": hex::encode(mining),
                "target": hex::encode(batch.target),
                "batch_template": serde_json::to_value(&batch).unwrap(),
                "total_fees": 0,
                "block_reward": REWARD,
            })),
        )
    }

    async fn submit(State(c): State<Mock>, Json(batch): Json<Batch>) -> (StatusCode, Json<Value>) {
        let mut c = c.lock().unwrap();
        let (mining, post_tx) = batch.mining_hash();
        let ext = create_extension(mining, batch.extension.nonce);
        let ok = ext.final_hash == batch.extension.final_hash
            && ext.final_hash < batch.target
            && batch.prev_header_hash == c.prev_header_hash;
        if !ok {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "Block rejected" })),
            );
        }
        c.height += 1;
        c.prev_midstate = post_tx;
        c.prev_header_hash = ext.final_hash;
        c.accepted += 1;
        let mined: Vec<[u8; 32]> = batch
            .transactions
            .iter()
            .filter_map(|t| match t {
                Transaction::Commit { commitment, .. } => Some(*commitment),
                _ => None,
            })
            .collect();
        c.pending_commits.retain(|(x, _)| !mined.contains(x));
        c.blocks.push(batch);
        (StatusCode::OK, Json(json!({ "accepted": true })))
    }

    async fn batch(
        State(c): State<Mock>,
        axum::extract::Path(h): axum::extract::Path<u64>,
    ) -> (StatusCode, Json<Value>) {
        let c = c.lock().unwrap();
        match c.blocks.get(h as usize) {
            Some(b) => (StatusCode::OK, Json(serde_json::to_value(b).unwrap())),
            None => (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": format!("Batch at height {} not found", h) })),
            ),
        }
    }

    /// midstate's `evaluate_commit_pow` (fast-mining: 16 bits).
    async fn commit(State(c): State<Mock>, Json(req): Json<Value>) -> (StatusCode, Json<Value>) {
        let mut c = c.lock().unwrap();
        let mut commitment = [0u8; 32];
        hex::decode_to_slice(
            req["commitment"].as_str().unwrap_or_default(),
            &mut commitment,
        )
        .unwrap();
        let spam_nonce = req["spam_nonce"].as_u64().unwrap_or(0);
        let (target_height, nonce) = ((spam_nonce >> 32) as u32, (spam_nonce & 0xFFFF_FFFF) as u32);
        if target_height as u64 >= c.height || c.height - target_height as u64 > 1000 {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "Commit PoW anchor height must be a past block" })),
            );
        }
        let mut data = [0u8; 68];
        data[..32].copy_from_slice(&c.blocks[target_height as usize].extension.final_hash);
        data[32..64].copy_from_slice(&commitment);
        data[64..].copy_from_slice(&nonce.to_le_bytes());
        let zeros = midwimble::core::types::count_leading_zeros(&hash(&data));
        if zeros < 16 {
            return (
                StatusCode::BAD_REQUEST,
                Json(
                    json!({ "error": format!("Insufficient PoW: need 16 leading zeros, got {zeros}") }),
                ),
            );
        }
        c.pending_commits.push((commitment, spam_nonce));
        (
            StatusCode::OK,
            Json(json!({ "commitment": hex::encode(commitment), "status": "committed" })),
        )
    }

    let app = Router::new()
        .route("/state", get(state))
        .route("/batch/{h}", get(batch))
        .route("/commit", post(commit))
        .route("/block_template", post(template))
        .route("/submit_batch", post(submit))
        .with_state(chain.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (addr, chain)
}

/// Mines one block on the mock (blocking; the mock's target is trivial).
pub fn mine_midstate_block(addr: &str) {
    use midwimble::rpc::RpcClient;
    let client = RpcClient::new(addr);
    let coinbase: Vec<serde_json::Value> = midwimble::merge_mine::decompose_value(REWARD)
        .iter()
        .enumerate()
        .map(|(i, v)| serde_json::json!({ "address": hex::encode([0x11u8; 32]), "value": v, "salt": hex::encode(hash(&(i as u64).to_le_bytes())) }))
        .collect();
    let tpl = client
        .post(
            "/block_template",
            &serde_json::json!({ "coinbase": coinbase }),
        )
        .unwrap();
    let mut batch = tpl["batch_template"].clone();
    let mining = midwimble::core::auxpow::bytes32(&tpl["mining_midstate"]).unwrap();
    let ext = create_extension(mining, 0);
    batch["extension"] = serde_json::json!({ "nonce": 0, "final_hash": ext.final_hash.to_vec() });
    client.post("/submit_batch", &batch).unwrap();
}
