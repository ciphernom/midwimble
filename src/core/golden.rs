//! Golden vectors for the encodings consensus hashes.
//!
//! Transaction, coinbase, checkpoint, relayed-header and registration hashes
//! are taken over bincode 1's default encoding of the structures, and the
//! mining hash over a fixed byte layout. A different encoding (another
//! bincode release, a reordered or retyped field, a changed derive) would
//! give every node built with it different block hashes: a silent chain
//! split. `Cargo.toml` pins bincode to the exact release, and these vectors
//! fail first if anything changes the bytes. A deliberate consensus change
//! updates them, and is a relaunch.

use super::anchor::{Checkpoint, HeaderLink};
use super::bond::{BondCoin, BondProof, BondRegistration, BondScript, MidstateRoots, MinerAuth};
use super::mmr::{ProofElement, UtxoProof};
use super::mw::crypto::{KernelSig, SchnorrSig};
use super::mw::stealth::PAYLOAD_LEN;
use super::mw::{
    Coinbase, Input, Kernel, KernelFeatures, Output, OutputGroup, Transaction, TxBody,
};
use super::relay::RelayHeaders;
use super::types::{
    compute_header_hash, midstate_header_hash, registrations_hash, BatchHeader, Extension,
};

fn output(seed: u8) -> Output {
    Output {
        commitment: [seed; 32],
        owner_key: [seed + 1; 32],
        ephemeral_key: [seed + 2; 32],
        view_tag: seed + 3,
        payload: vec![seed + 4; PAYLOAD_LEN],
        recovery_commitment: [seed + 5; 32],
    }
}

fn kernel(features: KernelFeatures, seed: u8) -> Kernel {
    Kernel {
        features,
        fee: 1_000 + seed as u64,
        min_height: 77,
        excess: [seed; 32],
        owner_excess: [seed + 1; 32],
        signature: KernelSig {
            c: [seed + 2; 32],
            s1: [seed + 3; 32],
            s2: [seed + 4; 32],
        },
    }
}

fn transaction() -> Transaction {
    Transaction {
        body: TxBody {
            inputs: vec![Input {
                commitment: [0x10; 32],
                owner_key: [0x11; 32],
                signature: SchnorrSig {
                    e: [0x12; 32],
                    s: [0x13; 32],
                },
            }],
            outputs: vec![OutputGroup {
                outputs: vec![output(0x20), output(0x30)],
                range_proof: vec![0x40; 64],
            }],
            kernels: vec![kernel(KernelFeatures::Plain, 0x50)],
        },
        kernel_offset: [0x60; 32],
        owner_offset: [0x61; 32],
    }
}

fn coinbase() -> Coinbase {
    Coinbase {
        outputs: OutputGroup {
            outputs: vec![output(0x70)],
            range_proof: vec![0x80; 32],
        },
        kernel: kernel(KernelFeatures::Coinbase, 0x90),
        extra: [0xa0; 32],
    }
}

fn checkpoint() -> Checkpoint {
    Checkpoint {
        version: 1,
        network: [0xb0; 32],
        mw_height: 10_000,
        mw_header_hash: [0xb1; 32],
        mw_state_root: [0xb2; 32],
        mw_cumulative_work: (1u128 << 100) | 12_345,
        previous_checkpoint: [0xb3; 32],
    }
}

fn relayed() -> RelayHeaders {
    let link = |seed: u8| HeaderLink {
        post_tx_midstate: [seed; 32],
        state_root: [seed + 1; 32],
        timestamp: 1_800_000_000 + seed as u64,
        target: [seed + 2; 32],
        nonce: 42,
        final_hash: [seed + 3; 32],
    };
    RelayHeaders {
        prev: [0xc0; 32],
        headers: vec![link(0xc1), link(0xc5)],
    }
}

fn registration() -> BondRegistration {
    BondRegistration {
        proof: BondProof {
            coin: BondCoin {
                script: BondScript {
                    mining_key: [0xd0; 32],
                    bonded_until: 400_000,
                    owner_pk: [0xd1; 32],
                },
                value: 5_000_000,
                salt: [0xd2; 32],
            },
            midstate_height: 318_000,
            roots: MidstateRoots {
                coins: [0xd3; 32],
                commitments: [0xd4; 32],
                chain_mmr: [0xd5; 32],
                burned_wots: Some([0xd6; 32]),
            },
            smt: UtxoProof {
                leaf_index: 0,
                leaf_count: 3,
                siblings: vec![
                    ProofElement {
                        hash: [0xd7; 32],
                        is_right: true,
                    },
                    ProofElement {
                        hash: [0xd8; 32],
                        is_right: false,
                    },
                ],
            },
        },
    }
}

fn header() -> BatchHeader {
    BatchHeader {
        height: 12,
        prev_midstate: [0xe0; 32],
        post_tx_midstate: [0xe1; 32],
        extension: Extension {
            nonce: 99,
            final_hash: [0xe2; 32],
        },
        timestamp: 1_800_000_123,
        target: [0xe3; 32],
        state_root: [0xe4; 32],
        prev_header_hash: [0xe5; 32],
        signer: Some([0xe6; 32]),
        chain_weight: (1u128 << 90) + 7,
        aux_pow: None,
    }
}

/// bincode 1's default encoding itself: fixed-width little-endian integers,
/// u64 length prefixes, a byte for `Option` and `bool`, a u32 enum tag.
#[test]
fn bincode_encodes_as_consensus_expects() {
    #[derive(serde::Serialize)]
    enum Tag {
        _A,
        B(u16),
    }
    let bytes = bincode::serialize(&(
        1u8,
        0x0203u16,
        0x0405_0607u32,
        0x0809_0a0b_0c0d_0e0fu64,
        1u128,
        vec![0xaau8, 0xbb],
        Some([0xccu8; 2]),
        None::<u8>,
        true,
        Tag::B(0xdddd),
    ))
    .unwrap();
    assert_eq!(
        hex::encode(bytes),
        concat!(
            "01",
            "0302",
            "07060504",
            "0f0e0d0c0b0a0908",
            "01000000000000000000000000000000",
            "0200000000000000aabb",
            "01cccc",
            "00",
            "01",
            "01000000dddd",
        )
    );
}

/// The hashes blocks commit to. If one changes, so does every block hash.
#[test]
fn consensus_hashes_are_unchanged() {
    let cases: [(&str, usize, [u8; 32], &str); 6] = [
        (
            "transaction",
            bincode::serialize(&transaction()).unwrap().len(),
            transaction().hash(),
            "910:69c220b1c859c744a84d2f76e329547ddf907c6d3aa465f3b8c9ce92a9c0c017",
        ),
        (
            "coinbase",
            bincode::serialize(&coinbase()).unwrap().len(),
            coinbase().hash(),
            "477:e3c95fc521160280a0ace4c1090702fd88721b66ba4b3b5ce1766b976c81cd98",
        ),
        (
            "checkpoint",
            bincode::serialize(&checkpoint()).unwrap().len(),
            checkpoint().id(),
            "153:3f26d0158668026410719fe75dd53422f6a6f5ec2c61a1d4b2effa3c1313e822",
        ),
        (
            "relayed headers",
            bincode::serialize(&relayed()).unwrap().len(),
            relayed().hash(),
            "328:5a54d5be059a2d5c387fcec1fcf4601f7979bb0152d843bde2c4573f5da10c80",
        ),
        (
            "registrations",
            bincode::serialize(&vec![registration()]).unwrap().len(),
            registrations_hash(&[registration()]),
            "347:9fb8d3b815cc80e33f06944de818a101087b207fbb84783c1d81a702d4008f44",
        ),
        (
            "miner authorisation",
            0,
            MinerAuth {
                bond_id: [0xf0; 32],
                signature: SchnorrSig {
                    e: [0xf1; 32],
                    s: [0xf2; 32],
                },
            }
            .hash(),
            "0:d282fb02c3e29690a46838c00f9071dba46891205ebe7e3d9e14b8ef3983f5cf",
        ),
    ];
    let mut wrong = Vec::new();
    for (name, len, hash, expected) in cases {
        let got = format!("{len}:{}", hex::encode(hash));
        if got != expected {
            wrong.push(format!("{name}: {got}"));
        }
    }
    assert!(wrong.is_empty(), "changed:\n{}", wrong.join("\n"));
}

/// The mining hash, and midstate's header hash it extends.
#[test]
fn header_hashes_are_unchanged() {
    let h = header();
    let unsigned = BatchHeader {
        signer: None,
        ..h.clone()
    };
    let midstate = midstate_header_hash(
        &h.prev_header_hash,
        &h.post_tx_midstate,
        &h.state_root,
        h.timestamp,
        &h.target,
    );
    assert_eq!(
        hex::encode(compute_header_hash(&h)),
        "33fcb75906f67de8bcdfffd5a9b379cb56f01ee8609d680728f7eb335a10929b"
    );
    assert_eq!(
        hex::encode(compute_header_hash(&unsigned)),
        "79a34f59542f87139dab9da6fedde5d836570e3c30497ddf23af5221a330f0d1"
    );
    // Midstate's own (`compute_header_hash` there), used for midstate's
    // headers in anchors, the relay and merged-mining parents.
    assert_eq!(
        hex::encode(midstate),
        "0ac049f699466f3d92bd920ec1dd3a55583fba7f9bd7fae36dbbda38133e40eb"
    );
}
