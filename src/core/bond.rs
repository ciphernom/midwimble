//! Bonded proof of work: recognising a midstate mining bond
//! (`docs/BONDED_POW.md`).
//!
//! A bond is an ordinary midstate coin locked by a P2SH script that commits
//! to a midwimble mining key and an unlock height. Midstate needs no consensus
//! change to hold one — its script VM already has the timelock and signature
//! opcodes — and never learns what the coin is for. Midwimble recognises a
//! bond by the exact script template below and proves that it exists with an
//! SMT inclusion proof against a midstate header.
//!
//! This is the verification half only; nothing here is wired into block
//! validation yet. Which midstate header a proof must verify against (each
//! epoch's snapshot, agreed inside midwimble's own chain) arrives with the
//! header change described in the design document.

use super::auxpow::midstate_coin_id;
use super::mmr::{verify_utxo_proof, UtxoProof};
use super::types::{hash, hash_concat};
use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};

/// Midstate opcodes the template uses (midstate `src/core/script.rs`).
const OP_PUSH_DATA: u8 = 0x01;
const OP_DROP: u8 = 0x10;
const OP_CHECKSIGVERIFY: u8 = 0x32;
const OP_CHECKTIMEVERIFY: u8 = 0x33;

/// Midstate heights at which its UTXO hashing and state-root preimage changed.
const MIDSTATE_V2_ACTIVATION_HEIGHT: u64 = 100_000;
const MIDSTATE_V4_ACTIVATION_HEIGHT: u64 = 163_675;

/// Smallest bond that grants eligibility, in midstate base units. Midstate
/// coins are powers of two, so this is one too: 2^34 units = 16 gMDS.
/// **Proposed, not yet a consensus constant.**
pub const MIN_MINING_BOND: u64 = 1 << 34;

/// How many midstate blocks a bond must stay locked beyond the snapshot it is
/// judged at (30 days). This *is* the unbonding delay: a bond stops counting
/// this long before its owner can spend it, so neither chain has to track an
/// unbonding state. **Proposed, not yet a consensus constant.**
pub const MIN_REMAINING_BOND_LOCK: u64 = 30 * 24 * 60;

/// The locking script of a mining bond:
///
/// ```text
/// PUSH_DATA <mining key>    DROP              binds the key into the address
/// PUSH_INT  <bonded_until>  CHECKTIMEVERIFY   unspendable below that height
/// PUSH_DATA <owner key>     CHECKSIGVERIFY    only the owner can spend it
/// PUSH_INT  1
/// ```
///
/// Spent with one witness item, the owner's signature. The mining key plays
/// no part in execution, but a midstate address is the hash of its script, so
/// the address — and with it the coin id — commits to the key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BondScript {
    pub mining_key: [u8; 32],
    pub bonded_until: u64,
    pub owner_pk: [u8; 32],
}

fn push_data(bc: &mut Vec<u8>, data: &[u8]) {
    bc.push(OP_PUSH_DATA);
    bc.extend_from_slice(&(data.len() as u16).to_le_bytes());
    bc.extend_from_slice(data);
}

/// Midstate's minimal little-endian integer encoding (`script::from_u64`).
fn int_bytes(v: u64) -> Vec<u8> {
    let b = v.to_le_bytes();
    let mut len = 8;
    while len > 1 && b[len - 1] == 0 {
        len -= 1;
    }
    b[..len].to_vec()
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn op(&mut self, want: u8) -> Result<()> {
        if self.bytes.get(self.at) != Some(&want) {
            bail!("not a mining bond script");
        }
        self.at += 1;
        Ok(())
    }

    fn push(&mut self) -> Result<&'a [u8]> {
        self.op(OP_PUSH_DATA)?;
        let len = self
            .bytes
            .get(self.at..self.at + 2)
            .ok_or_else(|| anyhow!("truncated bond script"))?;
        let len = u16::from_le_bytes([len[0], len[1]]) as usize;
        self.at += 2;
        let data = self
            .bytes
            .get(self.at..self.at + len)
            .ok_or_else(|| anyhow!("truncated bond script"))?;
        self.at += len;
        Ok(data)
    }

    fn push32(&mut self) -> Result<[u8; 32]> {
        self.push()?
            .try_into()
            .map_err(|_| anyhow!("bond script key is not 32 bytes"))
    }
}

impl BondScript {
    pub fn to_bytecode(&self) -> Vec<u8> {
        let mut bc = Vec::with_capacity(83);
        push_data(&mut bc, &self.mining_key);
        bc.push(OP_DROP);
        push_data(&mut bc, &int_bytes(self.bonded_until));
        bc.push(OP_CHECKTIMEVERIFY);
        push_data(&mut bc, &self.owner_pk);
        bc.push(OP_CHECKSIGVERIFY);
        push_data(&mut bc, &int_bytes(1));
        bc
    }

    /// Recognises exactly the template. Any other script — including this one
    /// with extra opcodes or an integer written non-minimally — is not a bond,
    /// so every bond has one encoding and one address.
    pub fn parse(bytecode: &[u8]) -> Result<Self> {
        let mut r = Reader {
            bytes: bytecode,
            at: 0,
        };
        let mining_key = r.push32()?;
        r.op(OP_DROP)?;
        let until = r.push()?;
        if until.is_empty() || until.len() > 8 {
            bail!("bond lock height is not a u64");
        }
        let mut le = [0u8; 8];
        le[..until.len()].copy_from_slice(until);
        let bonded_until = u64::from_le_bytes(le);
        r.op(OP_CHECKTIMEVERIFY)?;
        let owner_pk = r.push32()?;
        r.op(OP_CHECKSIGVERIFY)?;
        let parsed = Self {
            mining_key,
            bonded_until,
            owner_pk,
        };
        // Re-encoding catches everything else at once: a missing or different
        // final push, trailing bytes, and non-minimal integers.
        if parsed.to_bytecode() != bytecode {
            bail!("not the canonical mining bond encoding");
        }
        Ok(parsed)
    }

    /// The midstate address holding the bond: the hash of its script.
    pub fn address(&self) -> [u8; 32] {
        hash(&self.to_bytecode())
    }
}

/// A midstate coin locked by a bond script.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BondCoin {
    pub script: BondScript,
    pub value: u64,
    pub salt: [u8; 32],
}

impl BondCoin {
    /// The midstate coin id, which also serves as the bond's id: unique per
    /// coin, so one bond cannot be counted twice.
    pub fn coin_id(&self) -> [u8; 32] {
        midstate_coin_id(&self.script.address(), self.value, &self.salt)
    }
}

/// What a midstate header's `state_root` commits to (midstate
/// `core/state.rs`, state-root validation):
///
/// ```text
/// state_root = H( H( H(coins, commitments), chain_mmr ), burned_wots )
/// ```
///
/// The chain MMR root is the one from *before* the block appended itself, and
/// the burned-WOTS term exists from V4 activation onwards. A proof server that
/// returned the node's current roots instead would hand out proofs that match
/// no header at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MidstateRoots {
    /// UTXO SMT root after the block's transactions and coinbase.
    pub coins: [u8; 32],
    pub commitments: [u8; 32],
    /// Chain MMR root before the block itself was appended.
    pub chain_mmr: [u8; 32],
    /// Present exactly when the header is at or above V4 activation.
    pub burned_wots: Option<[u8; 32]>,
}

impl MidstateRoots {
    /// The `state_root` a midstate header at `height` carries for these roots.
    pub fn state_root(&self, height: u64) -> Result<[u8; 32]> {
        let smt = hash_concat(&self.coins, &self.commitments);
        let root = hash_concat(&smt, &self.chain_mmr);
        match (height >= MIDSTATE_V4_ACTIVATION_HEIGHT, self.burned_wots) {
            (true, Some(burned)) => Ok(hash_concat(&root, &burned)),
            (false, None) => Ok(root),
            _ => bail!("burned-WOTS root does not fit a header at height {height}"),
        }
    }
}

/// Evidence that a bond coin was unspent in the midstate state committed by
/// one particular header.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BondProof {
    pub coin: BondCoin,
    /// Height of the midstate header the proof is against.
    pub midstate_height: u64,
    pub roots: MidstateRoots,
    pub smt: UtxoProof,
}

/// A bond proven to exist, unspent, at a midstate height.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bond {
    pub id: [u8; 32],
    pub mining_key: [u8; 32],
    pub value: u64,
    pub bonded_until: u64,
    pub proven_at: u64,
}

impl BondProof {
    /// Checks the bond coin is in the UTXO set that the midstate header at
    /// `midstate_height` commits to with `header_state_root`. Obtaining that
    /// header — and knowing it is the one midwimble consensus agreed on — is
    /// the caller's job.
    pub fn verify(&self, header_state_root: &[u8; 32]) -> Result<Bond> {
        if self.midstate_height < MIDSTATE_V2_ACTIVATION_HEIGHT {
            bail!("bonds are only recognised against midstate's V2 state");
        }
        if self.roots.state_root(self.midstate_height)? != *header_state_root {
            bail!("roots do not match the midstate header's state root");
        }
        let id = self.coin.coin_id();
        if !verify_utxo_proof(&id, &self.smt, &self.roots.coins, true) {
            bail!("bond coin is not in midstate's UTXO set at that height");
        }
        Ok(Bond {
            id,
            mining_key: self.coin.script.mining_key,
            value: self.coin.value,
            bonded_until: self.coin.script.bonded_until,
            proven_at: self.midstate_height,
        })
    }
}

impl Bond {
    /// Version-1 eligibility at an epoch's snapshot: proven against that very
    /// snapshot, large enough, and locked long enough beyond it. The value is a
    /// gate, never a weight — a bigger bond buys no more mining power.
    pub fn eligible_at(&self, snapshot_height: u64) -> bool {
        self.proven_at == snapshot_height
            && self.value >= MIN_MINING_BOND
            && self.bonded_until >= snapshot_height.saturating_add(MIN_REMAINING_BOND_LOCK)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::mmr::UtxoAccumulator;

    fn script() -> BondScript {
        BondScript {
            mining_key: [0x11; 32],
            bonded_until: 400_000,
            owner_pk: [0x22; 32],
        }
    }

    /// Computed with an independent BLAKE3 (Python `blake3`) from the byte
    /// layout midstate's own `push_data`/`push_int` produce. Midstate's side
    /// (`script::compile_mining_bond`) carries the same vector.
    #[test]
    fn golden_vector() {
        let bc = script().to_bytecode();
        assert_eq!(
            hex::encode(&bc),
            "0120001111111111111111111111111111111111111111111111111111111111111111\
             10010300801a0633012000222222222222222222222222222222222222222222222222\
             22222222222222223201010001"
        );
        assert_eq!(
            hex::encode(script().address()),
            "22fd4a4255a093856e1b4a714deb228676742accbe4e3145a6fbcb50f757b67f"
        );
        let coin = BondCoin {
            script: script(),
            value: 1 << 34,
            salt: [0x33; 32],
        };
        assert_eq!(
            hex::encode(coin.coin_id()),
            "55bc6798dad6d8bdb3b69263e8509db120146acb61c3fb5cb4be37aee8226429"
        );
    }

    #[test]
    fn parser_accepts_only_the_template() {
        let bc = script().to_bytecode();
        assert_eq!(BondScript::parse(&bc).unwrap(), script());
        for until in [0u64, 1, 255, 256, u64::MAX] {
            let s = BondScript {
                bonded_until: until,
                ..script()
            };
            assert_eq!(BondScript::parse(&s.to_bytecode()).unwrap(), s);
        }
        // Trailing opcode.
        let mut extra = bc.clone();
        extra.push(OP_DROP);
        assert!(BondScript::parse(&extra).is_err());
        // Lock height padded to four bytes: executes the same on midstate, but
        // would give one bond two addresses.
        let mut padded = Vec::new();
        push_data(&mut padded, &[0x11; 32]);
        padded.push(OP_DROP);
        push_data(&mut padded, &[0x80, 0x1a, 0x06, 0x00]);
        // Everything after the lock-height push: 35 (key) + 1 (DROP) + 6.
        padded.extend_from_slice(&bc[42..]);
        assert_eq!(bc[42], OP_CHECKTIMEVERIFY);
        assert!(BondScript::parse(&padded).is_err());
        // Truncated, and a different final push.
        assert!(BondScript::parse(&bc[..bc.len() - 1]).is_err());
        let mut two = bc.clone();
        *two.last_mut().unwrap() = 2;
        assert!(BondScript::parse(&two).is_err());
        assert!(BondScript::parse(&[]).is_err());
    }

    /// Builds a midstate-shaped UTXO set holding the bond and returns a proof
    /// plus the header state root it must verify against.
    fn proven(coin: &BondCoin, height: u64) -> (BondProof, [u8; 32]) {
        let mut coins = UtxoAccumulator::new();
        for i in 0..50u8 {
            coins.insert(hash(&[i]), true);
        }
        coins.insert(coin.coin_id(), true);
        let roots = MidstateRoots {
            coins: coins.root(true),
            commitments: hash(b"commitments"),
            chain_mmr: hash(b"chain mmr before the block"),
            burned_wots: (height >= MIDSTATE_V4_ACTIVATION_HEIGHT).then(|| hash(b"burned")),
        };
        let proof = BondProof {
            coin: *coin,
            midstate_height: height,
            roots,
            smt: coins.prove(&coin.coin_id(), true).unwrap(),
        };
        let header_root = roots.state_root(height).unwrap();
        (proof, header_root)
    }

    fn coin() -> BondCoin {
        BondCoin {
            script: script(),
            value: MIN_MINING_BOND,
            salt: [0x33; 32],
        }
    }

    #[test]
    fn proof_verifies_against_the_header_root() {
        let (proof, root) = proven(&coin(), 300_000);
        let bond = proof.verify(&root).unwrap();
        assert_eq!(bond.id, coin().coin_id());
        assert_eq!(bond.mining_key, [0x11; 32]);
        assert_eq!(bond.proven_at, 300_000);
        // Before V4 the burned-WOTS term is absent, and must be.
        let (early, early_root) = proven(&coin(), 150_000);
        early.verify(&early_root).unwrap();
    }

    #[test]
    fn tampering_is_caught() {
        let (proof, root) = proven(&coin(), 300_000);
        // Another header.
        assert!(proof.verify(&hash(b"another header")).is_err());
        // Claiming a different mining key, value or owner changes the coin id,
        // so the SMT path no longer leads to the committed root.
        for tampered in [
            BondCoin {
                script: BondScript {
                    mining_key: [0x99; 32],
                    ..script()
                },
                ..coin()
            },
            BondCoin {
                value: MIN_MINING_BOND * 2,
                ..coin()
            },
            BondCoin {
                script: BondScript {
                    bonded_until: 900_000,
                    ..script()
                },
                ..coin()
            },
        ] {
            let mut forged = proof.clone();
            forged.coin = tampered;
            assert!(forged.verify(&root).is_err());
        }
        // A pre-V4 shape presented for a post-V4 header, and vice versa.
        let mut shape = proof.clone();
        shape.roots.burned_wots = None;
        assert!(shape.verify(&root).is_err());
        // Below V2 bonds are not recognised at all.
        let mut ancient = proof;
        ancient.midstate_height = 99_999;
        assert!(ancient.verify(&root).is_err());
    }

    #[test]
    fn eligibility_is_a_gate() {
        let snapshot = 300_000;
        let bond = Bond {
            id: [0; 32],
            mining_key: [0x11; 32],
            value: MIN_MINING_BOND,
            bonded_until: snapshot + MIN_REMAINING_BOND_LOCK,
            proven_at: snapshot,
        };
        assert!(bond.eligible_at(snapshot));
        // Running down the lock is how a bond unbonds.
        assert!(!bond.eligible_at(snapshot + 1));
        assert!(!Bond {
            value: MIN_MINING_BOND / 2,
            ..bond
        }
        .eligible_at(snapshot));
        // A proof against any other midstate height says nothing about the
        // snapshot.
        assert!(!Bond {
            proven_at: snapshot - 1,
            ..bond
        }
        .eligible_at(snapshot));
    }
}
