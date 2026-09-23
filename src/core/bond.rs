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

use super::anchor::{header_pow_ok, HeaderLink};
use super::auxpow::midstate_coin_id;
use super::mmr::{verify_utxo_proof, UtxoProof};
use super::state::calculate_work;
use super::mw::crypto::{schnorr_sign, schnorr_verify, SchnorrSig};
use super::types::{
    compute_header_hash, fold_unsigned, hash, hash_concat, hash_domain, Batch, BatchHeader,
    NETWORK_MAGIC,
};
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
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

/// Smallest bond that grants eligibility, in midstate base units: 2^34
/// (16 gMDS) on mainnet. A launch parameter, so a testnet can set it low
/// enough that testers risk nothing (`types::LAUNCH_MIN_MINING_BOND`).
pub const MIN_MINING_BOND: u64 = super::types::LAUNCH_MIN_MINING_BOND;

/// How many midstate blocks a bond must stay locked beyond the height it is
/// judged at (30 days on mainnet). This *is* the unbonding delay: a bond
/// stops counting this long before its owner can spend it, so neither chain
/// has to track an unbonding state. Also a launch parameter, so a testnet's
/// bonds free up in a day or two.
pub const MIN_REMAINING_BOND_LOCK: u64 = super::types::LAUNCH_MIN_REMAINING_BOND_LOCK;

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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

/// Midstate's genesis time. Its ASERT, like midwimble's, is anchored here, so
/// its height tracks `(t − genesis) / 60` — running ahead of that by
/// `240 · log2(hashrate / calibration)` blocks, never behind it for long.
const MIDSTATE_GENESIS_TIMESTAMP: u64 = 1_772_274_770;

/// Pads the clock estimate of midstate's height by seven days, more than
/// midstate's lead over its schedule at any plausible hashrate (about 3,500
/// blocks at today's roughly 28,000 times its calibration).
pub const CLOCK_MARGIN: u64 = 7 * 24 * 60;

/// Midstate's height as judged from a midwimble block's timestamp, estimated
/// high on purpose: an error can only retire a bond early, never let it mine
/// after it could have been spent. Deterministic from midwimble's own chain,
/// so a stalled or unreachable midstate never stops a bonded miner.
pub fn est_midstate_height(timestamp: u64) -> u64 {
    timestamp.saturating_sub(MIDSTATE_GENESIS_TIMESTAMP) / 60 + CLOCK_MARGIN
}

impl Bond {
    /// Version-1 eligibility for a block with this timestamp: large enough,
    /// and still locked for at least `MIN_REMAINING_BOND_LOCK` beyond the
    /// estimated midstate height. Nothing can spend a bond before its lock
    /// height, so the proof it was registered with keeps holding until then.
    /// The value is a gate, never a weight: a bigger bond buys no more mining
    /// power.
    pub fn eligible_at(&self, block_timestamp: u64) -> bool {
        eligible(self.value, self.bonded_until, block_timestamp)
    }
}

fn eligible(value: u64, bonded_until: u64, block_timestamp: u64) -> bool {
    value >= MIN_MINING_BOND
        && bonded_until >= est_midstate_height(block_timestamp).saturating_add(MIN_REMAINING_BOND_LOCK)
}

// ── Registration ─────────────────────────────────────────────────────────────

/// A registration must show a day of work above its proof's header, measured
/// in blocks of the *registering midwimble block's own target*.
///
/// Why midwimble's target and not the midstate headers' own: those headers
/// are the registrant's to choose. On a private fork they could claim easy
/// targets and make "a day" cheap. Midwimble's target is consensus, cannot be
/// lowered without out-hashing midwimble, and is in the same units — both
/// chains run the same proof of work at the same 60-second spacing — so it
/// measures the merged hashrate. Faking a registration therefore costs at least
/// a day of midwimble's entire network's work, however midstate's block reward
/// has decayed.
pub const REGISTRATION_WORK_BLOCKS: u128 = 24 * 60;

/// No header counts for more than 1/60 of the requirement, so a registration
/// needs at least 60 headers' worth of real work. Without the cap, one
/// improbably lucky hash on a very hard target could stand in for the day.
pub const REGISTRATION_MIN_HEADERS: u128 = 60;

/// Bounds a registration's size (144 bytes a header) and verification cost (a
/// full extension per header). Honest runs are about `1440 × share` headers,
/// where `share` is midwimble's fraction of midstate's hashrate.
pub const REGISTRATION_MAX_HEADERS: usize = 4_000;

/// The work a registration in a block with this target must show.
pub fn registration_work(midwimble_target: &[u8; 32]) -> u128 {
    calculate_work(midwimble_target).saturating_mul(REGISTRATION_WORK_BLOCKS)
}

/// Work the headers `above` a bond's proof are credited with, towards a
/// registration in a block with `midwimble_target`: each counts for at most
/// 1/60 of the requirement.
pub fn credited_work(above: &[HeaderLink], midwimble_target: &[u8; 32]) -> u128 {
    let cap = (registration_work(midwimble_target) / REGISTRATION_MIN_HEADERS).max(1);
    above.iter().fold(0u128, |sum, h| {
        sum.saturating_add(calculate_work(&h.target).min(cap))
    })
}

/// A bond proof plus the midstate headers that bury it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BondRegistration {
    pub proof: BondProof,
    /// `prev_header_hash` of the proof's header.
    pub prev_header_hash: [u8; 32],
    /// The proof's header, then the midstate headers built on it.
    pub headers: Vec<HeaderLink>,
}

impl BondRegistration {
    /// Verifies a registration carried by a midwimble block with target
    /// `midwimble_target`. The cheap checks run first; each header's proof of
    /// work costs a full extension, so it is checked last, in chain order, and
    /// the first bad header stops it. Forcing that work on a node costs the
    /// sender a real header's worth of hashing each time.
    pub fn verify(&self, midwimble_target: &[u8; 32]) -> Result<Bond> {
        if self.headers.len() > REGISTRATION_MAX_HEADERS {
            bail!("registration carries more than {REGISTRATION_MAX_HEADERS} headers");
        }
        let (proven, above) = self
            .headers
            .split_first()
            .ok_or_else(|| anyhow!("registration carries no midstate headers"))?;
        let required = registration_work(midwimble_target);
        let credited = credited_work(above, midwimble_target);
        if credited < required {
            bail!(
                "{credited} units of midstate work above the bond's header; a block at this target requires {required}"
            );
        }
        let bond = self.proof.verify(&proven.state_root)?;
        let mut prev = self.prev_header_hash;
        for (i, header) in self.headers.iter().enumerate() {
            if !header_pow_ok(prev, header, 0) {
                bail!("midstate header {i} of the registration fails its proof of work");
            }
            prev = header.final_hash;
        }
        Ok(bond)
    }
}

// ── Bonded mining in consensus ──────────────────────────────────────────────

/// First height whose block must be authorised by a registered, eligible
/// bond. Genesis is fixed data that nobody mines, so bonded mining begins
/// with the first mined block.
#[cfg(not(feature = "fast-mining"))]
pub const BONDED_MINING_FROM: u64 = 1;
/// Test builds: an authorisation is optional, but checked in full whenever a
/// block carries one. Temporary, until the node, pool and merge miner sign
/// their templates and the integration tests mine bonded blocks.
#[cfg(feature = "fast-mining")]
pub const BONDED_MINING_FROM: u64 = u64::MAX;

/// A block carries at most one registration. A producer registers its own
/// bond in the first block it mines, and the cap bounds how much
/// verification any one block can demand.
pub const MAX_REGISTRATIONS_PER_BLOCK: usize = 1;

/// Registration weight: four units per 144-byte header and 256 for the ~8 KB
/// proof, in line with what transaction data weighs per byte.
const REGISTRATION_BASE_WEIGHT: u64 = 256;
const REGISTRATION_WEIGHT_PER_HEADER: u64 = 4;

/// A registered bond as the chain's state holds it, keyed by bond id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BondEntry {
    pub mining_key: [u8; 32],
    pub value: u64,
    pub bonded_until: u64,
}

impl BondEntry {
    /// See [`Bond::eligible_at`].
    pub fn eligible_at(&self, block_timestamp: u64) -> bool {
        eligible(self.value, self.bonded_until, block_timestamp)
    }
}

impl BondRegistration {
    /// The bond's id: its midstate coin id.
    pub fn bond_id(&self) -> [u8; 32] {
        self.proof.coin.coin_id()
    }

    /// The state entry this registration creates, once it has verified.
    pub fn entry(&self) -> BondEntry {
        BondEntry {
            mining_key: self.proof.coin.script.mining_key,
            value: self.proof.coin.value,
            bonded_until: self.proof.coin.script.bonded_until,
        }
    }

    pub fn weight(&self) -> u64 {
        REGISTRATION_BASE_WEIGHT + REGISTRATION_WEIGHT_PER_HEADER * self.headers.len() as u64
    }
}

/// A block's bonded-mining authorisation: the bond it is mined under, and
/// that bond's mining-key signature over [`authorization_message`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MinerAuth {
    pub bond_id: [u8; 32],
    pub signature: SchnorrSig,
}

impl MinerAuth {
    pub fn hash(&self) -> [u8; 32] {
        hash_domain(
            b"midwimble.miner-auth.v1",
            &[&self.bond_id, &self.signature.e, &self.signature.s],
        )
    }
}

/// What a bonded miner signs for `batch` on a chain whose midstate is
/// `prev_midstate`: the mining hash the block would have without its
/// authorisation. The signature covers every other byte of the block, and the
/// proof of work then covers the signature, so a found block cannot be
/// re-attributed to another bond. Merged mining keeps that property, because
/// the midstate parent commits to the full mining hash.
pub fn authorization_message(prev_midstate: &[u8; 32], batch: &Batch) -> [u8; 32] {
    let header = BatchHeader {
        height: 0,
        prev_header_hash: batch.prev_header_hash,
        prev_midstate: *prev_midstate,
        post_tx_midstate: fold_unsigned(prev_midstate, batch),
        extension: batch.extension.clone(),
        timestamp: batch.timestamp,
        target: batch.target,
        state_root: batch.state_root,
        aux_pow: None,
    };
    hash_domain(
        b"midwimble.block-authorisation.v1",
        &[&compute_header_hash(&header), NETWORK_MAGIC],
    )
}

/// Checks `batch`'s authorisation against the bond set, which already
/// includes any registration the block itself carries.
pub fn check_miner_authorization(
    bonds: &im::HashMap<[u8; 32], BondEntry>,
    prev_midstate: &[u8; 32],
    batch: &Batch,
) -> Result<()> {
    let auth = batch
        .miner
        .as_ref()
        .ok_or_else(|| anyhow!("block is not authorised by a mining bond"))?;
    let bond = bonds.get(&auth.bond_id).ok_or_else(|| {
        anyhow!("block is mined under an unregistered bond {}", hex::encode(auth.bond_id))
    })?;
    if !bond.eligible_at(batch.timestamp) {
        bail!(
            "bond {} is not eligible at this block's time (too small, or its lock ends too soon)",
            hex::encode(auth.bond_id)
        );
    }
    let message = authorization_message(prev_midstate, batch);
    if !schnorr_verify(&bond.mining_key, &message, &auth.signature) {
        bail!("the block's miner signature does not verify under its bond's mining key");
    }
    Ok(())
}

/// What a block producer needs in order to mine under a bond.
#[derive(Clone)]
pub struct MinerBond {
    pub secret: Scalar,
    pub bond_id: [u8; 32],
    /// The bond's registration, carried in this producer's blocks until the
    /// chain has it.
    pub registration: Option<BondRegistration>,
}

impl std::fmt::Debug for MinerBond {
    /// Never prints the secret.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MinerBond")
            .field("bond_id", &hex::encode(self.bond_id))
            .field("registered_here", &self.registration.is_some())
            .finish_non_exhaustive()
    }
}

impl MinerBond {
    pub fn mining_key(&self) -> [u8; 32] {
        RistrettoPoint::mul_base(&self.secret).compress().to_bytes()
    }

    pub fn sign(&self, message: &[u8; 32]) -> SchnorrSig {
        schnorr_sign(&self.secret, message)
    }
}

/// A registration for `mining_key` that meets the registration rule at
/// `midwimble_target`, over a throwaway midstate-shaped state and headers.
/// Fast-mining (devnet and test) builds only: it mines real headers with
/// short extensions, which a real network's registrations could never use.
#[cfg(feature = "fast-mining")]
pub fn devnet_registration(
    mining_key: [u8; 32],
    bonded_until: u64,
    salt: [u8; 32],
    midwimble_target: &[u8; 32],
) -> BondRegistration {
    use super::anchor::link_mining_hash;
    use super::extension::create_extension;
    use super::mmr::UtxoAccumulator;
    let coin = BondCoin {
        script: BondScript {
            mining_key,
            bonded_until,
            owner_pk: hash(b"test bond owner"),
        },
        value: MIN_MINING_BOND,
        salt,
    };
    let mut coins = UtxoAccumulator::new();
    for i in 0..8u8 {
        coins.insert(hash(&[i, 0xb0]), true);
    }
    coins.insert(coin.coin_id(), true);
    let height = 300_000;
    let roots = MidstateRoots {
        coins: coins.root(true),
        commitments: hash(b"commitments"),
        chain_mmr: hash(b"chain mmr"),
        burned_wots: Some(hash(b"burned")),
    };
    let proof = BondProof {
        coin,
        midstate_height: height,
        roots,
        smt: coins.prove(&coin.coin_id(), true).expect("the bond coin is a member"),
    };
    // Headers worth 256 units each, or the per-header cap if that is lower.
    let mut header_target = [0xffu8; 32];
    header_target[0] = 0;
    let required = registration_work(midwimble_target);
    let per = calculate_work(&header_target).min((required / REGISTRATION_MIN_HEADERS).max(1));
    let above = (required / per) as u64 + 1;
    let mine = |prev: [u8; 32], state_root: [u8; 32], i: u64| {
        let mut link = HeaderLink {
            post_tx_midstate: hash(&i.to_le_bytes()),
            state_root,
            timestamp: 1_800_000_000 + 60 * i,
            target: header_target,
            nonce: 0,
            final_hash: [0; 32],
        };
        let mining = link_mining_hash(prev, &link);
        loop {
            let fin = create_extension(mining, link.nonce).final_hash;
            if fin < header_target {
                link.final_hash = fin;
                return link;
            }
            link.nonce += 1;
        }
    };
    let prev = hash(b"the header below the bond's");
    let mut headers = vec![mine(prev, roots.state_root(height).unwrap(), 0)];
    for i in 1..=above {
        let last = headers.last().unwrap().final_hash;
        headers.push(mine(last, hash(&i.to_be_bytes()), i));
    }
    BondRegistration {
        proof,
        prev_header_hash: prev,
        headers,
    }
}

// ── The producer's bond file and midstate RPC parsing ──────────────────────

/// What a block producer keeps on disk (`midwimble node --mining-bond`): the
/// mining secret and, as `midwimble bond register` fills them in, the bond
/// coin, the proof taken against midstate's tip, and the finished
/// registration. Guard it like a wallet key: whoever holds it can mine as the
/// bond (though never spend it; that takes the owner's midstate key).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct BondFile {
    /// Mining secret, hex.
    pub secret: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coin: Option<BondCoin>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<BondProof>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registration: Option<BondRegistration>,
}

impl BondFile {
    pub fn generate() -> Self {
        Self {
            secret: hex::encode(super::mw::crypto::random_scalar().to_bytes()),
            ..Self::default()
        }
    }

    pub fn secret(&self) -> Result<Scalar> {
        let bytes: [u8; 32] = hex::decode(&self.secret)?
            .try_into()
            .map_err(|_| anyhow!("bond file secret must be 32 bytes"))?;
        super::mw::crypto::scalar_from_bytes(&bytes)
            .ok_or_else(|| anyhow!("bond file secret is not a canonical scalar"))
    }

    pub fn mining_key(&self) -> Result<[u8; 32]> {
        Ok(RistrettoPoint::mul_base(&self.secret()?).compress().to_bytes())
    }

    /// What the node mines with. Needs a finished registration.
    pub fn miner_bond(&self) -> Result<MinerBond> {
        let registration = self.registration.clone().ok_or_else(|| {
            anyhow!("this bond is not registered yet: finish `midwimble bond register` first")
        })?;
        let bond = MinerBond {
            secret: self.secret()?,
            bond_id: registration.bond_id(),
            registration: Some(registration),
        };
        let registered_key = bond.registration.as_ref().unwrap().proof.coin.script.mining_key;
        if bond.mining_key() != registered_key {
            bail!("this file's secret is not the registered bond's mining key");
        }
        Ok(bond)
    }
}

/// One header of midstate's `GET /headers` response, as a link plus the hash
/// of the header before it.
pub fn header_link_from_json(h: &serde_json::Value) -> Result<(HeaderLink, [u8; 32])> {
    use super::auxpow::bytes32;
    let u64_of = |v: &serde_json::Value| {
        v.as_u64().ok_or_else(|| anyhow!("midstate header field is not a u64"))
    };
    let link = HeaderLink {
        post_tx_midstate: bytes32(&h["post_tx_midstate"])?,
        state_root: bytes32(&h["state_root"])?,
        timestamp: u64_of(&h["timestamp"])?,
        target: bytes32(&h["target"])?,
        nonce: u64_of(&h["extension"]["nonce"])?,
        final_hash: bytes32(&h["extension"]["final_hash"])?,
    };
    Ok((link, bytes32(&h["prev_header_hash"])?))
}

/// A bond proof from midstate's `GET /utxo_proof/:coin_id` response.
pub fn bond_proof_from_json(coin: BondCoin, v: &serde_json::Value) -> Result<BondProof> {
    use super::auxpow::bytes32;
    if let Some(e) = v.get("error") {
        bail!("midstate refused the proof: {e}");
    }
    let roots = MidstateRoots {
        coins: bytes32(&v["coins_root"])?,
        commitments: bytes32(&v["commitments_root"])?,
        chain_mmr: bytes32(&v["chain_mmr_root"])?,
        burned_wots: match &v["burned_wots_root"] {
            serde_json::Value::Null => None,
            b => Some(bytes32(b)?),
        },
    };
    Ok(BondProof {
        coin,
        midstate_height: v["height"]
            .as_u64()
            .ok_or_else(|| anyhow!("proof has no height"))?,
        roots,
        smt: serde_json::from_value(v["proof"].clone())?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::mmr::UtxoAccumulator;

    /// A real midstate mainnet header, height 297691, checked against its
    /// predecessor's hash with the exact code registrations use. Production
    /// builds only: it needs the real million-step extension.
    #[cfg(not(feature = "fast-mining"))]
    #[test]
    fn verifies_a_real_midstate_header() {
        let prev = [
            0, 0, 0, 69, 80, 103, 194, 112, 22, 147, 243, 28, 0, 248, 178, 198, 115, 71, 111,
            209, 96, 194, 254, 189, 159, 129, 242, 85, 223, 228, 248, 243,
        ];
        let mut target = [255u8; 32];
        target[..6].copy_from_slice(&[0, 0, 4, 193, 32, 127]);
        let link = HeaderLink {
            post_tx_midstate: [
                77, 173, 143, 201, 58, 55, 42, 180, 120, 49, 199, 104, 109, 234, 237, 174, 168,
                31, 199, 241, 102, 160, 92, 127, 150, 150, 136, 33, 175, 108, 75, 79,
            ],
            state_root: [
                84, 171, 15, 189, 239, 148, 177, 127, 181, 83, 162, 142, 181, 144, 7, 138, 72,
                17, 227, 169, 3, 9, 21, 136, 138, 20, 150, 166, 46, 120, 122, 200,
            ],
            timestamp: 1_789_993_393,
            target,
            nonce: 9_297_194_912_428,
            final_hash: [
                0, 0, 0, 102, 168, 40, 225, 155, 113, 82, 165, 33, 248, 48, 166, 12, 34, 149,
                135, 177, 254, 193, 74, 112, 88, 28, 39, 93, 45, 106, 77, 205,
            ],
        };
        assert!(header_pow_ok(prev, &link, 0));
        let mut flipped = link.clone();
        flipped.state_root[31] ^= 1;
        assert!(!header_pow_ok(prev, &flipped, 0));
    }

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

    /// The bond size and lock are launch parameters now, so a build can be
    /// given bad ones. These are the properties every build must keep, and
    /// the reason `types.rs` refuses the worst of them at compile time.
    #[test]
    fn bond_parameters_stay_usable() {
        assert_eq!(
            MIN_MINING_BOND.count_ones(),
            1,
            "a bond is one midstate coin, and coin values are powers of two"
        );
        assert!(MIN_MINING_BOND >= 1 << 20, "a bond has to cost something");
        assert!(
            MIN_REMAINING_BOND_LOCK >= 24 * 60,
            "the unbonding delay must outlast a reorg"
        );
        // Eligibility follows whatever this build was given, both ways.
        let t = 1_800_000_000;
        let bond = Bond {
            id: [0; 32],
            mining_key: [0x11; 32],
            value: MIN_MINING_BOND,
            bonded_until: est_midstate_height(t) + MIN_REMAINING_BOND_LOCK,
            proven_at: 300_000,
        };
        assert!(bond.eligible_at(t));
        assert!(!bond.eligible_at(t + 60), "the lock runs down");
        assert!(!Bond {
            value: MIN_MINING_BOND / 2,
            ..bond
        }
        .eligible_at(t));
    }

    #[test]
    fn eligibility_is_a_gate() {
        let t = 1_800_000_000;
        let bond = Bond {
            id: [0; 32],
            mining_key: [0x11; 32],
            value: MIN_MINING_BOND,
            bonded_until: est_midstate_height(t) + MIN_REMAINING_BOND_LOCK,
            proven_at: 300_000,
        };
        assert!(bond.eligible_at(t));
        // A minute later one more block of the lock has run down: that is how
        // a bond unbonds, with no state to track.
        assert!(!bond.eligible_at(t + 60));
        assert!(!Bond {
            value: MIN_MINING_BOND / 2,
            ..bond
        }
        .eligible_at(t));
        // The clock runs a week ahead of midstate's nominal schedule.
        assert_eq!(est_midstate_height(MIDSTATE_GENESIS_TIMESTAMP), CLOCK_MARGIN);
    }

    /// Registrations mine real midstate-style headers, so these run with the
    /// test build's short extensions.
    #[cfg(feature = "fast-mining")]
    mod registration {
        use super::*;
        use crate::core::anchor::link_mining_hash;
        use crate::core::extension::create_extension;

        /// About 64 units of work per header.
        const HEADER_TARGET: [u8; 32] = {
            let mut t = [0xff; 32];
            t[0] = 0x03;
            t
        };
        /// 3 units of work: a day is 4,320 units, capped at 72 a header, so 68
        /// ordinary headers are enough and 60 are not.
        const MW_TARGET: [u8; 32] = {
            let mut t = [0; 32];
            t[0] = 0x40;
            t
        };

        fn mine(prev: [u8; 32], state_root: [u8; 32], target: [u8; 32], i: u64) -> HeaderLink {
            let mut link = HeaderLink {
                post_tx_midstate: hash(&i.to_le_bytes()),
                state_root,
                timestamp: 1_800_000_000 + 60 * i,
                target,
                nonce: 0,
                final_hash: [0; 32],
            };
            let mining = link_mining_hash(prev, &link);
            loop {
                let fin = create_extension(mining, link.nonce).final_hash;
                if fin < target {
                    link.final_hash = fin;
                    return link;
                }
                link.nonce += 1;
            }
        }

        /// The bond's proof header, with `n` ordinary headers on top.
        fn registration(n: u64) -> BondRegistration {
            let (proof, root) = proven(&coin(), 300_000);
            let prev = hash(b"the header below the proof's");
            let mut headers = vec![mine(prev, root, HEADER_TARGET, 0)];
            for i in 1..=n {
                let last = headers.last().unwrap().final_hash;
                headers.push(mine(last, hash(&i.to_be_bytes()), HEADER_TARGET, i));
            }
            BondRegistration {
                proof,
                prev_header_hash: prev,
                headers,
            }
        }

        #[test]
        fn a_day_of_work_registers_the_bond() {
            assert_eq!(registration_work(&MW_TARGET), 4_320);
            let bond = registration(70).verify(&MW_TARGET).unwrap();
            assert_eq!(bond.id, coin().coin_id());
            assert_eq!(bond.mining_key, [0x11; 32]);
        }

        #[test]
        fn less_than_a_day_does_not() {
            assert!(registration(60).verify(&MW_TARGET).is_err());
        }

        /// The yardstick is the registering block's own target: the same
        /// headers fall short once midwimble's hashrate has doubled.
        #[test]
        fn the_bar_rises_with_midwimbles_hashrate() {
            let mut harder = MW_TARGET;
            harder[0] = 0x20;
            assert!(registration(70).verify(&harder).is_err());
        }

        #[test]
        fn one_lucky_header_cannot_carry_the_day() {
            let mut reg = registration(59);
            let last = reg.headers.last().unwrap().final_hash;
            let mut hard = [0xffu8; 32];
            hard[0] = 0;
            hard[1] = 0x03;
            // Uncapped, this one header would be worth several days.
            reg.headers.push(mine(last, hash(b"lucky"), hard, 60));
            assert!(calculate_work(&hard) > registration_work(&MW_TARGET));
            assert!(reg.verify(&MW_TARGET).is_err());
        }

        #[test]
        fn broken_links_bad_work_and_wrong_roots_are_caught() {
            let good = registration(70);
            let mut swapped = good.clone();
            swapped.headers.swap(10, 11);
            assert!(swapped.verify(&MW_TARGET).is_err());
            let mut forged = good.clone();
            forged.headers[30].nonce ^= 1;
            assert!(forged.verify(&MW_TARGET).is_err());
            let mut elsewhere = good.clone();
            elsewhere.headers[0].state_root = hash(b"another state");
            assert!(elsewhere.verify(&MW_TARGET).is_err());
            let mut bloated = good.clone();
            let extra = good.headers[1].clone();
            bloated
                .headers
                .extend(std::iter::repeat(extra).take(REGISTRATION_MAX_HEADERS));
            assert!(bloated.verify(&MW_TARGET).is_err());
        }
    }
}
