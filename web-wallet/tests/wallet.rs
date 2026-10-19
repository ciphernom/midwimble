//! The browser wallet against real (fast-mining) chains and the CLI wallet.

use midwimble::core::mw::{Context, StealthAddress, Transaction, WalletKeys};
use midwimble::core::state::apply_batch;
use midwimble::core::template::build_template;
use midwimble::core::types::{block_reward, COINBASE_MATURITY};
use midwimble::core::{Batch, State};
use midwimble_web_wallet::wallet::{self, BuiltSend, IncomingView, WalletCore, REORG};
use std::collections::HashSet;

const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
    abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
    abandon abandon abandon abandon abandon art";

/// A chain built block by block, as a node would hold it.
#[derive(Clone)]
struct Chain {
    state: State,
    ts: Vec<u64>,
    blocks: Vec<Batch>,
}

impl Chain {
    fn new() -> Self {
        let mut state = State::genesis();
        apply_batch(&mut state, Batch::genesis(), &[]).unwrap();
        Chain {
            state,
            ts: vec![Batch::genesis().timestamp],
            blocks: vec![Batch::genesis().clone()],
        }
    }

    fn mine(&mut self, to: &StealthAddress, txs: &[Transaction]) -> &Batch {
        let b = build_template(&self.state, &self.ts, txs, to, None)
            .unwrap()
            .mine_blocking();
        apply_batch(&mut self.state, &b, &self.ts).unwrap();
        self.ts.push(b.timestamp);
        self.blocks.push(b);
        self.blocks.last().unwrap()
    }

    fn mine_to_stranger(&mut self, n: usize) {
        let stranger = WalletKeys::random().address();
        for _ in 0..n {
            self.mine(&stranger, &[]);
        }
    }

    /// The next block's height, which is what `get_state` reports.
    fn tip(&self) -> u64 {
        self.state.height
    }

    /// Feeds the wallet every block it has not scanned, through the same
    /// hex bincode the light protocol carries.
    fn sync(&self, w: &mut WalletCore) {
        while w.scanned_height() < self.blocks.len() as u64 {
            let h = w.scanned_height();
            let hex = hex::encode(bincode::serialize(&self.blocks[h as usize]).unwrap());
            w.scan_block(h, &wallet::block_from_hex(&hex).unwrap())
                .unwrap();
        }
    }
}

const OTHER: &str = "legal winner thank year wave sausage worth useful legal winner thank year \
    wave sausage worth useful legal winner thank year wave sausage worth title";

fn tx_of(sent: &BuiltSend) -> Transaction {
    bincode::deserialize(&hex::decode(&sent.tx_hex).unwrap()).unwrap()
}

/// What `get_mempool` lists for a mempool holding `txs`.
fn live(txs: &[&Transaction]) -> HashSet<String> {
    txs.iter().map(|t| hex::encode(t.hash())).collect()
}

fn web_wallet(phrase: &str, height: u32, birth: u64) -> WalletCore {
    let key = wallet::recovery_key(phrase, height).unwrap();
    WalletCore::new(phrase, key, height, birth).unwrap()
}

#[test]
fn the_recovery_key_built_in_pieces_is_the_clis() {
    let master = wallet::recovery_master_seed(PHRASE).unwrap();
    let mut leaves = wallet::recovery_leaves(&master, 0, 2);
    leaves.extend(wallet::recovery_leaves(&master, 2, 2));
    let pieces = wallet::recovery_root(&leaves).unwrap();
    assert_eq!(pieces, wallet::recovery_key(PHRASE, 2).unwrap());

    // ...and so the address is the one `midwimble wallet restore` shows.
    let dir = tempfile::tempdir().unwrap();
    let cli =
        midwimble::wallet::Wallet::restore(&dir.path().join("w.mww"), "pw", PHRASE, 0, 2).unwrap();
    let web = WalletCore::new(PHRASE, pieces, 2, 0).unwrap();
    assert_eq!(web.address(), cli.address());
    assert_eq!(web.view_key(), cli.view_key().encode());
}

#[test]
fn typed_phrases_are_normalized_and_checked() {
    let shouted = PHRASE.to_uppercase().replace(' ', "  \n ");
    assert_eq!(
        wallet::normalize_mnemonic(&shouted).unwrap(),
        PHRASE.split_whitespace().collect::<Vec<_>>().join(" ")
    );
    let typo = PHRASE.replace("art", "arts");
    assert!(wallet::normalize_mnemonic(&typo).is_err());
    let fresh = wallet::generate_mnemonic();
    assert_eq!(fresh.split(' ').count(), 24);
    assert_eq!(wallet::normalize_mnemonic(&fresh).unwrap(), fresh);
}

#[test]
fn fees_match_the_cli() {
    for n in 0..20 {
        assert_eq!(
            wallet::suggested_fee(n),
            midwimble::wallet::suggested_fee(n)
        );
    }
}

#[test]
fn receives_matures_sends_and_confirms() {
    let mut chain = Chain::new();
    let mut w = web_wallet(PHRASE, 1, 0);
    let me = w.address();
    chain.mine(&me, &[]);
    chain.mine(&me, &[]);
    chain.sync(&mut w);
    let reward = block_reward(1) + block_reward(2);
    assert_eq!(w.balance(chain.tip()).immature, reward);
    assert_eq!(w.balance(chain.tip()).spendable, 0);
    assert!(
        w.quote(1, chain.tip()).is_err(),
        "coinbase is not mature yet"
    );

    chain.mine_to_stranger(COINBASE_MATURITY as usize);
    chain.sync(&mut w);
    let b = w.balance(chain.tip());
    assert_eq!((b.spendable, b.immature, b.pending), (reward, 0, 0));

    // One coin covers it: one input, change back.
    let bob = WalletKeys::random();
    let q = w.quote(1_000, chain.tip()).unwrap();
    assert_eq!((q.inputs, q.fee), (1, wallet::suggested_fee(1)));
    let sent = w
        .build_send(
            &bob.address().encode(),
            1_000,
            None,
            chain.tip(),
            1_700_000_000,
        )
        .unwrap();
    assert_eq!(sent.fee, q.fee);
    let tx: Transaction = bincode::deserialize(&hex::decode(&sent.tx_hex).unwrap()).unwrap();
    tx.validate(Context::Relay).unwrap();
    assert_eq!(hex::encode(tx.hash()), sent.tx_hash);
    let b = w.balance(chain.tip());
    assert_eq!(b.pending, block_reward(2).max(block_reward(1)));
    assert_eq!(w.pending_txs().len(), 1);

    let confirmed_at = chain.tip();
    chain.mine(&WalletKeys::random().address(), &[tx]);
    let block = chain.blocks.last().unwrap().clone();
    let report = w.scan_block(confirmed_at, &block).unwrap();
    assert_eq!(report.confirmed, vec![sent.tx_hash.clone()]);
    assert!(
        report.received.is_empty(),
        "change is not news: {:?}",
        report.received
    );
    chain.sync(&mut w);
    assert!(w.pending_txs().is_empty());
    let b = w.balance(chain.tip());
    assert_eq!(b.pending, 0);
    assert_eq!(b.spendable, reward - 1_000 - sent.fee);

    // History: two rewards (one now spent), and the payment with its change
    // folded in.
    let history = w.history(chain.tip());
    let payment = history.iter().find(|e| e.kind == "sent").unwrap();
    assert_eq!(
        (
            payment.status,
            payment.height,
            payment.value,
            payment.fee,
            payment.detailed
        ),
        ("confirmed", Some(confirmed_at), 1_000, Some(sent.fee), true)
    );
    assert_eq!(payment.to.as_deref(), Some(bob.address().encode().as_str()));
    assert_eq!(history.iter().filter(|e| e.kind == "mined").count(), 2);
    assert_eq!(
        history.iter().filter(|e| e.kind == "received").count(),
        0,
        "change is not income"
    );

    // A restored copy sees the same money, and the payment without details.
    let mut restored = web_wallet(PHRASE, 1, 0);
    chain.sync(&mut restored);
    assert_eq!(restored.balance(chain.tip()), w.balance(chain.tip()));
    let h = restored.history(chain.tip());
    let net = h.iter().find(|e| e.kind == "sent").unwrap();
    assert_eq!(
        (net.value, net.detailed, net.height),
        (1_000 + sent.fee, false, Some(confirmed_at))
    );
    assert_eq!(h.iter().filter(|e| e.kind == "received").count(), 0);
}

#[test]
fn spends_everything_and_refuses_more() {
    let mut chain = Chain::new();
    let mut w = web_wallet(PHRASE, 1, 0);
    let me = w.address();
    for _ in 0..3 {
        chain.mine(&me, &[]);
    }
    chain.mine_to_stranger(COINBASE_MATURITY as usize);
    chain.sync(&mut w);
    let all = w.balance(chain.tip()).spendable;
    let max = w.max_sendable(chain.tip());
    assert_eq!(max, all - wallet::suggested_fee(3));
    let to = WalletKeys::random().address().encode();
    assert!(w.build_send(&to, max + 1, None, chain.tip(), 0).is_err());
    let sent = w.build_send(&to, max, None, chain.tip(), 0).unwrap();
    assert_eq!((sent.inputs, sent.change), (3, 0));
    assert_eq!(w.balance(chain.tip()).spendable, 0);
    assert!(
        w.build_send(&to, 1, None, chain.tip(), 0).is_err(),
        "coins are reserved"
    );

    // A refused payment is forgotten and its coins come back.
    w.discard_send(&sent.tx_hash);
    assert_eq!(w.balance(chain.tip()).spendable, all);
    assert!(w.history(chain.tip()).iter().all(|e| e.kind != "sent"));

    // A cancelled one stays in history, and still confirms if it is mined.
    let sent = w.build_send(&to, 5_000, None, chain.tip(), 0).unwrap();
    w.cancel_pending(&sent.tx_hash);
    assert_eq!(w.balance(chain.tip()).spendable, all);
    assert!(w.pending_txs().is_empty());
    let tx: Transaction = bincode::deserialize(&hex::decode(&sent.tx_hex).unwrap()).unwrap();
    chain.mine(&WalletKeys::random().address(), &[tx]);
    chain.sync(&mut w);
    let e = w
        .history(chain.tip())
        .into_iter()
        .find(|e| e.kind == "sent")
        .unwrap();
    assert_eq!(e.status, "confirmed");
    assert_eq!(w.balance(chain.tip()).spendable, all - 5_000 - sent.fee);
}

#[test]
fn a_payment_beaten_by_another_copy_fails() {
    let mut chain = Chain::new();
    let mut a = web_wallet(PHRASE, 1, 0);
    let mut b = web_wallet(PHRASE, 1, 0);
    let me = a.address();
    chain.mine(&me, &[]);
    chain.mine_to_stranger(COINBASE_MATURITY as usize);
    chain.sync(&mut a);
    chain.sync(&mut b);
    let to = WalletKeys::random().address().encode();
    let lost = a.build_send(&to, 7_000, None, chain.tip(), 0).unwrap();
    let won = b.build_send(&to, 9_000, None, chain.tip(), 0).unwrap();
    let tx: Transaction = bincode::deserialize(&hex::decode(&won.tx_hex).unwrap()).unwrap();
    chain.mine(&WalletKeys::random().address(), &[tx]);
    chain.sync(&mut a);
    let e = a
        .history(chain.tip())
        .into_iter()
        .find(|e| e.tx_hash.as_deref() == Some(&lost.tx_hash))
        .unwrap();
    assert_eq!(e.status, "failed");
    assert!(a.pending_txs().is_empty());
    // The other copy's payment shows as an undetailed one, with its change.
    let spent = a
        .history(chain.tip())
        .into_iter()
        .find(|e| e.kind == "sent" && !e.detailed)
        .unwrap();
    assert_eq!(spent.value, 9_000 + won.fee);
    chain.sync(&mut b);
    assert_eq!(a.balance(chain.tip()), b.balance(chain.tip()));
    assert!(a.balance(chain.tip()).spendable > 0);
}

#[test]
fn reorgs_are_noticed_and_rolled_back() {
    let mut chain = Chain::new();
    let mut w = web_wallet(PHRASE, 1, 0);
    let me = w.address();
    chain.mine(&me, &[]);
    chain.mine(&me, &[]);
    chain.sync(&mut w);
    assert_eq!(w.scanned_height(), 3);

    // Another chain from genesis: its block 3 does not build on our block 2.
    let mut other = Chain::new();
    other.mine_to_stranger(3);
    let err = w.scan_block(3, &other.blocks[3]).unwrap_err().to_string();
    assert!(err.starts_with(REORG), "{err}");
    assert_eq!(w.scanned_height(), 3, "nothing applied");

    w.rollback_to(1);
    assert_eq!(w.scanned_height(), 1);
    assert_eq!(w.balance(chain.tip()).immature, 0);
    other.sync(&mut w);
    assert_eq!(w.scanned_height(), 4);
    assert_eq!(w.balance(other.tip()), wallet::Balance::default());

    // A wallet born later never looks at earlier blocks.
    let late = web_wallet(PHRASE, 1, 2);
    assert_eq!(late.scanned_height(), 2);
}

#[test]
fn wallet_files_move_between_cli_and_browser() {
    let dir = tempfile::tempdir().unwrap();
    let mut chain = Chain::new();

    // CLI → browser.
    let cli_path = dir.path().join("cli.mww");
    let (mut cli, phrase) = midwimble::wallet::Wallet::create(&cli_path, "hunter2", 1).unwrap();
    chain.mine(&cli.address(), &[]);
    chain.mine_to_stranger(COINBASE_MATURITY as usize);
    let blocks = chain.blocks.clone();
    cli.sync_with(chain.tip(), |s, n| {
        Ok(blocks
            .iter()
            .skip(s as usize)
            .take(n as usize)
            .cloned()
            .collect())
    })
    .unwrap();
    cli.save().unwrap();
    let file = std::fs::read(&cli_path).unwrap();
    let salt = wallet::file_salt(&file).unwrap();
    let key = wallet::derive_file_key("hunter2", &salt).unwrap();
    let wrong = wallet::derive_file_key("hunter3", &salt).unwrap();
    assert!(WalletCore::open(&file, &wrong).is_err());
    let mut web = WalletCore::open(&file, &key).unwrap();
    assert_eq!(web.mnemonic(), phrase);
    assert_eq!(web.address(), cli.address());
    assert_eq!(web.scanned_height(), chain.tip());
    assert_eq!(
        web.balance(chain.tip()).spendable,
        cli.balance(chain.tip()).spendable
    );
    assert!(web.balance(chain.tip()).spendable > 0);

    // The browser keeps going, then hands the file back.
    let to = WalletKeys::random().address().encode();
    let sent = web.build_send(&to, 2_500, None, chain.tip(), 0).unwrap();
    let tx: Transaction = bincode::deserialize(&hex::decode(&sent.tx_hex).unwrap()).unwrap();
    chain.mine(&WalletKeys::random().address(), &[tx]);
    chain.sync(&mut web);
    let sealed = web.seal(&key, &salt).unwrap();
    assert_ne!(sealed, file);
    let back_path = dir.path().join("back.mww");
    std::fs::write(&back_path, &sealed).unwrap();
    let back = midwimble::wallet::Wallet::open(&back_path, "hunter2").unwrap();
    assert_eq!(back.address(), web.address());
    assert_eq!(back.scanned_height(), web.scanned_height());
    assert_eq!(
        back.balance(chain.tip()).spendable,
        web.balance(chain.tip()).spendable
    );

    // And the browser reopens its own file, history included.
    let again = WalletCore::open(&sealed, &key).unwrap();
    assert_eq!(again.history(chain.tip()), web.history(chain.tip()));
    assert!(again
        .history(chain.tip())
        .iter()
        .any(|e| e.kind == "sent" && e.detailed));
}

/// The chain's unspent outputs as `get_utxos` lists them.
fn unspent_json(chain: &Chain) -> String {
    let mut live: Vec<(midwimble::core::mw::Output, u64, bool)> = Vec::new();
    for (h, b) in chain.blocks.iter().enumerate() {
        let spent: Vec<_> = b.body.input_commitments().copied().collect();
        live.retain(|(o, _, _)| !spent.contains(&o.commitment));
        live.extend(b.body.outputs().map(|o| (o.clone(), h as u64, false)));
        if let Some(cb) = &b.coinbase {
            live.extend(
                cb.outputs
                    .outputs
                    .iter()
                    .map(|o| (o.clone(), h as u64, true)),
            );
        }
    }
    let entries: Vec<_> = live
        .iter()
        .map(|(o, h, cb)| {
            serde_json::json!({
                "output_hex": hex::encode(bincode::serialize(o).unwrap()),
                "height": h,
                "coinbase": cb,
            })
        })
        .collect();
    serde_json::to_string(&entries).unwrap()
}

#[test]
fn restores_from_a_pruned_node_by_its_unspent_outputs() {
    let mut chain = Chain::new();
    let mut w = web_wallet(PHRASE, 1, 0);
    let me = w.address();
    chain.mine(&me, &[]);
    chain.mine(&me, &[]);
    chain.mine_to_stranger(COINBASE_MATURITY as usize);
    chain.sync(&mut w);
    let to = WalletKeys::random().address().encode();
    let sent = w.build_send(&to, 3_000, None, chain.tip(), 0).unwrap();
    let tx: Transaction = bincode::deserialize(&hex::decode(&sent.tx_hex).unwrap()).unwrap();
    chain.mine(&WalletKeys::random().address(), &[tx]);

    // The sender catches up from the UTXO set alone: its payment confirms.
    let utxos = wallet::unspent_from_json(&unspent_json(&chain)).unwrap();
    let r = w.scan_unspent(&utxos, chain.tip());
    assert_eq!(r.confirmed, vec![sent.tx_hash.clone()]);
    assert_eq!(r.spent.len(), 1);
    assert_eq!(w.scanned_height(), chain.tip());

    // A restore sees the same coins, and carries on scanning blocks.
    let mut restored = web_wallet(PHRASE, 1, 0);
    restored.scan_unspent(&utxos, chain.tip());
    assert_eq!(restored.balance(chain.tip()), w.balance(chain.tip()));
    chain.mine(&me, &[]);
    chain.sync(&mut restored);
    chain.sync(&mut w);
    assert_eq!(restored.balance(chain.tip()), w.balance(chain.tip()));
    assert!(restored.balance(chain.tip()).immature > 0);
}

#[test]
fn foreign_files_and_blocks_are_refused() {
    assert!(wallet::file_salt(b"not a wallet").is_err());
    assert!(wallet::block_from_hex("zz").is_err());
    assert!(wallet::block_from_hex("00").is_err());
    assert!(wallet::check_address("mw1notanaddress").is_err());
    let w = web_wallet(PHRASE, 1, 0);
    assert!(wallet::check_address(&w.address().encode()).is_ok());
    assert!(
        wallet::check_address(&w.view_key()).is_err(),
        "a view key is not an address"
    );
}

/// The address `midwimble wallet restore` prints for `PHRASE` at the default
/// recovery height (checked against the CLI and the WebAssembly build).
#[test]
#[ignore = "builds a whole recovery key: up to a minute"]
fn the_default_address_is_the_clis() {
    const CLI_ADDRESS: &str = "mw1qy4p3k3lesjmw6zp5w7ucxhk0avp829fc6gxsnp0jvw54s9k0y4ry98thq0j3kudjj0qjprg68cydv86y40g3u97750mdj6x8qru2srxg9j0zh4wtqz7ewc9xg4hs6daq34qmlma4x2y23ew6p5ckzfx238sy692x6";
    let height = midwimble::core::recovery::DEFAULT_RECOVERY_HEIGHT;
    let master = wallet::recovery_master_seed(PHRASE).unwrap();
    let key = wallet::recovery_root(&wallet::recovery_leaves(&master, 0, 1 << height)).unwrap();
    let w = WalletCore::new(PHRASE, key, height, 0).unwrap();
    assert_eq!(w.address().encode(), CLI_ADDRESS);
}

#[test]
fn payments_waiting_in_the_mempool_show_as_incoming() {
    let mut chain = Chain::new();
    let mut me = web_wallet(PHRASE, 1, 0);
    let mut alice = web_wallet(OTHER, 1, 0);
    chain.mine(&alice.address(), &[]);
    chain.mine_to_stranger(COINBASE_MATURITY as usize);
    chain.sync(&mut me);
    chain.sync(&mut alice);

    // Alice pays me; her transaction waits in the mempool.
    let paid = alice
        .build_send(&me.address().encode(), 5_000, None, chain.tip(), 0)
        .unwrap();
    let tx = tx_of(&paid);
    let pool = live(&[&tx]);
    let seen = me.scan_mempool(&[tx.clone()], &pool, 100);
    assert_eq!(
        seen,
        vec![IncomingView {
            tx_hash: paid.tx_hash.clone(),
            value: 5_000
        }]
    );
    let b = me.balance(chain.tip());
    assert_eq!(
        (b.spendable, b.incoming),
        (0, 5_000),
        "incoming is not spendable"
    );
    let first = &me.history(chain.tip())[0];
    assert_eq!(
        (first.kind, first.status, first.height, first.value),
        ("received", "pending", None, 5_000)
    );
    assert_eq!(first.created_at, Some(100));
    // Each payment is reported once.
    assert!(me.scan_mempool(&[tx.clone()], &pool, 110).is_empty());
    assert_eq!(me.balance(chain.tip()).incoming, 5_000);
    // Alice's own payment, change and all, is not income to her; a stranger
    // sees nothing at all.
    assert!(alice.scan_mempool(&[tx.clone()], &pool, 100).is_empty());
    assert_eq!(alice.balance(chain.tip()).incoming, 0);
    let mut stranger = web_wallet(&wallet::generate_mnemonic(), 1, 0);
    assert!(stranger.scan_mempool(&[tx.clone()], &pool, 100).is_empty());

    // A block confirms it: the coin replaces the incoming payment.
    chain.mine(&WalletKeys::random().address(), &[tx.clone()]);
    chain.sync(&mut me);
    let b = me.balance(chain.tip());
    assert_eq!((b.spendable, b.incoming), (5_000, 0));
    let history = me.history(chain.tip());
    assert_eq!(history.len(), 1, "{history:?}");
    assert_eq!(history[0].status, "confirmed");

    // A payment that leaves the mempool unconfirmed is forgotten.
    chain.sync(&mut alice);
    let again = alice
        .build_send(&me.address().encode(), 3_000, None, chain.tip(), 0)
        .unwrap();
    let dropped = tx_of(&again);
    assert_eq!(
        me.scan_mempool(&[dropped.clone()], &live(&[&dropped]), 200)
            .len(),
        1
    );
    assert!(me.scan_mempool(&[], &HashSet::new(), 210).is_empty());
    assert_eq!(me.balance(chain.tip()).incoming, 0);
    assert!(me
        .history(chain.tip())
        .iter()
        .all(|e| e.status != "pending"));

    // Another copy of my wallet paying someone: its change is not income.
    let mut copy = web_wallet(PHRASE, 1, 0);
    chain.sync(&mut copy);
    let out = copy
        .build_send(
            &WalletKeys::random().address().encode(),
            200,
            None,
            chain.tip(),
            0,
        )
        .unwrap();
    let out = tx_of(&out);
    assert!(me
        .scan_mempool(&[out.clone()], &live(&[&out]), 300)
        .is_empty());
}

#[test]
fn a_reorg_puts_a_payment_back_in_waiting() {
    let mut chain = Chain::new();
    let mut w = web_wallet(PHRASE, 1, 0);
    let me = w.address();
    chain.mine(&me, &[]);
    chain.mine_to_stranger(COINBASE_MATURITY as usize);
    chain.sync(&mut w);
    let funds = w.balance(chain.tip()).spendable;

    // The payment confirms on one branch...
    let fork = chain.clone();
    let paid = w
        .build_send(
            &WalletKeys::random().address().encode(),
            1_000,
            None,
            chain.tip(),
            0,
        )
        .unwrap();
    let height = chain.tip();
    chain.mine(&WalletKeys::random().address(), &[tx_of(&paid)]);
    chain.sync(&mut w);
    assert!(w.pending_txs().is_empty());
    let b = w.balance(chain.tip());
    assert_eq!((b.spendable, b.pending), (funds - 1_000 - paid.fee, 0));

    // ...and a longer branch without it wins.
    let mut other = fork;
    other.mine_to_stranger(2);
    let err = w
        .scan_block(height + 1, &other.blocks[height as usize + 1])
        .unwrap_err()
        .to_string();
    assert!(err.starts_with(REORG), "{err}");
    assert!(
        w.rollback_to(height),
        "the rollback changes what the wallet shows"
    );
    other.sync(&mut w);

    // The payment waits again: its coin stays reserved, not spendable, and
    // it is up for broadcasting again.
    let b = w.balance(other.tip());
    assert_eq!((b.spendable, b.pending), (0, funds));
    let pending = w.pending_txs();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].tx_hash, paid.tx_hash);
    let e = w
        .history(other.tip())
        .into_iter()
        .find(|e| e.tx_hash.as_deref() == Some(&paid.tx_hash))
        .unwrap();
    assert_eq!(e.status, "pending");
    assert!(w.quote(1, other.tip()).is_err(), "nothing else to spend");

    // Mined again on the winning branch, it confirms again.
    let tx: Transaction = bincode::deserialize(&hex::decode(&pending[0].tx_hex).unwrap()).unwrap();
    other.mine(&WalletKeys::random().address(), &[tx]);
    other.sync(&mut w);
    let b = w.balance(other.tip());
    assert_eq!((b.spendable, b.pending), (funds - 1_000 - paid.fee, 0));
    assert!(w.pending_txs().is_empty());

    // A rollback that undoes nothing of this wallet's says so.
    let mut quiet = web_wallet(&wallet::generate_mnemonic(), 1, 0);
    other.sync(&mut quiet);
    assert!(!quiet.rollback_to(other.tip() - 1));
}

#[test]
fn coins_found_again_after_a_deep_rollback_stay_reserved() {
    let mut chain = Chain::new();
    let mut w = web_wallet(PHRASE, 1, 0);
    let me = w.address();
    chain.mine(&me, &[]);
    chain.mine_to_stranger(COINBASE_MATURITY as usize);
    chain.sync(&mut w);
    let funds = w.balance(chain.tip()).spendable;
    let fork = chain.clone();
    let paid = w
        .build_send(
            &WalletKeys::random().address().encode(),
            1_000,
            None,
            chain.tip(),
            0,
        )
        .unwrap();
    let height = chain.tip();
    chain.mine(&WalletKeys::random().address(), &[tx_of(&paid)]);
    chain.sync(&mut w);

    // The worker steps back past the block that made the coin it spent.
    let mut other = fork;
    other.mine_to_stranger(2);
    assert!(w
        .scan_block(height + 1, &other.blocks[height as usize + 1])
        .is_err());
    assert!(w.rollback_to(1));
    assert_eq!(
        w.balance(other.tip()),
        wallet::Balance::default(),
        "the coin is forgotten"
    );
    let mut received = Vec::new();
    while w.scanned_height() < other.blocks.len() as u64 {
        let h = w.scanned_height();
        received.extend(w.scan_block(h, &other.blocks[h as usize]).unwrap().received);
    }
    // Found again, it is not news, and it is reserved for the payment that
    // spends it, which waits for a block again.
    assert!(received.is_empty(), "{received:?}");
    let b = w.balance(other.tip());
    assert_eq!((b.spendable, b.immature, b.pending), (0, 0, funds));
    assert_eq!(w.pending_txs().len(), 1);
    assert!(w.quote(1, other.tip()).is_err());
}
