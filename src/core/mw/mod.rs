//! Pluribit-style MimbleWimble, hardened.
//!
//! * [`crypto`]: Pedersen commitments, aggregated Bulletproofs, Schnorr.
//! * [`stealth`]: non-interactive stealth outputs with owner keys.
//! * [`transaction`]: outputs, inputs, kernels, balance rules, aggregation.
//! * [`builder`]: constructing transactions and coinbases.
//!
//! # Threat model for ownership
//!
//! Pluribit's non-interactive payments let the **payer** spend the payment
//! (they chose and therefore know its blinding factor). The fix has three
//! parts, and each one blocks a specific attack:
//!
//! | Part | Stops |
//! |---|---|
//! | Owner key `Ko = H(t)·G + B` plus input signature by `ko` | payer (or scan-key holder) spending directly |
//! | Owner sum `Σ Ko_in = Σ E' + x·G`, kernel proves knowledge of `e'` | payer copying the payee's input signature into their own transaction |
//! | Owner key and payload bound into the range-proof transcript | a relay rewriting `Ko` to burn or hijack a payment in flight |
//!
//! The owner sum protects against theft, not inflation, so it only needs to
//! hold when a block is accepted. Anti-inflation rests on the Pedersen
//! equation and range proofs as usual, and survives pruning.

pub mod builder;
pub mod crypto;
pub mod stealth;
pub mod transaction;

pub use builder::{
    build_coinbase, build_coinbase_with, build_transaction, BuiltTransaction, Payment, Spendable,
};
pub use crypto::{Point32, Scalar32};
pub use stealth::{scan_output, PayoutReceipt, StealthAddress, WalletKeys};
pub use transaction::{
    Coinbase, Context, GroupMember, Input, Kernel, KernelFeatures, Output, OutputGroup,
    StoredGroup, Transaction, TxBody,
};

#[cfg(test)]
mod tests {
    use super::crypto::*;
    use super::stealth::new_output;
    use super::*;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use curve25519_dalek::scalar::Scalar;

    /// A UTXO that Alice created for Bob: Alice knows the blinding factor.
    struct Planted {
        spendable_by_bob: Spendable,
        alice_knows_blinding: Scalar,
        value: u64,
        owner_key: Point32,
    }

    fn alice_pays_bob(bob: &WalletKeys, value: u64) -> Planted {
        let created = new_output(&bob.address(), value).unwrap();
        let owned = scan_output(bob, &created.output).unwrap();
        Planted {
            spendable_by_bob: Spendable {
                commitment: created.output.commitment,
                value,
                blinding: owned.blinding,
                owner_secret: owned.owner_secret,
            },
            alice_knows_blinding: created.blinding,
            value,
            owner_key: created.output.owner_key,
        }
    }

    #[test]
    fn honest_transaction_validates() {
        let bob = WalletKeys::random();
        let carol = WalletKeys::random();
        let utxo = alice_pays_bob(&bob, 1_000);
        let built = build_transaction(
            &[utxo.spendable_by_bob.clone()],
            &[Payment {
                to: carol.address(),
                value: 600,
            }],
            &bob.address(),
            10,
            0,
        )
        .unwrap();
        built.tx.validate(Context::Relay).unwrap();
        assert_eq!(built.change.unwrap().1, 390);
        assert_eq!(built.tx.fee().unwrap(), 10);

        // Carol and Bob can both find their outputs.
        let found_carol: u64 = built
            .tx
            .outputs()
            .filter_map(|o| scan_output(&carol, o))
            .map(|o| o.value)
            .sum();
        let found_bob: u64 = built
            .tx
            .outputs()
            .filter_map(|o| scan_output(&bob, o))
            .map(|o| o.value)
            .sum();
        assert_eq!((found_carol, found_bob), (600, 390));
    }

    /// The pluribit attack, first form: Alice knows the blinding factor and
    /// signs the input with her own key. The signature is valid for *her* key,
    /// so the only thing that stops this is the chain's record of the output's
    /// owner key, checked statefully (see `state.rs`). Here we confirm the
    /// input really does advertise a different owner key.
    #[test]
    fn payer_cannot_sign_for_payee_owner_key() {
        let bob = WalletKeys::random();
        let utxo = alice_pays_bob(&bob, 500);
        let alice_key = random_scalar();
        let forged = Input::sign(utxo.spendable_by_bob.commitment, &alice_key);
        assert!(forged.verify_signature());
        assert_ne!(
            forged.owner_key, utxo.owner_key,
            "state check will reject this input"
        );
    }

    /// The pluribit attack, second form: Alice copies Bob's genuine input
    /// (signature included) out of Bob's broadcast transaction and redirects
    /// the funds to herself. She knows every Pedersen secret involved, so the
    /// only barrier is the owner sum.
    #[test]
    fn payer_cannot_reuse_payee_input_signature() {
        let bob = WalletKeys::random();
        let alice = WalletKeys::random();
        let carol = WalletKeys::random();
        let utxo = alice_pays_bob(&bob, 1_000);

        // Bob's honest spend, as seen in the mempool.
        let bobs_tx = build_transaction(
            &[utxo.spendable_by_bob.clone()],
            &[Payment {
                to: carol.address(),
                value: 990,
            }],
            &bob.address(),
            10,
            0,
        )
        .unwrap()
        .tx;
        let copied_input = bobs_tx.body.inputs[0].clone();
        assert!(copied_input.verify_signature());

        // Alice pays everything to herself.
        let steal = new_output(&alice.address(), utxo.value - 10).unwrap();
        let group = OutputGroup::prove(
            vec![steal.output.clone()],
            &[steal.value],
            &[steal.blinding],
        )
        .unwrap();
        let offset = random_scalar();
        let e = steal.blinding - utxo.alice_knows_blinding - offset;

        // Attempt A: pick a known owner excess and solve x = log(Ko − E') — impossible,
        // so she guesses x. The owner sum then fails.
        let e_owner_guess = random_scalar();
        let x_guess = random_scalar();
        let tx_a = Transaction {
            body: TxBody {
                inputs: vec![copied_input.clone()],
                outputs: vec![group.clone()],
                kernels: vec![Kernel::new(
                    KernelFeatures::Plain,
                    10,
                    0,
                    &e,
                    &e_owner_guess,
                )],
            },
            kernel_offset: offset.to_bytes(),
            owner_offset: x_guess.to_bytes(),
        };
        tx_a.verify_crypto().unwrap(); // every individual signature is fine...
        let err = tx_a.validate(Context::Relay).unwrap_err().to_string();
        assert!(err.contains("owner sum"), "{err}"); // ...but ownership is not proven.

        // Attempt B: make the owner sum hold by setting E' = Ko − x·G. She
        // cannot know log(E'), so she signs with a wrong secret.
        let x = random_scalar();
        let owner_excess =
            decompress(&copied_input.owner_key).unwrap() - RistrettoPoint::mul_base(&x);
        let mut kernel = Kernel::new(KernelFeatures::Plain, 10, 0, &e, &random_scalar());
        kernel.owner_excess = compress(&owner_excess);
        let tx_b = Transaction {
            body: TxBody {
                inputs: vec![copied_input],
                outputs: vec![group],
                kernels: vec![kernel],
            },
            kernel_offset: offset.to_bytes(),
            owner_offset: x.to_bytes(),
        };
        tx_b.verify_sums().unwrap(); // both equations now balance...
        let err = tx_b.validate(Context::Relay).unwrap_err().to_string();
        assert!(err.contains("kernel signature"), "{err}"); // ...but she cannot sign.
    }

    #[test]
    fn relay_cannot_redirect_owner_key() {
        let bob = WalletKeys::random();
        let carol = WalletKeys::random();
        let mallory = WalletKeys::random();
        let utxo = alice_pays_bob(&bob, 100);
        let mut tx = build_transaction(
            &[utxo.spendable_by_bob],
            &[Payment {
                to: carol.address(),
                value: 99,
            }],
            &bob.address(),
            1,
            0,
        )
        .unwrap()
        .tx;
        tx.body.outputs[0].outputs[0].owner_key = mallory.address().spend;
        let err = tx.validate(Context::Relay).unwrap_err().to_string();
        assert!(err.contains("range proof"), "{err}");
    }

    #[test]
    fn fee_cannot_be_changed_after_signing() {
        let bob = WalletKeys::random();
        let utxo = alice_pays_bob(&bob, 100);
        let mut tx = build_transaction(
            &[utxo.spendable_by_bob],
            &[Payment {
                to: bob.address(),
                value: 50,
            }],
            &bob.address(),
            5,
            0,
        )
        .unwrap()
        .tx;
        tx.body.kernels[0].fee = 6;
        assert!(tx.validate(Context::Relay).is_err());
    }

    /// Outputs worth more than the inputs: the surplus is a G-component that
    /// no kernel excess (a multiple of H) can cancel.
    #[test]
    fn inflation_attempt_fails_pedersen_check() {
        let bob = WalletKeys::random();
        let utxo = alice_pays_bob(&bob, 100);
        let minted = new_output(&bob.address(), 150).unwrap();
        let group =
            OutputGroup::prove(vec![minted.output.clone()], &[150], &[minted.blinding]).unwrap();
        let input = Input::sign(
            utxo.spendable_by_bob.commitment,
            &utxo.spendable_by_bob.owner_secret,
        );
        let offset = random_scalar();
        let x = random_scalar();
        let e = minted.blinding - utxo.spendable_by_bob.blinding - offset;
        let e_owner = utxo.spendable_by_bob.owner_secret - x;
        let tx = Transaction {
            body: TxBody {
                inputs: vec![input],
                outputs: vec![group],
                kernels: vec![Kernel::new(KernelFeatures::Plain, 0, 0, &e, &e_owner)],
            },
            kernel_offset: offset.to_bytes(),
            owner_offset: x.to_bytes(),
        };
        tx.validate_structure(Context::Relay).unwrap();
        tx.verify_crypto().unwrap(); // proofs and signatures are all genuine
        let err = tx.verify_sums().unwrap_err().to_string();
        assert!(err.contains("Pedersen"), "{err}");
    }

    #[test]
    fn aggregation_preserves_validity() {
        let bob = WalletKeys::random();
        let dave = WalletKeys::random();
        let a = alice_pays_bob(&bob, 300);
        let b = alice_pays_bob(&dave, 400);
        let tx1 = build_transaction(
            &[a.spendable_by_bob],
            &[Payment {
                to: dave.address(),
                value: 100,
            }],
            &bob.address(),
            3,
            0,
        )
        .unwrap()
        .tx;
        let tx2 = build_transaction(
            &[b.spendable_by_bob],
            &[Payment {
                to: bob.address(),
                value: 100,
            }],
            &dave.address(),
            4,
            0,
        )
        .unwrap()
        .tx;
        let agg = Transaction::aggregate([&tx1, &tx2]).unwrap();
        agg.validate(Context::Block).unwrap();
        assert_eq!(agg.fee().unwrap(), 7);
        assert_eq!(agg.body.inputs.len(), 2);
        assert_eq!(agg.body.kernels.len(), 2);
        // Aggregating a transaction with itself is a double spend.
        assert!(Transaction::aggregate([&tx1, &tx1]).is_err());
        // Without the offsets, neither half balances on its own any more,
        // which is what makes aggregates unsplittable by kernel matching.
        let mut half = tx1.clone();
        half.kernel_offset = [0u8; 32];
        assert!(half.verify_sums().is_err());
    }

    #[test]
    fn coinbase_pays_exact_amount() {
        let miner = WalletKeys::random();
        let cb = build_coinbase(&[(miner.address(), 700), (miner.address(), 300)]).unwrap();
        cb.validate_structure().unwrap();
        cb.verify_crypto().unwrap();
        cb.verify_sum(1_000).unwrap();
        assert!(cb.verify_sum(1_001).is_err());
        let found: u64 = cb
            .outputs
            .outputs
            .iter()
            .filter_map(|o| scan_output(&miner, o))
            .map(|o| o.value)
            .sum();
        assert_eq!(found, 1_000);
    }

    #[test]
    fn plain_kernel_requires_owner_excess() {
        let k = Kernel::new(KernelFeatures::Plain, 1, 0, &random_scalar(), &Scalar::ZERO);
        let tx = Transaction {
            body: TxBody {
                inputs: vec![],
                outputs: vec![],
                kernels: vec![k],
            },
            kernel_offset: [0u8; 32],
            owner_offset: [0u8; 32],
        };
        let err = tx
            .validate_structure(Context::Block)
            .unwrap_err()
            .to_string();
        assert!(err.contains("owner excess"), "{err}");
    }

    #[test]
    fn pruned_groups_still_prove_their_unspent_members() {
        let a = WalletKeys::random();
        let outs: Vec<_> = (0..3)
            .map(|i| new_output(&a.address(), 10 + i).unwrap())
            .collect();
        let group = OutputGroup::prove(
            outs.iter().map(|o| o.output.clone()).collect(),
            &outs.iter().map(|o| o.value).collect::<Vec<_>>(),
            &outs.iter().map(|o| o.blinding).collect::<Vec<_>>(),
        )
        .unwrap();
        let mut stored = StoredGroup::from_group(&group);
        let id = stored.id();
        assert!(stored.verify());
        stored.spend(0).unwrap();
        stored.spend(2).unwrap();
        assert!(stored.verify(), "the proof survives pruning");
        assert_eq!(stored.id(), id, "the id is stable");
        assert_eq!(
            stored.unspent().map(|(i, _)| i).collect::<Vec<_>>(),
            vec![1]
        );
        assert!(stored.spend(0).is_err());
        assert!(!stored.is_fully_spent());
        // Tampering with a kept or pruned member breaks the proof.
        let mut bad = stored.clone();
        if let GroupMember::Unspent(o) = &mut bad.members[1] {
            o.payload[0] ^= 1;
        }
        assert!(!bad.verify());
        let mut bad = stored.clone();
        bad.members[0] = GroupMember::Spent {
            commitment: outs[0].output.commitment,
            metadata_hash: [0; 32],
        };
        assert!(!bad.verify());
        stored.spend(1).unwrap();
        assert!(stored.is_fully_spent());
    }

    #[test]
    fn empty_body_is_valid_only_in_blocks() {
        let empty = Transaction::empty();
        empty.validate(Context::Block).unwrap();
        assert!(empty.validate(Context::Relay).is_err());
    }
}
