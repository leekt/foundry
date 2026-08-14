//! EIP-8141 frame transactions, end to end through a running node.
//!
//! The envelope tests in `foundry-primitives` prove the encoding and the
//! signature rules; these prove that a valid signed frame transaction is
//! accepted, mined and *executed* -- the storage and balance assertions below
//! fail if the frame loop is skipped.
//!
//! Author: taek <leekt216@gmail.com>

use crate::utils::http_provider;
use alloy_consensus::Typed2718;
use alloy_eips::Encodable2718;
use alloy_network::{ReceiptResponse, TransactionBuilder};
use alloy_primitives::{Address, B256, Bytes, Sealable, U256, bytes, keccak256};
use alloy_provider::Provider;
use alloy_rpc_types::TransactionRequest;
use alloy_serde::WithOtherFields;
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use anvil::{NodeConfig, eth::EthApi, spawn};
use foundry_common::provider::RetryProvider;
use foundry_primitives::{FoundryNetwork, Frame, FrameSignature, TxFrame, flags, mode, scheme};

/// Deploys `5f355f5500`: `SSTORE(0, calldata[0..32])`, then stop. Payable by
/// virtue of having no value check at all.
const STORAGE_WRITER_INITCODE: Bytes = bytes!("645f355f55005f526005601bf3");

/// Deploys `5f5ffd`: `REVERT(0, 0)`, so every call to it fails.
const REVERTER_INITCODE: Bytes = bytes!("625f5ffd5f526003601df3");

/// The word the SENDER frame writes to slot 0.
const MAGIC: u64 = 0xdead_beef;

/// Deploys `initcode` from `from` and returns the contract's address.
async fn deploy(provider: &RetryProvider, from: Address, initcode: Bytes) -> Address {
    let deploy = TransactionRequest::default().with_from(from).into_create().with_input(initcode);
    let receipt = provider
        .send_transaction(WithOtherFields::new(deploy))
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    assert!(receipt.status(), "deployment reverted");
    receipt.contract_address.unwrap()
}

/// Signs `hash` into entry `index`.
///
/// EIP-8141 encodes secp256k1 as `v || r || s` with `v` the recovery id 0/1 --
/// not the `r || s || v` of an ordinary transaction, and not 27/28.
fn sign_hash_into(tx: &mut TxFrame, index: usize, signer: &PrivateKeySigner, hash: B256) {
    let sig = signer.sign_hash_sync(&hash).unwrap();
    let mut encoded = Vec::with_capacity(65);
    encoded.push(u8::from(sig.v()));
    encoded.extend_from_slice(&sig.r().to_be_bytes::<32>());
    encoded.extend_from_slice(&sig.s().to_be_bytes::<32>());
    tx.signatures[index].signature = encoded.into();
}

/// Signs entry `index` over the canonical signature hash.
///
/// The hash elides the raw bytes of empty-`msg` entries, so it does not move
/// when this writes the signature back.
fn sign_entry(tx: &mut TxFrame, index: usize, signer: &PrivateKeySigner) {
    let hash = tx.signature_hash();
    sign_hash_into(tx, index, signer, hash);
}

/// An empty-`msg` secp256k1 entry for `signer`, left unsigned. An empty `signer`
/// resolves to the transaction sender.
const fn signature_entry(signer: Bytes) -> FrameSignature {
    FrameSignature {
        scheme: scheme::SECP256K1,
        signer,
        msg: Bytes::new(), // empty == the canonical sig hash
        signature: Bytes::new(),
    }
}

/// The self-relay shape: a VERIFY frame on the sender approving both scopes,
/// then one SENDER frame per `(target, flags)` entry, each calling `target` with
/// 32 bytes of calldata. `flags` is where the atomic batch flag goes.
///
/// Every test below builds its transaction here, so a negative test differs from
/// its positive sibling only in the single field it changes afterwards.
fn frame_tx(
    sender: Address,
    nonce: u64,
    calls: &[(Address, u8)],
    max_fee_per_gas: u128,
    max_priority_fee_per_gas: u128,
) -> TxFrame {
    let verify = Frame {
        mode: mode::VERIFY,
        flags: flags::APPROVE_EXECUTION_PAYMENT,
        target: None, // null target == tx.sender
        gas_limit: 40_000,
        value: U256::ZERO,
        data: Bytes::new(),
    };
    let frames = std::iter::once(verify)
        .chain(calls.iter().map(|(target, flags)| Frame {
            mode: mode::SENDER,
            flags: *flags,
            target: Some(*target),
            gas_limit: 120_000,
            value: U256::ZERO,
            data: U256::from(MAGIC).to_be_bytes::<32>().into(),
        }))
        .collect();

    TxFrame {
        chain_id: U256::from(31337u64),
        nonce,
        sender,
        frames,
        signatures: vec![signature_entry(Bytes::new())],
        max_priority_fee_per_gas: U256::from(max_priority_fee_per_gas),
        max_fee_per_gas: U256::from(max_fee_per_gas),
        max_fee_per_blob_gas: U256::ZERO,
        blob_versioned_hashes: vec![],
    }
}

/// [`frame_tx`] with a single SENDER frame carrying `value`.
fn self_relay_tx(
    sender: Address,
    nonce: u64,
    target: Address,
    value: U256,
    max_fee_per_gas: u128,
    max_priority_fee_per_gas: u128,
) -> TxFrame {
    let mut tx = frame_tx(sender, nonce, &[(target, 0)], max_fee_per_gas, max_priority_fee_per_gas);
    tx.frames[1].value = value;
    tx
}

/// Validates, encodes and submits an already-signed `tx`, mines a block and
/// returns the transaction hash.
async fn submit_and_mine(
    api: &EthApi<FoundryNetwork>,
    provider: &RetryProvider,
    tx: &TxFrame,
) -> B256 {
    tx.validate().unwrap();
    tx.validate_signatures().unwrap();

    let mut raw = Vec::new();
    tx.encode_2718(&mut raw);
    let hash = *provider.send_raw_transaction(&raw).await.unwrap().tx_hash();
    api.mine_one().await.unwrap();
    hash
}

/// Reports whether `target`'s slot 0 holds the word a SENDER frame writes.
async fn wrote_magic(provider: &RetryProvider, target: Address) -> bool {
    provider.get_storage_at(target, U256::ZERO).await.unwrap() == U256::from(MAGIC)
}

#[tokio::test(flavor = "multi_thread")]
async fn frame_tx_is_mined_and_its_sender_frame_runs() {
    let (api, handle) = spawn(NodeConfig::test()).await;
    let provider = http_provider(&handle.http_endpoint());
    let wallet = handle.dev_wallets().next().unwrap();
    let sender = wallet.address();

    let deploy = TransactionRequest::default()
        .with_from(sender)
        .into_create()
        .with_input(STORAGE_WRITER_INITCODE);
    let receipt = provider
        .send_transaction(WithOtherFields::new(deploy))
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    assert!(receipt.status());
    let writer = receipt.contract_address.unwrap();

    let nonce = provider.get_transaction_count(sender).await.unwrap();
    let fees = provider.estimate_eip1559_fees().await.unwrap();
    let value = U256::from(1_234_000_000_000u64);

    let mut tx = self_relay_tx(
        sender,
        nonce,
        writer,
        value,
        fees.max_fee_per_gas,
        fees.max_priority_fee_per_gas,
    );
    sign_entry(&mut tx, 0, &wallet);
    tx.validate().unwrap();
    tx.validate_signatures().unwrap();

    let sender_balance_before = provider.get_balance(sender).await.unwrap();

    let mut raw = Vec::new();
    tx.encode_2718(&mut raw);
    let pending = provider.send_raw_transaction(&raw).await.unwrap();
    let hash = *pending.tx_hash();
    assert_eq!(hash, tx.hash_slow());

    api.mine_one().await.unwrap();

    let receipt = provider
        .get_transaction_receipt(hash)
        .await
        .unwrap()
        .expect("frame transaction was not mined");
    assert!(receipt.status(), "frame transaction reverted");
    assert_eq!(receipt.from, sender);

    // The point of the test: the SENDER frame's side effects, which only exist
    // if the frame actually executed.
    let stored = provider.get_storage_at(writer, U256::ZERO).await.unwrap();
    assert_eq!(stored, U256::from(MAGIC), "SENDER frame did not write storage");
    assert_eq!(
        provider.get_balance(writer).await.unwrap(),
        value,
        "SENDER frame did not transfer value"
    );

    // The sender's nonce moves exactly once, on the payment approval.
    assert_eq!(provider.get_transaction_count(sender).await.unwrap(), nonce + 1);

    // The payer was charged: the value left plus a non-zero fee on top.
    let sender_balance_after = provider.get_balance(sender).await.unwrap();
    let spent = sender_balance_before - sender_balance_after;
    assert!(spent > value, "payer was not charged a fee (spent {spent}, value {value})");

    // The transaction is retrievable and reports its frame type.
    let onchain = provider.get_transaction_by_hash(hash).await.unwrap().unwrap();
    assert_eq!(onchain.inner.inner.ty(), 0x06);

    let block = provider.get_block_by_number(receipt.block_number.unwrap().into()).await.unwrap();
    assert!(block.unwrap().transactions.hashes().any(|h| h == hash));
}

#[tokio::test(flavor = "multi_thread")]
async fn frame_tx_without_an_approving_verify_frame_is_not_mined() {
    let (api, handle) = spawn(NodeConfig::test()).await;
    let provider = http_provider(&handle.http_endpoint());
    let wallet = handle.dev_wallets().next().unwrap();
    let sender = wallet.address();

    let deploy = TransactionRequest::default()
        .with_from(sender)
        .into_create()
        .with_input(STORAGE_WRITER_INITCODE);
    let writer = provider
        .send_transaction(WithOtherFields::new(deploy))
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap()
        .contract_address
        .unwrap();

    let nonce = provider.get_transaction_count(sender).await.unwrap();
    let fees = provider.estimate_eip1559_fees().await.unwrap();

    // Same shape, but with no signature entry at all: the default VERIFY code
    // has nothing to bind the sender to, so nothing approves execution and the
    // SENDER frame must never run.
    let mut tx = self_relay_tx(
        sender,
        nonce,
        writer,
        U256::ZERO,
        fees.max_fee_per_gas,
        fees.max_priority_fee_per_gas,
    );
    tx.signatures.clear();
    tx.validate().unwrap();

    let mut raw = Vec::new();
    tx.encode_2718(&mut raw);
    let hash = *provider.send_raw_transaction(&raw).await.unwrap().tx_hash();

    api.mine_one().await.unwrap();

    assert!(
        provider.get_transaction_receipt(hash).await.unwrap().is_none(),
        "a frame transaction with no approving VERIFY frame was mined"
    );
    assert_eq!(
        provider.get_storage_at(writer, U256::ZERO).await.unwrap(),
        U256::ZERO,
        "the SENDER frame ran despite no approval"
    );
    assert_eq!(provider.get_transaction_count(sender).await.unwrap(), nonce);
}

#[tokio::test(flavor = "multi_thread")]
async fn frame_tx_with_a_foreign_signature_entry_is_not_mined() {
    let (api, handle) = spawn(NodeConfig::test()).await;
    let provider = http_provider(&handle.http_endpoint());
    let mut wallets = handle.dev_wallets();
    let wallet = wallets.next().unwrap();
    let other = wallets.next().unwrap();
    let sender = wallet.address();

    let deploy = TransactionRequest::default()
        .with_from(sender)
        .into_create()
        .with_input(STORAGE_WRITER_INITCODE);
    let writer = provider
        .send_transaction(WithOtherFields::new(deploy))
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap()
        .contract_address
        .unwrap();

    let nonce = provider.get_transaction_count(sender).await.unwrap();
    let fees = provider.estimate_eip1559_fees().await.unwrap();

    // A structurally valid signature -- by somebody who is not the sender. The
    // envelope check passes, so this has to be caught during execution.
    let mut tx = self_relay_tx(
        sender,
        nonce,
        writer,
        U256::ZERO,
        fees.max_fee_per_gas,
        fees.max_priority_fee_per_gas,
    );
    tx.signatures[0].signer = Bytes::from(other.address().to_vec());
    sign_entry(&mut tx, 0, &other);
    tx.validate().unwrap();
    tx.validate_signatures().expect("the entry is a valid signature, just not the sender's");

    let mut raw = Vec::new();
    tx.encode_2718(&mut raw);
    let hash = *provider.send_raw_transaction(&raw).await.unwrap().tx_hash();

    api.mine_one().await.unwrap();

    assert!(
        provider.get_transaction_receipt(hash).await.unwrap().is_none(),
        "a frame transaction approved by a foreign signer was mined"
    );
    assert_eq!(provider.get_storage_at(writer, U256::ZERO).await.unwrap(), U256::ZERO);
    assert_eq!(provider.get_transaction_count(sender).await.unwrap(), nonce);
}

// -- Atomic batches ---------------------------------------------------------

/// Runs `[VERIFY, first(batched), writer(batched), writer]` on a fresh node: an
/// atomic batch of three SENDER frames, whose first either writes storage or
/// reverts. Reports the transaction's gas used and whether the second and third
/// frames' writes survived.
///
/// The two calls to this are the positive/negative pair for the whole batch
/// mechanism: they differ only in whether the batch's first frame fails.
async fn run_three_frame_batch(first_reverts: bool) -> (u64, bool, bool) {
    let (api, handle) = spawn(NodeConfig::test()).await;
    let provider = http_provider(&handle.http_endpoint());
    let wallet = handle.dev_wallets().next().unwrap();
    let sender = wallet.address();

    let initcode = if first_reverts { REVERTER_INITCODE } else { STORAGE_WRITER_INITCODE };
    let first = deploy(&provider, sender, initcode).await;
    // Each writer gets its own contract, so "did this frame run" is answerable
    // per frame rather than for the batch as a whole.
    let second = deploy(&provider, sender, STORAGE_WRITER_INITCODE).await;
    let third = deploy(&provider, sender, STORAGE_WRITER_INITCODE).await;

    let nonce = provider.get_transaction_count(sender).await.unwrap();
    let fees = provider.estimate_eip1559_fees().await.unwrap();
    let mut tx = frame_tx(
        sender,
        nonce,
        &[(first, flags::ATOMIC_BATCH), (second, flags::ATOMIC_BATCH), (third, 0)],
        fees.max_fee_per_gas,
        fees.max_priority_fee_per_gas,
    );
    sign_entry(&mut tx, 0, &wallet);
    let hash = submit_and_mine(&api, &provider, &tx).await;

    let receipt = provider
        .get_transaction_receipt(hash)
        .await
        .unwrap()
        .expect("frame transaction was not mined");
    // A failing frame does not fail the transaction: it is reported per frame.
    assert!(receipt.status(), "frame transaction reverted");

    (receipt.gas_used(), wrote_magic(&provider, second).await, wrote_magic(&provider, third).await)
}

#[tokio::test(flavor = "multi_thread")]
async fn atomic_batch_that_succeeds_keeps_its_state() {
    let (_, second, third) = run_three_frame_batch(false).await;
    assert!(second, "the batch's second frame did not write");
    assert!(third, "the batch's terminating frame did not write");
}

#[tokio::test(flavor = "multi_thread")]
async fn atomic_batch_failure_rolls_back_and_skips_the_remaining_frames() {
    let (skipped_gas, second, third) = run_three_frame_batch(true).await;
    assert!(!second, "the frame after the batch failure ran and its write survived");
    assert!(!third, "the batch terminator ran after the batch had already failed");

    // Per-frame statuses are not exposed over RPC, so the evidence that the
    // remaining frames were *skipped* rather than run-and-rolled-back is the
    // gas: a skipped frame's allotment is left unspent. Same frame count, same
    // calldata, so the overhead and the calldata floor are identical.
    let (full_gas, _, _) = run_three_frame_batch(false).await;
    assert!(
        skipped_gas < full_gas,
        "skipped frames were charged: {skipped_gas} gas against {full_gas} when all three ran"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn atomic_batch_terminator_failure_rolls_the_batch_back() {
    let (api, handle) = spawn(NodeConfig::test()).await;
    let provider = http_provider(&handle.http_endpoint());
    let wallet = handle.dev_wallets().next().unwrap();
    let sender = wallet.address();

    let writer = deploy(&provider, sender, STORAGE_WRITER_INITCODE).await;
    let reverter = deploy(&provider, sender, REVERTER_INITCODE).await;

    let nonce = provider.get_transaction_count(sender).await.unwrap();
    let fees = provider.estimate_eip1559_fees().await.unwrap();

    // The batch terminator is the frame *without* the flag. It is still part of
    // the batch, so its failure has to undo the write the flagged frame made --
    // the case a rollback keyed on the flag alone gets wrong.
    let mut tx = frame_tx(
        sender,
        nonce,
        &[(writer, flags::ATOMIC_BATCH), (reverter, 0)],
        fees.max_fee_per_gas,
        fees.max_priority_fee_per_gas,
    );
    sign_entry(&mut tx, 0, &wallet);
    let hash = submit_and_mine(&api, &provider, &tx).await;

    let receipt = provider
        .get_transaction_receipt(hash)
        .await
        .unwrap()
        .expect("frame transaction was not mined");
    assert!(receipt.status(), "frame transaction reverted");
    assert!(
        !wrote_magic(&provider, writer).await,
        "the batch was not rolled back: the write survived the terminator's failure"
    );

    // The same batch with a terminator that succeeds keeps the write, so the
    // assertion above is about the rollback and not about the batch never
    // having run.
    let nonce = provider.get_transaction_count(sender).await.unwrap();
    let mut tx = frame_tx(
        sender,
        nonce,
        &[(writer, flags::ATOMIC_BATCH), (writer, 0)],
        fees.max_fee_per_gas,
        fees.max_priority_fee_per_gas,
    );
    sign_entry(&mut tx, 0, &wallet);
    submit_and_mine(&api, &provider, &tx).await;
    assert!(wrote_magic(&provider, writer).await, "a batch that succeeded was rolled back");
}

// -- Default code -----------------------------------------------------------

/// Runs the two-frame self-relay transaction on a fresh node, with the default
/// code's two inputs under the caller's control: the VERIFY frame's approval
/// flags, and whether the signature entry carries an explicit `msg` in place of
/// the empty one that stands for the canonical signature hash.
///
/// Reports whether the transaction was mined and whether the SENDER frame ran.
async fn run_default_code_verify(verify_flags: u8, explicit_msg: bool) -> (bool, bool) {
    let (api, handle) = spawn(NodeConfig::test()).await;
    let provider = http_provider(&handle.http_endpoint());
    let wallet = handle.dev_wallets().next().unwrap();
    let sender = wallet.address();
    let writer = deploy(&provider, sender, STORAGE_WRITER_INITCODE).await;

    let nonce = provider.get_transaction_count(sender).await.unwrap();
    let fees = provider.estimate_eip1559_fees().await.unwrap();
    let mut tx = frame_tx(
        sender,
        nonce,
        &[(writer, 0)],
        fees.max_fee_per_gas,
        fees.max_priority_fee_per_gas,
    );
    tx.frames[0].flags = verify_flags;

    if explicit_msg {
        // A digest of the sender's own choosing, correctly signed by the sender.
        // The entry is a valid signature and passes envelope validation; the
        // default code rejects it only because EIP-8141 requires an empty msg,
        // so that the entry signs the canonical hash and nothing else.
        let msg = keccak256(b"not the canonical signature hash");
        tx.signatures[0].msg = Bytes::from(msg.to_vec());
        sign_hash_into(&mut tx, 0, &wallet, msg);
    } else {
        sign_entry(&mut tx, 0, &wallet);
    }
    let hash = submit_and_mine(&api, &provider, &tx).await;

    let mined = provider.get_transaction_receipt(hash).await.unwrap().is_some();
    (mined, wrote_magic(&provider, writer).await)
}

#[tokio::test(flavor = "multi_thread")]
async fn default_code_verify_approves_the_scope_its_flags_name() {
    let (mined, written) = run_default_code_verify(flags::APPROVE_EXECUTION_PAYMENT, false).await;
    assert!(mined, "a well-formed default-code VERIFY frame was not mined");
    assert!(written, "the SENDER frame did not run");
}

#[tokio::test(flavor = "multi_thread")]
async fn default_code_verify_without_an_approval_scope_is_not_mined() {
    // allowed_scope == 0: the default code has nothing to approve, so it
    // reverts and the transaction never establishes a payer.
    let (mined, written) = run_default_code_verify(0, false).await;
    assert!(!mined, "a VERIFY frame with no approvable scope was mined");
    assert!(!written, "the SENDER frame ran despite no approval");
}

#[tokio::test(flavor = "multi_thread")]
async fn default_code_verify_with_an_explicit_msg_is_not_mined() {
    let (mined, written) = run_default_code_verify(flags::APPROVE_EXECUTION_PAYMENT, true).await;
    assert!(!mined, "the default code accepted a signature over an explicit msg");
    assert!(!written, "the SENDER frame ran despite no approval");
}

/// Runs a sponsored transaction whose payment is approved by the default code of
/// a second, code-less account:
///
/// 0. VERIFY on the sender, `APPROVE_EXECUTION` -- default code, signature 0.
/// 1. VERIFY on the sponsor, `APPROVE_PAYMENT` -- default code, signature 1.
/// 2. SENDER, writing storage.
///
/// With `displace_sponsor_signature` the sponsor's entry moves to index 2 and a
/// second copy of the sender's entry takes index 1. That is the only difference
/// between the two runs, and it changes only what the default code finds at the
/// index it selects for a payment-only scope.
async fn run_sponsored_payment(displace_sponsor_signature: bool) -> (bool, bool, Address) {
    let (api, handle) = spawn(NodeConfig::test()).await;
    let provider = http_provider(&handle.http_endpoint());
    let mut wallets = handle.dev_wallets();
    let wallet = wallets.next().unwrap();
    let sponsor_wallet = wallets.next().unwrap();
    let sender = wallet.address();
    let sponsor = sponsor_wallet.address();
    let writer = deploy(&provider, sender, STORAGE_WRITER_INITCODE).await;

    let nonce = provider.get_transaction_count(sender).await.unwrap();
    let fees = provider.estimate_eip1559_fees().await.unwrap();
    let mut tx = frame_tx(
        sender,
        nonce,
        &[(writer, 0)],
        fees.max_fee_per_gas,
        fees.max_priority_fee_per_gas,
    );
    tx.frames[0].flags = flags::APPROVE_EXECUTION;
    tx.frames.insert(
        1,
        Frame {
            mode: mode::VERIFY,
            flags: flags::APPROVE_PAYMENT,
            target: Some(sponsor),
            gas_limit: 40_000,
            value: U256::ZERO,
            data: Bytes::new(),
        },
    );

    let sponsor_index = if displace_sponsor_signature {
        tx.signatures.push(signature_entry(Bytes::new()));
        2
    } else {
        1
    };
    tx.signatures.push(signature_entry(Bytes::from(sponsor.to_vec())));
    sign_entry(&mut tx, 0, &wallet);
    if displace_sponsor_signature {
        sign_entry(&mut tx, 1, &wallet);
    }
    sign_entry(&mut tx, sponsor_index, &sponsor_wallet);

    let sponsor_balance_before = provider.get_balance(sponsor).await.unwrap();
    let hash = submit_and_mine(&api, &provider, &tx).await;

    let mined = provider.get_transaction_receipt(hash).await.unwrap().is_some();
    if mined {
        assert!(
            provider.get_balance(sponsor).await.unwrap() < sponsor_balance_before,
            "the sponsor was named payer but paid nothing"
        );
    }
    (mined, wrote_magic(&provider, writer).await, sponsor)
}

#[tokio::test(flavor = "multi_thread")]
async fn default_code_payment_only_scope_uses_signature_index_one() {
    let (mined, written, _) = run_sponsored_payment(false).await;
    assert!(mined, "the sponsor's default-code payment approval was rejected");
    assert!(written, "the SENDER frame did not run");
}

#[tokio::test(flavor = "multi_thread")]
async fn default_code_payment_only_scope_ignores_a_signature_at_another_index() {
    // The sponsor's entry sits at index 2; index 1 holds the sender's. A
    // payment-only scope reads index 1, finds a signature by somebody other
    // than the frame's target, and approves nothing -- so no payer is ever set.
    let (mined, written, _) = run_sponsored_payment(true).await;
    assert!(!mined, "the default code approved payment off the wrong signature index");
    assert!(!written, "the SENDER frame ran despite no payer");
}
