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
use alloy_primitives::{Bytes, Sealable, U256, bytes};
use alloy_provider::Provider;
use alloy_rpc_types::TransactionRequest;
use alloy_serde::WithOtherFields;
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use anvil::{NodeConfig, spawn};
use foundry_primitives::{Frame, FrameSignature, TxFrame, flags, mode, scheme};

/// Deploys `5f355f5500`: `SSTORE(0, calldata[0..32])`, then stop. Payable by
/// virtue of having no value check at all.
const STORAGE_WRITER_INITCODE: Bytes = bytes!("645f355f55005f526005601bf3");

/// The word the SENDER frame writes to slot 0.
const MAGIC: u64 = 0xdead_beef;

/// Signs entry `index` over the canonical signature hash.
///
/// EIP-8141 encodes secp256k1 as `v || r || s` with `v` the recovery id 0/1 --
/// not the `r || s || v` of an ordinary transaction, and not 27/28. The hash
/// elides the raw bytes of empty-`msg` entries, so it does not move when this
/// writes the signature back.
fn sign_entry(tx: &mut TxFrame, index: usize, signer: &PrivateKeySigner) {
    let sig = signer.sign_hash_sync(&tx.signature_hash()).unwrap();
    let mut encoded = Vec::with_capacity(65);
    encoded.push(u8::from(sig.v()));
    encoded.extend_from_slice(&sig.r().to_be_bytes::<32>());
    encoded.extend_from_slice(&sig.s().to_be_bytes::<32>());
    tx.signatures[index].signature = encoded.into();
}

/// The self-relay shape: a VERIFY frame on the sender approving both scopes,
/// then a SENDER frame calling `target` with `value` and 32 bytes of calldata.
fn self_relay_tx(
    sender: alloy_primitives::Address,
    nonce: u64,
    target: alloy_primitives::Address,
    value: U256,
    max_fee_per_gas: u128,
    max_priority_fee_per_gas: u128,
) -> TxFrame {
    TxFrame {
        chain_id: U256::from(31337u64),
        nonce,
        sender,
        frames: vec![
            Frame {
                mode: mode::VERIFY,
                flags: flags::APPROVE_EXECUTION_PAYMENT,
                target: None, // null target == tx.sender
                gas_limit: 40_000,
                value: U256::ZERO,
                data: Bytes::new(),
            },
            Frame {
                mode: mode::SENDER,
                flags: 0,
                target: Some(target),
                gas_limit: 120_000,
                value,
                data: U256::from(MAGIC).to_be_bytes::<32>().into(),
            },
        ],
        signatures: vec![FrameSignature {
            scheme: scheme::SECP256K1,
            signer: Bytes::new(), // empty == tx.sender
            msg: Bytes::new(),    // empty == the canonical sig hash
            signature: Bytes::new(),
        }],
        max_priority_fee_per_gas: U256::from(max_priority_fee_per_gas),
        max_fee_per_gas: U256::from(max_fee_per_gas),
        max_fee_per_blob_gas: U256::ZERO,
        blob_versioned_hashes: vec![],
    }
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
