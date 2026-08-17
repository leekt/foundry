//! EIP-7851 integration tests against ethereum/EIPs commit
//! 07f3bb3626d4db1f2ac501734fec5b3d32e185c5.

use alloy_consensus::{SignableTransaction, TxEip1559, transaction::TxEip7702};
use alloy_eips::Encodable2718;
use alloy_network::{ReceiptResponse, TransactionBuilder, TxSignerSync};
use alloy_primitives::{Address, Bytes, TxKind, U256, address};
use alloy_provider::Provider;
use alloy_rpc_types::{Authorization, TransactionRequest};
use alloy_signer::SignerSync;
use anvil::{NodeConfig, spawn};
use foundry_common::provider::RetryProvider;
use foundry_evm::hardfork::EthereumHardfork;

const AUTHORITY: Address = address!("1111111111111111111111111111111111111111");
const FIRST_DELEGATE: Address = address!("2222222222222222222222222222222222222222");
const SECOND_DELEGATE: Address = address!("3333333333333333333333333333333333333333");
const THIRD_DELEGATE: Address = address!("4444444444444444444444444444444444444444");
const STATIC_CALLER: Address = address!("5555555555555555555555555555555555555555");

/// Toolkit-local, non-normative assignment while EIP-7851 leaves the opcode TBD.
const SETSELFDELEGATE: u8 = 0xf7;
const EIP7702_DELEGATION_VERSION: u8 = 0x00;
const EIP7851_DELEGATION_VERSION: u8 = 0x01;
const SETSELFDELEGATE_GAS: u64 = 9_500;

fn delegation(version: u8, target: Address) -> Bytes {
    let mut code = Vec::with_capacity(23);
    code.extend_from_slice(&[0xef, 0x01, version]);
    code.extend_from_slice(target.as_slice());
    code.into()
}

fn setselfdelegate_runtime(target: Address) -> Bytes {
    let mut code = Vec::with_capacity(29);
    code.push(0x73); // PUSH20
    code.extend_from_slice(target.as_slice());
    code.extend_from_slice(&[
        SETSELFDELEGATE,
        0x5f, // PUSH0
        0x52, // MSTORE
        0x60,
        0x20, // PUSH1 32
        0x5f, // PUSH0
        0xf3, // RETURN
    ]);
    code.into()
}

fn reverting_runtime(target: Address) -> Bytes {
    let mut code = Vec::with_capacity(26);
    code.push(0x73); // PUSH20
    code.extend_from_slice(target.as_slice());
    code.extend_from_slice(&[
        SETSELFDELEGATE,
        0x50, // POP success
        0x5f, // PUSH0
        0x5f, // PUSH0
        0xfd, // REVERT
    ]);
    code.into()
}

fn static_caller_runtime(target: Address) -> Bytes {
    let mut code = vec![
        0x5f, // return size
        0x5f, // return offset
        0x5f, // calldata size
        0x5f, // calldata offset
        0x73, // PUSH20 target
    ];
    code.extend_from_slice(target.as_slice());
    code.extend_from_slice(&[
        0x61, 0xff, 0xff, // PUSH2 gas
        0xfa, // STATICCALL
        0x5f, // PUSH0
        0x52, // MSTORE
        0x60, 0x20, // PUSH1 32
        0x5f, // PUSH0
        0xf3, // RETURN
    ]);
    code.into()
}

fn gas_probe_runtime(target: Address) -> Bytes {
    let mut code = vec![0x5a, 0x73]; // GAS, PUSH20
    code.extend_from_slice(target.as_slice());
    code.extend_from_slice(&[
        SETSELFDELEGATE,
        0x50, // POP success
        0x5a, // GAS
        0x60,
        0x20, // PUSH1 32
        0x52, // MSTORE gas after
        0x5f, // PUSH0
        0x52, // MSTORE gas before
        0x60,
        0x40, // PUSH1 64
        0x5f, // PUSH0
        0xf3, // RETURN
    ]);
    code.into()
}

fn reentrant_runtime(target: Address) -> Bytes {
    let mut code = vec![0x73]; // PUSH20
    code.extend_from_slice(target.as_slice());
    code.extend_from_slice(&[
        SETSELFDELEGATE,
        0x50, // POP success
        0x60,
        0x11, // PUSH1 current-frame marker
        0x5f, // PUSH0
        0x52, // MSTORE
        0x60,
        0x20, // return size
        0x60,
        0x20, // return offset
        0x5f, // calldata size
        0x5f, // calldata offset
        0x5f, // value
        0x30, // ADDRESS
        0x61,
        0xff,
        0xff, // PUSH2 gas
        0xf1, // CALL
        0x50, // POP call success
        0x60,
        0x40, // PUSH1 64
        0x5f, // PUSH0
        0xf3, // RETURN
    ]);
    code.into()
}

fn enabled_config(hardfork: EthereumHardfork) -> NodeConfig {
    NodeConfig::test().with_hardfork(Some(hardfork.into())).enable_eip7851(true)
}

async fn call(provider: &RetryProvider, target: Address) -> Bytes {
    provider
        .call(TransactionRequest::default().with_to(target).with_gas_limit(200_000).into())
        .await
        .unwrap()
}

async fn call_word(provider: &RetryProvider, target: Address) -> U256 {
    U256::from_be_slice(call(provider, target).await.as_ref())
}

async fn send_call(provider: &RetryProvider, from: Address, target: Address) -> bool {
    provider
        .send_transaction(
            TransactionRequest::default()
                .with_from(from)
                .with_to(target)
                .with_gas_limit(200_000)
                .into(),
        )
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap()
        .status()
}

#[tokio::test(flavor = "multi_thread")]
async fn setselfdelegate_requires_opt_in_and_prague() {
    let configs = [
        NodeConfig::test().with_hardfork(Some(EthereumHardfork::Prague.into())),
        enabled_config(EthereumHardfork::Cancun),
    ];

    for config in configs {
        let (api, handle) = spawn(config).await;
        let provider = handle.http_provider();
        api.anvil_set_code(AUTHORITY, setselfdelegate_runtime(SECOND_DELEGATE)).await.unwrap();

        let err = provider
            .call(TransactionRequest::default().with_to(AUTHORITY).with_gas_limit(200_000).into())
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("NotActivated"), "unexpected error: {err}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn setselfdelegate_updates_both_designation_versions_without_nonce_bump_and_survives_reset() {
    let (api, handle) = spawn(enabled_config(EthereumHardfork::Prague)).await;
    let provider = handle.http_provider();
    let mut accounts = handle.dev_accounts();
    let from = accounts.next().unwrap();
    let after_reset_from = accounts.next().unwrap();
    api.anvil_set_code(FIRST_DELEGATE, setselfdelegate_runtime(SECOND_DELEGATE)).await.unwrap();
    api.anvil_set_code(SECOND_DELEGATE, setselfdelegate_runtime(THIRD_DELEGATE)).await.unwrap();
    api.anvil_set_code(THIRD_DELEGATE, Bytes::from_static(&[0x00])).await.unwrap();
    api.anvil_set_code(AUTHORITY, delegation(EIP7702_DELEGATION_VERSION, FIRST_DELEGATE))
        .await
        .unwrap();
    let nonce = provider.get_transaction_count(AUTHORITY).await.unwrap();

    assert!(send_call(&provider, from, AUTHORITY).await);
    assert_eq!(
        provider.get_code_at(AUTHORITY).await.unwrap(),
        delegation(EIP7851_DELEGATION_VERSION, SECOND_DELEGATE)
    );
    assert_eq!(provider.get_transaction_count(AUTHORITY).await.unwrap(), nonce);

    assert!(send_call(&provider, from, AUTHORITY).await);
    assert_eq!(
        provider.get_code_at(AUTHORITY).await.unwrap(),
        delegation(EIP7851_DELEGATION_VERSION, THIRD_DELEGATE)
    );
    assert_eq!(provider.get_transaction_count(AUTHORITY).await.unwrap(), nonce);

    api.anvil_reset(None).await.unwrap();
    api.anvil_set_code(FIRST_DELEGATE, setselfdelegate_runtime(SECOND_DELEGATE)).await.unwrap();
    api.anvil_set_code(SECOND_DELEGATE, Bytes::from_static(&[0x00])).await.unwrap();
    api.anvil_set_code(AUTHORITY, delegation(EIP7702_DELEGATION_VERSION, FIRST_DELEGATE))
        .await
        .unwrap();

    assert!(send_call(&provider, after_reset_from, AUTHORITY).await);
    assert_eq!(
        provider.get_code_at(AUTHORITY).await.unwrap(),
        delegation(EIP7851_DELEGATION_VERSION, SECOND_DELEGATE)
    );
    assert_eq!(provider.get_transaction_count(AUTHORITY).await.unwrap(), nonce);
}

#[tokio::test(flavor = "multi_thread")]
async fn setselfdelegate_returns_zero_for_invalid_authority_code_and_zero_target() {
    let (api, handle) = spawn(enabled_config(EthereumHardfork::Prague)).await;
    let provider = handle.http_provider();
    let from = handle.dev_accounts().next().unwrap();

    let invalid_code = setselfdelegate_runtime(SECOND_DELEGATE);
    api.anvil_set_code(AUTHORITY, invalid_code.clone()).await.unwrap();
    assert_eq!(call_word(&provider, AUTHORITY).await, U256::ZERO);
    assert!(send_call(&provider, from, AUTHORITY).await);
    assert_eq!(provider.get_code_at(AUTHORITY).await.unwrap(), invalid_code);

    api.anvil_set_code(FIRST_DELEGATE, setselfdelegate_runtime(Address::ZERO)).await.unwrap();
    let original = delegation(EIP7702_DELEGATION_VERSION, FIRST_DELEGATE);
    api.anvil_set_code(AUTHORITY, original.clone()).await.unwrap();
    assert_eq!(call_word(&provider, AUTHORITY).await, U256::ZERO);
    assert!(send_call(&provider, from, AUTHORITY).await);
    assert_eq!(provider.get_code_at(AUTHORITY).await.unwrap(), original);
}

#[tokio::test(flavor = "multi_thread")]
async fn setselfdelegate_halts_exceptionally_in_static_context() {
    let (api, handle) = spawn(enabled_config(EthereumHardfork::Prague)).await;
    let provider = handle.http_provider();
    let from = handle.dev_accounts().next().unwrap();
    let original = delegation(EIP7702_DELEGATION_VERSION, FIRST_DELEGATE);
    api.anvil_set_code(FIRST_DELEGATE, setselfdelegate_runtime(SECOND_DELEGATE)).await.unwrap();
    api.anvil_set_code(AUTHORITY, original.clone()).await.unwrap();
    api.anvil_set_code(STATIC_CALLER, static_caller_runtime(AUTHORITY)).await.unwrap();

    assert_eq!(call_word(&provider, STATIC_CALLER).await, U256::ZERO);
    assert!(send_call(&provider, from, STATIC_CALLER).await);
    assert_eq!(provider.get_code_at(AUTHORITY).await.unwrap(), original);
}

#[tokio::test(flavor = "multi_thread")]
async fn setselfdelegate_update_reverts_with_its_frame() {
    let (api, handle) = spawn(enabled_config(EthereumHardfork::Prague)).await;
    let provider = handle.http_provider();
    let from = handle.dev_accounts().next().unwrap();
    let original = delegation(EIP7702_DELEGATION_VERSION, FIRST_DELEGATE);
    api.anvil_set_code(FIRST_DELEGATE, reverting_runtime(SECOND_DELEGATE)).await.unwrap();
    api.anvil_set_code(AUTHORITY, original.clone()).await.unwrap();

    assert!(!send_call(&provider, from, AUTHORITY).await);
    assert_eq!(provider.get_code_at(AUTHORITY).await.unwrap(), original);
}

#[tokio::test(flavor = "multi_thread")]
async fn setselfdelegate_charges_exactly_9500_gas() {
    let (api, handle) = spawn(enabled_config(EthereumHardfork::Prague)).await;
    let provider = handle.http_provider();
    api.anvil_set_code(FIRST_DELEGATE, gas_probe_runtime(SECOND_DELEGATE)).await.unwrap();
    api.anvil_set_code(AUTHORITY, delegation(EIP7702_DELEGATION_VERSION, FIRST_DELEGATE))
        .await
        .unwrap();

    let output = call(&provider, AUTHORITY).await;
    assert_eq!(output.len(), 64);
    let gas_before = U256::from_be_slice(&output[..32]);
    let gas_after = U256::from_be_slice(&output[32..]);
    // PUSH20, POP, and the second GAS account for the seven non-opcode gas units.
    assert_eq!(gas_before - gas_after, U256::from(SETSELFDELEGATE_GAS + 7));
}

#[tokio::test(flavor = "multi_thread")]
async fn setselfdelegate_keeps_current_code_but_reentry_loads_the_new_delegate() {
    let (api, handle) = spawn(enabled_config(EthereumHardfork::Prague)).await;
    let provider = handle.http_provider();
    api.anvil_set_code(FIRST_DELEGATE, reentrant_runtime(SECOND_DELEGATE)).await.unwrap();
    api.anvil_set_code(
        SECOND_DELEGATE,
        Bytes::from_static(&[0x60, 0x2a, 0x5f, 0x52, 0x60, 0x20, 0x5f, 0xf3]),
    )
    .await
    .unwrap();
    api.anvil_set_code(AUTHORITY, delegation(EIP7702_DELEGATION_VERSION, FIRST_DELEGATE))
        .await
        .unwrap();

    let output = call(&provider, AUTHORITY).await;
    assert_eq!(output.len(), 64);
    assert_eq!(U256::from_be_slice(&output[..32]), U256::from(0x11));
    assert_eq!(U256::from_be_slice(&output[32..]), U256::from(42));
}

#[tokio::test(flavor = "multi_thread")]
async fn pool_rejects_raw_ecdsa_transaction_from_disabled_authority_without_inline_code() {
    let (api, handle) = spawn(enabled_config(EthereumHardfork::Prague)).await;
    let provider = handle.http_provider();
    let wallets = handle.dev_wallets().collect::<Vec<_>>();
    let sender = wallets[0].address();
    let disabled = delegation(EIP7851_DELEGATION_VERSION, FIRST_DELEGATE);
    api.anvil_set_code(
        FIRST_DELEGATE,
        Bytes::from_static(&[0x60, 0x2a, 0x5f, 0x52, 0x60, 0x20, 0x5f, 0xf3]),
    )
    .await
    .unwrap();
    api.anvil_set_code(sender, disabled.clone()).await.unwrap();

    let mut account = api.backend.get_account(sender).await.unwrap();
    assert!(account.code.is_some());
    account.code = None;
    {
        let db = api.backend.get_db();
        db.write().await.insert_account(sender, account);
    }
    assert!(api.backend.get_account(sender).await.unwrap().code.is_none());
    assert_eq!(provider.get_code_at(sender).await.unwrap(), disabled);

    let object_request =
        TransactionRequest::default().with_from(sender).with_to(sender).with_gas_limit(100_000);
    let output = provider.call(object_request.clone().into()).await.unwrap();
    assert_eq!(U256::from_be_slice(output.as_ref()), U256::from(42));
    assert!(provider.estimate_gas(object_request.clone().into()).await.unwrap() > 0);

    let fees = provider.estimate_eip1559_fees().await.unwrap();
    let mut tx = TxEip1559 {
        chain_id: api.chain_id(),
        gas_limit: 21_000,
        max_fee_per_gas: fees.max_fee_per_gas,
        max_priority_fee_per_gas: fees.max_priority_fee_per_gas,
        to: TxKind::Call(wallets[1].address()),
        ..Default::default()
    };
    let signature = wallets[0].sign_transaction_sync(&mut tx).unwrap();
    let mut encoded = Vec::new();
    tx.into_signed(signature).encode_2718(&mut encoded);

    let err = provider.send_raw_transaction(&encoded).await.unwrap_err().to_string();
    assert!(err.contains("sender not an eoa"), "unexpected error: {err}");

    api.anvil_impersonate_account(sender).await.unwrap();
    let receipt = provider
        .send_transaction(object_request.into())
        .await
        .expect("impersonated transaction should pass EIP-7851 pool admission")
        .get_receipt()
        .await
        .expect("impersonated transaction should be mined");
    assert!(receipt.status());
    assert!(receipt.block_number.is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn eip7702_skips_authorization_from_disabled_authority() {
    let (api, handle) = spawn(enabled_config(EthereumHardfork::Prague)).await;
    let provider = handle.http_provider();
    let wallets = handle.dev_wallets().collect::<Vec<_>>();
    let authority = wallets[0].address();
    let disabled = delegation(EIP7851_DELEGATION_VERSION, FIRST_DELEGATE);
    api.anvil_set_code(FIRST_DELEGATE, Bytes::from_static(&[0x00])).await.unwrap();
    api.anvil_set_code(SECOND_DELEGATE, Bytes::from_static(&[0x00])).await.unwrap();
    api.anvil_set_code(authority, disabled.clone()).await.unwrap();
    let authority_nonce = provider.get_transaction_count(authority).await.unwrap();

    let authorization = Authorization {
        chain_id: U256::from(api.chain_id()),
        address: SECOND_DELEGATE,
        nonce: authority_nonce,
    };
    let signature = wallets[0].sign_hash_sync(&authorization.signature_hash()).unwrap();
    let fees = provider.estimate_eip1559_fees().await.unwrap();
    let mut tx = TxEip7702 {
        chain_id: api.chain_id(),
        gas_limit: 100_000,
        max_fee_per_gas: fees.max_fee_per_gas,
        max_priority_fee_per_gas: fees.max_priority_fee_per_gas,
        to: wallets[2].address(),
        authorization_list: vec![authorization.into_signed(signature)],
        ..Default::default()
    };
    let signature = wallets[1].sign_transaction_sync(&mut tx).unwrap();
    let mut encoded = Vec::new();
    tx.into_signed(signature).encode_2718(&mut encoded);

    let receipt =
        provider.send_raw_transaction(&encoded).await.unwrap().get_receipt().await.unwrap();
    assert!(receipt.status());
    assert_eq!(provider.get_code_at(authority).await.unwrap(), disabled);
    assert_eq!(provider.get_transaction_count(authority).await.unwrap(), authority_nonce);
}
