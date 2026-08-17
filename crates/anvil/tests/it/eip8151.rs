//! EIP-8151 integration tests against ethereum/EIPs commit
//! bf7a4067f263bf7ce01c1511de48473e281d885d.

use alloy_evm::precompiles::{DynPrecompile, PrecompileInput};
use alloy_network::{ReceiptResponse, TransactionBuilder};
use alloy_primitives::{Address, B256, Bytes, Signature, U256, address, keccak256};
use alloy_provider::Provider;
use alloy_rpc_types::{
    AccessList, AccessListItem, TransactionRequest,
    state::{AccountOverride, EvmOverrides, StateOverride},
    trace::{
        geth::{GethDebugTracingOptions, GethTrace},
        parity::TraceType,
    },
};
use alloy_serde::WithOtherFields;
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use anvil::{NodeConfig, PrecompileFactory, spawn, try_spawn};
use foundry_common::provider::RetryProvider;
use foundry_evm::hardfork::EthereumHardfork;
use foundry_primitives::FoundryNetwork;
use revm::{
    bytecode::Bytecode,
    precompile::{PrecompileId, PrecompileOutput},
};

const EC_RECOVER: Address = address!("0000000000000000000000000000000000000001");
const PROBE: Address = address!("0000000000000000000000000000000000008151");
const REVERTING_PROBE: Address = address!("0000000000000000000000000000000000008152");
const DELEGATE: Address = address!("000000000000000000000000000000000000dE1e");
const DELEGATION_TARGET: Address = address!("000000000000000000000000000000000000dEaD");
const OVERRIDE_ADDRESS: Address = address!("0000000000000000000000000000000000000bad");
const ZERO_WORD: [u8; 32] = [0; 32];
const SETSELFDELEGATE: u8 = 0xf7;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ProbeResult {
    output: [u8; 32],
    success: bool,
    return_size: u64,
}

fn enabled_config() -> NodeConfig {
    NodeConfig::test().with_hardfork(Some(EthereumHardfork::Prague.into())).enable_eip8151(true)
}

fn ecrecover_input(signer: &PrivateKeySigner) -> (Address, B256, Signature, Bytes) {
    let hash = keccak256(b"foundry eip-8151 integration test");
    let signature = signer.sign_hash_sync(&hash).unwrap();
    let mut input = [0u8; 128];
    input[..32].copy_from_slice(hash.as_slice());
    input[63] = signature.v_byte();
    input[64..96].copy_from_slice(&signature.r().to_be_bytes::<32>());
    input[96..].copy_from_slice(&signature.s().to_be_bytes::<32>());
    (signer.address(), hash, signature, Bytes::copy_from_slice(&input))
}

fn invalid_ecrecover_input() -> Bytes {
    let mut input = [0u8; 128];
    input[63] = 29;
    Bytes::copy_from_slice(&input)
}

fn address_word(address: Address) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(address.as_slice());
    word
}

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
        0x50, // POP
        0x00, // STOP
    ]);
    code.into()
}

fn push2(code: &mut Vec<u8>, value: u16) {
    code.extend_from_slice(&[0x61, (value >> 8) as u8, value as u8]);
}

fn append_ecrecover_probe(code: &mut Vec<u8>, gas: u16, result_offset: u16) {
    push2(code, 32); // return size
    push2(code, result_offset); // return offset
    push2(code, 128); // input size
    code.push(0x5f); // input offset
    code.extend_from_slice(&[0x60, 0x01]); // ECRecover
    push2(code, gas);
    code.push(0xfa); // STATICCALL
    push2(code, result_offset + 32);
    code.push(0x52); // MSTORE success
    code.push(0x3d); // RETURNDATASIZE
    push2(code, result_offset + 64);
    code.push(0x52); // MSTORE return size
}

/// Calls ECRecover once for each supplied gas limit and returns `(output, success, returndatasize)`
/// triples. Keeping all calls in one frame makes transaction-scoped warmth directly observable.
fn probe_runtime(call_gas: &[u16]) -> Bytes {
    const RESULTS_OFFSET: u16 = 0x0100;
    const RESULT_LEN: u16 = 96;

    let mut code = Vec::new();
    push2(&mut code, 128);
    code.extend_from_slice(&[0x5f, 0x5f, 0x37]); // PUSH0, PUSH0, CALLDATACOPY

    for (index, gas) in call_gas.iter().copied().enumerate() {
        let result_offset = RESULTS_OFFSET + RESULT_LEN * index as u16;
        append_ecrecover_probe(&mut code, gas, result_offset);
    }

    push2(&mut code, RESULT_LEN * call_gas.len() as u16);
    push2(&mut code, RESULTS_OFFSET);
    code.push(0xf3); // RETURN
    code.into()
}

fn reverting_probe_runtime() -> Bytes {
    let mut code = Vec::new();
    push2(&mut code, 128);
    code.extend_from_slice(&[0x5f, 0x5f, 0x37]);
    append_ecrecover_probe(&mut code, 5_600, 0x0100);
    code.extend_from_slice(&[0x5f, 0x5f, 0xfd]); // REVERT
    code.into()
}

fn probe_after_reverted_subcall_runtime() -> Bytes {
    let mut code = Vec::new();
    push2(&mut code, 128);
    code.extend_from_slice(&[0x5f, 0x5f, 0x37]);

    code.push(0x5f); // return size
    code.push(0x5f); // return offset
    push2(&mut code, 128); // input size
    code.push(0x5f); // input offset
    push2(&mut code, 0x8152); // reverting probe
    push2(&mut code, 50_000);
    code.extend_from_slice(&[0xfa, 0x50]); // STATICCALL, POP

    append_ecrecover_probe(&mut code, 3_100, 0x0100);
    push2(&mut code, 96);
    push2(&mut code, 0x0100);
    code.push(0xf3);
    code.into()
}

fn decode_probe(output: &[u8]) -> Vec<ProbeResult> {
    let (chunks, remainder) = output.as_chunks::<96>();
    assert!(remainder.is_empty(), "invalid probe output length");
    chunks
        .iter()
        .map(|chunk| ProbeResult {
            output: chunk[..32].try_into().unwrap(),
            success: U256::from_be_slice(&chunk[32..64]) == U256::from(1),
            return_size: U256::from_be_slice(&chunk[64..96]).to::<u64>(),
        })
        .collect()
}

async fn call_probe(
    provider: &RetryProvider,
    input: Bytes,
    access_list: Option<AccessList>,
) -> Vec<ProbeResult> {
    let mut request =
        TransactionRequest::default().with_to(PROBE).with_input(input).with_gas_limit(500_000);
    request.access_list = access_list;
    decode_probe(&provider.call(request.into()).await.unwrap())
}

async fn install_probe(api: &anvil::eth::EthApi<FoundryNetwork>, call_gas: &[u16]) {
    api.anvil_set_code(PROBE, probe_runtime(call_gas)).await.unwrap();
}

async fn set_raw_legacy_code(
    api: &anvil::eth::EthApi<FoundryNetwork>,
    address: Address,
    code: Bytes,
) {
    let mut account = api.backend.get_account(address).await.unwrap();
    let code = Bytecode::new_legacy(code);
    account.code_hash = code.hash_slow();
    account.code = Some(code);
    api.backend.get_db().write().await.insert_account(address, account);
}

fn assert_allowed(result: ProbeResult, recovered: Address) {
    assert!(result.success);
    assert_eq!(result.return_size, 32);
    assert_eq!(result.output, address_word(recovered));
}

fn assert_rejected(result: ProbeResult) {
    assert!(result.success);
    assert_eq!(result.return_size, 32);
    assert_eq!(result.output, ZERO_WORD);
}

#[tokio::test(flavor = "multi_thread")]
async fn activation_is_default_off_prague_gated_and_ethereum_only() {
    let signer = PrivateKeySigner::random();
    let (recovered, _, _, input) = ecrecover_input(&signer);

    for config in [
        NodeConfig::test().with_hardfork(Some(EthereumHardfork::Prague.into())),
        NodeConfig::test()
            .with_hardfork(Some(EthereumHardfork::Cancun.into()))
            .enable_eip8151(true),
    ] {
        let (api, handle) = spawn(config).await;
        install_probe(&api, &[3_000]).await;
        api.anvil_set_code(recovered, Bytes::from_static(&[0x00])).await.unwrap();
        assert_allowed(
            call_probe(&handle.http_provider(), input.clone(), None).await[0],
            recovered,
        );
        let legacy_invalid =
            call_probe(&handle.http_provider(), invalid_ecrecover_input(), None).await[0];
        assert!(legacy_invalid.success);
        assert_eq!(legacy_invalid.return_size, 0);
    }

    let (api, handle) = spawn(enabled_config()).await;
    install_probe(&api, &[5_600]).await;
    api.anvil_set_code(recovered, Bytes::from_static(&[0x00])).await.unwrap();
    assert_rejected(call_probe(&handle.http_provider(), input, None).await[0]);

    let error = try_spawn(NodeConfig::test_tempo().enable_eip8151(true)).await.err().unwrap();
    assert!(error.to_string().contains("active profile is `tempo`"), "unexpected error: {error}");
}

#[tokio::test(flavor = "multi_thread")]
async fn raw_code_permission_is_exact_does_not_follow_delegation_and_is_not_cached() {
    let signer = PrivateKeySigner::random();
    let (recovered, _, _, input) = ecrecover_input(&signer);
    let (api, handle) = spawn(enabled_config()).await;
    let provider = handle.http_provider();
    install_probe(&api, &[5_600]).await;

    assert_allowed(call_probe(&provider, input.clone(), None).await[0], recovered);

    api.anvil_set_code(recovered, Bytes::new()).await.unwrap();
    assert_allowed(call_probe(&provider, input.clone(), None).await[0], recovered);

    api.anvil_set_code(DELEGATION_TARGET, Bytes::from_static(&[0x60, 0x00])).await.unwrap();
    api.anvil_set_code(recovered, delegation(0, DELEGATION_TARGET)).await.unwrap();
    assert_allowed(call_probe(&provider, input.clone(), None).await[0], recovered);

    for rejected_code in [
        Bytes::from_static(&[0x00]),
        delegation(1, DELEGATION_TARGET),
        Bytes::from_static(&[0xef, 0x01, 0x00]),
        Bytes::from(vec![0xef; 24]),
    ] {
        set_raw_legacy_code(&api, recovered, rejected_code).await;
        assert_rejected(call_probe(&provider, input.clone(), None).await[0]);
    }

    api.anvil_set_code(recovered, Bytes::new()).await.unwrap();
    assert_allowed(call_probe(&provider, input, None).await[0], recovered);
}

#[tokio::test(flavor = "multi_thread")]
async fn exact_gas_warmth_repetition_and_failed_recovery_match_eip8151() {
    let signer = PrivateKeySigner::random();
    let (recovered, _, _, input) = ecrecover_input(&signer);
    let (api, handle) = spawn(enabled_config()).await;
    let provider = handle.http_provider();

    install_probe(&api, &[5_599, 3_100, 5_600]).await;
    let reverted_warmth = call_probe(&provider, input.clone(), None).await;
    assert!(!reverted_warmth[0].success);
    assert!(!reverted_warmth[1].success);
    assert_allowed(reverted_warmth[2], recovered);

    install_probe(&api, &[5_600, 3_100]).await;
    let repeated = call_probe(&provider, input.clone(), None).await;
    assert_allowed(repeated[0], recovered);
    assert_allowed(repeated[1], recovered);

    api.anvil_set_code(REVERTING_PROBE, reverting_probe_runtime()).await.unwrap();
    api.anvil_set_code(PROBE, probe_after_reverted_subcall_runtime()).await.unwrap();
    assert!(!call_probe(&provider, input.clone(), None).await[0].success);

    api.anvil_set_code(recovered, Bytes::from_static(&[0x00])).await.unwrap();
    install_probe(&api, &[5_600, 3_100]).await;
    let repeated_rejection = call_probe(&provider, input.clone(), None).await;
    assert_rejected(repeated_rejection[0]);
    assert_rejected(repeated_rejection[1]);

    api.anvil_set_code(recovered, Bytes::new()).await.unwrap();

    let warm_access_list =
        AccessList::from(vec![AccessListItem { address: recovered, storage_keys: Vec::new() }]);
    install_probe(&api, &[3_099]).await;
    assert!(!call_probe(&provider, input.clone(), Some(warm_access_list.clone())).await[0].success);
    install_probe(&api, &[3_100]).await;
    assert_allowed(call_probe(&provider, input, Some(warm_access_list)).await[0], recovered);

    install_probe(&api, &[3_000]).await;
    let failed = call_probe(&provider, invalid_ecrecover_input(), None).await[0];
    assert_rejected(failed);
}

#[tokio::test(flavor = "multi_thread")]
async fn create_access_list_includes_nested_recovery_but_not_delegation_target() {
    let signer = PrivateKeySigner::random();
    let (recovered, _, _, input) = ecrecover_input(&signer);
    let (api, handle) = spawn(enabled_config()).await;
    let provider = handle.http_provider();
    install_probe(&api, &[5_600]).await;
    api.anvil_set_code(DELEGATION_TARGET, Bytes::from_static(&[0x60, 0x00])).await.unwrap();
    api.anvil_set_code(recovered, delegation(0, DELEGATION_TARGET)).await.unwrap();

    let from = handle.dev_accounts().next().unwrap();
    let nested_request = TransactionRequest::default()
        .with_from(from)
        .with_to(PROBE)
        .with_input(input.clone())
        .with_gas_limit(500_000);
    let nested = provider.create_access_list(&WithOtherFields::new(nested_request)).await.unwrap();

    let recovered_item = nested
        .access_list
        .0
        .iter()
        .find(|item| item.address == recovered)
        .expect("recovered account missing from access list");
    assert!(recovered_item.storage_keys.is_empty());
    assert!(!nested.access_list.0.iter().any(|item| item.address == DELEGATION_TARGET));

    install_probe(&api, &[3_100]).await;
    assert!(!call_probe(&provider, input.clone(), None).await[0].success);
    assert_allowed(call_probe(&provider, input, Some(nested.access_list)).await[0], recovered);
}

#[tokio::test(flavor = "multi_thread")]
async fn state_override_reset_and_fork_preserve_restrictions() {
    let signer = PrivateKeySigner::random();
    let (recovered, _, _, input) = ecrecover_input(&signer);
    let (api, handle) = spawn(enabled_config()).await;
    let provider = handle.http_provider();
    install_probe(&api, &[5_600]).await;

    let request = TransactionRequest::default()
        .with_to(PROBE)
        .with_input(input.clone())
        .with_gas_limit(500_000);
    let mut overrides = StateOverride::default();
    overrides.insert(
        recovered,
        AccountOverride { code: Some(Bytes::from_static(&[0x00])), ..Default::default() },
    );
    let overridden = api
        .call(WithOtherFields::new(request), None, EvmOverrides::new(Some(overrides), None))
        .await
        .unwrap();
    assert_rejected(decode_probe(&overridden)[0]);

    api.anvil_set_code(recovered, Bytes::from_static(&[0x00])).await.unwrap();
    assert_rejected(call_probe(&provider, input.clone(), None).await[0]);
    api.anvil_reset(None).await.unwrap();
    install_probe(&api, &[5_600]).await;
    assert_allowed(call_probe(&provider, input.clone(), None).await[0], recovered);

    let (source_api, source_handle) =
        spawn(NodeConfig::test().with_hardfork(Some(EthereumHardfork::Prague.into()))).await;
    source_api.anvil_set_code(recovered, Bytes::from_static(&[0x00])).await.unwrap();
    source_api.mine_one().await.unwrap();
    let (fork_api, fork_handle) =
        spawn(enabled_config().with_eth_rpc_url(Some(source_handle.http_endpoint()))).await;
    install_probe(&fork_api, &[5_600]).await;
    assert_rejected(call_probe(&fork_handle.http_provider(), input, None).await[0]);
}

#[tokio::test(flavor = "multi_thread")]
async fn call_transaction_estimate_and_trace_replay_agree() {
    let signer = PrivateKeySigner::random();
    let (recovered, _, _, input) = ecrecover_input(&signer);
    let (api, handle) = spawn(enabled_config()).await;
    let provider = handle.http_provider();
    install_probe(&api, &[5_600]).await;
    api.anvil_set_code(recovered, Bytes::from_static(&[0x00])).await.unwrap();

    let from = handle.dev_accounts().next().unwrap();
    let request = TransactionRequest::default()
        .with_from(from)
        .with_to(PROBE)
        .with_input(input)
        .with_gas_limit(500_000);
    let call_output = provider.call(request.clone().into()).await.unwrap();
    assert_rejected(decode_probe(&call_output)[0]);
    assert!(provider.estimate_gas(request.clone().into()).await.unwrap() > 0);

    let receipt =
        provider.send_transaction(request.into()).await.unwrap().get_receipt().await.unwrap();
    assert!(receipt.status());

    let replay = api
        .trace_replay_transaction(
            receipt.transaction_hash,
            [TraceType::Trace].into_iter().collect(),
        )
        .await
        .unwrap();
    assert_eq!(replay.output, call_output);

    let trace = api
        .debug_trace_transaction(receipt.transaction_hash, GethDebugTracingOptions::default())
        .await
        .unwrap();
    let GethTrace::Default(trace) = trace else { panic!("expected default transaction trace") };
    assert_eq!(trace.return_value, call_output);
}

#[tokio::test(flavor = "multi_thread")]
async fn eip7851_transition_from_ef0100_to_ef0101_disables_recovery() {
    let signer = PrivateKeySigner::random();
    let (recovered, _, _, input) = ecrecover_input(&signer);
    let config = enabled_config().enable_eip7851(true);
    let (api, handle) = spawn(config).await;
    let provider = handle.http_provider();
    install_probe(&api, &[5_600]).await;
    api.anvil_set_code(DELEGATE, setselfdelegate_runtime(DELEGATION_TARGET)).await.unwrap();
    api.anvil_set_code(recovered, delegation(0, DELEGATE)).await.unwrap();

    assert_allowed(call_probe(&provider, input.clone(), None).await[0], recovered);
    let receipt = provider
        .send_transaction(
            TransactionRequest::default()
                .with_from(handle.dev_accounts().next().unwrap())
                .with_to(recovered)
                .with_gas_limit(100_000)
                .into(),
        )
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    assert!(receipt.status());
    assert_eq!(provider.get_code_at(recovered).await.unwrap(), delegation(1, DELEGATION_TARGET));
    assert_rejected(call_probe(&provider, input, None).await[0]);
}

#[derive(Debug)]
struct EcrecoverOverride;

impl PrecompileFactory for EcrecoverOverride {
    fn precompiles(&self) -> Vec<(Address, DynPrecompile)> {
        vec![(
            EC_RECOVER,
            DynPrecompile::new_stateful(
                PrecompileId::custom("eip8151_test_override"),
                |input: PrecompileInput<'_>| {
                    Ok(PrecompileOutput::new(
                        5_600,
                        Bytes::copy_from_slice(&address_word(OVERRIDE_ADDRESS)),
                        input.reservoir,
                    ))
                },
            ),
        )]
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn deliberate_precompile_and_signature_overrides_preserve_layering() {
    let signer = PrivateKeySigner::random();
    let (recovered, _, _, input) = ecrecover_input(&signer);
    let (api, handle) = spawn(enabled_config().with_precompile_factory(EcrecoverOverride)).await;
    let provider = handle.http_provider();
    install_probe(&api, &[5_600]).await;
    assert_allowed(call_probe(&provider, input.clone(), None).await[0], OVERRIDE_ADDRESS);
    let request = WithOtherFields::new(
        TransactionRequest::default()
            .with_from(handle.dev_accounts().next().unwrap())
            .with_to(PROBE)
            .with_input(input)
            .with_gas_limit(500_000),
    );
    let access_list = provider.create_access_list(&request).await.unwrap().access_list;
    assert!(!access_list.0.iter().any(|item| item.address == recovered));

    let matching_signer = PrivateKeySigner::random();
    let (matching_recovered, _, matching_signature, matching_input) =
        ecrecover_input(&matching_signer);
    let nonmatching_signer = PrivateKeySigner::random();
    let (recovered, _, _, real_input) = ecrecover_input(&nonmatching_signer);
    let (api, handle) = spawn(enabled_config()).await;
    let provider = handle.http_provider();
    install_probe(&api, &[5_600]).await;
    api.anvil_set_code(recovered, Bytes::from_static(&[0x00])).await.unwrap();

    api.anvil_impersonate_signature(matching_signature.as_bytes().into(), OVERRIDE_ADDRESS)
        .await
        .unwrap();
    api.anvil_set_code(OVERRIDE_ADDRESS, Bytes::from_static(&[0x00])).await.unwrap();
    assert_allowed(call_probe(&provider, matching_input.clone(), None).await[0], OVERRIDE_ADDRESS);
    assert_rejected(call_probe(&provider, real_input.clone(), None).await[0]);

    let from = handle.dev_accounts().next().unwrap();
    let matching_request = WithOtherFields::new(
        TransactionRequest::default()
            .with_from(from)
            .with_to(PROBE)
            .with_input(matching_input)
            .with_gas_limit(500_000),
    );
    let matching_access_list =
        provider.create_access_list(&matching_request).await.unwrap().access_list;
    assert!(!matching_access_list.0.iter().any(|item| item.address == matching_recovered));

    let nonmatching_request = WithOtherFields::new(
        TransactionRequest::default()
            .with_from(from)
            .with_to(PROBE)
            .with_input(real_input)
            .with_gas_limit(500_000),
    );
    let nonmatching_access_list =
        provider.create_access_list(&nonmatching_request).await.unwrap().access_list;
    assert!(nonmatching_access_list.0.iter().any(|item| item.address == recovered));
}
