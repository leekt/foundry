//! EIP-8141 frame transactions, end to end through a running node.
//!
//! The envelope tests in `foundry-primitives` prove the encoding and the
//! signature rules; these prove that a valid signed frame transaction is
//! accepted, mined and *executed* -- the storage and balance assertions below
//! fail if the frame loop is skipped.
//!
//! Author: taek <leekt216@gmail.com>

use crate::utils::http_provider;
use alloy_consensus::{Typed2718, proofs::calculate_receipt_root};
use alloy_eips::{Encodable2718, eip7840::BlobParams};
use alloy_network::{ReceiptResponse, TransactionBuilder};
use alloy_primitives::{Address, B256, Bytes, Sealable, U256, bytes, keccak256};
use alloy_provider::{Provider, ext::TraceApi};
use alloy_rpc_types::{
    TransactionRequest,
    trace::parity::{Action, TraceResults, TraceType},
};
use alloy_serde::WithOtherFields;
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use anvil::{NodeConfig, eth::EthApi, spawn};
use foundry_common::provider::RetryProvider;
use foundry_evm::hardfork::EthereumHardfork;
use foundry_primitives::{
    EXPIRY_VERIFIER_ADDRESS, EXPIRY_VERIFIER_RUNTIME_CODE, FoundryNetwork, FoundryReceiptEnvelope,
    Frame, FrameReceipt, FrameSignature, TxFrame, flags, frame_gas as gas, mode, scheme,
};
use ml_dsa::{
    Keypair as _, MlDsa44, Seed, Signature as MlDsaSignature, Signer as _,
    SigningKey as MlDsaSigningKey,
};
use p256::ecdsa::{
    Signature as P256Signature, SigningKey as P256SigningKey, signature::hazmat::PrehashSigner,
};

/// Deploys `5f355f5500`: `SSTORE(0, calldata[0..32])`, then stop. Payable by
/// virtue of having no value check at all.
const STORAGE_WRITER_INITCODE: Bytes = bytes!("645f355f55005f526005601bf3");

/// Deploys `5f5ffd`: `REVERT(0, 0)`, so every call to it fails.
const REVERTER_INITCODE: Bytes = bytes!("625f5ffd5f526003601df3");

/// Deploys `5f355f5560035f5faa`: write calldata to slot 0, then approve both scopes.
const MUTATING_APPROVER_INITCODE: Bytes = bytes!("685f355f5560035f5faa5f5260096017f3");

/// The metadata-free runtime emitted for `contracts/src/accounts/P256Account.sol`.
///
/// The test installs the production runtime directly so it can focus on raw
/// frame-envelope admission and the account's VERIFY path without coupling the
/// Rust suite to an external Solidity build step. Slot zero is populated with
/// the key-derived signer below, exactly as the constructor would populate it.
/// Regenerate after rebuilding the contracts with:
/// `jq -r .deployedBytecode.object contracts/out/P256Account.sol/P256Account.json`.
const P256_ACCOUNT_RUNTIME: Bytes = bytes!(
    "608060405260043610610041575f3560e01c80636fa364651461004c5780638d2b1f571461006d578063ce4d01a3146100a7578063f3376a09146100c6575f5ffd5b3661004857005b5f5ffd5b348015610057575f5ffd5b5061006b61006636600461026f565b6100e5565b005b348015610078575f5ffd5b505f5461008b906001600160a01b031681565b6040516001600160a01b03909116815260200160405180910390f35b3480156100b2575f5ffd5b5061006b6100c136600461028f565b610158565b3480156100d1575f5ffd5b5061008b6100e036600461026f565b610205565b333014610105576040516314e1dbf760e11b815260040160405180910390fd5b61010f8282610217565b5f80546001600160a01b0319166001600160a01b039290921691821781556040517f316aad49c9322783338ad5a4800300704fe9b4005f32d40bb8c1348713e975919190a25050565b6002600182b41461017c5760405163afd2b59d60e01b815260040160405180910390fd5b600281b41561019e5760405163afd2b59d60e01b815260040160405180910390fd5b5f80546001600160a01b03169082b46001600160a01b0316146101d45760405163afd2b59d60e01b815260040160405180910390fd5b6006600ab0b3806101f85760405163353dfba360e21b815260040160405180910390fd5b61020181805f5faa5b5050565b5f6102108383610217565b9392505050565b5f82158015610224575081155b156102425760405163145a1fdd60e31b815260040160405180910390fd5b50604080516020808201949094528082019290925280518083038201815260609092019052805191012090565b5f5f60408385031215610280575f5ffd5b50508035926020909101359150565b5f6020828403121561029f575f5ffd5b503591905056"
);

/// The metadata-free runtime emitted for `contracts/src/accounts/MLDSAAccount.sol`.
///
/// As with the P256 fixture above, the test installs production runtime and
/// writes slot zero exactly as the constructor does. Regenerate with:
/// `jq -r .deployedBytecode.object contracts/out/MLDSAAccount.sol/MLDSAAccount.json`.
const MLDSA_ACCOUNT_RUNTIME: Bytes = bytes!(
    "608060405260043610610041575f3560e01c80639b0453f31461004c578063ce4d01a31461006d578063d52fafa41461008c578063e21e5a82146100c6575f5ffd5b3661004857005b5f5ffd5b348015610057575f5ffd5b5061006b6100663660046102e6565b6100e5565b005b348015610078575f5ffd5b5061006b610087366004610354565b61018c565b348015610097575f5ffd5b505f546100aa906001600160a01b031681565b6040516001600160a01b03909116815260200160405180910390f35b3480156100d1575f5ffd5b506100aa6100e03660046102e6565b610239565b333014610105576040516314e1dbf760e11b815260040160405180910390fd5b61014382828080601f0160208091040260200160405190810160405280939291908181526020018383808284375f9201919091525061027f92505050565b5f80546001600160a01b0319166001600160a01b039290921691821781556040517f139b5b7b89277bad2ac5217262c52f1eca5af1b14c6709ce1cfe93975ac921959190a25050565b6003600182b4146101b05760405163afd2b59d60e01b815260040160405180910390fd5b600281b4156101d25760405163afd2b59d60e01b815260040160405180910390fd5b5f80546001600160a01b03169082b46001600160a01b0316146102085760405163afd2b59d60e01b815260040160405180910390fd5b6006600ab0b38061022c5760405163353dfba360e21b815260040160405180910390fd5b61023581805f5faa5b5050565b5f61027883838080601f0160208091040260200160405190810160405280939291908181526020018383808284375f9201919091525061027f92505050565b9392505050565b5f6105208251146102b15781516040516317ab7d5d60e11b81526004016102a891815260200190565b60405180910390fd5b6040516102c890600360f81b90849060200161036b565b60408051601f19818403018152919052805160209091012092915050565b5f5f602083850312156102f7575f5ffd5b823567ffffffffffffffff81111561030d575f5ffd5b8301601f8101851361031d575f5ffd5b803567ffffffffffffffff811115610333575f5ffd5b856020828401011115610344575f5ffd5b6020919091019590945092505050565b5f60208284031215610364575f5ffd5b5035919050565b6001600160f81b03198316815281515f908060208501600185015e5f9201600101918252509291505056"
);

/// The metadata-free runtime emitted for `contracts/src/accounts/MultisigAccount.sol`.
/// Storage is initialized below as constructor-equivalent owner mappings and
/// threshold. Regenerate with:
/// `jq -r .deployedBytecode.object contracts/out/MultisigAccount.sol/MultisigAccount.json`.
const MULTISIG_ACCOUNT_RUNTIME: Bytes = bytes!(
    "608060405260043610610036575f3560e01c806325b90494146100415780632f54bf6e1461006257806342cde4e8146100a5575f5ffd5b3661003d57005b5f5ffd5b34801561004c575f5ffd5b5061006061005b366004610224565b6100c8565b005b34801561006d575f5ffd5b5061009061007c366004610295565b5f6020819052908152604090205460ff1681565b60405190151581526020015b60405180910390f35b3480156100b0575f5ffd5b506100ba60015481565b60405190815260200161009c565b5f80805b838110156101c5575f8585838181106100e7576100e76102c2565b9050602002013590505f6100fc82600190b490565b905060018114158015610110575060028114155b801561011d575060038114155b156101295750506101bd565b600282b4156101395750506101bd565b5f8083b46001600160a01b03165f8181526020819052604090205490915060ff16610166575050506101bd565b8481116101b25760405162461bcd60e51b81526020600482015260156024820152741bdddb995c881cda59dcc81b9bdd081cdbdc9d1959605a1b60448201526064015b60405180910390fd5b600190950194935050505b6001016100cc565b5060015482101561020c5760405162461bcd60e51b81526020600482015260116024820152701d1a1c995cda1bdb19081b9bdd081b595d607a1b60448201526064016101a9565b61021e6006600ab0b3805f5faa805f5faa5b50505050565b5f5f60208385031215610235575f5ffd5b823567ffffffffffffffff81111561024b575f5ffd5b8301601f8101851361025b575f5ffd5b803567ffffffffffffffff811115610271575f5ffd5b8560208260051b8401011115610285575f5ffd5b6020919091019590945092505050565b5f602082840312156102a5575f5ffd5b81356001600160a01b03811681146102bb575f5ffd5b9392505050565b634e487b7160e01b5f52603260045260245ffd"
);

fn eip7851_designation(target: Address) -> Bytes {
    let mut code = Vec::with_capacity(23);
    code.extend_from_slice(&[0xef, 0x01, 0x01]);
    code.extend_from_slice(target.as_slice());
    code.into()
}

fn frame_node_config() -> NodeConfig {
    NodeConfig::test().with_frame_transactions(true)
}

/// Deploys `60035f5faa`: approve both scopes without any ordinary state change.
const APPROVER_INITCODE: Bytes = bytes!("6460035f5faa5f526005601bf3");

/// Deploys code that stores GASPRICE, BLOBHASH(0), and TXPARAM(0) in slots 0..2.
const TX_ENV_PROBE_INITCODE: Bytes = bytes!("6d3a5f555f496001555fb0600255005f52600e6012f3");

/// The word the SENDER frame writes to slot 0.
const MAGIC: u64 = 0xdead_beef;

/// Deploys `initcode` from `from` and returns the contract's address.
async fn deploy(provider: &RetryProvider, from: Address, initcode: Bytes) -> Address {
    deploy_with_value(provider, from, initcode, U256::ZERO).await
}

/// Deploys `initcode` with an initial contract balance and returns its address.
async fn deploy_with_value(
    provider: &RetryProvider,
    from: Address,
    initcode: Bytes,
    value: U256,
) -> Address {
    let deploy = TransactionRequest::default()
        .with_from(from)
        .into_create()
        .with_input(initcode)
        .with_value(value);
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

/// Deterministic P256 test key (private scalar 1).
fn p256_test_key() -> P256SigningKey {
    let mut scalar = [0u8; 32];
    scalar[31] = 1;
    P256SigningKey::from_bytes((&scalar).into()).unwrap()
}

/// EIP-8141's P256 signer identity: `keccak256(qx || qy)[12..]`.
fn p256_signer(key: &P256SigningKey) -> Address {
    let public_key = key.verifying_key().to_encoded_point(false);
    let uncompressed = public_key.as_bytes();
    debug_assert_eq!(uncompressed.len(), 65);
    Address::from_slice(&keccak256(&uncompressed[1..])[12..])
}

/// Signs a canonical transaction hash into the native P256 wire encoding
/// `r || s || qx || qy` and normalizes `s` for the pinned low-s profile.
fn sign_p256_entry(tx: &mut TxFrame, index: usize, key: &P256SigningKey) {
    let signature: P256Signature = key.sign_prehash(tx.signature_hash().as_slice()).unwrap();
    let signature = signature.normalize_s().unwrap_or(signature);
    let public_key = key.verifying_key().to_encoded_point(false);

    let mut encoded = Vec::with_capacity(128);
    encoded.extend_from_slice(signature.to_bytes().as_slice());
    encoded.extend_from_slice(&public_key.as_bytes()[1..]);
    debug_assert_eq!(encoded.len(), 128);
    tx.signatures[index].signature = encoded.into();
}

/// Deterministic ML-DSA-44 key used by the native protocol/account fixture.
fn ml_dsa_44_test_key() -> MlDsaSigningKey<MlDsa44> {
    MlDsaSigningKey::from_seed(&Seed::from([0x42; 32]))
}

/// Toolkit-local ML-DSA signer identity: `keccak256(0x03 || public_key)[12..]`.
fn ml_dsa_44_signer(key: &MlDsaSigningKey<MlDsa44>) -> Address {
    let public_key = key.verifying_key().encode();
    let mut identity = Vec::with_capacity(1 + public_key.len());
    identity.push(scheme::ML_DSA_44);
    identity.extend_from_slice(public_key.as_slice());
    Address::from_slice(&keccak256(identity)[12..])
}

/// Signs the canonical transaction hash into the experimental native wire
/// encoding `signature[2420] || public_key[1312]`.
fn sign_ml_dsa_44_entry(tx: &mut TxFrame, index: usize, key: &MlDsaSigningKey<MlDsa44>) {
    let signature: MlDsaSignature<MlDsa44> = key.sign(tx.signature_hash().as_slice());
    let public_key = key.verifying_key().encode();

    let mut encoded = Vec::with_capacity(3_732);
    encoded.extend_from_slice(signature.encode().as_slice());
    encoded.extend_from_slice(public_key.as_slice());
    debug_assert_eq!(encoded.len(), 3_732);
    tx.signatures[index].signature = encoded.into();
}

/// ABI encoding of `validate(uint256)` selecting signature entry zero.
fn validate_signature_zero_calldata() -> Bytes {
    let mut data = Vec::with_capacity(36);
    data.extend_from_slice(&[0xce, 0x4d, 0x01, 0xa3]);
    data.extend_from_slice(&U256::ZERO.to_be_bytes::<32>());
    data.into()
}

/// ABI encoding of `validate(uint256[])` selecting entries zero and one.
fn validate_signature_zero_one_calldata() -> Bytes {
    let mut data = Vec::with_capacity(132);
    data.extend_from_slice(&[0x25, 0xb9, 0x04, 0x94]);
    data.extend_from_slice(&U256::from(32).to_be_bytes::<32>());
    data.extend_from_slice(&U256::from(2).to_be_bytes::<32>());
    data.extend_from_slice(&U256::ZERO.to_be_bytes::<32>());
    data.extend_from_slice(&U256::ONE.to_be_bytes::<32>());
    data.into()
}

/// Storage slot for `mapping(address => bool)` at Solidity slot zero.
fn owner_mapping_slot(owner: Address) -> U256 {
    let mut preimage = [0u8; 64];
    preimage[12..32].copy_from_slice(owner.as_slice());
    U256::from_be_slice(keccak256(preimage).as_slice())
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
        state_gas_limit: 0,
        value: U256::ZERO,
        data: Bytes::new(),
    };
    let frames = std::iter::once(verify)
        .chain(calls.iter().map(|(target, flags)| Frame {
            mode: mode::SENDER,
            flags: *flags,
            target: Some(*target),
            gas_limit: 120_000,
            state_gas_limit: 0,
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
async fn fresh_node_installs_the_canonical_expiry_verifier() {
    let (api, handle) = spawn(frame_node_config()).await;
    let provider = http_provider(&handle.http_endpoint());

    let code = provider.get_code_at(EXPIRY_VERIFIER_ADDRESS).await.unwrap();

    assert_eq!(code.as_ref(), EXPIRY_VERIFIER_RUNTIME_CODE);
    let activated_state_root = api.state_root().await.unwrap();

    api.anvil_set_code(EXPIRY_VERIFIER_ADDRESS, Bytes::new()).await.unwrap();
    assert_ne!(api.state_root().await.unwrap(), activated_state_root);
    api.anvil_reset(None).await.unwrap();
    let code = provider.get_code_at(EXPIRY_VERIFIER_ADDRESS).await.unwrap();
    assert_eq!(code.as_ref(), EXPIRY_VERIFIER_RUNTIME_CODE);
    assert_eq!(api.state_root().await.unwrap(), activated_state_root);
}

#[tokio::test(flavor = "multi_thread")]
async fn frame_profile_is_inactive_by_default() {
    let (_api, handle) = spawn(NodeConfig::test()).await;
    let provider = http_provider(&handle.http_endpoint());
    assert!(provider.get_code_at(EXPIRY_VERIFIER_ADDRESS).await.unwrap().is_empty());

    let wallet = handle.dev_wallets().next().unwrap();
    let sender = wallet.address();
    let mut tx = self_relay_tx(sender, 0, sender, U256::ZERO, 1_000_000_000, 1);
    sign_entry(&mut tx, 0, &wallet);
    let err = provider.send_raw_transaction(&tx.encoded_2718()).await.unwrap_err().to_string();
    assert!(err.contains("--enable-frame-transactions"), "unexpected error: {err}");
}

/// Runs one custom-code frame whose target and declared sender are the same funded contract.
async fn run_contract_approval_frame(
    frame_mode: u8,
    initcode: Bytes,
    gas_limit: u64,
) -> (bool, U256, u64, u64, u64) {
    let (api, handle) = spawn(frame_node_config()).await;
    let provider = http_provider(&handle.http_endpoint());
    let wallet = handle.dev_wallets().next().unwrap();
    let account = deploy_with_value(
        &provider,
        wallet.address(),
        initcode,
        U256::from(1_000_000_000_000_000_000u128),
    )
    .await;
    let nonce = provider.get_transaction_count(account).await.unwrap();
    let fees = provider.estimate_eip1559_fees().await.unwrap();
    let tx = TxFrame {
        chain_id: U256::from(31337u64),
        nonce,
        sender: account,
        frames: vec![Frame {
            mode: frame_mode,
            flags: flags::APPROVE_EXECUTION_PAYMENT,
            target: None,
            gas_limit,
            state_gas_limit: 0,
            value: U256::ZERO,
            data: U256::from(MAGIC).to_be_bytes::<32>().into(),
        }],
        signatures: vec![],
        max_priority_fee_per_gas: U256::from(fees.max_priority_fee_per_gas),
        max_fee_per_gas: U256::from(fees.max_fee_per_gas),
        max_fee_per_blob_gas: U256::ZERO,
        blob_versioned_hashes: vec![],
    };
    let max_gas = tx.max_gas();
    let hash = submit_and_mine(&api, &provider, &tx).await;
    let mined = provider.get_transaction_receipt(hash).await.unwrap().is_some();
    let stored = provider.get_storage_at(account, U256::ZERO).await.unwrap();
    let nonce_after = provider.get_transaction_count(account).await.unwrap();
    (mined, stored, nonce, nonce_after, max_gas)
}

#[tokio::test(flavor = "multi_thread")]
async fn frame_tx_is_mined_and_its_sender_frame_runs() {
    let (api, handle) = spawn(frame_node_config()).await;
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
    let payer = receipt
        .0
        .other
        .get_deserialized::<Address>("payer")
        .transpose()
        .unwrap()
        .expect("frame receipt has payer");
    let frame_receipts = receipt
        .0
        .other
        .get_deserialized::<Vec<FrameReceipt<alloy_rpc_types::Log>>>("frameReceipts")
        .transpose()
        .unwrap()
        .expect("frame receipt has nested receipts");
    assert_eq!(payer, sender);
    assert_eq!(frame_receipts.iter().map(|receipt| receipt.status).collect::<Vec<_>>(), [1, 1]);

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

    let consensus_receipt = FoundryReceiptEnvelope::from_frame_parts(
        receipt.cumulative_gas_used(),
        payer,
        frame_receipts.into_iter().map(|receipt| receipt.map_logs(|log| log.inner)).collect(),
    );
    let block =
        provider.get_block_by_number(receipt.block_number.unwrap().into()).await.unwrap().unwrap();
    assert!(block.transactions.hashes().any(|h| h == hash));
    assert_eq!(block.header.receipts_root, calculate_receipt_root(&[consensus_receipt]));
}

#[tokio::test(flavor = "multi_thread")]
async fn calldata_floor_with_state_gas_is_reflected_in_receipt_and_block() {
    let (api, handle) = spawn(frame_node_config()).await;
    let provider = http_provider(&handle.http_endpoint());
    let wallet = handle.dev_wallets().next().unwrap();
    let sender = wallet.address();
    let fresh = Address::repeat_byte(0xf1);
    assert!(provider.get_code_at(fresh).await.unwrap().is_empty());
    assert_eq!(provider.get_balance(fresh).await.unwrap(), U256::ZERO);

    let nonce = provider.get_transaction_count(sender).await.unwrap();
    let fees = provider.estimate_eip1559_fees().await.unwrap();
    let mut tx = self_relay_tx(
        sender,
        nonce,
        fresh,
        U256::ONE,
        fees.max_fee_per_gas,
        fees.max_priority_fee_per_gas,
    );
    tx.frames[1].gas_limit = 30_000;
    tx.frames[1].state_gas_limit = gas::NEW_ACCOUNT_STATE_GAS;
    // Make the EIP-7976 uniform calldata floor dominate actual execution gas.
    tx.frames[1].data = vec![0xff; 2_048].into();
    sign_entry(&mut tx, 0, &wallet);

    let (standard_gas, floor_gas, _) = tx.gas_limits().unwrap();
    let overhead = standard_gas - tx.sum_frame_gas().unwrap();
    let hash = submit_and_mine(&api, &provider, &tx).await;
    let receipt = provider
        .get_transaction_receipt(hash)
        .await
        .unwrap()
        .expect("floor-binding frame transaction was not mined");
    let frame_receipts = receipt
        .0
        .other
        .get_deserialized::<Vec<FrameReceipt<alloy_rpc_types::Log>>>("frameReceipts")
        .transpose()
        .unwrap()
        .expect("frame receipt has nested receipts");
    let execution_gas = frame_receipts.iter().map(|frame| frame.execution_gas_used).sum::<u64>();
    let state_gas = frame_receipts.iter().map(|frame| frame.state_gas_used).sum::<u64>();
    let gas_before_refund = overhead + execution_gas + state_gas;

    assert_eq!(state_gas, gas::NEW_ACCOUNT_STATE_GAS);
    assert!(
        gas_before_refund - state_gas < floor_gas,
        "test transaction did not bind its calldata floor"
    );
    // This transaction performs no refund-producing operation, so settlement
    // is exactly calldata_floor_gas + final state gas.
    let expected_gas_used = floor_gas + state_gas;
    assert_eq!(receipt.gas_used(), expected_gas_used);
    assert_eq!(receipt.cumulative_gas_used(), expected_gas_used);

    let block = provider
        .get_block_by_number(receipt.block_number.unwrap().into())
        .await
        .unwrap()
        .expect("receipt block exists");
    assert_eq!(block.header.gas_used, expected_gas_used);
}

#[tokio::test(flavor = "multi_thread")]
async fn raw_p256_frame_tx_runs_the_p256_account_authorization_path() {
    let (api, handle) = spawn(frame_node_config()).await;
    let provider = http_provider(&handle.http_endpoint());
    let wallet = handle.dev_wallets().next().unwrap();
    let writer = deploy(&provider, wallet.address(), STORAGE_WRITER_INITCODE).await;

    // Install the production P256Account runtime with the same slot-zero value
    // its constructor derives from the uncompressed public key.
    let account = Address::repeat_byte(0xa5);
    let key = p256_test_key();
    let signer = p256_signer(&key);
    api.anvil_set_code(account, P256_ACCOUNT_RUNTIME.clone()).await.unwrap();
    api.anvil_set_storage_at(
        account,
        U256::ZERO,
        B256::from(U256::from_be_slice(signer.as_slice())),
    )
    .await
    .unwrap();
    api.anvil_set_balance(account, U256::MAX / U256::from(2)).await.unwrap();

    let nonce = provider.get_transaction_count(account).await.unwrap();
    let fees = provider.estimate_eip1559_fees().await.unwrap();
    let mut tx = frame_tx(
        account,
        nonce,
        &[(writer, 0)],
        fees.max_fee_per_gas,
        fees.max_priority_fee_per_gas,
    );
    tx.frames[0].gas_limit = 100_000;
    tx.frames[0].state_gas_limit = 100_000;
    tx.frames[0].data = validate_signature_zero_calldata();
    tx.signatures[0] = FrameSignature {
        scheme: scheme::P256,
        signer: Bytes::copy_from_slice(signer.as_slice()),
        msg: Bytes::new(),
        signature: Bytes::new(),
    };
    sign_p256_entry(&mut tx, 0, &key);

    assert_eq!(tx.signatures[0].signature.len(), 128, "P256 wire signature length");
    tx.validate().unwrap();
    tx.validate_signatures().unwrap();
    let raw = tx.encoded_2718();
    assert_eq!(raw[0], 0x06, "raw transaction type");

    // Corrupt r while retaining a canonical scalar and the matching public key.
    // This reaches cryptographic verification and must be refused at raw-envelope
    // admission, before any frame executes or nonce is consumed.
    let mut invalid = tx.clone();
    let mut invalid_wire_signature = invalid.signatures[0].signature.to_vec();
    invalid_wire_signature[0] ^= 1;
    invalid.signatures[0].signature = invalid_wire_signature.into();
    assert!(invalid.validate_signatures().is_err());
    provider.send_raw_transaction(&invalid.encoded_2718()).await.unwrap_err();
    assert_eq!(provider.get_transaction_count(account).await.unwrap(), nonce);
    assert!(!wrote_magic(&provider, writer).await);

    let payer_balance_before = provider.get_balance(account).await.unwrap();
    let hash = submit_and_mine(&api, &provider, &tx).await;
    let receipt = provider
        .get_transaction_receipt(hash)
        .await
        .unwrap()
        .expect("native-P256 frame transaction was not mined");
    assert!(receipt.status(), "native-P256 frame transaction reverted");
    let payer = receipt
        .0
        .other
        .get_deserialized::<Address>("payer")
        .transpose()
        .unwrap()
        .expect("frame receipt has payer");
    assert_eq!(payer, account, "P256Account did not approve its own payment");
    assert!(
        provider.get_balance(account).await.unwrap() < payer_balance_before,
        "P256Account was named as payer but was not charged"
    );
    assert!(wrote_magic(&provider, writer).await, "authorized SENDER frame did not execute");
    assert_eq!(provider.get_transaction_count(account).await.unwrap(), nonce + 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn raw_ml_dsa_44_frame_tx_runs_the_production_account_authorization_path() {
    let (api, handle) = spawn(frame_node_config()).await;
    let provider = http_provider(&handle.http_endpoint());
    let deployer = handle.dev_wallets().next().unwrap();
    let writer = deploy(&provider, deployer.address(), STORAGE_WRITER_INITCODE).await;

    // Install production MLDSAAccount runtime with the constructor-equivalent
    // key identity in slot zero.
    let account = Address::repeat_byte(0xa6);
    let key = ml_dsa_44_test_key();
    let signer = ml_dsa_44_signer(&key);
    api.anvil_set_code(account, MLDSA_ACCOUNT_RUNTIME.clone()).await.unwrap();
    api.anvil_set_storage_at(
        account,
        U256::ZERO,
        B256::from(U256::from_be_slice(signer.as_slice())),
    )
    .await
    .unwrap();
    api.anvil_set_balance(account, U256::MAX / U256::from(2)).await.unwrap();

    let nonce = provider.get_transaction_count(account).await.unwrap();
    let fees = provider.estimate_eip1559_fees().await.unwrap();
    let mut tx = frame_tx(
        account,
        nonce,
        &[(writer, 0)],
        fees.max_fee_per_gas,
        fees.max_priority_fee_per_gas,
    );
    tx.frames[0].gas_limit = 45_000;
    tx.frames[0].state_gas_limit = 100_000;
    tx.frames[0].data = validate_signature_zero_calldata();
    tx.signatures[0] = FrameSignature {
        scheme: scheme::ML_DSA_44,
        signer: Bytes::copy_from_slice(signer.as_slice()),
        msg: Bytes::new(),
        signature: Bytes::new(),
    };
    sign_ml_dsa_44_entry(&mut tx, 0, &key);

    assert_eq!(tx.signatures[0].signature.len(), 3_732, "ML-DSA-44 wire length");
    assert!(
        gas::SIGNATURE_ML_DSA_44 + tx.frames[0].gas_limit <= gas::MAX_VERIFY_GAS,
        "native verification plus the declared VERIFY frame must fit the public-pool limit"
    );
    assert!(tx.frames[0].state_gas_limit <= gas::MAX_VERIFY_STATE_GAS);
    tx.validate().unwrap();
    tx.validate_signatures().unwrap();
    assert_eq!(tx.encoded_2718()[0], 0x06, "raw transaction type");

    // A signature corruption is rejected during raw-envelope admission, so
    // neither the sender nonce nor any SENDER-frame state can move.
    let mut invalid = tx.clone();
    let mut invalid_wire_signature = invalid.signatures[0].signature.to_vec();
    invalid_wire_signature[0] ^= 1;
    invalid.signatures[0].signature = invalid_wire_signature.into();
    assert!(invalid.validate_signatures().is_err());
    provider.send_raw_transaction(&invalid.encoded_2718()).await.unwrap_err();
    assert_eq!(provider.get_transaction_count(account).await.unwrap(), nonce);
    assert!(!wrote_magic(&provider, writer).await);

    let payer_balance_before = provider.get_balance(account).await.unwrap();
    let hash = submit_and_mine(&api, &provider, &tx).await;
    let receipt = provider
        .get_transaction_receipt(hash)
        .await
        .unwrap()
        .expect("native ML-DSA-44 frame transaction was not mined");
    assert!(receipt.status(), "native ML-DSA-44 frame transaction reverted");
    let payer = receipt
        .0
        .other
        .get_deserialized::<Address>("payer")
        .transpose()
        .unwrap()
        .expect("frame receipt has payer");
    assert_eq!(payer, account, "MLDSAAccount did not approve its own payment");
    assert!(
        provider.get_balance(account).await.unwrap() < payer_balance_before,
        "MLDSAAccount was named as payer but was not charged"
    );
    assert!(wrote_magic(&provider, writer).await, "authorized SENDER frame did not execute");
    assert_eq!(provider.get_transaction_count(account).await.unwrap(), nonce + 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn multisig_owner_reuses_its_execution_signature_to_pay_via_default_eoa_code() {
    let (api, handle) = spawn(frame_node_config()).await;
    let provider = http_provider(&handle.http_endpoint());
    let mut owners = handle.dev_wallets().take(2).collect::<Vec<_>>();
    owners.sort_by_key(|owner| owner.address());
    let owner_a = owners.remove(0);
    let owner_b = owners.remove(0);
    let deployer = handle.dev_wallets().nth(2).unwrap();
    let writer = deploy(&provider, deployer.address(), STORAGE_WRITER_INITCODE).await;

    // Install the production 2-of-2 account and reproduce its constructor
    // storage: isOwner lives in mapping slot zero; threshold lives in slot one.
    let account = Address::repeat_byte(0xa7);
    api.anvil_set_code(account, MULTISIG_ACCOUNT_RUNTIME.clone()).await.unwrap();
    for owner in [owner_a.address(), owner_b.address()] {
        api.anvil_set_storage_at(account, owner_mapping_slot(owner), B256::from(U256::ONE))
            .await
            .unwrap();
    }
    api.anvil_set_storage_at(account, U256::ONE, B256::from(U256::from(2))).await.unwrap();
    api.anvil_set_balance(account, U256::ZERO).await.unwrap();
    assert!(provider.get_code_at(owner_b.address()).await.unwrap().is_empty());

    let nonce = provider.get_transaction_count(account).await.unwrap();
    let owner_b_nonce_before = provider.get_transaction_count(owner_b.address()).await.unwrap();
    let owner_a_balance_before = provider.get_balance(owner_a.address()).await.unwrap();
    let owner_b_balance_before = provider.get_balance(owner_b.address()).await.unwrap();
    let fees = provider.estimate_eip1559_fees().await.unwrap();
    let mut tx = frame_tx(
        account,
        nonce,
        &[(writer, 0)],
        fees.max_fee_per_gas,
        fees.max_priority_fee_per_gas,
    );
    tx.frames[0].flags = flags::APPROVE_EXECUTION;
    tx.frames[0].gas_limit = 50_000;
    tx.frames[0].state_gas_limit = 100_000;
    tx.frames[0].data = validate_signature_zero_one_calldata();
    tx.frames.insert(
        1,
        Frame {
            mode: mode::VERIFY,
            flags: flags::APPROVE_PAYMENT,
            target: Some(owner_b.address()),
            gas_limit: 10_000,
            state_gas_limit: 0,
            value: U256::ZERO,
            data: Bytes::new(),
        },
    );
    tx.signatures = vec![
        signature_entry(Bytes::copy_from_slice(owner_a.address().as_slice())),
        signature_entry(Bytes::copy_from_slice(owner_b.address().as_slice())),
    ];
    sign_entry(&mut tx, 0, &owner_a);
    sign_entry(&mut tx, 1, &owner_b);
    assert!(
        2 * gas::SIGNATURE_SECP256K1 + tx.frames[0].gas_limit + tx.frames[1].gas_limit
            <= gas::MAX_VERIFY_GAS,
        "both native signatures and the VERIFY prefix must fit the public-pool limit"
    );
    assert!(tx.frames[0].state_gas_limit <= gas::MAX_VERIFY_STATE_GAS);
    tx.validate().unwrap();
    tx.validate_signatures().unwrap();

    let hash = submit_and_mine(&api, &provider, &tx).await;
    let receipt = provider
        .get_transaction_receipt(hash)
        .await
        .unwrap()
        .expect("multisig owner-funded frame transaction was not mined");
    assert!(receipt.status(), "multisig owner-funded frame transaction reverted");
    let payer = receipt
        .0
        .other
        .get_deserialized::<Address>("payer")
        .transpose()
        .unwrap()
        .expect("frame receipt has payer");

    assert_eq!(payer, owner_b.address(), "the selected multisig owner was not the payer");
    assert!(
        provider.get_balance(owner_b.address()).await.unwrap() < owner_b_balance_before,
        "the selected owner did not pay the frame transaction fee"
    );
    assert_eq!(
        provider.get_balance(owner_a.address()).await.unwrap(),
        owner_a_balance_before,
        "the execution-only owner was unexpectedly charged"
    );
    assert_eq!(provider.get_balance(account).await.unwrap(), U256::ZERO);
    assert_eq!(provider.get_transaction_count(account).await.unwrap(), nonce + 1);
    assert_eq!(
        provider.get_transaction_count(owner_b.address()).await.unwrap(),
        owner_b_nonce_before,
        "paying through default EOA code must not consume the owner's account nonce"
    );
    assert!(wrote_magic(&provider, writer).await, "multisig-authorized SENDER frame did not run");
}

#[tokio::test(flavor = "multi_thread")]
async fn eip7851_delegation_remains_active_for_frame_transactions() {
    let config = frame_node_config()
        .with_hardfork(Some(EthereumHardfork::Prague.into()))
        .enable_eip7851(true);
    let (api, handle) = spawn(config).await;
    let provider = http_provider(&handle.http_endpoint());
    let wallet = handle.dev_wallets().next().unwrap();
    let sender = wallet.address();
    let approver = deploy(&provider, sender, APPROVER_INITCODE).await;
    let writer = deploy(&provider, sender, STORAGE_WRITER_INITCODE).await;
    let authority = Address::repeat_byte(0x42);

    // The sender's delegated VERIFY frame approves payment and execution. The delegated SENDER
    // target then writes in the authority's storage context.
    api.anvil_set_code(sender, eip7851_designation(approver)).await.unwrap();
    api.anvil_set_code(authority, eip7851_designation(writer)).await.unwrap();

    let nonce = provider.get_transaction_count(sender).await.unwrap();
    let fees = provider.estimate_eip1559_fees().await.unwrap();
    let mut tx = frame_tx(
        sender,
        nonce,
        &[(authority, 0)],
        fees.max_fee_per_gas,
        fees.max_priority_fee_per_gas,
    );
    sign_entry(&mut tx, 0, &wallet);

    let hash = submit_and_mine(&api, &provider, &tx).await;
    let receipt = provider
        .get_transaction_receipt(hash)
        .await
        .unwrap()
        .expect("Frame transaction from EIP-7851 authority was not mined");
    assert!(receipt.status(), "Frame transaction from EIP-7851 authority reverted");
    assert!(wrote_magic(&provider, authority).await, "delegated Frame target did not execute");
    assert_eq!(provider.get_storage_at(writer, U256::ZERO).await.unwrap(), U256::ZERO);
}

#[tokio::test(flavor = "multi_thread")]
async fn raw_and_replay_traces_execute_the_frame_calls() {
    let (api, handle) = spawn(frame_node_config()).await;
    let provider = http_provider(&handle.http_endpoint());
    let wallet = handle.dev_wallets().next().unwrap();
    let sender = wallet.address();
    let writer = deploy(&provider, sender, STORAGE_WRITER_INITCODE).await;
    let nonce = provider.get_transaction_count(sender).await.unwrap();
    let fees = provider.estimate_eip1559_fees().await.unwrap();
    let mut tx = self_relay_tx(
        sender,
        nonce,
        writer,
        U256::ZERO,
        fees.max_fee_per_gas,
        fees.max_priority_fee_per_gas,
    );
    sign_entry(&mut tx, 0, &wallet);
    let raw = tx.encoded_2718();

    let raw_trace = provider.trace_raw_transaction(&raw).trace().state_diff().await.unwrap();
    assert!(
        raw_trace
            .trace
            .iter()
            .any(|trace| matches!(&trace.action, Action::Call(call) if call.to == writer))
    );
    assert!(raw_trace.state_diff.is_some());
    assert!(!wrote_magic(&provider, writer).await, "raw tracing committed frame state");

    let hash = *provider.send_raw_transaction(&raw).await.unwrap().tx_hash();
    api.mine_one().await.unwrap();
    let replay: TraceResults = provider
        .client()
        .request("trace_replayTransaction", (hash, vec![TraceType::Trace, TraceType::StateDiff]))
        .await
        .unwrap();
    assert!(
        replay
            .trace
            .iter()
            .any(|trace| matches!(&trace.action, Action::Call(call) if call.to == writer))
    );
    assert!(replay.state_diff.is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn transaction_hash_fork_replays_frame_envelopes_from_raw_bytes() {
    let (origin_api, origin_handle) = spawn(frame_node_config()).await;
    let origin_provider = http_provider(&origin_handle.http_endpoint());
    let wallet = origin_handle.dev_wallets().next().unwrap();
    let sender = wallet.address();
    let writer = deploy(&origin_provider, sender, STORAGE_WRITER_INITCODE).await;
    origin_api.anvil_set_auto_mine(false).await.unwrap();
    let nonce = origin_provider.get_transaction_count(sender).await.unwrap();
    let fees = origin_provider.estimate_eip1559_fees().await.unwrap();
    let mut tx = self_relay_tx(
        sender,
        nonce,
        writer,
        U256::ZERO,
        fees.max_fee_per_gas,
        fees.max_priority_fee_per_gas,
    );
    sign_entry(&mut tx, 0, &wallet);
    let hash = *origin_provider.send_raw_transaction(&tx.encoded_2718()).await.unwrap().tx_hash();
    origin_api.mine_one().await.unwrap();
    assert!(wrote_magic(&origin_provider, writer).await);

    let (_fork_api, fork_handle) = spawn(
        frame_node_config()
            .with_eth_rpc_url(Some(origin_handle.http_endpoint()))
            .with_fork_transaction_hash(Some(hash))
            .with_no_mining(true),
    )
    .await;
    let fork_provider = http_provider(&fork_handle.http_endpoint());

    assert!(wrote_magic(&fork_provider, writer).await);
    let receipt = fork_provider.get_transaction_receipt(hash).await.unwrap().unwrap();
    assert_eq!(receipt.0.inner.inner.r#type, 0x06);
    assert_eq!(receipt.0.other.get_deserialized::<Address>("payer").unwrap().unwrap(), sender);
}

#[tokio::test(flavor = "multi_thread")]
async fn fork_activation_happens_after_source_transaction_replay() {
    let (origin_api, origin_handle) = spawn(NodeConfig::test()).await;
    origin_api.anvil_set_auto_mine(false).await.unwrap();
    let origin_provider = http_provider(&origin_handle.http_endpoint());
    let sender = origin_handle.dev_wallets().next().unwrap().address();
    let pending = origin_provider
        .send_transaction(WithOtherFields::new(
            TransactionRequest::default()
                .from(sender)
                .to(EXPIRY_VERIFIER_ADDRESS)
                .with_input(bytes!("01")),
        ))
        .await
        .unwrap();
    let hash = *pending.tx_hash();
    origin_api.mine_one().await.unwrap();
    assert!(origin_provider.get_transaction_receipt(hash).await.unwrap().unwrap().status());

    let (_fork_api, fork_handle) = spawn(
        frame_node_config()
            .with_eth_rpc_url(Some(origin_handle.http_endpoint()))
            .with_fork_transaction_hash(Some(hash))
            .with_no_mining(true),
    )
    .await;
    let fork_provider = http_provider(&fork_handle.http_endpoint());

    assert!(fork_provider.get_transaction_receipt(hash).await.unwrap().unwrap().status());
    let code = fork_provider.get_code_at(EXPIRY_VERIFIER_ADDRESS).await.unwrap();
    assert_eq!(code.as_ref(), EXPIRY_VERIFIER_RUNTIME_CODE);
}

#[tokio::test(flavor = "multi_thread")]
async fn object_form_frame_requests_are_rejected_instead_of_downgraded() {
    let (_api, handle) = spawn(frame_node_config()).await;
    let provider = http_provider(&handle.http_endpoint());
    let sender = handle.dev_wallets().next().unwrap().address();
    let request = serde_json::json!({
        "type": "0x6",
        "from": sender,
        "frames": [],
        "signatures": [],
    });

    let result: Result<serde_json::Value, _> =
        provider.raw_request("eth_call".into(), (request, "latest")).await;
    let err = result.unwrap_err().to_string();
    assert!(err.contains("raw signed envelopes"), "unexpected error: {err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn unsupported_execution_profiles_reject_frame_envelopes_at_submission() {
    for config in [
        frame_node_config().with_hardfork(Some(EthereumHardfork::Amsterdam.into())),
        NodeConfig::test_tempo().with_frame_transactions(true),
    ] {
        let (_api, handle) = spawn(config).await;
        let provider = http_provider(&handle.http_endpoint());
        let wallet = handle.dev_wallets().next().unwrap();
        let sender = wallet.address();
        let mut tx = self_relay_tx(sender, 0, sender, U256::ZERO, 1_000_000_000, 1);
        sign_entry(&mut tx, 0, &wallet);

        let err = provider.send_raw_transaction(&tx.encoded_2718()).await.unwrap_err().to_string();
        assert!(err.contains("unsupported by the active"), "unexpected error: {err}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn frame_tx_without_an_approving_verify_frame_is_not_mined() {
    let (api, handle) = spawn(frame_node_config()).await;
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
    let (api, handle) = spawn(frame_node_config()).await;
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

#[tokio::test(flavor = "multi_thread")]
async fn verify_frame_state_change_is_static_and_invalidates_the_transaction() {
    let (mined, stored, nonce, nonce_after, _) =
        run_contract_approval_frame(mode::VERIFY, MUTATING_APPROVER_INITCODE, 100_000).await;

    assert!(!mined, "a VERIFY frame that executed SSTORE was mined");
    assert_eq!(stored, U256::ZERO, "VERIFY frame storage survived its static halt");
    assert_eq!(nonce_after, nonce, "failed VERIFY approval changed the sender nonce");
}

#[tokio::test(flavor = "multi_thread")]
async fn default_frame_state_change_remains_non_static() {
    let (mined, stored, nonce, nonce_after, _) =
        run_contract_approval_frame(mode::DEFAULT, MUTATING_APPROVER_INITCODE, 100_000).await;

    assert!(mined, "a DEFAULT frame that executed SSTORE was not mined");
    assert_eq!(stored, U256::from(MAGIC), "DEFAULT frame did not write storage");
    assert_eq!(nonce_after, nonce + 1, "successful approval did not increment the nonce");
}

#[tokio::test(flavor = "multi_thread")]
async fn verify_frame_can_still_execute_approve() {
    let (mined, stored, nonce, nonce_after, _) =
        run_contract_approval_frame(mode::VERIFY, APPROVER_INITCODE, 100_000).await;

    assert!(mined, "APPROVE was blocked by VERIFY static mode");
    assert_eq!(stored, U256::ZERO);
    assert_eq!(nonce_after, nonce + 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn frame_transaction_below_ordinary_intrinsic_gas_is_mined() {
    let (mined, stored, nonce, nonce_after, max_gas) =
        run_contract_approval_frame(mode::DEFAULT, APPROVER_INITCODE, 3_000).await;

    assert!(max_gas < 21_000, "test transaction has a {max_gas} gas limit");
    assert!(mined, "a valid sub-21k frame transaction was rejected");
    assert_eq!(stored, U256::ZERO);
    assert_eq!(nonce_after, nonce + 1);
}

// -- Atomic batches ---------------------------------------------------------

/// Runs `[VERIFY, first(batched), writer(batched), writer]` on a fresh node: an
/// atomic batch of three SENDER frames, whose first either writes storage or
/// reverts. Reports the transaction's gas used and whether the second and third
/// frames' writes survived.
///
/// The two calls to this are the positive/negative pair for the whole batch
/// mechanism: they differ only in whether the batch's first frame fails.
async fn run_three_frame_batch(first_reverts: bool) -> (u64, bool, bool, Vec<u8>) {
    let (api, handle) = spawn(frame_node_config()).await;
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
    let statuses = receipt
        .0
        .other
        .get_deserialized::<Vec<FrameReceipt<alloy_rpc_types::Log>>>("frameReceipts")
        .transpose()
        .unwrap()
        .expect("frame receipt has nested receipts")
        .iter()
        .map(|receipt| receipt.status)
        .collect();

    (
        receipt.gas_used(),
        wrote_magic(&provider, second).await,
        wrote_magic(&provider, third).await,
        statuses,
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn atomic_batch_that_succeeds_keeps_its_state() {
    let (_, second, third, statuses) = run_three_frame_batch(false).await;
    assert!(second, "the batch's second frame did not write");
    assert!(third, "the batch's terminating frame did not write");
    assert_eq!(statuses, [1, 1, 1, 1]);
}

#[tokio::test(flavor = "multi_thread")]
async fn atomic_batch_failure_rolls_back_and_skips_the_remaining_frames() {
    let (skipped_gas, second, third, statuses) = run_three_frame_batch(true).await;
    assert!(!second, "the frame after the batch failure ran and its write survived");
    assert!(!third, "the batch terminator ran after the batch had already failed");
    assert_eq!(statuses, [1, 0, 2, 2]);

    // A skipped frame's allotment is left unspent. Same frame count and
    // calldata means the overhead and calldata floor are identical.
    let (full_gas, _, _, _) = run_three_frame_batch(false).await;
    assert!(
        skipped_gas < full_gas,
        "skipped frames were charged: {skipped_gas} gas against {full_gas} when all three ran"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn atomic_batch_terminator_failure_rolls_the_batch_back() {
    let (api, handle) = spawn(frame_node_config()).await;
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
    let (api, handle) = spawn(frame_node_config()).await;
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
    let (api, handle) = spawn(frame_node_config()).await;
    let provider = http_provider(&handle.http_endpoint());
    let mut wallets = handle.dev_wallets();
    let wallet = wallets.next().unwrap();
    let sponsor_wallet = wallets.next().unwrap();
    let sender = wallet.address();
    let sponsor = sponsor_wallet.address();
    let writer = deploy(&provider, sender, STORAGE_WRITER_INITCODE).await;
    api.anvil_set_balance(sender, U256::ZERO).await.unwrap();
    assert_eq!(provider.get_balance(sender).await.unwrap(), U256::ZERO);

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
            state_gas_limit: 0,
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
async fn zero_balance_sender_is_accepted_when_signature_index_one_sponsor_pays() {
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

async fn blob_frame_transaction_is_mined(
    hardfork: EthereumHardfork,
    blob_count: usize,
    max_fee_per_blob_gas: u128,
    disable_pool_balance_checks: bool,
) -> bool {
    let config = frame_node_config()
        .with_hardfork(Some(hardfork.into()))
        .with_disable_pool_balance_checks(disable_pool_balance_checks);
    let (api, handle) = spawn(config).await;
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
    tx.max_fee_per_blob_gas = U256::from(max_fee_per_blob_gas);
    tx.blob_versioned_hashes = vec![B256::repeat_byte(0x01); blob_count];
    sign_entry(&mut tx, 0, &wallet);
    tx.validate().unwrap();
    tx.validate_signatures().unwrap();

    let mut raw = Vec::new();
    tx.encode_2718(&mut raw);
    let Ok(pending) = provider.send_raw_transaction(&raw).await else {
        return false;
    };
    let hash = *pending.tx_hash();
    api.mine_one().await.unwrap();
    provider.get_transaction_receipt(hash).await.unwrap().is_some()
}

#[tokio::test(flavor = "multi_thread")]
async fn frame_blob_count_uses_the_active_fork_limit() {
    let cancun_limit = BlobParams::cancun().max_blobs_per_tx as usize;
    let prague_limit = BlobParams::prague().max_blobs_per_tx as usize;
    assert!(prague_limit > cancun_limit);

    assert!(
        !blob_frame_transaction_is_mined(
            EthereumHardfork::Cancun,
            cancun_limit + 1,
            u128::MAX,
            false,
        )
        .await
    );
    assert!(
        blob_frame_transaction_is_mined(
            EthereumHardfork::Prague,
            cancun_limit + 1,
            u128::MAX,
            false,
        )
        .await
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn frame_blob_fee_cap_is_checked_by_the_pool() {
    assert!(
        !blob_frame_transaction_is_mined(EthereumHardfork::Cancun, 1, 0, false).await,
        "a frame transaction below the block blob fee was accepted"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn frame_fee_caps_remain_mandatory_when_pool_balance_checks_are_disabled() {
    let (api, handle) = spawn(frame_node_config().with_disable_pool_balance_checks(true)).await;
    let provider = http_provider(&handle.http_endpoint());
    let wallet = handle.dev_wallets().next().unwrap();
    let sender = wallet.address();
    let writer = deploy(&provider, sender, STORAGE_WRITER_INITCODE).await;
    let nonce = provider.get_transaction_count(sender).await.unwrap();
    let mut tx = frame_tx(sender, nonce, &[(writer, 0)], 0, 0);
    sign_entry(&mut tx, 0, &wallet);
    tx.validate().unwrap();
    tx.validate_signatures().unwrap();
    let mut raw = Vec::new();
    tx.encode_2718(&mut raw);

    assert!(provider.send_raw_transaction(&raw).await.is_err());
    api.mine_one().await.unwrap();
    assert!(!wrote_magic(&provider, writer).await);

    assert!(
        !blob_frame_transaction_is_mined(EthereumHardfork::Cancun, 1, 0, true).await,
        "disabling balance checks also disabled the frame blob fee cap"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn frame_opcodes_observe_transaction_gas_price_blob_hash_and_type() {
    let (api, handle) =
        spawn(frame_node_config().with_hardfork(Some(EthereumHardfork::Prague.into()))).await;
    let provider = http_provider(&handle.http_endpoint());
    let wallet = handle.dev_wallets().next().unwrap();
    let sender = wallet.address();
    let probe = deploy(&provider, sender, TX_ENV_PROBE_INITCODE).await;
    let nonce = provider.get_transaction_count(sender).await.unwrap();
    let fees = provider.estimate_eip1559_fees().await.unwrap();
    let blob_hash = B256::repeat_byte(0x01);
    let mut tx =
        frame_tx(sender, nonce, &[(probe, 0)], fees.max_fee_per_gas, fees.max_priority_fee_per_gas);
    tx.max_fee_per_blob_gas = U256::from(u128::MAX);
    tx.blob_versioned_hashes = vec![blob_hash];
    sign_entry(&mut tx, 0, &wallet);
    let hash = submit_and_mine(&api, &provider, &tx).await;
    let receipt = provider
        .get_transaction_receipt(hash)
        .await
        .unwrap()
        .expect("frame transaction was not mined");

    assert_eq!(
        provider.get_storage_at(probe, U256::ZERO).await.unwrap(),
        U256::from(receipt.effective_gas_price)
    );
    assert_eq!(
        provider.get_storage_at(probe, U256::ONE).await.unwrap(),
        U256::from_be_bytes(blob_hash.0)
    );
    assert_eq!(provider.get_storage_at(probe, U256::from(2)).await.unwrap(), U256::from(0x06));
}
