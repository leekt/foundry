use alloy_evm::precompiles::{DynPrecompile, PrecompileInput, PrecompilesMap};
use alloy_primitives::{Address, Bytes, address};
use revm::{
    context::{CfgEnv, journaled_state::JournalLoadError},
    precompile::{
        PrecompileError, PrecompileHalt, PrecompileId, PrecompileOutput, PrecompileResult,
        call_eth_precompile,
        secp256k1::{ec_recover_run, is_ecrecover_code_eligible},
    },
    primitives::hardfork::SpecId,
};
use std::borrow::Cow;

const ECRECOVER_BASE_GAS: u64 = 3_000;
const WARM_ACCOUNT_ACCESS_GAS: u64 = 100;
const COLD_ACCOUNT_ACCESS_GAS: u64 = 2_600;

static EIP8151_ECRECOVER_ID: PrecompileId =
    PrecompileId::Custom(Cow::Borrowed("eip8151_ecrecover"));

/// The ECRecover precompile address.
pub const EC_RECOVER: Address = address!("0x0000000000000000000000000000000000000001");

/// Returns whether `id` identifies Foundry's canonical EIP-8151 ECRecover wrapper.
pub fn is_eip8151_ecrecover_id(id: &PrecompileId) -> bool {
    id == &EIP8151_ECRECOVER_ID
}

/// Installs EIP-8151's stateful ECRecover implementation when explicitly enabled under Prague or
/// later.
pub fn install_eip8151_precompile(precompiles: &mut PrecompilesMap, cfg: &CfgEnv) {
    if !cfg.enable_eip8151 || cfg.spec < SpecId::PRAGUE {
        return;
    }
    precompiles.apply_precompile(&EC_RECOVER, |_| Some(eip8151_ecrecover()));
}

fn eip8151_ecrecover() -> DynPrecompile {
    DynPrecompile::new_stateful(EIP8151_ECRECOVER_ID.clone(), eip8151_ecrecover_call)
}

fn eip8151_ecrecover_call(mut input: PrecompileInput<'_>) -> PrecompileResult {
    let gas_limit = input.gas;
    let reservoir = input.reservoir;
    let mut output = call_eth_precompile(ec_recover_run, input.data, gas_limit, reservoir);
    if !output.is_success() {
        return Ok(output);
    }
    if output.bytes.is_empty() {
        output.bytes = Bytes::from([0u8; 32]);
        return Ok(output);
    }
    if output.bytes.len() != 32 {
        return Ok(output);
    }

    let recovered = Address::from_slice(&output.bytes[12..]);
    let warm_gas_used = ECRECOVER_BASE_GAS + WARM_ACCOUNT_ACCESS_GAS;
    let cold_gas_used = ECRECOVER_BASE_GAS + COLD_ACCOUNT_ACCESS_GAS;
    if gas_limit < warm_gas_used {
        return Ok(PrecompileOutput::halt(PrecompileHalt::OutOfGas, reservoir));
    }

    let mut account = match input
        .internals_mut()
        .load_account_mut_skip_cold_load(recovered, gas_limit < cold_gas_used)
    {
        Ok(account) => account,
        Err(JournalLoadError::ColdLoadSkipped) => {
            return Ok(PrecompileOutput::halt(PrecompileHalt::OutOfGas, reservoir));
        }
        Err(JournalLoadError::DBError(err)) => {
            return Err(PrecompileError::Fatal(err.to_string()));
        }
    };

    let raw_code =
        account.data.load_code().map_err(|err| PrecompileError::Fatal(format!("{err:?}")))?;
    if !is_ecrecover_code_eligible(raw_code.original_byte_slice()) {
        output.bytes = Bytes::from([0u8; 32]);
    }
    output.gas_used = if account.is_cold { cold_gas_used } else { warm_gas_used };
    Ok(output)
}

/// The SHA-256 precompile address.
pub const SHA_256: Address = address!("0x0000000000000000000000000000000000000002");

/// The RIPEMD-160 precompile address.
pub const RIPEMD_160: Address = address!("0x0000000000000000000000000000000000000003");

/// The Identity precompile address.
pub const IDENTITY: Address = address!("0x0000000000000000000000000000000000000004");

/// The ModExp precompile address.
pub const MOD_EXP: Address = address!("0x0000000000000000000000000000000000000005");

/// The ECAdd precompile address.
pub const EC_ADD: Address = address!("0x0000000000000000000000000000000000000006");

/// The ECMul precompile address.
pub const EC_MUL: Address = address!("0x0000000000000000000000000000000000000007");

/// The ECPairing precompile address.
pub const EC_PAIRING: Address = address!("0x0000000000000000000000000000000000000008");

/// The Blake2F precompile address.
pub const BLAKE_2F: Address = address!("0x0000000000000000000000000000000000000009");

/// The PointEvaluation precompile address.
pub const POINT_EVALUATION: Address = address!("0x000000000000000000000000000000000000000a");

/// The BLS12-381 G1ADD precompile address.
pub const BLS12_G1ADD: Address = address!("0x000000000000000000000000000000000000000b");

/// The BLS12-381 G1MSM precompile address.
pub const BLS12_G1MSM: Address = address!("0x000000000000000000000000000000000000000c");

/// The BLS12-381 G2ADD precompile address.
pub const BLS12_G2ADD: Address = address!("0x000000000000000000000000000000000000000d");

/// The BLS12-381 G2MSM precompile address.
pub const BLS12_G2MSM: Address = address!("0x000000000000000000000000000000000000000e");

/// The BLS12-381 pairing check precompile address.
pub const BLS12_PAIRING_CHECK: Address = address!("0x000000000000000000000000000000000000000f");

/// The BLS12-381 map Fp to G1 precompile address.
pub const BLS12_MAP_FP_TO_G1: Address = address!("0x0000000000000000000000000000000000000010");

/// The BLS12-381 map Fp2 to G2 precompile address.
pub const BLS12_MAP_FP2_TO_G2: Address = address!("0x0000000000000000000000000000000000000011");

/// The P256VERIFY precompile address.
pub const P256_VERIFY: Address = address!("0x0000000000000000000000000000000000000100");

/// The Celo transfer precompile address.
///
/// See <https://specs.celo.org/token_duality.html#the-transfer-precompile>
pub const CELO_TRANSFER: Address = address!("0x00000000000000000000000000000000000000fd");

/// Precompile addresses.
pub const PRECOMPILES: &[Address] = &[
    EC_RECOVER,
    SHA_256,
    RIPEMD_160,
    IDENTITY,
    MOD_EXP,
    EC_ADD,
    EC_MUL,
    EC_PAIRING,
    BLAKE_2F,
    POINT_EVALUATION,
    BLS12_G1ADD,
    BLS12_G1MSM,
    BLS12_G2ADD,
    BLS12_G2MSM,
    BLS12_PAIRING_CHECK,
    BLS12_MAP_FP_TO_G1,
    BLS12_MAP_FP2_TO_G2,
    P256_VERIFY,
];
