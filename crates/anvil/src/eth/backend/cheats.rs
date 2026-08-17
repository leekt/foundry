//! Support for "cheat codes" / bypass functions

use alloy_evm::precompiles::{DynPrecompile, Precompile, PrecompileInput};
use alloy_primitives::{
    Address, B256, Bytes,
    map::{AddressHashSet, foldhash::HashMap},
};
use foundry_evm::core::precompiles::is_eip8151_ecrecover_id;
use parking_lot::RwLock;
use revm::precompile::{
    PrecompileHalt, PrecompileId, PrecompileOutput, PrecompileResult, utilities::right_pad,
};
use std::{borrow::Cow, sync::Arc};

/// ID for the [`CheatEcrecover::precompile_id`] precompile.
static PRECOMPILE_ID_CHEAT_ECRECOVER: PrecompileId =
    PrecompileId::Custom(Cow::Borrowed("cheat_ecrecover"));
static PRECOMPILE_ID_CHEAT_EIP8151_FALLBACK: PrecompileId =
    PrecompileId::Custom(Cow::Borrowed("cheat_ecrecover_eip8151_fallback"));

pub(crate) fn is_cheat_eip8151_fallback_id(id: &PrecompileId) -> bool {
    id == &PRECOMPILE_ID_CHEAT_EIP8151_FALLBACK
}

pub(crate) fn ecrecover_signature(input: &[u8]) -> Bytes {
    let padded = right_pad::<128>(input);
    let mut signature = [0u8; 65];
    signature[..64].copy_from_slice(&padded[64..128]);
    signature[64] = padded[63];
    Bytes::copy_from_slice(&signature)
}

/// Manages user modifications that may affect the node's behavior
///
/// Contains the state of executed, non-eth standard cheat code RPC
#[derive(Clone, Debug, Default)]
pub struct CheatsManager {
    /// shareable state
    state: Arc<RwLock<CheatsState>>,
}

impl CheatsManager {
    /// Sets the account to impersonate
    ///
    /// Returns `true` if the account is already impersonated
    pub fn impersonate(&self, addr: Address) -> bool {
        trace!(target: "cheats", %addr, "start impersonating");
        // When somebody **explicitly** impersonates an account we need to store it so we are able
        // to return it from `eth_accounts`. That's why we do not simply call `is_impersonated()`
        // which does not check that list when auto impersonation is enabled.
        !self.state.write().impersonated_accounts.insert(addr)
    }

    /// Removes the account that from the impersonated set
    pub fn stop_impersonating(&self, addr: &Address) {
        trace!(target: "cheats", %addr, "stop impersonating");
        self.state.write().impersonated_accounts.remove(addr);
    }

    /// Returns true if the `addr` is currently impersonated
    pub fn is_impersonated(&self, addr: Address) -> bool {
        if self.auto_impersonate_accounts() {
            true
        } else {
            self.state.read().impersonated_accounts.contains(&addr)
        }
    }

    /// Returns true is auto impersonation is enabled
    pub fn auto_impersonate_accounts(&self) -> bool {
        self.state.read().auto_impersonate_accounts
    }

    /// Sets the auto impersonation flag which if set to true will make the `is_impersonated`
    /// function always return true
    pub fn set_auto_impersonate_account(&self, enabled: bool) {
        trace!(target: "cheats", "Auto impersonation set to {:?}", enabled);
        self.state.write().auto_impersonate_accounts = enabled
    }

    /// Returns all accounts that are currently being impersonated.
    pub fn impersonated_accounts(&self) -> AddressHashSet {
        self.state.read().impersonated_accounts.clone()
    }

    /// Registers an override so that `ecrecover(signature)` returns `addr`.
    pub fn add_recover_override(&self, sig: Bytes, addr: Address) {
        self.state.write().signature_overrides.insert(sig, addr);
    }

    /// If an override exists for `sig`, returns the address; otherwise `None`.
    pub fn get_recover_override(&self, sig: &Bytes) -> Option<Address> {
        self.state.read().signature_overrides.get(sig).copied()
    }

    /// Returns true if any ecrecover overrides have been registered.
    pub fn has_recover_overrides(&self) -> bool {
        !self.state.read().signature_overrides.is_empty()
    }

    /// Sets the `prevrandao` value to use for the next mined block.
    ///
    /// This is a one-shot override that is consumed by the next block and applies to that block
    /// only.
    pub fn set_next_block_prevrandao(&self, prevrandao: B256) {
        trace!(target: "cheats", %prevrandao, "set next block prevrandao");
        let mut state = self.state.write();
        state.prevrandao_generation = state.prevrandao_generation.wrapping_add(1);
        state.next_block_prevrandao = Some(prevrandao);
    }

    /// Prepares the manually set `prevrandao` without consuming it.
    pub(crate) fn prepare_next_block_prevrandao(&self) -> Option<PendingPrevrandao> {
        let state = self.state.read();
        state
            .next_block_prevrandao
            .map(|value| PendingPrevrandao { value, generation: state.prevrandao_generation })
    }

    /// Takes the manually set `prevrandao` value for forced replay mining.
    pub fn take_next_block_prevrandao(&self) -> Option<B256> {
        let mut state = self.state.write();
        state.prevrandao_generation = state.prevrandao_generation.wrapping_add(1);
        state.next_block_prevrandao.take()
    }

    /// Consumes a `prevrandao` override after the candidate using it was committed.
    pub(crate) fn consume_next_block_prevrandao(&self, pending: PendingPrevrandao) {
        let mut state = self.state.write();
        if state.prevrandao_generation == pending.generation {
            state.next_block_prevrandao.take();
        }
    }

    /// Clears any manually set `prevrandao` value for the next block.
    ///
    /// Used on reset/revert so a set-but-unmined override does not leak into a later block,
    /// mirroring how the next-block timestamp override is cleared by `TimeManager::reset`.
    pub fn clear_next_block_prevrandao(&self) {
        let mut state = self.state.write();
        state.prevrandao_generation = state.prevrandao_generation.wrapping_add(1);
        state.next_block_prevrandao.take();
    }
}

/// Container type for all the state variables
#[derive(Clone, Debug, Default)]
pub struct CheatsState {
    /// All accounts that are currently impersonated
    pub impersonated_accounts: AddressHashSet,
    /// If set to true will make the `is_impersonated` function always return true
    pub auto_impersonate_accounts: bool,
    /// Overrides for ecrecover: Signature => Address
    pub signature_overrides: HashMap<Bytes, Address>,
    /// The `prevrandao` value to use for the next mined block, if manually set via
    /// `anvil_setNextBlockPrevRandao`.
    pub next_block_prevrandao: Option<B256>,
    /// Generation of the most recently installed `prevrandao` override.
    prevrandao_generation: u64,
}

/// A `prevrandao` override reserved by a candidate block.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PendingPrevrandao {
    pub(crate) value: B256,
    generation: u64,
}

impl CheatEcrecover {
    pub fn new(cheats: Arc<CheatsManager>, fallback: DynPrecompile) -> Self {
        let precompile_id = if is_eip8151_ecrecover_id(fallback.precompile_id()) {
            PRECOMPILE_ID_CHEAT_EIP8151_FALLBACK.clone()
        } else {
            PRECOMPILE_ID_CHEAT_ECRECOVER.clone()
        };
        Self { cheats, fallback, precompile_id }
    }
}

impl Precompile for CheatEcrecover {
    fn call(&self, input: PrecompileInput<'_>) -> PrecompileResult {
        if !self.cheats.has_recover_overrides() {
            return self.fallback.call(input);
        }

        const ECRECOVER_BASE: u64 = 3_000;
        if input.gas < ECRECOVER_BASE {
            return Ok(PrecompileOutput::halt(PrecompileHalt::OutOfGas, input.reservoir));
        }
        let signature = ecrecover_signature(input.data);
        if let Some(addr) = self.cheats.get_recover_override(&signature) {
            let mut out = [0u8; 32];
            out[12..].copy_from_slice(addr.as_slice());
            return Ok(PrecompileOutput::new(
                ECRECOVER_BASE,
                Bytes::copy_from_slice(&out),
                input.reservoir,
            ));
        }
        self.fallback.call(input)
    }

    fn precompile_id(&self) -> &PrecompileId {
        &self.precompile_id
    }

    fn supports_caching(&self) -> bool {
        false
    }
}

/// A custom ecrecover precompile that supports cheat-based signature overrides.
#[derive(Debug)]
pub struct CheatEcrecover {
    cheats: Arc<CheatsManager>,
    fallback: DynPrecompile,
    precompile_id: PrecompileId,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidate_consumes_only_its_prevrandao_override() {
        let cheats = CheatsManager::default();
        let value = B256::with_last_byte(1);
        cheats.set_next_block_prevrandao(value);
        let pending = cheats.prepare_next_block_prevrandao().unwrap();

        cheats.set_next_block_prevrandao(value);
        cheats.consume_next_block_prevrandao(pending);

        assert_eq!(cheats.prepare_next_block_prevrandao().unwrap().value, value);
    }

    #[test]
    fn impersonate_returns_false_then_true() {
        let mgr = CheatsManager::default();
        let addr = Address::from([1u8; 20]);
        assert!(!mgr.impersonate(addr));
        assert!(mgr.impersonate(addr));
    }
}
