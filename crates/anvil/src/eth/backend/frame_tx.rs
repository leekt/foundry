//! EIP-8141 frame transaction execution.
//!
//! A frame transaction is not a single call: it is a list of frames, each run
//! as its own top-level call with its own caller, target and gas allotment.
//! This module drives that loop, tracks the transaction-scoped approval state
//! and settles the fee against the payer.
//!
//! Ported from the go-ethereum reference implementation (`executeFrame` and
//! `executeFrameAt` in `core/state_transition.go` on
//! `leekt/go-ethereum@fix/eip8141-frame-tx`).
//!
//! Author: taek <leekt216@gmail.com>

use crate::eth::backend::mem::inspector::AnvilInspector;
use alloy_evm::{Evm, block::StateDB, eth::EthEvm};
use alloy_primitives::{Address, TxKind, U256};
use alloy_consensus::Transaction as _;
use foundry_primitives::{ENTRY_POINT_ADDRESS, Frame, TxFrame, flags, mode};
use revm::{
    Database as _,
    context::{
        Block as _, TxEnv,
        result::{ExecutionResult, Output, ResultAndState, ResultGas, SuccessReason},
    },
    context_interface::host::{FrameInfo, FrameSigInfo, FrameTxContext},
    database::DatabaseCommit,
    interpreter::instructions::frame_tx::set_frame_tx_context,
    state::EvmState,
};

/// Approval scopes, mirroring the frame flags they are granted from.
const SCOPE_PAYMENT: u64 = flags::APPROVE_PAYMENT as u64;
const SCOPE_EXECUTION: u64 = flags::APPROVE_EXECUTION as u64;
const SCOPE_EXECUTION_AND_PAYMENT: u64 = flags::APPROVE_EXECUTION_PAYMENT as u64;

/// Frame receipt status, matching the reference's encoding.
const STATUS_FAILED: u8 = 0;
const STATUS_SUCCESS: u8 = 1;

/// Why a frame transaction could not be executed at all.
///
/// These are the conditions the reference treats as making the whole
/// transaction invalid rather than merely failing a frame.
#[derive(Clone, Debug, thiserror::Error)]
pub enum FrameExecutionError {
    /// A `SENDER` frame appeared before any frame approved execution.
    #[error("SENDER frame {index} before approval")]
    SenderBeforeApproval {
        /// Index of the offending frame.
        index: usize,
    },
    /// A `VERIFY` frame reverted, which invalidates the transaction.
    #[error("VERIFY frame {index} failed")]
    VerifyFailed {
        /// Index of the offending frame.
        index: usize,
    },
    /// No frame approved payment, so there is nobody to charge.
    #[error("no payer approved")]
    NoPayer,
    /// The declared gas figures do not fit in 64 bits.
    #[error("frame transaction gas overflow")]
    GasOverflow,
    /// The maximum cost does not fit in 256 bits.
    #[error("max cost exceeds 256 bits")]
    MaxCostOverflow,
    /// The EVM itself failed, which is not a frame-level failure.
    #[error("frame {index} could not be executed: {message}")]
    Evm {
        /// Index of the offending frame.
        index: usize,
        /// The underlying EVM error.
        message: String,
    },
}

/// The outcome of running every frame of a transaction.
#[derive(Clone, Debug)]
pub struct FrameTxOutcome<H> {
    /// The transaction-level result, as the block executor expects it.
    pub result: ResultAndState<H>,
    /// The account that paid, established by an `APPROVE` of payment.
    pub payer: Address,
    /// Per-frame `(status, gas_used)`, in frame order.
    pub frame_results: Vec<(u8, u64)>,
}

/// Suspends the fee rules that do not apply while frames are running.
///
/// Each frame is a top-level call priced at zero, because the payer is charged
/// once for the whole transaction after every frame has run. revm would
/// otherwise reject a zero-priced call against a non-zero base fee, and would
/// bill each frame's caller separately.
pub trait SuspendFeeRules {
    /// Sets both switches, returning their previous values.
    fn suspend_fee_rules(&mut self, suspended: bool) -> (bool, bool);
    /// Restores both switches to previously saved values.
    fn restore_fee_rules(&mut self, saved: (bool, bool));
}

impl<DB: alloy_evm::Database, I, P> SuspendFeeRules for EthEvm<DB, I, P> {
    fn suspend_fee_rules(&mut self, suspended: bool) -> (bool, bool) {
        let cfg = &mut self.ctx_mut().cfg;
        let saved = (cfg.disable_base_fee, cfg.disable_fee_charge);
        cfg.disable_base_fee = suspended;
        cfg.disable_fee_charge = suspended;
        saved
    }

    fn restore_fee_rules(&mut self, saved: (bool, bool)) {
        let cfg = &mut self.ctx_mut().cfg;
        (cfg.disable_base_fee, cfg.disable_fee_charge) = saved;
    }
}

/// Transaction-scoped approval state, shared across all frames.
#[derive(Debug, Default)]
struct ApprovalState {
    sender_approved: bool,
    payer: Option<Address>,
}

/// Builds the frame-transaction context the introspection opcodes read.
///
/// `frame_index` and `approvable_scopes` are the only per-frame parts; the rest
/// describes the whole transaction.
fn build_context(tx: &TxFrame, frame_index: usize, statuses: &[u8]) -> FrameTxContext {
    let frames = tx
        .frames
        .iter()
        .enumerate()
        .map(|(i, frame)| FrameInfo {
            resolved_target: frame.resolved_target(tx.sender),
            gas_limit: frame.gas_limit,
            mode: frame.mode,
            flags: frame.flags,
            value: frame.value,
            status: statuses.get(i).copied().unwrap_or(STATUS_FAILED),
            data: frame.data.clone(),
        })
        .collect();
    let signatures = tx
        .signatures
        .iter()
        .map(|sig| FrameSigInfo {
            // ARBITRARY entries have no protocol-assigned signer.
            resolved_signer: (sig.scheme != 0).then(|| sig.resolved_signer(tx.sender)).flatten(),
            scheme: sig.scheme,
            msg: if sig.msg.len() == 32 {
                alloy_primitives::B256::from_slice(&sig.msg)
            } else {
                alloy_primitives::B256::ZERO
            },
            signature: sig.signature.clone(),
        })
        .collect();

    let max_cost = max_cost(tx).unwrap_or(U256::MAX);
    FrameTxContext {
        sender: tx.sender,
        nonce: tx.nonce,
        sig_hash: tx.signature_hash(),
        max_cost,
        max_priority_fee_per_gas: tx.max_priority_fee_per_gas,
        max_fee_per_gas: tx.max_fee_per_gas,
        max_fee_per_blob_gas: tx.max_fee_per_blob_gas,
        blob_count: tx.blob_versioned_hashes.len() as u64,
        frame_index: frame_index as u64,
        frames,
        signatures,
        approvable_scopes: (tx.frames[frame_index].flags & flags::APPROVE_EXECUTION_PAYMENT) as u64,
        approved_scope: 0,
    }
}

/// `max_cost`: the most the payer may be charged for the transaction.
fn max_cost(tx: &TxFrame) -> Option<U256> {
    let blob_fee = tx.max_fee_per_blob_gas.checked_mul(U256::from(tx.blob_gas()))?;
    tx.max_fee_per_gas.checked_mul(U256::from(tx.max_gas()))?.checked_add(blob_fee)
}

/// Merges a frame's state diff into the running transaction diff.
///
/// revm reports absolute account state rather than deltas, so a later frame's
/// entry simply supersedes an earlier one.
fn merge_state(merged: &mut EvmState, frame_state: EvmState) {
    for (address, account) in frame_state {
        match merged.entry(address) {
            std::collections::hash_map::Entry::Occupied(mut slot) => {
                let existing = slot.get_mut();
                existing.info = account.info;
                existing.status |= account.status;
                existing.storage.extend(account.storage);
            }
            std::collections::hash_map::Entry::Vacant(slot) => {
                slot.insert(account);
            }
        }
    }
}

/// Builds the environment for a single frame's top-level call.
fn frame_env(tx: &TxFrame, frame: &Frame, caller: Address, caller_nonce: u64) -> TxEnv {
    TxEnv {
        // A frame is a plain call as far as revm is concerned; the frame
        // semantics live in the context the opcodes read.
        tx_type: 2,
        caller,
        // ORIGIN must report the frame's caller at every call depth, which
        // revm derives from the transaction caller.
        kind: TxKind::Call(frame.resolved_target(tx.sender)),
        data: frame.data.clone(),
        value: frame.value,
        gas_limit: frame.gas_limit,
        // Frames do not pay for their own gas: the payer is charged once, for
        // the whole transaction, after every frame has run.
        gas_price: 0,
        gas_priority_fee: Some(0),
        nonce: caller_nonce,
        chain_id: tx.chain_id(),
        ..Default::default()
    }
}

/// Runs every frame of `tx`, then settles the fee against the payer.
///
/// Returns the merged state diff so the caller can commit it as a single
/// transaction, matching how the block executor treats every other type.
pub fn execute_frame_tx<E>(
    evm: &mut E,
    tx: &TxFrame,
) -> Result<FrameTxOutcome<E::HaltReason>, FrameExecutionError>
where
    E: Evm<Tx = TxEnv, DB: StateDB, Inspector = AnvilInspector> + SuspendFeeRules,
{
    let saved_fee_rules = evm.suspend_fee_rules(true);
    let outcome = run_frames(evm, tx);
    evm.restore_fee_rules(saved_fee_rules);
    outcome
}

/// Runs every frame and settles the fee. Split from [`execute_frame_tx`] so the
/// fee rules are restored on every exit, including the error paths.
fn run_frames<E>(
    evm: &mut E,
    tx: &TxFrame,
) -> Result<FrameTxOutcome<E::HaltReason>, FrameExecutionError>
where
    E: Evm<Tx = TxEnv, DB: StateDB, Inspector = AnvilInspector> + SuspendFeeRules,
{
    let (_standard, floor_gas, max_gas) =
        tx.gas_limits().ok_or(FrameExecutionError::GasOverflow)?;
    let max_cost = max_cost(tx).ok_or(FrameExecutionError::MaxCostOverflow)?;

    let mut approval = ApprovalState::default();
    let mut merged = EvmState::default();
    let mut statuses = vec![STATUS_FAILED; tx.frames.len()];
    let mut frame_results = Vec::with_capacity(tx.frames.len());
    let mut frame_gas_total = 0u64;
    let mut logs = Vec::new();

    for (index, frame) in tx.frames.iter().enumerate() {
        // A SENDER frame speaks as the sender, so it may only run once some
        // frame has approved execution on the sender's behalf.
        let caller = if frame.mode == mode::SENDER {
            if !approval.sender_approved {
                return Err(FrameExecutionError::SenderBeforeApproval { index });
            }
            tx.sender
        } else {
            ENTRY_POINT_ADDRESS
        };
        let resolved_target = frame.resolved_target(tx.sender);

        // Install the context the introspection opcodes read, and arm the
        // watcher that records an APPROVE.
        set_frame_tx_context(Some(build_context(tx, index, &statuses)));
        evm.inspector_mut().watch_frame_approval(resolved_target);

        let caller_nonce = evm
            .db_mut()
            .basic(caller)
            .map_err(|err| FrameExecutionError::Evm { index, message: err.to_string() })?
            .map(|info| info.nonce)
            .unwrap_or_default();

        let outcome = evm.transact_raw(frame_env(tx, frame, caller, caller_nonce));

        let observed_scope = evm.inspector_mut().take_frame_approval();
        set_frame_tx_context(None);

        let ResultAndState { result, mut state } = outcome.map_err(|err| {
            FrameExecutionError::Evm { index, message: format!("{err:?}") }
        })?;

        // revm bumps the caller's nonce for every call it runs as a
        // transaction. EIP-8141 bumps the sender's nonce exactly once, when
        // payment is approved, so undo the per-frame bump here.
        if let Some(account) = state.get_mut(&caller) {
            account.info.nonce = caller_nonce;
        }

        let succeeded = result.is_success();
        let gas_used = result.tx_gas_used();
        frame_gas_total = frame_gas_total.saturating_add(gas_used);

        if succeeded {
            statuses[index] = STATUS_SUCCESS;
            logs.extend(result.logs().iter().cloned());
            merge_state(&mut merged, state.clone());
            evm.db_mut().commit(state);
        } else {
            // A failed frame keeps its gas but loses its state changes. A
            // reverting VERIFY frame invalidates the whole transaction.
            if frame.mode == mode::VERIFY {
                return Err(FrameExecutionError::VerifyFailed { index });
            }
        }
        frame_results.push((statuses[index], gas_used));

        // An account with no code of its own still validates frame
        // transactions, through the protocol-defined default code. In DEFAULT
        // and SENDER mode that is a plain empty-code call, which is what just
        // ran; only VERIFY mode carries extra semantics.
        let observed_scope = if succeeded
            && frame.mode == mode::VERIFY
            && observed_scope.is_none()
            && target_has_no_code(evm, resolved_target, index)?
        {
            default_verify_scope(tx, frame, resolved_target)
        } else {
            observed_scope
        };

        // A scope recorded by a frame that succeeded is one APPROVE granted:
        // APPROVE reverts unless the scope is a non-empty subset of the flags.
        if succeeded && let Some(scope) = observed_scope {
            apply_approval(evm, tx, frame, resolved_target, scope, max_cost, &mut approval, &mut merged)?;
        }
    }

    let payer = approval.payer.ok_or(FrameExecutionError::NoPayer)?;

    // The transaction is charged the greater of what the frames actually used
    // (plus the fixed overhead) and the calldata floor.
    let overhead = max_gas.saturating_sub(tx.sum_frame_gas().unwrap_or(0));
    let gas_used = frame_gas_total.saturating_add(overhead).max(floor_gas).min(max_gas);

    settle_fee(evm, tx, payer, gas_used, max_cost, &mut merged)?;

    // The transaction as a whole succeeds once a payer is established; an
    // individual frame's failure is reported in its own frame result, exactly
    // as the reference does.
    let result = ExecutionResult::Success {
        reason: SuccessReason::Return,
        gas: ResultGas::new(gas_used, 0, floor_gas),
        logs,
        output: Output::Call(Default::default()),
    };
    Ok(FrameTxOutcome {
        result: ResultAndState { result, state: merged },
        payer,
        frame_results,
    })
}

/// Reports whether a frame's resolved target has no code of its own, which
/// selects the EIP-8141 default code behaviour.
///
/// A non-existent account and one with the empty code hash both qualify; an
/// EIP-7702 delegation indicator does not, since it resolves to real code.
fn target_has_no_code<E>(
    evm: &mut E,
    target: Address,
    index: usize,
) -> Result<bool, FrameExecutionError>
where
    E: Evm<Tx = TxEnv, DB: StateDB, Inspector = AnvilInspector>,
{
    let info = evm
        .db_mut()
        .basic(target)
        .map_err(|err| FrameExecutionError::Evm { index, message: err.to_string() })?;
    Ok(info.is_none_or(|info| {
        info.code_hash == alloy_primitives::KECCAK256_EMPTY
            || info.code_hash == alloy_primitives::B256::ZERO
    }))
}

/// The EIP-8141 default code for a `VERIFY` frame whose target carries no code.
///
/// It approves the scope named by the frame's flags, provided the transaction
/// carries a matching secp256k1 signature over the canonical signature hash at
/// the expected index: the sender's own approval is signature 0, a sponsor's is
/// signature 1. The signature itself was already verified when the envelope was
/// validated, so only the binding to this target is checked here.
fn default_verify_scope(tx: &TxFrame, frame: &Frame, resolved_target: Address) -> Option<u64> {
    let allowed = frame.flags & flags::APPROVE_EXECUTION_PAYMENT;
    if allowed == 0 {
        return None;
    }
    let sig_index = if allowed & flags::APPROVE_EXECUTION != 0 { 0 } else { 1 };
    let sig = tx.signatures.get(sig_index)?;
    if sig.scheme != foundry_primitives::scheme::SECP256K1 || !sig.msg.is_empty() {
        return None;
    }
    if sig.resolved_signer(tx.sender)? != resolved_target {
        return None;
    }
    Some(allowed as u64)
}

/// Applies an `APPROVE` that a frame successfully executed.
///
/// Mirrors the reference's `FrameContext.Approve`: the scope must be permitted
/// by the frame's flags, execution may only be approved by the sender's own
/// frame, and approving payment collects `max_cost` from the payer up front and
/// bumps the sender's nonce.
#[allow(clippy::too_many_arguments)]
fn apply_approval<E>(
    evm: &mut E,
    tx: &TxFrame,
    frame: &Frame,
    resolved_target: Address,
    scope: u64,
    max_cost: U256,
    approval: &mut ApprovalState,
    merged: &mut EvmState,
) -> Result<(), FrameExecutionError>
where
    E: Evm<Tx = TxEnv, DB: StateDB, Inspector = AnvilInspector>,
{
    let allowed = (frame.flags & flags::APPROVE_EXECUTION_PAYMENT) as u64;
    if scope == 0 || scope & !allowed != 0 {
        return Ok(());
    }

    let approves_execution = scope & SCOPE_EXECUTION != 0;
    let approves_payment = scope & SCOPE_PAYMENT != 0;

    if approves_execution {
        // Only the sender's own frame may authorise the sender's execution.
        if approval.sender_approved || resolved_target != tx.sender {
            return Ok(());
        }
    }
    if approves_payment && (approval.payer.is_some() || !(approval.sender_approved || approves_execution))
    {
        // Payment may only be approved once, and only after execution has been.
        return Ok(());
    }
    debug_assert!(matches!(scope, SCOPE_PAYMENT | SCOPE_EXECUTION | SCOPE_EXECUTION_AND_PAYMENT));

    if approves_payment {
        let mut payer_account = evm
            .db_mut()
            .basic(resolved_target)
            .map_err(|err| FrameExecutionError::Evm { index: 0, message: err.to_string() })?
            .unwrap_or_default();
        // A payer that cannot cover the maximum cost cannot approve payment.
        if payer_account.balance < max_cost {
            return Ok(());
        }
        payer_account.balance -= max_cost;

        let mut sender_account = evm
            .db_mut()
            .basic(tx.sender)
            .map_err(|err| FrameExecutionError::Evm { index: 0, message: err.to_string() })?
            .unwrap_or_default();
        sender_account.nonce = sender_account.nonce.saturating_add(1);
        if resolved_target == tx.sender {
            sender_account.balance = payer_account.balance;
        }

        let mut diff = EvmState::default();
        diff.insert(resolved_target, touched_account(payer_account.clone()));
        diff.insert(tx.sender, touched_account(sender_account));
        merge_state(merged, diff.clone());
        evm.db_mut().commit(diff);

        approval.payer = Some(resolved_target);
    }
    if approves_execution {
        approval.sender_approved = true;
    }
    Ok(())
}

/// Refunds the payer the difference between the collected `max_cost` and the
/// fee actually charged, and pays the tip to the coinbase.
fn settle_fee<E>(
    evm: &mut E,
    tx: &TxFrame,
    payer: Address,
    gas_used: u64,
    max_cost: U256,
    merged: &mut EvmState,
) -> Result<(), FrameExecutionError>
where
    E: Evm<Tx = TxEnv, DB: StateDB, Inspector = AnvilInspector>,
{
    let base_fee = U256::from(evm.block().basefee());
    let tip = tx
        .max_priority_fee_per_gas
        .min(tx.max_fee_per_gas.saturating_sub(base_fee));
    let effective_gas_price = base_fee.saturating_add(tip);
    let charged = effective_gas_price.saturating_mul(U256::from(gas_used));
    let refund = max_cost.saturating_sub(charged);
    let coinbase = evm.block().beneficiary();

    let mut diff = EvmState::default();
    if !refund.is_zero() {
        let mut account = evm
            .db_mut()
            .basic(payer)
            .map_err(|err| FrameExecutionError::Evm { index: 0, message: err.to_string() })?
            .unwrap_or_default();
        account.balance = account.balance.saturating_add(refund);
        diff.insert(payer, touched_account(account));
    }

    let tip_fee = tip.saturating_mul(U256::from(gas_used));
    if !tip_fee.is_zero() {
        let mut account = evm
            .db_mut()
            .basic(coinbase)
            .map_err(|err| FrameExecutionError::Evm { index: 0, message: err.to_string() })?
            .unwrap_or_default();
        account.balance = account.balance.saturating_add(tip_fee);
        // The coinbase may also be the payer, in which case the refund above
        // already staged an entry that this must build on.
        if let Some(staged) = diff.get(&coinbase) {
            account.balance = staged.info.balance.saturating_add(tip_fee);
        }
        diff.insert(coinbase, touched_account(account));
    }

    merge_state(merged, diff.clone());
    evm.db_mut().commit(diff);
    Ok(())
}

/// Wraps account info as a touched account so the diff is committed.
fn touched_account(info: revm::state::AccountInfo) -> revm::state::Account {
    let mut account = revm::state::Account::from(info);
    account.mark_touch();
    account
}
