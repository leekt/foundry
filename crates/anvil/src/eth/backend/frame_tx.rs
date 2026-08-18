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

use crate::eth::backend::mem::inspector::{
    AnvilInspector, ApprovalState, FrameApprovalOutcome, FrameInspector,
};
use alloy_consensus::Transaction as _;
use alloy_evm::{Evm, eth::EthEvm};
use alloy_primitives::{Address, B256, Log, TxKind, U256, keccak256};
use foundry_primitives::{
    ENTRY_POINT_ADDRESS, Frame, FrameReceipt, TxFrame, flags, frame_gas, mode,
};
#[cfg(test)]
use foundry_primitives::{EXPIRY_VERIFIER_ADDRESS, EXPIRY_VERIFIER_RUNTIME_CODE};
use revm::{
    context::{
        Block as _, Cfg as _, ContextTr as _, JournalTr, TxEnv,
        journaled_state::{JournalCheckpoint, account::JournaledAccountTr},
        result::{ExecutionResult, Output, ResultAndState, ResultGas, SuccessReason},
    },
    context_interface::host::{FrameInfo, FrameSigInfo, FrameTxContext},
    interpreter::instructions::frame_tx::install_frame_tx_context,
    state::{AccountInfo, EvmState},
};

/// Approval scopes, mirroring the frame flags they are granted from.
const SCOPE_PAYMENT: u64 = flags::APPROVE_PAYMENT as u64;
const SCOPE_EXECUTION: u64 = flags::APPROVE_EXECUTION as u64;
const SCOPE_EXECUTION_AND_PAYMENT: u64 = flags::APPROVE_EXECUTION_PAYMENT as u64;

/// Frame receipt status, matching the reference's encoding.
const STATUS_FAILED: u8 = 0;
const STATUS_SUCCESS: u8 = 1;
/// A frame that never ran, because an earlier frame of its atomic batch failed.
const STATUS_SKIPPED: u8 = 2;

/// Why a frame transaction could not be executed at all.
///
/// These are the conditions the reference treats as making the whole
/// transaction invalid rather than merely failing a frame.
#[derive(Clone, Debug, thiserror::Error)]
pub enum FrameExecutionError {
    /// The outer nonce does not match the sender's live state nonce.
    #[error("frame transaction nonce {tx} does not match sender nonce {state}")]
    NonceMismatch {
        /// Nonce carried by the frame transaction.
        tx: u64,
        /// Sender nonce read from the live journal.
        state: u64,
    },
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
    /// The concrete EVM journal cannot begin an outer frame transaction.
    #[error("frame transaction lifecycle is unavailable")]
    LifecycleUnavailable,
    /// The frame-gas model here does not compose with Amsterdam node-level
    /// state-gas semantics.
    #[error("frame gas does not support Amsterdam state-gas rules")]
    StateGasUnsupported,
    /// An `APPROVE` that had to create the sender could not cover the
    /// account-creation state-gas charge from the approving frame's budget.
    #[error("frame {index} exhausted its state gas during APPROVE")]
    StateGasExhausted {
        /// Index of the offending frame.
        index: usize,
    },
    /// Final settlement exceeded the amount collected from the payer.
    #[error("charged fee exceeds precharged maximum")]
    ChargedExceedsMaxCost,
    /// A settlement credit would overflow an account balance.
    #[error("balance overflow while settling account {address}")]
    BalanceOverflow {
        /// Account whose balance could not be credited.
        address: Address,
    },
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
pub(crate) struct FrameTxOutcome<H> {
    /// The transaction-level result, as the block executor expects it.
    pub result: ResultAndState<H>,
    /// The account that paid, established by an `APPROVE` of payment.
    pub payer: Address,
    /// Consensus receipts for every frame, in frame order.
    pub frame_receipts: Vec<FrameReceipt>,
}

/// Suspends ordinary transaction rules that do not apply while frames run.
///
/// Each frame is a top-level call priced at zero, because the payer is charged
/// once for the whole transaction after every frame has run. revm would
/// otherwise reject a zero-priced call against a non-zero base fee, bill each
/// frame's caller separately, and reject a contract sender under EIP-3607.
pub trait SuspendFeeRules {
    /// Sets the frame-execution switches, returning their previous values.
    fn suspend_fee_rules(&mut self, suspended: bool) -> (bool, bool, bool);
    /// Restores the switches to previously saved values.
    fn restore_fee_rules(&mut self, saved: (bool, bool, bool));
    /// Reports whether incompatible Amsterdam state-gas accounting is active.
    fn is_frame_state_gas_enabled(&self) -> bool;
    /// Begins the persistent outer frame-transaction journal lifecycle.
    fn begin_frame_transaction(&mut self, sender: Address) -> bool;
    /// Reports whether the persistent outer lifecycle is active.
    fn is_frame_transaction_active(&self) -> bool;
    /// Reads an account from the live outer frame journal without warming it.
    fn frame_transaction_account_info(&mut self, address: Address) -> Result<AccountInfo, String>;
    /// Opens a journal checkpoint around a multi-frame atomic batch.
    fn frame_transaction_checkpoint(&mut self) -> JournalCheckpoint;
    /// Commits the latest atomic-batch checkpoint.
    fn frame_transaction_checkpoint_commit(&mut self);
    /// Reverts an atomic batch to its checkpoint.
    fn frame_transaction_checkpoint_revert(&mut self, checkpoint: JournalCheckpoint);
    /// Applies the default-code payment precharge and sender nonce bump in the journal.
    fn apply_default_payment_approval(
        &mut self,
        payer: Address,
        sender: Address,
        max_cost: U256,
    ) -> Result<bool, String>;
    /// Credits an account through journaled balance mutation.
    fn credit_frame_transaction_account(
        &mut self,
        address: Address,
        amount: U256,
    ) -> Result<bool, String>;
    /// Finishes the lifecycle, returning its sole cumulative state diff and canonical logs.
    fn finish_frame_transaction(&mut self) -> (EvmState, Vec<Log>);
    /// Aborts and clears the lifecycle. Repeated calls are harmless.
    fn abort_frame_transaction(&mut self);
}

/// Inspector operations required by the frame executor.
pub(crate) trait FrameTransactionInspector {
    fn watch_frame_approval(
        &mut self,
        resolved_target: Address,
        sender: Address,
        allowed_scope: u64,
        max_cost: U256,
        state: ApprovalState,
    );
    fn take_frame_approval(&mut self) -> Option<FrameApprovalOutcome>;
    fn begin_frame_transaction_trace(&mut self, sender: Address, gas_limit: u64);
    fn finish_frame_transaction_trace(&mut self, gas_used: u64);
}

impl FrameTransactionInspector for AnvilInspector {
    fn watch_frame_approval(
        &mut self,
        resolved_target: Address,
        sender: Address,
        allowed_scope: u64,
        max_cost: U256,
        state: ApprovalState,
    ) {
        AnvilInspector::watch_frame_approval(
            self,
            resolved_target,
            sender,
            allowed_scope,
            max_cost,
            state,
        );
    }

    fn take_frame_approval(&mut self) -> Option<FrameApprovalOutcome> {
        AnvilInspector::take_frame_approval(self)
    }

    fn begin_frame_transaction_trace(&mut self, sender: Address, gas_limit: u64) {
        AnvilInspector::begin_frame_transaction_trace(self, sender, gas_limit);
    }

    fn finish_frame_transaction_trace(&mut self, gas_used: u64) {
        AnvilInspector::finish_frame_transaction_trace(self, gas_used);
    }
}

impl<I> FrameTransactionInspector for (AnvilInspector, I) {
    fn watch_frame_approval(
        &mut self,
        resolved_target: Address,
        sender: Address,
        allowed_scope: u64,
        max_cost: U256,
        state: ApprovalState,
    ) {
        self.0.watch_frame_approval(resolved_target, sender, allowed_scope, max_cost, state);
    }

    fn take_frame_approval(&mut self) -> Option<FrameApprovalOutcome> {
        self.0.take_frame_approval()
    }

    fn begin_frame_transaction_trace(&mut self, sender: Address, gas_limit: u64) {
        self.0.begin_frame_transaction_trace(sender, gas_limit);
    }

    fn finish_frame_transaction_trace(&mut self, gas_used: u64) {
        self.0.finish_frame_transaction_trace(gas_used);
    }
}

impl<I: 'static> FrameTransactionInspector for FrameInspector<'_, I> {
    fn watch_frame_approval(
        &mut self,
        resolved_target: Address,
        sender: Address,
        allowed_scope: u64,
        max_cost: U256,
        state: ApprovalState,
    ) {
        self.approval_mut().watch_frame_approval(
            resolved_target,
            sender,
            allowed_scope,
            max_cost,
            state,
        );
    }

    fn take_frame_approval(&mut self) -> Option<FrameApprovalOutcome> {
        self.approval_mut().take_frame_approval()
    }

    fn begin_frame_transaction_trace(&mut self, sender: Address, gas_limit: u64) {
        self.begin_trace(sender, gas_limit);
    }

    fn finish_frame_transaction_trace(&mut self, gas_used: u64) {
        self.finish_trace(gas_used);
    }
}

impl<DB: alloy_evm::Database, I, P> SuspendFeeRules for EthEvm<DB, I, P> {
    fn suspend_fee_rules(&mut self, suspended: bool) -> (bool, bool, bool) {
        let cfg = &mut self.ctx_mut().cfg;
        let saved = (cfg.disable_base_fee, cfg.disable_fee_charge, cfg.disable_eip3607);
        cfg.disable_base_fee = suspended;
        cfg.disable_fee_charge = suspended;
        cfg.disable_eip3607 = suspended;
        saved
    }

    fn restore_fee_rules(&mut self, saved: (bool, bool, bool)) {
        let cfg = &mut self.ctx_mut().cfg;
        (cfg.disable_base_fee, cfg.disable_fee_charge, cfg.disable_eip3607) = saved;
    }

    fn is_frame_state_gas_enabled(&self) -> bool {
        self.ctx().cfg().is_amsterdam_eip8037_enabled()
            || self.ctx().cfg().is_amsterdam_eip2780_enabled()
    }

    fn begin_frame_transaction(&mut self, sender: Address) -> bool {
        self.ctx_mut().journal_mut().begin_frame_transaction(sender)
    }

    fn is_frame_transaction_active(&self) -> bool {
        self.ctx().journal().is_frame_transaction_active()
    }

    fn frame_transaction_account_info(&mut self, address: Address) -> Result<AccountInfo, String> {
        self.ctx_mut()
            .journal_mut()
            .frame_transaction_account_info(address)
            .map_err(|err| err.to_string())
            .and_then(|info| {
                info.ok_or_else(|| "frame transaction account lookup is unsupported".to_owned())
            })
    }

    fn frame_transaction_checkpoint(&mut self) -> JournalCheckpoint {
        self.ctx_mut().journal_mut().frame_transaction_checkpoint()
    }

    fn frame_transaction_checkpoint_commit(&mut self) {
        self.ctx_mut().journal_mut().frame_transaction_checkpoint_commit();
    }

    fn frame_transaction_checkpoint_revert(&mut self, checkpoint: JournalCheckpoint) {
        self.ctx_mut().journal_mut().frame_transaction_checkpoint_revert(checkpoint);
    }

    fn apply_default_payment_approval(
        &mut self,
        payer: Address,
        sender: Address,
        max_cost: U256,
    ) -> Result<bool, String> {
        let payer_info = self
            .ctx_mut()
            .journal_mut()
            .frame_transaction_account_info(payer)
            .map_err(|err| err.to_string())?
            .ok_or_else(|| "frame transaction account lookup is unsupported".to_owned())?;
        let sender_nonce = if payer == sender {
            payer_info.nonce
        } else {
            self.ctx_mut()
                .journal_mut()
                .frame_transaction_account_info(sender)
                .map_err(|err| err.to_string())?
                .ok_or_else(|| "frame transaction account lookup is unsupported".to_owned())?
                .nonce
        };
        if payer_info.balance < max_cost || sender_nonce == u64::MAX {
            return Ok(false);
        }

        if payer == sender {
            let mut account = self
                .ctx_mut()
                .journal_mut()
                .load_account_mut(payer)
                .map_err(|err| err.to_string())?;
            return Ok(account.decr_balance(max_cost) && account.bump_nonce());
        }

        let debited = self
            .ctx_mut()
            .journal_mut()
            .load_account_mut(payer)
            .map_err(|err| err.to_string())?
            .decr_balance(max_cost);
        let bumped = self
            .ctx_mut()
            .journal_mut()
            .load_account_mut(sender)
            .map_err(|err| err.to_string())?
            .bump_nonce();
        Ok(debited && bumped)
    }

    fn credit_frame_transaction_account(
        &mut self,
        address: Address,
        amount: U256,
    ) -> Result<bool, String> {
        self.ctx_mut()
            .journal_mut()
            .load_account_mut(address)
            .map(|mut account| account.incr_balance(amount))
            .map_err(|err| err.to_string())
    }

    fn finish_frame_transaction(&mut self) -> (EvmState, Vec<Log>) {
        self.ctx_mut().journal_mut().finish_frame_transaction()
    }

    fn abort_frame_transaction(&mut self) {
        self.ctx_mut().journal_mut().abort_frame_transaction();
    }
}

/// Synthetic default-code approval effects validated against a frame's state.
#[derive(Debug)]
struct ValidatedApproval {
    approves_execution: bool,
    payer: Option<Address>,
}

/// Canonical EIP-8250 hash of the legacy nonce domain: one key whose value is zero.
fn legacy_nonce_keys_hash() -> B256 {
    // keccak256(uint256(key_count) || uint256(key_0)).
    let mut preimage = [0u8; 64];
    preimage[31] = 1;
    keccak256(preimage)
}

/// `SYSTEM_ADDRESS` (EIP-4788), the emitter of EIP-7708 transfer logs.
const SYSTEM_ADDRESS: Address =
    Address::new(alloy_primitives::hex!("fffffffffffffffffffffffffffffffffffffffe"));

/// `keccak256("Transfer(address,address,uint256)")` (EIP-7708 topic 0).
const TRANSFER_TOPIC: B256 = B256::new(alloy_primitives::hex!(
    "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
));

/// The EIP-7708 transfer log a value-bearing frame emits before any EVM logs.
fn eth_transfer_log(from: Address, to: Address, value: U256) -> Log {
    Log::new_unchecked(
        SYSTEM_ADDRESS,
        vec![TRANSFER_TOPIC, from.into_word(), to.into_word()],
        value.to_be_bytes::<32>().to_vec().into(),
    )
}

/// Builds the frame-transaction context the introspection opcodes read.
///
/// `frame_index`, `state_gas_left` and `approvable_scopes` are the only
/// per-frame parts; the rest describes the whole transaction. Receipt gas of
/// already-completed frames is read from `receipts`.
fn build_context(
    tx: &TxFrame,
    frame_index: usize,
    statuses: &[u8],
    receipts: &[FrameReceipt],
    state_gas_left: u64,
    max_cost: U256,
) -> FrameTxContext {
    let frames = tx
        .frames
        .iter()
        .enumerate()
        .map(|(i, frame)| FrameInfo {
            resolved_target: frame.resolved_target(tx.sender),
            expected_caller: if frame.mode == mode::SENDER {
                tx.sender
            } else {
                ENTRY_POINT_ADDRESS
            },
            gas_limit: frame.gas_limit,
            state_gas_limit: frame.state_gas_limit,
            mode: frame.mode,
            flags: frame.flags,
            value: frame.value,
            status: statuses.get(i).copied().unwrap_or(STATUS_FAILED),
            execution_gas_used: receipts.get(i).map_or(0, |receipt| receipt.execution_gas_used),
            state_gas_used: receipts.get(i).map_or(0, |receipt| receipt.state_gas_used),
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

    FrameTxContext {
        sender: tx.sender,
        // The current wire envelope has only the scalar legacy key-zero nonce domain.
        nonce: tx.nonce,
        legacy_nonce: tx.nonce,
        nonce_keys: vec![U256::ZERO],
        nonce_keys_hash: legacy_nonce_keys_hash(),
        sig_hash: tx.signature_hash(),
        max_cost,
        max_priority_fee_per_gas: tx.max_priority_fee_per_gas,
        max_fee_per_gas: tx.max_fee_per_gas,
        max_fee_per_blob_gas: tx.max_fee_per_blob_gas,
        blob_count: tx.blob_versioned_hashes.len() as u64,
        state_gas_left,
        frame_index: frame_index as u64,
        frames,
        signatures,
        recent_root_references: Vec::new(),
        trace: Default::default(),
        approvable_scopes: (tx.frames[frame_index].flags & flags::APPROVE_EXECUTION_PAYMENT) as u64,
        approved_scope: 0,
        event_index: Default::default(),
    }
}

/// `max_cost`: the most the payer may be charged for the transaction.
fn max_cost(tx: &TxFrame, blob_base_fee: U256) -> Option<U256> {
    let blob_fee = blob_base_fee.checked_mul(U256::from(tx.blob_gas()))?;
    tx.max_fee_per_gas.checked_mul(U256::from(tx.max_gas()))?.checked_add(blob_fee)
}

/// Builds the environment for a single frame's top-level call.
fn frame_env(tx: &TxFrame, frame: &Frame, caller: Address, caller_nonce: u64) -> TxEnv {
    let mut tx_env = TxEnv {
        // Use the closest ordinary envelope so GASPRICE and BLOBHASH see the
        // original transaction fields. TXPARAM reads the frame context instead.
        tx_type: if tx.blob_versioned_hashes.is_empty() { 2 } else { 3 },
        caller,
        // ORIGIN must report the frame's caller at every call depth, which
        // revm derives from the transaction caller.
        kind: TxKind::Call(frame.resolved_target(tx.sender)),
        data: frame.data.clone(),
        value: frame.value,
        gas_limit: frame.gas_limit,
        // Fee charging is suspended while frames run, but transaction-info
        // opcodes must still observe the effective EIP-1559 price.
        gas_price: tx.max_fee_per_gas(),
        gas_priority_fee: tx.max_priority_fee_per_gas(),
        blob_hashes: tx.blob_versioned_hashes.clone(),
        max_fee_per_blob_gas: tx.max_fee_per_blob_gas().unwrap_or_default(),
        nonce: caller_nonce,
        chain_id: tx.chain_id(),
        ..Default::default()
    };
    tx_env.set_eip7851_sender_ecdsa_authenticated(false);
    tx_env
}

/// Runs every frame of `tx`, then settles the fee against the payer.
///
/// Returns the outer journal's cumulative diff so the caller commits exactly
/// once, matching how the block executor treats every other transaction type.
pub(crate) fn execute_frame_tx<E>(
    evm: &mut E,
    tx: &TxFrame,
) -> Result<FrameTxOutcome<E::HaltReason>, FrameExecutionError>
where
    E: Evm<Tx = TxEnv> + SuspendFeeRules,
    E::Inspector: FrameTransactionInspector,
{
    if evm.is_frame_state_gas_enabled() {
        return Err(FrameExecutionError::StateGasUnsupported);
    }
    let saved_fee_rules = evm.suspend_fee_rules(true);
    let lifecycle_started = evm.begin_frame_transaction(tx.sender);
    let outcome = if lifecycle_started {
        run_frames(evm, tx)
    } else {
        Err(FrameExecutionError::LifecycleUnavailable)
    };
    if outcome.is_err() && lifecycle_started {
        // Handler errors can abort before reaching here. The lifecycle API makes
        // this repeated cleanup harmless.
        evm.abort_frame_transaction();
    }
    // An EVM error can return before the normal per-frame take below.
    let _ = evm.inspector_mut().take_frame_approval();
    evm.restore_fee_rules(saved_fee_rules);
    outcome
}

/// Runs every frame and settles the fee. Split from [`execute_frame_tx`] so the
/// fee rules are restored and the state is unwound on every exit, including the
/// error paths.
fn run_frames<E>(
    evm: &mut E,
    tx: &TxFrame,
) -> Result<FrameTxOutcome<E::HaltReason>, FrameExecutionError>
where
    E: Evm<Tx = TxEnv> + SuspendFeeRules,
    E::Inspector: FrameTransactionInspector,
{
    let sender_nonce = evm
        .frame_transaction_account_info(tx.sender)
        .map_err(|message| FrameExecutionError::Evm { index: 0, message })?
        .nonce;
    if tx.nonce != sender_nonce {
        return Err(FrameExecutionError::NonceMismatch { tx: tx.nonce, state: sender_nonce });
    }

    let (standard_gas, floor_gas, max_gas) =
        tx.gas_limits().ok_or(FrameExecutionError::GasOverflow)?;
    let blob_base_fee = U256::from(evm.block().blob_gasprice().unwrap_or_default());
    let max_cost = max_cost(tx, blob_base_fee).ok_or(FrameExecutionError::MaxCostOverflow)?;
    evm.inspector_mut().begin_frame_transaction_trace(tx.sender, max_gas);

    let mut approval = ApprovalState::default();
    let mut statuses = vec![STATUS_FAILED; tx.frames.len()];
    let mut frame_receipts = Vec::with_capacity(tx.frames.len());
    let mut frame_gas_total = 0u64;
    let mut frame_state_total = 0u64;
    let mut refund_counter = 0i64;

    // Frames run one atomic batch at a time. A batch is the maximal contiguous
    // run [start, end] where frames start..end-1 carry the ATOMIC_BATCH flag and
    // frame end does not; a lone unflagged frame is the degenerate batch
    // [start, start]. The terminator is part of the batch, so its failure rolls
    // the batch back just as a flagged frame's does.
    let mut start = 0;
    while start < tx.frames.len() {
        let mut batch_end = start;
        while batch_end < tx.frames.len() - 1
            && tx.frames[batch_end].flags & flags::ATOMIC_BATCH != 0
        {
            batch_end += 1;
        }
        // A lone failed frame is already reverted by its frame-call checkpoint.
        // Multi-frame batches need one surrounding checkpoint so prior
        // successful frames are reverted with the failing terminator.
        let batch_checkpoint = (batch_end > start).then(|| evm.frame_transaction_checkpoint());
        let approval_before_batch = approval;
        let refund_before_batch = refund_counter;
        let mut failed = None;

        for index in start..=batch_end {
            let frame = &tx.frames[index];
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

            let caller_nonce = evm
                .frame_transaction_account_info(caller)
                .map_err(|message| FrameExecutionError::Evm { index, message })?
                .nonce;

            // EIP-8037 frame gas pools. The toolkit meters the state dimension
            // for the charges EIP-8141 itself defines -- account creation by a
            // value-bearing frame and sender creation by APPROVE. Opcode-level
            // EIP-8037 charges (SSTORE, code deposit) are not modeled here.
            let mut state_gas_left = frame.state_gas_limit;
            let payer_before = approval.payer;
            let sender_missing = account_missing(evm, tx.sender, index)?;
            let mut halted_on_state_gas = false;
            if !frame.value.is_zero() && account_missing(evm, resolved_target, index)? {
                if state_gas_left < frame_gas::NEW_ACCOUNT_STATE_GAS {
                    // A charge exceeding its pool is an exceptional halt of the
                    // frame, consuming its execution pool.
                    halted_on_state_gas = true;
                } else {
                    state_gas_left -= frame_gas::NEW_ACCOUNT_STATE_GAS;
                }
            }

            let mut succeeded;
            let gross_gas_used;
            let mut frame_logs;
            if halted_on_state_gas {
                succeeded = false;
                gross_gas_used = frame.gas_limit;
                frame_logs = Vec::new();
            } else {
                // Scope the opcode context to this frame. Dropping the guard
                // restores an outer context even when execution errors or
                // unwinds.
                evm.inspector_mut().watch_frame_approval(
                    resolved_target,
                    tx.sender,
                    (frame.flags & flags::APPROVE_EXECUTION_PAYMENT) as u64,
                    max_cost,
                    approval,
                );
                let outcome = {
                    let _frame_context = install_frame_tx_context(build_context(
                        tx,
                        index,
                        &statuses,
                        &frame_receipts,
                        state_gas_left,
                        max_cost,
                    ));
                    evm.transact_raw(frame_env(tx, frame, caller, caller_nonce))
                };

                let observed = evm
                    .inspector_mut()
                    .take_frame_approval()
                    .expect("frame approval watcher was installed");
                approval = observed.state;

                // `transact_raw` has already finalized this frame call through
                // the active REVM lifecycle. Its returned state is observational
                // only; the outer journal remains the source of truth.
                let ResultAndState { result, state: _ } = outcome.map_err(|err| {
                    FrameExecutionError::Evm { index, message: format!("{err:?}") }
                })?;

                succeeded = result.is_success();
                gross_gas_used = result.gas().total_gas_spent();
                frame_logs = result.logs().to_vec();

                // An account with no code of its own still validates frame
                // transactions, through the protocol-defined default code. In
                // DEFAULT and SENDER mode that is a plain empty-code call, which
                // is what just ran; only VERIFY mode carries extra semantics.
                let uses_default_verify = succeeded
                    && frame.mode == mode::VERIFY
                    && observed.attempts.is_empty()
                    && target_has_no_code(evm, resolved_target, index)?;
                let default_scope = uses_default_verify
                    .then(|| default_verify_scope(tx, frame, resolved_target))
                    .flatten();

                // Empty-code VERIFY executes the protocol's synthetic APPROVE.
                // Its validation failure is a VERIFY revert, not merely an
                // absent payer.
                let mut validated_approval = None;
                if uses_default_verify {
                    if let Some(scope) = default_scope {
                        match validate_default_approval(
                            evm,
                            tx,
                            frame,
                            resolved_target,
                            scope,
                            max_cost,
                            &approval,
                            index,
                        )? {
                            Some(validated) => validated_approval = Some(validated),
                            None => succeeded = false,
                        }
                    } else {
                        succeeded = false;
                    }
                }

                if let Some(validated) = validated_approval
                    && !apply_default_approval(
                        evm,
                        validated,
                        tx.sender,
                        max_cost,
                        &mut approval,
                        index,
                    )?
                {
                    succeeded = false;
                }

                if succeeded {
                    refund_counter = refund_counter
                        .checked_add(observed.refund_counter)
                        .ok_or(FrameExecutionError::GasOverflow)?;
                }
            }
            frame_gas_total = frame_gas_total
                .checked_add(gross_gas_used)
                .ok_or(FrameExecutionError::GasOverflow)?;

            // Incrementing the nonce of a non-existent sender created the
            // account: charge `STATE_BYTES_PER_NEW_ACCOUNT * CPSB` from the
            // approving frame's state budget. A pool that cannot cover the
            // charge invalidates the transaction, as approval effects cannot
            // stand without the charge.
            if succeeded && sender_missing && payer_before.is_none() && approval.payer.is_some() {
                if state_gas_left < frame_gas::NEW_ACCOUNT_STATE_GAS {
                    return Err(FrameExecutionError::StateGasExhausted { index });
                }
                state_gas_left -= frame_gas::NEW_ACCOUNT_STATE_GAS;
            }

            if succeeded {
                statuses[index] = STATUS_SUCCESS;
                // A non-zero value transfer to an address other than the sender
                // emits the EIP-7708 transfer log, before the frame's EVM logs.
                if !frame.value.is_zero() && resolved_target != tx.sender {
                    frame_logs.insert(0, eth_transfer_log(tx.sender, resolved_target, frame.value));
                }
            } else {
                // A failed frame keeps its execution gas but loses its state
                // changes, including its attributed state gas. A reverting
                // VERIFY frame invalidates the whole transaction.
                if frame.mode == mode::VERIFY {
                    return Err(FrameExecutionError::VerifyFailed { index });
                }
            }
            let state_gas_used = if succeeded { frame.state_gas_limit - state_gas_left } else { 0 };
            frame_state_total = frame_state_total
                .checked_add(state_gas_used)
                .ok_or(FrameExecutionError::GasOverflow)?;
            frame_receipts.push(FrameReceipt {
                status: statuses[index],
                execution_gas_used: gross_gas_used,
                state_gas_used,
                logs: frame_logs,
            });

            if !succeeded {
                failed = Some(index);
                break;
            }
        }

        // A failure anywhere in a multi-frame batch undoes journal state,
        // warmth, creation metadata, logs and approval precharge. Frames that
        // ran retain their status and gross gas; the suffix is skipped.
        if let (Some(checkpoint), Some(failed)) = (batch_checkpoint, failed) {
            evm.frame_transaction_checkpoint_revert(checkpoint);
            approval = approval_before_batch;
            refund_counter = refund_before_batch;
            // Unrolling the batch removes state-gas charges attributed to its
            // frames from their receipts, along with their logs.
            for receipt in &mut frame_receipts[start..] {
                receipt.logs.clear();
                frame_state_total -= receipt.state_gas_used;
                receipt.state_gas_used = 0;
            }
            for status in &mut statuses[failed + 1..=batch_end] {
                *status = STATUS_SKIPPED;
                // A skipped frame's gas allotments are left unspent.
                frame_receipts.push(FrameReceipt {
                    status: STATUS_SKIPPED,
                    execution_gas_used: 0,
                    state_gas_used: 0,
                    logs: Vec::new(),
                });
            }
        } else if batch_checkpoint.is_some() {
            evm.frame_transaction_checkpoint_commit();
        }
        start = batch_end + 1;
    }

    let payer = approval.payer.ok_or(FrameExecutionError::NoPayer)?;

    // Settlement (EIP-8141 gas accounting): the intrinsic overhead plus what
    // the frames actually used in both dimensions, refund-capped, with the
    // calldata floor compared against the execution component alone. State gas
    // never absorbs into the data floor.
    let overhead = standard_gas.saturating_sub(tx.sum_frame_gas().unwrap_or(0));
    let gas_used_before_refund = frame_gas_total
        .checked_add(frame_state_total)
        .and_then(|used| used.checked_add(overhead))
        .ok_or(FrameExecutionError::GasOverflow)?;
    let applied_refund =
        u64::try_from(refund_counter).unwrap_or_default().min(gas_used_before_refund / 5);
    let gas_used_after_refund = gas_used_before_refund.saturating_sub(applied_refund);
    let tx_execution_gas = gas_used_after_refund.saturating_sub(frame_state_total).max(floor_gas);
    let gas_used = tx_execution_gas.saturating_add(frame_state_total).min(max_gas);

    settle_fee(evm, tx, payer, gas_used, max_cost, blob_base_fee)?;
    let (state, journal_logs) = evm.finish_frame_transaction();
    evm.inspector_mut().finish_frame_transaction_trace(gas_used);
    // Synthesized EIP-7708 transfer logs live only in the frame receipts; the
    // journal carries everything the EVM emitted.
    debug_assert_eq!(
        journal_logs,
        frame_receipts
            .iter()
            .flat_map(|receipt| receipt.logs.iter().filter(|log| log.address != SYSTEM_ADDRESS))
            .cloned()
            .collect::<Vec<_>>()
    );
    // The transaction-level log view is the frame receipts' concatenation,
    // transfer logs included.
    let logs =
        frame_receipts.iter().flat_map(|receipt| receipt.logs.iter().cloned()).collect::<Vec<_>>();

    // The transaction as a whole succeeds once a payer is established; an
    // individual frame's failure is reported in its own frame result, exactly
    // as the reference does.
    let result = ExecutionResult::Success {
        reason: SuccessReason::Return,
        gas: ResultGas::default()
            .with_total_gas_spent(gas_used_before_refund)
            .with_refunded(applied_refund)
            .with_floor_gas(floor_gas),
        logs,
        output: Output::Call(Default::default()),
    };
    Ok(FrameTxOutcome { result: ResultAndState { result, state }, payer, frame_receipts })
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
    E: Evm<Tx = TxEnv> + SuspendFeeRules,
{
    let info = evm
        .frame_transaction_account_info(target)
        .map_err(|message| FrameExecutionError::Evm { index, message })?;
    Ok(info.code_hash == alloy_primitives::KECCAK256_EMPTY
        || info.code_hash == alloy_primitives::B256::ZERO)
}

/// Reports whether an account does not exist under the EIP-8037 existence
/// rule: no balance, no nonce and no code. Creating such an account charges
/// `STATE_BYTES_PER_NEW_ACCOUNT * CPSB` state gas.
fn account_missing<E>(
    evm: &mut E,
    address: Address,
    index: usize,
) -> Result<bool, FrameExecutionError>
where
    E: Evm<Tx = TxEnv> + SuspendFeeRules,
{
    let info = evm
        .frame_transaction_account_info(address)
        .map_err(|message| FrameExecutionError::Evm { index, message })?;
    Ok(info.balance.is_zero()
        && info.nonce == 0
        && (info.code_hash == alloy_primitives::KECCAK256_EMPTY
            || info.code_hash == alloy_primitives::B256::ZERO))
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

/// Validates the synthetic `APPROVE` executed by empty-account default code.
///
/// Mirrors the reference's `FrameContext.Approve`: the scope must be permitted
/// by the frame's flags, execution may only be approved by the sender's own
/// frame, and approving payment collects `max_cost` from the payer up front and
/// bumps the sender's nonce.
#[allow(clippy::too_many_arguments)]
fn validate_default_approval<E>(
    evm: &mut E,
    tx: &TxFrame,
    frame: &Frame,
    resolved_target: Address,
    scope: u64,
    max_cost: U256,
    approval: &ApprovalState,
    index: usize,
) -> Result<Option<ValidatedApproval>, FrameExecutionError>
where
    E: Evm<Tx = TxEnv> + SuspendFeeRules,
{
    let allowed = (frame.flags & flags::APPROVE_EXECUTION_PAYMENT) as u64;
    if scope == 0 || scope & !allowed != 0 {
        return Ok(None);
    }

    let approves_execution = scope & SCOPE_EXECUTION != 0;
    let approves_payment = scope & SCOPE_PAYMENT != 0;

    if approves_execution {
        // Only the sender's own frame may authorise the sender's execution.
        if approval.sender_approved || resolved_target != tx.sender {
            return Ok(None);
        }
    }
    if approves_payment
        && (approval.payer.is_some() || !(approval.sender_approved || approves_execution))
    {
        // Payment may only be approved once, and only after execution has been.
        return Ok(None);
    }
    debug_assert!(matches!(scope, SCOPE_PAYMENT | SCOPE_EXECUTION | SCOPE_EXECUTION_AND_PAYMENT));

    if approves_payment {
        let payer_account = evm
            .frame_transaction_account_info(resolved_target)
            .map_err(|message| FrameExecutionError::Evm { index, message })?;
        // A payer that cannot cover the maximum cost cannot approve payment.
        if payer_account.balance < max_cost {
            return Ok(None);
        }
        let sender_nonce = if resolved_target == tx.sender {
            payer_account.nonce
        } else {
            evm.frame_transaction_account_info(tx.sender)
                .map_err(|message| FrameExecutionError::Evm { index, message })?
                .nonce
        };
        if sender_nonce == u64::MAX {
            return Ok(None);
        }
    }

    Ok(Some(ValidatedApproval {
        approves_execution,
        payer: approves_payment.then_some(resolved_target),
    }))
}

/// Applies default-code approval effects to the live outer journal.
fn apply_default_approval<E>(
    evm: &mut E,
    validated: ValidatedApproval,
    sender: Address,
    max_cost: U256,
    approval: &mut ApprovalState,
    index: usize,
) -> Result<bool, FrameExecutionError>
where
    E: Evm<Tx = TxEnv> + SuspendFeeRules,
{
    let ValidatedApproval { approves_execution, payer } = validated;
    if let Some(payer) = payer {
        let applied = evm
            .apply_default_payment_approval(payer, sender, max_cost)
            .map_err(|message| FrameExecutionError::Evm { index, message })?;
        if !applied {
            return Ok(false);
        }
        approval.payer = Some(payer);
    }
    if approves_execution {
        approval.sender_approved = true;
    }
    Ok(true)
}

/// Refunds the payer the difference between the collected `max_cost` and the
/// fee actually charged, and pays the tip to the coinbase.
fn settle_fee<E>(
    evm: &mut E,
    tx: &TxFrame,
    payer: Address,
    gas_used: u64,
    max_cost: U256,
    blob_base_fee: U256,
) -> Result<(), FrameExecutionError>
where
    E: Evm<Tx = TxEnv> + SuspendFeeRules,
{
    let base_fee = U256::from(evm.block().basefee());
    let tip = tx.max_priority_fee_per_gas.min(tx.max_fee_per_gas.saturating_sub(base_fee));
    let effective_gas_price =
        base_fee.checked_add(tip).ok_or(FrameExecutionError::MaxCostOverflow)?;
    let blob_fee = blob_base_fee
        .checked_mul(U256::from(tx.blob_gas()))
        .ok_or(FrameExecutionError::MaxCostOverflow)?;
    let charged = effective_gas_price
        .checked_mul(U256::from(gas_used))
        .and_then(|fee| fee.checked_add(blob_fee))
        .ok_or(FrameExecutionError::MaxCostOverflow)?;
    let refund = max_cost.checked_sub(charged).ok_or(FrameExecutionError::ChargedExceedsMaxCost)?;
    let coinbase = evm.block().beneficiary();

    if !refund.is_zero() {
        let credited = evm
            .credit_frame_transaction_account(payer, refund)
            .map_err(|message| FrameExecutionError::Evm { index: 0, message })?;
        if !credited {
            return Err(FrameExecutionError::BalanceOverflow { address: payer });
        }
    }

    let tip_fee =
        tip.checked_mul(U256::from(gas_used)).ok_or(FrameExecutionError::MaxCostOverflow)?;
    if !tip_fee.is_zero() {
        let credited = evm
            .credit_frame_transaction_account(coinbase, tip_fee)
            .map_err(|message| FrameExecutionError::Evm { index: 0, message })?;
        if !credited {
            return Err(FrameExecutionError::BalanceOverflow { address: coinbase });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eth::backend::{
        db::{Db, MaybeFullDatabase},
        mem::{in_memory_db::StateRootDb, state::state_root},
    };
    use alloy_evm::{EvmEnv, block::StateDB, eth::EthEvmBuilder, precompiles::PrecompilesMap};
    use foundry_evm::inspectors::{TracingInspector, TracingInspectorConfig};
    use revm::{
        Database as _, DatabaseCommit, Inspector,
        bytecode::Bytecode,
        context::result::HaltReason,
        context_interface::block::BlobExcessGasAndPrice,
        database::InMemoryDB,
        interpreter::{
            CallInputs, CallOutcome, InstructionResult, instructions::frame_tx::frame_tx_context,
            interpreter::EthInterpreter,
        },
        primitives::hardfork::SpecId,
    };

    const TEST_GAS_LIMIT: u64 = 100_000;

    fn test_evm(
        accounts: impl IntoIterator<Item = (Address, U256, u64, Bytecode)>,
    ) -> EthEvm<InMemoryDB, AnvilInspector, PrecompilesMap> {
        let mut db = InMemoryDB::default();
        for (address, balance, nonce, code) in accounts {
            db.insert_account_info(
                address,
                AccountInfo { balance, nonce, ..Default::default() }.with_code(code),
            );
        }
        EthEvmBuilder::new(db, EvmEnv::default())
            .activate_inspector(AnvilInspector::default())
            .build()
    }

    #[test]
    fn frame_execution_preserves_eip7851() {
        let mut evm = test_evm([]);
        evm.ctx_mut().cfg.enable_eip7851 = true;

        let saved = evm.suspend_fee_rules(true);
        assert!(evm.ctx().cfg.enable_eip7851);

        evm.restore_fee_rules(saved);
        assert!(evm.ctx().cfg.enable_eip7851);
    }

    fn state_root_evm(
        accounts: impl IntoIterator<Item = (Address, U256, u64, Bytecode)>,
    ) -> EthEvm<StateRootDb, AnvilInspector, PrecompilesMap> {
        let mut db = StateRootDb::new(false);
        for (address, balance, nonce, code) in accounts {
            db.insert_account(
                address,
                AccountInfo { balance, nonce, ..Default::default() }.with_code(code),
            );
        }
        EthEvmBuilder::new(db, EvmEnv::default())
            .activate_inspector(AnvilInspector::default())
            .build()
    }

    fn execute_and_commit<DB>(
        evm: &mut EthEvm<DB, AnvilInspector, PrecompilesMap>,
        tx: &TxFrame,
    ) -> Result<FrameTxOutcome<HaltReason>, FrameExecutionError>
    where
        DB: StateDB,
    {
        let outcome = execute_frame_tx(evm, tx)?;
        evm.db_mut().commit(outcome.result.state.clone());
        Ok(outcome)
    }

    fn approver_code(scope: u8, mutate: bool) -> Bytecode {
        let mut code = Vec::new();
        if mutate {
            // SSTORE(0, calldataload(0)); LOG0(0, 0).
            code.extend_from_slice(&[0x5f, 0x35, 0x5f, 0x55, 0x5f, 0x5f, 0xa0]);
        }
        // APPROVE(0, 0, scope).
        code.extend_from_slice(&[0x60, scope, 0x5f, 0x5f, 0xaa]);
        Bytecode::new_raw(code.into())
    }

    fn reverter_code() -> Bytecode {
        Bytecode::new_raw(vec![0x5f, 0x5f, 0xfd].into())
    }

    fn push_word(code: &mut Vec<u8>, value: U256) {
        if value.is_zero() {
            code.push(0x5f);
            return;
        }
        let bytes = value.to_be_bytes::<32>();
        let first = bytes.iter().position(|byte| *byte != 0).unwrap();
        let value = &bytes[first..];
        code.push(0x5f + value.len() as u8);
        code.extend_from_slice(value);
    }

    fn push_label(code: &mut Vec<u8>) -> usize {
        code.push(0x61);
        let patch = code.len();
        code.extend_from_slice(&[0, 0]);
        patch
    }

    fn patch_label(code: &mut [u8], patch: usize, destination: usize) {
        code[patch..patch + 2].copy_from_slice(&u16::try_from(destination).unwrap().to_be_bytes());
    }

    #[derive(Clone, Copy)]
    struct NestedApproval {
        target: Option<Address>,
        scope: u8,
        length: U256,
        succeeds: bool,
    }

    /// Builds code whose empty-calldata entry point makes the requested calls,
    /// while non-empty self-calls execute `APPROVE(scope, length)`.
    fn nested_approver_code(calls: &[NestedApproval]) -> Bytecode {
        nested_approver_code_with_result(calls, true)
    }

    fn nested_approver_code_with_result(calls: &[NestedApproval], root_succeeds: bool) -> Bytecode {
        let mut code = vec![0x36]; // CALLDATASIZE.
        let child_patch = push_label(&mut code);
        code.push(0x57); // JUMPI.

        for call in calls {
            // Store the scope and return-data length as two calldata words.
            push_word(&mut code, U256::from(call.scope));
            code.extend_from_slice(&[0x5f, 0x52]); // MSTORE(0, scope).
            push_word(&mut code, call.length);
            code.extend_from_slice(&[0x60, 0x20, 0x52]); // MSTORE(32, length).

            // CALL(gas=30_000, target, value=0, in=[0, 64], out=[]).
            code.extend_from_slice(&[0x5f, 0x5f, 0x60, 0x40, 0x5f, 0x5f]);
            if let Some(target) = call.target {
                code.push(0x73);
                code.extend_from_slice(target.as_slice());
            } else {
                code.push(0x30); // ADDRESS.
            }
            code.extend_from_slice(&[0x61, 0x75, 0x30, 0xf1]);

            if !call.succeeds {
                code.push(0x15); // ISZERO.
            }
            let success_patch = push_label(&mut code);
            code.push(0x57); // JUMPI.
            code.extend_from_slice(&[0x5f, 0x5f, 0xfd]); // Unexpected result: REVERT(0, 0).
            let success = code.len();
            code.push(0x5b); // JUMPDEST.
            patch_label(&mut code, success_patch, success);
        }
        if root_succeeds {
            code.push(0x00); // STOP.
        } else {
            code.extend_from_slice(&[0x5f, 0x5f, 0xfd]); // REVERT(0, 0).
        }

        let child = code.len();
        code.push(0x5b); // JUMPDEST.
        code.extend_from_slice(&[
            0x5f, 0x35, // CALLDATALOAD(0): scope.
            0x60, 0x20, 0x35, // CALLDATALOAD(32): length.
            0x5f, // offset = 0.
            0xaa, // APPROVE.
        ]);
        patch_label(&mut code, child_patch, child);
        Bytecode::new_raw(code.into())
    }

    fn create_then_approve_code(create_opcode: u8) -> Bytecode {
        let mut code = vec![
            0x5f, 0x35, // CALLDATALOAD(0).
            0x60, 0x01, 0x14, // EQ(scope, APPROVE_PAYMENT).
        ];
        let create_patch = push_label(&mut code);
        code.push(0x57); // JUMPI.

        let approve = code.len();
        code.push(0x5b); // JUMPDEST.
        code.extend_from_slice(&[0x5f, 0x35, 0x5f, 0x5f, 0xaa]);

        let create = code.len();
        code.push(0x5b); // JUMPDEST.
        let arguments = if create_opcode == 0xf0 { 3 } else { 4 };
        code.extend(std::iter::repeat_n(0x5f, arguments));
        code.extend_from_slice(&[create_opcode, 0x50]); // CREATE/CREATE2; POP.
        let approve_patch = push_label(&mut code);
        code.push(0x56); // JUMP.

        patch_label(&mut code, create_patch, create);
        patch_label(&mut code, approve_patch, approve);
        Bytecode::new_raw(code.into())
    }

    fn funded_create_then_approve_code() -> Bytecode {
        let mut code = vec![
            0x5f, 0x35, // CALLDATALOAD(0).
            0x60, 0x01, 0x14, // EQ(scope, APPROVE_PAYMENT).
        ];
        let create_patch = push_label(&mut code);
        code.push(0x57); // JUMPI.

        let approve = code.len();
        code.push(0x5b); // JUMPDEST.
        code.extend_from_slice(&[0x5f, 0x35, 0x5f, 0x5f, 0xaa]);

        let create = code.len();
        code.push(0x5b); // JUMPDEST.
        // Store initcode that returns one STOP byte, then CREATE it with 7 wei.
        code.extend_from_slice(&[
            0x67, 0x60, 0x00, 0x5f, 0x53, 0x60, 0x01, 0x5f, 0xf3, 0x5f, 0x52, 0x60, 0x08, 0x60,
            0x18, 0x60, 0x07, 0xf0, 0x50,
        ]);
        let approve_patch = push_label(&mut code);
        code.push(0x56); // JUMP.

        patch_label(&mut code, create_patch, create);
        patch_label(&mut code, approve_patch, approve);
        Bytecode::new_raw(code.into())
    }

    fn selfdestruct_child_factory_code(beneficiary: Address) -> Bytecode {
        let mut runtime = vec![0x73]; // PUSH20 beneficiary; SELFDESTRUCT.
        runtime.extend_from_slice(beneficiary.as_slice());
        runtime.push(0xff);

        let mut initcode = vec![
            0x60,
            runtime.len() as u8,
            0x60,
            0x0c,
            0x60,
            0x00,
            0x39,
            0x60,
            runtime.len() as u8,
            0x60,
            0x00,
            0xf3,
        ];
        initcode.extend_from_slice(&runtime);

        let mut factory = vec![
            0x60,
            initcode.len() as u8,
            0x60,
            0x0f,
            0x60,
            0x00,
            0x39,
            0x60,
            initcode.len() as u8,
            0x60,
            0x00,
            0x60,
            0x07,
            0xf0,
            0x00,
        ];
        factory.extend_from_slice(&initcode);
        Bytecode::new_raw(factory.into())
    }

    fn approval_frame(target: Address, frame_mode: u8, frame_flags: u8, value: u64) -> Frame {
        Frame {
            mode: frame_mode,
            flags: frame_flags,
            target: Some(target),
            gas_limit: TEST_GAS_LIMIT,
            data: U256::from(value).to_be_bytes::<32>().into(),
            ..Default::default()
        }
    }

    fn empty_approval_frame(target: Address, frame_flags: u8) -> Frame {
        Frame {
            mode: mode::DEFAULT,
            flags: frame_flags,
            target: Some(target),
            gas_limit: 250_000,
            ..Default::default()
        }
    }

    fn approval_tx(sender: Address, nonce: u64, chain_id: u64, frames: Vec<Frame>) -> TxFrame {
        TxFrame {
            chain_id: U256::from(chain_id),
            nonce,
            sender,
            frames,
            max_fee_per_gas: U256::ONE,
            ..Default::default()
        }
    }

    fn atomic_create_with_sponsor_tx(
        sender: Address,
        reverter: Address,
        sponsor: Address,
        chain_id: u64,
    ) -> TxFrame {
        approval_tx(
            sender,
            0,
            chain_id,
            vec![
                approval_frame(
                    sender,
                    mode::DEFAULT,
                    flags::APPROVE_EXECUTION,
                    flags::APPROVE_EXECUTION as u64,
                ),
                approval_frame(
                    sender,
                    mode::SENDER,
                    flags::APPROVE_PAYMENT | flags::ATOMIC_BATCH,
                    flags::APPROVE_PAYMENT as u64,
                ),
                approval_frame(reverter, mode::DEFAULT, 0, 0),
                approval_frame(sponsor, mode::DEFAULT, flags::APPROVE_PAYMENT, 0),
            ],
        )
    }

    fn frame_statuses<H>(outcome: &FrameTxOutcome<H>) -> Vec<u8> {
        outcome.frame_receipts.iter().map(|receipt| receipt.status).collect()
    }

    #[test]
    fn build_context_models_the_legacy_nonce_domain() {
        let tx = TxFrame {
            nonce: 42,
            sender: Address::repeat_byte(0x42),
            frames: vec![Frame::default(), Frame { mode: mode::SENDER, ..Default::default() }],
            ..Default::default()
        };

        let context = build_context(&tx, 0, &[], &[], 0, U256::from(123));

        assert_eq!(context.nonce, 42);
        assert_eq!(context.max_cost, U256::from(123));
        assert_eq!(context.legacy_nonce, 42);
        assert_eq!(context.nonce_keys, [U256::ZERO]);
        assert_eq!(
            context.nonce_keys_hash,
            alloy_primitives::b256!(
                "ada5013122d395ba3c54772283fb069b10426056ef8ca54750cb9bb552a59e7d"
            )
        );
        assert!(context.recent_root_references.is_empty());
        assert_eq!(context.trace, Default::default());
        assert_eq!(context.frames[0].expected_caller, ENTRY_POINT_ADDRESS);
        assert_eq!(context.frames[1].expected_caller, tx.sender);
    }

    #[test]
    fn frame_context_is_restored_after_anvil_execution_error() {
        let _outer_context =
            install_frame_tx_context(FrameTxContext { nonce: 99, ..Default::default() });
        let mut evm = EthEvmBuilder::new(InMemoryDB::default(), EvmEnv::default())
            .activate_inspector(AnvilInspector::default())
            .build();
        let tx = TxFrame {
            chain_id: U256::from(evm.chain_id()),
            frames: vec![Frame { gas_limit: 30_000, ..Default::default() }],
            ..Default::default()
        };

        let result = execute_frame_tx(&mut evm, &tx);

        assert!(matches!(result, Err(FrameExecutionError::NoPayer)));
        assert_eq!(frame_tx_context().unwrap().nonce, 99);
        assert!(!evm.is_frame_transaction_active());
        assert!(evm.ctx().journal().evm_state().is_empty());
        assert!(evm.ctx().journal().logs().is_empty());
    }

    #[test]
    fn outer_nonce_must_match_before_any_frame_executes() {
        let sender = Address::repeat_byte(0x44);
        for tx_nonce in [6, 8] {
            let mut evm = test_evm([(
                sender,
                U256::MAX,
                7,
                approver_code(flags::APPROVE_EXECUTION_PAYMENT, false),
            )]);
            let tx = approval_tx(
                sender,
                tx_nonce,
                evm.chain_id(),
                vec![approval_frame(sender, mode::DEFAULT, flags::APPROVE_EXECUTION_PAYMENT, 0)],
            );

            let err = execute_frame_tx(&mut evm, &tx).unwrap_err();

            assert!(matches!(
                err,
                FrameExecutionError::NonceMismatch { tx, state: 7 } if tx == tx_nonce
            ));
            assert!(!evm.is_frame_transaction_active());
            assert!(evm.ctx().journal().evm_state().is_empty());
            assert!(evm.ctx().journal().logs().is_empty());
        }
    }

    #[test]
    fn scalar_frame_gas_rejects_amsterdam_state_gas() {
        let sender = Address::repeat_byte(0x48);
        let mut evm = test_evm([(
            sender,
            U256::MAX,
            0,
            approver_code(flags::APPROVE_EXECUTION_PAYMENT, false),
        )]);
        evm.ctx_mut().cfg.set_spec_and_mainnet_gas_params(SpecId::AMSTERDAM);
        let tx = approval_tx(
            sender,
            0,
            evm.chain_id(),
            vec![approval_frame(sender, mode::DEFAULT, flags::APPROVE_EXECUTION_PAYMENT, 0)],
        );

        assert!(matches!(
            execute_frame_tx(&mut evm, &tx),
            Err(FrameExecutionError::StateGasUnsupported)
        ));
        assert!(!evm.is_frame_transaction_active());
    }

    #[test]
    fn canonical_expiry_verifier_accepts_current_time_and_rejects_expired_time() {
        let sender = Address::repeat_byte(0x45);
        let accounts = [
            (sender, U256::MAX, 0, approver_code(flags::APPROVE_EXECUTION_PAYMENT, false)),
            (
                EXPIRY_VERIFIER_ADDRESS,
                U256::ZERO,
                1,
                Bytecode::new_raw(EXPIRY_VERIFIER_RUNTIME_CODE.to_vec().into()),
            ),
        ];
        let frames = |expiry: u64| {
            vec![
                approval_frame(sender, mode::DEFAULT, flags::APPROVE_EXECUTION_PAYMENT, 0),
                Frame {
                    mode: mode::VERIFY,
                    target: Some(EXPIRY_VERIFIER_ADDRESS),
                    gas_limit: TEST_GAS_LIMIT,
                    data: expiry.to_be_bytes().to_vec().into(),
                    ..Default::default()
                },
            ]
        };

        let mut valid = test_evm(accounts.clone());
        valid.ctx_mut().block.timestamp = U256::from(100);
        let valid_chain_id = valid.chain_id();
        let outcome =
            execute_frame_tx(&mut valid, &approval_tx(sender, 0, valid_chain_id, frames(100)))
                .unwrap();
        assert_eq!(frame_statuses(&outcome), [STATUS_SUCCESS, STATUS_SUCCESS]);

        let mut expired = test_evm(accounts);
        expired.ctx_mut().block.timestamp = U256::from(100);
        let expired_chain_id = expired.chain_id();
        let err =
            execute_frame_tx(&mut expired, &approval_tx(sender, 0, expired_chain_id, frames(99)))
                .unwrap_err();
        assert!(matches!(err, FrameExecutionError::VerifyFailed { index: 1 }));
        assert!(!expired.is_frame_transaction_active());
        assert!(expired.ctx().journal().evm_state().is_empty());
    }

    #[test]
    fn trace_keeps_every_top_level_frame_under_one_transaction_root() {
        let sender = Address::repeat_byte(0x46);
        let target = Address::repeat_byte(0x47);
        let mut evm = test_evm([
            (sender, U256::MAX, 0, approver_code(flags::APPROVE_EXECUTION_PAYMENT, false)),
            (target, U256::ZERO, 0, Bytecode::new_raw(vec![0x00].into())),
        ]);
        *evm.inspector_mut() = AnvilInspector::default().with_tracing();
        let tx = approval_tx(
            sender,
            0,
            evm.chain_id(),
            vec![
                approval_frame(sender, mode::DEFAULT, flags::APPROVE_EXECUTION_PAYMENT, 0),
                approval_frame(target, mode::DEFAULT, 0, 0),
            ],
        );

        execute_frame_tx(&mut evm, &tx).unwrap();

        let nodes = evm.inspector().tracer.as_ref().unwrap().traces().nodes();
        assert_eq!(nodes[0].trace.address, sender);
        assert_eq!(nodes[0].trace.depth, 0);
        assert_eq!(nodes[0].children, [1, 2]);
        assert_eq!(nodes[1].trace.address, sender);
        assert_eq!(nodes[1].trace.depth, 1);
        assert_eq!(nodes[1].parent, Some(0));
        assert_eq!(nodes[2].trace.address, target);
        assert_eq!(nodes[2].trace.depth, 1);
        assert_eq!(nodes[2].parent, Some(0));
    }

    #[test]
    fn composed_raw_tracer_keeps_every_top_level_frame() {
        let sender = Address::repeat_byte(0x49);
        let target = Address::repeat_byte(0x4a);
        let mut db = InMemoryDB::default();
        for (address, balance, code) in [
            (sender, U256::MAX, approver_code(flags::APPROVE_EXECUTION_PAYMENT, false)),
            (target, U256::ZERO, Bytecode::new_raw(vec![0x00].into())),
        ] {
            db.insert_account_info(
                address,
                AccountInfo { balance, ..Default::default() }.with_code(code),
            );
        }
        let mut tracer = TracingInspector::new(TracingInspectorConfig::all().set_steps(false));
        let chain_id;
        {
            let inspector = FrameInspector::new(&mut tracer);
            let mut evm =
                EthEvmBuilder::new(db, EvmEnv::default()).activate_inspector(inspector).build();
            chain_id = evm.chain_id();
            let tx = approval_tx(
                sender,
                0,
                chain_id,
                vec![
                    approval_frame(sender, mode::DEFAULT, flags::APPROVE_EXECUTION_PAYMENT, 0),
                    approval_frame(target, mode::DEFAULT, 0, 0),
                ],
            );
            execute_frame_tx(&mut evm, &tx).unwrap();
        }

        let nodes = tracer.traces().nodes();
        assert_eq!(nodes[0].trace.address, sender);
        assert_eq!(nodes[0].children, [1, 2]);
        assert_eq!(nodes[1].trace.address, sender);
        assert_eq!(nodes[2].trace.address, target);
    }

    #[test]
    fn composed_inspector_outcome_precedes_approval_accounting() {
        #[derive(Default)]
        struct RevertFirstCall(bool);

        impl<CTX> Inspector<CTX, EthInterpreter> for RevertFirstCall {
            fn call_end(
                &mut self,
                _ecx: &mut CTX,
                _inputs: &CallInputs,
                outcome: &mut CallOutcome,
            ) {
                if !self.0 {
                    outcome.result.result = InstructionResult::Revert;
                    self.0 = true;
                }
            }
        }

        let sender = Address::repeat_byte(0x4b);
        let initial_balance = U256::MAX;
        let mut db = InMemoryDB::default();
        db.insert_account_info(
            sender,
            AccountInfo { balance: initial_balance, ..Default::default() }
                .with_code(approver_code(flags::APPROVE_EXECUTION_PAYMENT, false)),
        );
        let mut mutator = RevertFirstCall::default();
        let inspector = FrameInspector::new(&mut mutator);
        let mut evm =
            EthEvmBuilder::new(db, EvmEnv::default()).activate_inspector(inspector).build();
        let tx = approval_tx(
            sender,
            0,
            evm.chain_id(),
            vec![approval_frame(sender, mode::DEFAULT, flags::APPROVE_EXECUTION_PAYMENT, 0)],
        );

        assert!(matches!(execute_frame_tx(&mut evm, &tx), Err(FrameExecutionError::NoPayer)));
        let account = evm.db_mut().basic(sender).unwrap().unwrap();
        assert_eq!(account.balance, initial_balance);
        assert_eq!(account.nonce, 0);
    }

    #[test]
    fn frame_target_warmth_persists_only_after_success() {
        let sender = Address::repeat_byte(0x10);
        let retained_warm = Address::repeat_byte(0x20);
        let reverted_warm = Address::repeat_byte(0x30);
        let cold_oog = Address::repeat_byte(0x40);
        let mut evm = test_evm([
            (sender, U256::MAX, 0, approver_code(flags::APPROVE_EXECUTION_PAYMENT, false)),
            (retained_warm, U256::ZERO, 0, Bytecode::new_raw(vec![0x00].into())),
            (reverted_warm, U256::ZERO, 0, reverter_code()),
            (cold_oog, U256::ZERO, 0, Bytecode::new_raw(vec![0x00].into())),
        ]);
        let tx = approval_tx(
            sender,
            0,
            evm.chain_id(),
            vec![
                approval_frame(sender, mode::DEFAULT, flags::APPROVE_EXECUTION_PAYMENT, 0),
                Frame {
                    mode: mode::DEFAULT,
                    target: Some(retained_warm),
                    gas_limit: 2_600,
                    ..Default::default()
                },
                Frame {
                    mode: mode::DEFAULT,
                    target: Some(retained_warm),
                    gas_limit: 100,
                    ..Default::default()
                },
                Frame {
                    mode: mode::DEFAULT,
                    target: Some(reverted_warm),
                    gas_limit: 2_604,
                    ..Default::default()
                },
                Frame {
                    mode: mode::DEFAULT,
                    target: Some(reverted_warm),
                    gas_limit: 2_604,
                    ..Default::default()
                },
                Frame {
                    mode: mode::DEFAULT,
                    target: Some(cold_oog),
                    gas_limit: 2_599,
                    ..Default::default()
                },
            ],
        );

        let outcome = execute_frame_tx(&mut evm, &tx).unwrap();

        assert_eq!(
            frame_statuses(&outcome),
            [
                STATUS_SUCCESS,
                STATUS_SUCCESS,
                STATUS_SUCCESS,
                STATUS_FAILED,
                STATUS_FAILED,
                STATUS_FAILED,
            ]
        );
        assert_eq!(outcome.frame_receipts[1].execution_gas_used, 2_600);
        assert_eq!(outcome.frame_receipts[2].execution_gas_used, 100);
        assert_eq!(outcome.frame_receipts[3].execution_gas_used, 2_604);
        assert_eq!(outcome.frame_receipts[4].execution_gas_used, 2_604);
        assert_eq!(outcome.frame_receipts[5].execution_gas_used, 2_599);
    }

    #[test]
    fn atomic_rollback_restores_target_coldness() {
        let sender = Address::repeat_byte(0x05);
        let target = Address::repeat_byte(0x06);
        let reverter = Address::repeat_byte(0x07);
        let mut evm = test_evm([
            (sender, U256::MAX, 0, approver_code(flags::APPROVE_EXECUTION_PAYMENT, false)),
            (target, U256::ZERO, 0, Bytecode::new_raw(vec![0x00].into())),
            (reverter, U256::ZERO, 0, reverter_code()),
        ]);
        let tx = approval_tx(
            sender,
            0,
            evm.chain_id(),
            vec![
                approval_frame(sender, mode::DEFAULT, flags::APPROVE_EXECUTION_PAYMENT, 0),
                Frame {
                    mode: mode::DEFAULT,
                    flags: flags::ATOMIC_BATCH,
                    target: Some(target),
                    gas_limit: 2_600,
                    ..Default::default()
                },
                approval_frame(reverter, mode::DEFAULT, 0, 0),
                Frame {
                    mode: mode::DEFAULT,
                    target: Some(target),
                    gas_limit: 2_600,
                    ..Default::default()
                },
            ],
        );

        let outcome = execute_frame_tx(&mut evm, &tx).unwrap();

        assert_eq!(
            frame_statuses(&outcome),
            [STATUS_SUCCESS, STATUS_SUCCESS, STATUS_FAILED, STATUS_SUCCESS]
        );
        assert_eq!(outcome.frame_receipts[1].execution_gas_used, 2_600);
        assert_eq!(outcome.frame_receipts[3].execution_gas_used, 2_600);
    }

    /// A value transfer to a missing account charges the frame's state budget
    /// and every value frame to a non-sender target emits the EIP-7708 log.
    #[test]
    fn value_frame_state_gas_and_transfer_log() {
        let sender = Address::repeat_byte(0x31);
        let fresh = Address::repeat_byte(0x32);
        let existing = Address::repeat_byte(0x33);
        let mut evm = test_evm([
            (sender, U256::MAX, 0, approver_code(flags::APPROVE_EXECUTION_PAYMENT, false)),
            (existing, U256::ONE, 0, Bytecode::default()),
        ]);
        let tx = approval_tx(
            sender,
            0,
            evm.chain_id(),
            vec![
                approval_frame(sender, mode::DEFAULT, flags::APPROVE_EXECUTION_PAYMENT, 0),
                Frame {
                    mode: mode::SENDER,
                    target: Some(fresh),
                    gas_limit: 30_000,
                    state_gas_limit: frame_gas::NEW_ACCOUNT_STATE_GAS,
                    value: U256::from(5u64),
                    ..Default::default()
                },
                Frame {
                    mode: mode::SENDER,
                    target: Some(existing),
                    gas_limit: 30_000,
                    value: U256::from(5u64),
                    ..Default::default()
                },
            ],
        );

        let outcome = execute_frame_tx(&mut evm, &tx).unwrap();

        assert_eq!(frame_statuses(&outcome), [STATUS_SUCCESS, STATUS_SUCCESS, STATUS_SUCCESS]);
        // Creating `fresh` cost the account-creation state gas; the transfer to
        // the existing account cost none.
        assert_eq!(outcome.frame_receipts[1].state_gas_used, frame_gas::NEW_ACCOUNT_STATE_GAS);
        assert_eq!(outcome.frame_receipts[2].state_gas_used, 0);
        // Both value frames emit the EIP-7708 transfer log first.
        for (receipt, to) in
            [(&outcome.frame_receipts[1], fresh), (&outcome.frame_receipts[2], existing)]
        {
            let log = receipt.logs.first().expect("transfer log");
            assert_eq!(log.address, SYSTEM_ADDRESS);
            assert_eq!(log.topics()[0], TRANSFER_TOPIC);
            assert_eq!(log.topics()[1], sender.into_word());
            assert_eq!(log.topics()[2], to.into_word());
        }
        // The transaction-level logs include the synthesized transfer logs.
        assert_eq!(outcome.result.result.logs().len(), 2);
    }

    /// The account-creation charge exceeding the frame's state budget is an
    /// exceptional halt: the execution pool is consumed and no state is used.
    #[test]
    fn value_frame_without_state_budget_halts() {
        let sender = Address::repeat_byte(0x34);
        let fresh = Address::repeat_byte(0x35);
        let mut evm = test_evm([(
            sender,
            U256::MAX,
            0,
            approver_code(flags::APPROVE_EXECUTION_PAYMENT, false),
        )]);
        let tx = approval_tx(
            sender,
            0,
            evm.chain_id(),
            vec![
                approval_frame(sender, mode::DEFAULT, flags::APPROVE_EXECUTION_PAYMENT, 0),
                Frame {
                    mode: mode::SENDER,
                    target: Some(fresh),
                    gas_limit: 30_000,
                    state_gas_limit: frame_gas::NEW_ACCOUNT_STATE_GAS - 1,
                    value: U256::from(5u64),
                    ..Default::default()
                },
            ],
        );

        let outcome = execute_frame_tx(&mut evm, &tx).unwrap();

        assert_eq!(frame_statuses(&outcome), [STATUS_SUCCESS, STATUS_FAILED]);
        let halted = &outcome.frame_receipts[1];
        assert_eq!(halted.execution_gas_used, 30_000);
        assert_eq!(halted.state_gas_used, 0);
        assert!(halted.logs.is_empty());
    }

    #[test]
    fn default_code_approval_and_settlement_remain_journaled_until_executor_commit() {
        let sender = Address::repeat_byte(0x09);
        let initial_balance = U256::MAX;
        let mut evm = test_evm([(sender, initial_balance, 0, Bytecode::default())]);
        evm.ctx_mut().block.basefee = 1;
        let mut tx = approval_tx(
            sender,
            0,
            evm.chain_id(),
            vec![Frame {
                mode: mode::VERIFY,
                flags: flags::APPROVE_EXECUTION_PAYMENT,
                target: Some(sender),
                gas_limit: TEST_GAS_LIMIT,
                ..Default::default()
            }],
        );
        tx.signatures = vec![foundry_primitives::FrameSignature {
            scheme: foundry_primitives::scheme::SECP256K1,
            ..Default::default()
        }];

        let outcome = execute_frame_tx(&mut evm, &tx).unwrap();

        let database_sender = evm.db_mut().basic(sender).unwrap().unwrap();
        assert_eq!(database_sender.nonce, 0);
        assert_eq!(database_sender.balance, initial_balance);
        assert_eq!(outcome.result.state[&sender].info.nonce, 1);
        assert!(outcome.result.state[&sender].info.balance < initial_balance);

        evm.db_mut().commit(outcome.result.state.clone());
        assert_eq!(evm.db_mut().basic(sender).unwrap().unwrap().nonce, 1);
    }

    #[test]
    fn storage_original_and_refund_are_preserved_across_frames() {
        let sender = Address::repeat_byte(0x0a);
        let writer = Address::repeat_byte(0x0b);
        let writer_code = Bytecode::new_raw(vec![0x5f, 0x35, 0x5f, 0x55, 0x00].into());
        let mut evm = test_evm([
            (sender, U256::MAX, 0, approver_code(flags::APPROVE_EXECUTION_PAYMENT, false)),
            (writer, U256::ZERO, 0, writer_code),
        ]);
        evm.db_mut().insert_account_storage(writer, U256::ZERO, U256::ONE).unwrap();
        let tx = approval_tx(
            sender,
            0,
            evm.chain_id(),
            vec![
                approval_frame(sender, mode::DEFAULT, flags::APPROVE_EXECUTION_PAYMENT, 0),
                approval_frame(writer, mode::DEFAULT, 0, 0),
                approval_frame(writer, mode::DEFAULT, 0, 1),
            ],
        );

        let outcome = execute_and_commit(&mut evm, &tx).unwrap();

        assert_eq!(outcome.result.result.gas().inner_refunded(), 2_800);
        assert_eq!(evm.db_mut().storage(writer, U256::ZERO).unwrap(), U256::ONE);
    }

    #[test]
    fn transient_storage_is_cleared_between_frames() {
        let sender = Address::repeat_byte(0x0c);
        let target = Address::repeat_byte(0x0d);
        // Non-empty calldata stores 1 in transient slot 0. Empty calldata reads
        // that slot and persists it to storage slot 0.
        let code = Bytecode::new_raw(
            vec![
                0x36, 0x60, 0x0b, 0x57, 0x60, 0x00, 0x5c, 0x60, 0x00, 0x55, 0x00, 0x5b, 0x60, 0x01,
                0x60, 0x00, 0x5d, 0x00,
            ]
            .into(),
        );
        let mut evm = test_evm([
            (sender, U256::MAX, 0, approver_code(flags::APPROVE_EXECUTION_PAYMENT, false)),
            (target, U256::ZERO, 0, code),
        ]);
        let tx = approval_tx(
            sender,
            0,
            evm.chain_id(),
            vec![
                approval_frame(sender, mode::DEFAULT, flags::APPROVE_EXECUTION_PAYMENT, 0),
                Frame {
                    mode: mode::DEFAULT,
                    target: Some(target),
                    gas_limit: TEST_GAS_LIMIT,
                    data: vec![1].into(),
                    ..Default::default()
                },
                Frame {
                    mode: mode::DEFAULT,
                    target: Some(target),
                    gas_limit: TEST_GAS_LIMIT,
                    ..Default::default()
                },
            ],
        );

        execute_and_commit(&mut evm, &tx).unwrap();

        assert_eq!(evm.db_mut().storage(target, U256::ZERO).unwrap(), U256::ZERO);
    }

    #[test]
    fn verify_frames_are_static_while_default_and_approve_remain_available() {
        let sender = Address::repeat_byte(0x11);

        let mut verify = test_evm([(
            sender,
            U256::MAX,
            0,
            approver_code(flags::APPROVE_EXECUTION_PAYMENT, true),
        )]);
        let tx = approval_tx(
            sender,
            0,
            verify.chain_id(),
            vec![approval_frame(sender, mode::VERIFY, flags::APPROVE_EXECUTION_PAYMENT, 1)],
        );
        assert!(matches!(
            execute_frame_tx(&mut verify, &tx),
            Err(FrameExecutionError::VerifyFailed { index: 0 })
        ));
        assert_eq!(verify.db_mut().storage(sender, U256::ZERO).unwrap(), U256::ZERO);

        let mut default = test_evm([(
            sender,
            U256::MAX,
            0,
            approver_code(flags::APPROVE_EXECUTION_PAYMENT, true),
        )]);
        let tx = approval_tx(
            sender,
            0,
            default.chain_id(),
            vec![approval_frame(sender, mode::DEFAULT, flags::APPROVE_EXECUTION_PAYMENT, 1)],
        );
        let outcome = execute_and_commit(&mut default, &tx).unwrap();
        assert_eq!(frame_statuses(&outcome), [STATUS_SUCCESS]);
        assert_eq!(default.db_mut().storage(sender, U256::ZERO).unwrap(), U256::ONE);

        let mut approve_only = test_evm([(
            sender,
            U256::MAX,
            0,
            approver_code(flags::APPROVE_EXECUTION_PAYMENT, false),
        )]);
        let tx = approval_tx(
            sender,
            0,
            approve_only.chain_id(),
            vec![approval_frame(sender, mode::VERIFY, flags::APPROVE_EXECUTION_PAYMENT, 0)],
        );
        assert_eq!(
            frame_statuses(&execute_frame_tx(&mut approve_only, &tx).unwrap()),
            [STATUS_SUCCESS]
        );
    }

    #[test]
    fn nested_self_calls_apply_each_approval_at_its_opcode_boundary() {
        let sender = Address::repeat_byte(0x12);
        let code = nested_approver_code(&[
            NestedApproval {
                target: None,
                scope: flags::APPROVE_EXECUTION,
                length: U256::ZERO,
                succeeds: true,
            },
            NestedApproval {
                target: None,
                scope: flags::APPROVE_PAYMENT,
                length: U256::ZERO,
                succeeds: true,
            },
        ]);
        let mut evm = test_evm([(sender, U256::MAX, 0, code)]);
        let tx = approval_tx(
            sender,
            0,
            evm.chain_id(),
            vec![empty_approval_frame(sender, flags::APPROVE_EXECUTION_PAYMENT)],
        );

        let outcome = execute_and_commit(&mut evm, &tx).unwrap();

        assert_eq!(frame_statuses(&outcome), [STATUS_SUCCESS]);
        assert_eq!(outcome.payer, sender);
        assert_eq!(evm.db_mut().basic(sender).unwrap().unwrap().nonce, 1);
    }

    #[test]
    fn caught_nested_duplicate_approval_reverts_only_that_call() {
        let sender = Address::repeat_byte(0x13);
        let code = nested_approver_code(&[
            NestedApproval {
                target: None,
                scope: flags::APPROVE_EXECUTION_PAYMENT,
                length: U256::ZERO,
                succeeds: true,
            },
            NestedApproval {
                target: None,
                scope: flags::APPROVE_EXECUTION_PAYMENT,
                length: U256::ZERO,
                succeeds: false,
            },
        ]);
        let mut evm = test_evm([(sender, U256::MAX, 0, code)]);
        let tx = approval_tx(
            sender,
            0,
            evm.chain_id(),
            vec![empty_approval_frame(sender, flags::APPROVE_EXECUTION_PAYMENT)],
        );

        let outcome = execute_and_commit(&mut evm, &tx).unwrap();

        assert_eq!(frame_statuses(&outcome), [STATUS_SUCCESS]);
        assert_eq!(evm.db_mut().basic(sender).unwrap().unwrap().nonce, 1);
    }

    #[test]
    fn rejected_duplicate_approval_still_charges_return_memory_expansion() {
        fn gas_used(length: U256) -> u64 {
            let sender = Address::repeat_byte(0x13);
            let code = nested_approver_code(&[
                NestedApproval {
                    target: None,
                    scope: flags::APPROVE_EXECUTION_PAYMENT,
                    length: U256::ZERO,
                    succeeds: true,
                },
                NestedApproval {
                    target: None,
                    scope: flags::APPROVE_EXECUTION_PAYMENT,
                    length,
                    succeeds: false,
                },
            ]);
            let mut evm = test_evm([(sender, U256::MAX, 0, code)]);
            let tx = approval_tx(
                sender,
                0,
                evm.chain_id(),
                vec![empty_approval_frame(sender, flags::APPROVE_EXECUTION_PAYMENT)],
            );
            execute_and_commit(&mut evm, &tx).unwrap().frame_receipts[0].execution_gas_used
        }

        // C_mem(256 words) - C_mem(1 word) = (3*256 + 256^2/512) - 3.
        assert_eq!(gas_used(U256::from(8192)) - gas_used(U256::from(32)), 893);
    }

    #[test]
    fn enclosing_revert_discards_nested_approval_and_precharge() {
        let sender = Address::repeat_byte(0x24);
        let code = nested_approver_code_with_result(
            &[NestedApproval {
                target: None,
                scope: flags::APPROVE_EXECUTION_PAYMENT,
                length: U256::ZERO,
                succeeds: true,
            }],
            false,
        );
        let initial_balance = U256::MAX;
        let mut evm = test_evm([(sender, initial_balance, 0, code)]);
        let tx = approval_tx(
            sender,
            0,
            evm.chain_id(),
            vec![empty_approval_frame(sender, flags::APPROVE_EXECUTION_PAYMENT)],
        );

        assert!(matches!(execute_frame_tx(&mut evm, &tx), Err(FrameExecutionError::NoPayer)));
        let sender = evm.db_mut().basic(sender).unwrap().unwrap();
        assert_eq!(sender.nonce, 0);
        assert_eq!(sender.balance, initial_balance);
    }

    #[test]
    fn caught_foreign_approval_reverts_and_is_not_recorded() {
        let sender = Address::repeat_byte(0x14);
        let foreign = Address::repeat_byte(0x15);
        let code = nested_approver_code(&[
            NestedApproval {
                target: Some(foreign),
                scope: flags::APPROVE_EXECUTION,
                length: U256::ZERO,
                succeeds: false,
            },
            NestedApproval {
                target: None,
                scope: flags::APPROVE_EXECUTION_PAYMENT,
                length: U256::ZERO,
                succeeds: true,
            },
        ]);
        let mut evm = test_evm([
            (sender, U256::MAX, 0, code),
            (foreign, U256::ZERO, 0, approver_code(flags::APPROVE_EXECUTION, false)),
        ]);
        let tx = approval_tx(
            sender,
            0,
            evm.chain_id(),
            vec![empty_approval_frame(sender, flags::APPROVE_EXECUTION_PAYMENT)],
        );

        let outcome = execute_and_commit(&mut evm, &tx).unwrap();

        assert_eq!(frame_statuses(&outcome), [STATUS_SUCCESS]);
        assert_eq!(outcome.payer, sender);
    }

    #[test]
    fn caught_oog_approval_is_not_recorded() {
        let sender = Address::repeat_byte(0x16);
        let code = nested_approver_code(&[
            NestedApproval {
                target: None,
                scope: flags::APPROVE_EXECUTION,
                length: U256::MAX,
                succeeds: false,
            },
            NestedApproval {
                target: None,
                scope: flags::APPROVE_PAYMENT,
                length: U256::ZERO,
                succeeds: false,
            },
            NestedApproval {
                target: None,
                scope: flags::APPROVE_EXECUTION_PAYMENT,
                length: U256::ZERO,
                succeeds: true,
            },
        ]);
        let mut evm = test_evm([(sender, U256::MAX, 0, code)]);
        let tx = approval_tx(
            sender,
            0,
            evm.chain_id(),
            vec![empty_approval_frame(sender, flags::APPROVE_EXECUTION_PAYMENT)],
        );

        let outcome = execute_and_commit(&mut evm, &tx).unwrap();

        assert_eq!(frame_statuses(&outcome), [STATUS_SUCCESS]);
        assert_eq!(evm.db_mut().basic(sender).unwrap().unwrap().nonce, 1);
    }

    #[test]
    fn atomic_rollback_restores_approval_precharge_and_nonce() {
        let sender = Address::repeat_byte(0x17);
        let reverter = Address::repeat_byte(0x18);
        let mut evm = test_evm([
            (sender, U256::MAX, 0, approver_code(flags::APPROVE_EXECUTION_PAYMENT, false)),
            (reverter, U256::ZERO, 0, reverter_code()),
        ]);
        let tx = approval_tx(
            sender,
            0,
            evm.chain_id(),
            vec![
                approval_frame(
                    sender,
                    mode::DEFAULT,
                    flags::APPROVE_EXECUTION_PAYMENT | flags::ATOMIC_BATCH,
                    0,
                ),
                approval_frame(reverter, mode::DEFAULT, 0, 0),
                approval_frame(sender, mode::DEFAULT, flags::APPROVE_EXECUTION_PAYMENT, 0),
            ],
        );

        let outcome = execute_and_commit(&mut evm, &tx).unwrap();

        assert_eq!(frame_statuses(&outcome), [STATUS_SUCCESS, STATUS_FAILED, STATUS_SUCCESS]);
        assert_eq!(outcome.payer, sender);
        assert_eq!(evm.db_mut().basic(sender).unwrap().unwrap().nonce, 1);
    }

    #[test]
    fn atomic_rollback_discards_transaction_refund_counter() {
        let sender = Address::repeat_byte(0x19);
        let clearer = Address::repeat_byte(0x1a);
        let reverter = Address::repeat_byte(0x1b);
        let clearer_code = Bytecode::new_raw(vec![0x5f, 0x5f, 0x55, 0x00].into());
        let accounts = [
            (sender, U256::MAX, 0, approver_code(flags::APPROVE_EXECUTION_PAYMENT, false)),
            (clearer, U256::ZERO, 0, clearer_code.clone()),
            (reverter, U256::ZERO, 0, reverter_code()),
        ];

        let mut committed = test_evm(accounts.clone());
        committed.db_mut().insert_account_storage(clearer, U256::ZERO, U256::ONE).unwrap();
        let committed_tx = approval_tx(
            sender,
            0,
            committed.chain_id(),
            vec![
                approval_frame(sender, mode::DEFAULT, flags::APPROVE_EXECUTION_PAYMENT, 0),
                approval_frame(clearer, mode::DEFAULT, 0, 0),
            ],
        );
        let committed_outcome = execute_frame_tx(&mut committed, &committed_tx).unwrap();
        assert!(committed_outcome.result.result.gas().inner_refunded() > 0);

        let mut rolled_back = test_evm(accounts);
        rolled_back.db_mut().insert_account_storage(clearer, U256::ZERO, U256::ONE).unwrap();
        let rolled_back_tx = approval_tx(
            sender,
            0,
            rolled_back.chain_id(),
            vec![
                approval_frame(sender, mode::DEFAULT, flags::APPROVE_EXECUTION_PAYMENT, 0),
                approval_frame(clearer, mode::DEFAULT, flags::ATOMIC_BATCH, 0),
                approval_frame(reverter, mode::DEFAULT, 0, 0),
            ],
        );
        let rolled_back_outcome = execute_and_commit(&mut rolled_back, &rolled_back_tx).unwrap();

        assert_eq!(rolled_back_outcome.result.result.gas().inner_refunded(), 0);
        assert_eq!(rolled_back.db_mut().storage(clearer, U256::ZERO).unwrap(), U256::ONE);
    }

    #[test]
    fn atomic_rollback_discards_canonical_logs() {
        let sender = Address::repeat_byte(0x1c);
        let logger = Address::repeat_byte(0x1d);
        let reverter = Address::repeat_byte(0x1e);
        let sponsor = Address::repeat_byte(0x1f);
        let log_code = Bytecode::new_raw(vec![0x5f, 0x5f, 0xa0, 0x00].into());
        let mut evm = test_evm([
            (sender, U256::MAX, 0, approver_code(flags::APPROVE_EXECUTION, false)),
            (logger, U256::ZERO, 0, log_code),
            (reverter, U256::ZERO, 0, reverter_code()),
            (sponsor, U256::MAX, 0, approver_code(flags::APPROVE_PAYMENT, false)),
        ]);
        let tx = approval_tx(
            sender,
            0,
            evm.chain_id(),
            vec![
                approval_frame(
                    sender,
                    mode::DEFAULT,
                    flags::APPROVE_EXECUTION,
                    flags::APPROVE_EXECUTION as u64,
                ),
                approval_frame(logger, mode::DEFAULT, flags::ATOMIC_BATCH, 0),
                approval_frame(reverter, mode::DEFAULT, 0, 0),
                approval_frame(
                    sponsor,
                    mode::DEFAULT,
                    flags::APPROVE_PAYMENT,
                    flags::APPROVE_PAYMENT as u64,
                ),
            ],
        );

        let outcome = execute_frame_tx(&mut evm, &tx).unwrap();

        assert_eq!(
            frame_statuses(&outcome),
            [STATUS_SUCCESS, STATUS_SUCCESS, STATUS_FAILED, STATUS_SUCCESS]
        );
        assert!(outcome.result.result.logs().is_empty());
        assert!(outcome.frame_receipts.iter().all(|receipt| receipt.logs.is_empty()));
    }

    #[test]
    fn invalid_default_verify_cannot_be_rescued_by_a_later_payer() {
        let sender = Address::repeat_byte(0x1c);
        let empty = Address::repeat_byte(0x1d);
        let mut evm = test_evm([
            (sender, U256::MAX, 0, approver_code(flags::APPROVE_EXECUTION_PAYMENT, false)),
            (empty, U256::MAX, 0, Bytecode::default()),
        ]);
        let tx = approval_tx(
            sender,
            0,
            evm.chain_id(),
            vec![
                approval_frame(empty, mode::VERIFY, flags::APPROVE_PAYMENT, 0),
                approval_frame(sender, mode::DEFAULT, flags::APPROVE_EXECUTION_PAYMENT, 0),
            ],
        );

        assert!(matches!(
            execute_frame_tx(&mut evm, &tx),
            Err(FrameExecutionError::VerifyFailed { index: 0 })
        ));
        assert_eq!(evm.db_mut().basic(sender).unwrap().unwrap().nonce, 0);
    }

    #[test]
    fn settlement_charges_blob_base_fee_without_refunding_it() {
        let sender = Address::repeat_byte(0x1e);
        let blob_base_fee = U256::from(7);
        let mut tx = approval_tx(
            sender,
            0,
            1,
            vec![approval_frame(sender, mode::DEFAULT, flags::APPROVE_EXECUTION_PAYMENT, 0)],
        );
        tx.max_fee_per_blob_gas = U256::from(100);
        tx.blob_versioned_hashes = vec![B256::repeat_byte(0x01)];
        let initial_balance = max_cost(&tx, blob_base_fee).unwrap();
        let mut evm = test_evm([(
            sender,
            initial_balance,
            0,
            approver_code(flags::APPROVE_EXECUTION_PAYMENT, false),
        )]);
        tx.chain_id = U256::from(evm.chain_id());
        evm.ctx_mut().block.basefee = 0;
        evm.ctx_mut().block.blob_excess_gas_and_price =
            Some(BlobExcessGasAndPrice { excess_blob_gas: 0, blob_gasprice: blob_base_fee.to() });

        execute_and_commit(&mut evm, &tx).unwrap();

        let balance = evm.db_mut().basic(sender).unwrap().unwrap().balance;
        assert_eq!(initial_balance - balance, blob_base_fee * U256::from(tx.blob_gas()));
    }

    #[test]
    fn settlement_rejects_charges_above_the_precharged_maximum() {
        let sender = Address::repeat_byte(0x2f);
        let initial_balance = U256::MAX;
        let mut evm = test_evm([(
            sender,
            initial_balance,
            0,
            approver_code(flags::APPROVE_EXECUTION_PAYMENT, false),
        )]);
        evm.ctx_mut().block.basefee = u64::MAX;
        let tx = approval_tx(
            sender,
            0,
            evm.chain_id(),
            vec![approval_frame(sender, mode::DEFAULT, flags::APPROVE_EXECUTION_PAYMENT, 0)],
        );

        assert!(matches!(
            execute_frame_tx(&mut evm, &tx),
            Err(FrameExecutionError::ChargedExceedsMaxCost)
        ));
        assert_eq!(evm.db_mut().basic(sender).unwrap().unwrap().balance, initial_balance);
        assert!(!evm.is_frame_transaction_active());
        assert!(evm.ctx().journal().evm_state().is_empty());
    }

    #[test]
    fn create_and_create2_use_the_pre_frame_sender_nonce() {
        for (name, opcode) in [("CREATE", 0xf0), ("CREATE2", 0xf5)] {
            let sender = Address::repeat_byte(opcode);
            let mut evm = test_evm([(sender, U256::MAX, 0, create_then_approve_code(opcode))]);
            let tx = approval_tx(
                sender,
                0,
                evm.chain_id(),
                vec![
                    approval_frame(
                        sender,
                        mode::DEFAULT,
                        flags::APPROVE_EXECUTION,
                        flags::APPROVE_EXECUTION as u64,
                    ),
                    approval_frame(
                        sender,
                        mode::SENDER,
                        flags::APPROVE_PAYMENT,
                        flags::APPROVE_PAYMENT as u64,
                    ),
                ],
            );

            execute_and_commit(&mut evm, &tx).unwrap();

            let expected = if opcode == 0xf0 {
                sender.create(0)
            } else {
                sender.create2(B256::ZERO, keccak256([]))
            };
            assert!(
                evm.db_mut().basic(expected).unwrap().is_some(),
                "{name} did not use the pre-frame sender nonce"
            );
            if opcode == 0xf0 {
                assert!(
                    evm.db_mut().basic(sender.create(1)).unwrap().is_none(),
                    "CREATE used a synthetic frame-call nonce"
                );
            }
            assert_eq!(
                evm.db_mut().basic(sender).unwrap().unwrap().nonce,
                2,
                "{name} nonce increment was erased"
            );
        }
    }

    #[test]
    fn created_local_survives_until_later_frame_selfdestruct() {
        let sender = Address::repeat_byte(0x7a);
        let factory = Address::repeat_byte(0x7b);
        let beneficiary = Address::repeat_byte(0x7c);
        let factory_nonce = 1;
        let created = factory.create(factory_nonce);
        let mut evm = test_evm([
            (sender, U256::MAX, 0, approver_code(flags::APPROVE_EXECUTION_PAYMENT, false)),
            (factory, U256::from(7), factory_nonce, selfdestruct_child_factory_code(beneficiary)),
        ]);
        let tx = approval_tx(
            sender,
            0,
            evm.chain_id(),
            vec![
                approval_frame(sender, mode::DEFAULT, flags::APPROVE_EXECUTION_PAYMENT, 0),
                Frame {
                    mode: mode::DEFAULT,
                    target: Some(factory),
                    gas_limit: 300_000,
                    ..Default::default()
                },
                Frame {
                    mode: mode::DEFAULT,
                    target: Some(created),
                    gas_limit: TEST_GAS_LIMIT,
                    ..Default::default()
                },
            ],
        );

        let outcome = execute_and_commit(&mut evm, &tx).unwrap();

        assert_eq!(frame_statuses(&outcome), [STATUS_SUCCESS; 3]);
        assert!(
            evm.db_mut().basic(created).unwrap().as_ref().is_none_or(AccountInfo::is_empty),
            "a contract created and destroyed in the outer transaction survived"
        );
        assert_eq!(evm.db_mut().basic(beneficiary).unwrap().unwrap().balance, U256::from(7));
    }

    #[test]
    fn atomic_rollback_deletes_an_account_created_inside_the_batch() {
        let sender = Address::repeat_byte(0x81);
        let reverter = Address::repeat_byte(0x82);
        let sponsor = Address::repeat_byte(0x83);
        let created = sender.create(0);
        let mut evm = state_root_evm([
            (sender, U256::MAX, 0, create_then_approve_code(0xf0)),
            (reverter, U256::ZERO, 0, reverter_code()),
            (sponsor, U256::MAX, 0, approver_code(flags::APPROVE_PAYMENT, false)),
        ]);
        let tx = atomic_create_with_sponsor_tx(sender, reverter, sponsor, evm.chain_id());

        let outcome = execute_and_commit(&mut evm, &tx).unwrap();

        assert_eq!(
            frame_statuses(&outcome),
            [STATUS_SUCCESS, STATUS_SUCCESS, STATUS_FAILED, STATUS_SUCCESS]
        );
        assert!(evm.db_mut().basic(created).unwrap().as_ref().is_none_or(AccountInfo::is_empty));
        assert_eq!(evm.db_mut().basic(sender).unwrap().unwrap().nonce, 1);

        let root = evm.db_mut().maybe_state_root().unwrap();
        let accounts = evm.db_mut().maybe_full_db().unwrap();
        assert_eq!(root, state_root(&accounts), "rolled-back CREATE left state-root residue");
    }

    #[test]
    fn atomic_rollback_preserves_a_prefunded_create_destination() {
        let sender = Address::repeat_byte(0x84);
        let reverter = Address::repeat_byte(0x85);
        let sponsor = Address::repeat_byte(0x86);
        let created = sender.create(0);
        let prefund = U256::from(123);
        let mut evm = state_root_evm([
            (sender, U256::MAX, 0, create_then_approve_code(0xf0)),
            (reverter, U256::ZERO, 0, reverter_code()),
            (sponsor, U256::MAX, 0, approver_code(flags::APPROVE_PAYMENT, false)),
            (created, prefund, 0, Bytecode::default()),
        ]);
        let tx = atomic_create_with_sponsor_tx(sender, reverter, sponsor, evm.chain_id());

        let outcome = execute_and_commit(&mut evm, &tx).unwrap();

        assert_eq!(
            frame_statuses(&outcome),
            [STATUS_SUCCESS, STATUS_SUCCESS, STATUS_FAILED, STATUS_SUCCESS]
        );
        let restored = evm.db_mut().basic(created).unwrap().unwrap();
        assert_eq!(restored.balance, prefund);
        assert_eq!(restored.nonce, 0);
        assert!(restored.is_empty_code_hash());
    }

    #[test]
    fn returned_state_is_the_only_executor_commit_after_atomic_recreation() {
        let sender = Address::repeat_byte(0x87);
        let reverter = Address::repeat_byte(0x88);
        let created = sender.create(0);
        let mut evm = state_root_evm([
            (sender, U256::MAX, 0, funded_create_then_approve_code()),
            (reverter, U256::ZERO, 0, reverter_code()),
        ]);
        let tx = approval_tx(
            sender,
            0,
            evm.chain_id(),
            vec![
                approval_frame(
                    sender,
                    mode::DEFAULT,
                    flags::APPROVE_EXECUTION,
                    flags::APPROVE_EXECUTION as u64,
                ),
                approval_frame(
                    sender,
                    mode::SENDER,
                    flags::APPROVE_PAYMENT | flags::ATOMIC_BATCH,
                    flags::APPROVE_PAYMENT as u64,
                ),
                approval_frame(reverter, mode::DEFAULT, 0, 0),
                approval_frame(
                    sender,
                    mode::SENDER,
                    flags::APPROVE_PAYMENT,
                    flags::APPROVE_PAYMENT as u64,
                ),
            ],
        );

        let outcome = execute_frame_tx(&mut evm, &tx).unwrap();
        assert_eq!(
            frame_statuses(&outcome),
            [STATUS_SUCCESS, STATUS_SUCCESS, STATUS_FAILED, STATUS_SUCCESS]
        );
        assert!(!outcome.result.state[&created].is_selfdestructed());
        assert!(
            evm.db_mut().basic(created).unwrap().as_ref().is_none_or(AccountInfo::is_empty),
            "frame execution committed intermediate state to the database"
        );

        // The block executor applies the outer journal's cumulative diff once.
        evm.db_mut().commit(outcome.result.state.clone());

        let account = evm.db_mut().basic(created).unwrap().unwrap();
        assert_eq!(account.balance, U256::from(7));
        assert_eq!(account.nonce, 1);
        assert_eq!(account.code_hash, keccak256([0u8]));
    }

    #[test]
    fn approval_validation_rejects_every_protocol_invalid_condition() {
        let sender = Address::repeat_byte(0x21);
        let foreign = Address::repeat_byte(0x22);
        let payer = Address::repeat_byte(0x23);
        let mut evm = test_evm([
            (sender, U256::MAX, 0, Bytecode::default()),
            (foreign, U256::MAX, 0, Bytecode::default()),
            (payer, U256::MAX, 0, Bytecode::default()),
        ]);
        let tx = approval_tx(sender, 0, evm.chain_id(), vec![]);
        assert!(evm.begin_frame_transaction(sender));
        let cases = [
            (
                "scope outside flags",
                flags::APPROVE_EXECUTION_PAYMENT as u64,
                flags::APPROVE_PAYMENT,
                sender,
                false,
                None,
            ),
            (
                "duplicate sender approval",
                flags::APPROVE_EXECUTION as u64,
                flags::APPROVE_EXECUTION,
                sender,
                true,
                None,
            ),
            (
                "foreign execution approval",
                flags::APPROVE_EXECUTION as u64,
                flags::APPROVE_EXECUTION,
                foreign,
                false,
                None,
            ),
            (
                "duplicate payer",
                flags::APPROVE_PAYMENT as u64,
                flags::APPROVE_PAYMENT,
                payer,
                true,
                Some(sender),
            ),
            (
                "payment before sender approval",
                flags::APPROVE_PAYMENT as u64,
                flags::APPROVE_PAYMENT,
                payer,
                false,
                None,
            ),
        ];

        for (case, scope, frame_flags, target, sender_approved, current_payer) in cases {
            let frame = approval_frame(target, mode::DEFAULT, frame_flags, 0);
            let approval = ApprovalState { sender_approved, payer: current_payer };
            assert!(
                validate_default_approval(
                    &mut evm,
                    &tx,
                    &frame,
                    target,
                    scope,
                    U256::ONE,
                    &approval,
                    0,
                )
                .unwrap()
                .is_none(),
                "{case}"
            );
        }
        evm.abort_frame_transaction();
    }

    #[test]
    fn approval_validation_uses_live_journal_balance_and_nonce() {
        let sender = Address::repeat_byte(0x31);
        let depleted_payer = Address::repeat_byte(0x32);
        let funded_payer = Address::repeat_byte(0x33);
        let mut evm = test_evm([
            (sender, U256::ZERO, 0, Bytecode::default()),
            (depleted_payer, U256::MAX, 0, Bytecode::default()),
            (funded_payer, U256::ZERO, 0, Bytecode::default()),
        ]);
        let tx = approval_tx(sender, 0, evm.chain_id(), vec![]);
        let approval = ApprovalState { sender_approved: true, payer: None };
        assert!(evm.begin_frame_transaction(sender));

        evm.ctx_mut()
            .journal_mut()
            .load_account_mut(depleted_payer)
            .unwrap()
            .set_balance(U256::ZERO);
        assert!(
            validate_default_approval(
                &mut evm,
                &tx,
                &approval_frame(depleted_payer, mode::DEFAULT, flags::APPROVE_PAYMENT, 0,),
                depleted_payer,
                SCOPE_PAYMENT,
                U256::ONE,
                &approval,
                0,
            )
            .unwrap()
            .is_none()
        );

        evm.ctx_mut().journal_mut().load_account_mut(funded_payer).unwrap().set_balance(U256::ONE);
        let validated = validate_default_approval(
            &mut evm,
            &tx,
            &approval_frame(funded_payer, mode::DEFAULT, flags::APPROVE_PAYMENT, 0),
            funded_payer,
            SCOPE_PAYMENT,
            U256::ONE,
            &approval,
            0,
        )
        .unwrap()
        .unwrap();
        assert_eq!(validated.payer, Some(funded_payer));

        evm.ctx_mut().journal_mut().load_account_mut(sender).unwrap().set_nonce(u64::MAX);
        assert!(
            validate_default_approval(
                &mut evm,
                &tx,
                &approval_frame(funded_payer, mode::DEFAULT, flags::APPROVE_PAYMENT, 0),
                funded_payer,
                SCOPE_PAYMENT,
                U256::ONE,
                &approval,
                0,
            )
            .unwrap()
            .is_none()
        );
        evm.abort_frame_transaction();
    }

    #[test]
    fn underfunded_approval_discards_state_logs_and_success_status() {
        let sender = Address::repeat_byte(0x41);
        let underfunded = Address::repeat_byte(0x42);
        let sponsor = Address::repeat_byte(0x43);
        let mut evm = test_evm([
            (sender, U256::ZERO, 0, approver_code(flags::APPROVE_EXECUTION, false)),
            (underfunded, U256::ZERO, 0, approver_code(flags::APPROVE_PAYMENT, true)),
            (sponsor, U256::MAX, 0, approver_code(flags::APPROVE_PAYMENT, false)),
        ]);
        let tx = approval_tx(
            sender,
            0,
            evm.chain_id(),
            vec![
                approval_frame(sender, mode::DEFAULT, flags::APPROVE_EXECUTION, 0),
                approval_frame(underfunded, mode::DEFAULT, flags::APPROVE_PAYMENT, 1),
                approval_frame(sponsor, mode::DEFAULT, flags::APPROVE_PAYMENT, 0),
            ],
        );

        let outcome = execute_and_commit(&mut evm, &tx).unwrap();

        assert_eq!(frame_statuses(&outcome), [STATUS_SUCCESS, STATUS_FAILED, STATUS_SUCCESS]);
        assert!(outcome.result.result.logs().is_empty());
        assert_eq!(evm.db_mut().storage(underfunded, U256::ZERO).unwrap(), U256::ZERO);
    }

    #[test]
    fn duplicate_approval_discards_state_logs_and_success_status() {
        let sender = Address::repeat_byte(0x51);
        let mut evm = test_evm([(
            sender,
            U256::MAX,
            0,
            approver_code(flags::APPROVE_EXECUTION_PAYMENT, true),
        )]);
        let tx = approval_tx(
            sender,
            0,
            evm.chain_id(),
            vec![
                approval_frame(sender, mode::DEFAULT, flags::APPROVE_EXECUTION_PAYMENT, 1),
                approval_frame(sender, mode::DEFAULT, flags::APPROVE_EXECUTION_PAYMENT, 2),
            ],
        );

        let outcome = execute_and_commit(&mut evm, &tx).unwrap();

        assert_eq!(frame_statuses(&outcome), [STATUS_SUCCESS, STATUS_FAILED]);
        assert_eq!(outcome.result.result.logs().len(), 1);
        assert_eq!(evm.db_mut().storage(sender, U256::ZERO).unwrap(), U256::ONE);
    }

    #[test]
    fn foreign_approval_discards_state_logs_and_success_status() {
        let sender = Address::repeat_byte(0x61);
        let foreign = Address::repeat_byte(0x62);
        let mut evm = test_evm([
            (sender, U256::MAX, 0, approver_code(flags::APPROVE_EXECUTION_PAYMENT, false)),
            (foreign, U256::ZERO, 0, approver_code(flags::APPROVE_EXECUTION, true)),
        ]);
        let tx = approval_tx(
            sender,
            0,
            evm.chain_id(),
            vec![
                approval_frame(foreign, mode::DEFAULT, flags::APPROVE_EXECUTION, 1),
                approval_frame(sender, mode::DEFAULT, flags::APPROVE_EXECUTION_PAYMENT, 0),
            ],
        );

        let outcome = execute_and_commit(&mut evm, &tx).unwrap();

        assert_eq!(frame_statuses(&outcome), [STATUS_FAILED, STATUS_SUCCESS]);
        assert!(outcome.result.result.logs().is_empty());
        assert_eq!(evm.db_mut().storage(foreign, U256::ZERO).unwrap(), U256::ZERO);
    }

    #[test]
    fn sender_frame_executes_after_payment_moves_nonce_to_max() {
        let sender = Address::repeat_byte(0x70);
        let writer = Address::repeat_byte(0x71);
        let writer_code = Bytecode::new_raw(vec![0x60, 0x01, 0x5f, 0x55, 0x00].into());
        let mut evm = test_evm([
            (
                sender,
                U256::MAX,
                u64::MAX - 1,
                approver_code(flags::APPROVE_EXECUTION_PAYMENT, false),
            ),
            (writer, U256::ZERO, 0, writer_code),
        ]);
        let tx = approval_tx(
            sender,
            u64::MAX - 1,
            evm.chain_id(),
            vec![
                approval_frame(sender, mode::DEFAULT, flags::APPROVE_EXECUTION_PAYMENT, 0),
                approval_frame(writer, mode::SENDER, 0, 0),
            ],
        );

        let outcome = execute_and_commit(&mut evm, &tx).unwrap();

        assert_eq!(frame_statuses(&outcome), [STATUS_SUCCESS, STATUS_SUCCESS]);
        assert_eq!(evm.db_mut().basic(sender).unwrap().unwrap().nonce, u64::MAX);
        assert_eq!(evm.db_mut().storage(writer, U256::ZERO).unwrap(), U256::ONE);
    }

    #[test]
    fn sender_nonce_overflow_reverts_approval_without_saturating() {
        let sender = Address::repeat_byte(0x71);
        let mut evm = test_evm([(
            sender,
            U256::MAX,
            u64::MAX,
            approver_code(flags::APPROVE_EXECUTION_PAYMENT, true),
        )]);
        let tx = approval_tx(
            sender,
            u64::MAX,
            evm.chain_id(),
            vec![approval_frame(sender, mode::DEFAULT, flags::APPROVE_EXECUTION_PAYMENT, 1)],
        );

        assert!(matches!(execute_frame_tx(&mut evm, &tx), Err(FrameExecutionError::NoPayer)));
        assert_eq!(evm.db_mut().basic(sender).unwrap().unwrap().nonce, u64::MAX);
        assert_eq!(evm.db_mut().storage(sender, U256::ZERO).unwrap(), U256::ZERO);
    }
}
