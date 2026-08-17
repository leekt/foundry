//! Anvil specific [`revm::Inspector`] implementation

use crate::eth::macros::node_info;
use alloy_primitives::{Address, B256, Log, LogData, U256};
use alloy_sol_types::SolValue;
use foundry_evm::{
    call_inspectors,
    decode::decode_console_logs,
    inspectors::{LogCollector, TracingInspector},
    traces::{
        CallKind, CallTrace, CallTraceDecoder, CallTraceNode, SparsedTraceArena,
        TracingInspectorConfig, render_trace_arena_inner,
    },
};
use revm::{
    Inspector,
    context::{ContextTr, JournalTr, journaled_state::account::JournaledAccountTr},
    handler::FrameResult,
    inspector::JournalExt,
    interpreter::{
        CallInputs, CallOutcome, CallScheme, CreateInputs, CreateOutcome, CreateScheme, FrameInput,
        InstructionResult, Interpreter, InterpreterAction,
        interpreter::EthInterpreter,
        interpreter_types::{InputsTr, Jumps, LoopControl},
    },
};
use revm_inspectors::transfer::{TRANSFER_EVENT_TOPIC, TRANSFER_LOG_EMITTER, TransferInspector};
use std::{any::Any, sync::Arc};

/// The [`revm::Inspector`] used when transacting in the evm
#[derive(Clone, Debug, Default)]
pub struct AnvilInspector {
    /// Collects all traces
    pub tracer: Option<TracingInspector>,
    /// Collects all `console.sol` logs
    pub log_collector: Option<LogCollector>,
    /// Collects all internal ETH transfers as ERC20 transfer events.
    pub transfer: Option<TransferInspector>,
    /// Collects canonical and synthetic transfer logs for an `eth_simulateV1` response.
    simulation_logs: Option<SimulationLogCollector>,
    /// Watches for the EIP-8141 `APPROVE` opcode while a frame is executing.
    pub frame_approval: Option<FrameApprovalWatcher>,
    /// Whether the tracer has a synthetic frame-transaction root.
    frame_trace_root: bool,
}

/// Composes EIP-8141 approval tracking with an arbitrary caller-provided inspector.
pub(crate) struct FrameInspector<'a, I> {
    approval: AnvilInspector,
    inner: &'a mut I,
    trace_root: bool,
}

impl<'a, I> FrameInspector<'a, I> {
    pub(crate) fn new(inner: &'a mut I) -> Self {
        Self { approval: AnvilInspector::default(), inner, trace_root: false }
    }

    pub(crate) fn approval_mut(&mut self) -> &mut AnvilInspector {
        &mut self.approval
    }
}

impl<I: Any> FrameInspector<'_, I> {
    pub(crate) fn begin_trace(&mut self, sender: Address, gas_limit: u64) {
        let Some(tracer) = (self.inner as &mut dyn Any).downcast_mut::<TracingInspector>() else {
            return;
        };
        configure_frame_trace_root(tracer, sender, gas_limit);
        self.trace_root = true;
    }

    pub(crate) fn finish_trace(&mut self, gas_used: u64) {
        let Some(tracer) = (self.inner as &mut dyn Any).downcast_mut::<TracingInspector>() else {
            return;
        };
        finish_frame_trace_root(tracer, gas_used);
    }
}

fn configure_frame_trace_root(tracer: &mut TracingInspector, sender: Address, gas_limit: u64) {
    let root = tracer
        .traces_mut()
        .nodes_mut()
        .first_mut()
        .expect("tracing arena always contains a root node");
    *root = CallTraceNode {
        idx: 0,
        trace: CallTrace {
            caller: sender,
            address: sender,
            kind: CallKind::Call,
            gas_limit,
            ..Default::default()
        },
        ..Default::default()
    };
}

fn finish_frame_trace_root(tracer: &mut TracingInspector, gas_used: u64) {
    let Some(root) = tracer.traces_mut().nodes_mut().first_mut() else { return };
    root.trace.success = true;
    root.trace.status = Some(InstructionResult::Return);
    root.trace.gas_used = gas_used;
}

/// The EIP-8141 `APPROVE` opcode.
const APPROVE_OPCODE: u8 = 0xaa;
/// EIP-8141 approval scope bits.
const APPROVE_PAYMENT: u64 = 0x01;
const APPROVE_EXECUTION: u64 = 0x02;

/// Transaction-scoped EIP-8141 approval state.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ApprovalState {
    pub(crate) sender_approved: bool,
    pub(crate) payer: Option<Address>,
}

/// One `APPROVE` opcode encountered while executing a frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ApprovalAttempt {
    /// Scope read from the stack, or `None` when the stack was too short.
    pub(crate) scope: Option<u64>,
    /// Whether the opcode completed successfully and its effects were applied.
    pub(crate) succeeded: bool,
}

/// Approval and refund effects that survived the frame's call tree.
#[derive(Clone, Debug)]
pub(crate) struct FrameApprovalOutcome {
    pub(crate) state: ApprovalState,
    pub(crate) attempts: Vec<ApprovalAttempt>,
    pub(crate) refund_counter: i64,
}

#[derive(Clone, Copy, Debug)]
struct PendingApproval {
    scope: u64,
    next_state: Option<ApprovalState>,
}

/// Applies and records every `APPROVE` attempted by an executing frame.
///
/// The approval state checkpoints mirror EVM call checkpoints. This lets a
/// nested successful approval affect subsequent calls immediately while still
/// removing it if an enclosing call later reverts.
#[derive(Clone, Debug, Default)]
pub struct FrameApprovalWatcher {
    /// The resolved target of the frame currently executing. `APPROVE` only
    /// counts from this address, matching the reference's `ADDRESS` check.
    pub resolved_target: Address,
    sender: Address,
    allowed_scope: u64,
    max_cost: U256,
    state: ApprovalState,
    frame_checkpoints: Vec<(ApprovalState, usize)>,
    pending: Option<PendingApproval>,
    attempts: Vec<ApprovalAttempt>,
    refund_counter: i64,
}

impl AnvilInspector {
    /// Creates one stable trace root whose children are the transaction's top-level frames.
    pub(crate) fn begin_frame_transaction_trace(&mut self, sender: Address, gas_limit: u64) {
        self.frame_trace_root = self.tracer.is_some();
        let Some(tracer) = &mut self.tracer else { return };
        configure_frame_trace_root(tracer, sender, gas_limit);
    }

    /// Finalizes the synthetic frame-transaction trace root.
    pub(crate) fn finish_frame_transaction_trace(&mut self, gas_used: u64) {
        let Some(tracer) = &mut self.tracer else { return };
        finish_frame_trace_root(tracer, gas_used);
    }

    /// Arms the approval watcher for a frame targeting `resolved_target`.
    pub(crate) fn watch_frame_approval(
        &mut self,
        resolved_target: Address,
        sender: Address,
        allowed_scope: u64,
        max_cost: U256,
        state: ApprovalState,
    ) {
        self.frame_approval = Some(FrameApprovalWatcher {
            resolved_target,
            sender,
            allowed_scope,
            max_cost,
            state,
            ..Default::default()
        });
    }

    /// Disarms the watcher and returns effects that survived the frame.
    pub(crate) fn take_frame_approval(&mut self) -> Option<FrameApprovalOutcome> {
        self.frame_approval.take().map(|watcher| FrameApprovalOutcome {
            state: watcher.state,
            attempts: watcher.attempts,
            refund_counter: watcher.refund_counter,
        })
    }
}

fn validate_frame_approval<CTX>(
    watcher: &FrameApprovalWatcher,
    address: Address,
    scope: u64,
    ecx: &mut CTX,
) -> Result<Option<ApprovalState>, <CTX::Db as revm::Database>::Error>
where
    CTX: ContextTr,
{
    if address != watcher.resolved_target || scope == 0 || scope & !watcher.allowed_scope != 0 {
        return Ok(None);
    }

    let approves_execution = scope & APPROVE_EXECUTION != 0;
    let approves_payment = scope & APPROVE_PAYMENT != 0;
    if approves_execution
        && (watcher.state.sender_approved || watcher.resolved_target != watcher.sender)
    {
        return Ok(None);
    }
    if approves_payment
        && (watcher.state.payer.is_some() || !(watcher.state.sender_approved || approves_execution))
    {
        return Ok(None);
    }

    if approves_payment {
        let (payer_balance, payer_nonce) = {
            let payer = ecx.journal_mut().load_account(watcher.resolved_target)?;
            (payer.info.balance, payer.info.nonce)
        };
        if payer_balance < watcher.max_cost {
            return Ok(None);
        }
        let sender_nonce = if watcher.resolved_target == watcher.sender {
            payer_nonce
        } else {
            ecx.journal_mut().load_account(watcher.sender)?.info.nonce
        };
        if sender_nonce == u64::MAX {
            return Ok(None);
        }
    }

    Ok(Some(ApprovalState {
        sender_approved: watcher.state.sender_approved || approves_execution,
        payer: if approves_payment { Some(watcher.resolved_target) } else { watcher.state.payer },
    }))
}

fn apply_frame_approval<CTX>(
    watcher: &FrameApprovalWatcher,
    next_state: ApprovalState,
    ecx: &mut CTX,
) -> Result<bool, <CTX::Db as revm::Database>::Error>
where
    CTX: ContextTr,
{
    let Some(payer) = next_state.payer.filter(|_| watcher.state.payer.is_none()) else {
        return Ok(true);
    };

    if payer == watcher.sender {
        let mut account = ecx.journal_mut().load_account_mut(payer)?;
        return Ok(account.decr_balance(watcher.max_cost) && account.bump_nonce());
    }

    let debited = ecx.journal_mut().load_account_mut(payer)?.decr_balance(watcher.max_cost);
    let bumped = ecx.journal_mut().load_account_mut(watcher.sender)?.bump_nonce();
    Ok(debited && bumped)
}

fn reject_approval_return(interp: &mut Interpreter) {
    let Some(InterpreterAction::Return(result)) = interp.bytecode.action().as_mut() else {
        unreachable!("APPROVE return action exists at step end")
    };
    result.result = InstructionResult::Revert;
    result.output = Default::default();
}

/// Runs the tracing callback below the synthetic frame-transaction root.
///
/// REVM checkpoints are index values, so this empty checkpoint changes only the
/// reported call depth and is committed immediately afterward.
fn with_frame_trace_depth<CTX, T>(ecx: &mut CTX, offset: usize, f: impl FnOnce(&mut CTX) -> T) -> T
where
    CTX: ContextTr,
{
    for _ in 0..offset {
        let _ = ecx.journal_mut().checkpoint();
    }
    let result = f(ecx);
    for _ in 0..offset {
        ecx.journal_mut().checkpoint_commit();
    }
    result
}

#[derive(Clone, Debug)]
struct SimulationLog {
    log: Log,
    index: u64,
    canonical: bool,
}

/// Collects simulation response logs without inserting synthetic logs into EVM state.
#[derive(Clone, Debug, Default)]
struct SimulationLogCollector {
    logs: Vec<SimulationLog>,
    checkpoints: Vec<usize>,
    next_index: u64,
    trace_transfers: bool,
    journal_log_count: usize,
}

impl SimulationLogCollector {
    fn push_log(&mut self, log: Log, canonical: bool) {
        self.logs.push(SimulationLog { log, index: self.next_index, canonical });
        self.next_index += 1;
    }

    fn push_canonical_log(&mut self, log: Log, journal_log_count: usize) {
        self.push_log(log, true);
        self.journal_log_count = journal_log_count;
    }

    fn sync_journal_logs(&mut self, logs: &[Log]) {
        self.journal_log_count = self.journal_log_count.min(logs.len());
        for log in &logs[self.journal_log_count..] {
            self.push_log(log.clone(), true);
        }
        self.journal_log_count = logs.len();
    }

    fn push_transfer(&mut self, from: Address, to: Address, value: U256) {
        if !self.trace_transfers || value.is_zero() {
            return;
        }
        self.push_log(
            Log {
                address: TRANSFER_LOG_EMITTER,
                data: LogData::new_unchecked(
                    vec![
                        TRANSFER_EVENT_TOPIC,
                        B256::from_slice(&from.abi_encode()),
                        B256::from_slice(&to.abi_encode()),
                    ],
                    value.abi_encode().into(),
                ),
            },
            false,
        );
    }

    fn frame_start(&mut self) {
        self.checkpoints.push(self.logs.len());
    }

    fn frame_end(&mut self, success: bool, journal_log_count: usize) {
        let checkpoint = self.checkpoints.pop().expect("execution frame checkpoint exists");
        if !success {
            self.logs.truncate(checkpoint);
        }
        self.journal_log_count = journal_log_count;
    }

    fn append_remaining_canonical_logs(&mut self, canonical_logs: &[Log]) {
        let mut canonical_logs = canonical_logs.iter();
        for collected in self.logs.iter().filter(|log| log.canonical) {
            let canonical =
                canonical_logs.next().expect("collected canonical log exists in result");
            assert_eq!(&collected.log, canonical, "collected canonical logs preserve ordering");
        }
        for log in canonical_logs {
            self.push_log(log.clone(), true);
        }
    }
}

/// Configuration for per-transaction inspector lifecycle.
#[derive(Clone, Debug)]
pub struct InspectorTxConfig {
    /// Whether to print traces to stdout.
    pub print_traces: bool,
    /// Whether to print logs to stdout.
    pub print_logs: bool,
    /// Whether to enable step-level tracing (with state diffs).
    pub enable_steps_tracing: bool,
    /// Decoder for populating trace labels.
    pub call_trace_decoder: Arc<CallTraceDecoder>,
}

impl AnvilInspector {
    /// Finish a transaction: print traces/logs, drain the tracer, and reset for the next tx.
    ///
    /// Returns the collected call trace nodes from the finished transaction.
    pub fn finish_transaction(&mut self, config: &InspectorTxConfig) -> Vec<CallTraceNode> {
        // Print before draining so the tracer is still populated.
        if config.print_traces {
            self.print_traces(config.call_trace_decoder.clone());
        }
        self.print_logs();

        let traces = self.tracer.take().map(|t| t.into_traces().into_nodes()).unwrap_or_default();

        self.reset_transaction(config);

        traces
    }

    /// Discards a transaction's traces/logs and resets the inspector without printing them.
    pub fn discard_transaction(&mut self, config: &InspectorTxConfig) {
        self.reset_transaction(config);
    }

    /// Resets per-transaction collectors for the next transaction.
    fn reset_transaction(&mut self, config: &InspectorTxConfig) {
        // Reinstall tracer for next tx.
        let tracing_config = if config.enable_steps_tracing {
            TracingInspectorConfig::all().with_state_diffs()
        } else {
            TracingInspectorConfig::all().set_steps(false)
        };
        self.tracer = Some(TracingInspector::new(tracing_config));
        self.frame_trace_root = false;

        // Reset log collector for next tx.
        self.log_collector = config.print_logs.then(|| LogCollector::Capture { logs: Vec::new() });
    }

    /// Called after the inspecting the evm
    ///
    /// This will log all `console.sol` logs
    pub fn print_logs(&self) {
        if let Some(LogCollector::Capture { logs }) = &self.log_collector {
            print_logs(logs);
        }
    }

    /// Consumes the type and prints the traces.
    pub fn into_print_traces(mut self, decoder: Arc<CallTraceDecoder>) {
        if let Some(a) = self.tracer.take() {
            print_traces(a, decoder);
        }
    }

    /// Called after the inspecting the evm
    /// This will log all traces
    pub fn print_traces(&self, decoder: Arc<CallTraceDecoder>) {
        if let Some(a) = self.tracer.clone() {
            print_traces(a, decoder);
        }
    }

    /// Configures the `Tracer` [`revm::Inspector`]
    pub fn with_tracing(mut self) -> Self {
        self.tracer = Some(TracingInspector::new(TracingInspectorConfig::all().set_steps(false)));
        self
    }

    /// Configures the `TracingInspector` [`revm::Inspector`]
    pub fn with_tracing_config(mut self, config: TracingInspectorConfig) -> Self {
        self.tracer = Some(TracingInspector::new(config));
        self
    }

    /// Enables steps recording for `Tracer`.
    pub fn with_steps_tracing(mut self) -> Self {
        self.tracer = Some(TracingInspector::new(TracingInspectorConfig::all().with_state_diffs()));
        self
    }

    /// Configures the `Tracer` [`revm::Inspector`] with a log collector
    pub fn with_log_collector(mut self) -> Self {
        self.log_collector = Some(LogCollector::Capture { logs: Vec::new() });
        self
    }

    /// Configures the `Tracer` [`revm::Inspector`] with a transfer event collector
    pub fn with_transfers(mut self) -> Self {
        self.transfer = Some(TransferInspector::new(false).with_logs(true));
        self
    }

    /// Collects canonical and synthetic transfer logs for an `eth_simulateV1` response.
    pub fn with_simulation_logs(mut self, trace_transfers: bool) -> Self {
        self.simulation_logs =
            Some(SimulationLogCollector { trace_transfers, ..Default::default() });
        self
    }

    /// Takes the collected `eth_simulateV1` response logs and attempted log count.
    pub fn take_simulation_logs(
        &mut self,
        canonical_logs: &[Log],
        success: bool,
    ) -> Option<(Vec<(u64, Log)>, u64)> {
        self.simulation_logs.take().map(|mut collector| {
            if success {
                collector.append_remaining_canonical_logs(canonical_logs);
            } else {
                // A top-level revert can discard logs without producing an enclosing call frame
                // callback. Preserve the attempted count for subsequent log indices.
                collector.logs.clear();
            }
            (
                collector.logs.into_iter().map(|log| (log.index, log.log)).collect(),
                collector.next_index,
            )
        })
    }

    /// Configures the `Tracer` [`revm::Inspector`] with a trace printer
    pub fn with_trace_printer(mut self) -> Self {
        self.tracer = Some(TracingInspector::new(TracingInspectorConfig::all().with_state_diffs()));
        self
    }
}

/// Prints the traces for the inspector
///
/// Caution: This blocks on call trace decoding
///
/// # Panics
///
/// If called outside tokio runtime
fn print_traces(tracer: TracingInspector, decoder: Arc<CallTraceDecoder>) {
    let arena = tokio::task::block_in_place(move || {
        tokio::runtime::Handle::current().block_on(async move {
            let mut arena = tracer.into_traces();
            decoder.populate_traces(arena.nodes_mut()).await;
            arena
        })
    });

    let traces =
        SparsedTraceArena { arena, ignored: Default::default(), diagnostics: Default::default() };
    let trace = render_trace_arena_inner(&traces, false, true);
    node_info!(Traces = %format!("\n{}", trace));
}

impl<CTX> Inspector<CTX, EthInterpreter> for AnvilInspector
where
    CTX: ContextTr<Journal: JournalExt>,
{
    fn initialize_interp(&mut self, interp: &mut Interpreter, ecx: &mut CTX) {
        if let Some(collector) = &mut self.simulation_logs {
            collector.sync_journal_logs(ecx.journal().logs());
        }
        call_inspectors!([&mut self.tracer], |inspector| {
            inspector.initialize_interp(interp, ecx);
        });
    }

    fn step(&mut self, interp: &mut Interpreter, ecx: &mut CTX) {
        if let Some(watcher) = &mut self.frame_approval
            && interp.bytecode.opcode() == APPROVE_OPCODE
        {
            // APPROVE pops [offset, len, scope], so the scope sits third from
            // the top of the stack.
            let stack = interp.stack.data();
            if let Some(scope) = stack.len().checked_sub(3).map(|i| stack[i]) {
                let scope = u64::try_from(scope).unwrap_or(u64::MAX);
                if interp.input.target_address() != watcher.resolved_target
                    || scope == 0
                    || scope & !watcher.allowed_scope != 0
                {
                    watcher.attempts.push(ApprovalAttempt { scope: Some(scope), succeeded: false });
                    interp.halt(InstructionResult::Revert);
                } else {
                    match validate_frame_approval(
                        watcher,
                        interp.input.target_address(),
                        scope,
                        ecx,
                    ) {
                        Ok(Some(next_state)) => {
                            watcher.pending =
                                Some(PendingApproval { scope, next_state: Some(next_state) });
                        }
                        Ok(None) => {
                            // Transaction-context rejection happens after the native opcode has
                            // charged for expanding its return-data memory.
                            watcher.pending = Some(PendingApproval { scope, next_state: None });
                        }
                        Err(err) => {
                            watcher
                                .attempts
                                .push(ApprovalAttempt { scope: Some(scope), succeeded: false });
                            *ecx.error() = Err(err.into());
                            interp.halt_fatal();
                        }
                    }
                }
            } else {
                watcher.attempts.push(ApprovalAttempt { scope: None, succeeded: false });
            }
        }
        if let Some(collector) = &mut self.simulation_logs {
            collector.sync_journal_logs(ecx.journal().logs());
        }
        call_inspectors!([&mut self.tracer], |inspector| {
            inspector.step(interp, ecx);
        });
    }

    fn step_end(&mut self, interp: &mut Interpreter, ecx: &mut CTX) {
        if let Some(watcher) = &mut self.frame_approval
            && let Some(pending) = watcher.pending.take()
        {
            let mut succeeded = false;
            if interp.bytecode.instruction_result() == Some(InstructionResult::Return) {
                if let Some(next_state) = pending.next_state {
                    match apply_frame_approval(watcher, next_state, ecx) {
                        Ok(true) => {
                            watcher.state = next_state;
                            succeeded = true;
                        }
                        Ok(false) => reject_approval_return(interp),
                        Err(err) => {
                            *ecx.error() = Err(err.into());
                            interp.halt_fatal();
                        }
                    }
                } else {
                    reject_approval_return(interp);
                }
            }
            watcher.attempts.push(ApprovalAttempt { scope: Some(pending.scope), succeeded });
        }
        call_inspectors!([&mut self.tracer], |inspector| {
            inspector.step_end(interp, ecx);
        });
        if let Some(collector) = &mut self.simulation_logs {
            collector.sync_journal_logs(ecx.journal().logs());
        }
    }

    #[allow(clippy::redundant_clone)]
    fn log(&mut self, ecx: &mut CTX, log: Log) {
        call_inspectors!([&mut self.tracer, &mut self.log_collector], |inspector| {
            inspector.log(ecx, log.clone());
        });
        if let Some(collector) = &mut self.simulation_logs {
            collector.push_canonical_log(log, ecx.journal().logs().len());
        }
    }

    #[allow(clippy::redundant_clone)]
    fn log_full(&mut self, interp: &mut Interpreter, ecx: &mut CTX, log: Log) {
        call_inspectors!([&mut self.tracer, &mut self.log_collector], |inspector| {
            inspector.log_full(interp, ecx, log.clone());
        });
        if let Some(collector) = &mut self.simulation_logs {
            collector.push_canonical_log(log, ecx.journal().logs().len());
        }
    }

    fn call(&mut self, ecx: &mut CTX, inputs: &mut CallInputs) -> Option<CallOutcome> {
        let trace_depth_offset = usize::from(self.frame_trace_root);
        if let Some(watcher) = &mut self.frame_approval {
            watcher.frame_checkpoints.push((watcher.state, watcher.attempts.len()));
        }
        if let Some(collector) = &mut self.simulation_logs {
            collector.sync_journal_logs(ecx.journal().logs());
            collector.frame_start();
            if matches!(inputs.scheme, CallScheme::Call)
                && let Some(value) = inputs.transfer_value()
            {
                collector.push_transfer(inputs.transfer_from(), inputs.transfer_to(), value);
            }
        }
        if let Some(tracer) = &mut self.tracer
            && let Some(result) =
                with_frame_trace_depth(ecx, trace_depth_offset, |ecx| tracer.call(ecx, inputs))
        {
            return Some(result);
        }
        call_inspectors!(
            #[ret]
            [&mut self.log_collector, &mut self.transfer],
            |inspector| inspector.call(ecx, inputs).map(Some),
        );
        None
    }

    fn call_end(&mut self, ecx: &mut CTX, inputs: &CallInputs, outcome: &mut CallOutcome) {
        if let Some(watcher) = &mut self.frame_approval
            && let Some((checkpoint, attempt_index)) = watcher.frame_checkpoints.pop()
        {
            let succeeded = outcome.instruction_result().is_ok();
            if !succeeded {
                watcher.state = checkpoint;
                for attempt in &mut watcher.attempts[attempt_index..] {
                    attempt.succeeded = false;
                }
            }
            if watcher.frame_checkpoints.is_empty() {
                watcher.refund_counter = if succeeded { outcome.gas().refunded() } else { 0 };
            }
        }
        if let Some(tracer) = &mut self.tracer {
            tracer.call_end(ecx, inputs, outcome);
        }
        if let Some(collector) = &mut self.simulation_logs {
            collector.sync_journal_logs(ecx.journal().logs());
            collector.frame_end(outcome.instruction_result().is_ok(), ecx.journal().logs().len());
        }
    }

    fn create(&mut self, ecx: &mut CTX, inputs: &mut CreateInputs) -> Option<CreateOutcome> {
        let trace_depth_offset = usize::from(self.frame_trace_root);
        if let Some(watcher) = &mut self.frame_approval {
            watcher.frame_checkpoints.push((watcher.state, watcher.attempts.len()));
        }
        if let Some(collector) = &mut self.simulation_logs {
            collector.sync_journal_logs(ecx.journal().logs());
            collector.frame_start();
            if matches!(inputs.scheme(), CreateScheme::Create | CreateScheme::Create2 { .. })
                && let Ok(account) = ecx.journal_mut().load_account(inputs.caller())
            {
                let address = inputs.created_address(account.data.info.nonce);
                collector.push_transfer(inputs.caller(), address, inputs.value());
            }
        }
        if let Some(tracer) = &mut self.tracer
            && let Some(result) =
                with_frame_trace_depth(ecx, trace_depth_offset, |ecx| tracer.create(ecx, inputs))
        {
            return Some(result);
        }
        call_inspectors!(
            #[ret]
            [&mut self.transfer],
            |inspector| inspector.create(ecx, inputs).map(Some),
        );
        None
    }

    fn create_end(&mut self, ecx: &mut CTX, inputs: &CreateInputs, outcome: &mut CreateOutcome) {
        if let Some(watcher) = &mut self.frame_approval
            && let Some((checkpoint, attempt_index)) = watcher.frame_checkpoints.pop()
            && !(outcome.instruction_result().is_ok() && outcome.address.is_some())
        {
            watcher.state = checkpoint;
            for attempt in &mut watcher.attempts[attempt_index..] {
                attempt.succeeded = false;
            }
        }
        if let Some(tracer) = &mut self.tracer {
            tracer.create_end(ecx, inputs, outcome);
        }
        if let Some(collector) = &mut self.simulation_logs {
            collector.sync_journal_logs(ecx.journal().logs());
            collector.frame_end(
                outcome.instruction_result().is_ok() && outcome.address.is_some(),
                ecx.journal().logs().len(),
            );
        }
    }

    fn selfdestruct(&mut self, contract: Address, target: Address, value: U256) {
        call_inspectors!([&mut self.tracer, &mut self.transfer], |inspector| {
            Inspector::<CTX, EthInterpreter>::selfdestruct(inspector, contract, target, value)
        });
        if let Some(collector) = &mut self.simulation_logs {
            collector.push_transfer(contract, target, value);
        }
    }
}

impl<CTX, I> Inspector<CTX, EthInterpreter> for FrameInspector<'_, I>
where
    CTX: ContextTr<Journal: JournalExt>,
    I: Inspector<CTX, EthInterpreter>,
{
    fn initialize_interp(&mut self, interp: &mut Interpreter, ecx: &mut CTX) {
        self.inner.initialize_interp(interp, ecx);
        self.approval.initialize_interp(interp, ecx);
    }

    fn step(&mut self, interp: &mut Interpreter, ecx: &mut CTX) {
        self.inner.step(interp, ecx);
        self.approval.step(interp, ecx);
    }

    fn step_end(&mut self, interp: &mut Interpreter, ecx: &mut CTX) {
        self.inner.step_end(interp, ecx);
        self.approval.step_end(interp, ecx);
    }

    fn log(&mut self, ecx: &mut CTX, log: Log) {
        self.approval.log(ecx, log.clone());
        self.inner.log(ecx, log);
    }

    fn log_full(&mut self, interp: &mut Interpreter, ecx: &mut CTX, log: Log) {
        self.approval.log_full(interp, ecx, log.clone());
        self.inner.log_full(interp, ecx, log);
    }

    fn frame_start(&mut self, ecx: &mut CTX, input: &mut FrameInput) -> Option<FrameResult> {
        let inspected = self.inner.frame_start(ecx, input);
        inspected.or_else(|| self.approval.frame_start(ecx, input))
    }

    fn frame_end(&mut self, ecx: &mut CTX, input: &FrameInput, result: &mut FrameResult) {
        self.inner.frame_end(ecx, input, result);
        self.approval.frame_end(ecx, input, result);
    }

    fn call(&mut self, ecx: &mut CTX, inputs: &mut CallInputs) -> Option<CallOutcome> {
        let inspected = with_frame_trace_depth(ecx, usize::from(self.trace_root), |ecx| {
            self.inner.call(ecx, inputs)
        });
        inspected.or_else(|| self.approval.call(ecx, inputs))
    }

    fn call_end(&mut self, ecx: &mut CTX, inputs: &CallInputs, outcome: &mut CallOutcome) {
        self.inner.call_end(ecx, inputs, outcome);
        self.approval.call_end(ecx, inputs, outcome);
    }

    fn create(&mut self, ecx: &mut CTX, inputs: &mut CreateInputs) -> Option<CreateOutcome> {
        let inspected = with_frame_trace_depth(ecx, usize::from(self.trace_root), |ecx| {
            self.inner.create(ecx, inputs)
        });
        inspected.or_else(|| self.approval.create(ecx, inputs))
    }

    fn create_end(&mut self, ecx: &mut CTX, inputs: &CreateInputs, outcome: &mut CreateOutcome) {
        self.inner.create_end(ecx, inputs, outcome);
        self.approval.create_end(ecx, inputs, outcome);
    }

    fn selfdestruct(&mut self, contract: Address, target: Address, value: U256) {
        Inspector::<CTX, EthInterpreter>::selfdestruct(&mut self.approval, contract, target, value);
        Inspector::<CTX, EthInterpreter>::selfdestruct(self.inner, contract, target, value);
    }
}

/// Prints all the logs
pub fn print_logs(logs: &[Log]) {
    for log in decode_console_logs(logs) {
        tracing::info!(target: crate::logging::EVM_CONSOLE_LOG_TARGET, "{}", log);
    }
}
