//! EIP-8141 frame transaction (type `0x06`).
//!
//! A frame transaction decomposes a transaction into frames that validate it,
//! approve gas payment and execute user operations. It carries an explicit
//! `sender` and no outer ECDSA signature; authentication happens inside the
//! frames via the signature entries.
//!
//! Ported from the go-ethereum reference implementation (`core/types/tx_frame.go`
//! on `leekt/go-ethereum@fix/eip8141-frame-tx`), which the RLP field order, the
//! canonical signature hash and the gas rules below follow exactly.
//!
//! Author: taek <leekt216@gmail.com>

use alloy_consensus::{Transaction, Typed2718};
use alloy_eips::{
    Encodable2718,
    eip2718::{Decodable2718, Eip2718Error, Eip2718Result},
    eip4844::{DATA_GAS_PER_BLOB, VERSIONED_HASH_VERSION_KZG},
    eip7702::SignedAuthorization,
};
use alloy_primitives::{
    Address, B256, Bytes, ChainId, Sealable, TxKind, U256, keccak256, private::alloy_rlp::Buf,
};
use alloy_rlp::{BufMut, Decodable, Encodable, Header, length_of_length};
use serde::{Deserialize, Serialize};

/// Transaction type id of an EIP-8141 frame transaction.
pub const FRAME_TX_TYPE_ID: u8 = 0x06;

/// Frame modes.
pub mod mode {
    /// Execute the frame as `ENTRY_POINT`.
    pub const DEFAULT: u8 = 0;
    /// Frame identifies as transaction validation; runs static.
    pub const VERIFY: u8 = 1;
    /// Execute the frame as `tx.sender`.
    pub const SENDER: u8 = 2;
}

/// Frame flags.
pub mod flags {
    /// The frame may approve payment.
    pub const APPROVE_PAYMENT: u8 = 0x1;
    /// The frame may approve execution.
    pub const APPROVE_EXECUTION: u8 = 0x2;
    /// Mask of both approval scopes.
    pub const APPROVE_EXECUTION_PAYMENT: u8 = 0x3;
    /// The frame is part of an atomic batch with the frame that follows it.
    pub const ATOMIC_BATCH: u8 = 0x4;
}

/// Signature schemes.
pub mod scheme {
    /// Not validated by the protocol; the frame code interprets the bytes.
    pub const ARBITRARY: u8 = 0x0;
    /// secp256k1, encoded `v || r || s` with `v` the recovery id.
    pub const SECP256K1: u8 = 0x1;
    /// P256, encoded `r || s || qx || qy`.
    pub const P256: u8 = 0x2;
}

/// Gas constants, following the EIP-8141 parameter tables.
pub mod gas {
    /// Base intrinsic cost of a frame transaction (EIP-2780 `TX_BASE_COST`).
    pub const INTRINSIC_COST: u64 = 12000;
    /// Cost per value-bearing frame with an explicit non-sender target
    /// (EIP-2780 `TX_VALUE_COST`).
    pub const VALUE_COST: u64 = 6000;
    /// Fixed per-frame cost (CALL overhead + receipt log entry).
    pub const PER_FRAME_COST: u64 = 475;
    /// Maximum number of frames in a frame transaction.
    pub const MAX_FRAMES: usize = 64;
    /// Exact calldata length of an expiry verifier frame.
    pub const EXPIRY_DATA_LENGTH: usize = 8;
    /// Cost of verifying a secp256k1 signature entry.
    pub const SIGNATURE_SECP256K1: u64 = 2800;
    /// Cost of verifying a P256 signature entry.
    pub const SIGNATURE_P256: u64 = 6700;
    /// Cost of a structurally-checked arbitrary signature entry.
    pub const SIGNATURE_ARBITRARY: u64 = 100;
    /// Token cost per non-zero byte (EIP-7623/7976).
    pub const TOKEN_PER_NON_ZERO_BYTE: u64 = 4;
    /// `STANDARD_TOKEN_COST` (EIP-7976), which params spells as the
    /// per-zero-byte cost.
    pub const STANDARD_TOKEN_COST: u64 = 4;
    /// `TOTAL_COST_FLOOR_PER_TOKEN` (EIP-7976).
    pub const COST_FLOOR_PER_TOKEN: u64 = 16;
    /// `TX_MAX_GAS_LIMIT` (EIP-7825): cap on the transaction's execution budget.
    pub const TX_MAX_GAS_LIMIT: u64 = 16_777_216;
    /// `CPSB` (EIP-8037): cost per state byte.
    pub const CPSB: u64 = 1530;
    /// `STATE_BYTES_PER_NEW_ACCOUNT` (EIP-8037).
    pub const STATE_BYTES_PER_NEW_ACCOUNT: u64 = 120;
    /// State gas charged when a value-bearing frame or `APPROVE` creates an
    /// account: `STATE_BYTES_PER_NEW_ACCOUNT * CPSB`.
    pub const NEW_ACCOUNT_STATE_GAS: u64 = STATE_BYTES_PER_NEW_ACCOUNT * CPSB;
    /// `MAX_VERIFY_GAS`: execution-gas budget of a public-mempool validation
    /// prefix, including signature verification.
    pub const MAX_VERIFY_GAS: u64 = 100_000;
    /// `MAX_VERIFY_STATE_GAS`: state-gas budget of a public-mempool validation
    /// prefix.
    pub const MAX_VERIFY_STATE_GAS: u64 = 500_000;
}

/// `ENTRY_POINT`: the caller of `DEFAULT` and `VERIFY` frames.
pub const ENTRY_POINT_ADDRESS: Address =
    Address::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xaa]);

/// `EXPIRY_VERIFIER`: the predeploy holding the expiry verifier code.
pub const EXPIRY_VERIFIER_ADDRESS: Address =
    Address::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x81, 0x41]);

/// Canonical EIP-8141 expiry verifier runtime installed at [`EXPIRY_VERIFIER_ADDRESS`].
pub const EXPIRY_VERIFIER_RUNTIME_CODE: &[u8] =
    &alloy_primitives::hex!("60083614600a575f5ffd5b5f3560c01c4211601657005b5f5ffd");

/// A single frame within a frame transaction.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Frame {
    /// Frame mode: 0 `DEFAULT`, 1 `VERIFY`, 2 `SENDER`, 3 `POST_TX`. Mode 3 is
    /// available to synthetic opcode contexts, but [`TxFrame::validate`] rejects
    /// it on the real wire path until POST_TX integration exists.
    pub mode: u8,
    /// Frame flags.
    pub flags: u8,
    /// Call target; `None` means `tx.sender`.
    pub target: Option<Address>,
    /// Execution gas limit allotted to this frame (`limits.execution`).
    pub gas_limit: u64,
    /// State gas limit allotted to this frame (`limits.state`, EIP-8037).
    #[serde(default)]
    pub state_gas_limit: u64,
    /// Value transferred by the frame. Only a `SENDER` frame may be non-zero.
    pub value: U256,
    /// Calldata supplied to the frame.
    pub data: Bytes,
}

impl Frame {
    /// Returns the target after resolving a null target to `sender`.
    pub fn resolved_target(&self, sender: Address) -> Address {
        self.target.unwrap_or(sender)
    }

    /// Returns whether this is an expiry verifier frame: a `VERIFY` frame
    /// targeting `EXPIRY_VERIFIER`. Frames in other modes that happen to target
    /// that address are ordinary calls into the predeploy.
    pub fn is_expiry_verifier(&self) -> bool {
        self.mode == mode::VERIFY && self.target == Some(EXPIRY_VERIFIER_ADDRESS)
    }

    /// Payload length of the nested `limits = [execution, state]` list.
    fn limits_payload_length(&self) -> usize {
        self.gas_limit.length() + self.state_gas_limit.length()
    }

    fn rlp_payload_length(&self) -> usize {
        let limits = self.limits_payload_length();
        self.mode.length()
            + self.flags.length()
            + target_rlp_length(self.target)
            + limits
            + length_of_length(limits)
            + self.value.length()
            + self.data.length()
    }
}

/// Encodes an optional target the way geth's `rlp:"nil"` pointer does: an
/// absent target is the empty string, a present one a 20-byte string.
fn encode_target(target: Option<Address>, out: &mut dyn BufMut) {
    match target {
        Some(address) => address.encode(out),
        None => out.put_u8(alloy_rlp::EMPTY_STRING_CODE),
    }
}

fn target_rlp_length(target: Option<Address>) -> usize {
    target.map_or(1, |address| address.length())
}

fn decode_target(buf: &mut &[u8]) -> alloy_rlp::Result<Option<Address>> {
    match buf.first() {
        None => Err(alloy_rlp::Error::InputTooShort),
        Some(&alloy_rlp::EMPTY_STRING_CODE) => {
            buf.advance(1);
            Ok(None)
        }
        _ => Address::decode(buf).map(Some),
    }
}

impl Encodable for Frame {
    fn encode(&self, out: &mut dyn BufMut) {
        Header { list: true, payload_length: self.rlp_payload_length() }.encode(out);
        self.mode.encode(out);
        self.flags.encode(out);
        encode_target(self.target, out);
        Header { list: true, payload_length: self.limits_payload_length() }.encode(out);
        self.gas_limit.encode(out);
        self.state_gas_limit.encode(out);
        self.value.encode(out);
        self.data.encode(out);
    }

    fn length(&self) -> usize {
        let payload_length = self.rlp_payload_length();
        payload_length + length_of_length(payload_length)
    }
}

impl Decodable for Frame {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let mut payload = Header::decode_bytes(buf, true)?;
        let mode = u8::decode(&mut payload)?;
        let flags = u8::decode(&mut payload)?;
        let target = decode_target(&mut payload)?;
        let mut limits = Header::decode_bytes(&mut payload, true)?;
        let gas_limit = u64::decode(&mut limits)?;
        let state_gas_limit = u64::decode(&mut limits)?;
        if !limits.is_empty() {
            return Err(alloy_rlp::Error::UnexpectedLength);
        }
        let this = Self {
            mode,
            flags,
            target,
            gas_limit,
            state_gas_limit,
            value: U256::decode(&mut payload)?,
            data: Bytes::decode(&mut payload)?,
        };
        if !payload.is_empty() {
            return Err(alloy_rlp::Error::UnexpectedLength);
        }
        Ok(this)
    }
}

/// A signature entry within a frame transaction.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FrameSignature {
    /// Signature scheme: 0 `ARBITRARY`, 1 `SECP256K1`, or 2 `P256`.
    pub scheme: u8,
    /// Empty (meaning `tx.sender`) or a 20-byte address.
    pub signer: Bytes,
    /// Empty (meaning the canonical signature hash) or a 32-byte digest.
    pub msg: Bytes,
    /// Raw signature bytes.
    pub signature: Bytes,
}

impl FrameSignature {
    /// Returns the signer address, defaulting to the transaction sender when no
    /// explicit signer is provided. Returns `None` for a malformed signer.
    pub fn resolved_signer(&self, sender: Address) -> Option<Address> {
        match self.signer.len() {
            0 => Some(sender),
            20 => Some(Address::from_slice(&self.signer)),
            _ => None,
        }
    }

    /// Gas cost of verifying this entry, or `None` for an unknown scheme.
    pub const fn verification_cost(&self) -> Option<u64> {
        match self.scheme {
            scheme::SECP256K1 => Some(gas::SIGNATURE_SECP256K1),
            scheme::P256 => Some(gas::SIGNATURE_P256),
            scheme::ARBITRARY => Some(gas::SIGNATURE_ARBITRARY),
            _ => None,
        }
    }

    fn rlp_payload_length(&self) -> usize {
        self.scheme.length() + self.signer.length() + self.msg.length() + self.signature.length()
    }
}

impl Encodable for FrameSignature {
    fn encode(&self, out: &mut dyn BufMut) {
        Header { list: true, payload_length: self.rlp_payload_length() }.encode(out);
        self.scheme.encode(out);
        self.signer.encode(out);
        self.msg.encode(out);
        self.signature.encode(out);
    }

    fn length(&self) -> usize {
        let payload_length = self.rlp_payload_length();
        payload_length + length_of_length(payload_length)
    }
}

impl Decodable for FrameSignature {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let mut payload = Header::decode_bytes(buf, true)?;
        let this = Self {
            scheme: u8::decode(&mut payload)?,
            signer: Bytes::decode(&mut payload)?,
            msg: Bytes::decode(&mut payload)?,
            signature: Bytes::decode(&mut payload)?,
        };
        if !payload.is_empty() {
            return Err(alloy_rlp::Error::UnexpectedLength);
        }
        Ok(this)
    }
}

/// An EIP-8141 frame transaction.
///
/// Field order matches the reference RLP payload exactly; changing it changes
/// both the transaction hash and the canonical signature hash.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TxFrame {
    /// EIP-155 chain id.
    pub chain_id: U256,
    /// Sender nonce.
    #[serde(with = "alloy_serde::quantity")]
    pub nonce: u64,
    /// The declared sender. A frame transaction carries no outer signature, so
    /// this is authoritative and must never be recovered from one.
    pub sender: Address,
    /// The frames, executed in order.
    pub frames: Vec<Frame>,
    /// The signature entries.
    pub signatures: Vec<FrameSignature>,
    /// `maxPriorityFeePerGas`.
    ///
    /// The wire field is 256 bits, but local Alloy/REVM fee APIs use `u128`;
    /// [`Self::validate`] rejects values that cannot be represented locally.
    pub max_priority_fee_per_gas: U256,
    /// `maxFeePerGas`.
    pub max_fee_per_gas: U256,
    /// `maxFeePerBlobGas`.
    pub max_fee_per_blob_gas: U256,
    /// EIP-4844 blob versioned hashes.
    pub blob_versioned_hashes: Vec<B256>,
}

impl TxFrame {
    /// Payload length of the nested `fees = [priority, max, blob]` list.
    fn fees_payload_length(&self) -> usize {
        self.max_priority_fee_per_gas.length()
            + self.max_fee_per_gas.length()
            + self.max_fee_per_blob_gas.length()
    }

    fn rlp_payload_length(&self) -> usize {
        let fees = self.fees_payload_length();
        self.chain_id.length()
            + self.nonce.length()
            + self.sender.length()
            + self.frames.length()
            + self.signatures.length()
            + fees
            + length_of_length(fees)
            + self.blob_versioned_hashes.length()
    }

    /// Encodes the RLP payload (without the type byte).
    pub fn encode_payload(&self, out: &mut dyn BufMut) {
        Header { list: true, payload_length: self.rlp_payload_length() }.encode(out);
        self.chain_id.encode(out);
        self.nonce.encode(out);
        self.sender.encode(out);
        self.frames.encode(out);
        self.signatures.encode(out);
        Header { list: true, payload_length: self.fees_payload_length() }.encode(out);
        self.max_priority_fee_per_gas.encode(out);
        self.max_fee_per_gas.encode(out);
        self.max_fee_per_blob_gas.encode(out);
        self.blob_versioned_hashes.encode(out);
    }

    fn payload_length_with_header(&self) -> usize {
        let payload_length = self.rlp_payload_length();
        payload_length + length_of_length(payload_length)
    }

    /// Decodes the RLP payload (without the type byte).
    pub fn decode_payload(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let mut payload = Header::decode_bytes(buf, true)?;
        let chain_id = U256::decode(&mut payload)?;
        let nonce = u64::decode(&mut payload)?;
        let sender = Address::decode(&mut payload)?;
        let frames = Vec::<Frame>::decode(&mut payload)?;
        let signatures = Vec::<FrameSignature>::decode(&mut payload)?;
        let mut fees = Header::decode_bytes(&mut payload, true)?;
        let max_priority_fee_per_gas = U256::decode(&mut fees)?;
        let max_fee_per_gas = U256::decode(&mut fees)?;
        let max_fee_per_blob_gas = U256::decode(&mut fees)?;
        if !fees.is_empty() {
            return Err(alloy_rlp::Error::UnexpectedLength);
        }
        let this = Self {
            chain_id,
            nonce,
            sender,
            frames,
            signatures,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            max_fee_per_blob_gas,
            blob_versioned_hashes: Vec::<B256>::decode(&mut payload)?,
        };
        if !payload.is_empty() {
            return Err(alloy_rlp::Error::UnexpectedLength);
        }
        Ok(this)
    }

    /// Computes the canonical signature hash.
    ///
    /// The raw signature bytes of every entry with an empty `msg` are elided
    /// before hashing, so that an entry signing the canonical hash does not have
    /// to commit to itself.
    pub fn signature_hash(&self) -> B256 {
        let mut elided = self.clone();
        for signature in &mut elided.signatures {
            if signature.msg.is_empty() {
                signature.signature = Bytes::new();
            }
        }
        elided.hash_slow()
    }

    /// Sum of all frame execution gas limits, or `None` on overflow.
    pub fn sum_frame_execution_gas(&self) -> Option<u64> {
        self.frames.iter().try_fold(0u64, |total, frame| total.checked_add(frame.gas_limit))
    }

    /// Sum of all frame state gas limits, or `None` on overflow.
    pub fn sum_frame_state_gas(&self) -> Option<u64> {
        self.frames.iter().try_fold(0u64, |total, frame| total.checked_add(frame.state_gas_limit))
    }

    /// Sum of all frame gas limits across both dimensions, or `None` on
    /// overflow.
    pub fn sum_frame_gas(&self) -> Option<u64> {
        self.sum_frame_execution_gas()?.checked_add(self.sum_frame_state_gas()?)
    }

    /// `TX_VALUE_COST` for every value-bearing frame whose explicitly named
    /// target is not the sender (EIP-2780): the recipient balance write and
    /// transfer log are priced statically.
    pub fn value_transfer_cost(&self) -> Option<u64> {
        let valued = self
            .frames
            .iter()
            .filter(|frame| {
                !frame.value.is_zero()
                    && frame.target.is_some()
                    && frame.target != Some(self.sender)
            })
            .count() as u64;
        valued.checked_mul(gas::VALUE_COST)
    }

    /// Total gas cost of verifying all signature entries, or `None` on overflow
    /// or an unknown scheme.
    pub fn signature_verification_cost(&self) -> Option<u64> {
        self.signatures
            .iter()
            .try_fold(0u64, |total, sig| total.checked_add(sig.verification_cost()?))
    }

    /// Weighted calldata-token count used by the standard intrinsic: one token
    /// per zero byte and `TOKEN_PER_NON_ZERO_BYTE` per non-zero byte.
    pub fn calldata_tokens(&self) -> Option<u64> {
        fn tokens_in(bytes: &[u8]) -> u64 {
            #[allow(clippy::naive_bytecount)] // not worth a dependency for calldata-sized inputs
            let zero = bytes.iter().filter(|b| **b == 0).count() as u64;
            zero + (bytes.len() as u64 - zero) * gas::TOKEN_PER_NON_ZERO_BYTE
        }

        let mut total = 0u64;
        for frame in &self.frames {
            total = total.checked_add(tokens_in(&frame.data))?;
        }
        for sig in &self.signatures {
            for field in [&sig.signer, &sig.msg, &sig.signature] {
                total = total.checked_add(tokens_in(field))?;
            }
        }
        Some(total)
    }

    /// Uniform calldata-token count used by the EIP-7976 floor: every charged
    /// byte contributes `TOKEN_PER_NON_ZERO_BYTE` tokens, regardless of value.
    pub fn calldata_floor_tokens(&self) -> Option<u64> {
        let bytes = self
            .frames
            .iter()
            .try_fold(0u64, |total, frame| total.checked_add(frame.data.len() as u64))?;
        let bytes = self.signatures.iter().try_fold(bytes, |total, sig| {
            [&sig.signer, &sig.msg, &sig.signature]
                .into_iter()
                .try_fold(total, |total, field| total.checked_add(field.len() as u64))
        })?;
        bytes.checked_mul(gas::TOKEN_PER_NON_ZERO_BYTE)
    }

    /// `frame_tx_intrinsic_gas` in the EIP-2780 sense: derivable from the
    /// transaction fields alone, charged entirely in the execution dimension.
    pub fn intrinsic_gas(&self) -> Option<u64> {
        let base = (self.frames.len() as u64)
            .checked_mul(gas::PER_FRAME_COST)?
            .checked_add(gas::INTRINSIC_COST)?
            .checked_add(self.signature_verification_cost()?)?
            .checked_add(self.value_transfer_cost()?)?;
        base.checked_add(self.calldata_tokens()?.checked_mul(gas::STANDARD_TOKEN_COST)?)
    }

    /// Computes `(standard_gas_limit, calldata_floor_gas, max_gas)`.
    ///
    /// The standard limit is the intrinsic gas plus the sum of every frame's
    /// execution and state gas limits. The floor shares the intrinsic base but
    /// charges `COST_FLOOR_PER_TOKEN` against a uniform four-token count for
    /// every charged byte, and excludes frame gas. `max_gas` compares the floor
    /// with the declared state budgets added, since state gas never absorbs into
    /// the data floor.
    pub fn gas_limits(&self) -> Option<(u64, u64, u64)> {
        let base = (self.frames.len() as u64)
            .checked_mul(gas::PER_FRAME_COST)?
            .checked_add(gas::INTRINSIC_COST)?
            .checked_add(self.signature_verification_cost()?)?
            .checked_add(self.value_transfer_cost()?)?;
        let standard_tokens = self.calldata_tokens()?;
        let floor_tokens = self.calldata_floor_tokens()?;

        let standard = base
            .checked_add(standard_tokens.checked_mul(gas::STANDARD_TOKEN_COST)?)?
            .checked_add(self.sum_frame_gas()?)?;
        let floor = base.checked_add(floor_tokens.checked_mul(gas::COST_FLOOR_PER_TOKEN)?)?;
        let max_gas = standard.max(floor.checked_add(self.sum_frame_state_gas()?)?);
        Some((standard, floor, max_gas))
    }

    /// Maximum gas the transaction may consume, saturating to `u64::MAX` when
    /// the figures overflow. Overflow makes the transaction invalid, which
    /// validation reports separately; saturating here keeps the value monotonic
    /// so a block gas check rejects it either way.
    pub fn max_gas(&self) -> u64 {
        self.gas_limits().map_or(u64::MAX, |(_, _, max_gas)| max_gas)
    }

    /// Total blob gas the transaction consumes.
    pub const fn blob_gas(&self) -> u64 {
        DATA_GAS_PER_BLOB * self.blob_versioned_hashes.len() as u64
    }

    /// Performs the static validity checks on the envelope (EIP-8141
    /// `validate_frame_tx`).
    ///
    /// This is everything that can be decided without touching state, so a
    /// malformed envelope can be rejected at the RPC boundary before it ever
    /// reaches the pool.
    pub fn validate(&self) -> Result<(), FrameTxError> {
        if self.frames.is_empty() || self.frames.len() > gas::MAX_FRAMES {
            return Err(FrameTxError::FrameCount(self.frames.len()));
        }
        let max_u128 = U256::from(u128::MAX);
        if self.max_priority_fee_per_gas > max_u128 {
            return Err(FrameTxError::MaxPriorityFeePerGasOverflow);
        }
        if self.max_fee_per_gas > max_u128 {
            return Err(FrameTxError::MaxFeePerGasOverflow);
        }
        if self.max_fee_per_blob_gas > max_u128 {
            return Err(FrameTxError::MaxFeePerBlobGasOverflow);
        }
        if self.max_priority_fee_per_gas > self.max_fee_per_gas {
            return Err(FrameTxError::PriorityFeeAboveMaxFee);
        }
        // EIP-4844 blob constraints. The frame path does not run the ordinary
        // pre-check, so the versioned hashes have to be validated here.
        for (i, hash) in self.blob_versioned_hashes.iter().enumerate() {
            if hash[0] != VERSIONED_HASH_VERSION_KZG {
                return Err(FrameTxError::BlobHashVersion(i));
            }
        }
        if self.blob_versioned_hashes.is_empty() && !self.max_fee_per_blob_gas.is_zero() {
            return Err(FrameTxError::BlobFeeWithoutBlobs);
        }

        for sig in &self.signatures {
            match sig.scheme {
                scheme::SECP256K1 | scheme::P256 => {
                    if !sig.signer.is_empty() && sig.signer.len() != 20 {
                        return Err(FrameTxError::SignerLength(sig.signer.len()));
                    }
                }
                scheme::ARBITRARY => {
                    if !sig.signer.is_empty() {
                        return Err(FrameTxError::ArbitrarySignerNotEmpty);
                    }
                }
                other => return Err(FrameTxError::SignatureScheme(other)),
            }
            if !sig.msg.is_empty() && sig.msg.len() != 32 {
                return Err(FrameTxError::MsgLength(sig.msg.len()));
            }
        }

        let mut total_frame_gas = 0u64;
        let mut expiry_frames = 0;
        for (i, frame) in self.frames.iter().enumerate() {
            if frame.mode > mode::SENDER || frame.flags >= 8 {
                return Err(FrameTxError::ModeOrFlags { index: i });
            }
            if frame.mode != mode::SENDER && !frame.value.is_zero() {
                return Err(FrameTxError::ValueOnNonSenderFrame { index: i });
            }
            total_frame_gas = total_frame_gas
                .checked_add(frame.gas_limit)
                .and_then(|total| total.checked_add(frame.state_gas_limit))
                .ok_or(FrameTxError::GasOverflow)?;

            // Approval of execution is only allowed when the target is null or
            // the sender: nothing else may authorise the sender's execution.
            if frame.flags & flags::APPROVE_EXECUTION != 0
                && frame.target.is_some_and(|target| target != self.sender)
            {
                return Err(FrameTxError::ApproveExecutionTarget { index: i });
            }

            // An atomic batch flag requires a subsequent non-VERIFY frame.
            if frame.flags & flags::ATOMIC_BATCH != 0 {
                if frame.mode == mode::VERIFY {
                    return Err(FrameTxError::AtomicBatchOnVerify { index: i });
                }
                if self.frames.get(i + 1).is_none_or(|next| next.mode == mode::VERIFY) {
                    return Err(FrameTxError::AtomicBatchTerminator { index: i });
                }
            }

            // A frame belongs to a batch when it or its predecessor carries the
            // flag; batch frames may not carry approval scope, which keeps the
            // approval context constant across a batch unroll.
            let in_batch = frame.flags & flags::ATOMIC_BATCH != 0
                || (i > 0 && self.frames[i - 1].flags & flags::ATOMIC_BATCH != 0);
            if in_batch && frame.flags & flags::APPROVE_EXECUTION_PAYMENT != 0 {
                return Err(FrameTxError::ApproveScopeInBatch { index: i });
            }

            // An expiry verifier frame must carry exactly an 8-byte deadline,
            // no flags and no state budget, and at most one may appear per
            // transaction.
            if frame.is_expiry_verifier() {
                expiry_frames += 1;
                if expiry_frames > 1 {
                    return Err(FrameTxError::MultipleExpiryFrames);
                }
                if frame.flags != 0
                    || frame.state_gas_limit != 0
                    || frame.data.len() != gas::EXPIRY_DATA_LENGTH
                {
                    return Err(FrameTxError::MalformedExpiryFrame { index: i });
                }
            }
        }

        // Overflowing gas figures make the transaction invalid.
        let (_, floor, _) = self.gas_limits().ok_or(FrameTxError::GasOverflow)?;

        // EIP-7825: the execution budget must fit the transaction gas cap.
        // State gas is excluded; it is bounded by block state-gas capacity.
        let execution_budget = self
            .intrinsic_gas()
            .and_then(|intrinsic| intrinsic.checked_add(self.sum_frame_execution_gas()?))
            .ok_or(FrameTxError::GasOverflow)?;
        if execution_budget.max(floor) > gas::TX_MAX_GAS_LIMIT {
            return Err(FrameTxError::GasCapExceeded);
        }
        Ok(())
    }

    /// Validates every signature entry against the canonical signature hash.
    ///
    /// Call after [`TxFrame::validate`], which establishes the structural
    /// invariants this relies on.
    pub fn validate_signatures(&self) -> Result<(), FrameTxError> {
        let sig_hash = self.signature_hash();
        for (i, sig) in self.signatures.iter().enumerate() {
            if !self.validate_signature(sig, sig_hash) {
                return Err(FrameTxError::InvalidSignature { index: i });
            }
        }
        Ok(())
    }

    /// Validates a single signature entry against `sig_hash` (EIP-8141
    /// `validate_signature`). Reports whether the entry is structurally valid
    /// and, for protocol-validated schemes, cryptographically valid.
    pub fn validate_signature(&self, sig: &FrameSignature, sig_hash: B256) -> bool {
        // An empty msg signs the canonical hash; an explicit one must be a
        // non-zero 32-byte digest.
        let msg = match sig.msg.len() {
            0 => sig_hash,
            32 if sig.msg.iter().any(|b| *b != 0) => B256::from_slice(&sig.msg),
            _ => return false,
        };
        let Some(resolved) = sig.resolved_signer(self.sender) else { return false };

        match sig.scheme {
            scheme::SECP256K1 => verify_secp256k1(&sig.signature, msg, resolved),
            scheme::P256 => verify_p256(&sig.signature, msg, resolved),
            // An ARBITRARY entry is interpreted by the frame code, not the
            // protocol; it is only required to name no signer.
            scheme::ARBITRARY => sig.signer.is_empty(),
            _ => false,
        }
    }
}

/// secp256k1 group order, and its halved value for the low-s check.
const SECP256K1_N: U256 = U256::from_be_bytes(alloy_primitives::hex!(
    "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
));
/// P256 (secp256r1) group order.
const SECP256R1_N: U256 = U256::from_be_bytes(alloy_primitives::hex!(
    "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
));

/// Verifies a secp256k1 entry, whose 65 bytes are encoded `v || r || s` with
/// `v` the recovery id (0 or 1) -- note this is *not* the usual `r || s || v`.
fn verify_secp256k1(signature: &[u8], msg: B256, resolved: Address) -> bool {
    if signature.len() != 65 {
        return false;
    }
    let v = signature[0];
    let r = U256::from_be_slice(&signature[1..33]);
    let s = U256::from_be_slice(&signature[33..65]);

    // r and s must be canonical, and s low. revm's ecrecover silently
    // normalises a high s, so rejecting it here is what keeps malleable
    // signatures out rather than merely re-encoding them.
    if v > 1 || r.is_zero() || s.is_zero() || r >= SECP256K1_N || s > SECP256K1_N / U256::from(2u8)
    {
        return false;
    }

    // ecrecover expects `r || s`, with the recovery id passed separately.
    let mut rs = [0u8; 64];
    rs.copy_from_slice(&signature[1..65]);
    match revm::precompile::secp256k1::ecrecover(&rs.into(), v, &msg) {
        // The returned word is keccak256(pubkey) whose low 20 bytes are the address.
        Ok(word) => Address::from_slice(&word[12..]) == resolved,
        Err(_) => false,
    }
}

/// Verifies a P256 entry, whose 128 bytes are encoded `r || s || qx || qy`.
fn verify_p256(signature: &[u8], msg: B256, resolved: Address) -> bool {
    if signature.len() != 128 {
        return false;
    }
    let r = U256::from_be_slice(&signature[0..32]);
    let s = U256::from_be_slice(&signature[32..64]);
    if r.is_zero() || s.is_zero() || r >= SECP256R1_N || s > SECP256R1_N / U256::from(2u8) {
        return false;
    }
    let qx = &signature[64..96];
    let qy = &signature[96..128];
    if qx.iter().chain(qy).all(|b| *b == 0) {
        return false;
    }
    // The signer address must be keccak256(qx || qy)[12..].
    if Address::from_slice(&keccak256(&signature[64..128])[12..]) != resolved {
        return false;
    }

    // P256VERIFY takes `msg || r || s || qx || qy`.
    let mut input = [0u8; 160];
    input[..32].copy_from_slice(msg.as_slice());
    input[32..].copy_from_slice(&signature[..128]);
    revm::precompile::secp256r1::verify_impl(&input)
}

/// Why a frame transaction envelope is invalid.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FrameTxError {
    /// The transaction has no frames, or more than `MAX_FRAMES`.
    #[error("invalid number of frames: {0}")]
    FrameCount(usize),
    /// `maxPriorityFeePerGas` cannot be represented by Alloy/REVM's fee API.
    #[error("maxPriorityFeePerGas exceeds u128::MAX")]
    MaxPriorityFeePerGasOverflow,
    /// `maxFeePerGas` cannot be represented by Alloy/REVM's fee API.
    #[error("maxFeePerGas exceeds u128::MAX")]
    MaxFeePerGasOverflow,
    /// `maxFeePerBlobGas` cannot be represented by Alloy/REVM's fee API.
    #[error("maxFeePerBlobGas exceeds u128::MAX")]
    MaxFeePerBlobGasOverflow,
    /// The priority fee exceeds the total gas fee cap.
    #[error("maxPriorityFeePerGas exceeds maxFeePerGas")]
    PriorityFeeAboveMaxFee,
    /// A blob versioned hash uses an unknown version byte.
    #[error("blob {0} has invalid hash version")]
    BlobHashVersion(usize),
    /// A non-zero blob fee with no blobs attached.
    #[error("non-zero blob fee with no blob hashes")]
    BlobFeeWithoutBlobs,
    /// A signer field that is neither empty nor a 20-byte address.
    #[error("invalid signer length: {0}")]
    SignerLength(usize),
    /// An `ARBITRARY` entry named a signer, which the protocol cannot resolve.
    #[error("ARBITRARY signature must have empty signer")]
    ArbitrarySignerNotEmpty,
    /// An unknown signature scheme.
    #[error("invalid signature scheme: {0}")]
    SignatureScheme(u8),
    /// A msg field that is neither empty nor a 32-byte digest.
    #[error("invalid msg length: {0}")]
    MsgLength(usize),
    /// A frame declared an unknown mode or reserved flag bits.
    #[error("frame {index} has invalid mode or flags")]
    ModeOrFlags {
        /// Index of the offending frame.
        index: usize,
    },
    /// Only a `SENDER` frame may transfer value.
    #[error("frame {index} has non-zero value on a non-SENDER frame")]
    ValueOnNonSenderFrame {
        /// Index of the offending frame.
        index: usize,
    },
    /// A frame claiming `APPROVE_EXECUTION` targeted something other than the sender.
    #[error("frame {index}: APPROVE_EXECUTION target must be the sender")]
    ApproveExecutionTarget {
        /// Index of the offending frame.
        index: usize,
    },
    /// A `VERIFY` frame cannot take part in an atomic batch.
    #[error("frame {index}: atomic batch on a VERIFY frame")]
    AtomicBatchOnVerify {
        /// Index of the offending frame.
        index: usize,
    },
    /// An atomic batch must be closed by a following non-`VERIFY` frame.
    #[error("frame {index}: atomic batch must be followed by a non-VERIFY frame")]
    AtomicBatchTerminator {
        /// Index of the offending frame.
        index: usize,
    },
    /// A frame inside an atomic batch carried approval scope flags.
    #[error("frame {index}: approval scope inside an atomic batch")]
    ApproveScopeInBatch {
        /// Index of the offending frame.
        index: usize,
    },
    /// At most one expiry verifier frame may appear per transaction.
    #[error("multiple expiry verifier frames")]
    MultipleExpiryFrames,
    /// An expiry verifier frame carried flags or a deadline of the wrong length.
    #[error("malformed expiry verifier frame {index}")]
    MalformedExpiryFrame {
        /// Index of the offending frame.
        index: usize,
    },
    /// The declared gas figures do not fit in 64 bits.
    #[error("frame transaction gas overflow")]
    GasOverflow,
    /// The execution budget exceeds the EIP-7825 transaction gas cap.
    #[error("execution budget exceeds TX_MAX_GAS_LIMIT")]
    GasCapExceeded,
    /// A signature entry failed structural or cryptographic validation.
    #[error("signature {index} invalid")]
    InvalidSignature {
        /// Index of the offending entry.
        index: usize,
    },
}

impl Sealable for TxFrame {
    /// The transaction hash: `keccak256(0x06 || rlp(payload))`.
    fn hash_slow(&self) -> B256 {
        let mut buf = Vec::with_capacity(1 + self.payload_length_with_header());
        buf.put_u8(FRAME_TX_TYPE_ID);
        self.encode_payload(&mut buf);
        keccak256(&buf)
    }
}

impl Typed2718 for TxFrame {
    fn ty(&self) -> u8 {
        FRAME_TX_TYPE_ID
    }
}

impl Encodable2718 for TxFrame {
    fn encode_2718_len(&self) -> usize {
        1 + self.payload_length_with_header()
    }

    fn encode_2718(&self, out: &mut dyn BufMut) {
        out.put_u8(FRAME_TX_TYPE_ID);
        self.encode_payload(out);
    }
}

impl Decodable2718 for TxFrame {
    fn typed_decode(ty: u8, buf: &mut &[u8]) -> Eip2718Result<Self> {
        if ty != FRAME_TX_TYPE_ID {
            return Err(Eip2718Error::UnexpectedType(ty));
        }
        Ok(Self::decode_payload(buf)?)
    }

    fn fallback_decode(_buf: &mut &[u8]) -> Eip2718Result<Self> {
        // A frame transaction is always typed; there is no legacy form.
        Err(Eip2718Error::UnexpectedType(FRAME_TX_TYPE_ID))
    }
}

/// Narrows a wire fee for Alloy's generic transaction accessors.
///
/// Accepted frame transactions are validated to fit exactly in `u128`; raw
/// callers may inspect an unvalidated envelope, so the public trait surface must
/// remain total rather than panic on malformed input.
fn saturating_fee_u128(value: U256) -> u128 {
    u128::try_from(value).unwrap_or(u128::MAX)
}

impl Transaction for TxFrame {
    fn chain_id(&self) -> Option<ChainId> {
        ChainId::try_from(self.chain_id).ok()
    }

    fn nonce(&self) -> u64 {
        self.nonce
    }

    /// A frame transaction has no explicit gas field; the limit is derived from
    /// the frames and signatures.
    fn gas_limit(&self) -> u64 {
        self.max_gas()
    }

    fn gas_price(&self) -> Option<u128> {
        None
    }

    fn max_fee_per_gas(&self) -> u128 {
        saturating_fee_u128(self.max_fee_per_gas)
    }

    fn max_priority_fee_per_gas(&self) -> Option<u128> {
        Some(saturating_fee_u128(self.max_priority_fee_per_gas))
    }

    fn max_fee_per_blob_gas(&self) -> Option<u128> {
        Some(saturating_fee_u128(self.max_fee_per_blob_gas))
    }

    fn priority_fee_or_price(&self) -> u128 {
        saturating_fee_u128(self.max_priority_fee_per_gas)
    }

    fn effective_gas_price(&self, base_fee: Option<u64>) -> u128 {
        let max_fee = self.max_fee_per_gas();
        let Some(base_fee) = base_fee.map(u128::from) else { return max_fee };
        base_fee.saturating_add(
            self.max_priority_fee_per_gas()
                .unwrap_or_default()
                .min(max_fee.saturating_sub(base_fee)),
        )
    }

    fn is_dynamic_fee(&self) -> bool {
        true
    }

    /// A frame transaction has no single call target; each frame carries its
    /// own. It is never a create.
    fn kind(&self) -> TxKind {
        TxKind::Call(self.sender)
    }

    fn is_create(&self) -> bool {
        false
    }

    fn value(&self) -> U256 {
        U256::ZERO
    }

    /// A frame transaction has no top-level calldata; each frame carries its own.
    fn input(&self) -> &Bytes {
        static EMPTY: std::sync::LazyLock<Bytes> = std::sync::LazyLock::new(Bytes::new);
        &EMPTY
    }

    fn access_list(&self) -> Option<&alloy_eips::eip2930::AccessList> {
        None
    }

    fn blob_versioned_hashes(&self) -> Option<&[B256]> {
        Some(&self.blob_versioned_hashes)
    }

    fn authorization_list(&self) -> Option<&[SignedAuthorization]> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal single-frame transaction: a DEFAULT frame with no target.
    fn sample() -> TxFrame {
        TxFrame {
            chain_id: U256::from(31337u64),
            nonce: 7,
            sender: Address::repeat_byte(0x11),
            frames: vec![
                Frame {
                    mode: mode::VERIFY,
                    flags: flags::APPROVE_EXECUTION_PAYMENT,
                    target: None,
                    gas_limit: 50_000,
                    state_gas_limit: 0,
                    value: U256::ZERO,
                    data: Bytes::from_static(b"\x01\x02\x00\x03"),
                },
                Frame {
                    mode: mode::SENDER,
                    flags: 0,
                    target: Some(Address::repeat_byte(0x22)),
                    gas_limit: 21_000,
                    state_gas_limit: 200_000,
                    value: U256::from(1_000u64),
                    data: Bytes::new(),
                },
            ],
            signatures: vec![FrameSignature {
                scheme: scheme::SECP256K1,
                signer: Bytes::new(),
                msg: Bytes::new(),
                signature: Bytes::from(vec![0xAB; 65]),
            }],
            max_priority_fee_per_gas: U256::from(1_000_000_000u64),
            max_fee_per_gas: U256::from(2_000_000_000u64),
            max_fee_per_blob_gas: U256::ZERO,
            blob_versioned_hashes: vec![],
        }
    }

    /// Pinned wire vector for the transaction built by `sample()`, under the
    /// master-spec envelope (`fees` and `limits` sublists). The previous
    /// go-ethereum cross-check (`leekt/go-ethereum@fix/eip8141-frame-tx`)
    /// implements the pinned envelope and predates this format; regenerate the
    /// cross-check once the reference adopts the new wire format. If the RLP
    /// field order, the null-target encoding or the sig-hash eliding drifts,
    /// this test breaks.
    const REFERENCE_RAW: &str = "06f8a4827a6907941111111111111111111111111111111111111111f3ce010380c482c35080808401020003e30280942222222222222222222222222222222222222222c782520883030d408203e880f848f846018080b841abababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababcb843b9aca00847735940080c0";
    const REFERENCE_TX_HASH: &str =
        "0x274786f735c1d5f8cf673a4865d25e5c83aa72805d1668d65b48f89e5a221ff4";
    const REFERENCE_SIG_HASH: &str =
        "0x23d97c249576b62ed4d31a1e331af99cea9fcc6910ed9c1dd2b57d03cd6bb9ed";

    #[test]
    fn encoding_matches_the_pinned_vector() {
        let tx = sample();

        let mut encoded = Vec::new();
        tx.encode_2718(&mut encoded);
        assert_eq!(alloy_primitives::hex::encode(&encoded), REFERENCE_RAW);

        assert_eq!(tx.hash_slow(), REFERENCE_TX_HASH.parse::<B256>().unwrap());
        assert_eq!(tx.signature_hash(), REFERENCE_SIG_HASH.parse::<B256>().unwrap());
    }

    #[test]
    fn decoding_the_reference_vector_reproduces_the_transaction() {
        let raw = alloy_primitives::hex::decode(REFERENCE_RAW).unwrap();
        let decoded = TxFrame::decode_2718_exact(raw.as_slice()).unwrap();
        assert_eq!(decoded, sample());
    }

    /// A fully signed single-frame transaction over the master-spec envelope,
    /// signed with anvil's first dev key
    /// (`0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80`)
    /// over the canonical signature hash of `signed_sample()`. Encoded
    /// `v || r || s` with `v` the recovery id.
    const SIGNED_SIGNATURE: &str = "0106834df11a4f16c17824695a77de51ae3d12f2a6946f1c056be75d1b6228259a28420899b8e8b16652ee694b4a6fd6551717c456a7d51fa348abb2cdf8c8f399";
    const SIGNED_RAW: &str = "06f87c827a698094f39fd6e51aad88f6f4ce6ab8827279cfffb92266cbca010380c482c350808080f848f846018080b8410106834df11a4f16c17824695a77de51ae3d12f2a694\
6f1c056be75d1b6228259a28420899b8e8b16652ee694b4a6fd6551717c456a7d51fa348abb2cdf8c8f399cb843b9aca00847735940080c0";
    const SIGNED_SENDER: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
    const SIGNED_SIG_HASH: &str =
        "0x10db3f07e098246cdf4056883c5a2754d90dff087c410b2bbc3af2a75891c7d9";

    /// The signed vector's envelope: one self-verifying frame, no state gas.
    fn signed_sample() -> TxFrame {
        TxFrame {
            chain_id: U256::from(31337u64),
            nonce: 0,
            sender: SIGNED_SENDER.parse().unwrap(),
            frames: vec![Frame {
                mode: mode::VERIFY,
                flags: flags::APPROVE_EXECUTION_PAYMENT,
                target: None,
                gas_limit: 50_000,
                state_gas_limit: 0,
                value: U256::ZERO,
                data: Bytes::new(),
            }],
            signatures: vec![FrameSignature {
                scheme: scheme::SECP256K1,
                signer: Bytes::new(),
                msg: Bytes::new(),
                signature: alloy_primitives::hex::decode(SIGNED_SIGNATURE)
                    .unwrap_or_else(|_| vec![0xAB; 65])
                    .into(),
            }],
            max_priority_fee_per_gas: U256::from(1_000_000_000u64),
            max_fee_per_gas: U256::from(2_000_000_000u64),
            max_fee_per_blob_gas: U256::ZERO,
            blob_versioned_hashes: vec![],
        }
    }

    fn signed_vector() -> TxFrame {
        let raw = alloy_primitives::hex::decode(SIGNED_RAW).unwrap();
        TxFrame::decode_2718_exact(raw.as_slice()).unwrap()
    }

    #[test]
    fn accepts_the_reference_signed_transaction() {
        let tx = signed_vector();

        assert_eq!(tx, signed_sample());
        assert_eq!(tx.sender, SIGNED_SENDER.parse::<Address>().unwrap());
        assert_eq!(tx.signature_hash(), SIGNED_SIG_HASH.parse::<B256>().unwrap());

        tx.validate().expect("reference envelope must be valid");
        tx.validate_signatures().expect("reference signature must verify");
    }

    #[test]
    fn rejects_a_signature_over_a_different_hash() {
        // Flipping a byte the signature commits to moves the canonical hash, so
        // the recovered signer no longer matches the declared sender.
        let mut tx = signed_vector();
        tx.nonce += 1;
        assert_eq!(tx.validate_signatures(), Err(FrameTxError::InvalidSignature { index: 0 }));
    }

    #[test]
    fn rejects_a_signature_in_r_s_v_order() {
        // EIP-8141 encodes secp256k1 as v || r || s. Re-encoding the same
        // signature as r || s || v must not verify, or the port would silently
        // accept the wrong layout.
        let tx = signed_vector();
        let vrs = tx.signatures[0].signature.clone();
        let mut rsv = Vec::with_capacity(65);
        rsv.extend_from_slice(&vrs[1..65]);
        rsv.push(vrs[0]);

        let mut mutated = tx.clone();
        mutated.signatures[0].signature = rsv.into();
        // The sig hash elides these bytes, so the digest is unchanged and only
        // the layout differs.
        assert_eq!(mutated.signature_hash(), tx.signature_hash());
        assert!(mutated.validate_signatures().is_err());
    }

    #[test]
    fn rejects_a_high_s_signature() {
        // revm's ecrecover silently normalises a high s; the low-s check is
        // what actually keeps malleable signatures out.
        let tx = signed_vector();
        let sig = tx.signatures[0].signature.clone();
        let s = U256::from_be_slice(&sig[33..65]);
        let flipped_s = SECP256K1_N - s;

        let mut malleable = Vec::with_capacity(65);
        malleable.push(sig[0] ^ 1); // the flipped s pairs with the other parity
        malleable.extend_from_slice(&sig[1..33]);
        malleable.extend_from_slice(&flipped_s.to_be_bytes::<32>());

        let mut mutated = tx.clone();
        mutated.signatures[0].signature = malleable.into();
        assert!(mutated.validate_signatures().is_err());
    }

    /// Daimo's first EIP-7951 vector, split as
    /// `msg || r || s || qx || qy`. EIP-8141 carries the last four words in
    /// the signature field and resolves the signer from `keccak256(qx || qy)`.
    const P256_VECTOR: &str = "4cee90eb86eaa050036147a12d49004b6b9c72bd725d39d4785011fe190f0b4da73bd4903f0ce3b639bbbf6e8e80d16931ff4bcf5993d58468e8fb19086e8cac36dbcd03009df8c59286b162af3bd7fcc0450c9aa81be5d10d312af6c66b1d604aebd3099c618202fcfe16ae7770b0c49ab5eadf74b754204a3bb6060e44eff37618b065f9832de4ca6ca971a7a1adc826d0f7c00181a5fb2ddf79ae00b4e10e";

    fn p256_vector() -> (FrameSignature, B256) {
        let input = alloy_primitives::hex::decode(P256_VECTOR).unwrap();
        let msg = B256::from_slice(&input[..32]);
        let resolved = Address::from_slice(&keccak256(&input[96..160])[12..]);
        let signature = FrameSignature {
            scheme: scheme::P256,
            signer: Bytes::copy_from_slice(resolved.as_slice()),
            msg: Bytes::new(),
            signature: Bytes::copy_from_slice(&input[32..]),
        };
        (signature, msg)
    }

    #[test]
    fn accepts_a_canonical_p256_wire_signature() {
        let (signature, canonical_hash) = p256_vector();
        assert!(sample().validate_signature(&signature, canonical_hash));
    }

    #[test]
    fn rejects_p256_wrong_hash_signer_and_wire_length() {
        let (signature, canonical_hash) = p256_vector();
        let tx = sample();

        assert!(!tx.validate_signature(&signature, B256::repeat_byte(0x42)));

        let mut wrong_signer = signature.clone();
        wrong_signer.signer = Bytes::from(vec![0x42; 20]);
        assert!(!tx.validate_signature(&wrong_signer, canonical_hash));

        let mut short = signature;
        short.signature = Bytes::copy_from_slice(&short.signature[..127]);
        assert!(!tx.validate_signature(&short, canonical_hash));
    }

    #[test]
    fn rejects_a_high_s_p256_signature_from_the_pinned_profile() {
        let (mut signature, canonical_hash) = p256_vector();
        let s = U256::from_be_slice(&signature.signature[32..64]);
        let high_s = SECP256R1_N - s;
        let mut high_s_signature = signature.signature.to_vec();
        high_s_signature[32..64].copy_from_slice(&high_s.to_be_bytes::<32>());
        signature.signature = high_s_signature.into();

        // EIP-7951 verifies both forms, but the toolkit's pinned EIP-8141
        // profile requires the unique low-s encoding before frame execution.
        assert!(!sample().validate_signature(&signature, canonical_hash));
    }

    #[test]
    fn validate_rejects_malformed_envelopes() {
        let base = signed_vector();

        let mut no_frames = base.clone();
        no_frames.frames.clear();
        assert_eq!(no_frames.validate(), Err(FrameTxError::FrameCount(0)));

        let mut too_many = base.clone();
        too_many.frames = vec![base.frames[0].clone(); gas::MAX_FRAMES + 1];
        assert_eq!(too_many.validate(), Err(FrameTxError::FrameCount(gas::MAX_FRAMES + 1)));

        let mut bad_mode = base.clone();
        bad_mode.frames[0].mode = 3;
        assert_eq!(bad_mode.validate(), Err(FrameTxError::ModeOrFlags { index: 0 }));

        // Only a SENDER frame may carry value.
        let mut valued_verify = base.clone();
        valued_verify.frames[0].value = U256::from(1u8);
        assert_eq!(valued_verify.validate(), Err(FrameTxError::ValueOnNonSenderFrame { index: 0 }));

        // APPROVE_EXECUTION may only target the sender.
        let mut foreign_approval = base.clone();
        foreign_approval.frames[0].target = Some(Address::repeat_byte(0x99));
        assert_eq!(
            foreign_approval.validate(),
            Err(FrameTxError::ApproveExecutionTarget { index: 0 })
        );

        // An atomic batch may not sit on a VERIFY frame.
        let mut batched_verify = base.clone();
        batched_verify.frames[0].flags |= flags::ATOMIC_BATCH;
        assert_eq!(batched_verify.validate(), Err(FrameTxError::AtomicBatchOnVerify { index: 0 }));

        // A batch flag on the last frame has no terminator.
        let mut dangling_batch = base.clone();
        dangling_batch.frames[0].mode = mode::SENDER;
        dangling_batch.frames[0].flags = flags::ATOMIC_BATCH;
        assert_eq!(
            dangling_batch.validate(),
            Err(FrameTxError::AtomicBatchTerminator { index: 0 })
        );

        // Scheme 3 is reserved. Alternative and post-quantum signatures must
        // be carried explicitly as ARBITRARY bytes and interpreted by frame
        // code.
        let mut reserved_scheme = base.clone();
        reserved_scheme.signatures[0].scheme = 3;
        assert_eq!(reserved_scheme.signatures[0].verification_cost(), None);
        assert_eq!(reserved_scheme.validate(), Err(FrameTxError::SignatureScheme(3)));

        let mut unknown_scheme = base.clone();
        unknown_scheme.signatures[0].scheme = 9;
        assert_eq!(unknown_scheme.validate(), Err(FrameTxError::SignatureScheme(9)));

        let mut named_arbitrary = base.clone();
        named_arbitrary.signatures[0].scheme = scheme::ARBITRARY;
        named_arbitrary.signatures[0].signer = Bytes::from(vec![0x11; 20]);
        assert_eq!(named_arbitrary.validate(), Err(FrameTxError::ArbitrarySignerNotEmpty));

        let mut bad_msg = base.clone();
        bad_msg.signatures[0].msg = Bytes::from(vec![0x11; 31]);
        assert_eq!(bad_msg.validate(), Err(FrameTxError::MsgLength(31)));

        let mut blob_fee = base.clone();
        blob_fee.max_fee_per_blob_gas = U256::from(1u8);
        assert_eq!(blob_fee.validate(), Err(FrameTxError::BlobFeeWithoutBlobs));

        // Blob count is fork-dependent and is enforced by the pool against the
        // active BlobParams, not by this fork-agnostic envelope validation.
        let mut fork_dependent_blob_count = base.clone();
        fork_dependent_blob_count.blob_versioned_hashes = vec![B256::repeat_byte(0x01); 7];
        fork_dependent_blob_count.validate().unwrap();

        // The unmodified vector must still pass, or the cases above prove nothing.
        base.validate().unwrap();
    }

    #[test]
    fn validate_rejects_fees_that_tx_env_cannot_represent() {
        let base = signed_vector();
        let overflow = U256::from(u128::MAX) + U256::ONE;

        let mut priority_overflow = base.clone();
        priority_overflow.max_priority_fee_per_gas = overflow;
        assert_eq!(priority_overflow.validate(), Err(FrameTxError::MaxPriorityFeePerGasOverflow));

        let mut max_fee_overflow = base.clone();
        max_fee_overflow.max_fee_per_gas = overflow;
        assert_eq!(max_fee_overflow.validate(), Err(FrameTxError::MaxFeePerGasOverflow));

        let mut blob_fee_overflow = base.clone();
        blob_fee_overflow.max_fee_per_blob_gas = overflow;
        assert_eq!(blob_fee_overflow.validate(), Err(FrameTxError::MaxFeePerBlobGasOverflow));

        let mut priority_above_max = base.clone();
        priority_above_max.max_priority_fee_per_gas = U256::from(2);
        priority_above_max.max_fee_per_gas = U256::ONE;
        assert_eq!(priority_above_max.validate(), Err(FrameTxError::PriorityFeeAboveMaxFee));

        let mut max_supported = base;
        max_supported.max_priority_fee_per_gas = U256::from(u128::MAX);
        max_supported.max_fee_per_gas = U256::from(u128::MAX);
        max_supported.max_fee_per_blob_gas = U256::from(u128::MAX);
        max_supported.blob_versioned_hashes = vec![B256::repeat_byte(VERSIONED_HASH_VERSION_KZG)];
        max_supported.validate().unwrap();
        assert_eq!(max_supported.max_priority_fee_per_gas(), Some(u128::MAX));
        assert_eq!(max_supported.max_fee_per_gas(), u128::MAX);
        assert_eq!(max_supported.max_fee_per_blob_gas(), Some(u128::MAX));
    }

    #[test]
    fn unvalidated_fee_accessors_saturate_instead_of_panicking() {
        let overflow = U256::from(u128::MAX) + U256::ONE;
        let tx = TxFrame {
            max_priority_fee_per_gas: overflow,
            max_fee_per_gas: U256::MAX,
            max_fee_per_blob_gas: overflow,
            ..Default::default()
        };

        assert_eq!(tx.max_priority_fee_per_gas(), Some(u128::MAX));
        assert_eq!(tx.max_fee_per_gas(), u128::MAX);
        assert_eq!(tx.max_fee_per_blob_gas(), Some(u128::MAX));
        assert_eq!(tx.priority_fee_or_price(), u128::MAX);
        assert_eq!(tx.effective_gas_price(Some(u64::MAX)), u128::MAX);
    }

    #[test]
    fn an_all_zero_explicit_msg_is_rejected() {
        let mut tx = signed_vector();
        tx.signatures[0].msg = Bytes::from(vec![0u8; 32]);
        // Structurally a 32-byte msg is fine, but the zero digest is not.
        tx.validate().unwrap();
        assert!(tx.validate_signatures().is_err());
    }

    #[test]
    fn arbitrary_signature_bytes_are_left_to_frame_code() {
        let mut tx = signed_vector();
        tx.signatures[0] = FrameSignature {
            scheme: scheme::ARBITRARY,
            signer: Bytes::new(),
            msg: Bytes::new(),
            // Large post-quantum signatures are opaque protocol payloads.
            signature: Bytes::from(vec![0xa5; 3_732]),
        };

        assert_eq!(tx.signatures[0].verification_cost(), Some(gas::SIGNATURE_ARBITRARY));
        tx.validate().unwrap();
        tx.validate_signatures().unwrap();
    }

    #[test]
    fn rlp_round_trip_preserves_every_field() {
        let tx = sample();
        let mut encoded = Vec::new();
        tx.encode_2718(&mut encoded);

        assert_eq!(encoded[0], FRAME_TX_TYPE_ID);
        assert_eq!(encoded.len(), tx.encode_2718_len());

        let decoded = TxFrame::decode_2718(&mut encoded.as_slice()).unwrap();
        assert_eq!(decoded, tx);
    }

    #[test]
    fn absent_target_round_trips_as_none() {
        let tx = sample();
        let mut encoded = Vec::new();
        tx.encode_2718(&mut encoded);
        let decoded = TxFrame::decode_2718(&mut encoded.as_slice()).unwrap();

        assert_eq!(decoded.frames[0].target, None);
        assert_eq!(decoded.frames[1].target, Some(Address::repeat_byte(0x22)));
        // A null target resolves to the sender.
        assert_eq!(decoded.frames[0].resolved_target(decoded.sender), decoded.sender);
    }

    #[test]
    fn signature_hash_elides_raw_bytes_of_empty_msg_entries() {
        let tx = sample();
        // Changing the raw bytes of an empty-msg entry must not move the hash.
        let mut mutated = tx.clone();
        mutated.signatures[0].signature = Bytes::from(vec![0xCD; 65]);
        assert_eq!(tx.signature_hash(), mutated.signature_hash());
        // The transaction hash, which does not elide, must move.
        assert_ne!(tx.hash_slow(), mutated.hash_slow());

        // With an explicit msg the raw bytes are committed to.
        let mut explicit = tx.clone();
        explicit.signatures[0].msg = Bytes::from(vec![0x01; 32]);
        let mut explicit_mutated = explicit.clone();
        explicit_mutated.signatures[0].signature = Bytes::from(vec![0xCD; 65]);
        assert_ne!(explicit.signature_hash(), explicit_mutated.signature_hash());
    }

    #[test]
    fn value_transfer_cost_only_charges_explicit_external_targets() {
        let sender = Address::repeat_byte(0x11);
        let tx = TxFrame {
            sender,
            frames: vec![
                // A missing target resolves to the sender and does not write a
                // distinct recipient balance or emit a transfer log.
                Frame { value: U256::ONE, target: None, ..Default::default() },
                Frame { value: U256::ONE, target: Some(sender), ..Default::default() },
                Frame {
                    value: U256::ONE,
                    target: Some(Address::repeat_byte(0x22)),
                    ..Default::default()
                },
                Frame {
                    value: U256::ZERO,
                    target: Some(Address::repeat_byte(0x33)),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };

        assert_eq!(tx.value_transfer_cost(), Some(gas::VALUE_COST));
        assert_eq!(
            tx.intrinsic_gas(),
            Some(gas::INTRINSIC_COST + 4 * gas::PER_FRAME_COST + gas::VALUE_COST)
        );
    }

    #[test]
    fn gas_limits_follow_the_reference_formula() {
        let tx = sample();
        let (standard, floor, max_gas) = tx.gas_limits().unwrap();

        // 4 bytes of frame data (2 zero-ish: 0x01,0x02,0x00,0x03 -> one zero)
        // plus the 65 signature bytes, all non-zero.
        let standard_tokens = tx.calldata_tokens().unwrap();
        let floor_tokens = tx.calldata_floor_tokens().unwrap();
        assert_eq!(standard_tokens, (1 + 3 * 4) + 65 * 4);
        assert_eq!(floor_tokens, (4 + 65) * 4);

        // One value-bearing frame charges TX_VALUE_COST inside the intrinsic.
        let base = 2 * gas::PER_FRAME_COST
            + gas::INTRINSIC_COST
            + gas::SIGNATURE_SECP256K1
            + gas::VALUE_COST;
        // Frame execution limits sum to 71_000, state limits to 200_000.
        assert_eq!(standard, base + standard_tokens * gas::STANDARD_TOKEN_COST + 71_000 + 200_000);
        assert_eq!(floor, base + floor_tokens * gas::COST_FLOOR_PER_TOKEN);
        // State gas never absorbs into the data floor.
        assert_eq!(max_gas, standard.max(floor + 200_000));
        assert_eq!(tx.max_gas(), max_gas);
        assert_eq!(tx.intrinsic_gas().unwrap(), base + standard_tokens * gas::STANDARD_TOKEN_COST);
    }

    #[test]
    fn calldata_floor_prices_zero_and_nonzero_bytes_uniformly() {
        let transaction = |byte| TxFrame {
            frames: vec![Frame { data: Bytes::from(vec![byte; 2]), ..Default::default() }],
            signatures: vec![FrameSignature {
                scheme: scheme::ARBITRARY,
                signer: Bytes::new(),
                msg: Bytes::new(),
                signature: Bytes::from(vec![byte; 2]),
            }],
            ..Default::default()
        };
        let zero = transaction(0);
        let nonzero = transaction(0xff);

        assert_eq!(zero.calldata_tokens(), Some(4));
        assert_eq!(nonzero.calldata_tokens(), Some(16));
        assert_eq!(zero.calldata_floor_tokens(), Some(16));
        assert_eq!(nonzero.calldata_floor_tokens(), Some(16));

        let base = gas::INTRINSIC_COST + gas::PER_FRAME_COST + gas::SIGNATURE_ARBITRARY;
        assert_eq!(zero.intrinsic_gas(), Some(base + 4 * gas::STANDARD_TOKEN_COST));
        assert_eq!(nonzero.intrinsic_gas(), Some(base + 16 * gas::STANDARD_TOKEN_COST));
        assert_eq!(zero.gas_limits().unwrap().1, base + 16 * gas::COST_FLOOR_PER_TOKEN);
        assert_eq!(zero.gas_limits().unwrap().1, nonzero.gas_limits().unwrap().1);
    }

    #[test]
    fn uniform_calldata_floor_enforces_the_transaction_gas_cap() {
        let base = gas::INTRINSIC_COST + gas::PER_FRAME_COST;
        let gas_per_floor_byte = gas::TOKEN_PER_NON_ZERO_BYTE * gas::COST_FLOOR_PER_TOKEN;
        let max_floor_bytes = ((gas::TX_MAX_GAS_LIMIT - base) / gas_per_floor_byte) as usize;
        let transaction = |length| TxFrame {
            frames: vec![Frame { data: Bytes::from(vec![0; length]), ..Default::default() }],
            ..Default::default()
        };

        let at_cap = transaction(max_floor_bytes);
        assert!(at_cap.gas_limits().unwrap().1 <= gas::TX_MAX_GAS_LIMIT);
        at_cap.validate().unwrap();

        let above_cap = transaction(max_floor_bytes + 1);
        assert!(above_cap.intrinsic_gas().unwrap() < gas::TX_MAX_GAS_LIMIT);
        assert!(above_cap.gas_limits().unwrap().1 > gas::TX_MAX_GAS_LIMIT);
        assert_eq!(above_cap.validate(), Err(FrameTxError::GasCapExceeded));
    }

    #[test]
    fn validate_enforces_batch_scope_and_state_gas_rules() {
        let base = signed_vector();

        // Approval scope on a frame that carries the batch flag.
        let mut scoped_batch = base.clone();
        scoped_batch.frames = vec![
            base.frames[0].clone(),
            Frame {
                mode: mode::SENDER,
                flags: flags::ATOMIC_BATCH | flags::APPROVE_PAYMENT,
                target: Some(Address::repeat_byte(0x22)),
                gas_limit: 21_000,
                ..Default::default()
            },
            Frame {
                mode: mode::SENDER,
                flags: 0,
                target: Some(Address::repeat_byte(0x22)),
                gas_limit: 21_000,
                ..Default::default()
            },
        ];
        assert_eq!(scoped_batch.validate(), Err(FrameTxError::ApproveScopeInBatch { index: 1 }));

        // Approval scope on a batch terminator (predecessor carries the flag).
        let mut scoped_terminator = base.clone();
        scoped_terminator.frames = vec![
            base.frames[0].clone(),
            Frame {
                mode: mode::SENDER,
                flags: flags::ATOMIC_BATCH,
                target: Some(Address::repeat_byte(0x22)),
                gas_limit: 21_000,
                ..Default::default()
            },
            Frame {
                mode: mode::SENDER,
                flags: flags::APPROVE_PAYMENT,
                target: Some(Address::repeat_byte(0x22)),
                gas_limit: 21_000,
                ..Default::default()
            },
        ];
        assert_eq!(
            scoped_terminator.validate(),
            Err(FrameTxError::ApproveScopeInBatch { index: 2 })
        );

        // An expiry verifier frame may not carry a state budget.
        let mut expiry_state = base.clone();
        expiry_state.frames.insert(
            0,
            Frame {
                mode: mode::VERIFY,
                flags: 0,
                target: Some(EXPIRY_VERIFIER_ADDRESS),
                gas_limit: 5_000,
                state_gas_limit: 1,
                value: U256::ZERO,
                data: Bytes::from(vec![0u8; gas::EXPIRY_DATA_LENGTH]),
            },
        );
        assert_eq!(expiry_state.validate(), Err(FrameTxError::MalformedExpiryFrame { index: 0 }));

        // The EIP-7825 cap binds the execution budget, not the state budget.
        let mut over_cap = base.clone();
        over_cap.frames[0].gas_limit = gas::TX_MAX_GAS_LIMIT;
        assert_eq!(over_cap.validate(), Err(FrameTxError::GasCapExceeded));
        let mut state_heavy = base.clone();
        state_heavy.frames[0].state_gas_limit = gas::TX_MAX_GAS_LIMIT * 4;
        state_heavy.validate().unwrap();
    }

    #[test]
    fn resolved_signer_defaults_to_sender_and_rejects_malformed() {
        let sender = Address::repeat_byte(0x11);
        let explicit = Address::repeat_byte(0x33);

        let empty = FrameSignature::default();
        assert_eq!(empty.resolved_signer(sender), Some(sender));

        let named = FrameSignature { signer: Bytes::from(explicit.to_vec()), ..Default::default() };
        assert_eq!(named.resolved_signer(sender), Some(explicit));

        let malformed = FrameSignature { signer: Bytes::from(vec![0u8; 7]), ..Default::default() };
        assert_eq!(malformed.resolved_signer(sender), None);
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        let tx = sample();
        let mut encoded = Vec::new();
        tx.encode_2718(&mut encoded);
        encoded.push(0x80);
        assert!(TxFrame::decode_2718_exact(encoded.as_slice()).is_err());
    }

    #[test]
    fn decode_rejects_a_truncated_payload() {
        let tx = sample();
        let mut encoded = Vec::new();
        tx.encode_2718(&mut encoded);
        encoded.truncate(encoded.len() - 1);
        assert!(TxFrame::decode_2718(&mut encoded.as_slice()).is_err());
    }

    #[test]
    fn decode_rejects_a_frame_with_a_missing_field() {
        // A frame list with only five of the six fields must not decode.
        let mut frame = Vec::new();
        let payload = {
            let mut buf = Vec::new();
            0u8.encode(&mut buf);
            0u8.encode(&mut buf);
            encode_target(None, &mut buf);
            21_000u64.encode(&mut buf);
            U256::ZERO.encode(&mut buf);
            buf
        };
        Header { list: true, payload_length: payload.len() }.encode(&mut frame);
        frame.extend_from_slice(&payload);
        assert!(Frame::decode(&mut frame.as_slice()).is_err());
    }

    #[test]
    fn decode_rejects_a_wrong_type_byte() {
        let tx = sample();
        let mut encoded = Vec::new();
        tx.encode_2718(&mut encoded);
        encoded[0] = 0x05;
        assert!(TxFrame::decode_2718(&mut encoded.as_slice()).is_err());
    }
}
