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
    eip4844::{DATA_GAS_PER_BLOB, MAX_BLOBS_PER_BLOCK_DENCUN, VERSIONED_HASH_VERSION_KZG},
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

/// Gas constants, mirroring `params/protocol_params.go`.
pub mod gas {
    /// Base intrinsic cost of a frame transaction.
    pub const INTRINSIC_COST: u64 = 15000;
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
    /// Token cost per non-zero byte (EIP-7623).
    pub const TOKEN_PER_NON_ZERO_BYTE: u64 = 4;
    /// `STANDARD_TOKEN_COST`, which params spells as the per-zero-byte cost.
    pub const STANDARD_TOKEN_COST: u64 = 4;
    /// `TOTAL_COST_FLOOR_PER_TOKEN` (EIP-7623).
    pub const COST_FLOOR_PER_TOKEN: u64 = 10;
}

/// `ENTRY_POINT`: the caller of `DEFAULT` and `VERIFY` frames.
pub const ENTRY_POINT_ADDRESS: Address =
    Address::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xaa]);

/// `EXPIRY_VERIFIER`: the predeploy holding the expiry verifier code.
pub const EXPIRY_VERIFIER_ADDRESS: Address = Address::new([
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x81, 0x41,
]);

/// A single frame within a frame transaction.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Frame {
    /// Frame mode: 0 `DEFAULT`, 1 `VERIFY`, 2 `SENDER`.
    pub mode: u8,
    /// Frame flags.
    pub flags: u8,
    /// Call target; `None` means `tx.sender`.
    pub target: Option<Address>,
    /// Gas limit allotted to this frame.
    pub gas_limit: u64,
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

    fn rlp_payload_length(&self) -> usize {
        self.mode.length()
            + self.flags.length()
            + target_rlp_length(self.target)
            + self.gas_limit.length()
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
        self.gas_limit.encode(out);
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
        let this = Self {
            mode: u8::decode(&mut payload)?,
            flags: u8::decode(&mut payload)?,
            target: decode_target(&mut payload)?,
            gas_limit: u64::decode(&mut payload)?,
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
    /// Signature scheme: 0 `ARBITRARY`, 1 `SECP256K1`, 2 `P256`.
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
    pub nonce: u64,
    /// The declared sender. A frame transaction carries no outer signature, so
    /// this is authoritative and must never be recovered from one.
    pub sender: Address,
    /// The frames, executed in order.
    pub frames: Vec<Frame>,
    /// The signature entries.
    pub signatures: Vec<FrameSignature>,
    /// `maxPriorityFeePerGas`.
    pub max_priority_fee_per_gas: U256,
    /// `maxFeePerGas`.
    pub max_fee_per_gas: U256,
    /// `maxFeePerBlobGas`.
    pub max_fee_per_blob_gas: U256,
    /// EIP-4844 blob versioned hashes.
    pub blob_versioned_hashes: Vec<B256>,
}

impl TxFrame {
    fn rlp_payload_length(&self) -> usize {
        self.chain_id.length()
            + self.nonce.length()
            + self.sender.length()
            + self.frames.length()
            + self.signatures.length()
            + self.max_priority_fee_per_gas.length()
            + self.max_fee_per_gas.length()
            + self.max_fee_per_blob_gas.length()
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
        let this = Self {
            chain_id: U256::decode(&mut payload)?,
            nonce: u64::decode(&mut payload)?,
            sender: Address::decode(&mut payload)?,
            frames: Vec::<Frame>::decode(&mut payload)?,
            signatures: Vec::<FrameSignature>::decode(&mut payload)?,
            max_priority_fee_per_gas: U256::decode(&mut payload)?,
            max_fee_per_gas: U256::decode(&mut payload)?,
            max_fee_per_blob_gas: U256::decode(&mut payload)?,
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

    /// Sum of all frame gas limits, or `None` on overflow.
    pub fn sum_frame_gas(&self) -> Option<u64> {
        self.frames.iter().try_fold(0u64, |total, frame| total.checked_add(frame.gas_limit))
    }

    /// Total gas cost of verifying all signature entries, or `None` on overflow
    /// or an unknown scheme.
    pub fn signature_verification_cost(&self) -> Option<u64> {
        self.signatures
            .iter()
            .try_fold(0u64, |total, sig| total.checked_add(sig.verification_cost()?))
    }

    /// Total number of calldata tokens across frames and signatures: one token
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

    /// Computes `(standard_gas_limit, calldata_floor_gas, max_gas)`.
    ///
    /// Both limits share a base of the intrinsic cost, the per-frame cost and
    /// the signature verification cost. The standard limit adds the calldata
    /// cost at `STANDARD_TOKEN_COST` per token plus the sum of the frame gas
    /// limits; the floor charges `COST_FLOOR_PER_TOKEN` per token instead and
    /// excludes frame gas.
    pub fn gas_limits(&self) -> Option<(u64, u64, u64)> {
        let base = (self.frames.len() as u64)
            .checked_mul(gas::PER_FRAME_COST)?
            .checked_add(gas::INTRINSIC_COST)?
            .checked_add(self.signature_verification_cost()?)?;
        let tokens = self.calldata_tokens()?;

        let standard = base
            .checked_add(tokens.checked_mul(gas::STANDARD_TOKEN_COST)?)?
            .checked_add(self.sum_frame_gas()?)?;
        let floor = base.checked_add(tokens.checked_mul(gas::COST_FLOOR_PER_TOKEN)?)?;
        Some((standard, floor, standard.max(floor)))
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
        // EIP-4844 blob constraints. The frame path does not run the ordinary
        // pre-check, so the versioned hashes have to be validated here.
        if self.blob_versioned_hashes.len() > MAX_BLOBS_PER_BLOCK_DENCUN {
            return Err(FrameTxError::TooManyBlobs(self.blob_versioned_hashes.len()));
        }
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
            total_frame_gas =
                total_frame_gas.checked_add(frame.gas_limit).ok_or(FrameTxError::GasOverflow)?;

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

            // An expiry verifier frame must carry exactly an 8-byte deadline
            // and no flags, and at most one may appear per transaction.
            if frame.is_expiry_verifier() {
                expiry_frames += 1;
                if expiry_frames > 1 {
                    return Err(FrameTxError::MultipleExpiryFrames);
                }
                if frame.flags != 0 || frame.data.len() != gas::EXPIRY_DATA_LENGTH {
                    return Err(FrameTxError::MalformedExpiryFrame { index: i });
                }
            }
        }

        // Overflowing gas figures make the transaction invalid.
        self.gas_limits().ok_or(FrameTxError::GasOverflow)?;
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
const SECP256K1_N: U256 =
    U256::from_be_bytes(alloy_primitives::hex!(
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
    ));
/// P256 (secp256r1) group order.
const SECP256R1_N: U256 =
    U256::from_be_bytes(alloy_primitives::hex!(
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
    if v > 1
        || r.is_zero()
        || s.is_zero()
        || r >= SECP256K1_N
        || s > SECP256K1_N / U256::from(2u8)
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
    if r.is_zero()
        || s.is_zero()
        || r >= SECP256R1_N
        || s > SECP256R1_N / U256::from(2u8)
    {
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
    /// More blobs than a single transaction may carry.
    #[error("{0} blobs exceeds the per-transaction limit")]
    TooManyBlobs(usize),
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

/// Saturating conversion for the fee accessors, which the `Transaction` trait
/// types as `u128` while the envelope stores the full 256-bit RLP value.
fn saturating_u128(value: U256) -> u128 {
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
        saturating_u128(self.max_fee_per_gas)
    }

    fn max_priority_fee_per_gas(&self) -> Option<u128> {
        Some(saturating_u128(self.max_priority_fee_per_gas))
    }

    fn max_fee_per_blob_gas(&self) -> Option<u128> {
        Some(saturating_u128(self.max_fee_per_blob_gas))
    }

    fn priority_fee_or_price(&self) -> u128 {
        saturating_u128(self.max_priority_fee_per_gas)
    }

    fn effective_gas_price(&self, base_fee: Option<u64>) -> u128 {
        let max_fee = self.max_fee_per_gas();
        let Some(base_fee) = base_fee.map(u128::from) else { return max_fee };
        base_fee.saturating_add(
            self.max_priority_fee_per_gas().unwrap_or_default().min(max_fee.saturating_sub(base_fee)),
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
                    value: U256::ZERO,
                    data: Bytes::from_static(b"\x01\x02\x00\x03"),
                },
                Frame {
                    mode: mode::SENDER,
                    flags: 0,
                    target: Some(Address::repeat_byte(0x22)),
                    gas_limit: 21_000,
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

    /// Byte-exact agreement with the go-ethereum reference implementation for
    /// the transaction built by `sample()`. Generated from `FrameTx` on
    /// `leekt/go-ethereum@fix/eip8141-frame-tx`; if the RLP field order, the
    /// null-target encoding or the sig-hash eliding drifts, this test breaks.
    const REFERENCE_RAW: &str = "06f89c827a6907941111111111111111111111111111111111111111eccc01038082c350808401020003de028094222222222222222222222222222222222222222282520882\
03e880f848f846018080b841ababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababab843b9aca008477359400\
80c0";
    const REFERENCE_TX_HASH: &str =
        "0x74cb5b842b70918cbccf31e9522537fa72406961c9a589b30620bc29e3357d3d";
    const REFERENCE_SIG_HASH: &str =
        "0xa489131fd3a35916dc4faa1e13f4de92a191736258a76031802f513136a187a0";

    #[test]
    fn encoding_matches_the_go_ethereum_reference() {
        let tx = sample();

        let mut encoded = Vec::new();
        tx.encode_2718(&mut encoded);
        assert_eq!(alloy_primitives::hex::encode(&encoded), REFERENCE_RAW);

        assert_eq!(tx.hash_slow(), REFERENCE_TX_HASH.parse::<B256>().unwrap());
        assert_eq!(tx.signature_hash(), REFERENCE_SIG_HASH.parse::<B256>().unwrap());

        // The reference reports standard=90842, floor=21480, max_gas=90842.
        assert_eq!(tx.gas_limits().unwrap(), (90_842, 21_480, 90_842));
    }

    #[test]
    fn decoding_the_reference_vector_reproduces_the_transaction() {
        let raw = alloy_primitives::hex::decode(REFERENCE_RAW).unwrap();
        let decoded = TxFrame::decode_2718_exact(raw.as_slice()).unwrap();
        assert_eq!(decoded, sample());
    }

    /// A fully signed single-frame transaction produced by the go-ethereum
    /// reference using anvil's first dev key. The reference asserts its own
    /// `ValidateSignature` accepts it before emitting these bytes.
    const SIGNED_RAW: &str = "06f879827a698094f39fd6e51aad88f6f4ce6ab8827279cfffb92266c9c801038082c3508080f848f846018080b8410183f2f7d3321170e7cb523462693ed9480f7be7b49b\
317fa340c03949e3a5054c0c5900775a8e3478e75eb049b8598c6acdb41b6f25ffa9c700416e6db5fa45b6843b9aca00847735940080c0";
    const SIGNED_SENDER: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
    const SIGNED_SIG_HASH: &str =
        "0x8fb9b3ddc010b51b33a22f243eef5688509bb0862087360ec49ac51597da3237";

    fn signed_vector() -> TxFrame {
        let raw = alloy_primitives::hex::decode(SIGNED_RAW).unwrap();
        TxFrame::decode_2718_exact(raw.as_slice()).unwrap()
    }

    #[test]
    fn accepts_the_reference_signed_transaction() {
        let tx = signed_vector();

        assert_eq!(tx.sender, SIGNED_SENDER.parse::<Address>().unwrap());
        assert_eq!(tx.signature_hash(), SIGNED_SIG_HASH.parse::<B256>().unwrap());
        assert_eq!(tx.gas_limits().unwrap(), (69_291, 20_815, 69_291));

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
        assert_eq!(
            valued_verify.validate(),
            Err(FrameTxError::ValueOnNonSenderFrame { index: 0 })
        );

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

        let mut bad_scheme = base.clone();
        bad_scheme.signatures[0].scheme = 9;
        assert_eq!(bad_scheme.validate(), Err(FrameTxError::SignatureScheme(9)));

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

        // The unmodified vector must still pass, or the cases above prove nothing.
        base.validate().unwrap();
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
    fn gas_limits_follow_the_reference_formula() {
        let tx = sample();
        let (standard, floor, max_gas) = tx.gas_limits().unwrap();

        // 4 bytes of frame data (2 zero-ish: 0x01,0x02,0x00,0x03 -> one zero)
        // plus the 65 signature bytes, all non-zero.
        let tokens = tx.calldata_tokens().unwrap();
        assert_eq!(tokens, (1 + 3 * 4) + 65 * 4);

        let base = 2 * gas::PER_FRAME_COST + gas::INTRINSIC_COST + gas::SIGNATURE_SECP256K1;
        assert_eq!(standard, base + tokens * gas::STANDARD_TOKEN_COST + 71_000);
        assert_eq!(floor, base + tokens * gas::COST_FLOOR_PER_TOKEN);
        assert_eq!(max_gas, standard.max(floor));
        assert_eq!(tx.max_gas(), max_gas);
    }

    #[test]
    fn resolved_signer_defaults_to_sender_and_rejects_malformed() {
        let sender = Address::repeat_byte(0x11);
        let explicit = Address::repeat_byte(0x33);

        let empty = FrameSignature::default();
        assert_eq!(empty.resolved_signer(sender), Some(sender));

        let named =
            FrameSignature { signer: Bytes::from(explicit.to_vec()), ..Default::default() };
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
