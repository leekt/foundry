use alloy_consensus::{
    Eip658Value, Receipt, ReceiptEnvelope, ReceiptWithBloom, RlpDecodableReceipt,
    RlpEncodableReceipt, TxReceipt, Typed2718,
};
use alloy_network::eip2718::{
    Decodable2718, EIP1559_TX_TYPE_ID, EIP2930_TX_TYPE_ID, EIP4844_TX_TYPE_ID, EIP7702_TX_TYPE_ID,
    Eip2718Error, Encodable2718, LEGACY_TX_TYPE_ID,
};
use alloy_primitives::{Address, Bloom, Log, TxHash, logs_bloom};
use alloy_rlp::{BufMut, Decodable, Encodable, Header, bytes, length_of_length};
use alloy_rpc_types::{BlockNumHash, trace::otterscan::OtsReceipt};
#[cfg(feature = "optimism")]
use op_alloy_consensus::{
    DEPOSIT_TX_TYPE_ID, OpDepositReceipt, OpDepositReceiptWithBloom, POST_EXEC_TX_TYPE_ID,
};
use serde::{Deserialize, Serialize};
use tempo_primitives::TEMPO_TX_TYPE_ID;

use crate::{FoundryTxType, transaction::frame::FRAME_TX_TYPE_ID};

/// Receipt for one executed EIP-8141 frame.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FrameReceipt<T = Log> {
    /// Top-level frame return status (`0` failed, `1` succeeded, `2` skipped).
    #[serde(with = "alloy_serde::quantity")]
    pub status: u8,
    /// Gross execution gas used by this frame (`gas_used.execution`), before
    /// transaction-level refunds.
    #[serde(with = "alloy_serde::quantity")]
    pub execution_gas_used: u64,
    /// Final state gas attributed to this frame (`gas_used.state`), after all
    /// state-gas refills and rollbacks in the transaction have been applied.
    #[serde(with = "alloy_serde::quantity", default)]
    pub state_gas_used: u64,
    /// Canonical logs retained by this frame.
    pub logs: Vec<T>,
}

impl<T> FrameReceipt<T> {
    /// Converts this frame receipt's log type.
    pub fn map_logs<U>(self, f: impl FnMut(T) -> U) -> FrameReceipt<U> {
        FrameReceipt {
            status: self.status,
            execution_gas_used: self.execution_gas_used,
            state_gas_used: self.state_gas_used,
            logs: self.logs.into_iter().map(f).collect(),
        }
    }

    /// Payload length of the nested `gas_used = [execution, state]` list.
    fn gas_used_payload_length(&self) -> usize {
        self.execution_gas_used.length() + self.state_gas_used.length()
    }

    fn rlp_payload_length(&self) -> usize
    where
        T: Encodable,
    {
        let gas_used = self.gas_used_payload_length();
        self.status.length() + gas_used + length_of_length(gas_used) + self.logs.length()
    }
}

impl<T: Encodable> Encodable for FrameReceipt<T> {
    fn encode(&self, out: &mut dyn BufMut) {
        Header { list: true, payload_length: self.rlp_payload_length() }.encode(out);
        self.status.encode(out);
        Header { list: true, payload_length: self.gas_used_payload_length() }.encode(out);
        self.execution_gas_used.encode(out);
        self.state_gas_used.encode(out);
        self.logs.encode(out);
    }

    fn length(&self) -> usize {
        let payload_length = self.rlp_payload_length();
        Header { list: true, payload_length }.length_with_payload()
    }
}

impl<T: Decodable> Decodable for FrameReceipt<T> {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let header = Header::decode(buf)?;
        if !header.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }
        let remaining = buf.len();
        let status = Decodable::decode(buf)?;
        let mut gas_used = Header::decode_bytes(buf, true)?;
        let execution_gas_used = Decodable::decode(&mut gas_used)?;
        let state_gas_used = Decodable::decode(&mut gas_used)?;
        if !gas_used.is_empty() {
            return Err(alloy_rlp::Error::UnexpectedLength);
        }
        let receipt =
            Self { status, execution_gas_used, state_gas_used, logs: Decodable::decode(buf)? };
        if receipt.status > 2 || buf.len() + header.payload_length != remaining {
            return Err(alloy_rlp::Error::UnexpectedLength);
        }
        Ok(receipt)
    }
}

/// Consensus receipt payload for an EIP-8141 frame transaction.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FrameTransactionReceipt<T = Log> {
    /// Standard RPC-compatible transaction receipt view.
    #[serde(flatten)]
    pub inner: Receipt<T>,
    /// Account that paid the transaction fee.
    pub payer: Address,
    /// Ordered receipts for every frame.
    pub frame_receipts: Vec<FrameReceipt<T>>,
}

impl<T: Clone> FrameTransactionReceipt<T> {
    /// Builds a frame receipt and its flattened transaction-level log view.
    pub fn new(
        cumulative_gas_used: u64,
        payer: Address,
        frame_receipts: Vec<FrameReceipt<T>>,
    ) -> Self {
        let logs = frame_receipts.iter().flat_map(|frame| frame.logs.iter().cloned()).collect();
        Self {
            inner: Receipt { status: Eip658Value::Eip658(true), cumulative_gas_used, logs },
            payer,
            frame_receipts,
        }
    }
}

impl<T> FrameTransactionReceipt<T> {
    /// Converts both nested and flattened logs to another type.
    pub fn map_logs<U: Clone>(self, mut f: impl FnMut(T) -> U) -> FrameTransactionReceipt<U> {
        let cumulative_gas_used = self.inner.cumulative_gas_used;
        let frame_receipts =
            self.frame_receipts.into_iter().map(|frame| frame.map_logs(&mut f)).collect();
        FrameTransactionReceipt::new(cumulative_gas_used, self.payer, frame_receipts)
    }
}

impl<T: Encodable> RlpEncodableReceipt for FrameTransactionReceipt<T> {
    fn rlp_encoded_length_with_bloom(&self, _bloom: &Bloom) -> usize {
        let payload_length = self.inner.cumulative_gas_used.length()
            + self.payer.length()
            + self.frame_receipts.length();
        Header { list: true, payload_length }.length_with_payload()
    }

    fn rlp_encode_with_bloom(&self, _bloom: &Bloom, out: &mut dyn BufMut) {
        let payload_length = self.inner.cumulative_gas_used.length()
            + self.payer.length()
            + self.frame_receipts.length();
        Header { list: true, payload_length }.encode(out);
        self.inner.cumulative_gas_used.encode(out);
        self.payer.encode(out);
        self.frame_receipts.encode(out);
    }
}

impl<T> RlpDecodableReceipt for FrameTransactionReceipt<T>
where
    T: AsRef<Log> + Clone + Decodable,
{
    fn rlp_decode_with_bloom(buf: &mut &[u8]) -> alloy_rlp::Result<ReceiptWithBloom<Self>> {
        let header = Header::decode(buf)?;
        if !header.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }
        let remaining = buf.len();
        let cumulative_gas_used = Decodable::decode(buf)?;
        let payer = Decodable::decode(buf)?;
        let frame_receipts: Vec<FrameReceipt<T>> = Decodable::decode(buf)?;
        if buf.len() + header.payload_length != remaining {
            return Err(alloy_rlp::Error::UnexpectedLength);
        }
        let receipt = Self::new(cumulative_gas_used, payer, frame_receipts);
        let logs_bloom = logs_bloom(receipt.inner.logs.iter().map(AsRef::as_ref));
        Ok(ReceiptWithBloom { receipt, logs_bloom })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum FoundryReceiptEnvelope<T = Log> {
    #[serde(rename = "0x0", alias = "0x00")]
    Legacy(ReceiptWithBloom<Receipt<T>>),
    #[serde(rename = "0x1", alias = "0x01")]
    Eip2930(ReceiptWithBloom<Receipt<T>>),
    #[serde(rename = "0x2", alias = "0x02")]
    Eip1559(ReceiptWithBloom<Receipt<T>>),
    #[serde(rename = "0x3", alias = "0x03")]
    Eip4844(ReceiptWithBloom<Receipt<T>>),
    #[serde(rename = "0x4", alias = "0x04")]
    Eip7702(ReceiptWithBloom<Receipt<T>>),
    #[cfg(feature = "optimism")]
    #[serde(rename = "0x7D", alias = "0x7d")]
    PostExec(ReceiptWithBloom<Receipt<T>>),
    #[cfg(feature = "optimism")]
    #[serde(rename = "0x7E", alias = "0x7e")]
    Deposit(OpDepositReceiptWithBloom<T>),
    #[serde(rename = "0x76")]
    Tempo(ReceiptWithBloom<Receipt<T>>),
    /// EIP-8141 frame transaction receipt.
    #[serde(rename = "0x6", alias = "0x06")]
    Frame(ReceiptWithBloom<FrameTransactionReceipt<T>>),
}

impl FoundryReceiptEnvelope<alloy_rpc_types::Log> {
    /// Creates a new [`FoundryReceiptEnvelope`] from the given parts.
    pub fn from_parts(
        status: bool,
        cumulative_gas_used: u64,
        logs: impl IntoIterator<Item = alloy_rpc_types::Log>,
        tx_type: FoundryTxType,
        #[cfg_attr(not(feature = "optimism"), allow(unused_variables))] deposit_nonce: Option<u64>,
        #[cfg_attr(not(feature = "optimism"), allow(unused_variables))]
        deposit_receipt_version: Option<u64>,
    ) -> Self {
        let logs = logs.into_iter().collect::<Vec<_>>();
        let logs_bloom = logs_bloom(logs.iter().map(|l| &l.inner));
        let inner_receipt =
            Receipt { status: Eip658Value::Eip658(status), cumulative_gas_used, logs };
        match tx_type {
            FoundryTxType::Legacy => {
                Self::Legacy(ReceiptWithBloom { receipt: inner_receipt, logs_bloom })
            }
            FoundryTxType::Eip2930 => {
                Self::Eip2930(ReceiptWithBloom { receipt: inner_receipt, logs_bloom })
            }
            FoundryTxType::Eip1559 => {
                Self::Eip1559(ReceiptWithBloom { receipt: inner_receipt, logs_bloom })
            }
            FoundryTxType::Eip4844 => {
                Self::Eip4844(ReceiptWithBloom { receipt: inner_receipt, logs_bloom })
            }
            FoundryTxType::Eip7702 => {
                Self::Eip7702(ReceiptWithBloom { receipt: inner_receipt, logs_bloom })
            }
            #[cfg(feature = "optimism")]
            FoundryTxType::PostExec => {
                Self::PostExec(ReceiptWithBloom { receipt: inner_receipt, logs_bloom })
            }
            #[cfg(feature = "optimism")]
            FoundryTxType::Deposit => {
                let inner = OpDepositReceiptWithBloom {
                    receipt: OpDepositReceipt {
                        inner: inner_receipt,
                        deposit_nonce,
                        deposit_receipt_version,
                    },
                    logs_bloom,
                };
                Self::Deposit(inner)
            }
            FoundryTxType::Tempo => {
                Self::Tempo(ReceiptWithBloom { receipt: inner_receipt, logs_bloom })
            }
            FoundryTxType::Frame => {
                panic!("frame receipts require payer and per-frame receipt data")
            }
        }
    }
}

impl FoundryReceiptEnvelope<Log> {
    pub fn convert_logs_rpc(
        self,
        block_numhash: BlockNumHash,
        block_timestamp: u64,
        transaction_hash: TxHash,
        transaction_index: u64,
        next_log_index: usize,
    ) -> FoundryReceiptEnvelope<alloy_rpc_types::Log> {
        if let Self::Frame(receipt) = &self {
            let mut log_index = next_log_index;
            let frame_receipts = receipt
                .receipt
                .frame_receipts
                .iter()
                .map(|frame| FrameReceipt {
                    status: frame.status,
                    execution_gas_used: frame.execution_gas_used,
                    state_gas_used: frame.state_gas_used,
                    logs: frame
                        .logs
                        .iter()
                        .cloned()
                        .map(|log| {
                            let log = alloy_rpc_types::Log {
                                inner: log,
                                block_hash: Some(block_numhash.hash),
                                block_number: Some(block_numhash.number),
                                block_timestamp: Some(block_timestamp),
                                transaction_hash: Some(transaction_hash),
                                transaction_index: Some(transaction_index),
                                log_index: Some(log_index as u64),
                                removed: false,
                            };
                            log_index += 1;
                            log
                        })
                        .collect(),
                })
                .collect();
            return FoundryReceiptEnvelope::from_frame_parts(
                receipt.receipt.inner.cumulative_gas_used,
                receipt.receipt.payer,
                frame_receipts,
            );
        }

        let logs = self
            .logs()
            .iter()
            .enumerate()
            .map(|(index, log)| alloy_rpc_types::Log {
                inner: log.clone(),
                block_hash: Some(block_numhash.hash),
                block_number: Some(block_numhash.number),
                block_timestamp: Some(block_timestamp),
                transaction_hash: Some(transaction_hash),
                transaction_index: Some(transaction_index),
                log_index: Some((next_log_index + index) as u64),
                removed: false,
            })
            .collect::<Vec<_>>();
        #[cfg(feature = "optimism")]
        let (deposit_nonce, deposit_receipt_version) =
            (self.deposit_nonce(), self.deposit_receipt_version());
        #[cfg(not(feature = "optimism"))]
        let (deposit_nonce, deposit_receipt_version) = (None, None);
        FoundryReceiptEnvelope::<alloy_rpc_types::Log>::from_parts(
            self.status(),
            self.cumulative_gas_used(),
            logs,
            self.tx_type(),
            deposit_nonce,
            deposit_receipt_version,
        )
    }
}

impl<T> FoundryReceiptEnvelope<T> {
    /// Builds an EIP-8141 receipt from its consensus fields.
    pub fn from_frame_parts(
        cumulative_gas_used: u64,
        payer: Address,
        frame_receipts: Vec<FrameReceipt<T>>,
    ) -> Self
    where
        T: AsRef<Log> + Clone,
    {
        let receipt = FrameTransactionReceipt::new(cumulative_gas_used, payer, frame_receipts);
        let logs_bloom = logs_bloom(receipt.inner.logs.iter().map(AsRef::as_ref));
        Self::Frame(ReceiptWithBloom { receipt, logs_bloom })
    }

    /// Returns `true` if this is an OP stack deposit receipt.
    #[cfg(feature = "optimism")]
    pub const fn is_deposit(&self) -> bool {
        matches!(self, Self::Deposit(_))
    }

    /// Returns `true` if this is an OP stack post-execution synthetic receipt.
    #[cfg(feature = "optimism")]
    pub const fn is_post_exec(&self) -> bool {
        matches!(self, Self::PostExec(_))
    }

    /// Returns `true` if this is a Tempo receipt.
    pub const fn is_tempo(&self) -> bool {
        matches!(self, Self::Tempo(_))
    }

    /// Returns `true` if this is an EIP-8141 frame receipt.
    pub const fn is_frame(&self) -> bool {
        matches!(self, Self::Frame(_))
    }

    /// Return the [`FoundryTxType`] of the inner receipt.
    pub const fn tx_type(&self) -> FoundryTxType {
        match self {
            Self::Legacy(_) => FoundryTxType::Legacy,
            Self::Eip2930(_) => FoundryTxType::Eip2930,
            Self::Eip1559(_) => FoundryTxType::Eip1559,
            Self::Eip4844(_) => FoundryTxType::Eip4844,
            Self::Eip7702(_) => FoundryTxType::Eip7702,
            #[cfg(feature = "optimism")]
            Self::PostExec(_) => FoundryTxType::PostExec,
            #[cfg(feature = "optimism")]
            Self::Deposit(_) => FoundryTxType::Deposit,
            Self::Tempo(_) => FoundryTxType::Tempo,
            Self::Frame(_) => FoundryTxType::Frame,
        }
    }

    /// Returns the success status of the receipt's transaction.
    pub const fn status(&self) -> bool {
        self.as_receipt().status.coerce_status()
    }

    /// Returns the cumulative gas used at this receipt.
    pub const fn cumulative_gas_used(&self) -> u64 {
        self.as_receipt().cumulative_gas_used
    }

    /// Converts the receipt's log type by applying a function to each log.
    ///
    /// Returns the receipt with the new log type.
    pub fn map_logs<U: Clone>(self, f: impl FnMut(T) -> U) -> FoundryReceiptEnvelope<U> {
        match self {
            Self::Legacy(r) => FoundryReceiptEnvelope::Legacy(r.map_logs(f)),
            Self::Eip2930(r) => FoundryReceiptEnvelope::Eip2930(r.map_logs(f)),
            Self::Eip1559(r) => FoundryReceiptEnvelope::Eip1559(r.map_logs(f)),
            Self::Eip4844(r) => FoundryReceiptEnvelope::Eip4844(r.map_logs(f)),
            Self::Eip7702(r) => FoundryReceiptEnvelope::Eip7702(r.map_logs(f)),
            #[cfg(feature = "optimism")]
            Self::PostExec(r) => FoundryReceiptEnvelope::PostExec(r.map_logs(f)),
            #[cfg(feature = "optimism")]
            Self::Deposit(r) => FoundryReceiptEnvelope::Deposit(
                r.map_receipt(|r: OpDepositReceipt<T>| r.map_logs(f)),
            ),
            Self::Tempo(r) => FoundryReceiptEnvelope::Tempo(r.map_logs(f)),
            Self::Frame(r) => {
                FoundryReceiptEnvelope::Frame(r.map_receipt(|receipt| receipt.map_logs(f)))
            }
        }
    }

    /// Return the receipt logs.
    pub fn logs(&self) -> &[T] {
        &self.as_receipt().logs
    }

    /// Consumes the type and returns the logs.
    pub fn into_logs(self) -> Vec<T> {
        self.into_receipt().logs
    }

    /// Return the receipt's bloom.
    pub const fn logs_bloom(&self) -> &Bloom {
        match self {
            Self::Legacy(t) => &t.logs_bloom,
            Self::Eip2930(t) => &t.logs_bloom,
            Self::Eip1559(t) => &t.logs_bloom,
            Self::Eip4844(t) => &t.logs_bloom,
            Self::Eip7702(t) => &t.logs_bloom,
            #[cfg(feature = "optimism")]
            Self::PostExec(t) => &t.logs_bloom,
            #[cfg(feature = "optimism")]
            Self::Deposit(t) => &t.logs_bloom,
            Self::Tempo(t) => &t.logs_bloom,
            Self::Frame(t) => &t.logs_bloom,
        }
    }

    /// Consumes the type and returns the underlying [`Receipt`].
    pub fn into_receipt(self) -> Receipt<T> {
        match self {
            Self::Legacy(t)
            | Self::Eip2930(t)
            | Self::Eip1559(t)
            | Self::Eip4844(t)
            | Self::Eip7702(t)
            | Self::Tempo(t) => t.receipt,
            Self::Frame(t) => t.receipt.inner,
            #[cfg(feature = "optimism")]
            Self::PostExec(t) => t.receipt,
            #[cfg(feature = "optimism")]
            Self::Deposit(t) => t.receipt.into_inner(),
        }
    }

    /// Return the inner receipt.
    pub const fn as_receipt(&self) -> &Receipt<T> {
        match self {
            Self::Legacy(t)
            | Self::Eip2930(t)
            | Self::Eip1559(t)
            | Self::Eip4844(t)
            | Self::Eip7702(t)
            | Self::Tempo(t) => &t.receipt,
            Self::Frame(t) => &t.receipt.inner,
            #[cfg(feature = "optimism")]
            Self::PostExec(t) => &t.receipt,
            #[cfg(feature = "optimism")]
            Self::Deposit(t) => &t.receipt.inner,
        }
    }
}

impl<T> TxReceipt for FoundryReceiptEnvelope<T>
where
    T: Clone + core::fmt::Debug + PartialEq + Eq + Send + Sync,
{
    type Log = T;

    fn status_or_post_state(&self) -> Eip658Value {
        self.as_receipt().status
    }

    fn status(&self) -> bool {
        self.status()
    }

    /// Return the receipt's bloom.
    fn bloom(&self) -> Bloom {
        *self.logs_bloom()
    }

    fn bloom_cheap(&self) -> Option<Bloom> {
        Some(self.bloom())
    }

    /// Returns the cumulative gas used at this receipt.
    fn cumulative_gas_used(&self) -> u64 {
        self.cumulative_gas_used()
    }

    /// Return the receipt logs.
    fn logs(&self) -> &[T] {
        self.logs()
    }
}

impl Encodable for FoundryReceiptEnvelope {
    fn encode(&self, out: &mut dyn bytes::BufMut) {
        match self {
            Self::Legacy(r) => r.encode(out),
            Self::Frame(_) => {
                let payload_length = self.encode_2718_len();
                Header { list: false, payload_length }.encode(out);
                self.encode_2718(out);
            }
            receipt => {
                let payload_len = match receipt {
                    Self::Eip2930(r) => r.length() + 1,
                    Self::Eip1559(r) => r.length() + 1,
                    Self::Eip4844(r) => r.length() + 1,
                    Self::Eip7702(r) => r.length() + 1,
                    #[cfg(feature = "optimism")]
                    Self::PostExec(r) => r.length() + 1,
                    #[cfg(feature = "optimism")]
                    Self::Deposit(r) => r.length() + 1,
                    Self::Tempo(r) => r.length() + 1,
                    _ => unreachable!("receipt already matched"),
                };

                match receipt {
                    Self::Eip2930(r) => {
                        Header { list: true, payload_length: payload_len }.encode(out);
                        EIP2930_TX_TYPE_ID.encode(out);
                        r.encode(out);
                    }
                    Self::Eip1559(r) => {
                        Header { list: true, payload_length: payload_len }.encode(out);
                        EIP1559_TX_TYPE_ID.encode(out);
                        r.encode(out);
                    }
                    Self::Eip4844(r) => {
                        Header { list: true, payload_length: payload_len }.encode(out);
                        EIP4844_TX_TYPE_ID.encode(out);
                        r.encode(out);
                    }
                    Self::Eip7702(r) => {
                        Header { list: true, payload_length: payload_len }.encode(out);
                        EIP7702_TX_TYPE_ID.encode(out);
                        r.encode(out);
                    }
                    #[cfg(feature = "optimism")]
                    Self::PostExec(r) => {
                        Header { list: true, payload_length: payload_len }.encode(out);
                        POST_EXEC_TX_TYPE_ID.encode(out);
                        r.encode(out);
                    }
                    #[cfg(feature = "optimism")]
                    Self::Deposit(r) => {
                        Header { list: true, payload_length: payload_len }.encode(out);
                        DEPOSIT_TX_TYPE_ID.encode(out);
                        r.encode(out);
                    }
                    Self::Tempo(r) => {
                        Header { list: true, payload_length: payload_len }.encode(out);
                        TEMPO_TX_TYPE_ID.encode(out);
                        r.encode(out);
                    }
                    _ => unreachable!("receipt already matched"),
                }
            }
        }
    }
}

impl Decodable for FoundryReceiptEnvelope {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        use bytes::Buf;
        use std::cmp::Ordering;

        // a receipt is either encoded as a string (non legacy) or a list (legacy).
        // We should not consume the buffer if we are decoding a legacy receipt, so let's
        // check if the first byte is between 0x80 and 0xbf.
        let rlp_type = *buf
            .first()
            .ok_or(alloy_rlp::Error::Custom("cannot decode a receipt from empty bytes"))?;

        match rlp_type.cmp(&alloy_rlp::EMPTY_LIST_CODE) {
            Ordering::Less => {
                // strip out the string header
                let _header = Header::decode(buf)?;
                let receipt_type = *buf.first().ok_or(alloy_rlp::Error::Custom(
                    "typed receipt cannot be decoded from an empty slice",
                ))?;
                if receipt_type == EIP2930_TX_TYPE_ID {
                    buf.advance(1);
                    <ReceiptWithBloom as Decodable>::decode(buf)
                        .map(FoundryReceiptEnvelope::Eip2930)
                } else if receipt_type == EIP1559_TX_TYPE_ID {
                    buf.advance(1);
                    <ReceiptWithBloom as Decodable>::decode(buf)
                        .map(FoundryReceiptEnvelope::Eip1559)
                } else if receipt_type == EIP4844_TX_TYPE_ID {
                    buf.advance(1);
                    <ReceiptWithBloom as Decodable>::decode(buf)
                        .map(FoundryReceiptEnvelope::Eip4844)
                } else if receipt_type == EIP7702_TX_TYPE_ID {
                    buf.advance(1);
                    <ReceiptWithBloom as Decodable>::decode(buf)
                        .map(FoundryReceiptEnvelope::Eip7702)
                } else if receipt_type == FRAME_TX_TYPE_ID {
                    buf.advance(1);
                    <ReceiptWithBloom<FrameTransactionReceipt> as Decodable>::decode(buf)
                        .map(FoundryReceiptEnvelope::Frame)
                } else if receipt_type == TEMPO_TX_TYPE_ID {
                    buf.advance(1);
                    <ReceiptWithBloom as Decodable>::decode(buf).map(FoundryReceiptEnvelope::Tempo)
                } else {
                    #[cfg(feature = "optimism")]
                    {
                        if receipt_type == POST_EXEC_TX_TYPE_ID {
                            buf.advance(1);
                            return <ReceiptWithBloom as Decodable>::decode(buf)
                                .map(FoundryReceiptEnvelope::PostExec);
                        }
                        if receipt_type == DEPOSIT_TX_TYPE_ID {
                            buf.advance(1);
                            return <OpDepositReceiptWithBloom as Decodable>::decode(buf)
                                .map(FoundryReceiptEnvelope::Deposit);
                        }
                    }
                    Err(alloy_rlp::Error::Custom("invalid receipt type"))
                }
            }
            Ordering::Equal => {
                Err(alloy_rlp::Error::Custom("an empty list is not a valid receipt encoding"))
            }
            Ordering::Greater => {
                <ReceiptWithBloom as Decodable>::decode(buf).map(FoundryReceiptEnvelope::Legacy)
            }
        }
    }
}

impl Typed2718 for FoundryReceiptEnvelope {
    fn ty(&self) -> u8 {
        match self {
            Self::Legacy(_) => LEGACY_TX_TYPE_ID,
            Self::Eip2930(_) => EIP2930_TX_TYPE_ID,
            Self::Eip1559(_) => EIP1559_TX_TYPE_ID,
            Self::Eip4844(_) => EIP4844_TX_TYPE_ID,
            Self::Eip7702(_) => EIP7702_TX_TYPE_ID,
            #[cfg(feature = "optimism")]
            Self::PostExec(_) => POST_EXEC_TX_TYPE_ID,
            #[cfg(feature = "optimism")]
            Self::Deposit(_) => DEPOSIT_TX_TYPE_ID,
            Self::Tempo(_) => TEMPO_TX_TYPE_ID,
            Self::Frame(_) => FRAME_TX_TYPE_ID,
        }
    }
}

impl Encodable2718 for FoundryReceiptEnvelope {
    fn encode_2718_len(&self) -> usize {
        match self {
            Self::Legacy(r) => r.length(),
            Self::Eip2930(r) => 1 + r.length(),
            Self::Eip1559(r) => 1 + r.length(),
            Self::Eip4844(r) => 1 + r.length(),
            Self::Eip7702(r) => 1 + r.length(),
            #[cfg(feature = "optimism")]
            Self::PostExec(r) => 1 + r.length(),
            #[cfg(feature = "optimism")]
            Self::Deposit(r) => 1 + r.length(),
            Self::Tempo(r) => 1 + r.length(),
            Self::Frame(r) => 1 + r.length(),
        }
    }

    fn encode_2718(&self, out: &mut dyn BufMut) {
        if let Some(ty) = self.type_flag() {
            out.put_u8(ty);
        }
        match self {
            Self::Legacy(r)
            | Self::Eip2930(r)
            | Self::Eip1559(r)
            | Self::Eip4844(r)
            | Self::Eip7702(r)
            | Self::Tempo(r) => r.encode(out),
            Self::Frame(r) => r.encode(out),
            #[cfg(feature = "optimism")]
            Self::PostExec(r) => r.encode(out),
            #[cfg(feature = "optimism")]
            Self::Deposit(r) => r.encode(out),
        }
    }
}

impl Decodable2718 for FoundryReceiptEnvelope {
    fn typed_decode(ty: u8, buf: &mut &[u8]) -> Result<Self, Eip2718Error> {
        #[cfg(feature = "optimism")]
        {
            if ty == DEPOSIT_TX_TYPE_ID {
                return Ok(Self::Deposit(OpDepositReceiptWithBloom::decode(buf)?));
            }
            if ty == POST_EXEC_TX_TYPE_ID {
                return Ok(Self::PostExec(ReceiptWithBloom::decode(buf)?));
            }
        }
        if ty == FRAME_TX_TYPE_ID {
            return Ok(Self::Frame(
                <ReceiptWithBloom<FrameTransactionReceipt> as Decodable>::decode(buf)?,
            ));
        }
        if ty == TEMPO_TX_TYPE_ID {
            return Ok(Self::Tempo(ReceiptWithBloom::decode(buf)?));
        }
        match ReceiptEnvelope::typed_decode(ty, buf)? {
            ReceiptEnvelope::Eip2930(tx) => Ok(Self::Eip2930(tx)),
            ReceiptEnvelope::Eip1559(tx) => Ok(Self::Eip1559(tx)),
            ReceiptEnvelope::Eip4844(tx) => Ok(Self::Eip4844(tx)),
            ReceiptEnvelope::Eip7702(tx) => Ok(Self::Eip7702(tx)),
            _ => Err(Eip2718Error::RlpError(alloy_rlp::Error::Custom("unexpected tx type"))),
        }
    }

    fn fallback_decode(buf: &mut &[u8]) -> Result<Self, Eip2718Error> {
        match ReceiptEnvelope::fallback_decode(buf)? {
            ReceiptEnvelope::Legacy(tx) => Ok(Self::Legacy(tx)),
            _ => Err(Eip2718Error::RlpError(alloy_rlp::Error::Custom("unexpected tx type"))),
        }
    }
}

impl From<FoundryReceiptEnvelope<alloy_rpc_types::Log>> for OtsReceipt {
    fn from(receipt: FoundryReceiptEnvelope<alloy_rpc_types::Log>) -> Self {
        Self {
            status: receipt.status(),
            cumulative_gas_used: receipt.cumulative_gas_used(),
            logs: Some(receipt.logs().to_vec()),
            logs_bloom: Some(receipt.logs_bloom().to_owned()),
            r#type: receipt.tx_type() as u8,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{B256, Bytes, LogData, hex};
    use std::str::FromStr;

    fn receipt_for(tx_type: FoundryTxType) -> FoundryReceiptEnvelope {
        FoundryReceiptEnvelope::<alloy_rpc_types::Log>::from_parts(
            true,
            0,
            Vec::new(),
            tx_type,
            None,
            None,
        )
        .map_logs(|log| log.inner)
    }

    #[test]
    fn receipt_predicates() {
        assert!(receipt_for(FoundryTxType::Legacy).is_legacy());
        assert!(receipt_for(FoundryTxType::Eip2930).is_eip2930());
        assert!(receipt_for(FoundryTxType::Eip1559).is_eip1559());
        assert!(receipt_for(FoundryTxType::Eip4844).is_eip4844());
        assert!(receipt_for(FoundryTxType::Eip7702).is_eip7702());
        assert!(receipt_for(FoundryTxType::Tempo).is_tempo());
        assert!(!receipt_for(FoundryTxType::Tempo).is_legacy());
        assert!(
            FoundryReceiptEnvelope::from_frame_parts(0, Address::ZERO, Vec::<FrameReceipt>::new(),)
                .is_frame()
        );

        #[cfg(feature = "optimism")]
        {
            assert!(receipt_for(FoundryTxType::Deposit).is_deposit());
            assert!(receipt_for(FoundryTxType::PostExec).is_post_exec());
        }
    }

    #[test]
    fn frame_receipt_uses_eip8141_consensus_payload() {
        let payer = Address::repeat_byte(0x11);
        let receipt = FoundryReceiptEnvelope::from_frame_parts(
            21_000,
            payer,
            vec![
                FrameReceipt {
                    status: 1,
                    execution_gas_used: 16,
                    state_gas_used: 7,
                    logs: Vec::new(),
                },
                FrameReceipt {
                    status: 0,
                    execution_gas_used: 0,
                    state_gas_used: 0,
                    logs: Vec::new(),
                },
                FrameReceipt {
                    status: 2,
                    execution_gas_used: 0,
                    state_gas_used: 0,
                    logs: Vec::new(),
                },
            ],
        );
        // `gas_used` is the nested `[execution, state]` list per frame receipt.
        let expected = hex!(
            "06eb825208941111111111111111111111111111111111111111d2c501c21007c0c580c28080c0c502c28080c0"
        );

        let encoded = receipt.encoded_2718();
        assert_eq!(encoded, expected);
        let decoded = FoundryReceiptEnvelope::decode_2718(&mut encoded.as_slice()).unwrap();
        assert_eq!(decoded, receipt);
        let FoundryReceiptEnvelope::Frame(frame) = decoded else { unreachable!() };
        assert_eq!(frame.receipt.payer, payer);
        assert_eq!(frame.receipt.frame_receipts.len(), 3);
        assert!(frame.receipt.inner.status.coerce_status());

        let mut network_encoded = Vec::new();
        receipt.encode(&mut network_encoded);
        let network_decoded =
            FoundryReceiptEnvelope::decode(&mut network_encoded.as_slice()).unwrap();
        assert_eq!(network_decoded, receipt);
    }

    #[test]
    fn encode_legacy_receipt() {
        let expected = hex::decode("f901668001b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f85ff85d940000000000000000000000000000000000000011f842a0000000000000000000000000000000000000000000000000000000000000deada0000000000000000000000000000000000000000000000000000000000000beef830100ff").unwrap();

        let mut data = vec![];
        let receipt = FoundryReceiptEnvelope::Legacy(ReceiptWithBloom {
            receipt: Receipt {
                status: false.into(),
                cumulative_gas_used: 0x1,
                logs: vec![Log {
                    address: Address::from_str("0000000000000000000000000000000000000011").unwrap(),
                    data: LogData::new_unchecked(
                        vec![
                            B256::from_str(
                                "000000000000000000000000000000000000000000000000000000000000dead",
                            )
                            .unwrap(),
                            B256::from_str(
                                "000000000000000000000000000000000000000000000000000000000000beef",
                            )
                            .unwrap(),
                        ],
                        Bytes::from_str("0100ff").unwrap(),
                    ),
                }],
            },
            logs_bloom: [0; 256].into(),
        });

        receipt.encode(&mut data);

        // check that the rlp length equals the length of the expected rlp
        assert_eq!(receipt.length(), expected.len());
        assert_eq!(data, expected);
    }

    #[test]
    fn decode_legacy_receipt() {
        let data = hex::decode("f901668001b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f85ff85d940000000000000000000000000000000000000011f842a0000000000000000000000000000000000000000000000000000000000000deada0000000000000000000000000000000000000000000000000000000000000beef830100ff").unwrap();

        let expected = FoundryReceiptEnvelope::Legacy(ReceiptWithBloom {
            receipt: Receipt {
                status: false.into(),
                cumulative_gas_used: 0x1,
                logs: vec![Log {
                    address: Address::from_str("0000000000000000000000000000000000000011").unwrap(),
                    data: LogData::new_unchecked(
                        vec![
                            B256::from_str(
                                "000000000000000000000000000000000000000000000000000000000000dead",
                            )
                            .unwrap(),
                            B256::from_str(
                                "000000000000000000000000000000000000000000000000000000000000beef",
                            )
                            .unwrap(),
                        ],
                        Bytes::from_str("0100ff").unwrap(),
                    ),
                }],
            },
            logs_bloom: [0; 256].into(),
        });

        let receipt = FoundryReceiptEnvelope::decode(&mut &data[..]).unwrap();

        assert_eq!(receipt, expected);
    }

    #[test]
    fn encode_tempo_receipt() {
        use alloy_network::eip2718::Encodable2718;
        use tempo_primitives::TEMPO_TX_TYPE_ID;

        let receipt = FoundryReceiptEnvelope::Tempo(ReceiptWithBloom {
            receipt: Receipt {
                status: true.into(),
                cumulative_gas_used: 157716,
                logs: vec![Log {
                    address: Address::from_str("20c0000000000000000000000000000000000000").unwrap(),
                    data: LogData::new_unchecked(
                        vec![
                            B256::from_str(
                                "8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925",
                            )
                            .unwrap(),
                            B256::from_str(
                                "000000000000000000000000566ff0f4a6114f8072ecdc8a7a8a13d8d0c6b45f",
                            )
                            .unwrap(),
                            B256::from_str(
                                "000000000000000000000000dec0000000000000000000000000000000000000",
                            )
                            .unwrap(),
                        ],
                        Bytes::from_str(
                            "0000000000000000000000000000000000000000000000000000000000989680",
                        )
                        .unwrap(),
                    ),
                }],
            },
            logs_bloom: [0; 256].into(),
        });

        assert_eq!(receipt.tx_type(), FoundryTxType::Tempo);
        assert_eq!(receipt.ty(), TEMPO_TX_TYPE_ID);
        assert!(receipt.status());
        assert_eq!(receipt.cumulative_gas_used(), 157716);
        assert_eq!(receipt.logs().len(), 1);

        // Encode and decode round-trip
        let mut encoded = Vec::new();
        receipt.encode_2718(&mut encoded);

        // First byte should be the Tempo type ID
        assert_eq!(encoded[0], TEMPO_TX_TYPE_ID);

        // Decode it back
        let decoded = FoundryReceiptEnvelope::decode(&mut &encoded[..]).unwrap();
        assert_eq!(receipt, decoded);
    }

    #[test]
    fn decode_tempo_receipt() {
        use alloy_network::eip2718::Encodable2718;
        use tempo_primitives::TEMPO_TX_TYPE_ID;

        let receipt = FoundryReceiptEnvelope::Tempo(ReceiptWithBloom {
            receipt: Receipt { status: true.into(), cumulative_gas_used: 21000, logs: vec![] },
            logs_bloom: [0; 256].into(),
        });

        // Encode and decode via 2718
        let mut encoded = Vec::new();
        receipt.encode_2718(&mut encoded);
        assert_eq!(encoded[0], TEMPO_TX_TYPE_ID);

        use alloy_network::eip2718::Decodable2718;
        let decoded = FoundryReceiptEnvelope::decode_2718(&mut &encoded[..]).unwrap();
        assert_eq!(receipt, decoded);
    }

    #[test]
    fn tempo_receipt_from_parts() {
        let receipt = FoundryReceiptEnvelope::<alloy_rpc_types::Log>::from_parts(
            true,
            100000,
            vec![],
            FoundryTxType::Tempo,
            None,
            None,
        );

        assert_eq!(receipt.tx_type(), FoundryTxType::Tempo);
        assert!(receipt.status());
        assert_eq!(receipt.cumulative_gas_used(), 100000);
        assert!(receipt.logs().is_empty());
        #[cfg(feature = "optimism")]
        {
            assert!(receipt.deposit_nonce().is_none());
            assert!(receipt.deposit_receipt_version().is_none());
        }
    }

    #[test]
    fn tempo_receipt_map_logs() {
        let receipt = FoundryReceiptEnvelope::Tempo(ReceiptWithBloom {
            receipt: Receipt {
                status: true.into(),
                cumulative_gas_used: 21000,
                logs: vec![Log {
                    address: Address::from_str("20c0000000000000000000000000000000000000").unwrap(),
                    data: LogData::new_unchecked(vec![], Bytes::default()),
                }],
            },
            logs_bloom: [0; 256].into(),
        });

        // Map logs to a different type (just clone in this case)
        let mapped = receipt.map_logs(|log| log);
        assert_eq!(mapped.logs().len(), 1);
        assert_eq!(mapped.tx_type(), FoundryTxType::Tempo);
    }
}
