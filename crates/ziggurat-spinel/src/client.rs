use crate::{
    HdlcSpecial, SPINEL_FRAME_MAX_SIZE, SpinelCommandId, SpinelFrame, SpinelFrameParsingError,
    SpinelFramePropValueIs, SpinelHeader, SpinelPropertyId, SpinelProtocol, SpinelResetReason,
    SpinelStatus, hdlc_escape_into, packed_uint21_deserialize, packed_uint21_to_bytes,
};
use std::future::Future;
use std::pin::Pin;
use std::string::String;
use thiserror::Error;
use ziggurat_ieee_802154::FrameBytes;
use ziggurat_ieee_802154::types::Eui64;

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::Mutex as AsyncMutex;
use tokio::sync::mpsc;
use tokio::time::{Duration, Instant, sleep, sleep_until, timeout};

/// A link to the RCP: a serial port or a TCP socket. Boxed so [`SpinelClient`] stays
/// transport-agnostic regardless of which one a caller opens.
pub trait RcpTransport: AsyncRead + AsyncWrite + Send + Unpin + 'static {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin + 'static> RcpTransport for T {}

/// A local RCP link — serial, or Ethernet to a network-attached RCP — answers in
/// milliseconds; anything beyond this is a failure. Wi-Fi is not supported: its
/// latency variance can spuriously trip `MAX_CONSECUTIVE_TIMEOUTS` below and force a
/// reset-recovery against a perfectly healthy radio.
const TIMEOUT: Duration = Duration::from_secs(2);

/// Consecutive command timeouts before the RCP is presumed wedged and the
/// reset-recovery path is triggered.
const MAX_CONSECUTIVE_TIMEOUTS: u32 = 4;

/// Opens a fresh link to the RCP, used to reconnect after the old one died.
///
/// Called once per attempt, so a device path is resolved again each time (a
/// re-enumerated USB board may come back on another tty behind the same
/// `/dev/serial/by-id/` symlink).
pub type TransportOpener = Arc<
    dyn Fn() -> Pin<Box<dyn Future<Output = std::io::Result<Box<dyn RcpTransport>>> + Send>>
        + Send
        + Sync,
>;

/// How the reader reopens a lost RCP link: exponential backoff from `initial_backoff`,
/// capped at `max_backoff`, abandoned once `give_up_after` has passed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReconnectPolicy {
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
    pub give_up_after: Duration,
    /// Also presume the link dead, and reopen it, after `MAX_CONSECUTIVE_TIMEOUTS`
    /// command timeouts. Catches links that die without an EOF: a TCP peer that
    /// vanished, or a serial-to-TCP bridge that kept TCP up while its serial port went.
    pub reopen_on_unresponsive: bool,
}

impl Default for ReconnectPolicy {
    fn default() -> Self {
        Self {
            initial_backoff: Duration::from_millis(500),
            max_backoff: Duration::from_secs(5),
            give_up_after: Duration::from_secs(60),
            reopen_on_unresponsive: false,
        }
    }
}

impl ReconnectPolicy {
    /// The delay before reopen attempt `attempt`, counting from 1.
    pub fn backoff(&self, attempt: u32) -> Duration {
        let factor = 2u32.saturating_pow(attempt.saturating_sub(1));
        self.initial_backoff
            .saturating_mul(factor)
            .min(self.max_backoff)
    }
}

#[derive(Clone)]
struct Reconnect {
    opener: TransportOpener,
    policy: ReconnectPolicy,
}

impl Reconnect {
    /// Retry the opener with backoff until it succeeds or the policy's budget runs out.
    async fn reopen(&self) -> Option<Box<dyn RcpTransport>> {
        let started = Instant::now();
        let mut attempt = 0;

        loop {
            attempt += 1;
            let delay = self.policy.backoff(attempt);
            if started.elapsed() + delay > self.policy.give_up_after {
                tracing::error!(
                    "Giving up on the RCP link after {} attempts over {:?}",
                    attempt - 1,
                    started.elapsed()
                );
                return None;
            }

            sleep(delay).await;

            match (self.opener)().await {
                Ok(transport) => {
                    tracing::info!("RCP link reopened on attempt {attempt}");
                    return Some(transport);
                }
                Err(err) => {
                    tracing::warn!("Reopening the RCP link failed (attempt {attempt}): {err}");
                }
            }
        }
    }
}

/// Set after a reopen: if the RCP has not announced a reset by `deadline` (the
/// protocol's reset count is still `seen`), one is synthesized so recovery still runs.
#[derive(Clone, Copy)]
struct ResetWatch {
    deadline: Instant,
    seen: u64,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SpinelTxFrame {
    pub psdu: Vec<u8>,
    pub channel: Option<u8>,
    pub max_csma_backoffs: Option<u8>,
    pub max_frame_retries: Option<u8>,
    pub enable_csma_ca: Option<bool>,
    pub is_header_updated: Option<bool>,
    pub is_a_retransmit: Option<bool>,
    pub is_security_processed: Option<bool>,
    pub tx_delay: Option<u32>,
    pub tx_delay_base_time: Option<u32>,
    pub rx_channel_after_tx: Option<u8>,
    pub tx_power: Option<i8>,
}

impl SpinelTxFrame {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(&(self.psdu.len() as u16).to_le_bytes());
        result.extend_from_slice(&self.psdu);

        // TODO: These are not really optional per-field, they must be contiguous: if a
        // field is not provided, all subsequent fields must be omitted as well
        if let Some(channel) = self.channel {
            result.push(channel);
        }

        if let Some(max_csma_backoffs) = self.max_csma_backoffs {
            result.push(max_csma_backoffs);
        }

        if let Some(max_frame_retries) = self.max_frame_retries {
            result.push(max_frame_retries);
        }

        if let Some(enable_csma_ca) = self.enable_csma_ca {
            result.push(enable_csma_ca as u8);
        }

        if let Some(is_header_updated) = self.is_header_updated {
            result.push(is_header_updated as u8);
        }

        if let Some(is_a_retransmit) = self.is_a_retransmit {
            result.push(is_a_retransmit as u8);
        }

        if let Some(is_security_processed) = self.is_security_processed {
            result.push(is_security_processed as u8);
        }

        if let Some(tx_delay) = self.tx_delay {
            result.extend_from_slice(&tx_delay.to_le_bytes());
        }

        if let Some(tx_delay_base_time) = self.tx_delay_base_time {
            result.extend_from_slice(&tx_delay_base_time.to_le_bytes());
        }

        if let Some(rx_channel_after_tx) = self.rx_channel_after_tx {
            result.push(rx_channel_after_tx);
        }

        if let Some(tx_power) = self.tx_power {
            result.push(tx_power as u8);
        }

        result
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SpinelRxFrame {
    pub psdu: FrameBytes,
    pub rssi: i8,
    pub noise_floor: i8,
    pub flags: u32,
    pub channel: u8,
    pub lqi: u8,
    pub timestamp_us: u64,
    pub receive_error: u8,
    pub manufacturer_specific: Vec<u8>,
}

#[derive(Error, Debug, PartialEq, Eq)]
pub enum SpinelRxFrameError {
    #[error("frame too short, expected at least {expected} bytes, got {got}")]
    TooShort { expected: usize, got: usize },
    #[error("PSDU too long to fit its frame bound, got {got} bytes")]
    PsduTooLong { got: usize },
}

impl SpinelRxFrame {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SpinelRxFrameError> {
        let mut offset = 0;

        // The 2-byte PSDU length prefix must be present before it can be read
        if bytes.len() < 2 {
            return Err(SpinelRxFrameError::TooShort {
                expected: 2,
                got: bytes.len(),
            });
        }
        let psdu_len = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]) as usize;
        offset += 2;

        // The PSDU is followed by a fixed metadata trailer: rssi, noise floor, flags,
        // channel, lqi, timestamp, and receive error
        let expected = offset + psdu_len + (1 + 1 + 4 + 1 + 1 + 8 + 1);
        if expected > bytes.len() {
            return Err(SpinelRxFrameError::TooShort {
                expected,
                got: bytes.len(),
            });
        }

        let psdu = FrameBytes::from_slice(&bytes[offset..offset + psdu_len])
            .map_err(|_| SpinelRxFrameError::PsduTooLong { got: psdu_len })?;
        offset += psdu_len;

        let rssi = bytes[offset] as i8;
        offset += 1;

        let noise_floor = bytes[offset] as i8;
        offset += 1;

        let flags = u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]);
        offset += 4;

        let channel = bytes[offset];
        offset += 1;

        let lqi = bytes[offset];
        offset += 1;

        let timestamp_us = u64::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
            bytes[offset + 4],
            bytes[offset + 5],
            bytes[offset + 6],
            bytes[offset + 7],
        ]);
        offset += 8;

        let receive_error = bytes[offset];
        offset += 1;

        let manufacturer_specific = bytes[offset..].to_vec();

        Ok(Self {
            psdu,
            rssi,
            noise_floor,
            flags,
            channel,
            lqi,
            timestamp_us,
            receive_error,
            manufacturer_specific,
        })
    }
}

#[derive(Error, Debug)]
pub enum SpinelError {
    #[error("io error")]
    IoError(#[from] std::io::Error),
    #[error("command cancelled by an RCP reset")]
    CancelledByReset,
    #[error("the spinel transport closed")]
    TransportClosed,
    #[error("timeout")]
    Timeout,
    #[error("spinel U21 parsing error")]
    U21ParsingError(#[from] SpinelFrameParsingError),
    #[error("invalid property id {property_id} in response")]
    InvalidResponsePropertyId { property_id: u32 },
    #[error("NCP version is not valid UTF-8")]
    NcpVersionNotUtf8,
    #[error("invalid hardware address: {got:02X?}")]
    InvalidHardwareAddress { got: Vec<u8> },
    #[error("unexpected response property: expected {expected:?}, got {got:?}")]
    UnexpectedResponseProperty {
        expected: SpinelPropertyId,
        got: SpinelPropertyId,
    },
    #[error("response payload was empty")]
    EmptyResponse,
    #[error("invalid spinel status {status}")]
    InvalidStatus { status: u8 },
}

/// The writer half of the port plus its serialization scratch: frames go out one at a
/// time, so two persistent buffers cover every TX without per-frame allocation.
struct SpinelWriter {
    port: WriteHalf<Box<dyn RcpTransport>>,
    frame_scratch: Vec<u8>,
    hdlc_scratch: Vec<u8>,
}

pub struct SpinelClient {
    /// The reader half of the port, owned by the task spawned in `spawn_reader`.
    reader: Mutex<Option<ReadHalf<Box<dyn RcpTransport>>>>,
    /// The writer half of the port. The mutex also serializes outbound HDLC writes so
    /// concurrent commands cannot interleave partial frames inside the byte stream.
    writer: Arc<AsyncMutex<SpinelWriter>>,
    pub protocol: Arc<Mutex<SpinelProtocol>>,
    /// Functional ownership of the radio (scan, reset recovery, channel retune), taken via
    /// [`Self::lock_radio`].
    exclusive_lock: AsyncMutex<()>,
    consecutive_timeouts: AtomicU32,
    /// How to reopen the link when it dies; `None` makes a dead link fatal.
    reconnect: Option<Reconnect>,
    /// Tells the reader the RCP stopped answering, per
    /// [`ReconnectPolicy::reopen_on_unresponsive`]. Capacity 1: one pending signal is
    /// enough.
    unresponsive_tx: mpsc::Sender<()>,
    unresponsive_rx: Mutex<Option<mpsc::Receiver<()>>>,
}

impl SpinelClient {
    pub fn new(port: Box<dyn RcpTransport>) -> Self {
        let (reader, writer) = tokio::io::split(port);
        let (unresponsive_tx, unresponsive_rx) = mpsc::channel(1);

        Self {
            reader: Mutex::new(Some(reader)),
            writer: Arc::new(AsyncMutex::new(SpinelWriter {
                port: writer,
                frame_scratch: Vec::with_capacity(SPINEL_FRAME_MAX_SIZE),
                // Worst-case HDLC escaping doubles the frame, plus two flags
                hdlc_scratch: Vec::with_capacity(2 * SPINEL_FRAME_MAX_SIZE + 2),
            })),
            protocol: Arc::new(Mutex::new(SpinelProtocol::new())),
            exclusive_lock: AsyncMutex::new(()),
            consecutive_timeouts: AtomicU32::new(0),
            reconnect: None,
            unresponsive_tx,
            unresponsive_rx: Mutex::new(Some(unresponsive_rx)),
        }
    }

    /// Reopen the link with `opener` when it hits EOF or a read error, instead of
    /// exiting. After a reopen the RCP is reset, and its reset notification drives the
    /// usual reset recovery, which reprograms the radio.
    #[must_use]
    pub fn with_reconnect(mut self, opener: TransportOpener, policy: ReconnectPolicy) -> Self {
        self.reconnect = Some(Reconnect { opener, policy });
        self
    }

    pub fn set_property_update_receiver(
        &self,
        property_id: SpinelPropertyId,
        tx: mpsc::Sender<SpinelFramePropValueIs>,
    ) {
        self.protocol
            .lock()
            .expect("Failed to lock Spinel")
            .property_update_receivers
            .insert(property_id, tx);
    }

    pub fn set_reset_notification_receiver(&self, tx: mpsc::Sender<SpinelStatus>) {
        self.protocol
            .lock()
            .expect("Failed to lock Spinel")
            .set_reset_notification_receiver(tx);
    }

    /// Start a reading loop to parse and handle inbound frames.
    ///
    /// A dead link (USB yank, EOF) is reopened per [`Self::with_reconnect`]. Once that
    /// fails, or without it, the whole process exits: the supervisor (Docker) restarts
    /// us. A half-dead process with a deaf radio is the worst failure mode.
    pub fn spawn_reader(&self) {
        let reader = self.reader_task();

        tokio::spawn(async move {
            reader.await;
            tracing::error!("RCP link lost, exiting");
            std::process::exit(1);
        });
    }

    /// The reading loop, resolving only once the link is lost for good.
    pub(crate) fn reader_task(&self) -> impl Future<Output = ()> + Send + 'static {
        let mut reader = self
            .reader
            .lock()
            .expect("Failed to lock reader")
            .take()
            .expect("Reader already taken");
        let protocol = Arc::clone(&self.protocol);
        let writer = Arc::clone(&self.writer);
        let reconnect = self.reconnect.clone();
        let mut unresponsive_rx = self
            .unresponsive_rx
            .lock()
            .expect("Failed to lock unresponsive receiver")
            .take()
            .expect("Unresponsive receiver already taken");

        async move {
            let mut buffer = [0u8; 2048];
            let mut reset_watch: Option<ResetWatch> = None;

            loop {
                let watch_deadline = reset_watch.map_or_else(Instant::now, |w| w.deadline);
                let read = tokio::select! {
                    read = reader.read(&mut buffer) => read,
                    () = sleep_until(watch_deadline), if reset_watch.is_some() => {
                        let watch = reset_watch.take().expect("Reset watch is set");
                        let mut protocol = protocol.lock().expect("Failed to lock Spinel");
                        if protocol.reset_count == watch.seen {
                            tracing::warn!(
                                "RCP did not announce its reset after the reopen, recovering anyway"
                            );
                            protocol.notify_reset(SpinelStatus::ResetUnknown);
                        }
                        drop(protocol);
                        continue;
                    }
                    Some(()) = unresponsive_rx.recv() => Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "RCP unresponsive, presuming the link dead",
                    )),
                };

                match read {
                    Ok(n) if n > 0 => {
                        protocol
                            .lock()
                            .expect("Failed to lock Spinel")
                            .handle_inbound_bytes(&buffer[..n]);
                        continue;
                    }
                    Ok(_) => tracing::error!("Serial port EOF"),
                    Err(e) => tracing::error!("Serial port read failed ({e})"),
                }

                // Nothing in flight can be answered over the dead link
                protocol
                    .lock()
                    .expect("Failed to lock Spinel")
                    .fail_all_pending_requests();

                let Some(reconnect) = &reconnect else {
                    return;
                };
                let Some(transport) = reconnect.reopen().await else {
                    return;
                };

                let (new_reader, new_writer) = tokio::io::split(transport);
                reader = new_reader;
                writer.lock().await.port = new_writer;
                // Timeouts piled up against the old link say nothing about the new one
                while unresponsive_rx.try_recv().is_ok() {}

                // Same as startup: reset the RCP. Its reset notification triggers the
                // driver's reset recovery, which reprograms the radio
                let seen = protocol.lock().expect("Failed to lock Spinel").reset_count;
                reset_watch = Some(ResetWatch {
                    deadline: Instant::now() + TIMEOUT,
                    seen,
                });
                if let Err(e) = write_frame(&writer, &reset_frame(SpinelResetReason::Stack)).await {
                    tracing::warn!("Failed to reset the RCP after the reopen: {e}");
                }
            }
        }
    }

    async fn send_frame(&self, frame: &SpinelFrame) -> Result<(), SpinelError> {
        write_frame(&self.writer, frame).await
    }

    /// `CMD_RESET` is acknowledged with an unsolicited `LastStatus = RESET_*`
    /// notification rather than a tid-matched response, so this only sends.
    pub async fn send_reset(&self, reason: SpinelResetReason) -> Result<(), SpinelError> {
        self.send_frame(&reset_frame(reason)).await
    }

    pub async fn send_command(
        &self,
        command_id: SpinelCommandId,
        payload: Vec<u8>,
    ) -> Result<SpinelFrame, SpinelError> {
        let (frame, rx) = {
            self.protocol
                .lock()
                .expect("Failed to lock Spinel")
                .prepare_request(command_id, payload)
        };

        tracing::trace!("Sending frame {frame:?}");

        self.send_frame(&frame).await?;

        match timeout(TIMEOUT, rx).await {
            Ok(Ok(response_frame)) => {
                self.consecutive_timeouts.store(0, Ordering::Relaxed);
                Ok(response_frame)
            }
            Ok(Err(_)) => {
                self.protocol
                    .lock()
                    .expect("Failed to lock Spinel")
                    .cancel_request(frame.header.transaction_id);

                Err(SpinelError::CancelledByReset)
            }
            Err(_) => {
                self.protocol
                    .lock()
                    .expect("Failed to lock Spinel")
                    .cancel_request(frame.header.transaction_id);

                let timeouts = self.consecutive_timeouts.fetch_add(1, Ordering::Relaxed) + 1;
                if timeouts >= MAX_CONSECUTIVE_TIMEOUTS {
                    self.consecutive_timeouts.store(0, Ordering::Relaxed);
                    if self
                        .reconnect
                        .as_ref()
                        .is_some_and(|r| r.policy.reopen_on_unresponsive)
                    {
                        tracing::error!(
                            "RCP unresponsive after {timeouts} consecutive command timeouts, reopening the link"
                        );
                        let _ = self.unresponsive_tx.try_send(());
                    } else {
                        tracing::error!(
                            "RCP unresponsive after {timeouts} consecutive command timeouts, triggering reset recovery"
                        );
                        self.protocol
                            .lock()
                            .expect("Failed to lock Spinel")
                            .notify_reset(SpinelStatus::ResponseTimeout);
                    }
                }

                Err(SpinelError::Timeout)
            }
        }
    }

    pub async fn prop_value_get(
        &self,
        property_id: SpinelPropertyId,
    ) -> Result<Vec<u8>, SpinelError> {
        match self.prop_value_get_once(property_id).await {
            Err(SpinelError::Timeout) => self.prop_value_get_once(property_id).await,
            result => result,
        }
    }

    async fn prop_value_get_once(
        &self,
        property_id: SpinelPropertyId,
    ) -> Result<Vec<u8>, SpinelError> {
        let response = self
            .send_command(
                SpinelCommandId::PropValueGet,
                packed_uint21_to_bytes(property_id as u32),
            )
            .await?;

        let response_payload = response.payload;
        let (_rsp_property_id, payload) =
            packed_uint21_deserialize(&response_payload).map_err(SpinelError::U21ParsingError)?;

        Ok(payload.to_vec())
    }

    pub async fn prop_value_set(
        &self,
        property_id: SpinelPropertyId,
        value: Vec<u8>,
    ) -> Result<(SpinelPropertyId, Vec<u8>), SpinelError> {
        match self.prop_value_set_once(property_id, value.clone()).await {
            Err(SpinelError::Timeout) => self.prop_value_set_once(property_id, value).await,
            result => result,
        }
    }

    async fn prop_value_set_once(
        &self,
        property_id: SpinelPropertyId,
        value: Vec<u8>,
    ) -> Result<(SpinelPropertyId, Vec<u8>), SpinelError> {
        let response = self
            .send_command(
                SpinelCommandId::PropValueSet,
                packed_uint21_to_bytes(property_id as u32)
                    .iter()
                    .chain(value.iter())
                    .cloned()
                    .collect(),
            )
            .await?;

        let response_payload = response.payload;
        let (rsp_property_id_int, payload) =
            packed_uint21_deserialize(&response_payload).map_err(SpinelError::U21ParsingError)?;

        let rsp_property_id = SpinelPropertyId::try_from(rsp_property_id_int).map_err(|_| {
            SpinelError::InvalidResponsePropertyId {
                property_id: rsp_property_id_int,
            }
        })?;

        tracing::trace!(
            "Setting property {property_id:?}={value:02X?}, result {rsp_property_id:?}={payload:02X?}"
        );

        Ok((rsp_property_id, payload.to_vec()))
    }

    /// Take functional ownership of the radio, fencing out transmits for the life of the
    /// guard. The right tool for any operation that drives the radio across multiple
    /// commands: scans, channel retune, reset recovery. The guard can itself transmit —
    /// see [`ExclusiveRadio::transmit_frame`].
    pub async fn lock_radio(&self) -> ExclusiveRadio<'_> {
        ExclusiveRadio {
            client: self,
            _guard: self.exclusive_lock.lock().await,
        }
    }

    // Convenience method wrapping broad functionality are below
    pub async fn get_ncp_version(&self) -> Result<String, SpinelError> {
        let ncp_version_rsp = self.prop_value_get(SpinelPropertyId::NcpVersion).await?;

        let ncp_version_with_null =
            String::from_utf8(ncp_version_rsp).map_err(|_| SpinelError::NcpVersionNotUtf8)?;

        Ok(ncp_version_with_null
            .trim_matches(char::from(0x00))
            .to_string())
    }

    /// The radio's factory-programmed EUI64, a core property readable in any RCP state.
    pub async fn get_hw_address(&self) -> Result<Eui64, SpinelError> {
        let rsp = self.prop_value_get(SpinelPropertyId::Hwaddr).await?;

        let bytes: [u8; 8] = rsp
            .try_into()
            .map_err(|rsp: Vec<u8>| SpinelError::InvalidHardwareAddress { got: rsp })?;

        Ok(Eui64::from_be_bytes(bytes))
    }

    pub async fn transmit_frame(
        &self,
        tx_frame: &SpinelTxFrame,
    ) -> Result<SpinelStatus, SpinelError> {
        let _exclusive_lock = self.exclusive_lock.lock().await;
        self.transmit_frame_inner(tx_frame).await
    }

    /// Put a frame on the air, assuming the caller already holds the radio.
    async fn transmit_frame_inner(
        &self,
        tx_frame: &SpinelTxFrame,
    ) -> Result<SpinelStatus, SpinelError> {
        // No retry on timeout: a duplicate transmit is worse than a failed one, and the
        // NWK retry paths handle the failure
        let (rsp_prop_id, rsp) = self
            .prop_value_set_once(SpinelPropertyId::StreamRaw, tx_frame.to_bytes())
            .await?;

        if rsp_prop_id != SpinelPropertyId::LastStatus {
            return Err(SpinelError::UnexpectedResponseProperty {
                expected: SpinelPropertyId::LastStatus,
                got: rsp_prop_id,
            });
        }

        if rsp.is_empty() {
            return Err(SpinelError::EmptyResponse);
        }

        SpinelStatus::try_from(rsp[0]).map_err(|_| SpinelError::InvalidStatus { status: rsp[0] })
    }
}

fn reset_frame(reason: SpinelResetReason) -> SpinelFrame {
    SpinelFrame {
        header: SpinelHeader {
            flag: 0b10,
            network_link_id: 0,
            transaction_id: 0,
        },
        command_id: SpinelCommandId::Reset,
        payload: vec![reason as u8],
    }
}

/// Serialize and HDLC-frame `frame` into the writer's persistent scratch buffers
/// and put it on the wire.
// The writer lock is intentionally held until the write completes: it is what
// serializes outbound frames on the wire
#[allow(clippy::significant_drop_tightening)]
async fn write_frame(
    writer: &AsyncMutex<SpinelWriter>,
    frame: &SpinelFrame,
) -> Result<(), SpinelError> {
    let mut writer = writer.lock().await;
    let SpinelWriter {
        port,
        frame_scratch,
        hdlc_scratch,
    } = &mut *writer;

    frame_scratch.clear();
    frame.serialize_into(frame_scratch);

    hdlc_scratch.clear();
    hdlc_scratch.push(HdlcSpecial::Flag as u8);
    hdlc_escape_into(frame_scratch, hdlc_scratch);
    hdlc_scratch.push(HdlcSpecial::Flag as u8);

    tracing::trace!("Writing {hdlc_scratch:02X?}");

    port.write_all(hdlc_scratch)
        .await
        .map_err(SpinelError::IoError)?;

    Ok(())
}

/// Functional ownership of the radio, handed out by [`SpinelClient::lock_radio`].
pub struct ExclusiveRadio<'a> {
    client: &'a SpinelClient,
    _guard: tokio::sync::MutexGuard<'a, ()>,
}

impl ExclusiveRadio<'_> {
    /// Put a frame on the air while owning the radio.
    pub async fn transmit_frame(
        &self,
        tx_frame: &SpinelTxFrame,
    ) -> Result<SpinelStatus, SpinelError> {
        self.client.transmit_frame_inner(tx_frame).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SpinelFramePropValueIs;
    use std::collections::VecDeque;
    use std::io;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{DuplexStream, ReadBuf, duplex};
    use tokio::time::Instant;

    /// One scripted result per reopen attempt; once exhausted, every attempt fails.
    type Script = Arc<Mutex<VecDeque<io::Result<Box<dyn RcpTransport>>>>>;

    /// An opener replaying `script` and recording the instant of every attempt.
    fn scripted_opener(script: Script, attempts: Arc<Mutex<Vec<Instant>>>) -> TransportOpener {
        Arc::new(move || {
            attempts.lock().unwrap().push(Instant::now());
            let next = script.lock().unwrap().pop_front();
            Box::pin(async move {
                next.unwrap_or_else(|| Err(io::Error::from(io::ErrorKind::NotFound)))
            })
        })
    }

    fn not_found() -> io::Result<Box<dyn RcpTransport>> {
        Err(io::Error::from(io::ErrorKind::NotFound))
    }

    /// A fake RCP link: the client end as a transport, and the RCP's end for the test.
    fn link() -> (Box<dyn RcpTransport>, DuplexStream) {
        let (host, rcp) = duplex(4096);
        (Box::new(host), rcp)
    }

    /// A transport whose every read fails, as a yanked USB serial port does.
    struct BrokenTransport;

    impl AsyncRead for BrokenTransport {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::Error::other(
                "device reports readiness to read but returned no data",
            )))
        }
    }

    impl AsyncWrite for BrokenTransport {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn hdlc(frame: &SpinelFrame) -> Vec<u8> {
        let mut out = vec![HdlcSpecial::Flag as u8];
        hdlc_escape_into(&frame.to_bytes(), &mut out);
        out.push(HdlcSpecial::Flag as u8);
        out
    }

    fn reset_command() -> Vec<u8> {
        hdlc(&SpinelFrame {
            header: SpinelHeader {
                flag: 0b10,
                network_link_id: 0,
                transaction_id: 0,
            },
            command_id: SpinelCommandId::Reset,
            payload: vec![SpinelResetReason::Stack as u8],
        })
    }

    fn reset_announcement(status: SpinelStatus) -> Vec<u8> {
        hdlc(&SpinelFrame {
            header: SpinelHeader {
                flag: 0b10,
                network_link_id: 0,
                transaction_id: 0,
            },
            command_id: SpinelCommandId::PropValueIs,
            payload: SpinelFramePropValueIs {
                property_id: SpinelPropertyId::LastStatus,
                value: packed_uint21_to_bytes(status as u32),
            }
            .to_bytes(),
        })
    }

    async fn read_exactly(rcp: &mut DuplexStream, len: usize) -> Vec<u8> {
        let mut buf = vec![0u8; len];
        rcp.read_exact(&mut buf).await.unwrap();
        buf
    }

    struct Harness {
        client: Arc<SpinelClient>,
        attempts: Arc<Mutex<Vec<Instant>>>,
        resets: mpsc::Receiver<SpinelStatus>,
        reader: tokio::task::JoinHandle<()>,
    }

    /// A client on `initial`, reconnecting per `script` under the default policy, with
    /// its reader running as a task.
    fn harness(
        initial: Box<dyn RcpTransport>,
        script: Vec<io::Result<Box<dyn RcpTransport>>>,
    ) -> Harness {
        harness_with(ReconnectPolicy::default(), initial, script)
    }

    fn harness_with(
        policy: ReconnectPolicy,
        initial: Box<dyn RcpTransport>,
        script: Vec<io::Result<Box<dyn RcpTransport>>>,
    ) -> Harness {
        let attempts = Arc::new(Mutex::new(Vec::new()));
        let opener = scripted_opener(
            Arc::new(Mutex::new(script.into_iter().collect())),
            Arc::clone(&attempts),
        );
        let client = Arc::new(SpinelClient::new(initial).with_reconnect(opener, policy));
        let (reset_tx, resets) = mpsc::channel(8);
        client.set_reset_notification_receiver(reset_tx);
        let reader = tokio::spawn(client.reader_task());

        Harness {
            client,
            attempts,
            resets,
            reader,
        }
    }

    fn offsets(attempts: &[Instant], start: Instant) -> Vec<Duration> {
        attempts.iter().map(|at| *at - start).collect()
    }

    #[test]
    fn backoff_doubles_from_initial_and_caps_at_max() {
        let policy = ReconnectPolicy::default();
        let delays: Vec<_> = (1..=6).map(|n| policy.backoff(n)).collect();

        assert_eq!(
            delays,
            [500, 1000, 2000, 4000, 5000, 5000].map(Duration::from_millis)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn eof_reopens_with_backoff_and_resets_the_rcp() {
        let (initial, rcp_old) = link();
        let (fresh, mut rcp_new) = link();
        let h = harness(initial, vec![not_found(), not_found(), Ok(fresh)]);

        let start = Instant::now();
        drop(rcp_old);

        let reset = reset_command();
        assert_eq!(read_exactly(&mut rcp_new, reset.len()).await, reset);
        assert_eq!(
            offsets(&h.attempts.lock().unwrap(), start),
            [500, 1500, 3500].map(Duration::from_millis)
        );
        assert!(!h.reader.is_finished());
    }

    #[tokio::test(start_paused = true)]
    async fn eof_fails_pending_commands_with_cancelled_by_reset() {
        let (initial, rcp_old) = link();
        let (fresh, _rcp_new) = link();
        let h = harness(initial, vec![Ok(fresh)]);

        let client = Arc::clone(&h.client);
        let pending = tokio::spawn(async move {
            client
                .prop_value_get_once(SpinelPropertyId::NcpVersion)
                .await
        });
        tokio::task::yield_now().await;
        drop(rcp_old);

        assert!(matches!(
            pending.await.unwrap(),
            Err(SpinelError::CancelledByReset)
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn rcp_reset_announcement_on_the_new_link_reaches_the_reset_receiver() {
        let (initial, rcp_old) = link();
        let (fresh, mut rcp_new) = link();
        let mut h = harness(initial, vec![Ok(fresh)]);
        drop(rcp_old);

        let reset = reset_command();
        read_exactly(&mut rcp_new, reset.len()).await;
        rcp_new
            .write_all(&reset_announcement(SpinelStatus::ResetSoftware))
            .await
            .unwrap();

        assert_eq!(h.resets.recv().await, Some(SpinelStatus::ResetSoftware));
        // The announcement satisfied the watchdog: no synthesized reset follows
        tokio::time::sleep(TIMEOUT * 2).await;
        assert!(h.resets.try_recv().is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn silent_rcp_after_reopen_gets_a_synthesized_reset() {
        let (initial, rcp_old) = link();
        let (fresh, mut rcp_new) = link();
        let mut h = harness(initial, vec![Ok(fresh)]);
        drop(rcp_old);

        let reset = reset_command();
        read_exactly(&mut rcp_new, reset.len()).await;
        let sent = Instant::now();

        assert_eq!(h.resets.recv().await, Some(SpinelStatus::ResetUnknown));
        assert_eq!(Instant::now() - sent, TIMEOUT);
    }

    #[tokio::test(start_paused = true)]
    async fn read_error_is_handled_like_eof() {
        let (fresh, mut rcp_new) = link();
        let h = harness(Box::new(BrokenTransport), vec![Ok(fresh)]);

        let reset = reset_command();
        assert_eq!(read_exactly(&mut rcp_new, reset.len()).await, reset);
        assert_eq!(h.attempts.lock().unwrap().len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn gives_up_once_the_reconnect_budget_is_spent() {
        let (initial, rcp_old) = link();
        let h = harness(initial, Vec::new());

        let start = Instant::now();
        drop(rcp_old);
        h.reader.await.unwrap();

        let budget = ReconnectPolicy::default().give_up_after;
        let attempts = offsets(&h.attempts.lock().unwrap(), start);
        assert!(!attempts.is_empty());
        assert!(attempts.iter().all(|at| *at <= budget));
        assert!(Instant::now() - start <= budget);
    }

    #[tokio::test(start_paused = true)]
    async fn without_reconnect_eof_ends_the_reader_at_once() {
        let (initial, rcp_old) = link();
        let client = SpinelClient::new(initial);
        let reader = tokio::spawn(client.reader_task());

        let start = Instant::now();
        drop(rcp_old);
        reader.await.unwrap();

        assert_eq!(Instant::now(), start);
    }

    #[tokio::test(start_paused = true)]
    async fn commands_work_again_over_the_new_link() {
        let (initial, rcp_old) = link();
        let (fresh, mut rcp_new) = link();
        let h = harness(initial, vec![Ok(fresh)]);
        drop(rcp_old);

        let reset = reset_command();
        read_exactly(&mut rcp_new, reset.len()).await;

        let client = Arc::clone(&h.client);
        let version = tokio::spawn(async move { client.get_ncp_version().await });

        // Answer the request with the tid it was sent with
        let mut request = vec![0u8; 64];
        let n = rcp_new.read(&mut request).await.unwrap();
        let mut unescaped = Vec::new();
        crate::hdlc_unescape_into(&request[..n], &mut unescaped).unwrap();
        let tid = SpinelHeader::from_bytes(&unescaped).unwrap().transaction_id;
        let mut payload = packed_uint21_to_bytes(SpinelPropertyId::NcpVersion as u32);
        payload.extend_from_slice(b"OPENTHREAD/test\0");
        rcp_new
            .write_all(&hdlc(&SpinelFrame {
                header: SpinelHeader {
                    flag: 0b10,
                    network_link_id: 0,
                    transaction_id: tid,
                },
                command_id: SpinelCommandId::PropValueIs,
                payload,
            }))
            .await
            .unwrap();

        assert_eq!(version.await.unwrap().unwrap(), "OPENTHREAD/test");
    }

    const REOPEN_ON_UNRESPONSIVE: ReconnectPolicy = ReconnectPolicy {
        initial_backoff: Duration::from_millis(500),
        max_backoff: Duration::from_secs(5),
        give_up_after: Duration::from_secs(60),
        reopen_on_unresponsive: true,
    };

    /// Send commands one after another to a silent RCP until `count` have timed out. A
    /// command in flight when the link is presumed dead is cancelled instead.
    async fn time_out_commands(client: &SpinelClient, count: u32) {
        let mut timeouts = 0;
        while timeouts < count {
            match client
                .prop_value_get_once(SpinelPropertyId::NcpVersion)
                .await
            {
                Err(SpinelError::Timeout) => timeouts += 1,
                Err(SpinelError::CancelledByReset) => {}
                other => panic!("unexpected result {other:?}"),
            }
        }
    }

    #[test]
    fn reopen_on_unresponsive_is_off_by_default() {
        assert!(!ReconnectPolicy::default().reopen_on_unresponsive);
    }

    #[tokio::test(start_paused = true)]
    async fn unresponsive_link_is_reopened_when_enabled() {
        // The old link stays open but silent, like a TCP peer that vanished
        let (initial, _rcp_old) = link();
        let (fresh, mut rcp_new) = link();
        let mut h = harness_with(REOPEN_ON_UNRESPONSIVE, initial, vec![Ok(fresh)]);

        time_out_commands(&h.client, MAX_CONSECUTIVE_TIMEOUTS).await;
        let stalled = Instant::now();

        let reset = reset_command();
        assert_eq!(read_exactly(&mut rcp_new, reset.len()).await, reset);
        assert_eq!(
            offsets(&h.attempts.lock().unwrap(), stalled),
            [ReconnectPolicy::default().initial_backoff]
        );
        assert!(h.resets.try_recv().is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn timeouts_during_a_reopen_do_not_drop_the_new_link() {
        let (initial, _rcp_old) = link();
        let (fresh, mut rcp_new) = link();
        // Five failures: the sixth attempt succeeds 12.5 s in
        let mut script: Vec<_> = (0..5).map(|_| not_found()).collect();
        script.push(Ok(fresh));
        let h = harness_with(REOPEN_ON_UNRESPONSIVE, initial, script);

        time_out_commands(&h.client, MAX_CONSECUTIVE_TIMEOUTS).await;
        // The writer still points at the old silent link until the reopen succeeds
        time_out_commands(&h.client, MAX_CONSECUTIVE_TIMEOUTS).await;

        let reset = reset_command();
        read_exactly(&mut rcp_new, reset.len()).await;
        tokio::time::sleep(Duration::from_secs(30)).await;

        assert_eq!(h.attempts.lock().unwrap().len(), 6);
        assert!(!h.reader.is_finished());
    }

    #[tokio::test(start_paused = true)]
    async fn unresponsive_link_gets_a_reset_by_default() {
        let (initial, _rcp_old) = link();
        let mut h = harness(initial, Vec::new());

        time_out_commands(&h.client, MAX_CONSECUTIVE_TIMEOUTS).await;

        assert_eq!(h.resets.try_recv(), Ok(SpinelStatus::ResponseTimeout));
        tokio::time::sleep(Duration::from_secs(10)).await;
        assert!(h.attempts.lock().unwrap().is_empty());
    }
}
