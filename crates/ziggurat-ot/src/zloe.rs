//! SPIKE: the ZLOE backbone around the radio (feature `zloe`). [`ZloePhy`] is `ZloeCore`
//! on this runtime: a blocking mutex, the platform clock, and datagrams that leave through
//! `ziggurat_platform_zloe_send` and arrive through `ziggurat_zloe_datagram`. The firmware
//! glue owns the socket and discovery. Every `ziggurat_zloe_*` call is made from the same
//! context as the other `ziggurat_*` calls. IPv6 only.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use core::sync::atomic::{AtomicPtr, Ordering};
use core::time::Duration;

use embassy_futures::select::{select, Either};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::blocking_mutex::Mutex as BlockingMutex;
use embassy_sync::channel::Channel;
use embassy_sync::signal::Signal;
use ziggurat_ieee_802154::types::{Eui64, Nwk};
use ziggurat_phy::{RadioConfig, RadioError, RadioPhy, Receiver, RxFrame, TxFrame, TxResult};
use ziggurat_zloe_core::{
    AckOutcome, BackboneTransport, Clock, CoreLock, Inbound, MacHeader, Resolved, ZloeCore,
    ZloeState, KIND_NETINFO_REQ, MAC_FRAME_DATA,
};

use crate::platform;

/// A peer's IPv6 address and UDP port.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ZigguratZloeAddr {
    pub addr: [u8; 16],
    pub port: u16,
    /// The interface of a link-local address.
    pub scope: u32,
}

/// One peer, for `ziggurat_zloe_peers`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ZigguratZloePeer {
    /// In 802.15.4 wire order.
    pub eui64: [u8; 8],
    pub nwk: u16,
    pub has_nwk: bool,
    pub live: bool,
    pub lqi: u8,
    /// Milliseconds since its last datagram; `UINT32_MAX` when it never sent one.
    pub last_rx_age_ms: u32,
    pub addr: ZigguratZloeAddr,
}

unsafe extern "C" {
    /// Queue one datagram for `to`. Must not block. False when it could not be queued.
    pub fn ziggurat_platform_zloe_send(
        to: *const ZigguratZloeAddr,
        data: *const u8,
        len: usize,
    ) -> bool;

    /// The network settings a coordinator answered with (an encoded `NetworkInfoPayload`).
    pub fn ziggurat_platform_zloe_netinfo(data: *const u8, len: usize);
}

const BACKBONE_RX_DEPTH: usize = 16;
static BACKBONE_RX: Channel<CriticalSectionRawMutex, RxFrame, BACKBONE_RX_DEPTH> = Channel::new();

pub struct Lock(BlockingMutex<CriticalSectionRawMutex, RefCell<ZloeState>>);

impl CoreLock for Lock {
    fn with<R>(&self, f: impl FnOnce(&mut ZloeState) -> R) -> R {
        self.0.lock(|cell| f(&mut cell.borrow_mut()))
    }
}

pub struct PlatformClock;

impl Clock for PlatformClock {
    fn now_ms(&self) -> u64 {
        unsafe { platform::ziggurat_platform_time_now_us() / 1000 }
    }
}

type AckSignal = Signal<CriticalSectionRawMutex, ()>;

pub struct FfiTransport {
    pending: BlockingMutex<CriticalSectionRawMutex, RefCell<Vec<(u32, Arc<AckSignal>)>>>,
}

fn to_ffi(addr: SocketAddr) -> Option<ZigguratZloeAddr> {
    match addr {
        SocketAddr::V6(v6) => Some(ZigguratZloeAddr {
            addr: v6.ip().octets(),
            port: v6.port(),
            scope: v6.scope_id(),
        }),
        SocketAddr::V4(_) => None,
    }
}

fn from_ffi(addr: &ZigguratZloeAddr) -> SocketAddr {
    SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::from(addr.addr),
        addr.port,
        0,
        addr.scope,
    ))
}

fn platform_send(to: SocketAddr, datagram: &[u8]) -> bool {
    to_ffi(to).is_some_and(|to| unsafe {
        ziggurat_platform_zloe_send(&raw const to, datagram.as_ptr(), datagram.len())
    })
}

impl BackboneTransport for FfiTransport {
    async fn send(&self, to: SocketAddr, datagram: &[u8]) -> bool {
        platform_send(to, datagram)
    }

    async fn send_wait_ack(
        &self,
        to: SocketAddr,
        datagram: &[u8],
        seq: u32,
        timeout_ms: u64,
    ) -> AckOutcome {
        let signal = Arc::new(AckSignal::new());
        self.pending
            .lock(|p| p.borrow_mut().push((seq, signal.clone())));
        let outcome = if !platform_send(to, datagram) {
            AckOutcome::SendFailed
        } else if embassy_time::with_timeout(
            embassy_time::Duration::from_millis(timeout_ms),
            signal.wait(),
        )
        .await
        .is_ok()
        {
            AckOutcome::Acked
        } else {
            AckOutcome::TimedOut
        };
        self.pending.lock(|p| {
            p.borrow_mut()
                .retain(|(_, waiting)| !Arc::ptr_eq(waiting, &signal));
        });
        outcome
    }

    fn complete_ack(&self, seq: u32) -> bool {
        self.pending.lock(|p| {
            p.borrow()
                .iter()
                .find(|(waiting, _)| *waiting == seq)
                .is_some_and(|(_, signal)| {
                    signal.signal(());
                    true
                })
        })
    }
}

pub type Core = ZloeCore<Lock, PlatformClock, FfiTransport>;

static CORE: AtomicPtr<Core> = AtomicPtr::new(core::ptr::null_mut());

fn core_ref() -> Option<&'static Core> {
    unsafe { CORE.load(Ordering::Acquire).as_ref() }
}

/// Makes the core, once, from `ziggurat_start`.
pub fn init() {
    let mut seed = [0u8; 4];
    unsafe { platform::ziggurat_platform_entropy(seed.as_mut_ptr(), seed.len()) };
    let core = Box::new(ZloeCore::new(
        Lock(BlockingMutex::new(RefCell::new(ZloeState::new(
            u32::from_le_bytes(seed),
        )))),
        PlatformClock,
        FfiTransport {
            pending: BlockingMutex::new(RefCell::new(Vec::new())),
        },
    ));
    CORE.store(Box::into_raw(core), Ordering::Release);
}

/// A radio with the backbone around it.
pub struct ZloePhy<P: RadioPhy> {
    inner: P,
}

impl<P: RadioPhy> ZloePhy<P> {
    pub const fn new(inner: P) -> Self {
        Self { inner }
    }
}

/// The radio's and the backbone's received frames on one stream.
pub struct ZloeRx<R> {
    inner: R,
}

impl<R: Receiver<RxFrame>> Receiver<RxFrame> for ZloeRx<R> {
    async fn recv(&mut self) -> Option<RxFrame> {
        loop {
            match select(self.inner.recv(), BACKBONE_RX.receive()).await {
                Either::First(None) => return None,
                Either::First(Some(frame)) => {
                    if core_ref().is_none_or(|core| core.keep_air_frame(&frame.psdu)) {
                        return Some(frame);
                    }
                }
                Either::Second(frame) => return Some(frame),
            }
        }
    }
}

impl<P: RadioPhy> RadioPhy for ZloePhy<P> {
    type Exclusive<'a> = P::Exclusive<'a>;
    type RxStream = ZloeRx<P::RxStream>;
    type ResetStream = P::ResetStream;

    async fn reset(&self) -> Result<(), RadioError> {
        self.inner.reset().await
    }

    async fn reconfigure(&self, config: &RadioConfig) -> Result<(), RadioError> {
        self.inner.reconfigure(config).await?;
        // The capture config uses a broadcast address; there is no identity to announce
        if config.short_address != Nwk(0xFFFF) && !config.promiscuous {
            if let Some(core) = core_ref() {
                core.state.with(|s| {
                    s.set_radio(
                        config.extended_address,
                        config.short_address,
                        config.channel,
                    )
                });
            }
        }
        Ok(())
    }

    async fn set_frame_pending_table(
        &self,
        short: &[Nwk],
        extended: &[Eui64],
    ) -> Result<(), RadioError> {
        self.inner.set_frame_pending_table(short, extended).await
    }

    async fn transmit(&self, frame: TxFrame) -> Result<TxResult, RadioError> {
        if let (Some(core), Some(mac)) = (core_ref(), MacHeader::parse(&frame.psdu)) {
            if mac.dest.is_broadcast() {
                // Beacon requests and other MAC commands mean nothing to backbone peers
                if mac.frame_type == MAC_FRAME_DATA {
                    core.send_broadcast(&frame.psdu, false, &[]).await;
                }
            } else if core.send_to_peer(&mac, &frame.psdu).await {
                return Ok(TxResult::Acked);
            }
        }
        self.inner.transmit(frame).await
    }

    async fn energy_detect(&self, channel: u8, duration: Duration) -> Result<i8, RadioError> {
        self.inner.energy_detect(channel, duration).await
    }

    async fn lock(&self) -> Self::Exclusive<'_> {
        self.inner.lock().await
    }

    fn subscribe_rx(&self) -> Self::RxStream {
        ZloeRx {
            inner: self.inner.subscribe_rx(),
        }
    }

    fn subscribe_reset(&self) -> Self::ResetStream {
        self.inner.subscribe_reset()
    }
}

/// One datagram from the backbone.
///
/// # Safety
/// `data` must point to `len` readable bytes, `from` to a valid address.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ziggurat_zloe_datagram(
    data: *const u8,
    len: usize,
    from: *const ZigguratZloeAddr,
) {
    let Some(core) = core_ref() else { return };
    let buf = unsafe { core::slice::from_raw_parts(data, len) };
    let from = from_ffi(unsafe { &*from });
    match core.on_datagram(buf, from) {
        Inbound::NetinfoResponse(info) => unsafe {
            ziggurat_platform_zloe_netinfo(info.as_ptr(), info.len());
        },
        Inbound::Data { frame, reply } => {
            if let Some(frame) = frame {
                let _ = BACKBONE_RX.try_send(frame);
            }
            if let Some(reply) = reply {
                platform_send(from, &reply);
            }
        }
        // We never serve network settings
        Inbound::NetinfoRequest { .. } | Inbound::Nothing => {}
    }
}

/// Discovery resolved a node. `eui64` and `epan` are in 802.15.4 wire order.
///
/// # Safety
/// `eui64` and `epan` must point to 8 readable bytes, `addrs` to `addr_count` addresses,
/// best first.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ziggurat_zloe_peer_resolved(
    eui64: *const u8,
    epan: *const u8,
    nwk: u16,
    coordinator: bool,
    addrs: *const ZigguratZloeAddr,
    addr_count: usize,
) {
    let Some(core) = core_ref() else { return };
    let eui64 = Eui64(unsafe { *eui64.cast::<[u8; 8]>() });
    let epan = Eui64(unsafe { *epan.cast::<[u8; 8]>() });
    let addrs = unsafe { core::slice::from_raw_parts(addrs, addr_count) };
    let candidates = addrs
        .iter()
        .enumerate()
        .map(|(rank, a)| ((rank as u8, 0), from_ffi(a)))
        .collect();
    core.state.with(|s| {
        s.on_resolved(
            eui64,
            Resolved {
                epan: Some(epan),
                nwk: Some(Nwk(nwk)),
                candidates,
                mcast: [None, None],
                quic_port: None,
            },
            coordinator,
        );
    });
}

/// Discovery says a node went away.
///
/// # Safety
/// `eui64` must point to 8 readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ziggurat_zloe_peer_removed(eui64: *const u8) {
    let Some(core) = core_ref() else { return };
    let eui64 = Eui64(unsafe { *eui64.cast::<[u8; 8]>() });
    core.state.with(|s| s.on_removed(eui64));
}

/// The network's extended PAN ID, in 802.15.4 wire order.
///
/// # Safety
/// `epan` must point to 8 readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ziggurat_zloe_set_epan(epan: *const u8) {
    let Some(core) = core_ref() else { return };
    let epan = Eui64(unsafe { *epan.cast::<[u8; 8]>() });
    core.state.with(|s| s.set_epan(epan));
}

/// Ask the first coordinator discovery found for the network settings; they arrive through
/// `ziggurat_platform_zloe_netinfo`. False when none is known yet.
#[unsafe(no_mangle)]
pub extern "C" fn ziggurat_zloe_request_netinfo() -> bool {
    let Some(core) = core_ref() else { return false };
    let Some((addr, request)) = core.state.with(|s| {
        let addr = s.coordinators.values().next().map(|(addr, _)| *addr)?;
        let seq = s.next_seq();
        Some((addr, s.netinfo_header(KIND_NETINFO_REQ, seq)))
    }) else {
        return false;
    };
    platform_send(addr, &request)
}

/// Copy up to `cap` peers into `out`; returns how many were written.
///
/// # Safety
/// `out` must have room for `cap` peers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ziggurat_zloe_peers(out: *mut ZigguratZloePeer, cap: usize) -> usize {
    let Some(core) = core_ref() else { return 0 };
    let now = core.clock.now_ms();
    core.state.with(|s| {
        let mut written = 0;
        for (eui64, peer) in s.peers.iter().take(cap) {
            let Some(addr) = to_ffi(peer.addr) else {
                continue;
            };
            let entry = ZigguratZloePeer {
                eui64: eui64.0,
                nwk: peer.nwk.map_or(0xFFFF, |n| n.0),
                has_nwk: peer.nwk.is_some(),
                live: peer.live(now),
                lqi: peer.lqi(),
                last_rx_age_ms: peer.last_rx_ms.map_or(u32::MAX, |t| {
                    u32::try_from(now.saturating_sub(t)).unwrap_or(u32::MAX - 1)
                }),
                addr,
            };
            unsafe { out.add(written).write(entry) };
            written += 1;
        }
        written
    })
}
