//! SPIKE (throwaway): ZLOE (Zigbee Link Over Ethernet), a TREL-like IP backbone,
//! wrapped around any [`RadioPhy`].
//!
//! The backbone behaves as a second 802.15.4 "radio" that only reaches other Ziggurat
//! nodes. Raw 802.15.4 frames (FCS stripped) are carried in UDP datagrams:
//!
//! * unicasts whose MAC destination is a known backbone peer go over UDP only, with a
//!   tiny ack/retransmit standing in for the MAC ACK, falling back to the air on
//!   failure;
//! * broadcasts go over the air *and* to every backbone peer (NWK broadcast dedup
//!   absorbs the duplicates);
//! * frames received over the backbone carry an LQI derived from the backbone link's
//!   health (ack success), 255 when clean, so NWK link costs to backbone peers are low
//!   and routing prefers the backbone without NWK changes; over-the-air copies of a
//!   live backbone peer's frames are dropped (they also come over the backbone), so the
//!   peer's link quality is not mixed with the radio's.
//!
//! Peers are discovered with mDNS/DNS-SD (`_zloe._udp`, TXT `xa`/`xp` as in TREL),
//! configured statically, or learned from the first datagram they send us. Transport
//! is one dual-stack UDP socket: IPv6 link-local is preferred, IPv4 works too.
//!
//! A test-only deny list fakes "out of radio range": over-the-air frames whose MAC
//! source is denied are dropped, and over-the-air unicasts to a denied MAC destination
//! report `NoAck` without being transmitted. The RCP still auto-ACKs frames from denied
//! devices at the hardware level; see the spike notes.

pub mod quic;
pub mod security;

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use ziggurat_ieee_802154::types::{Eui64, Nwk};
use ziggurat_phy::{RadioConfig, RadioError, RadioPhy, Receiver, RxFrame, TxFrame, TxResult};
use ziggurat_zloe_core::{
    ACK_TIMEOUT_MS, ATTEMPTS, AckOutcome, BackboneTransport, Clock, CoreLock, FLAG_ACK_REQUEST,
    Identity, Inbound, KIND_NETINFO_REQ, KIND_NETINFO_RSP, MAC_FRAME_DATA, MacAddress, MacHeader,
    Resolved, V4, V6, VERSION, ZloeCore, ZloeState,
};

pub const SERVICE_TYPE: &str = "_zloe._udp.local.";

/// Produces the encoded network settings a coordinator hands to satellites.
pub type NetInfoProvider = Arc<dyn Fn() -> Option<Vec<u8>> + Send + Sync>;
const PROBE_INTERVAL: Duration = Duration::from_secs(5);
const ACK_TIMEOUT: Duration = Duration::from_millis(ACK_TIMEOUT_MS);

#[derive(Debug, Clone, Default)]
pub struct DenyList {
    pub eui64: HashSet<Eui64>,
    pub nwk: HashSet<Nwk>,
}

impl DenyList {
    fn denies(&self, address: &MacAddress) -> bool {
        match address {
            MacAddress::Short(nwk) => self.nwk.contains(nwk),
            MacAddress::Extended(eui64) => self.eui64.contains(eui64),
            MacAddress::None => false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TrelConfig {
    /// UDP port to listen on (0 disables the backbone entirely)
    pub port: u16,
    /// Peers reachable without discovery; their identity is learned from traffic
    pub static_peers: Vec<SocketAddr>,
    pub mdns: bool,
    /// Network interface (e.g. `eth0`) the backbone is confined to: mDNS only runs
    /// there and peers are reached through its addresses. `None`: all interfaces.
    pub interface: Option<String>,
    /// Reach peers over IPv4 when they advertise both (default: IPv6 link-local)
    pub prefer_ipv4: bool,
    /// UDP port of the network's multicast group (0: do not listen or advertise).
    /// Needs `interface`: link-local multicast is per interface.
    pub mcast_port: u16,
    /// Test hook: while this file exists, datagrams arriving on the multicast group
    /// are dropped, as if the network had stopped delivering multicast to us.
    pub mcast_block_file: Option<std::path::PathBuf>,
    /// Test hook: behave like a host without IPv6 (IPv4 socket, no IPv6 peers or group)
    pub ipv4_only: bool,
    /// Secure mode: peer links over authenticated QUIC; plain UDP data, multicast and
    /// the unauthenticated settings hand-out are off
    pub quic: Option<QuicConfig>,
    pub deny: DenyList,
}

#[derive(Debug, Clone)]
pub struct QuicConfig {
    /// UDP port of the QUIC endpoint
    pub port: u16,
    /// Coordinator: where to write the current enrollment code
    pub code_file: Option<std::path::PathBuf>,
}

/// The addresses of the interface the backbone is confined to.
#[derive(Debug, Clone, Copy)]
struct LocalNet {
    index: u32,
    v4: Option<(Ipv4Addr, Ipv4Addr)>,
}

fn local_net(name: &str) -> std::io::Result<LocalNet> {
    let addrs: Vec<_> = if_addrs::get_if_addrs()?
        .into_iter()
        .filter(|iface| iface.name == name)
        .collect();
    let index = addrs.iter().find_map(|i| i.index).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("ZLOE interface {name:?} not found"),
        )
    })?;
    let v4 = addrs.iter().find_map(|i| match &i.addr {
        if_addrs::IfAddr::V4(v4) => Some((v4.ip, v4.netmask)),
        if_addrs::IfAddr::V6(_) => None,
    });
    Ok(LocalNet { index, v4 })
}

/// The core's state and what only the host keeps next to it.
#[derive(Default)]
struct Shared {
    core: ZloeState,
    rx_tx: Option<mpsc::Sender<RxFrame>>,
    mdns_fullname: Option<String>,
    netinfo_provider: Option<NetInfoProvider>,
    netinfo_waiter: Option<oneshot::Sender<Vec<u8>>>,
}

/// [`CoreLock`] over the shared state.
struct HostLock(Arc<Mutex<Shared>>);

impl CoreLock for HostLock {
    fn with<R>(&self, f: impl FnOnce(&mut ZloeState) -> R) -> R {
        f(&mut self.0.lock().core)
    }
}

/// [`Clock`] counting from when the backbone was made.
#[derive(Clone, Copy)]
struct HostClock(Instant);

impl Clock for HostClock {
    fn now_ms(&self) -> u64 {
        self.0.elapsed().as_millis() as u64
    }
}

type Pending = Arc<Mutex<HashMap<u32, oneshot::Sender<()>>>>;

/// [`BackboneTransport`] over the UDP socket.
struct UdpTransport {
    socket: Arc<UdpSocket>,
    pending: Pending,
    dual_stack: bool,
}

impl BackboneTransport for UdpTransport {
    async fn send(&self, to: SocketAddr, datagram: &[u8]) -> bool {
        self.socket
            .send_to(datagram, to_family(to, self.dual_stack))
            .await
            .is_ok()
    }

    async fn send_wait_ack(
        &self,
        to: SocketAddr,
        datagram: &[u8],
        seq: u32,
        timeout_ms: u64,
    ) -> AckOutcome {
        let (tx, rx) = oneshot::channel();
        self.pending.lock().insert(seq, tx);
        let outcome = if self
            .socket
            .send_to(datagram, to_family(to, self.dual_stack))
            .await
            .is_err()
        {
            AckOutcome::SendFailed
        } else if tokio::time::timeout(Duration::from_millis(timeout_ms), rx)
            .await
            .is_ok()
        {
            AckOutcome::Acked
        } else {
            AckOutcome::TimedOut
        };
        self.pending.lock().remove(&seq);
        outcome
    }

    fn complete_ack(&self, seq: u32) -> bool {
        let waiter = self.pending.lock().remove(&seq);
        waiter.is_some_and(|w| w.send(()).is_ok())
    }
}

type Core = ZloeCore<HostLock, HostClock, UdpTransport>;

/// Datagram counters, for the bench.
#[derive(Default)]
struct Stats {
    /// 802.15.4 broadcasts handed to the backbone
    broadcasts: AtomicU64,
    /// Multicast datagrams they were sent as
    multicast: AtomicU64,
    /// Unicast copies sent to peers multicast does not reach
    unicast_copies: AtomicU64,
    probes: AtomicU64,
}

struct Backbone {
    socket: Arc<UdpSocket>,
    shared: Arc<Mutex<Shared>>,
    core: Arc<Core>,
    pending: Pending,
    stats: Arc<Stats>,
    mcast_block_file: Option<std::path::PathBuf>,
    static_peers: Vec<SocketAddr>,
    mdns: Option<mdns_sd::ServiceDaemon>,
    port: u16,
    /// Set when confined to one interface
    local_net: Option<LocalNet>,
    prefer_ipv4: bool,
    /// The socket is IPv6 dual-stack: IPv4 targets go out as v4-mapped addresses
    dual_stack: bool,
    mcast_port: u16,
    /// The task reading our multicast socket; replaced when the network changes
    mcast_reader: Mutex<Option<tokio::task::JoinHandle<()>>>,
    mcast4_reader: Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// Secure mode: the QUIC link to peers
    quic: Option<Arc<quic::QuicLink>>,
}

pub struct TrelPhy<P: RadioPhy> {
    inner: P,
    backbone: Option<Backbone>,
    deny: DenyList,
    shared: Arc<Mutex<Shared>>,
    clock: HostClock,
}

/// The merged received-frame stream.
pub struct TrelRx(mpsc::Receiver<RxFrame>);

impl Receiver<RxFrame> for TrelRx {
    async fn recv(&mut self) -> Option<RxFrame> {
        self.0.recv().await
    }
}

impl<P: RadioPhy> TrelPhy<P> {
    /// Must be called from within a Tokio runtime.
    pub async fn new(inner: P, config: TrelConfig) -> std::io::Result<Self> {
        let shared = Arc::new(Mutex::new(Shared {
            core: ZloeState::new(rand_u32()),
            ..Shared::default()
        }));
        let clock = HostClock(Instant::now());

        let backbone = if config.port == 0 {
            None
        } else {
            let local_net = config.interface.as_deref().map(local_net).transpose()?;
            let (socket, dual_stack) = bind_socket(config.port, config.ipv4_only)?;
            let socket = Arc::new(socket);
            tracing::info!(
                "ZLOE backbone listening on UDP {} ({}, {}, prefer {})",
                config.port,
                if dual_stack {
                    "IPv6 dual-stack"
                } else {
                    "IPv4 only"
                },
                config.interface.as_deref().unwrap_or("all interfaces"),
                if config.prefer_ipv4 {
                    "IPv4"
                } else {
                    "IPv6 link-local"
                },
            );

            let mdns = if config.mdns {
                match mdns_sd::ServiceDaemon::new() {
                    Ok(daemon) => {
                        if let Some(name) = &config.interface {
                            let _ = daemon.disable_interface(mdns_sd::IfKind::All);
                            let _ = daemon.disable_interface(mdns_sd::IfKind::LoopbackV4);
                            let _ = daemon.disable_interface(mdns_sd::IfKind::LoopbackV6);
                            if let Err(e) =
                                daemon.enable_interface(mdns_sd::IfKind::Name(name.clone()))
                            {
                                tracing::warn!("ZLOE: mDNS on {name} failed: {e}");
                            }
                        }
                        Some(daemon)
                    }
                    Err(e) => {
                        tracing::warn!("ZLOE: mDNS unavailable, static peers only: {e}");
                        None
                    }
                }
            } else {
                None
            };

            let pending: Pending = Arc::new(Mutex::new(HashMap::new()));
            let core = Arc::new(ZloeCore::new(
                HostLock(Arc::clone(&shared)),
                clock,
                UdpTransport {
                    socket: Arc::clone(&socket),
                    pending: Arc::clone(&pending),
                    dual_stack,
                },
            ));

            // Secure mode: QUIC peer links; its datagrams go through the same handler
            let quic = match &config.quic {
                Some(qc) => {
                    let handler: quic::Handler = {
                        let h_core = Arc::clone(&core);
                        let h_shared = Arc::clone(&shared);
                        Arc::new(move |buf: &[u8], from: SocketAddr| {
                            process_datagram(&h_core, &h_shared, buf, from, false)
                        })
                    };
                    let n_shared = Arc::clone(&shared);
                    let netinfo: quic::NetInfo = Arc::new(move || {
                        let provider = n_shared.lock().netinfo_provider.clone();
                        provider.and_then(|provide| provide())
                    });
                    shared.lock().core.secure = true;
                    Some(quic::QuicLink::new(
                        qc.port,
                        handler,
                        netinfo,
                        qc.code_file.clone(),
                    )?)
                }
                None => None,
            };

            let backbone = Backbone {
                quic,
                socket,
                shared: Arc::clone(&shared),
                core,
                pending,
                stats: Arc::new(Stats::default()),
                mcast_block_file: config.mcast_block_file,
                static_peers: config.static_peers,
                mdns,
                port: config.port,
                local_net,
                prefer_ipv4: config.prefer_ipv4,
                dual_stack,
                mcast_port: if config.quic.is_some() {
                    0
                } else {
                    config.mcast_port
                },
                mcast_reader: Mutex::new(None),
                mcast4_reader: Mutex::new(None),
            };
            backbone.spawn_udp_reader(Arc::clone(&backbone.socket), None);
            backbone.spawn_mdns_browser();
            backbone.spawn_prober();
            Some(backbone)
        };

        Ok(Self {
            inner,
            backbone,
            deny: config.deny,
            shared,
            clock,
        })
    }

    pub const fn inner(&self) -> &P {
        &self.inner
    }

    /// The network's extended PAN ID (TREL's `xp` in mDNS): peers on other networks are
    /// ignored. Set by the stack's owner when the network is configured.
    pub fn set_extended_pan_id(&self, epan: Eui64) {
        let identity = self.shared.lock().core.set_epan(epan);
        if let (Some(identity), Some(backbone)) = (identity, &self.backbone) {
            backbone.advertise(identity);
        }
    }

    /// Secure mode: the network key is known (configured, or after enrollment). Derives
    /// the network CA and our certificate and starts the QUIC links.
    pub fn set_network_key(
        &self,
        nwk_key: &[u8; 16],
        epan: Eui64,
        me: Eui64,
        coordinator: bool,
    ) -> std::io::Result<()> {
        let Some(link) = self.backbone.as_ref().and_then(|b| b.quic.as_ref()) else {
            return Ok(());
        };
        let role = if coordinator {
            security::Role::Coordinator
        } else {
            security::Role::Satellite
        };
        link.set_network(nwk_key, epan, me, role)
    }

    /// Secure mode, coordinator side: whether the network is in pairing mode, when
    /// satellites may enroll without a code.
    pub fn set_pairing_open(&self, pairing_open: quic::PairingOpen) {
        if let Some(link) = self.backbone.as_ref().and_then(|b| b.quic.as_ref()) {
            link.set_pairing_open(pairing_open);
        }
    }

    /// Secure mode, satellite side: find a coordinator on the backbone (on `epan`, when
    /// given) and enroll with `code`: returns the network settings it sends.
    pub async fn enroll(
        &self,
        epan: Option<Eui64>,
        code: &str,
        timeout: Duration,
    ) -> std::io::Result<Vec<u8>> {
        let Some(backbone) = &self.backbone else {
            return Err(std::io::Error::other("ZLOE backbone is disabled"));
        };
        let Some(link) = &backbone.quic else {
            return Err(std::io::Error::other(
                "enrollment needs --zloe-security quic",
            ));
        };
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let target = {
                let shared = self.shared.lock();
                shared
                    .core
                    .coordinators
                    .iter()
                    .filter(|(_, (_, e))| epan.is_none() || *e == epan)
                    .find_map(|(eui64, (addr, _))| {
                        shared
                            .core
                            .coordinator_quic
                            .get(eui64)
                            .map(|qp| (*eui64, with_port(*addr, *qp)))
                    })
            };
            if let Some((eui64, addr)) = target {
                tracing::info!("ZLOE/QUIC: enrolling with coordinator {eui64:?} at {addr}");
                return link.enroll(addr, code).await;
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "no secure coordinator on the ZLOE backbone",
                ));
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    /// Coordinator side: hand these settings to satellites that ask over the backbone.
    pub fn set_netinfo_provider(&self, provider: NetInfoProvider) {
        self.shared.lock().netinfo_provider = Some(provider);
    }

    /// Satellite side: find a coordinator on the backbone (on extended PAN `epan`, when
    /// given) and fetch its network settings. Retries until `timeout`.
    pub async fn fetch_network(
        &self,
        epan: Option<Eui64>,
        timeout: Duration,
    ) -> std::io::Result<Vec<u8>> {
        let backbone = self
            .backbone
            .as_ref()
            .ok_or_else(|| std::io::Error::other("ZLOE backbone is disabled (--zloe-port 0)"))?;
        let deadline = tokio::time::Instant::now() + timeout;

        while tokio::time::Instant::now() < deadline {
            let candidates: Vec<(Eui64, SocketAddr, Option<Eui64>)> = {
                let shared = self.shared.lock();
                shared
                    .core
                    .coordinators
                    .iter()
                    .filter(|(_, (_, x))| epan.is_none() || *x == epan)
                    .map(|(eui64, (addr, x))| (*eui64, *addr, *x))
                    .collect()
            };
            let Some(&(eui64, addr, coordinator_epan)) = candidates.first() else {
                tokio::time::sleep(Duration::from_millis(250)).await;
                continue;
            };
            if candidates.len() > 1 {
                tracing::warn!(
                    "ZLOE: {} coordinators match, using {eui64:?} (epan {coordinator_epan:?}); \
                     pick one with --zloe-satellite-epan",
                    candidates.len()
                );
            }

            let (tx, rx) = oneshot::channel();
            let request = {
                let mut shared = self.shared.lock();
                shared.netinfo_waiter = Some(tx);
                let seq = shared.core.next_seq();
                shared.core.netinfo_header(KIND_NETINFO_REQ, seq)
            };
            tracing::info!("ZLOE: asking coordinator {eui64:?} at {addr} for network settings");
            backbone
                .socket
                .send_to(&request, to_family(addr, backbone.dual_stack))
                .await?;
            if let Ok(Ok(info)) = tokio::time::timeout(Duration::from_secs(1), rx).await {
                return Ok(info);
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "no coordinator answered on the ZLOE backbone",
        ))
    }
}

/// Handle one ZLOE datagram (from UDP or a QUIC link); returns the reply to send back
/// to `from` (an ack or the network settings), if any.
fn process_datagram(
    core: &Core,
    shared: &Mutex<Shared>,
    buf: &[u8],
    from: SocketAddr,
    allow_netinfo: bool,
) -> Option<Vec<u8>> {
    match core.on_datagram(buf, from) {
        Inbound::Nothing => None,
        // Bootstrap exchange: the backbone is trusted, so the settings (network
        // key included) go to whoever asks
        Inbound::NetinfoRequest { seq, eui64 } => {
            if !allow_netinfo {
                return None;
            }
            let provider = shared.lock().netinfo_provider.clone();
            let info = provider.and_then(|provide| provide())?;
            tracing::info!("ZLOE: sending network settings to {from} ({eui64:?})");
            let mut rsp = shared.lock().core.netinfo_header(KIND_NETINFO_RSP, seq);
            rsp.extend_from_slice(&info);
            Some(rsp)
        }
        Inbound::NetinfoResponse(info) => {
            if let Some(waiter) = shared.lock().netinfo_waiter.take() {
                let _ = waiter.send(info);
            }
            None
        }
        Inbound::Data { frame, reply } => {
            if let Some(frame) = frame {
                let tx = shared.lock().rx_tx.clone();
                if let Some(tx) = tx {
                    tracing::trace!("ZLOE: rx {} bytes from {from}", frame.psdu.len());
                    let _ = tx.try_send(frame);
                }
            }
            reply
        }
    }
}

/// One dual-stack IPv6 socket (IPv4 arrives v4-mapped); IPv4-only when the host has no
/// IPv6.
fn bind_socket(port: u16, ipv4_only: bool) -> std::io::Result<(UdpSocket, bool)> {
    use socket2::{Domain, Protocol, Socket, Type};
    let v6 = if ipv4_only {
        Err(std::io::Error::other("IPv4 only requested"))
    } else {
        Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)).and_then(|s| {
            s.set_only_v6(false)?;
            s.bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)).into())?;
            Ok(s)
        })
    };
    let (socket, dual_stack) = match v6 {
        Ok(s) => (s, true),
        Err(e) => {
            tracing::warn!("ZLOE: no IPv6 socket ({e}), using IPv4 only");
            let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
            s.bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)).into())?;
            (s, false)
        }
    };
    socket.set_nonblocking(true)?;
    Ok((UdpSocket::from_std(socket.into())?, dual_stack))
}

/// v4-mapped IPv6 back to plain IPv4, so a peer has one spelling of its address.
fn canonical(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(v6) => v6
            .ip()
            .to_ipv4_mapped()
            .map_or(addr, |v4| SocketAddr::new(IpAddr::V4(v4), v6.port())),
        SocketAddr::V4(_) => addr,
    }
}

impl Backbone {
    /// Read datagrams from `rx` (the unicast socket, or the multicast one). Acks and
    /// replies always leave from the unicast socket, so peers see our unicast port.
    fn spawn_udp_reader(
        &self,
        rx: Arc<UdpSocket>,
        block: Option<(std::path::PathBuf, &'static str)>,
    ) -> tokio::task::JoinHandle<()> {
        let socket = Arc::clone(&self.socket);
        let core = Arc::clone(&self.core);
        let shared = Arc::clone(&self.shared);
        let dual_stack = self.dual_stack;
        let secure = self.quic.is_some();

        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            loop {
                let (len, from) = match rx.recv_from(&mut buf).await {
                    Ok((len, from)) => (len, canonical(from)),
                    Err(e) => {
                        tracing::warn!("ZLOE: UDP receive failed: {e}");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                // Test hook: an empty file blocks every group, "v4"/"v6" just one
                if let Some((file, family)) = &block
                    && let Ok(content) = std::fs::read_to_string(file)
                    && (content.trim().is_empty() || content.contains(family))
                {
                    continue;
                }
                // Secure mode: plain UDP carries nothing we trust
                if secure {
                    continue;
                }
                if let Some(reply) = process_datagram(&core, &shared, &buf[..len], from, true) {
                    let _ = socket.send_to(&reply, to_family(from, dual_stack)).await;
                }
            }
        })
    }

    fn spawn_mdns_browser(&self) {
        let Some(daemon) = &self.mdns else { return };
        let events = match daemon.browse(SERVICE_TYPE) {
            Ok(events) => events,
            Err(e) => {
                tracing::warn!("ZLOE: mDNS browse failed: {e}");
                return;
            }
        };
        let shared = Arc::clone(&self.shared);
        let local_net = self.local_net;
        let dual_stack = self.dual_stack;
        let prefer_ipv4 = self.prefer_ipv4;

        tokio::spawn(async move {
            while let Ok(event) = events.recv_async().await {
                match event {
                    mdns_sd::ServiceEvent::ServiceResolved(info) => {
                        let Some(eui64) = info
                            .get_property_val_str("xa")
                            .and_then(|s| Eui64::try_from_hex(s).ok())
                        else {
                            continue;
                        };
                        let epan = info
                            .get_property_val_str("xp")
                            .and_then(|s| Eui64::try_from_hex(s).ok());
                        let nwk = info
                            .get_property_val_str("nwk")
                            .and_then(|s| Nwk::try_from_hex(s).ok());
                        // Usable only on a known interface: the group is link-local
                        // Usable only on a known interface: groups are link-local
                        // (IPv6) or bound to the interface's subnet (IPv4)
                        let mc6 = info
                            .get_property_val_str("mc")
                            .and_then(|s| s.parse::<SocketAddrV6>().ok())
                            .filter(|mc| mc.ip().is_multicast() && dual_stack)
                            .zip(local_net)
                            .map(|(mut mc, net)| {
                                mc.set_scope_id(net.index);
                                SocketAddr::V6(mc)
                            });
                        let mc4 = info
                            .get_property_val_str("mc4")
                            .and_then(|s| s.parse::<SocketAddrV4>().ok())
                            .filter(|mc| mc.ip().is_multicast())
                            .filter(|_| local_net.is_some_and(|n| n.v4.is_some()))
                            .map(SocketAddr::V4);
                        let mcast = [mc6, mc4];
                        let quic_port = (info.get_property_val_str("sec") == Some("quic"))
                            .then(|| info.get_property_val_str("qp"))
                            .flatten()
                            .and_then(|p| p.parse::<u16>().ok());
                        // mDNS lists every address of every interface (Docker bridges,
                        // loopback, ...): pick deterministically
                        let candidates = candidate_addresses(
                            info.get_addresses(),
                            info.get_port(),
                            local_net,
                            prefer_ipv4,
                            dual_stack,
                        );
                        if candidates.is_empty() {
                            continue;
                        }

                        // Kept even while we have no identity (a satellite browses
                        // before it knows its network) and applied once we do
                        shared.lock().core.on_resolved(
                            eui64,
                            Resolved {
                                epan,
                                nwk,
                                candidates,
                                mcast,
                                quic_port,
                            },
                            info.get_property_val_str("role") == Some("coordinator"),
                        );
                    }
                    mdns_sd::ServiceEvent::ServiceRemoved(_, fullname) => {
                        let Some(eui64) = fullname
                            .split('.')
                            .next()
                            .and_then(|s| Eui64::try_from_hex(s).ok())
                        else {
                            continue;
                        };
                        shared.lock().core.on_removed(eui64);
                    }
                    _ => {}
                }
            }
        });
    }

    fn block_hook(&self, family: &'static str) -> Option<(std::path::PathBuf, &'static str)> {
        self.mcast_block_file.clone().map(|f| (f, family))
    }

    /// Join the network's multicast groups and read from them: `[IPv6, IPv4]`, each
    /// `None` when multicast is off, the backbone interface (or its address of that
    /// family) is unknown, or joining fails.
    fn listen_multicast(&self, epan: Eui64) -> [Option<SocketAddr>; 2] {
        use socket2::{Domain, Protocol, SockRef, Socket, Type};

        for reader in [&self.mcast_reader, &self.mcast4_reader] {
            if let Some(old) = reader.lock().take() {
                old.abort(); // closes the socket, leaving the previous group
            }
        }
        if self.mcast_port == 0 {
            return [None, None];
        }
        let Some(net) = self.local_net else {
            tracing::info!("ZLOE: no multicast without --zloe-interface");
            return [None, None];
        };

        // Several nodes on one host (the bench) share the port
        let open = |domain: Domain, bind: SocketAddr| -> std::io::Result<Socket> {
            let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
            if domain == Domain::IPV6 {
                socket.set_only_v6(true)?;
            }
            socket.set_reuse_address(true)?;
            socket.set_reuse_port(true)?;
            socket.bind(&bind.into())?;
            Ok(socket)
        };
        let start = |socket: Socket| -> std::io::Result<Arc<UdpSocket>> {
            socket.set_nonblocking(true)?;
            Ok(Arc::new(UdpSocket::from_std(socket.into())?))
        };

        let mc6 = self.dual_stack.then(|| {
            let group = multicast_group(epan);
            let joined = open(
                Domain::IPV6,
                (Ipv6Addr::UNSPECIFIED, self.mcast_port).into(),
            )
            .and_then(|s| s.join_multicast_v6(&group, net.index).map(|()| s))
            .and_then(start);
            match joined {
                Ok(socket) => {
                    let mc = SocketAddrV6::new(group, self.mcast_port, 0, net.index);
                    tracing::info!("ZLOE: listening on multicast group {mc}");
                    *self.mcast_reader.lock() =
                        Some(self.spawn_udp_reader(socket, self.block_hook("v6")));
                    Some(SocketAddr::V6(mc))
                }
                Err(e) => {
                    tracing::warn!("ZLOE: cannot join multicast group {group}: {e}");
                    None
                }
            }
        });

        let mc4 = net.v4.map(|(iface_ip, _)| {
            let group = multicast_group_v4(epan);
            let joined = open(
                Domain::IPV4,
                (Ipv4Addr::UNSPECIFIED, self.mcast_port).into(),
            )
            .and_then(|s| s.join_multicast_v4(&group, &iface_ip).map(|()| s))
            .and_then(start);
            // Our IPv4 multicast leaves through the unicast socket (so peers see our
            // unicast port), out of the backbone interface
            let sending = SockRef::from(&*self.socket).set_multicast_if_v4(&iface_ip);
            match (joined, sending) {
                (Ok(socket), Ok(())) => {
                    let mc = SocketAddrV4::new(group, self.mcast_port);
                    tracing::info!("ZLOE: listening on multicast group {mc}");
                    *self.mcast4_reader.lock() =
                        Some(self.spawn_udp_reader(socket, self.block_hook("v4")));
                    Some(SocketAddr::V4(mc))
                }
                (Err(e), _) | (_, Err(e)) => {
                    tracing::warn!("ZLOE: cannot use IPv4 multicast group {group}: {e}");
                    None
                }
            }
        });

        [mc6.flatten(), mc4.flatten()]
    }

    fn advertise(&self, identity: Identity) {
        let mcast = self.listen_multicast(identity.epan);
        let Some(daemon) = &self.mdns else { return };
        let mut shared = self.shared.lock();
        if let Some(old) = shared.mdns_fullname.take() {
            let _ = daemon.unregister(&old);
        }

        let instance = hex_be(&identity.eui64.to_be_bytes());
        let mut properties: HashMap<String, String> = [
            ("v".to_string(), VERSION.to_string()),
            ("xa".to_string(), instance.clone()),
            ("xp".to_string(), hex_be(&identity.epan.to_be_bytes())),
            ("nwk".to_string(), format!("{:04x}", identity.nwk.as_u16())),
            (
                "role".to_string(),
                if identity.nwk == Nwk(0x0000) {
                    "coordinator"
                } else {
                    "router"
                }
                .to_string(),
            ),
        ]
        .into_iter()
        .collect();

        // `mc`: where we listen for multicast. Absent when we cannot, so peers know
        // to reach us by unicast only
        if let [Some(SocketAddr::V6(mc)), _] = mcast {
            properties.insert("mc".to_string(), format!("[{}]:{}", mc.ip(), mc.port()));
        }
        if let [_, Some(mc4)] = mcast {
            properties.insert("mc4".to_string(), mc4.to_string());
        }
        // Security mode; a secure node also announces its QUIC port
        match &self.quic {
            Some(link) => {
                properties.insert("sec".to_string(), "quic".to_string());
                properties.insert("qp".to_string(), link.port.to_string());
            }
            None => {
                properties.insert("sec".to_string(), "none".to_string());
            }
        }

        // Addresses (IPv6 link-local and IPv4) come from the interfaces mDNS runs on,
        // which --zloe-interface already narrows to one
        let host = format!("ziggurat-{instance}.local.");
        match mdns_sd::ServiceInfo::new(SERVICE_TYPE, &instance, &host, "", self.port, properties) {
            Ok(info) => {
                let info = info.enable_addr_auto();
                let fullname = info.get_fullname().to_string();
                match daemon.register(info) {
                    Ok(()) => {
                        tracing::info!("ZLOE: advertising {fullname}");
                        shared.mdns_fullname = Some(fullname);
                    }
                    Err(e) => tracing::warn!("ZLOE: mDNS register failed: {e}"),
                }
            }
            Err(e) => tracing::warn!("ZLOE: bad mDNS service info: {e}"),
        }
    }

    /// Every probe interval: multicast an empty datagram that each peer answers by
    /// unicast, so we know which peers our multicast reaches.
    fn spawn_prober(&self) {
        let socket = Arc::clone(&self.socket);
        let shared = Arc::clone(&self.shared);
        let clock = self.core.clock;
        let stats = Arc::clone(&self.stats);
        let prefer_ipv4 = self.prefer_ipv4;
        let dual_stack = self.dual_stack;
        let quic = self.quic.clone();

        tokio::spawn(async move {
            let mut tick = tokio::time::interval(PROBE_INTERVAL);
            loop {
                tick.tick().await;
                // Secure mode: keep a QUIC link to every secure peer (the lower EUI64
                // dials); no multicast to probe
                if let Some(link) = &quic {
                    let targets: Vec<(Eui64, SocketAddr)> = shared
                        .lock()
                        .core
                        .peers
                        .iter()
                        .filter_map(|(eui64, p)| {
                            p.quic_port.map(|qp| (*eui64, with_port(p.addr, qp)))
                        })
                        .collect();
                    for (peer, addr) in targets {
                        link.ensure_connected(peer, addr);
                    }
                    continue;
                }
                let probes = shared.lock().core.plan_probes(prefer_ipv4, clock.now_ms());
                for (group, probe) in probes {
                    let _ = socket.send_to(&probe, to_family(group, dual_stack)).await;
                    stats.probes.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
    }

    fn peer_eui_for(&self, dest: &MacAddress) -> Option<Eui64> {
        self.shared.lock().core.peer_eui_for(dest)
    }

    async fn send_broadcast(&self, psdu: &[u8]) {
        // Secure mode: one QUIC datagram per connected peer
        if let Some(link) = &self.quic {
            let Some((_, datagram)) = self.shared.lock().core.data_datagram(0, psdu) else {
                return;
            };
            self.stats.broadcasts.fetch_add(1, Ordering::Relaxed);
            for peer in link.connected() {
                if link.send(peer, &datagram) {
                    self.stats.unicast_copies.fetch_add(1, Ordering::Relaxed);
                }
            }
            return;
        }

        let (groups, copies) = self
            .core
            .send_broadcast(psdu, self.prefer_ipv4, &self.static_peers)
            .await;
        self.stats.broadcasts.fetch_add(1, Ordering::Relaxed);
        self.stats
            .multicast
            .fetch_add(groups as u64, Ordering::Relaxed);
        self.stats
            .unicast_copies
            .fetch_add(copies as u64, Ordering::Relaxed);
    }

    /// Secure mode: unicast over the peer's QUIC link, acked like the UDP path.
    async fn send_unicast_quic(&self, peer: Eui64, psdu: &[u8], ack_request: bool) -> bool {
        let Some(link) = &self.quic else { return false };
        if !link.is_connected(peer) {
            return false;
        }
        let flags = if ack_request { FLAG_ACK_REQUEST } else { 0 };
        let Some((seq, datagram)) = self.shared.lock().core.data_datagram(flags, psdu) else {
            return false;
        };

        if !ack_request {
            return link.send(peer, &datagram);
        }
        for _ in 0..ATTEMPTS {
            let (tx, rx) = oneshot::channel();
            self.pending.lock().insert(seq, tx);
            if !link.send(peer, &datagram) {
                break;
            }
            if tokio::time::timeout(ACK_TIMEOUT, rx).await.is_ok() {
                return true;
            }
        }
        self.pending.lock().remove(&seq);
        false
    }
}

impl<P: RadioPhy> RadioPhy for TrelPhy<P> {
    type Exclusive<'a> = P::Exclusive<'a>;
    type RxStream = TrelRx;
    type ResetStream = P::ResetStream;

    async fn reset(&self) -> Result<(), RadioError> {
        self.inner.reset().await
    }

    async fn reconfigure(&self, config: &RadioConfig) -> Result<(), RadioError> {
        self.inner.reconfigure(config).await?;

        // The capture config uses a broadcast address; there is no identity to announce
        if config.short_address == Nwk(0xFFFF) || config.promiscuous {
            return Ok(());
        }
        let identity = self.shared.lock().core.set_radio(
            config.extended_address,
            config.short_address,
            config.channel,
        );
        if let (Some(identity), Some(backbone)) = (identity, &self.backbone) {
            backbone.advertise(identity);
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
        let Some(mac) = MacHeader::parse(&frame.psdu) else {
            return self.inner.transmit(frame).await;
        };

        if let Some(backbone) = &self.backbone {
            if mac.dest.is_broadcast() {
                // Beacon requests and other MAC commands mean nothing to backbone peers
                if mac.frame_type == MAC_FRAME_DATA {
                    backbone.send_broadcast(&frame.psdu).await;
                }
            } else if backbone.quic.is_some() {
                if let Some(peer) = backbone.peer_eui_for(&mac.dest) {
                    if backbone
                        .send_unicast_quic(peer, &frame.psdu, mac.ack_request)
                        .await
                    {
                        tracing::trace!("ZLOE: tx to {:?} via QUIC", mac.dest);
                        return Ok(TxResult::Acked);
                    }
                    tracing::info!("ZLOE: QUIC to {:?} failed, falling back to air", mac.dest);
                }
            } else if backbone.core.send_to_peer(&mac, &frame.psdu).await {
                return Ok(TxResult::Acked);
            }
        }

        if self.deny.denies(&mac.dest) {
            tracing::trace!("ZLOE deny: not transmitting to {:?}", mac.dest);
            return Ok(if mac.ack_request {
                TxResult::NoAck
            } else {
                TxResult::Acked
            });
        }

        self.inner.transmit(frame).await
    }

    async fn energy_detect(&self, channel: u8, duration: Duration) -> Result<i8, RadioError> {
        self.inner.energy_detect(channel, duration).await
    }

    async fn lock(&self) -> Self::Exclusive<'_> {
        self.inner.lock().await
    }

    fn subscribe_rx(&self) -> TrelRx {
        let (tx, rx) = mpsc::channel(64);
        self.shared.lock().rx_tx = Some(tx.clone());

        let mut inner_rx = self.inner.subscribe_rx();
        let deny = self.deny.clone();
        let shared = Arc::clone(&self.shared);
        let has_backbone = self.backbone.is_some();
        let clock = self.clock;

        // Over-the-air frames: apply the deny list, and drop copies of what a live
        // backbone peer also sends over the backbone
        tokio::spawn(async move {
            while let Some(frame) = inner_rx.recv().await {
                if let Some(mac) = MacHeader::parse(&frame.psdu) {
                    if deny.denies(&mac.source) {
                        tracing::trace!("ZLOE deny: dropping air frame from {:?}", mac.source);
                        continue;
                    }
                    if has_backbone {
                        let live_peer = !shared
                            .lock()
                            .core
                            .keep_air_frame(&mac.source, clock.now_ms());
                        if live_peer {
                            tracing::trace!("ZLOE: dropping air copy from {:?}", mac.source);
                            continue;
                        }
                    }
                }
                if tx.send(frame).await.is_err() {
                    break;
                }
            }
        });

        TrelRx(rx)
    }

    fn subscribe_reset(&self) -> Self::ResetStream {
        self.inner.subscribe_reset()
    }
}

impl<P: RadioPhy> TrelPhy<P> {
    /// Datagram counters since start, for diagnostics.
    pub fn stats(&self) -> Option<String> {
        let stats = &self.backbone.as_ref()?.stats;
        Some(format!(
            "broadcasts={} multicast={} unicast_copies={} probes={}",
            stats.broadcasts.load(Ordering::Relaxed),
            stats.multicast.load(Ordering::Relaxed),
            stats.unicast_copies.load(Ordering::Relaxed),
            stats.probes.load(Ordering::Relaxed),
        ))
    }

    /// Peers currently known, for diagnostics.
    pub fn peers(&self) -> Vec<String> {
        let now = self.clock.now_ms();
        self.shared
            .lock()
            .core
            .peers
            .iter()
            .map(|(eui64, p)| {
                format!(
                    "{eui64:?} nwk={:?} addr={} via={:?} lqi={} mc={} last_rx={:?}",
                    p.nwk,
                    p.addr,
                    p.source,
                    p.lqi(),
                    [V6, V4]
                        .into_iter()
                        .filter_map(|f| p.mcast[f].addr.map(|a| (a, p.mcast[f].confirmed(now))))
                        .map(|(a, ok)| format!("{a} {}", if ok { "ok" } else { "unconfirmed" }))
                        .collect::<Vec<_>>()
                        .join(", "),
                    p.last_rx_ms
                        .map(|t| Duration::from_millis(now.saturating_sub(t)))
                )
            })
            .collect()
    }
}

/// Every address mDNS resolved for a peer that we could use, best first.
///
/// Confined to one interface (`--zloe-interface`): IPv6 link-local on that interface
/// first (IPv4 first with `prefer_ipv4`), then IPv4 on its subnet, then routable IPv6.
/// Not confined: a link-local address's scope is ambiguous (mDNS reports it once per
/// interface the answer arrived on, Docker bridges and veths included), so IPv4 and
/// routable IPv6 come first and link-local is a last resort.
fn candidate_addresses(
    addrs: &HashSet<mdns_sd::ScopedIp>,
    port: u16,
    local_net: Option<LocalNet>,
    prefer_ipv4: bool,
    dual_stack: bool,
) -> Vec<((u8, u8), SocketAddr)> {
    let mut ranked: Vec<((u8, u8), SocketAddr)> = addrs
        .iter()
        .filter_map(|scoped| match scoped {
            mdns_sd::ScopedIp::V6(v6) => {
                let ip = *v6.addr();
                let index = v6.scope_id().index;
                if ip.is_loopback() || !dual_stack {
                    return None;
                }
                let link_local = (ip.segments()[0] & 0xffc0) == 0xfe80;
                let class = match (local_net, link_local) {
                    (Some(net), true) if net.index != index => return None,
                    (Some(_), true) => u8::from(prefer_ipv4),
                    (Some(_), false) | (None, false) => 2,
                    (None, true) => 3,
                };
                let scope = if link_local { index } else { 0 };
                Some((
                    (class, 0),
                    SocketAddr::V6(SocketAddrV6::new(ip, port, 0, scope)),
                ))
            }
            mdns_sd::ScopedIp::V4(v4) => {
                let ip = *v4.addr();
                if let Some(net) = local_net {
                    let (ours, mask) = net.v4?;
                    if u32::from(ip) & u32::from(mask) != u32::from(ours) & u32::from(mask) {
                        return None;
                    }
                }
                let class = if local_net.is_some() {
                    u8::from(!prefer_ipv4)
                } else {
                    0
                };
                Some((
                    (class, address_rank(ip)),
                    SocketAddr::new(IpAddr::V4(ip), port),
                ))
            }
            _ => None,
        })
        .collect();
    ranked.sort();
    ranked
}

/// The network's multicast group: transient (`ff1x`), link-local scope (`ffx2`), with
/// the low 32 bits of the extended PAN ID: `ff12::5a4c:hhhh:hhhh`.
fn multicast_group(epan: Eui64) -> Ipv6Addr {
    let e = epan.to_be_bytes();
    Ipv6Addr::new(
        0xff12,
        0,
        0,
        0,
        0,
        0x5a4c,
        u16::from_be_bytes([e[4], e[5]]),
        u16::from_be_bytes([e[6], e[7]]),
    )
}

/// The network's IPv4 multicast group, organization-local scope (RFC 2365), with the
/// last two bytes of the extended PAN ID: `239.255.h.h`.
fn multicast_group_v4(epan: Eui64) -> Ipv4Addr {
    let e = epan.to_be_bytes();
    Ipv4Addr::new(239, 255, e[6], e[7])
}

/// The same address on another port, keeping an IPv6 link-local scope
/// (`SocketAddr::new(ip, port)` would drop it).
fn with_port(mut addr: SocketAddr, port: u16) -> SocketAddr {
    addr.set_port(port);
    addr
}

/// IPv4 targets on a dual-stack IPv6 socket must be v4-mapped.
fn to_family(addr: SocketAddr, dual_stack: bool) -> SocketAddr {
    match addr {
        SocketAddr::V4(v4) if dual_stack => {
            SocketAddr::V6(SocketAddrV6::new(v4.ip().to_ipv6_mapped(), v4.port(), 0, 0))
        }
        _ => addr,
    }
}

/// Lower is better: 192.168/16, 10/8, other non-loopback, 172.16/12 (usually
/// container bridges), link-local, loopback.
const fn address_rank(ip: std::net::Ipv4Addr) -> u8 {
    let o = ip.octets();
    match o {
        [192, 168, ..] => 0,
        [10, ..] => 1,
        [172, 16..=31, ..] => 3,
        [169, 254, ..] => 4,
        [127, ..] => 5,
        _ => 2,
    }
}

fn hex_be(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn rand_u32() -> u32 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    (nanos ^ (nanos >> 32)) as u32
}
