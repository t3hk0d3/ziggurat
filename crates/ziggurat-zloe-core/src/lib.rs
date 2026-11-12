//! SPIKE (throwaway): the logic of ZLOE (Zigbee Link Over Ethernet) without any I/O, shared
//! by the host (`ziggurat-phy-trel`) and the MCU (`ziggurat-ot`), so both keep one
//! implementation: identity, peer table, backbone first with the radio on failure, per-frame
//! ack and retries, duplicate drop, LQI 255 for backbone frames (as TREL), dropping air copies.
//!
//! Locks, clocks and sockets are behind [`CoreLock`], [`Clock`] and [`BackboneTransport`].
//! [`ZloeState`] is the plain state; [`ZloeCore`] ties it to those three.

#![no_std]

extern crate alloc;

#[cfg(test)]
extern crate std;

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;
use core::future::Future;
use core::net::SocketAddr;

use ziggurat_ieee_802154::types::{Eui64, Nwk};
use ziggurat_phy::RxFrame;

pub const MAGIC: [u8; 2] = *b"ZL";
pub const VERSION: u8 = 2;
pub const HEADER_LEN: usize = 27;
pub const KIND_DATA: u8 = 0;
pub const KIND_ACK: u8 = 1;
/// Trusted-backbone bootstrap: ask a coordinator for the network settings, and its
/// answer (an encoded `NetworkInfoPayload`, opaque to this crate).
pub const KIND_NETINFO_REQ: u8 = 2;
pub const KIND_NETINFO_RSP: u8 = 3;
/// Multicast liveness probe: no payload, answered with a unicast ack.
pub const KIND_PROBE: u8 = 4;
pub const FLAG_ACK_REQUEST: u8 = 0x01;
/// 802.15.4 frame type "data": the only broadcasts that belong on the backbone.
pub const MAC_FRAME_DATA: u8 = 1;

pub const ACK_TIMEOUT_MS: u64 = 50;
pub const ATTEMPTS: usize = 3;
const DEDUP_WINDOW: usize = 64;
/// RSSI reported for frames received over the backbone.
const BACKBONE_RSSI: i8 = -20;
/// A peer whose datagrams arrived this recently has a live backbone link: its
/// over-the-air frames are duplicates (two Link Status periods).
const BACKBONE_LIVE_MS: u64 = 35_000;
/// A peer that has not acked a probe for this long (two missed probes) gets unicast
/// copies of broadcasts again.
const MCAST_CONFIRM_WINDOW_MS: u64 = 12_000;
/// Weight of the newest sample in the backbone ack-success average.
const HEALTH_ALPHA: f32 = 0.125;

/// Index into per-family multicast state.
pub const V6: usize = 0;
pub const V4: usize = 1;

/// Runs a closure on the state under whatever lock the runtime has.
pub trait CoreLock: Send + Sync {
    fn with<R>(&self, f: impl FnOnce(&mut ZloeState) -> R) -> R;
}

/// Monotonic milliseconds.
pub trait Clock: Send + Sync {
    fn now_ms(&self) -> u64;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckOutcome {
    Acked,
    TimedOut,
    SendFailed,
}

/// What the core needs from below: send datagrams, and wait for acks the core reports with
/// [`complete_ack`](Self::complete_ack).
pub trait BackboneTransport: Send + Sync {
    /// Send one datagram. `false` when it could not be handed to the network.
    fn send(&self, to: SocketAddr, datagram: &[u8]) -> impl Future<Output = bool> + Send;

    /// Send one datagram and wait up to `timeout_ms` for the ack of `seq`.
    fn send_wait_ack(
        &self,
        to: SocketAddr,
        datagram: &[u8],
        seq: u32,
        timeout_ms: u64,
    ) -> impl Future<Output = AckOutcome> + Send;

    /// An ack for `seq` arrived. `true` when a `send_wait_ack` was waiting on it.
    fn complete_ack(&self, seq: u32) -> bool;
}

// -- wire format ---------------------------------------------------------------------

/// `"ZL" | ver=2 | kind | flags | seq:u32le | xa: EUI64 | nwk:u16le | epan: extended PAN ID`
/// (EUI64s in 802.15.4 wire order, i.e. little-endian)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireHeader {
    pub kind: u8,
    pub flags: u8,
    pub seq: u32,
    pub eui64: Eui64,
    pub nwk: Nwk,
    pub epan: Eui64,
}

impl WireHeader {
    #[must_use]
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < HEADER_LEN || bytes[..2] != MAGIC || bytes[2] != VERSION {
            return None;
        }
        Some(Self {
            kind: bytes[3],
            flags: bytes[4],
            seq: u32::from_le_bytes(bytes[5..9].try_into().ok()?),
            eui64: Eui64(bytes[9..17].try_into().ok()?),
            nwk: Nwk(u16::from_le_bytes([bytes[17], bytes[18]])),
            epan: Eui64(bytes[19..27].try_into().ok()?),
        })
    }

    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + 128);
        out.extend_from_slice(&MAGIC);
        out.push(VERSION);
        out.push(self.kind);
        out.push(self.flags);
        out.extend_from_slice(&self.seq.to_le_bytes());
        out.extend_from_slice(&self.eui64.0);
        out.extend_from_slice(&self.nwk.0.to_le_bytes());
        out.extend_from_slice(&self.epan.0);
        out
    }
}

// -- minimal 802.15.4 MAC header parsing --------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacAddress {
    None,
    Short(Nwk),
    Extended(Eui64),
}

impl MacAddress {
    #[must_use]
    pub const fn is_broadcast(&self) -> bool {
        matches!(self, Self::Short(Nwk(0xFFFF)))
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MacHeader {
    pub frame_type: u8,
    pub ack_request: bool,
    pub dest: MacAddress,
    pub source: MacAddress,
}

impl MacHeader {
    #[must_use]
    pub fn parse(psdu: &[u8]) -> Option<Self> {
        let fcf = u16::from_le_bytes([*psdu.first()?, *psdu.get(1)?]);
        let ack_request = fcf & (1 << 5) != 0;
        let pan_compression = fcf & (1 << 6) != 0;
        let dest_mode = (fcf >> 10) & 0b11;
        let src_mode = (fcf >> 14) & 0b11;

        let mut i = 3; // FCF + sequence number
        let mut read_addr = |mode: u16, with_pan: bool| -> Option<MacAddress> {
            if mode == 0 {
                return Some(MacAddress::None);
            }
            if with_pan {
                i += 2;
            }
            match mode {
                2 => {
                    let nwk = u16::from_le_bytes([*psdu.get(i)?, *psdu.get(i + 1)?]);
                    i += 2;
                    Some(MacAddress::Short(Nwk(nwk)))
                }
                3 => {
                    let eui64 = Eui64(psdu.get(i..i + 8)?.try_into().ok()?);
                    i += 8;
                    Some(MacAddress::Extended(eui64))
                }
                _ => None,
            }
        };
        let dest = read_addr(dest_mode, true)?;
        let source = read_addr(src_mode, !pan_compression)?;
        Some(Self {
            frame_type: (fcf & 0b111) as u8,
            ack_request,
            dest,
            source,
        })
    }
}

// -- peers ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerSource {
    Mdns,
    Learned,
}

/// One multicast group a peer announced, and whether our probes reach it there.
#[derive(Debug, Clone, Copy, Default)]
pub struct Group {
    /// Scoped to our backbone interface (IPv6) or plain (IPv4)
    pub addr: Option<SocketAddr>,
    /// When the peer last acked one of our probes on this group
    pub acked_ms: Option<u64>,
}

impl Group {
    #[must_use]
    pub fn confirmed(&self, now: u64) -> bool {
        self.addr.is_some()
            && self
                .acked_ms
                .is_some_and(|t| now.saturating_sub(t) < MCAST_CONFIRM_WINDOW_MS)
    }
}

#[derive(Debug, Clone)]
pub struct Peer {
    pub addr: SocketAddr,
    pub nwk: Option<Nwk>,
    pub source: PeerSource,
    pub last_rx_ms: Option<u64>,
    /// Backbone ack success, exponentially averaged (1.0 = clean)
    pub health: f32,
    /// Every usable address mDNS gave, best first: tried in turn when sends fail
    pub alternates: Vec<SocketAddr>,
    /// The multicast group and port the peer listens on (mDNS TXT `mc`), scoped to
    /// our backbone interface. `None`: the peer cannot be reached by multicast.
    pub mcast: [Group; 2],
    /// QUIC port the peer announced (TXT `qp`), secure mode only
    pub quic_port: Option<u16>,
    /// The confirmation state last logged, to log each change once
    pub mcast_logged_ok: bool,
}

impl Peer {
    #[must_use]
    pub fn new(addr: SocketAddr, nwk: Option<Nwk>, source: PeerSource) -> Self {
        Self {
            addr,
            nwk,
            source,
            last_rx_ms: None,
            health: 1.0,
            alternates: Vec::new(),
            mcast: [Group::default(), Group::default()],
            quic_port: None,
            mcast_logged_ok: false,
        }
    }

    /// The group our multicast reaches this peer through, by preference: a group the
    /// peer announced and has acked a recent probe on.
    #[must_use]
    pub fn multicast_group(&self, prefer_ipv4: bool, now: u64) -> Option<SocketAddr> {
        let order = if prefer_ipv4 { [V4, V6] } else { [V6, V4] };
        order
            .into_iter()
            .find(|&f| self.mcast[f].confirmed(now))
            .and_then(|f| self.mcast[f].addr)
    }

    /// The current address went unanswered: move to the next advertised one.
    pub fn rotate(&mut self) {
        if self.alternates.len() < 2 {
            return;
        }
        let next = self
            .alternates
            .iter()
            .position(|a| *a == self.addr)
            .map_or(0, |i| (i + 1) % self.alternates.len());
        tracing::info!(
            "ZLOE: {} unanswered, trying {}",
            self.addr,
            self.alternates[next]
        );
        self.addr = self.alternates[next];
    }

    #[must_use]
    pub fn live(&self, now: u64) -> bool {
        self.last_rx_ms
            .is_some_and(|t| now.saturating_sub(t) < BACKBONE_LIVE_MS)
    }

    /// What frames from this peer report: a datagram arrived, so the link works. Unanswered
    /// sends only drive retries, rotation and the radio fallback (`health` is diagnostics): a
    /// score kept from them would stick, since a costly link is no longer used and never
    /// earns a success back.
    #[must_use]
    pub const fn lqi(&self) -> u8 {
        255
    }

    pub fn record(&mut self, acked: bool) {
        let sample = if acked { 1.0 } else { 0.0 };
        self.health += HEALTH_ALPHA * (sample - self.health);
    }
}

/// Our identity on the backbone: complete once both the radio configuration (address,
/// channel) and the network's extended PAN ID are known.
#[derive(Debug, Clone, Copy)]
pub struct Identity {
    pub eui64: Eui64,
    pub nwk: Nwk,
    pub epan: Eui64,
    pub channel: u8,
}

/// What discovery last told us about a node.
#[derive(Debug, Clone)]
pub struct Resolved {
    pub epan: Option<Eui64>,
    pub nwk: Option<Nwk>,
    /// Usable addresses, best first, with their rank
    pub candidates: Vec<((u8, u8), SocketAddr)>,
    /// Announced groups: [IPv6 (`mc`), IPv4 (`mc4`)]
    pub mcast: [Option<SocketAddr>; 2],
    /// Security mode (`sec`) and QUIC port (`qp`)
    pub quic_port: Option<u16>,
}

/// What a received datagram turned out to be.
#[derive(Debug)]
pub enum Inbound {
    /// Nothing for the caller: an ack, a dropped or malformed datagram.
    Nothing,
    /// Somebody asks for the network settings; only a coordinator answers.
    NetinfoRequest { seq: u32, eui64: Eui64 },
    /// The settings we asked for.
    NetinfoResponse(Vec<u8>),
    /// A frame for the stack (none when it was a duplicate or a probe) and the reply to send.
    Data {
        frame: Option<RxFrame>,
        reply: Option<Vec<u8>>,
    },
}

/// The plain state behind a [`CoreLock`].
#[derive(Default)]
pub struct ZloeState {
    pub identity: Option<Identity>,
    /// Radio half of the identity, from the radio's configuration
    pub radio: Option<(Eui64, Nwk, u8)>,
    /// Network half, from the network's configuration
    pub epan: Option<Eui64>,
    pub peers: BTreeMap<Eui64, Peer>,
    /// Recently delivered (sender, backbone seq), to drop retransmits of a frame whose
    /// ack was lost.
    seen: BTreeMap<Eui64, VecDeque<u32>>,
    /// Coordinators seen on the backbone (`role=coordinator`), kept even before we have
    /// an identity of our own: satellites bootstrap from them
    pub coordinators: BTreeMap<Eui64, (SocketAddr, Option<Eui64>)>,
    /// Everything discovery resolved, by extended address
    pub resolved: BTreeMap<Eui64, Resolved>,
    /// Secure (QUIC) mode
    pub secure: bool,
    /// QUIC ports of coordinators seen on the backbone (enrollment targets)
    pub coordinator_quic: BTreeMap<Eui64, u16>,
    /// Packet numbers of our latest multicast probes, with their family
    probes: VecDeque<(u32, usize)>,
    seq: u32,
}

impl ZloeState {
    /// `seed` starts the packet numbers, so a restart does not look like retransmits.
    #[must_use]
    pub fn new(seed: u32) -> Self {
        Self {
            seq: seed,
            ..Self::default()
        }
    }

    pub const fn next_seq(&mut self) -> u32 {
        let seq = self.seq;
        self.seq = self.seq.wrapping_add(1);
        seq
    }

    /// The radio half of the identity changed; returns the identity when it is new.
    pub fn set_radio(&mut self, eui64: Eui64, nwk: Nwk, channel: u8) -> Option<Identity> {
        self.radio = Some((eui64, nwk, channel));
        self.update_identity()
    }

    /// The extended PAN ID is known; returns the identity when it is new.
    pub fn set_epan(&mut self, epan: Eui64) -> Option<Identity> {
        self.epan = Some(epan);
        self.update_identity()
    }

    fn update_identity(&mut self) -> Option<Identity> {
        let (eui64, nwk, channel) = self.radio?;
        let epan = self.epan?;
        let identity = Identity {
            eui64,
            nwk,
            epan,
            channel,
        };
        let changed = self.identity.is_none_or(|old| {
            old.eui64 != identity.eui64 || old.nwk != identity.nwk || old.epan != identity.epan
        });
        self.identity = Some(identity);
        if changed {
            // Nodes resolved before we knew our network become peers now
            let known: Vec<Eui64> = self.resolved.keys().copied().collect();
            for eui64 in known {
                self.apply_resolved(eui64);
            }
        }
        changed.then_some(identity)
    }

    /// Discovery resolved a node: kept even while we have no identity (a satellite
    /// browses before it knows its network) and applied once we do.
    pub fn on_resolved(&mut self, eui64: Eui64, resolved: Resolved, coordinator: bool) {
        let Some(&(_, addr)) = resolved.candidates.first() else {
            return;
        };
        if coordinator {
            if let Some(qp) = resolved.quic_port {
                self.coordinator_quic.insert(eui64, qp);
            }
            let epan = resolved.epan;
            if self.coordinators.insert(eui64, (addr, epan)).is_none() {
                tracing::info!("ZLOE: coordinator {eui64:?} (epan {epan:?}) at {addr}");
            }
        }
        self.resolved.insert(eui64, resolved);
        self.apply_resolved(eui64);
    }

    /// Discovery says a node went away.
    pub fn on_removed(&mut self, eui64: Eui64) {
        self.resolved.remove(&eui64);
        if let Some(peer) = self.peers.get_mut(&eui64) {
            // A peer kept alive by its own traffic loses what only discovery told us
            peer.mcast = [Group::default(), Group::default()];
        }
        if self
            .peers
            .get(&eui64)
            .is_some_and(|p| p.source == PeerSource::Mdns)
        {
            tracing::info!("ZLOE: mDNS peer {eui64:?} went away");
            self.peers.remove(&eui64);
        }
    }

    /// Create or update the peer for a resolved node on our network.
    fn apply_resolved(&mut self, eui64: Eui64) {
        let Some(identity) = self.identity else {
            return;
        };
        let Some(resolved) = self.resolved.get(&eui64).cloned() else {
            return;
        };
        if eui64 == identity.eui64 || resolved.epan != Some(identity.epan) {
            return;
        }
        // A secure node only peers with secure nodes, and the other way around
        if self.secure != resolved.quic_port.is_some() {
            return;
        }
        let Some(&(best_key, addr)) = resolved.candidates.first() else {
            return;
        };
        let nwk = resolved.nwk;

        let peer = self.peers.entry(eui64).or_insert_with(|| {
            tracing::info!("ZLOE: mDNS peer {eui64:?} / {nwk:?} at {addr}");
            Peer::new(addr, nwk, PeerSource::Mdns)
        });
        // Once the peer has talked to us, its datagrams' source address is authoritative.
        // Until then follow discovery, but only to a strictly better address: answers
        // trickle in per interface and would make it flap
        let current_key = resolved
            .candidates
            .iter()
            .find(|(_, a)| *a == peer.addr)
            .map(|(k, _)| *k);
        peer.alternates = resolved.candidates.iter().map(|(_, a)| *a).collect();
        peer.quic_port = resolved.quic_port;
        for family in [V6, V4] {
            if peer.mcast[family].addr != resolved.mcast[family] {
                tracing::info!(
                    "ZLOE: peer {eui64:?} multicast: {:?}",
                    resolved.mcast[family]
                );
                peer.mcast[family] = Group {
                    addr: resolved.mcast[family],
                    acked_ms: None,
                };
            }
        }
        if peer.last_rx_ms.is_none() && current_key.is_none_or(|k| best_key < k) {
            tracing::info!("ZLOE: mDNS peer {eui64:?} moved to {addr}");
            peer.addr = addr;
        }
        if nwk.is_some() {
            peer.nwk = nwk;
        }
    }

    /// A data or probe datagram: refresh the peer, drop duplicates, build the frame and ack.
    fn on_data(&mut self, header: &WireHeader, buf: &[u8], from: SocketAddr, now: u64) -> Inbound {
        let Some(identity) = self.identity else {
            return Inbound::Nothing;
        };
        if header.epan != identity.epan || header.eui64 == identity.eui64 {
            return Inbound::Nothing;
        }

        // Learn (or refresh) the peer from its own traffic
        let peer = self.peers.entry(header.eui64).or_insert_with(|| {
            tracing::info!(
                "ZLOE: learned peer {:?} / {:?} at {from}",
                header.eui64,
                header.nwk
            );
            Peer::new(from, None, PeerSource::Learned)
        });
        peer.addr = from;
        peer.nwk = Some(header.nwk);
        peer.last_rx_ms = Some(now);
        let lqi = peer.lqi();

        // A probe only refreshes the peer and gets its ack
        let seen = self.seen.entry(header.eui64).or_default();
        let duplicate = header.kind == KIND_PROBE || seen.contains(&header.seq);
        if !duplicate {
            seen.push_back(header.seq);
            if seen.len() > DEDUP_WINDOW {
                seen.pop_front();
            }
        }

        let frame = (!duplicate).then(|| RxFrame {
            psdu: buf[HEADER_LEN..].to_vec(),
            channel: identity.channel,
            rssi: BACKBONE_RSSI,
            lqi,
            timestamp_us: 0,
        });
        let reply = (header.flags & FLAG_ACK_REQUEST != 0).then(|| {
            WireHeader {
                kind: KIND_ACK,
                flags: 0,
                seq: header.seq,
                eui64: identity.eui64,
                nwk: identity.nwk,
                epan: identity.epan,
            }
            .to_bytes()
        });
        Inbound::Data { frame, reply }
    }

    /// An ack nobody was waiting on: an answer to a probe?
    fn on_probe_ack(&mut self, header: &WireHeader, now: u64) {
        let family = self
            .probes
            .iter()
            .find(|(seq, _)| *seq == header.seq)
            .map(|(_, f)| *f);
        if let Some(family) = family
            && let Some(peer) = self.peers.get_mut(&header.eui64)
        {
            peer.mcast[family].acked_ms = Some(now);
        }
    }

    /// Whether an over-the-air frame goes to the stack: copies of what a live backbone
    /// peer also sends over the backbone do not.
    #[must_use]
    pub fn keep_air_frame(&self, source: &MacAddress, now: u64) -> bool {
        let live_peer = match source {
            MacAddress::Extended(eui64) => self.peers.get(eui64).is_some_and(|p| p.live(now)),
            MacAddress::Short(nwk) => self
                .peers
                .values()
                .any(|p| p.nwk == Some(*nwk) && p.live(now)),
            MacAddress::None => false,
        };
        !live_peer
    }

    #[must_use]
    pub fn peer_for(&self, dest: &MacAddress) -> Option<SocketAddr> {
        match dest {
            MacAddress::Extended(eui64) => self.peers.get(eui64).map(|p| p.addr),
            MacAddress::Short(nwk) => self
                .peers
                .values()
                .find(|p| p.nwk == Some(*nwk))
                .map(|p| p.addr),
            MacAddress::None => None,
        }
    }

    #[must_use]
    pub fn peer_eui_for(&self, dest: &MacAddress) -> Option<Eui64> {
        match dest {
            MacAddress::Extended(eui64) => self.peers.contains_key(eui64).then_some(*eui64),
            MacAddress::Short(nwk) => self
                .peers
                .iter()
                .find(|(_, p)| p.nwk == Some(*nwk))
                .map(|(e, _)| *e),
            MacAddress::None => None,
        }
    }

    /// A data datagram carrying `psdu`, with a fresh packet number. `None` without an identity.
    pub fn data_datagram(&mut self, flags: u8, psdu: &[u8]) -> Option<(u32, Vec<u8>)> {
        let identity = self.identity?;
        let seq = self.next_seq();
        let mut datagram = WireHeader {
            kind: KIND_DATA,
            flags,
            seq,
            eui64: identity.eui64,
            nwk: identity.nwk,
            epan: identity.epan,
        }
        .to_bytes();
        datagram.extend_from_slice(psdu);
        Some((seq, datagram))
    }

    /// Header for the bootstrap messages, sent before we may have an identity.
    #[must_use]
    pub fn netinfo_header(&self, kind: u8, seq: u32) -> Vec<u8> {
        let identity = self.identity;
        WireHeader {
            kind,
            flags: 0,
            seq,
            eui64: identity.map_or(Eui64([0; 8]), |i| i.eui64),
            nwk: identity.map_or(Nwk(0xFFFF), |i| i.nwk),
            epan: identity.map_or(Eui64([0; 8]), |i| i.epan),
        }
        .to_bytes()
    }

    /// Where a broadcast goes: multicast groups, and unicast copies for the peers multicast
    /// does not reach (no announced address, or probes unanswered) and `extra` addresses
    /// no known peer has.
    #[must_use]
    pub fn broadcast_targets(
        &self,
        prefer_ipv4: bool,
        extra: &[SocketAddr],
        now: u64,
    ) -> (Vec<SocketAddr>, Vec<SocketAddr>) {
        let mut groups: Vec<SocketAddr> = Vec::new();
        let mut copies: Vec<SocketAddr> = Vec::new();
        for peer in self.peers.values() {
            match peer.multicast_group(prefer_ipv4, now) {
                Some(group) => {
                    if !groups.contains(&group) {
                        groups.push(group);
                    }
                }
                None => copies.push(peer.addr),
            }
        }
        for addr in extra {
            if !self.peers.values().any(|p| p.addr == *addr) {
                copies.push(*addr);
            }
        }
        (groups, copies)
    }

    /// One probe datagram per multicast group worth probing, so an ack tells which family
    /// works: the preferred group only, the other only while the preferred one is absent
    /// or unconfirmed, so a peer can fail over without doubling the probe traffic.
    pub fn plan_probes(&mut self, prefer_ipv4: bool, now: u64) -> Vec<(SocketAddr, Vec<u8>)> {
        let Some(identity) = self.identity else {
            return Vec::new();
        };
        let mut groups: Vec<(usize, SocketAddr)> = Vec::new();
        for (eui64, peer) in &mut self.peers {
            let order = if prefer_ipv4 { [V4, V6] } else { [V6, V4] };
            for family in order {
                let Some(group) = peer.mcast[family].addr else {
                    continue;
                };
                if !groups.contains(&(family, group)) {
                    groups.push((family, group));
                }
                if peer.mcast[family].confirmed(now) {
                    break;
                }
            }
            let ok = peer.multicast_group(prefer_ipv4, now);
            if ok.is_some() != peer.mcast_logged_ok {
                peer.mcast_logged_ok = ok.is_some();
                match ok {
                    Some(group) => {
                        tracing::info!("ZLOE: multicast reaches {eui64:?} via {group}");
                    }
                    None => tracing::warn!(
                        "ZLOE: multicast does not reach {eui64:?}, sending it unicast copies"
                    ),
                }
            }
        }

        let probes: Vec<(SocketAddr, Vec<u8>)> = groups
            .into_iter()
            .map(|(family, group)| {
                let seq = self.next_seq();
                self.probes.push_back((seq, family));
                let probe = WireHeader {
                    kind: KIND_PROBE,
                    flags: FLAG_ACK_REQUEST,
                    seq,
                    eui64: identity.eui64,
                    nwk: identity.nwk,
                    epan: identity.epan,
                }
                .to_bytes();
                (group, probe)
            })
            .collect();
        while self.probes.len() > 8 {
            self.probes.pop_front();
        }
        probes
    }

    fn record_link(&mut self, to: SocketAddr, acked: bool) {
        if let Some(peer) = self.peers.values_mut().find(|p| p.addr == to) {
            peer.record(acked);
        }
    }

    fn rotate(&mut self, to: SocketAddr) {
        if let Some(peer) = self.peers.values_mut().find(|p| p.addr == to) {
            peer.rotate();
        }
    }
}

/// [`ZloeState`] with the lock, clock and transport of one runtime.
pub struct ZloeCore<L, C, T> {
    pub state: L,
    pub clock: C,
    pub transport: T,
}

impl<L: CoreLock, C: Clock, T: BackboneTransport> ZloeCore<L, C, T> {
    pub const fn new(state: L, clock: C, transport: T) -> Self {
        Self {
            state,
            clock,
            transport,
        }
    }

    /// Handle one ZLOE datagram.
    pub fn on_datagram(&self, buf: &[u8], from: SocketAddr) -> Inbound {
        let Some(header) = WireHeader::parse(buf) else {
            tracing::debug!("ZLOE: dropping malformed datagram from {from}");
            return Inbound::Nothing;
        };
        let now = self.clock.now_ms();
        match header.kind {
            KIND_ACK => {
                if !self.transport.complete_ack(header.seq) {
                    self.state.with(|s| s.on_probe_ack(&header, now));
                }
                Inbound::Nothing
            }
            KIND_NETINFO_REQ => Inbound::NetinfoRequest {
                seq: header.seq,
                eui64: header.eui64,
            },
            KIND_NETINFO_RSP => Inbound::NetinfoResponse(buf[HEADER_LEN..].to_vec()),
            KIND_DATA | KIND_PROBE => self.state.with(|s| s.on_data(&header, buf, from, now)),
            _ => Inbound::Nothing,
        }
    }

    /// Whether an over-the-air frame goes to the stack.
    pub fn keep_air_frame(&self, psdu: &[u8]) -> bool {
        let Some(mac) = MacHeader::parse(psdu) else {
            return true;
        };
        let now = self.clock.now_ms();
        self.state.with(|s| s.keep_air_frame(&mac.source, now))
    }

    /// Send a broadcast's backbone copies. Returns the datagrams sent as (multicast, unicast).
    pub async fn send_broadcast(
        &self,
        psdu: &[u8],
        prefer_ipv4: bool,
        extra: &[SocketAddr],
    ) -> (usize, usize) {
        let now = self.clock.now_ms();
        let Some((datagram, groups, copies)) = self.state.with(|s| {
            let (_, datagram) = s.data_datagram(0, psdu)?;
            let (groups, copies) = s.broadcast_targets(prefer_ipv4, extra, now);
            Some((datagram, groups, copies))
        }) else {
            return (0, 0);
        };
        // Every target gets the same packet number, so a peer that receives both keeps one
        for &group in &groups {
            self.transport.send(group, &datagram).await;
        }
        for &copy in &copies {
            self.transport.send(copy, &datagram).await;
        }
        (groups.len(), copies.len())
    }

    /// Reliable-ish unicast to one peer: `true` once acked, or once sent when no ack is
    /// wanted. After [`ATTEMPTS`] unanswered tries the peer's health drops and it moves to
    /// its next address.
    pub async fn send_unicast(&self, to: SocketAddr, psdu: &[u8], ack_request: bool) -> bool {
        let flags = if ack_request { FLAG_ACK_REQUEST } else { 0 };
        let Some((seq, datagram)) = self.state.with(|s| s.data_datagram(flags, psdu)) else {
            return false;
        };
        if !ack_request {
            return self.transport.send(to, &datagram).await;
        }
        for attempt in 0..ATTEMPTS {
            let outcome = self
                .transport
                .send_wait_ack(to, &datagram, seq, ACK_TIMEOUT_MS)
                .await;
            let acked = outcome == AckOutcome::Acked;
            self.state.with(|s| s.record_link(to, acked));
            if acked {
                if attempt > 0 {
                    tracing::debug!("ZLOE: unicast to {to} acked after {} retries", attempt);
                }
                return true;
            }
            if outcome == AckOutcome::SendFailed {
                break;
            }
        }
        tracing::debug!("ZLOE: unicast to {to} not acked");
        self.state.with(|s| s.rotate(to));
        false
    }

    /// Backbone first: `true` when a unicast went over the backbone. `false` means the frame
    /// still has to go on the radio (no such peer, or the backbone failed).
    pub async fn send_to_peer(&self, mac: &MacHeader, psdu: &[u8]) -> bool {
        let Some(peer) = self.state.with(|s| s.peer_for(&mac.dest)) else {
            return false;
        };
        if self.send_unicast(peer, psdu, mac.ack_request).await {
            tracing::trace!("ZLOE: tx to {:?} via backbone", mac.dest);
            return true;
        }
        tracing::info!(
            "ZLOE: backbone to {:?} failed, falling back to air",
            mac.dest
        );
        false
    }
}

#[cfg(test)]
mod tests;
