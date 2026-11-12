use core::cell::Cell;
use core::net::{IpAddr, Ipv6Addr};
use core::pin::pin;
use core::task::{Context, Poll, Waker};
use std::sync::Mutex;

use super::*;

const ME: Eui64 = Eui64([1; 8]);
const PEER: Eui64 = Eui64([2; 8]);
const EPAN: Eui64 = Eui64([9; 8]);

struct Lock(Mutex<ZloeState>);
impl CoreLock for Lock {
    fn with<R>(&self, f: impl FnOnce(&mut ZloeState) -> R) -> R {
        f(&mut self.0.lock().unwrap())
    }
}

struct FakeClock(Mutex<Cell<u64>>);
impl Clock for FakeClock {
    fn now_ms(&self) -> u64 {
        self.0.lock().unwrap().get()
    }
}

#[derive(Default)]
struct Fake {
    sent: Mutex<Vec<(SocketAddr, Vec<u8>)>>,
    /// Which try gets acked (`None`: never)
    ack_on_try: Option<usize>,
    pending: Mutex<Option<u32>>,
}

impl BackboneTransport for Fake {
    async fn send(&self, to: SocketAddr, datagram: &[u8]) -> bool {
        self.sent.lock().unwrap().push((to, datagram.to_vec()));
        true
    }
    async fn send_wait_ack(&self, to: SocketAddr, datagram: &[u8], _: u32, _: u64) -> AckOutcome {
        let tries = {
            let mut sent = self.sent.lock().unwrap();
            sent.push((to, datagram.to_vec()));
            sent.len()
        };
        if self.ack_on_try == Some(tries) {
            AckOutcome::Acked
        } else {
            AckOutcome::TimedOut
        }
    }
    fn complete_ack(&self, seq: u32) -> bool {
        let mut pending = self.pending.lock().unwrap();
        let hit = *pending == Some(seq);
        if hit {
            *pending = None;
        }
        hit
    }
}

fn block_on<F: Future>(f: F) -> F::Output {
    let mut f = pin!(f);
    match f.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(v) => v,
        Poll::Pending => panic!("fake transport never waits"),
    }
}

fn addr(last: u16) -> SocketAddr {
    SocketAddr::new(
        IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, last)),
        19790,
    )
}

fn core_with(ack_on_try: Option<usize>) -> ZloeCore<Lock, FakeClock, Fake> {
    let mut state = ZloeState::new(100);
    state.set_radio(ME, Nwk(0x1234), 20);
    state.set_epan(EPAN);
    ZloeCore::new(
        Lock(Mutex::new(state)),
        FakeClock(Mutex::new(Cell::new(1000))),
        Fake {
            ack_on_try,
            ..Fake::default()
        },
    )
}

fn datagram(kind: u8, flags: u8, seq: u32, eui64: Eui64, epan: Eui64, body: &[u8]) -> Vec<u8> {
    let mut out = WireHeader {
        kind,
        flags,
        seq,
        eui64,
        nwk: Nwk(0x4321),
        epan,
    }
    .to_bytes();
    out.extend_from_slice(body);
    out
}

fn resolved(epan: Eui64, addrs: &[SocketAddr]) -> Resolved {
    Resolved {
        epan: Some(epan),
        nwk: Some(Nwk(0x4321)),
        candidates: addrs.iter().map(|a| ((0, 0), *a)).collect(),
        mcast: [None, None],
        quic_port: None,
    }
}

fn add_peer(core: &ZloeCore<Lock, FakeClock, Fake>, addrs: &[SocketAddr]) {
    core.state
        .with(|s| s.on_resolved(PEER, resolved(EPAN, addrs), false));
}

/// A MAC data frame, short addressing, PAN compression.
fn mac_frame(dest: u16, src: u16, ack: bool, frame_type: u16) -> Vec<u8> {
    let fcf: u16 = frame_type | (u16::from(ack) << 5) | (1 << 6) | (2 << 10) | (2 << 14);
    let mut out = fcf.to_le_bytes().to_vec();
    out.push(7);
    out.extend_from_slice(&[0x61, 0xAD]);
    out.extend_from_slice(&dest.to_le_bytes());
    out.extend_from_slice(&src.to_le_bytes());
    out.push(0xEE);
    out
}

#[test]
fn wire_header_is_27_bytes_and_round_trips() {
    let bytes = datagram(KIND_DATA, 1, 0xAABBCCDD, PEER, EPAN, &[]);
    assert_eq!(bytes.len(), HEADER_LEN);
    assert_eq!(&bytes[..3], b"ZL\x02");
    let header = WireHeader::parse(&bytes).unwrap();
    assert_eq!(header.seq, 0xAABBCCDD);
    assert_eq!(header.eui64, PEER);
    assert_eq!(header.nwk, Nwk(0x4321));
    assert_eq!(header.epan, EPAN);
}

#[test]
fn data_from_peer_delivers_once_with_lqi_and_acks() {
    let core = core_with(None);
    let bytes = datagram(KIND_DATA, FLAG_ACK_REQUEST, 5, PEER, EPAN, &[0xAB]);
    let Inbound::Data { frame, reply } = core.on_datagram(&bytes, addr(2)) else {
        panic!("not data");
    };
    let frame = frame.unwrap();
    assert_eq!(frame.psdu, [0xAB]);
    assert_eq!(frame.lqi, 255);
    assert_eq!(frame.channel, 20);
    let ack = WireHeader::parse(&reply.unwrap()).unwrap();
    assert_eq!((ack.kind, ack.seq, ack.eui64), (KIND_ACK, 5, ME));
    core.state.with(|s| {
        let peer = &s.peers[&PEER];
        assert_eq!(peer.addr, addr(2));
        assert_eq!(peer.nwk, Some(Nwk(0x4321)));
        assert_eq!(peer.last_rx_ms, Some(1000));
    });
}

#[test]
fn retransmit_returns_no_frame_but_still_acks() {
    let core = core_with(None);
    let bytes = datagram(KIND_DATA, FLAG_ACK_REQUEST, 5, PEER, EPAN, &[0xAB]);
    core.on_datagram(&bytes, addr(2));
    let Inbound::Data { frame, reply } = core.on_datagram(&bytes, addr(2)) else {
        panic!("not data");
    };
    assert!(frame.is_none());
    assert!(reply.is_some());
}

#[test]
fn other_network_or_self_is_dropped_and_learns_no_peer() {
    let core = core_with(None);
    let other = datagram(KIND_DATA, 0, 1, PEER, Eui64([8; 8]), &[1]);
    let own = datagram(KIND_DATA, 0, 2, ME, EPAN, &[1]);
    assert!(matches!(
        core.on_datagram(&other, addr(2)),
        Inbound::Nothing
    ));
    assert!(matches!(core.on_datagram(&own, addr(2)), Inbound::Nothing));
    core.state.with(|s| assert!(s.peers.is_empty()));
}

#[test]
fn malformed_datagrams_are_dropped() {
    let core = core_with(None);
    let mut bad_magic = datagram(KIND_DATA, 0, 1, PEER, EPAN, &[]);
    bad_magic[0] = b'X';
    let mut bad_version = datagram(KIND_DATA, 0, 1, PEER, EPAN, &[]);
    bad_version[2] = 1;
    for bytes in [&bad_magic[..], &bad_version[..], &b"ZL"[..]] {
        assert!(matches!(core.on_datagram(bytes, addr(2)), Inbound::Nothing));
    }
}

#[test]
fn netinfo_response_returns_the_settings() {
    let core = core_with(None);
    let bytes = datagram(KIND_NETINFO_RSP, 0, 1, PEER, EPAN, &[1, 2, 3]);
    assert!(matches!(
        core.on_datagram(&bytes, addr(2)),
        Inbound::NetinfoResponse(v) if v == [1, 2, 3]
    ));
}

#[test]
fn ack_completes_the_pending_unicast() {
    let core = core_with(None);
    *core.transport.pending.lock().unwrap() = Some(7);
    let ack = datagram(KIND_ACK, 0, 7, PEER, EPAN, &[]);
    assert!(matches!(core.on_datagram(&ack, addr(2)), Inbound::Nothing));
    assert_eq!(*core.transport.pending.lock().unwrap(), None);
}

#[test]
fn air_frame_from_live_peer_is_dropped_stale_or_unknown_kept() {
    let core = core_with(None);
    let frame = mac_frame(0xFFFF, 0x4321, false, 1);
    assert!(core.keep_air_frame(&frame), "unknown source");
    core.on_datagram(&datagram(KIND_DATA, 0, 1, PEER, EPAN, &[1]), addr(2));
    assert!(!core.keep_air_frame(&frame), "live peer");
    core.clock.0.lock().unwrap().set(1000 + BACKBONE_LIVE_MS);
    assert!(core.keep_air_frame(&frame), "stale peer");
}

#[test]
fn broadcast_makes_one_copy_per_peer_with_one_packet_number() {
    let core = core_with(None);
    add_peer(&core, &[addr(2)]);
    core.state.with(|s| {
        s.on_resolved(Eui64([3; 8]), resolved(EPAN, &[addr(3)]), false);
    });
    let frame = mac_frame(0xFFFF, 0x1234, false, 1);
    assert_eq!(block_on(core.send_broadcast(&frame, false, &[])), (0, 2));
    let sent = core.transport.sent.lock().unwrap().clone();
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[0].1, sent[1].1);
}

#[test]
fn unicast_to_peer_goes_over_the_backbone() {
    let core = core_with(Some(1));
    add_peer(&core, &[addr(2)]);
    let frame = mac_frame(0x4321, 0x1234, true, 1);
    let mac = MacHeader::parse(&frame).unwrap();
    assert!(block_on(core.send_to_peer(&mac, &frame)));
    let sent = core.transport.sent.lock().unwrap().clone();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].0, addr(2));
    let header = WireHeader::parse(&sent[0].1).unwrap();
    assert_eq!(header.flags, FLAG_ACK_REQUEST);
    assert_eq!(&sent[0].1[HEADER_LEN..], &frame[..]);
}

#[test]
fn unicast_to_unknown_destination_stays_off_the_backbone() {
    let core = core_with(Some(1));
    let frame = mac_frame(0x7777, 0x1234, true, 1);
    let mac = MacHeader::parse(&frame).unwrap();
    assert!(!block_on(core.send_to_peer(&mac, &frame)));
    assert!(core.transport.sent.lock().unwrap().is_empty());
}

#[test]
fn acked_on_a_retry_returns_true() {
    let core = core_with(Some(3));
    add_peer(&core, &[addr(2)]);
    assert!(block_on(core.send_unicast(addr(2), &[1], true)));
    assert_eq!(core.transport.sent.lock().unwrap().len(), 3);
}

#[test]
fn three_tries_without_ack_lower_health_and_rotate_but_keep_full_lqi() {
    let core = core_with(None);
    add_peer(&core, &[addr(2), addr(3)]);
    assert!(!block_on(core.send_unicast(addr(2), &[1], true)));
    assert_eq!(core.transport.sent.lock().unwrap().len(), ATTEMPTS);
    core.state.with(|s| {
        let peer = &s.peers[&PEER];
        assert!(peer.health < 1.0);
        assert_eq!(
            peer.lqi(),
            255,
            "frames from the peer still report a working link"
        );
        assert_eq!(peer.addr, addr(3));
    });
}

#[test]
fn resolved_peer_on_our_network_is_created_other_ignored() {
    let core = core_with(None);
    core.state.with(|s| {
        s.on_resolved(PEER, resolved(EPAN, &[addr(2)]), false);
        s.on_resolved(Eui64([3; 8]), resolved(Eui64([8; 8]), &[addr(3)]), false);
        assert_eq!(s.peers.len(), 1);
        assert_eq!(s.peers[&PEER].addr, addr(2));
    });
}

#[test]
fn secure_peer_is_ignored_by_an_unsecure_node() {
    let core = core_with(None);
    core.state.with(|s| {
        let mut r = resolved(EPAN, &[addr(2)]);
        r.quic_port = Some(19890);
        s.on_resolved(PEER, r, false);
        assert!(s.peers.is_empty());
    });
}

#[test]
fn peer_resolved_before_identity_becomes_a_peer_later() {
    let mut s = ZloeState::new(0);
    s.on_resolved(PEER, resolved(EPAN, &[addr(2)]), false);
    assert!(s.peers.is_empty());
    s.set_radio(ME, Nwk(0x1234), 20);
    assert!(s.set_epan(EPAN).is_some());
    assert_eq!(s.peers.len(), 1);
}

#[test]
fn coordinator_is_kept_without_an_identity() {
    let mut s = ZloeState::new(0);
    s.on_resolved(PEER, resolved(EPAN, &[addr(2)]), true);
    assert_eq!(s.coordinators[&PEER], (addr(2), Some(EPAN)));
}

#[test]
fn netinfo_request_before_identity_has_a_zero_identity() {
    let s = ZloeState::new(0);
    let header = WireHeader::parse(&s.netinfo_header(KIND_NETINFO_REQ, 3)).unwrap();
    assert_eq!(header.eui64, Eui64([0; 8]));
    assert_eq!(header.nwk, Nwk(0xFFFF));
}
