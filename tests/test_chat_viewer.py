"""Comprehensive regression, protocol, and HTTP/SSE integration tests for tools.chat_viewer."""

from __future__ import annotations

import json
import random
import shutil
import struct
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import pytest
from starlette.testclient import TestClient

from tools.chat_viewer.battle import Lzw16Decoder
from tools.chat_viewer.history import MatchHistoryStore
from tools.chat_viewer.kcp import KcpStreamReassembler
from tools.chat_viewer.pcap_reader import (
    LINKTYPE_ETHERNET,
    LINKTYPE_RAW,
    LINKTYPE_SLL,
    LINKTYPE_SLL2,
    IncrementalPcapReader,
    InvalidPcapMagicError,
)
from tools.chat_viewer.protocol import extract_events_from_tick_bytes, lz4_decompress_raw
from tools.chat_viewer.server import create_app, validate_loopback_host
from tools.chat_viewer.session import MatchStore, SessionRouter
from tools.chat_viewer.templates import TemplateResolver

CAPTURES_DIR = REPO_ROOT / "captures"

# Replay tests need the author's private `.pcap` captures (they hold real player
# names and UIDs, so they are never committed). Skip them on a fresh clone.
needs_captures = pytest.mark.skipif(
    not (CAPTURES_DIR / "draft_CHAT4.pcap").is_file(),
    reason="private captures/*.pcap not present (not in the public repo)",
)


def _decode_pcap_whole(path: Path, templates_path: Path | None = None) -> tuple[MatchStore, SessionRouter, IncrementalPcapReader]:
    store = MatchStore()
    templates = TemplateResolver(templates_path) if templates_path is not None else TemplateResolver(REPO_ROOT / "data" / "__missing__.json")
    router = SessionRouter(store=store, templates=templates)
    reader = IncrementalPcapReader()
    for pkt in reader.feed(path.read_bytes()):
        router.on_packet(pkt, skipped_truncated=reader.skipped_truncated)
    return store, router, reader


def _build_udp_ipv4_packet(src_ip: str, sport: int, dst_ip: str, dport: int, payload: bytes) -> bytes:
    udp_len = 8 + len(payload)
    ip_len = 20 + udp_len
    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        ip_len,
        1,
        0,
        64,
        17,
        0,
        bytes(int(x) for x in src_ip.split(".")),
        bytes(int(x) for x in dst_ip.split(".")),
    )
    udp_hdr = struct.pack("!HHHH", sport, dport, udp_len, 0)
    return ip_hdr + udp_hdr + payload


def _wrap_link_frame(linktype: int, ip_pkt: bytes) -> bytes:
    if linktype == LINKTYPE_RAW:
        return ip_pkt
    if linktype == LINKTYPE_ETHERNET:
        return (b"\xaa" * 6) + (b"\xbb" * 6) + struct.pack("!H", 0x0800) + ip_pkt
    if linktype == LINKTYPE_SLL:
        return struct.pack("!HHH8sH", 0, 1, 6, b"\x00" * 8, 0x0800) + ip_pkt
    if linktype == LINKTYPE_SLL2:
        return struct.pack("!HHIHBB8s", 0x0800, 0, 44, 1, 0, 6, b"\x00" * 8) + ip_pkt
    raise ValueError(linktype)


def _pcap_header(linktype: int = LINKTYPE_RAW, snaplen: int = 65535) -> bytes:
    return struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, snaplen, linktype)


def _pcap_record(ts_sec: int, ts_usec: int, frame: bytes, orig_len: int | None = None) -> bytes:
    olen = len(frame) if orig_len is None else orig_len
    return struct.pack("<IIII", ts_sec, ts_usec, len(frame), olen) + frame


def _encode_varint(val: int) -> bytes:
    out = bytearray()
    while True:
        b = val & 0x7F
        val >>= 7
        if val:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _make_030146_lzw_packet(conv: bytes, seq: int, encoded_tick: bytes) -> bytes:
    inner = b"\x70\x00" + _encode_varint(seq) + b"\x01\x01\x42" + _encode_varint(len(encoded_tick)) + encoded_tick + b"\x80"
    sub = b"\x03\x01\x46" + _encode_varint(len(inner)) + inner
    return b"\x01\x75" + conv + struct.pack("<H", len(sub)) + sub


def _make_fake_lzw_uncompressed_words(raw_bytes: bytes) -> bytes:
    # Using raw byte codewords 0..255 is always valid LZW-16 output as long as we advance encoder table identically.
    table: dict[bytes, int] = {bytes([i]): i for i in range(256)}
    next_code = 0x0101
    codes: list[int] = []
    cur = b""
    for b in raw_bytes:
        nxt = cur + bytes([b])
        if nxt in table:
            cur = nxt
        else:
            codes.append(table[cur])
            if next_code < 0x4000:
                table[nxt] = next_code
                next_code += 1
            cur = bytes([b])
    if cur:
        codes.append(table[cur])
    return b"".join(c.to_bytes(2, "big") for c in codes)


# ---------------------------------------------------------------------------
# Spec §10 Tests 1..9
# ---------------------------------------------------------------------------


@needs_captures
def test_1_draft_chat4_merged_match() -> None:
    store, router, _ = _decode_pcap_whole(CAPTURES_DIR / "draft_CHAT4.pcap")
    matches = store.get_matches()
    assert len(matches) == 1
    m = matches[0]
    assert m.battle_id == "231398567527828650"
    assert m.local_uid == 30028189
    assert m.local_camp == 1
    assert m.battle.lzw_errors == 0
    assert router.kcp.lz4_errors == 0
    assert router.kcp.pkt_lz4_errors == 0

    battle_evs = [ev for ev in m.events if ev.phase == "battle"]
    draft_evs = [ev for ev in m.events if ev.phase == "draft"]
    loading_evs = [ev for ev in m.events if ev.phase == "loading"]

    assert len(battle_evs) == 13
    assert battle_evs[0].tick == 141
    assert battle_evs[-1].tick == 1612

    enemy_team = [ev for ev in battle_evs if ev.tick == 578]
    assert len(enemy_team) == 1
    assert enemy_team[0].raw_text == "team rex"
    assert enemy_team[0].channel == 2
    assert enemy_team[0].side == "ENEMY"
    assert enemy_team[0].sender_name == "E1dreda."

    assert any(ev.raw_text == "1/team chat" and ev.side == "SELF" for ev in draft_evs)
    assert any(ev.raw_text == "1/hi" and ev.side == "ENEMY" for ev in draft_evs)
    assert any(ev.raw_text == "1/hahahahqtest" and ev.channel == 22 for ev in loading_evs)
    assert any(ev.raw_text == "1/tetahqjq" and ev.channel == 22 for ev in loading_evs)


@needs_captures
def test_2_draft_draft_merged_match() -> None:
    store, router, _ = _decode_pcap_whole(CAPTURES_DIR / "draft_DRAFT.pcap")
    matches = store.get_matches()
    assert len(matches) == 1
    m = matches[0]
    assert m.battle_id == "223233370841656980"
    assert m.battle.lzw_errors == 0
    assert router.kcp.lz4_errors == 0

    draft_evs = [ev for ev in m.events if ev.phase == "draft"]
    battle_evs = [ev for ev in m.events if ev.phase == "battle"]
    assert len(draft_evs) == 28
    assert len(battle_evs) == 17

    assert any(ev.raw_text == "1/team draft" and ev.side == "SELF" for ev in draft_evs)
    assert any(ev.raw_text == "1/Hi hi" and ev.side == "ENEMY" for ev in draft_evs)
    assert any(ev.raw_text == "1/I love Hora" and ev.side == "ENEMY" for ev in draft_evs)
    assert any(ev.raw_text == "Hi" and ev.tick == 1067 and ev.side == "ENEMY" for ev in battle_evs)
    assert any(ev.raw_text == "Team Hora" and ev.tick == 1180 and ev.side == "ENEMY" for ev in battle_evs)


@needs_captures
def test_3_draft_live6_4151_lz4_and_templates() -> None:
    # Verify exact KCP blocks sn=0..1, sn=5..20, sn=159..182 (24,088 bytes) first.
    reader = IncrementalPcapReader()
    kcp = KcpStreamReassembler()
    target_ep = ("149.104.112.216", 5507)
    completed: list[tuple[bytes, int, int, int, int]] = []
    for pkt in reader.feed((CAPTURES_DIR / "draft_LIVE6.pcap").read_bytes()):
        if (pkt.src_ip, pkt.sport) == target_ep and pkt.payload[:2] in (b"\x01\x51", b"\x41\x51", b"\x01\x52", b"\x41\x52"):
            for msg in kcp.on_datagram(pkt.ts, target_ep, "in", pkt.payload):
                completed.append((msg.conv, msg.sn_start, msg.sn_end, msg.comp, len(msg.payload)))
    assert kcp.lz4_errors == 0
    assert kcp.pkt_lz4_errors == 0
    assert any(sn0 == 0 and sn1 == 1 and comp == 1 for _, sn0, sn1, comp, _ in completed)
    assert any(sn0 == 5 and sn1 == 20 and comp == 1 for _, sn0, sn1, comp, _ in completed)
    assert any(sn0 == 159 and sn1 == 182 and comp == 1 and ln == 24088 for _, sn0, sn1, comp, ln in completed)

    store, router, _ = _decode_pcap_whole(CAPTURES_DIR / "draft_LIVE6.pcap")
    assert router.kcp.lz4_errors == 0
    assert router.kcp.pkt_lz4_errors == 0
    matches = store.get_matches()
    assert len(matches) == 2

    m1 = matches[0]
    assert m1.battle_id == "704578279919062684"
    assert m1.battle.lzw_errors == 0
    assert matches[1].battle.lzw_errors == 0

    by_text = {ev.raw_text: ev for ev in m1.events}
    assert by_text["8/48273/0"].slot == 0x13
    assert by_text["5/6/133"].slot == 0x23
    assert by_text["7/154830/ 8"].slot == 0x24


@needs_captures
def test_4_live_chat_check_midmatch_resync() -> None:
    store, _, _ = _decode_pcap_whole(CAPTURES_DIR / "live_chat_check.pcap")
    matches = store.get_matches()
    assert len(matches) == 1
    m = matches[0]
    assert m.battle.fsm_state == "SYNCED_MIDMATCH"
    assert m.battle.lzw_errors == 0
    assert m.battle.decoded_ticks == 74  # ticks 4590..4663
    assert m.battle.next_tick == 4664
    assert len(m.gaps) == 1
    g = m.gaps[0]
    assert g.resolved is True
    assert g.from_tick == 4447
    assert g.to_tick == 4589
    assert g.sync_tick == 4590


@needs_captures
def test_5_draft_chat3_raw_0x52_ticks() -> None:
    store, router, _ = _decode_pcap_whole(CAPTURES_DIR / "draft_CHAT3.pcap")
    assert router.kcp.lz4_errors == 0
    matches = store.get_matches()
    assert len(matches) == 1
    m = matches[0]
    assert m.battle_id == "609902284293776795"
    assert m.battle.mode == "raw"
    assert m.battle.fsm_state == "SYNCED"
    assert len(m.players_by_uid) == 10

    battle_evs = [ev for ev in m.events if ev.phase == "battle"]
    assert [(ev.tick, ev.raw_text, ev.side, ev.sender_name) for ev in battle_evs] == [
        (361, "team", "SELF", "naradira"),
        (394, "all", "SELF", "naradira"),
        (4808, "fany ayam mana", "ENEMY", "Alzheimer"),
        (8905, "ayam", "ENEMY", "Alzheimer"),
    ]


@needs_captures
def test_6_draft_live1_conv_rebind_single_match() -> None:
    store, _, _ = _decode_pcap_whole(CAPTURES_DIR / "draft_LIVE1.pcap")
    matches = store.get_matches()
    m5005 = [m for m in matches if m.ep == ("164.52.38.84", 5005)]
    assert len(m5005) == 1
    m = m5005[0]
    assert {"30497419", "5be1451a", "2a440a29", "53d3148c"} <= m.convs
    assert m.rebind_count >= 1
    assert m.battle.lzw.reset_count == 0
    assert m.battle.session_reset_count == 0

    # Synthetic non-truncated LZW continuity test across a 3rd-conv 01 71 / 01 72 switch.
    enc_table: dict[bytes, int] = {bytes([i]): i for i in range(256)}
    enc_next = 0x0101

    def enc_tick(raw_data: bytes) -> bytes:
        nonlocal enc_next
        codes: list[int] = []
        cur = b""
        for b in raw_data:
            nxt = cur + bytes([b])
            if nxt in enc_table:
                cur = nxt
            else:
                codes.append(enc_table[cur])
                if enc_next < 0x4000:
                    enc_table[nxt] = enc_next
                    enc_next += 1
                cur = bytes([b])
        if cur:
            codes.append(enc_table[cur])
        return b"".join(c.to_bytes(2, "big") for c in codes)

    chat_body = b"\x70\x00\x02\x41\x0bhello world\x80"
    ev_pkt = b"\x70\x51\x01\x70\x00\x10\x01\x06\x43" + _encode_varint(len(chat_body)) + chat_body + b"\x80\x80"
    tick0_lzw = enc_tick(b"\x70\x80")
    tick1_lzw = enc_tick(ev_pkt)

    s2 = MatchStore()
    r2 = SessionRouter(store=s2)
    conv1 = bytes.fromhex("30497419")
    conv3 = bytes.fromhex("2a440a29")

    pkts = [
        _build_udp_ipv4_packet("10.0.0.2", 5005, "192.168.1.10", 40001, _make_030146_lzw_packet(conv1, 0, tick0_lzw)),
        _build_udp_ipv4_packet("192.168.1.10", 40001, "10.0.0.2", 5005, b"\x01\x71" + conv3 + b"\x00" * 10),
        _build_udp_ipv4_packet("10.0.0.2", 5005, "192.168.1.10", 40001, b"\x01\x72" + conv3 + conv1 + b"\x00" * 6),
        _build_udp_ipv4_packet("10.0.0.2", 5005, "192.168.1.10", 40001, _make_030146_lzw_packet(conv3, 1, tick1_lzw)),
    ]
    raw_pcap = _pcap_header(LINKTYPE_RAW) + b"".join(_pcap_record(100 + i, 0, p) for i, p in enumerate(pkts))
    rdr = IncrementalPcapReader()
    for u in rdr.feed(raw_pcap):
        r2.on_packet(u)

    ms = s2.get_matches()
    assert len(ms) == 1
    assert ms[0].rebind_count == 1
    assert ms[0].battle.lzw.reset_count == 0
    assert ms[0].battle.fsm_state == "SYNCED"
    assert [ev.raw_text for ev in ms[0].events] == ["hello world"]


@needs_captures
def test_7_draft_relog_split_reused_port_and_fsm_rules() -> None:
    store, _, _ = _decode_pcap_whole(CAPTURES_DIR / "draft_RELOG.pcap")
    matches = store.get_matches()
    assert len(matches) == 2
    assert matches[0].ep == ("164.52.109.153", 5007)
    assert matches[1].ep == ("164.52.38.98", 5007)

    # Synthetic composite FSM rules on the EXACT SAME (ip, port):
    # (a) Different battleid -> new match;
    # (b) Same battleid reconnect restarting at tick 0 -> same match + deduped chat + reset_for_reconnect;
    # (c) Draft 03 02 arriving after BATTLE -> new match;
    # (d) tick == 0 after >15s idle with max_tick > 100 -> new match.
    s = MatchStore()
    r = SessionRouter(store=s)
    conv = b"\xaa\xbb\xcc\xdd"

    def make_kcp_login(c: bytes, sn: int, bid: str) -> bytes:
        body = f"\x70\x00\x00\x46\x20Play_{bid}_1".encode("ascii")
        return b"\x01\x51" + c + struct.pack("<IIIHBBH", 0, 1, sn, 64, 0, 0, len(body)) + body

    def make_kcp_draft_chat(c: bytes, sn: int, txt: str) -> bytes:
        cb = b"\x70\x00\x04\x41" + _encode_varint(len(txt)) + txt.encode() + b"\x80"
        inner = b"\x70\x51\x01\x70\x00\x10\x01\x06\x43" + _encode_varint(len(cb)) + cb + b"\x80\x80"
        body = b"\x70\x00\xcd\x08\x03\x02\x46" + _encode_varint(len(inner)) + inner + b"\x80"
        return b"\x01\x51" + c + struct.pack("<IIIHBBH", 0, 1, sn, 64, 0, 0, len(body)) + body

    conv2 = b"\x11\x22\x33\x44"
    conv3 = b"\x55\x66\x77\x88"
    rdr = IncrementalPcapReader()
    t0_lzw = _make_fake_lzw_uncompressed_words(b"\x70\x80")
    frames = [
        (100, _build_udp_ipv4_packet("1.2.3.4", 5007, "10.0.0.1", 40000, make_kcp_login(conv, 0, "111111"))),
        (101, _build_udp_ipv4_packet("1.2.3.4", 5007, "10.0.0.1", 40000, make_kcp_draft_chat(conv, 1, "1/draft one"))),
        # Simulate tick 0 -> 105 then full client reconnect with new conv2, SAME battleid=111111, and tick 0 replay.
        (102, _build_udp_ipv4_packet("1.2.3.4", 5007, "10.0.0.1", 40000, _make_030146_lzw_packet(conv, 0, t0_lzw))),
        (103, _build_udp_ipv4_packet("1.2.3.4", 5007, "10.0.0.1", 40000, _make_030146_lzw_packet(conv, 105, t0_lzw))),
        (104, _build_udp_ipv4_packet("1.2.3.4", 5007, "10.0.0.1", 40000, make_kcp_login(conv2, 0, "111111"))),
        (105, _build_udp_ipv4_packet("1.2.3.4", 5007, "10.0.0.1", 40000, _make_030146_lzw_packet(conv2, 0, t0_lzw))),
        # Rule (a): different battleid on same ip:port -> Match 2.
        (120, _build_udp_ipv4_packet("1.2.3.4", 5007, "10.0.0.1", 40000, make_kcp_login(conv3, 0, "222222"))),
        (121, _build_udp_ipv4_packet("1.2.3.4", 5007, "10.0.0.1", 40000, _make_030146_lzw_packet(conv3, 0, t0_lzw))),
        # Rule (c): draft 03 02 after BATTLE on same ip:port -> Match 3.
        (130, _build_udp_ipv4_packet("1.2.3.4", 5007, "10.0.0.1", 40000, make_kcp_draft_chat(conv3, 1, "1/draft three"))),
        (131, _build_udp_ipv4_packet("1.2.3.4", 5007, "10.0.0.1", 40000, _make_030146_lzw_packet(conv3, 105, t0_lzw))),
        # Rule (d): tick == 0 after >15s idle with max_tick > 100 -> Match 4.
        (160, _build_udp_ipv4_packet("1.2.3.4", 5007, "10.0.0.1", 40000, _make_030146_lzw_packet(conv3, 0, t0_lzw))),
    ]
    raw = _pcap_header(LINKTYPE_RAW) + b"".join(_pcap_record(t, 0, f) for t, f in frames)
    for pkt in rdr.feed(raw):
        r.on_packet(pkt)

    ms = s.get_matches()
    assert len(ms) == 4
    assert ms[0].battle_id == "111111"
    assert ms[0].battle.session_reset_count == 1
    assert ms[1].battle_id == "222222"
    assert [ev.raw_text for ev in ms[2].events] == ["1/draft three"]


@needs_captures
def test_8_chunked_partial_read_fuzz_and_linktypes() -> None:
    rng = random.Random(20261126)
    for fname in ("draft_CHAT4.pcap", "live_chat_check.pcap"):
        data = (CAPTURES_DIR / fname).read_bytes()
        whole_store, _, whole_rdr = _decode_pcap_whole(CAPTURES_DIR / fname)

        chunk_store = MatchStore()
        chunk_router = SessionRouter(
            store=chunk_store,
            templates=TemplateResolver(REPO_ROOT / "data" / "__missing__.json"),
        )
        chunk_rdr = IncrementalPcapReader()
        off = 0
        while off < len(data):
            step = rng.randint(1, 37)
            for pkt in chunk_rdr.feed(data[off : off + step]):
                chunk_router.on_packet(pkt, skipped_truncated=chunk_rdr.skipped_truncated)
            off += step

        assert chunk_rdr.skipped_truncated == whole_rdr.skipped_truncated
        assert chunk_store.get_matches_snapshot() == whole_store.get_matches_snapshot()

    # Invalid magic raises immediately on first 4 bytes.
    bad_rdr = IncrementalPcapReader()
    with pytest.raises(InvalidPcapMagicError):
        bad_rdr.feed(b"su: permission denied\n")

    # Truncated orig_len > incl_len is skipped across all 4 link types.
    for lt in (LINKTYPE_RAW, LINKTYPE_ETHERNET, LINKTYPE_SLL, LINKTYPE_SLL2):
        ip_pkt = _build_udp_ipv4_packet("10.1.1.1", 5007, "10.1.1.2", 45000, b"\x01\x75\x00\x00\x00\x00\x00\x00")
        frame = _wrap_link_frame(lt, ip_pkt)
        stream = _pcap_header(lt) + _pcap_record(1, 500, frame, orig_len=len(frame) + 20) + _pcap_record(2, 500, frame)
        rdr = IncrementalPcapReader()
        pkts = rdr.feed(stream)
        assert rdr.skipped_truncated == 1
        assert len(pkts) == 1
        assert pkts[0].sport == 5007
        assert pkts[0].payload == b"\x01\x75\x00\x00\x00\x00\x00\x00"


@needs_captures
def test_9_http_sse_integration_templates_and_fallback(tmp_path: Path) -> None:
    # Verify loopback guard.
    assert validate_loopback_host("127.0.0.1") == "127.0.0.1"
    with pytest.raises(ValueError):
        validate_loopback_host("0.0.0.0")

    # Verify template JSON expansion + raw fallback.
    tmpl_file = tmp_path / "chat_templates.json"
    tmpl_file.write_text(
        json.dumps(
            {
                "messages": {"48273": "Request backup", "154830": "Attack Lord", "2": "Gather"},
                "heroes": {"133": "Kaja", "88": "Claude"},
                "strings": {"11010": "Ban {hero}"},
            }
        ),
        encoding="utf-8",
    )
    tr = TemplateResolver(tmpl_file)
    assert tr.format_text("1/hello") == ("hello", False)
    assert tr.format_text("8/48273/0") == ("Request backup", True)
    assert tr.format_text("3/11010/88") == ("Ban Claude", True)
    assert tr.format_text("5/6/133") == ("Suggest Kaja", True)
    assert tr.format_text("7/999999/8") == ("7/999999/8", True)

    # Verify outbound 0x44c fallback resolves CAMP 1/CAMP 2 -> SELF/ENEMY when mid=1001/1202 absent.
    store_fb = MatchStore()
    router_fb = SessionRouter(store=store_fb, templates=tr)
    conv = b"\x11\x22\x33\x44"
    out_sub = b"\x70\x00\xcc\x08\x01\x01\x45\x10\x70\x71\x01\x06\x43\x0a\x70\x00\x02\x41\x04ping\x80\x80"
    out_chat = b"\x01\x75" + conv + struct.pack("<H", len(out_sub)) + out_sub
    in_chat_body1 = b"\x70\x00\x02\x41\x04ping\x4b\x0d123-4567-9999\x80"
    in_chat_body2 = b"\x70\x00\x03\x41\x03yo!\x4b\x0d123-7654-9999\x80"
    raw_tick0 = b"\x70\x51\x01\x70\x00\x22\x01\x06\x43" + _encode_varint(len(in_chat_body2)) + in_chat_body2 + b"\x80\x80"
    raw_tick1 = b"\x70\x51\x01\x70\x00\x11\x01\x06\x43" + _encode_varint(len(in_chat_body1)) + in_chat_body1 + b"\x80\x80"

    enc_table: dict[bytes, int] = {bytes([i]): i for i in range(256)}
    enc_next = 0x0101

    def encode_lzw_seq(raw_bytes: bytes) -> bytes:
        nonlocal enc_next
        codes: list[int] = []
        cur = b""
        for b in raw_bytes:
            nxt = cur + bytes([b])
            if nxt in enc_table:
                cur = nxt
            else:
                codes.append(enc_table[cur])
                if enc_next < 0x4000:
                    enc_table[nxt] = enc_next
                    enc_next += 1
                cur = bytes([b])
        if cur:
            codes.append(enc_table[cur])
        return b"".join(c.to_bytes(2, "big") for c in codes)

    p0 = _build_udp_ipv4_packet("5.5.5.5", 5007, "10.0.0.1", 40001, _make_030146_lzw_packet(conv, 0, encode_lzw_seq(raw_tick0)))
    p1 = _build_udp_ipv4_packet("10.0.0.1", 40001, "5.5.5.5", 5007, out_chat)
    p2 = _build_udp_ipv4_packet("5.5.5.5", 5007, "10.0.0.1", 40001, _make_030146_lzw_packet(conv, 1, encode_lzw_seq(raw_tick1)))
    rdr_fb = IncrementalPcapReader()
    for u in rdr_fb.feed(_pcap_header(LINKTYPE_RAW) + _pcap_record(10, 0, p0) + _pcap_record(11, 0, p1) + _pcap_record(11, 100, p2)):
        router_fb.on_packet(u)
    m_fb = store_fb.get_matches()[0]
    assert m_fb.local_camp == 1
    assert m_fb.local_uid == 4567
    # First event arrived as CAMP 2 before outbound 0x44c; retroactive refresh turns it into ENEMY!
    assert [ev.side for ev in m_fb.events] == ["ENEMY", "SELF"]

    # Starlette HTTP/SSE integration test + Last-Event-ID replay.
    app = create_app(
        captures_dir=CAPTURES_DIR,
        templates_path=tmpl_file,
        history_dir=tmp_path / "hist",
        heartbeat_interval=0.2,
        auto_scan_history=False,
    )
    with TestClient(app) as client:
        r_home = client.get("/")
        assert r_home.status_code == 200
        assert "MLBB Passive Chat Viewer" in r_home.text
        assert "EventSource" in r_home.text

        r_pcaps = client.get("/api/pcaps")
        assert r_pcaps.status_code == 200
        names = [x["name"] for x in r_pcaps.json()["pcaps"]]
        assert "draft_CHAT4.pcap" in names

        r_src = client.post(
            "/api/source",
            json={"mode": "pcap", "path": str(CAPTURES_DIR / "draft_CHAT4.pcap"), "follow": False},
        )
        assert r_src.status_code == 200

        # Wait briefly for background replay thread to finish.
        deadline = time.monotonic() + 10.0
        matches_json = []
        while time.monotonic() < deadline:
            r_m = client.get("/api/matches")
            assert r_m.status_code == 200
            body = r_m.json()
            matches_json = body["matches"]
            if matches_json and len(matches_json[0]["events"]) == 33 and not body["status"]["capture_alive"]:
                break
            time.sleep(0.05)

        assert len(matches_json) == 1
        assert len(matches_json[0]["events"]) == 33

        def _parse_sse_frames(body: str) -> list[tuple[int, str, dict]]:
            frames_out: list[tuple[int, str, dict]] = []
            cur_id = 0
            cur_ev = ""
            for line in body.splitlines():
                if line.startswith("id: "):
                    cur_id = int(line[4:])
                elif line.startswith("event: "):
                    cur_ev = line[7:]
                elif line.startswith("data: "):
                    frames_out.append((cur_id, cur_ev, json.loads(line[6:])))
            return frames_out

        # Check SSE headers, initial snapshot, and heartbeat.
        r_sse = client.get("/events?max_events=2")
        assert r_sse.status_code == 200
        assert "text/event-stream" in r_sse.headers["content-type"]
        assert r_sse.headers.get("cache-control") == "no-cache"
        assert r_sse.headers.get("x-accel-buffering") == "no"
        seen_events = _parse_sse_frames(r_sse.text)
        assert len(seen_events) == 2
        assert seen_events[0][1] == "snapshot"
        assert seen_events[1][1] == "status"
        assert seen_events[1][0] > seen_events[0][0]

        # Test Last-Event-ID replay from RAM after publishing a new chat event via follow file.
        growing = tmp_path / "follow.pcap"
        growing.write_bytes(_pcap_header(LINKTYPE_RAW) + _pcap_record(10, 0, p0))
        r_follow = client.post("/api/source", json={"mode": "pcap", "path": str(growing), "follow": True})
        assert r_follow.status_code == 200

        # Wait until initial tick 0 event from follow.pcap has been ingested before taking baseline id.
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            ms_init = client.get("/api/matches").json()["matches"]
            if ms_init and len(ms_init[0]["events"]) >= 1:
                break
            time.sleep(0.05)

        first_frames = _parse_sse_frames(client.get("/events?once=1").text)
        assert first_frames
        first_id = first_frames[-1][0]

        # Append outbound + inbound chat while SSE client is disconnected.
        with growing.open("ab") as fh:
            fh.write(_pcap_record(11, 0, p1))
            fh.write(_pcap_record(11, 100, p2))

        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            ms_now = client.get("/api/matches").json()["matches"]
            if ms_now and len(ms_now[0]["events"]) >= 2:
                break
            time.sleep(0.05)

        r_replay = client.get("/events?once=1", headers={"Last-Event-ID": str(first_id)})
        assert r_replay.status_code == 200
        replayed = _parse_sse_frames(r_replay.text)

        replayed_chats = [d for _, ev_name, d in replayed if ev_name == "chat"]
        assert any(c["raw_text"] == "ping" and c["side"] == "SELF" for c in replayed_chats)
        assert replayed[-1][1] == "status"
        assert all(eid > first_id for eid, _, _ in replayed)
        assert [eid for eid, _, _ in replayed] == sorted(eid for eid, _, _ in replayed)

        stop_res = client.post("/api/source", json={"mode": "stop"})
        assert stop_res.status_code == 200
        assert stop_res.json()["status"]["source_detail"] == ""


@needs_captures
def test_10_past_games_history_cache_and_api(tmp_path: Path) -> None:
    caps_dir = tmp_path / "caps"
    hist_dir = tmp_path / "hist"
    caps_dir.mkdir()

    shutil.copyfile(CAPTURES_DIR / "draft_CHAT4.pcap", caps_dir / "draft_CHAT4.pcap")
    shutil.copyfile(CAPTURES_DIR / "live_chat_check.pcap", caps_dir / "live_chat_check.pcap")

    # Also drop an empty non-chat UDP capture (>100 B) to verify include_empty filtering.
    empty_pkt = _build_udp_ipv4_packet("10.0.0.2", 5009, "10.0.0.1", 41000, b"\x01\x75\x11\x22\x33\x44\x04\x00\x70\x00\x00\x80")
    (caps_dir / "empty_probe.pcap").write_bytes(
        _pcap_header(LINKTYPE_RAW) + _pcap_record(1, 0, empty_pkt) + _pcap_record(2, 0, empty_pkt)
    )

    tr = TemplateResolver(tmp_path / "__missing__.json")
    hist = MatchHistoryStore(captures_dir=caps_dir, history_dir=hist_dir, templates=tr)
    hist.start_background_scan()
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        listing = hist.list_games(include_empty=True)
        if not listing["scan"]["scanning"] and listing["scan"]["done"] >= 3:
            break
        time.sleep(0.05)

    with_chat = hist.list_games(include_empty=False)
    assert with_chat["total_with_chat"] == 1
    assert with_chat["total_all"] == 3
    g_sum = with_chat["games"][0]
    assert g_sum["game_id"] == "pcap:draft_CHAT4.pcap:m1"
    assert g_sum["enemy_team_count"] == 5
    assert g_sum["typed_count"] == 24
    assert g_sum["quickchat_count"] == 9
    assert g_sum["ally_players"] == ["naradira"]
    assert g_sum["enemy_players"] == ["E1dreda."]
    assert "team rex" in g_sum["preview"]

    all_caps = hist.list_games(include_empty=True)
    assert any(g["game_id"] == "pcap:live_chat_check.pcap:m1" and g["has_gaps"] for g in all_caps["games"])

    full_game = hist.get_game("pcap:draft_CHAT4.pcap:m1")
    assert full_game is not None
    assert len(full_game["events"]) == 33
    assert len(full_game["players"]) == 2

    # Second instance loads cached games instantaneously without rescanning.
    hist_reloaded = MatchHistoryStore(captures_dir=caps_dir, history_dir=hist_dir, templates=tr)
    assert hist_reloaded.list_games(include_empty=False)["total_with_chat"] == 1

    # HTTP /api/history + live save/delete checks via TestClient.
    app = create_app(
        captures_dir=caps_dir,
        history_dir=hist_dir,
        templates_path=tmp_path / "__missing__.json",
        auto_scan_history=True,
    )
    with TestClient(app) as client:
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            r_h = client.get("/api/history")
            if not r_h.json()["scan"]["scanning"] and r_h.json()["total_with_chat"] >= 1:
                break
            time.sleep(0.05)

        r_h = client.get("/api/history?include_empty=0")
        assert r_h.status_code == 200
        assert r_h.json()["total_with_chat"] == 1

        r_g = client.get("/api/history/pcap:draft_CHAT4.pcap:m1")
        assert r_g.status_code == 200
        assert len(r_g.json()["events"]) == 33

        assert client.get("/api/history/pcap:missing.pcap:m1").status_code == 404
        assert client.delete("/api/history/pcap:draft_CHAT4.pcap:m1").status_code == 400

        # Following an external capture (simulating tee=False live capture) saves a live game upon stop and allows deletion.
        external_live = tmp_path / "external_live.pcap"
        shutil.copyfile(CAPTURES_DIR / "draft_DRAFT.pcap", external_live)
        ext_store, _, _ = _decode_pcap_whole(external_live)
        ext_matches = ext_store.get_matches()
        assert ext_matches and ext_matches[0].battle_id
        expected_live_events = len(ext_matches[0].events)
        expected_live_gid = f"live:{ext_matches[0].battle_id}"

        r_follow = client.post(
            "/api/source",
            json={"mode": "pcap", "path": str(external_live), "follow": True},
        )
        assert r_follow.status_code == 200
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            ms = client.get("/api/matches").json()["matches"]
            if ms and len(ms[0]["events"]) == expected_live_events:
                break
            time.sleep(0.05)

        r_stop = client.post("/api/source", json={"mode": "stop"})
        assert r_stop.status_code == 200
        assert r_stop.json()["status"]["source_detail"] == ""

        live_games = [g for g in client.get("/api/history").json()["games"] if g["origin"] == "live"]
        assert len(live_games) == 1
        live_gid = live_games[0]["game_id"]
        assert live_gid == expected_live_gid

        assert client.delete(f"/api/history/{live_gid}").status_code == 200
        assert client.delete(f"/api/history/{live_gid}").status_code == 404
        assert all(g["game_id"] != live_gid for g in client.get("/api/history").json()["games"])


@needs_captures
def test_11_draft_live6_ev45_swap_and_attribution() -> None:
    store, _, _ = _decode_pcap_whole(CAPTURES_DIR / "draft_LIVE6.pcap")
    matches = store.get_matches()
    assert len(matches) == 2

    m1, m2 = matches
    # Match 1 (ep 5507): uid=338471731 (d., pos 9 -> 0x23) swaps with uid=389466225 (Rambutan., pos 7 -> 0x21).
    assert m1.battle_id == "704578279919062684"
    assert m1.attribution_frozen is True
    assert m1.frozen_at_tick == 0
    assert m1.anomalies == []
    assert len(m1.swap_history) == 1
    assert m1.slot_to_uid[0x21] == 338471731
    assert m1.slot_to_uid[0x23] == 389466225
    assert m1.players_by_uid[338471731].slot == 0x21
    assert m1.players_by_uid[389466225].slot == 0x23

    m1_checks = [(ev.phase, ev.slot, ev.raw_text, ev.sender_uid, ev.sender_name) for ev in m1.events]
    assert ("draft", 0x23, "5/6/133", 338471731, "d.") in m1_checks
    assert ("draft", 0x23, "5/6/122", 338471731, "d.") in m1_checks
    assert ("draft", 0x21, "7/31471/9", 338471731, "d.") in m1_checks
    assert ("draft", 0x23, "1/Last game", 389466225, "Rambutan.") in m1_checks

    # Match 2 (ep 5503): uid=88409820 (ame., pos 4 -> 0x13) swaps with uid=1382063784 (ʀʌᴠɪᴏʟɪ, pos 3 -> 0x12).
    assert m2.battle_id == "705721359695090677"
    assert m2.attribution_frozen is True
    assert m2.anomalies == []
    assert len(m2.swap_history) == 1
    assert m2.slot_to_uid[0x12] == 88409820
    assert m2.slot_to_uid[0x13] == 1382063784
    assert m2.players_by_uid[88409820].slot == 0x12
    assert m2.players_by_uid[1382063784].slot == 0x13

    m2_checks = [(ev.phase, ev.slot, ev.raw_text, ev.sender_uid, ev.sender_name) for ev in m2.events]
    assert ("draft", 0x12, "1/I was changing song", 1382063784, "ʀʌᴠɪᴏʟɪ") in m2_checks
    assert ("draft", 0x12, "5/6/131", 1382063784, "ʀʌᴠɪᴏʟɪ") in m2_checks
    assert ("draft", 0x13, "5/6/129", 88409820, "ame.") in m2_checks
    assert ("draft", 0x12, "7/31471/4", 88409820, "ame.") in m2_checks
    assert ("draft", 0x13, "1/huh I picked jul what", 1382063784, "ʀʌᴠɪᴏʟɪ") in m2_checks
    assert ("battle", 0x13, "kal long u", 1382063784, "ʀʌᴠɪᴏʟɪ") in m2_checks


def test_12_ev45_edge_cases_freeze_mismatch_and_kcp_fragment_guard() -> None:
    def make_kcp_seg(conv: bytes, sn: int, body: bytes, frg: int = 0) -> bytes:
        return b"\x01\x51" + conv + struct.pack("<IIIHBBH", 0, 1, sn, 64, frg, 0, len(body)) + body

    def make_1202(players: list[tuple[int, int, int, str]]) -> bytes:
        items = []
        for uid, camp, seat, name in sorted(players, key=lambda x: x[0]):  # UID-sorted, not seat-sorted!
            nb = name.encode("utf-8")
            items.append(
                b"\x70\x00"
                + _encode_varint(uid)
                + b"\x01"
                + _encode_varint(camp)
                + b"\x02"
                + _encode_varint(seat)
                + b"\x43"
                + _encode_varint(len(nb))
                + nb
                + b"\x80"
            )
        return b"\x70\x00\xb2\x09\x70\x50" + _encode_varint(len(items)) + b"".join(items) + b"\x80"

    def make_1101(sub_items: list[bytes], phase_byte: int = 0x02) -> bytes:
        inner = b"\x70\x51" + _encode_varint(len(sub_items)) + b"".join(sub_items) + b"\x80"
        return b"\x70\x00\xcd\x08\x03" + bytes([phase_byte]) + b"\x46" + _encode_varint(len(inner)) + inner + b"\x80"

    def make_ev45_item(req_uid: int, hero_id: int, req_pos: int, ack_uid: int, ack_pos: int) -> bytes:
        body = (
            b"\x70\x00"
            + _encode_varint(req_uid)
            + b"\x01"
            + _encode_varint(hero_id)
            + b"\x02"
            + _encode_varint(req_pos)
            + b"\x03"
            + _encode_varint(ack_uid)
            + b"\x04"
            + _encode_varint(ack_pos)
            + b"\x80"
        )
        return b"\x70\x00" + _encode_varint(ack_uid) + b"\x01\x45\x43" + _encode_varint(len(body)) + body + b"\x80"

    def make_ev06_item(slot: int, ch: int, text: str, msg_uid: str = "") -> bytes:
        tb = text.encode("utf-8")
        cb = b"\x70\x00" + _encode_varint(ch) + b"\x41" + _encode_varint(len(tb)) + tb
        if msg_uid:
            mb = msg_uid.encode("utf-8")
            cb += b"\x4b" + _encode_varint(len(mb)) + mb
        cb += b"\x80"
        return b"\x70\x00" + _encode_varint(slot) + b"\x01\x06\x43" + _encode_varint(len(cb)) + cb + b"\x80"

    def feed_pkt(router: SessionRouter, ts: float, payload: bytes) -> None:
        raw = _pcap_header(LINKTYPE_RAW) + _pcap_record(
            int(ts), 0, _build_udp_ipv4_packet("2.2.2.2", 5507, "10.0.0.1", 40000, payload)
        )
        rdr = IncrementalPcapReader()
        for pkt in rdr.feed(raw):
            router.on_packet(pkt)

    store = MatchStore()
    router = SessionRouter(store=store, templates=TemplateResolver(REPO_ROOT / "data" / "__missing__.json"))
    conv = b"\xaa\xbb\xcc\x01"

    # 1) Send UID-sorted mid=1202 (uid=200 at camp=2,seat=3; uid=300 at camp=2,seat=1).
    feed_pkt(
        router,
        10.0,
        make_kcp_seg(conv, 0, make_1202([(300, 2, 1, "Alice"), (200, 2, 3, "Bob"), (100, 1, 0, "Self")])),
    )
    sess = store.get_matches()[0]
    assert sess.slot_to_uid[0x21] == 300
    assert sess.slot_to_uid[0x23] == 200

    # 2) Fragmented KCP ev=0x45 guard: sn=2 (frg=1) then sn=3 (frg=0) with sn=1 missing must NOT apply swap.
    swap_1101 = make_1101([make_ev45_item(req_uid=200, hero_id=122, req_pos=9, ack_uid=300, ack_pos=7)])
    mid = len(swap_1101) // 2
    feed_pkt(router, 11.0, make_kcp_seg(conv, 2, swap_1101[:mid], frg=1))
    assert sess.slot_to_uid[0x21] == 300
    assert sess.slot_to_uid[0x23] == 200
    feed_pkt(router, 12.0, make_kcp_seg(conv, 3, swap_1101[mid:], frg=0))
    assert sess.slot_to_uid[0x21] == 300
    assert sess.slot_to_uid[0x23] == 200
    assert sess.swap_history == []

    # Truncated cd 08 packet must also be ignored safely.
    feed_pkt(router, 12.5, make_kcp_seg(conv, 4, swap_1101[:-3], frg=0))
    assert sess.slot_to_uid[0x21] == 300
    assert sess.swap_history == []

    # Once sn=1 (frg=0) arrives to establish the leading fragment boundary, sn=2..3 drains and swaps!
    noop_1101 = make_1101([])
    feed_pkt(router, 13.0, make_kcp_seg(conv, 1, noop_1101, frg=0))
    assert sess.slot_to_uid[0x21] == 200
    assert sess.slot_to_uid[0x23] == 300
    assert len(sess.swap_history) == 1

    # Duplicate ev=0x45 in a distinct KCP packet is idempotent (does not undo or duplicate swap).
    feed_pkt(router, 14.0, make_kcp_seg(conv, 5, make_1101([make_ev45_item(200, 122, 9, 300, 7)]), frg=0))
    assert sess.slot_to_uid[0x21] == 200
    assert sess.slot_to_uid[0x23] == 300
    assert len(sess.swap_history) == 1

    # 3) Pre-freeze self-correcting ev=0x06 check overrides slot_to_uid and logs mismatch anomaly.
    feed_pkt(
        router,
        15.0,
        make_kcp_seg(conv, 6, make_1101([make_ev06_item(0x21, 4, "1/override", "555-300-1")]), frg=0),
    )
    assert sess.slot_to_uid[0x21] == 300
    assert any(a["kind"] == "slot_uid_mismatch" and a["expected_uid"] == 200 and a["actual_uid"] == 300 for a in sess.anomalies)
    feed_pkt(router, 16.0, make_kcp_seg(conv, 7, make_1101([make_ev06_item(0x21, 4, "5/6/122")]), frg=0))
    assert sess.events[-1].sender_uid == 300

    # 4) Freeze at battle start (tick 0): swaps and mismatches after tick 0 must NOT alter roster!
    enc_table: dict[bytes, int] = {bytes([i]): i for i in range(256)}
    enc_next = 0x0101

    def enc_tick(raw_data: bytes) -> bytes:
        nonlocal enc_next
        codes: list[int] = []
        cur = b""
        for b in raw_data:
            nxt = cur + bytes([b])
            if nxt in enc_table:
                cur = nxt
            else:
                codes.append(enc_table[cur])
                if enc_next < 0x4000:
                    enc_table[nxt] = enc_next
                    enc_next += 1
                cur = bytes([b])
        if cur:
            codes.append(table_get := enc_table[cur])
            _ = table_get
        return b"".join(c.to_bytes(2, "big") for c in codes)

    feed_pkt(router, 20.0, _make_030146_lzw_packet(conv, 0, enc_tick(b"\x70\x80")))
    assert sess.attribution_frozen is True
    assert sess.frozen_at_tick == 0

    # Post-freeze ev=0x45 in battle tick must record post_freeze_swap anomaly and leave 0x21 -> 300 untouched.
    post_swap_tick = b"\x70\x51\x01" + make_ev45_item(300, 122, 7, 200, 9) + b"\x80"
    feed_pkt(router, 21.0, _make_030146_lzw_packet(conv, 1, enc_tick(post_swap_tick)))
    assert sess.slot_to_uid[0x21] == 300
    assert any(a["kind"] == "post_freeze_swap" and a["tick"] == 1 for a in sess.anomalies)

    # Post-freeze ev=0x06 mismatch records anomaly, tags that ChatEvent with msg_uid, and keeps roster frozen.
    post_chat_tick = b"\x70\x51\x01" + make_ev06_item(0x21, 2, "hi", "555-200-99") + b"\x80"
    feed_pkt(router, 22.0, _make_030146_lzw_packet(conv, 2, enc_tick(post_chat_tick)))
    assert sess.slot_to_uid[0x21] == 300
    assert sess.events[-1].sender_uid == 200
    assert any(a["kind"] == "slot_uid_mismatch" and a["frozen"] is True and a["tick"] == 2 for a in sess.anomalies)


def test_13_real_chat_templates_resolution(tmp_path: Path) -> None:
    sample_file = tmp_path / "chat_templates.json"
    sample_file.write_text(
        json.dumps(
            {
                "messages": {
                    "2/0": "I'll go Mid Lane.",
                    "2/2": "I'll roam.",
                    "2/3": "I'll Jungle.",
                    "2/9": "I'll go Exp Lane.",
                    "2/16": "We got this!",
                    "4": "I want to go {lane}",
                    "4_hero": "I want to use {hero} to go to {lane}.",
                    "5/3": "I'm {0} and I want to use {1}.",
                    "5/3_notitle": "I want to use {2}. My current Hero Power is {1}.",
                    "5/5": "I want to use {hero}. {1}, {2}",
                    "5/6": "I want to use {hero}.",
                    "5/7": "Got MVP using {0} in the last match, with a score of {1}/{2}/{3}.",
                    "7/31471": "Thank you! Victory is ours! @{0}",
                    "7/31684": "A balanced lineup! We got this!",
                    "7/154830": "Thanks, well done! @{0}",
                    "8/48273": "Which hero should we ban?",
                    "12/40200": "[Emote] Genius!",
                    "12/40677": "[Emote] Hahaha!",
                    "12/40724": "[Emote] realmeow M7",
                },
                "heroes": {
                    "17": {"name": "Fanny", "role": "Assassin"},
                    "55": {"name": "Angela", "role": "Support"},
                    "88": {"name": "Masha", "role": "Fighter/Tank"},
                    "114": {"name": "Melissa", "role": "Marksman"},
                    "126": {"name": "Suyou", "role": "Assassin/Fighter"},
                    "133": {"name": "Hirara", "role": "Assassin"},
                },
                "strings": {
                    "11010": "Ban {hero} ({role})",
                },
                "lanes": {
                    "1": "Exp Lane",
                    "2": "Mid Lane",
                    "3": "Roaming",
                    "4": "Jungling",
                    "5": "Gold Lane",
                },
            }
        ),
        encoding="utf-8",
    )
    tr = TemplateResolver(sample_file)
    assert tr.format_text("3/11010/88") == ("Ban Masha (Fighter/Tank)", True)
    assert tr.format_text("5/6/133") == ("I want to use Hirara.", True)
    assert tr.format_text("5/5/3842/5265/17") == ("I want to use Fanny. Matches: 5265, Win Rate: 73.0%", True)
    assert tr.format_text("5/7/4/22/1/5/133") == (
        "Got MVP using Hirara in the last match, with a score of 22/1/5.",
        True,
    )
    assert tr.format_text("5/3/Global No.64 Suyou/10557/206/126|4/5/126") == (
        "I'm Global No.64 Suyou and I want to use Suyou.",
        True,
    )
    assert tr.format_text("5/3//1250/0/114|4/4/114") == (
        "I want to use Melissa. My current Hero Power is 1250.",
        True,
    )
    assert tr.format_text("7/31471/4") == ("Thank you! Victory is ours! @4", True)
    assert tr.format_text("7/154830/ 8") == ("Thanks, well done! @8", True)
    assert tr.format_text("7/31684") == ("A balanced lineup! We got this!", True)
    assert tr.format_text("8/48273/0") == ("Which hero should we ban?", True)
    assert tr.format_text("12/40200") == ("[Emote] Genius!", True)
    assert tr.format_text("12/40677") == ("[Emote] Hahaha!", True)
    assert tr.format_text("2/0", channel=1) == ("I'll go Mid Lane.", True)
    assert tr.format_text("2/0", channel=10) == ("2/0", True)
    assert tr.format_text("2/2", channel=4) == ("I'll roam.", True)
    assert tr.format_text("2/3", channel=4) == ("I'll Jungle.", True)
    assert tr.format_text("2/9", channel=1) == ("I'll go Exp Lane.", True)
    assert tr.format_text("4/3", channel=1) == ("I want to go Roaming", True)
    assert tr.format_text("4/1", channel=1) == ("I want to go Exp Lane", True)
    assert tr.format_text("4/5", channel=1) == ("I want to go Gold Lane", True)
    assert tr.format_text("4/3/55", channel=1) == ("I want to use Angela to go to Roaming.", True)
    assert tr.format_text("5/47544373") == ("5/47544373", True)

    real_tmpl = REPO_ROOT / "data" / "chat_templates.json"
    if real_tmpl.is_file():
        for cap_name in ("draft_LIVE6.pcap", "draft_DRAFT.pcap", "draft_CHAT4.pcap"):
            store, _, _ = _decode_pcap_whole(CAPTURES_DIR / cap_name, templates_path=real_tmpl)
            for sess in store.get_matches():
                for ev in sess.events:
                    if ev.is_template and not (ev.channel == 10 and ev.raw_text == "2/0"):
                        assert ev.display_text != ev.raw_text, f"{cap_name}: unexpanded {ev.raw_text!r}"
                        assert "[-]" not in ev.display_text
                        assert "[f6d57f]" not in ev.display_text

        live_cap = CAPTURES_DIR / "live_20261126_234439.pcap"
        if live_cap.is_file():
            store_live, _, _ = _decode_pcap_whole(live_cap, templates_path=real_tmpl)
            evs_live = [(ev.sender_name, ev.channel, ev.raw_text, ev.display_text) for s in store_live.get_matches() for ev in s.events]
            assert ("mashasha", 1, "2/9", "I'll go Exp Lane.") in evs_live
            assert ("Chudvial999", 1, "4/3", "I want to go Roaming") in evs_live
            ch10_20 = [ev for ev in evs_live if ev[1] == 10 and ev[2] == "2/0"]
            assert ch10_20 and all(ev[3] == "2/0" for ev in ch10_20)


@needs_captures
def test_14_hero_pick_tracking_live_swap_and_1203(tmp_path: Path) -> None:
    def make_kcp_seg(conv: bytes, sn: int, body: bytes, frg: int = 0) -> bytes:
        return b"\x01\x51" + conv + struct.pack("<IIIHBBH", 0, 1, sn, 64, frg, 0, len(body)) + body

    def make_roster_msg(mid: int, players: list[tuple[int, int, int, str, int | None]]) -> bytes:
        items = []
        for uid, camp, seat, name, hero_id in sorted(players, key=lambda x: x[0]):
            nb = name.encode("utf-8")
            item = (
                b"\x70\x00"
                + _encode_varint(uid)
                + b"\x01"
                + _encode_varint(camp)
                + b"\x02"
                + _encode_varint(seat)
                + b"\x43"
                + _encode_varint(len(nb))
                + nb
            )
            if hero_id is not None:
                item += b"\x07" + _encode_varint(hero_id)
            item += b"\x80"
            items.append(item)
        return b"\x70\x00" + _encode_varint(mid) + b"\x70\x50" + _encode_varint(len(items)) + b"".join(items) + b"\x80"

    def make_1101(sub_items: list[bytes], phase_byte: int = 0x02) -> bytes:
        inner = b"\x70\x51" + _encode_varint(len(sub_items)) + b"".join(sub_items) + b"\x80"
        return b"\x70\x00\xcd\x08\x03" + bytes([phase_byte]) + b"\x46" + _encode_varint(len(inner)) + inner + b"\x80"

    def make_ev33_hover(uid: int, hero_id: int) -> bytes:
        body = b"\x70\x00" + _encode_varint(hero_id) + b"\x80"
        return b"\x70\x00" + _encode_varint(uid) + b"\x01\x33\x43" + _encode_varint(len(body)) + body + b"\x80"

    def make_ev34_confirm(uid: int, hero_id: int) -> bytes:
        body = b"\x70\x00" + _encode_varint(hero_id) + b"\x80"
        return b"\x70\x00" + _encode_varint(uid) + b"\x01\x34\x43" + _encode_varint(len(body)) + body + b"\x80"

    def make_ev45_item(req_uid: int, hero_id: int, req_pos: int, ack_uid: int, ack_pos: int) -> bytes:
        body = (
            b"\x70\x00"
            + _encode_varint(req_uid)
            + b"\x01"
            + _encode_varint(hero_id)
            + b"\x02"
            + _encode_varint(req_pos)
            + b"\x03"
            + _encode_varint(ack_uid)
            + b"\x04"
            + _encode_varint(ack_pos)
            + b"\x80"
        )
        return b"\x70\x00" + _encode_varint(ack_uid) + b"\x01\x45\x43" + _encode_varint(len(body)) + body + b"\x80"

    def make_ev06_item(slot: int, ch: int, text: str, msg_uid: str = "") -> bytes:
        tb = text.encode("utf-8")
        cb = b"\x70\x00" + _encode_varint(ch) + b"\x41" + _encode_varint(len(tb)) + tb
        if msg_uid:
            mb = msg_uid.encode("utf-8")
            cb += b"\x4b" + _encode_varint(len(mb)) + mb
        cb += b"\x80"
        return b"\x70\x00" + _encode_varint(slot) + b"\x01\x06\x43" + _encode_varint(len(cb)) + cb + b"\x80"

    def feed_pkt(router: SessionRouter, ts: float, payload: bytes, *, direction: str = "in") -> None:
        if direction == "out":
            pkt_bytes = _build_udp_ipv4_packet("10.0.0.1", 40000, "2.2.2.2", 5509, payload)
        else:
            pkt_bytes = _build_udp_ipv4_packet("2.2.2.2", 5509, "10.0.0.1", 40000, payload)
        rdr = IncrementalPcapReader()
        for pkt in rdr.feed(_pcap_header(LINKTYPE_RAW) + _pcap_record(int(ts), 0, pkt_bytes)):
            router.on_packet(pkt)

    tmpl_file = tmp_path / "heroes.json"
    tmpl_file.write_text(
        json.dumps(
            {
                "messages": {"2/9": "I'll go Exp Lane."},
                "heroes": {
                    "17": "Fanny",
                    "41": "Gatotkaca",
                    "55": "Angela",
                    "88": "Masha",
                    "122": "Nolan",
                    "129": "Zetian",
                    "131": "Sora",
                    "133": "Hirara",
                },
            }
        ),
        encoding="utf-8",
    )
    tr = TemplateResolver(tmpl_file)
    store = MatchStore()
    router = SessionRouter(store=store, templates=tr)
    conv = b"\x12\x34\x56\x78"

    # Identify local uid=1000 via outbound mid=1001, then deliver mid=1202 roster.
    out_1001 = b"\x70\x00" + _encode_varint(1001) + b"\x70\x00" + _encode_varint(1000) + b"\x80\x80"
    feed_pkt(router, 9.0, make_kcp_seg(conv, 0, out_1001), direction="out")
    feed_pkt(
        router,
        10.0,
        make_kcp_seg(conv, 0, make_roster_msg(1202, [(1000, 1, 0, "Self", None), (2000, 1, 1, "Bob", None), (3000, 1, 2, "Alice", None), (4000, 2, 0, "Foe", None)])),
    )
    sess = store.get_matches()[0]
    assert sess.players_by_uid[2000].hero_id is None
    assert sess.players_by_uid[2000].hero_name == ""

    # Chat before pick has empty sender_hero.
    feed_pkt(router, 11.0, make_kcp_seg(conv, 1, make_1101([make_ev06_item(0x11, 1, "2/9", "999-2000-1")])))
    assert sess.events[-1].sender_hero_id is None
    assert sess.events[-1].sender_hero == ""

    # Hover ev=0x33 must NOT set picked hero.
    feed_pkt(router, 12.0, make_kcp_seg(conv, 2, make_1101([make_ev33_hover(2000, 17)])))
    assert sess.players_by_uid[2000].hero_id is None

    # Confirm lock-in ev=0x34 sets hero, backfills earlier chat event, and publishes match_update.
    feed_pkt(router, 13.0, make_kcp_seg(conv, 3, make_1101([make_ev34_confirm(2000, 17)])))
    assert sess.players_by_uid[2000].hero_id == 17
    assert sess.players_by_uid[2000].hero_name == "Fanny"
    assert sess.events[0].sender_hero_id == 17
    assert sess.events[0].sender_hero == "Fanny"
    updates = [d for _, ename, d in store._replay_log if ename == "match_update"]
    assert updates
    assert any(
        p["uid"] == 2000 and p["hero_name"] == "Fanny"
        for p in updates[-1]["players"]
    )
    assert updates[-1]["events"][0]["sender_hero"] == "Fanny"

    # Alice confirms 55 (Angela), then ev=0x45 help-picks 55 for Bob and swaps slots (0x11 <-> 0x12).
    feed_pkt(router, 14.0, make_kcp_seg(conv, 4, make_1101([make_ev34_confirm(3000, 55)])))
    feed_pkt(router, 15.0, make_kcp_seg(conv, 5, make_1101([make_ev45_item(req_uid=2000, hero_id=55, req_pos=2, ack_uid=3000, ack_pos=3)])))
    assert sess.players_by_uid[2000].hero_id == 55
    assert sess.players_by_uid[2000].hero_name == "Angela"
    assert sess.events[0].sender_hero == "Angela"
    assert sess.players_by_uid[3000].hero_id is None
    assert sess.slot_to_uid[0x12] == 2000
    assert sess.slot_to_uid[0x11] == 3000

    # Alice locks 133 (Hirara); Foe auto-locks 17 without ev=0x34, reconciled via mid=1203 without undoing swapped seats!
    feed_pkt(router, 16.0, make_kcp_seg(conv, 6, make_1101([make_ev34_confirm(3000, 133)])))
    feed_pkt(
        router,
        17.0,
        make_kcp_seg(conv, 7, make_roster_msg(1203, [(1000, 1, 0, "Self", 88), (2000, 1, 1, "Bob", 55), (3000, 1, 2, "Alice", 133), (4000, 2, 0, "Foe", 17)])),
    )
    assert {u: sess.players_by_uid[u].hero_name for u in (1000, 2000, 3000, 4000)} == {
        1000: "Masha",
        2000: "Angela",
        3000: "Hirara",
        4000: "Fanny",
    }
    assert sess.slot_to_uid[0x12] == 2000
    assert sess.slot_to_uid[0x11] == 3000
    feed_pkt(router, 18.0, make_kcp_seg(conv, 8, make_1101([make_ev06_item(0x20, 3, "glhf", "999-4000-2")])))
    assert sess.events[-1].side == "ENEMY"
    assert sess.events[-1].sender_hero == "Fanny"

    # Real capture draft_LIVE6.pcap: ev=0x45 help-pick + ev=0x34 + mid=1203, zero anomalies.
    store_d6, _, _ = _decode_pcap_whole(CAPTURES_DIR / "draft_LIVE6.pcap", templates_path=tmpl_file)
    m1, m2 = store_d6.get_matches()
    assert m1.anomalies == []
    assert m1.players_by_uid[338471731].hero_name == "Nolan"
    assert m1.players_by_uid[389466225].hero_name == "Gatotkaca"
    assert any(ev.sender_uid == 338471731 and ev.sender_hero == "Nolan" for ev in m1.events)
    assert any(ev.raw_text == "1/Last game" and ev.sender_hero == "Gatotkaca" for ev in m1.events)

    assert m2.anomalies == []
    assert m2.players_by_uid[88409820].hero_name == "Zetian"
    assert m2.players_by_uid[1382063784].hero_name == "Sora"
    assert any(ev.raw_text == "kal long u" and ev.sender_hero == "Sora" for ev in m2.events)

    # Mid-match capture leaves hero fields empty cleanly.
    store_mid, _, _ = _decode_pcap_whole(CAPTURES_DIR / "live_chat_check.pcap", templates_path=tmpl_file)
    for m_mid in store_mid.get_matches():
        assert all(p.hero_id is None and p.hero_name == "" for p in m_mid.players_by_uid.values())
        assert all(ev.sender_hero_id is None and ev.sender_hero == "" for ev in m_mid.events)

    # Real full templates check on live_20261126_234439.pcap if present on disk.
    real_tmpl = REPO_ROOT / "data" / "chat_templates.json"
    live_cap = CAPTURES_DIR / "live_20261126_234439.pcap"
    if real_tmpl.is_file() and live_cap.is_file():
        store_live, _, _ = _decode_pcap_whole(live_cap, templates_path=real_tmpl)
        m_live = store_live.get_matches()[0]
        assert len(m_live.players_by_uid) == 10
        by_name = {p.name: p.hero_name for p in m_live.players_by_uid.values()}
        assert all(by_name.values())
        assert by_name["naradira"] == "Ling"
        assert by_name["mashasha"] == "Argus"
        assert by_name["Chudvial999"] == "Sun"
        assert by_name["SnowBall"] == "Angela"
        assert any(ev.sender_name == "mashasha" and ev.raw_text == "2/9" and ev.sender_hero == "Argus" for ev in m_live.events)

    # UI HTML serves hero badge styles and helper.
    app = create_app(
        captures_dir=CAPTURES_DIR,
        templates_path=tmpl_file,
        history_dir=tmp_path / "hist",
        auto_scan_history=False,
    )
    with TestClient(app) as client:
        r_home = client.get("/")
        assert r_home.status_code == 200
        assert ".hero-tag" in r_home.text
        assert ".chip-hero" in r_home.text
        assert "heroForEvent" in r_home.text


@needs_captures
def test_15_history_dedup_and_dynamic_live_updates(tmp_path: Path) -> None:
    from tools.chat_viewer.history import MatchHistoryStore, _dedup_records

    caps_dir = tmp_path / "caps"
    hist_dir = tmp_path / "hist"
    caps_dir.mkdir()
    hist_dir.mkdir()

    shutil.copyfile(CAPTURES_DIR / "draft_CHAT4.pcap", caps_dir / "draft_CHAT4.pcap")
    real_tmpl = REPO_ROOT / "data" / "chat_templates.json"
    tmpl_arg = real_tmpl if real_tmpl.is_file() else (tmp_path / "__missing__.json")
    live_cap = CAPTURES_DIR / "live_20261126_234439.pcap"
    if live_cap.is_file():
        shutil.copyfile(live_cap, caps_dir / "live_20261126_234439.pcap")

    # Seed stale hero-less live_games.json entries sharing the same battle_ids as the PCAPs.
    base_chat4 = _decode_pcap_whole(CAPTURES_DIR / "draft_CHAT4.pcap", templates_path=tmpl_arg)[0].get_matches_snapshot()[0]
    stale_chat4 = dict(base_chat4)
    stale_chat4["game_id"] = "live:231398567527828650"
    stale_chat4["origin"] = "live"
    stale_chat4["source_name"] = "Live capture"
    seeded_live: dict[str, dict] = {"live:231398567527828650": stale_chat4}

    if live_cap.is_file():
        base_live = _decode_pcap_whole(live_cap, templates_path=tmpl_arg)[0].get_matches_snapshot()[0]
        stale_live = dict(base_live)
        stale_live["game_id"] = f"live:{base_live['battle_id']}"
        stale_live["origin"] = "live"
        stale_live["source_name"] = "Live capture"
        stale_live["players"] = [
            {k: v for k, v in p.items() if k not in ("hero_id", "hero_name")}
            for p in base_live["players"]
        ]
        stale_live["events"] = [
            {k: v for k, v in ev.items() if k not in ("sender_hero_id", "sender_hero")}
            for ev in base_live["events"]
        ]
        seeded_live[stale_live["game_id"]] = stale_live

    (hist_dir / "live_games.json").write_text(
        json.dumps({"version": 1, "games": seeded_live}, ensure_ascii=False),
        encoding="utf-8",
    )

    app = create_app(
        captures_dir=caps_dir,
        templates_path=tmpl_arg,
        history_dir=hist_dir,
        auto_scan_history=True,
    )
    with TestClient(app) as client:
        expected_total = 2 if live_cap.is_file() else 1
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            r_h = client.get("/api/history")
            if not r_h.json()["scan"]["scanning"] and r_h.json()["total_with_chat"] >= expected_total:
                break
            time.sleep(0.05)

        games = client.get("/api/history").json()["games"]
        assert len(games) == expected_total
        bids = [g["battle_id"] for g in games if g.get("battle_id")]
        assert len(bids) == len(set(bids))
        assert any(g["game_id"] == "pcap:draft_CHAT4.pcap:m1" for g in games)
        assert not any(g["game_id"] == "live:231398567527828650" for g in games)

        if live_cap.is_file():
            win_gid = "pcap:live_20261126_234439.pcap:m1"
            assert any(g["game_id"] == win_gid for g in games)
            assert not any(g["game_id"] == "live:802901785110406092" for g in games)
            full = client.get(f"/api/history/{win_gid}").json()
            assert sum(1 for p in full["players"] if p.get("hero_name")) == 10

        # UI contains dynamic hero precedence, scroll preservation, and history_updated handlers.
        html = client.get("/").text
        assert "history_updated" in html
        assert "loadedHistoryGames.clear" in html
        assert "prevScrollTop" in html
        hero_fn = html.split("function heroForEvent", 1)[1].split("}", 1)[0]
        assert hero_fn.index("heroByUid.has(ev.sender_uid)") < hero_fn.index("ev.sender_hero")

        # Deleted PCAP gets pruned from Past Games on rescan.
        (caps_dir / "draft_CHAT4.pcap").unlink()
        app.state.history.start_background_scan(force=False)
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            r_after = client.get("/api/history?include_empty=1")
            if not r_after.json()["scan"]["scanning"]:
                break
            time.sleep(0.05)
        assert all(g["game_id"] != "pcap:draft_CHAT4.pcap:m1" for g in r_after.json()["games"])

    # Fallback deduplication without battle_id: matches within 5s on same endpoint, keeps 35s-apart matches separate.
    no_bid_records = [
        {
            "game_id": "live:1000:1.2.3.4:5002",
            "origin": "live",
            "source_name": "Live capture",
            "battle_id": None,
            "server_ip": "1.2.3.4",
            "server_port": 5002,
            "first_ts": 1000.0,
            "last_ts": 1010.0,
            "players": [],
            "events": [{"seq_id": 1, "raw_text": "hi", "display_text": "hi", "is_template": False}],
            "gaps": [],
        },
        {
            "game_id": "pcap:match_a.pcap:m1",
            "origin": "pcap",
            "source_name": "match_a.pcap",
            "battle_id": None,
            "server_ip": "1.2.3.4",
            "server_port": 5002,
            "first_ts": 1003.0,
            "last_ts": 1010.0,
            "players": [],
            "events": [{"seq_id": 1, "raw_text": "hi", "display_text": "hi", "is_template": False}],
            "gaps": [],
        },
        {
            "game_id": "live:1038:1.2.3.4:5002",
            "origin": "live",
            "source_name": "Live capture",
            "battle_id": None,
            "server_ip": "1.2.3.4",
            "server_port": 5002,
            "first_ts": 1038.0,
            "last_ts": 1050.0,
            "players": [],
            "events": [{"seq_id": 1, "raw_text": "next", "display_text": "next", "is_template": False}],
            "gaps": [],
        },
    ]
    deduped = _dedup_records(no_bid_records)
    assert [r["game_id"] for r in deduped] == ["pcap:match_a.pcap:m1", "live:1038:1.2.3.4:5002"]

    # Richer live wins while PCAP is stale; index_pcap_file upgrades it and publishes history_updated SSE.
    cap_up_dir = tmp_path / "up_caps"
    hist_up_dir = tmp_path / "up_hist"
    cap_up_dir.mkdir()
    tee_file = cap_up_dir / "live_tee.pcap"
    raw_chat4 = (CAPTURES_DIR / "draft_CHAT4.pcap").read_bytes()
    tee_file.write_bytes(raw_chat4[: len(raw_chat4) // 2])

    sse_store = MatchStore()
    up_hist = MatchHistoryStore(
        captures_dir=cap_up_dir,
        history_dir=hist_up_dir,
        templates=TemplateResolver(tmpl_arg),
        on_change=lambda: sse_store.publish("history_updated", {"ts": time.time()}),
    )
    assert up_hist.index_pcap_file(tee_file) is True
    stale_pcap_events = len(up_hist.get_game("pcap:live_tee.pcap:m1")["events"])
    assert stale_pcap_events < 33

    rich_live = dict(base_chat4)
    rich_live["players"] = [dict(p, hero_id=17, hero_name="Fanny") for p in base_chat4["players"]]
    up_hist.save_live_matches([rich_live])
    listed_before = up_hist.list_games(include_empty=False)["games"]
    assert len(listed_before) == 1
    assert listed_before[0]["game_id"] == "live:231398567527828650"

    # Now finish writing full PCAP + add hero to verify index_pcap_file supersedes live and emits SSE.
    tee_file.write_bytes(raw_chat4)
    rich_live_no_hero = dict(base_chat4)
    up_hist.save_live_matches([rich_live_no_hero])
    assert up_hist.index_pcap_file(tee_file) is True
    listed_after = up_hist.list_games(include_empty=False)["games"]
    assert len(listed_after) == 1
    assert listed_after[0]["game_id"] == "pcap:live_tee.pcap:m1"
    assert any(ev_name == "history_updated" for _, ev_name, _ in sse_store._replay_log)
    assert up_hist.index_pcap_file(tmp_path / "outside.pcap") is False

    # Incremental SSE check on live_20261126_234439.pcap: chat before pick gets empty hero, then match_update backfills!
    if live_cap.is_file():
        live_sse_store = MatchStore()
        live_router = SessionRouter(store=live_sse_store, templates=TemplateResolver(tmpl_arg))
        rdr = IncrementalPcapReader()
        for pkt in rdr.feed(live_cap.read_bytes()):
            live_router.on_packet(pkt)
        events_seq = [(ev_name, data) for _, ev_name, data in live_sse_store._replay_log]
        chat_pre = next(
            d for name, d in events_seq if name == "chat" and d.get("sender_name") == "mashasha" and d.get("raw_text") == "2/9"
        )
        assert chat_pre["sender_hero"] == ""
        backfills = [
            d
            for name, d in events_seq
            if name == "match_update"
            and "events" in d
            and any(e.get("sender_name") == "mashasha" and e.get("sender_hero") == "Argus" for e in d["events"])
        ]
        assert backfills


@needs_captures
def test_16_early_roster_1230_1242_mode_party_and_bots(tmp_path: Path) -> None:
    from tools.chat_viewer.history import CACHE_SCHEMA_VERSION

    assert CACHE_SCHEMA_VERSION == 6

    # 1) Full draft_LIVE6.pcap: Ranked 5-stack, country distribution, metadata, zero anomalies.
    store_d6, _, _ = _decode_pcap_whole(CAPTURES_DIR / "draft_LIVE6.pcap")
    m1, m2 = store_d6.get_matches()
    assert m1.anomalies == []
    assert m1.mode_label == "Ranked"
    s1 = m1.summary_dict()
    assert s1["mode_label"] == "Ranked"
    assert s1["local_party_size"] == 5
    assert s1["party_label"] == "5-stack"
    assert s1["country_counts"] == {"ID": 2, "IN": 1, "MV": 1, "MY": 6}
    assert len(s1["players"]) == 10
    assert all(p["country"] and p["zone_id"] and p["room_id"] and p["is_bot"] is False for p in s1["players"])

    assert m2.anomalies == []
    s2 = m2.summary_dict()
    assert s2["mode_label"] == "Ranked"
    assert s2["local_party_size"] == 5
    assert s2["party_label"] == "5-stack"
    assert s2["country_counts"] == {"ID": 1, "IN": 1, "MV": 1, "MY": 7}

    # 2) Early ban-phase cutoff BEFORE mid=1202 (t+241.3s): mid=1242 (t+164.8s) + mid=1230 (t+183.0s)
    #    must already populate all 10 players, names, local_uid, mode, and countries!
    rdr_early = IncrementalPcapReader()
    pkts_d6 = rdr_early.feed((CAPTURES_DIR / "draft_LIVE6.pcap").read_bytes())
    t0 = pkts_d6[0].ts
    store_early = MatchStore()
    router_early = SessionRouter(store=store_early, templates=TemplateResolver(REPO_ROOT / "data" / "__missing__.json"))
    for pkt in pkts_d6:
        if pkt.ts >= t0 + 235.0:
            break
        router_early.on_packet(pkt)
    m_early = store_early.get_matches()[0]
    assert m_early.local_uid == 30028189
    assert m_early.mode_label == "Ranked"
    assert len(m_early.players_by_uid) == 10
    assert m_early.players_by_uid[30028189].country == "ID"
    assert all(p.name for p in m_early.players_by_uid.values())

    # 3) draft_CHAT3.pcap (Brawl Solo) & draft_CHAT4.pcap (Custom Draft).
    store_c3, _, _ = _decode_pcap_whole(CAPTURES_DIR / "draft_CHAT3.pcap")
    s_c3 = store_c3.get_matches()[0].summary_dict()
    assert s_c3["mode_label"] == "Brawl"
    assert s_c3["local_party_size"] == 1
    assert s_c3["party_label"] == "Solo"
    assert s_c3["country_counts"] == {"ID": 10}

    store_c4, _, _ = _decode_pcap_whole(CAPTURES_DIR / "draft_CHAT4.pcap")
    s_c4 = store_c4.get_matches()[0].summary_dict()
    assert s_c4["mode_label"] == "Custom Draft"
    assert s_c4["party_label"] == ""
    assert s_c4["country_counts"] == {"ID": 1, "SG": 1}

    # 4) Synthetic mid=1230 ('s', 1) wrapper with bRobot=1, country, zone_id, room_id, and post-freeze metadata merge.
    def make_kcp_seg(conv: bytes, sn: int, body: bytes) -> bytes:
        return b"\x01\x51" + conv + struct.pack("<IIIHBBH", 0, 1, sn, 64, 0, 0, len(body)) + body

    def wrap_b6_msg(mid: int, inner_root: bytes) -> bytes:
        return b"\x70\x00" + _encode_varint(mid) + b"\x46" + _encode_varint(len(inner_root)) + inner_root + b"\x80"

    def make_player_item(uid: int, camp: int, seat: int, name: str, *, bot: bool = False, cc: str = "", zone: int = 0, room: int = 0) -> bytes:
        nb = name.encode("utf-8")
        buf = bytearray(b"\x70\x00" + _encode_varint(uid) + b"\x01" + _encode_varint(camp) + b"\x02" + _encode_varint(seat) + b"\x43" + _encode_varint(len(nb)) + nb)
        if bot:
            buf += b"\x04\x01"
        if zone > 0:
            buf += b"\x09" + _encode_varint(zone)
        if room > 0:
            buf += b"\x0f\x16" + _encode_varint(room)
        if cc:
            cb = cc.encode("ascii")
            buf += b"\x4f\x1a" + _encode_varint(len(cb)) + cb
        buf += b"\x80"
        return bytes(buf)

    items_1230 = [
        make_player_item(1001, 1, 0, "HostUser", cc="id", zone=2041, room=999),
        make_player_item(1002, 1, 1, "FriendMY", cc="my", zone=2178, room=999),
    ]
    s1_fields = b"\x01\x01\x02\x01\x50" + _encode_varint(len(items_1230)) + b"".join(items_1230) + b"\x80"
    root_1230 = b"\x70\x71" + s1_fields + b"\x80"
    pkt_1230 = wrap_b6_msg(1230, root_1230)

    items_1203_post = [
        make_player_item(1001, 2, 4, "HostUser", cc="id", zone=2041, room=999),
        make_player_item(9001, 2, 0, "BotEnemy", bot=True, cc="sg", zone=5001, room=888),
    ]
    root_1203 = b"\x70\x50" + _encode_varint(len(items_1203_post)) + b"".join(items_1203_post) + b"\x80"
    pkt_1203 = wrap_b6_msg(1203, root_1203)

    store_syn = MatchStore()
    router_syn = SessionRouter(store=store_syn, templates=TemplateResolver(tmp_path / "__missing__.json"))
    conv = b"\xde\xad\xbe\xef"
    out_1001 = b"\x70\x00" + _encode_varint(1001) + b"\x70\x00" + _encode_varint(1001) + b"\x80\x80"
    frames = [
        _build_udp_ipv4_packet("10.0.0.1", 40000, "2.2.2.2", 5507, b"\x01\x51" + conv + struct.pack("<IIIHBBH", 0, 1, 0, 64, 0, 0, len(out_1001)) + out_1001),
        _build_udp_ipv4_packet("2.2.2.2", 5507, "10.0.0.1", 40000, make_kcp_seg(conv, 0, pkt_1230)),
        _build_udp_ipv4_packet("2.2.2.2", 5507, "10.0.0.1", 40000, _make_030146_lzw_packet(conv, 0, _make_fake_lzw_uncompressed_words(b"\x70\x80"))),
        _build_udp_ipv4_packet("2.2.2.2", 5507, "10.0.0.1", 40000, make_kcp_seg(conv, 1, pkt_1203)),
    ]
    rdr_syn = IncrementalPcapReader()
    for pkt in rdr_syn.feed(_pcap_header(LINKTYPE_RAW) + b"".join(_pcap_record(10 + i, 0, f) for i, f in enumerate(frames))):
        router_syn.on_packet(pkt)

    m_syn = store_syn.get_matches()[0]
    assert m_syn.mode_label == "Classic"
    assert m_syn.players_by_uid[1001].camp == 1  # Frozen at tick 0! Must not revert to 2 from post-freeze 1203.
    assert m_syn.players_by_uid[1001].country == "ID"
    assert m_syn.players_by_uid[1002].country == "MY"
    assert m_syn.players_by_uid[9001].is_bot is True
    assert m_syn.players_by_uid[9001].country == "SG"
    assert m_syn.summary_dict()["party_label"] == "Duo"

    # 5) UI HTML includes country/bot chip classes.
    app = create_app(
        captures_dir=CAPTURES_DIR,
        templates_path=tmp_path / "__missing__.json",
        history_dir=tmp_path / "hist",
        auto_scan_history=False,
    )
    with TestClient(app) as client:
        html = client.get("/").text
        assert ".chip-cc" in html
        assert ".chip-bot" in html
        assert ".mini-badge.mode" in html


def test_17_packed_7bit_tick_deltas_and_gap_reasons(tmp_path: Path) -> None:
    from tools.chat_viewer.battle import BattleTickProcessor, extract_ticks_from_subframe

    def make_lzw_sub(seq: int, v1: int | None, fields: list[tuple[int, bytes]]) -> bytes:
        inner = bytearray(b"\x70")
        if seq != 0:
            inner += b"\x00" + _encode_varint(seq)
        if v1 is not None:
            inner += b"\x01" + _encode_varint(v1)
        for tag, pay in fields:
            inner += bytes([tag]) + _encode_varint(len(pay)) + pay
        inner += b"\x80"
        return b"\x03\x01\x46" + _encode_varint(len(inner)) + bytes(inner)

    assert [t for t, _, _ in extract_ticks_from_subframe(make_lzw_sub(10, 1, [(0x42, b"\x01\x01"), (0x43, b"\x01\x02")]))] == [10, 11]
    assert [t for t, _, _ in extract_ticks_from_subframe(make_lzw_sub(0, 386, [(0x42, b"a"), (0x43, b"b"), (0x44, b"c")]))] == [0, 2, 3]
    assert [t for t, _, _ in extract_ticks_from_subframe(make_lzw_sub(50, 515, [(0x42, b"a"), (0x43, b"b"), (0x44, b"c")]))] == [50, 53, 54]
    assert [
        t for t, _, _ in extract_ticks_from_subframe(make_lzw_sub(100, 82434, [(0x42, b"a"), (0x43, b"b"), (0x44, b"c"), (0x45, b"d")]))
    ] == [100, 102, 104, 105]
    assert [
        t for t, _, _ in extract_ticks_from_subframe(make_lzw_sub(200, 115459, [(0x42, b"a"), (0x43, b"b"), (0x44, b"c"), (0x45, b"d")]))
    ] == [200, 203, 206, 207]

    # Sparse raw tick tag 0x55 with v1=82434 ([2, 4, 5]) resolves to seq + 5.
    raw_inner = b"\x70\x00" + _encode_varint(300) + b"\x01" + _encode_varint(82434) + b"\x55\x00\x80"
    raw_sub = b"\x03\x01\x46" + _encode_varint(len(raw_inner)) + raw_inner
    assert extract_ticks_from_subframe(raw_sub) == [(305, "raw", [])]

    # Gap reason: mid_match (first tick > 0, resolved with 0x0100 reset + empty next tick).
    bp_mid = BattleTickProcessor()
    o_mid = bp_mid.on_tick(1.0, 50, "lzw", b"\x01\x01")
    assert o_mid[0].kind == "gap_open" and o_mid[0].reason == "mid_match"
    bp_mid.on_tick(2.0, 130, "lzw", (0x0100).to_bytes(2, "big"))
    o_mid_res = bp_mid.on_tick(3.0, 131, "lzw", _make_fake_lzw_uncompressed_words(b"\x70\x80"))
    assert o_mid_res[0].kind == "gap_resolved" and o_mid_res[0].reason == "mid_match"

    # Gap reason: packet_loss (synced at 0 then skip > 75 ticks).
    bp_loss = BattleTickProcessor()
    assert bp_loss.on_tick(1.0, 0, "lzw", _make_fake_lzw_uncompressed_words(b"\x70\x80")) == []
    o_loss = bp_loss.on_tick(5.0, 80, "lzw", _make_fake_lzw_uncompressed_words(b"\x70\x80"))
    assert o_loss[0].kind == "gap_open" and o_loss[0].reason == "packet_loss"
    bp_loss.on_tick(6.0, 81, "lzw", (0x0100).to_bytes(2, "big"))
    o_loss_res = bp_loss.on_tick(7.0, 82, "lzw", _make_fake_lzw_uncompressed_words(b"\x70\x80"))
    assert o_loss_res[0].kind == "gap_resolved" and o_loss_res[0].reason == "packet_loss"

    # Gap reason: desync (bad LZW code after tick 0).
    bp_desync = BattleTickProcessor()
    bp_desync.on_tick(1.0, 0, "lzw", _make_fake_lzw_uncompressed_words(b"\x70\x80"))
    o_des = bp_desync.on_tick(2.0, 1, "lzw", (0x3FFE).to_bytes(2, "big"))
    assert o_des[0].kind == "desync" and o_des[0].reason == "desync"

    # Real capture live_20261127_101201.pcap decodes cleanly with zero gaps and zero LZW errors.
    live_cap = CAPTURES_DIR / "live_20261127_101201.pcap"
    if live_cap.is_file():
        tmpl_arg = REPO_ROOT / "data" / "chat_templates.json"
        store_1012, _, _ = _decode_pcap_whole(live_cap, templates_path=tmpl_arg if tmpl_arg.is_file() else None)
        ms = store_1012.get_matches()
        assert len(ms) == 1
        m_1012 = ms[0]
        assert m_1012.gaps == []
        assert m_1012.battle.lzw_errors == 0
        assert m_1012.battle.decoded_ticks >= 5000

    app = create_app(
        captures_dir=CAPTURES_DIR,
        templates_path=tmp_path / "__missing__.json",
        history_dir=tmp_path / "hist",
        auto_scan_history=False,
    )
    with TestClient(app) as client:
        html = client.get("/").text
        assert "Missed packets" in html
        assert "Stream resync" in html


def test_18_adb_hot_switch_make_before_break_and_name_recovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import io
    import os
    from tools.chat_viewer import ingest as ingest_mod
    from tools.chat_viewer.ingest import IngestController

    def make_kcp_seg(conv: bytes, sn: int, body: bytes) -> bytes:
        return b"\x01\x51" + conv + struct.pack("<IIIHBBH", 0, 1, sn, 64, 0, 0, len(body)) + body

    def make_roster_msg(mid: int, players: list[tuple[int, int, int, str, int | None]]) -> bytes:
        items = []
        for uid, camp, seat, name, hero_id in sorted(players, key=lambda x: x[0]):
            nb = name.encode("utf-8")
            item = (
                b"\x70\x00"
                + _encode_varint(uid)
                + b"\x01"
                + _encode_varint(camp)
                + b"\x02"
                + _encode_varint(seat)
                + b"\x43"
                + _encode_varint(len(nb))
                + nb
            )
            if hero_id is not None:
                item += b"\x07" + _encode_varint(hero_id)
            item += b"\x80"
            items.append(item)
        return b"\x70\x00" + _encode_varint(mid) + b"\x70\x50" + _encode_varint(len(items)) + b"".join(items) + b"\x80"

    def make_ev06_item(slot: int, ch: int, text: str, msg_uid: str = "") -> bytes:
        tb = text.encode("utf-8")
        cb = b"\x70\x00" + _encode_varint(ch) + b"\x41" + _encode_varint(len(tb)) + tb
        if msg_uid:
            mb = msg_uid.encode("utf-8")
            cb += b"\x4b" + _encode_varint(len(mb)) + mb
        cb += b"\x80"
        return b"\x70\x00" + _encode_varint(slot) + b"\x01\x06\x43" + _encode_varint(len(cb)) + cb + b"\x80"

    def make_tick_item_list(ev_items: list[bytes]) -> bytes:
        if not ev_items:
            return b"\x70\x80"
        return b"\x70\x51" + _encode_varint(len(ev_items)) + b"".join(ev_items) + b"\x80"

    class _FakePipeProc:
        def __init__(self) -> None:
            r_fd, w_fd = os.pipe()
            self.stdout = os.fdopen(r_fd, "rb", buffering=0)
            self._w_fd: int | None = w_fd
            self.stderr = io.BytesIO(b"")
            self._rc: int | None = None
            self._lock = __import__("threading").Lock()

        def feed_bytes(self, data: bytes) -> None:
            with self._lock:
                if self._w_fd is not None and data:
                    os.write(self._w_fd, data)

        def close_writer(self, rc: int = 0) -> None:
            with self._lock:
                if self._w_fd is not None:
                    self._rc = rc
                    os.close(self._w_fd)
                    self._w_fd = None

        def poll(self) -> int | None:
            return self._rc

        def terminate(self) -> None:
            self.close_writer(0)

        def wait(self, timeout: float | None = None) -> int:
            return self._rc if self._rc is not None else 0

        def kill(self) -> None:
            self.close_writer(-9)

    caps_dir = tmp_path / "caps"
    caps_dir.mkdir()
    tmpl_file = tmp_path / "tmpl.json"
    tmpl_file.write_text(json.dumps({"heroes": {"17": "Fanny", "55": "Angela", "88": "Masha"}}), encoding="utf-8")
    adb_exe = tmp_path / "adb.exe"
    adb_exe.write_bytes(b"")

    conv = b"\x01\x02\x03\x04"
    enc_table: dict[bytes, int] = {bytes([i]): i for i in range(256)}
    enc_next = 0x0101

    def enc_lzw(raw_data: bytes) -> bytes:
        nonlocal enc_next
        codes: list[int] = []
        cur = b""
        for b in raw_data:
            nxt = cur + bytes([b])
            if nxt in enc_table:
                cur = nxt
            else:
                codes.append(enc_table[cur])
                if enc_next < 0x4000:
                    enc_table[nxt] = enc_next
                    enc_next += 1
                cur = bytes([b])
        if cur:
            codes.append(enc_table[cur])
        return b"".join(c.to_bytes(2, "big") for c in codes)

    # Pre-build stateful battle tick packets 0..80 so overlap ticks reuse identical LZW bytes.
    tick_chat_map = {
        20: [make_ev06_item(0x11, 2, "hello before switch", "999001-2000-1")],
        38: [make_ev06_item(0x11, 2, "during overlap", "999001-2000-2")],
        60: [make_ev06_item(0x20, 3, "after switch", "999001-3000-3")],
    }
    tick_records: list[bytes] = []
    for tidx in range(81):
        enc_bytes = enc_lzw(make_tick_item_list(tick_chat_map.get(tidx, [])))
        ip_pkt = _build_udp_ipv4_packet("2.2.2.2", 5509, "10.0.0.1", 40000, _make_030146_lzw_packet(conv, tidx, enc_bytes))
        tick_records.append(_pcap_record(100 + tidx, 0, ip_pkt))

    out_1001 = b"\x70\x00" + _encode_varint(1001) + b"\x70\x00" + _encode_varint(1000) + b"\x80\x80"
    roster_1203 = make_roster_msg(
        1203,
        [(1000, 1, 0, "HostMe", 17), (2000, 1, 1, "AllyBob", 55), (3000, 2, 0, "EnemyFoe", 88)],
    )
    init_records = (
        _pcap_header(LINKTYPE_RAW)
        + _pcap_record(90, 0, _build_udp_ipv4_packet("10.0.0.1", 40000, "2.2.2.2", 5509, make_kcp_seg(conv, 0, out_1001)))
        + _pcap_record(91, 0, _build_udp_ipv4_packet("2.2.2.2", 5509, "10.0.0.1", 40000, make_kcp_seg(conv, 0, roster_1203)))
    )

    spawned: list[tuple[str, _FakePipeProc]] = []

    def fake_popen(cmd, stdout=None, stderr=None, bufsize=0):  # noqa: ARG001
        serial = cmd[cmd.index("-s") + 1]
        proc = _FakePipeProc()
        spawned.append((serial, proc))
        return proc

    monkeypatch.setattr(ingest_mod.subprocess, "Popen", fake_popen)

    # 1) Make-before-break ADB hot-switch: 0 gaps, 0 LZW errors, 0 duplicate chat, intact roster & tee file.
    tr = TemplateResolver(tmpl_file)
    store = MatchStore()
    router = SessionRouter(store=store, templates=tr)
    ingest = IngestController(
        router=router,
        store=store,
        captures_dir=caps_dir,
        adb_path=adb_exe,
        handoff_overlap_seconds=0.15,
    )
    ingest.start_adb("RRCY1032Y6F", tee=True)
    proc_usb = spawned[-1][1]
    proc_usb.feed_bytes(init_records + b"".join(tick_records[:41]))

    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        ms = store.get_matches()
        if ms and ms[0].battle.decoded_ticks >= 41:
            break
        time.sleep(0.02)
    assert store.get_matches()[0].battle.decoded_ticks == 41

    # Switch to Wireless ADB while USB is still open, then overlap ticks 35..40 and feed 41..80 on Wi-Fi.
    ingest.start_adb("192.168.1.17:36125", tee=True, preserve_session=True)
    assert store.get_status()["switching_to"] == "192.168.1.17:36125"
    proc_wifi = spawned[-1][1]
    proc_wifi.feed_bytes(_pcap_header(LINKTYPE_RAW) + b"".join(tick_records[35:81]))
    proc_usb.feed_bytes(b"".join(tick_records[41:46]))

    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        st = store.get_status()
        ms = store.get_matches()
        if st["active_serial"] == "192.168.1.17:36125" and st["switching_to"] is None and ms and ms[0].battle.decoded_ticks >= 81:
            break
        time.sleep(0.02)

    ingest.stop()
    ms = store.get_matches()
    assert len(ms) == 1
    m = ms[0]
    assert m.battle_id == "999001"
    assert m.gaps == []
    assert m.battle.lzw_errors == 0
    assert m.battle.decoded_ticks == 81
    assert [(ev.raw_text, ev.sender_name, ev.sender_hero, ev.side) for ev in m.events] == [
        ("hello before switch", "AllyBob", "Angela", "ALLY"),
        ("during overlap", "AllyBob", "Angela", "ALLY"),
        ("after switch", "EnemyFoe", "Masha", "ENEMY"),
    ]
    tee_files = sorted(caps_dir.glob("live_*.pcap"))
    assert len(tee_files) == 1 and tee_files[0].stat().st_size > 100
    re_store, _, _ = _decode_pcap_whole(tee_files[0], templates_path=tmpl_file)
    assert len(re_store.get_matches()[0].events) == 3

    # 2) Failed hot-switch keeps old stream alive with clear error.
    ingest.start_adb("RRCY1032Y6F", tee=False)
    proc_usb2 = spawned[-1][1]
    proc_usb2.feed_bytes(init_records + tick_records[0])
    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline and not store.get_matches():
        time.sleep(0.02)

    ingest.start_adb("192.168.1.99:5555", tee=False, preserve_session=True)
    proc_bad = spawned[-1][1]
    proc_bad.feed_bytes(b"BAD!")
    proc_bad.close_writer(1)
    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline:
        st = store.get_status()
        if st["switching_to"] is None and st["last_error"]:
            break
        time.sleep(0.02)
    st_after_fail = store.get_status()
    assert st_after_fail["capture_alive"] is True
    assert st_after_fail["active_serial"] == "RRCY1032Y6F"
    assert "Switch to 192.168.1.99:5555 failed" in (st_after_fail["last_error"] or "")
    ingest.stop()

    # Session-preserving resume after stop keeps existing players/events without resetting match_id.
    ingest.start_adb("192.168.1.17:36125", tee=False, preserve_session=True)
    proc_resume = spawned[-1][1]
    proc_resume.feed_bytes(_pcap_header(LINKTYPE_RAW) + tick_records[1])
    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline:
        ms_res = store.get_matches()
        if ms_res and ms_res[0].battle.decoded_ticks >= 2:
            break
        time.sleep(0.02)
    assert len(store.get_matches()) == 1
    assert store.get_matches()[0].players_by_uid[2000].name == "AllyBob"
    assert store.get_matches()[0].battle.decoded_ticks >= 2
    ingest.stop()

    # 3) Cluster merge + roster/UID name recovery across split captures & restarted live streams.
    hist_dir = tmp_path / "hist"
    split_caps = tmp_path / "split_caps"
    split_caps.mkdir()
    seeded_live = {
        "live:older999": {
            "game_id": "live:older999",
            "origin": "live",
            "source_name": "Live capture",
            "battle_id": "older999",
            "server_ip": "3.3.3.3",
            "server_port": 5005,
            "first_ts": 500.0,
            "last_ts": 510.0,
            "players": [{"uid": 999001, "name": "KnownOldFriend", "camp": 1, "seat": 2, "slot": 18}],
            "events": [{"seq_id": 1, "ts": 505.0, "phase": "draft", "channel": 4, "slot": 18, "sender_uid": 999001, "sender_name": "KnownOldFriend", "side": "ALLY", "raw_text": "hi", "display_text": "hi", "is_template": False}],
            "gaps": [],
        },
        "live:888877776666:draft": {
            "game_id": "live:888877776666:draft",
            "origin": "live",
            "source_name": "Live capture",
            "battle_id": None,
            "server_ip": "4.4.4.4",
            "server_port": 5505,
            "first_ts": 1000.0,
            "last_ts": 1020.0,
            "local_uid": 1000,
            "local_camp": 1,
            "players": [
                {"uid": 1000, "name": "HostMe", "camp": 1, "seat": 0, "slot": 0x10, "hero_id": 17, "hero_name": "Fanny"},
                {"uid": 2000, "name": "BuddyOne", "camp": 1, "seat": 1, "slot": 0x11, "hero_id": 55, "hero_name": "Angela"},
                {"uid": 3000, "name": "RivalOne", "camp": 2, "seat": 0, "slot": 0x20, "hero_id": 88, "hero_name": "Masha"},
            ],
            "events": [
                {"seq_id": 1, "ts": 1010.0, "phase": "draft", "channel": 4, "slot": 0x11, "camp": 1, "sender_uid": 2000, "sender_name": "BuddyOne", "sender_hero_id": 55, "sender_hero": "Angela", "side": "ALLY", "raw_text": "draft gl", "display_text": "draft gl", "is_template": False, "msg_uid": ""},
            ],
            "gaps": [],
        },
        "live:888877776666": {
            "game_id": "live:888877776666",
            "origin": "live",
            "source_name": "Live capture",
            "battle_id": "888877776666",
            "server_ip": "4.4.4.4",
            "server_port": 5505,
            "first_ts": 1003.0,
            "last_ts": 1200.0,
            "players": [],
            "events": [
                {"seq_id": 1, "ts": 1100.0, "phase": "battle", "tick": 500, "channel": 2, "slot": 0x11, "camp": 1, "sender_uid": None, "sender_name": "slot 0x11", "side": "CAMP 1", "raw_text": "early msg", "display_text": "early msg", "is_template": False, "msg_uid": ""},
                {"seq_id": 2, "ts": 1120.0, "phase": "battle", "tick": 600, "channel": 2, "slot": 0x11, "camp": 1, "sender_uid": 2000, "sender_name": "uid:2000", "side": "CAMP 1", "raw_text": "late msg", "display_text": "late msg", "is_template": False, "msg_uid": "888877776666-2000-2"},
                {"seq_id": 3, "ts": 1130.0, "phase": "battle", "tick": 650, "channel": 3, "slot": 0x23, "camp": 2, "sender_uid": 999001, "sender_name": "uid:999001", "side": "CAMP 2", "raw_text": "old friend", "display_text": "old friend", "is_template": False, "msg_uid": "888877776666-999001-3"},
            ],
            "gaps": [],
        },
    }
    hist_dir.mkdir()
    (hist_dir / "live_games.json").write_text(json.dumps({"version": 1, "games": seeded_live}), encoding="utf-8")

    hist = MatchHistoryStore(captures_dir=split_caps, history_dir=hist_dir, templates=tr)
    listed = hist.list_games(include_empty=False)["games"]
    assert len(listed) == 2
    merged_game = hist.get_game("live:888877776666")
    assert merged_game is not None
    assert merged_game["summary"]["ally_players"] == ["HostMe", "BuddyOne"]
    assert [(e["raw_text"], e["sender_name"], e["side"]) for e in merged_game["events"]] == [
        ("draft gl", "BuddyOne", "ALLY"),
        ("early msg", "BuddyOne", "ALLY"),
        ("late msg", "BuddyOne", "ALLY"),
        ("old friend", "KnownOldFriend", "ENEMY"),
    ]

    # Live mid-battle SessionRouter hydrated from MatchHistoryStore resolves both slot 0x11 backfill and KnownOldFriend.
    mid_store = MatchStore()
    mid_router = SessionRouter(
        store=mid_store,
        templates=tr,
        match_roster_lookup=hist.lookup_match_roster,
        uid_name_lookup=hist.lookup_player_name,
    )
    mid_enc_table = {bytes([i]): i for i in range(256)}
    mid_codes: list[int] = []
    cur = b""
    for b in make_tick_item_list(
        [
            make_ev06_item(0x11, 2, "early slot"),
            make_ev06_item(0x23, 3, "from old friend", "888877776666-999001-4"),
            make_ev06_item(0x11, 2, "from buddy", "888877776666-2000-5"),
        ]
    ):
        nxt = cur + bytes([b])
        if nxt in mid_enc_table:
            cur = nxt
        else:
            mid_codes.append(mid_enc_table[cur])
            cur = bytes([b])
    if cur:
        mid_codes.append(mid_enc_table[cur])
    mid_pkt = _build_udp_ipv4_packet(
        "4.4.4.4", 5505, "10.0.0.1", 40000, _make_030146_lzw_packet(conv, 0, b"".join(c.to_bytes(2, "big") for c in mid_codes))
    )
    for pkt in IncrementalPcapReader().feed(_pcap_header(LINKTYPE_RAW) + _pcap_record(2000, 0, mid_pkt)):
        mid_router.on_packet(pkt)
    m_restarted = mid_store.get_matches()[0]
    assert [(ev.raw_text, ev.sender_name, ev.side) for ev in m_restarted.events] == [
        ("early slot", "BuddyOne", "ALLY"),
        ("from old friend", "KnownOldFriend", "ENEMY"),
        ("from buddy", "BuddyOne", "ALLY"),
    ]

    # If real split captures from 17:25 + 17:28 exist on disk, verify merging yields all 10 names & heroes.
    cap_1725 = CAPTURES_DIR / "live_20261127_172543.pcap"
    cap_1728 = CAPTURES_DIR / "live_lag_20261127_172850.pcap"
    real_tmpl = REPO_ROOT / "data" / "chat_templates.json"
    if cap_1725.is_file() and cap_1728.is_file() and real_tmpl.is_file():
        real_caps = tmp_path / "real_1725"
        real_caps.mkdir()
        shutil.copyfile(cap_1725, real_caps / cap_1725.name)
        shutil.copyfile(cap_1728, real_caps / cap_1728.name)
        real_hist = MatchHistoryStore(captures_dir=real_caps, history_dir=tmp_path / "real_hist", templates=TemplateResolver(real_tmpl))
        real_hist.start_background_scan()
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            r_l = real_hist.list_games(include_empty=False)
            if not r_l["scan"]["scanning"] and r_l["games"]:
                break
            time.sleep(0.05)
        g_829 = [g for g in real_hist.list_games()["games"] if g.get("battle_id") == "829733665579293409"]
        assert len(g_829) == 1
        assert "Chudvial999" in g_829[0]["ally_players"] or "Chudvial999" in g_829[0]["enemy_players"]

    # 4) Clear source mode, /api/adb/wireless error check, and UI control HTML.
    app = create_app(
        captures_dir=caps_dir,
        templates_path=tmpl_file,
        history_dir=tmp_path / "ui_hist",
        adb_path=adb_exe,
        auto_scan_history=False,
    )
    with TestClient(app) as client:
        assert client.post("/api/source", json={"mode": "clear"}).status_code == 200
        assert client.post("/api/adb/wireless", json={"action": "bogus"}).status_code == 400
        html = client.get("/").text
        for needle in ("btnSwitchDevice", "btnConnectWireless", "btnClearSession", "switch_adb", "preserve_session", "/api/adb/wireless"):
            assert needle in html






