"""Comprehensive regression, protocol, and HTTP/SSE integration tests for tools.chat_viewer."""

from __future__ import annotations

import json
import random
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


def test_8_chunked_partial_read_fuzz_and_linktypes() -> None:
    rng = random.Random(20261126)
    for fname in ("draft_CHAT4.pcap", "live_chat_check.pcap"):
        data = (CAPTURES_DIR / fname).read_bytes()
        whole_store, _, whole_rdr = _decode_pcap_whole(CAPTURES_DIR / fname)

        chunk_store = MatchStore()
        chunk_router = SessionRouter(store=chunk_store)
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
        heartbeat_interval=0.2,
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

        client.post("/api/source", json={"mode": "stop"})
