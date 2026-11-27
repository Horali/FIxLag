"""Comprehensive protocol, RTT, Zstd, deduplication, and HTTP/SSE tests for tools.lag_mapper."""

from __future__ import annotations

import json
import random
import shutil
import socket
import struct
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import pytest
from starlette.testclient import TestClient

from tools.chat_viewer.pcap_reader import (
    LINKTYPE_ETHERNET,
    LINKTYPE_RAW,
    LINKTYPE_SLL,
    LINKTYPE_SLL2,
    InvalidPcapMagicError,
)
from tools.chat_viewer.templates import TemplateResolver
from tools.lag_mapper.aggregator import LagAggregator
from tools.lag_mapper.classifier import classify_ip
from tools.lag_mapper.detector import LagPacketEngine
from tools.lag_mapper.pcap_net import IncrementalNetPcapReader, classify_link
from tools.lag_mapper.rtt import RttTracker
from tools.lag_mapper.server import create_app, pick_loopback_port, validate_loopback_host
from tools.lag_mapper.tcp_lobby import TcpLobbyDecoder, redact_pii

CAPTURES_DIR = REPO_ROOT / "captures"


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


def _pcap_header(linktype: int = LINKTYPE_RAW, magic: bytes = b"\xd4\xc3\xb2\xa1") -> bytes:
    endian = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
    return struct.pack(endian + "IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype)


def _pcap_record(
    ts_sec: int,
    ts_sub: int,
    frame: bytes,
    orig_len: int | None = None,
    endian: str = "<",
) -> bytes:
    olen = len(frame) if orig_len is None else orig_len
    return struct.pack(endian + "IIII", ts_sec, ts_sub, len(frame), olen) + frame


def _build_udp_ipv4(src_ip: str, sport: int, dst_ip: str, dport: int, payload: bytes) -> bytes:
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


def _build_tcp_ipv4(
    src_ip: str,
    sport: int,
    dst_ip: str,
    dport: int,
    seq: int,
    payload: bytes,
    flags: int = 0x18,
) -> bytes:
    tcp_len = 20 + len(payload)
    ip_len = 20 + tcp_len
    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        ip_len,
        2,
        0,
        64,
        6,
        0,
        bytes(int(x) for x in src_ip.split(".")),
        bytes(int(x) for x in dst_ip.split(".")),
    )
    tcp_hdr = struct.pack("!HHIIBBHHH", sport, dport, seq, 1, 0x50, flags, 65535, 0, 0)
    return ip_hdr + tcp_hdr + payload


def _wrap_link(linktype: int, ip_pkt: bytes, *, ifindex: int = 44, vlan: bool = False) -> bytes:
    if linktype == LINKTYPE_RAW:
        return ip_pkt
    if linktype == LINKTYPE_ETHERNET:
        hdr = (b"\xaa" * 6) + (b"\xbb" * 6)
        if vlan:
            return hdr + struct.pack("!HHHHH", 0x8100, 10, 0x88A8, 20, 0x0800) + ip_pkt
        return hdr + struct.pack("!H", 0x0800) + ip_pkt
    if linktype == LINKTYPE_SLL:
        return struct.pack("!HHH8sH", 0, 1, 6, b"\x00" * 8, 0x0800) + ip_pkt
    if linktype == LINKTYPE_SLL2:
        return struct.pack("!HHIHBB8s", 0x0800, 0, ifindex, 1, 0, 6, b"\x00" * 8) + ip_pkt
    raise ValueError(linktype)


def test_1_pcap_net_linktypes_tcp_udp_chunking_and_truncation() -> None:
    # 1. Invalid magic fails immediately.
    bad = IncrementalNetPcapReader()
    with pytest.raises(InvalidPcapMagicError):
        bad.feed(b"NOT_PCAP")

    # 2. Link attribution checks (SLL2 ifindex + IP fallback).
    assert classify_link("10.0.0.1", 44) == ("wlan0", "Wi-Fi")
    assert classify_link("192.168.1.5", 63) == ("rmnet_data0", "Cellular")
    assert classify_link("192.168.1.5", 123) == ("rmnet_data0", "Cellular")
    assert classify_link("192.168.1.5", 14) == ("rmnet_ipa0", "Cellular")
    assert classify_link("192.168.1.17", None) == ("wlan0", "Wi-Fi")
    assert classify_link("172.16.5.4", None) == ("wlan0", "Wi-Fi")
    assert classify_link("10.156.63.86", None) == ("rmnet_data0", "Cellular")
    assert classify_link("100.64.2.9", None) == ("rmnet_data0", "Cellular")

    # 3. All 4 linktypes + stacked VLAN + UDP & TCP + truncated skip.
    udp_ip = _build_udp_ipv4("192.168.1.17", 41234, "149.104.112.216", 5507, b"\x01\x75hello")
    tcp_ip = _build_tcp_ipv4("192.168.1.17", 55000, "161.202.213.215", 30101, 1001, b"\x00\x00\x00\x08test")

    for lt in (LINKTYPE_RAW, LINKTYPE_ETHERNET, LINKTYPE_SLL, LINKTYPE_SLL2):
        f_udp = _wrap_link(lt, udp_ip + (b"\x00" * 6 if lt == LINKTYPE_ETHERNET else b""), ifindex=44, vlan=(lt == LINKTYPE_ETHERNET))
        f_tcp = _wrap_link(lt, tcp_ip, ifindex=123)
        stream = (
            _pcap_header(lt)
            + _pcap_record(100, 1000, f_udp, orig_len=len(f_udp) + 32)
            + _pcap_record(101, 2000, f_udp)
            + _pcap_record(102, 3000, f_tcp)
        )
        rdr = IncrementalNetPcapReader()
        pkts = rdr.feed(stream)
        assert rdr.skipped_truncated == 1
        assert len(pkts) == 2
        assert pkts[0].proto == "udp"
        assert pkts[0].payload == b"\x01\x75hello"
        assert pkts[1].proto == "tcp"
        assert pkts[1].tcp_seq == 1001
        assert pkts[1].payload == b"\x00\x00\x00\x08test"
        if lt == LINKTYPE_SLL2:
            assert pkts[0].ifindex == 44
            assert pkts[1].ifindex == 123

    # 4. Big-endian nanosecond header + random 1..37 byte chunked equivalence.
    be_ns_hdr = struct.pack(">IHHIIII", 0xA1B23C4D, 2, 4, 0, 0, 65535, LINKTYPE_RAW)
    be_stream = be_ns_hdr + _pcap_record(50, 500_000_000, udp_ip, endian=">") + _pcap_record(51, 250_000_000, tcp_ip, endian=">")
    whole = IncrementalNetPcapReader().feed(be_stream)
    rng = random.Random(42)
    chunk_rdr = IncrementalNetPcapReader()
    chunked = []
    off = 0
    while off < len(be_stream):
        step = rng.randint(1, 37)
        chunked.extend(chunk_rdr.feed(be_stream[off : off + step]))
        off += step
    assert len(whole) == 2
    assert [(p.proto, p.ts, p.payload, p.tcp_seq) for p in chunked] == [
        (p.proto, p.ts, p.payload, p.tcp_seq) for p in whole
    ]


def test_2_rtt_0x3f5_draft_live6_wifi_vs_cellular() -> None:
    rdr = IncrementalNetPcapReader()
    rtt = RttTracker()
    target_ep = ("149.104.112.216", 5507)
    for pkt in rdr.feed((CAPTURES_DIR / "draft_LIVE6.pcap").read_bytes()):
        if pkt.proto != "udp":
            continue
        if (pkt.dst_ip, pkt.dport) == target_ep:
            rtt.on_udp_packet(pkt, ep=target_ep, direction="out")
        elif (pkt.src_ip, pkt.sport) == target_ep:
            rtt.on_udp_packet(pkt, ep=target_ep, direction="in")

    summary = rtt.summarize_endpoint(target_ep)
    wifi = summary["links"]["Wi-Fi"]
    cell = summary["links"]["Cellular"]

    assert wifi["sample_count"] >= 900
    assert cell["sample_count"] >= 900
    assert 30.0 <= wifi["median_ms"] <= 46.0
    assert 46.0 <= cell["median_ms"] <= 62.0
    assert wifi["median_ms"] < cell["median_ms"]
    assert wifi["jitter_ms"] > 0.0
    assert cell["jitter_ms"] > 0.0
    assert "wlan0 (192.168.1.17)" in summary["by_iface_ip"]
    assert "rmnet_data0 (10.156.63.86)" in summary["by_iface_ip"]

    wifi_pts = [pt for pt in summary["series"] if pt["link"] == "Wi-Fi"]
    cell_pts = [pt for pt in summary["series"] if pt["link"] == "Cellular"]
    assert 1 <= len(wifi_pts) <= 180
    assert 1 <= len(cell_pts) <= 180


def test_3_probe_30190_sweep_detection() -> None:
    # Live capture containing both :30190 probes with replies and matches.
    eng_live = LagPacketEngine(record_feed=True)
    rdr = IncrementalNetPcapReader()
    for pkt in rdr.feed((CAPTURES_DIR / "draft_LIVE6.pcap").read_bytes()):
        eng_live.on_packet(pkt, skipped_truncated=rdr.skipped_truncated)
    eng_live.flush()

    probes = eng_live.get_probes_list()
    assert len(probes) >= 40
    assert eng_live.lanes["PROBE_30190"]["packets"] >= 80
    replied = [p for p in probes if p["median_rtt_ms"] is not None]
    assert len(replied) >= 20
    assert any(p["provider"] != "Observed" for p in probes)

    # Cold-start capture with standalone :30190 sweep (no match).
    eng_cold = LagPacketEngine(record_feed=True)
    rdr_cold = IncrementalNetPcapReader()
    for pkt in rdr_cold.feed((CAPTURES_DIR / "draft_COLD2.pcap").read_bytes()):
        eng_cold.on_packet(pkt, skipped_truncated=rdr_cold.skipped_truncated)
    cold_probes = eng_cold.get_probes_list()
    assert len(cold_probes) >= 5
    assert eng_cold.lanes["PROBE_30190"]["packets"] >= 10


def test_4_tcp_30101_zstd_handover_geo_pii_skip_and_no_zstd_fallback() -> None:
    data = (CAPTURES_DIR / "draft_LIVE6.pcap").read_bytes()
    rdr = IncrementalNetPcapReader()
    pkts = rdr.feed(data)

    # 1. Real capture with Zstd enabled.
    eng = LagPacketEngine(live_mode=False, record_feed=True)
    for pkt in pkts:
        eng.on_packet(pkt, skipped_truncated=rdr.skipped_truncated)
    eng.flush()

    assert eng.lobby.zstd_available is True
    assert eng.lobby.zstd_frames >= 400
    assert eng.lobby.zstd_errors == 0
    assert eng.lobby.dropped_pii_frames >= 1

    handover_eps = {h["target_ep"] for h in eng.lobby.handovers}
    assert "149.104.112.216:5507" in handover_eps
    assert "38.54.99.212:5503" in handover_eps
    assert len(eng.lobby.lobby_geo_by_name) >= 5

    # Ensure no email addresses appear anywhere in exported match/live JSON.
    matches_json = json.dumps(eng.build_match_records(source_name="draft_LIVE6.pcap", origin="pcap"))
    snap_json = json.dumps(eng.get_live_packets_snapshot())
    assert "gmail.com" not in matches_json.lower()
    assert "gmail.com" not in snap_json.lower()
    assert redact_pii("login test.user@example.com token eyJhbGciOiJIUzI1NiJ9.abcdefghij.sig") == (
        "login [redacted-email] token [redacted-token]"
    )

    # 2. Synthetic mid=10208 must be dropped strictly before decoding, while mid=20008 still works.
    dec = TcpLobbyDecoder(live_mode=True)
    body_10208 = b"\x70\x00" + _encode_varint(10208) + b"\x41\x19secret.login@example.com\x80"
    frame_10208 = b"\x00" + len(body_10208 + b"xxxx").to_bytes(3, "big") + body_10208
    body_20008 = b"\x70\x00" + _encode_varint(20008) + b"\x41\x14149.104.112.216:5507\x80"
    frame_20008 = b"\x00" + len(body_20008 + b"xxxx").to_bytes(3, "big") + body_20008

    from tools.lag_mapper.pcap_net import NetPacket

    evs1 = dec.on_tcp_packet(
        NetPacket(ts=10.0, src_ip="161.202.213.215", dst_ip="192.168.1.17", sport=30101, dport=55000, proto="tcp", payload=frame_10208, ifindex=44, tcp_seq=100)
    )
    evs2 = dec.on_tcp_packet(
        NetPacket(ts=11.0, src_ip="161.202.213.215", dst_ip="192.168.1.17", sport=30101, dport=55000, proto="tcp", payload=frame_20008, ifindex=44, tcp_seq=100 + len(frame_10208))
    )
    assert evs1 == []
    assert dec.dropped_pii_frames == 1
    assert len(evs2) == 1
    assert evs2[0]["target_ep"] == "149.104.112.216:5507"

    # 3. Missing zstd graceful skip fallback.
    dec_no_zstd = TcpLobbyDecoder(enable_zstd=False)
    for pkt in pkts:
        if pkt.proto == "tcp" and (pkt.sport == 30101 or pkt.dport == 30101):
            dec_no_zstd.on_tcp_packet(pkt)
    dec_no_zstd.flush()
    assert dec_no_zstd.zstd_available is False
    assert dec_no_zstd.skipped_zstd_frames >= 400
    assert dec_no_zstd.zstd_errors == 0


def test_5_tcp_port_plus_50_mirror_detection() -> None:
    for fname, expected_mirrors in (
        ("draft_LIVE6.pcap", {("149.104.112.216", 5557), ("38.54.99.212", 5553)}),
        ("draft_CHAT4.pcap", {("154.93.118.110", 5057)}),
    ):
        eng = LagPacketEngine(record_feed=False)
        rdr = IncrementalNetPcapReader()
        for pkt in rdr.feed((CAPTURES_DIR / fname).read_bytes()):
            eng.on_packet(pkt, skipped_truncated=rdr.skipped_truncated)
        eng.flush()

        matches = eng.build_match_records(source_name=fname, origin="pcap")
        mirrors = {(m["server_ip"], m["tcp_mirror"]["port"]) for m in matches if m.get("tcp_mirror")}
        assert expected_mirrors <= mirrors
        assert eng.lanes["TCP_MIRROR"]["packets"] > 100
        # Non-MLBB TCP ports like FCM :5228 must never be promoted into TCP_MIRROR.
        assert all((ip, port - 50) in eng._ep_flows for ip, port in eng._tcp_mirror_promoted)


def test_6_matches_csv_dedup_notes_and_correlations(tmp_path: Path) -> None:
    caps = tmp_path / "caps"
    data = tmp_path / "data"
    caps.mkdir()
    data.mkdir()

    shutil.copyfile(CAPTURES_DIR / "draft_CHAT4.pcap", caps / "draft_CHAT4.pcap")
    # Inspect draft_CHAT4 first_ts so we place a matching CSV row within +/- 180s.
    tmp_eng = LagPacketEngine(record_feed=False)
    tmp_rdr = IncrementalNetPcapReader()
    for p in tmp_rdr.feed((caps / "draft_CHAT4.pcap").read_bytes()):
        tmp_eng.on_packet(p, skipped_truncated=tmp_rdr.skipped_truncated)
    tmp_eng.flush()
    chat4_rec = tmp_eng.build_match_records(source_name="draft_CHAT4.pcap", origin="pcap")[0]
    import datetime

    iso_match = datetime.datetime.fromtimestamp(chat4_rec["first_ts"] + 30.0).astimezone().isoformat(timespec="seconds")

    csv_lines = [
        "ts,label,host,displayed_ping_ms,endpoint,port,provider,city_geo,confidence,ifaces,out_pkts,in_pkts,duration_s,other_endpoints,party,note",
        f'{iso_match},CHAT4,me,24.0,{chat4_rec["server_ip"]},{chat4_rec["server_port"]},Observed,Jakarta,csv,"wlan0",100,100,120.0,,"1q: me(ID)",solo baseline test',
        '2026-11-25T13:45:13+07:00,M2,MY friend,41.0,164.52.109.153,5007,CDS Global Cloud,Singapore?,prefix,,,,,,"5q: 2 MY (MY host), SG, IN, me ID",standalone csv match',
    ]
    csv_path = data / "matches.csv"
    csv_before = "\n".join(csv_lines) + "\n"
    csv_path.write_text(csv_before, encoding="utf-8")

    tr = TemplateResolver(tmp_path / "__missing__.json")
    agg = LagAggregator(captures_dir=caps, data_dir=data, templates=tr)
    assert agg.index_pcap_file(caps / "draft_CHAT4.pcap")

    matches = agg.get_matches()
    assert len(matches) == 2
    deduped = next(m for m in matches if m["server_ip"] == chat4_rec["server_ip"])
    assert deduped["origin"] == "pcap"
    assert deduped["csv_matched"] is True
    assert deduped["host"] == "me"
    assert deduped["displayed_ping_ms"] == 24.0
    assert deduped["note"] == "solo baseline test"

    standalone = next(m for m in matches if m["server_ip"] == "164.52.109.153")
    assert standalone["origin"] == "csv"
    assert standalone["local_party_size"] == 5

    # Persist user note override into lag_mapper_notes.json without altering matches.csv.
    agg.save_note(deduped["match_key"], host="SG friend", displayed_ping_ms=27.5, note="updated note")
    assert csv_path.read_text(encoding="utf-8") == csv_before
    assert (data / "lag_mapper_notes.json").is_file()

    agg_reloaded = LagAggregator(captures_dir=caps, data_dir=data, templates=tr)
    reloaded_match = next(m for m in agg_reloaded.get_matches() if m["match_key"] == deduped["match_key"])
    assert reloaded_match["host"] == "SG friend"
    assert reloaded_match["displayed_ping_ms"] == 27.5
    assert reloaded_match["note"] == "updated note"

    corr = agg_reloaded.get_correlations()
    assert corr["baseline_ms"] is not None
    assert len(corr["groups"]) == 2
    assert classify_ip("149.104.112.216")["confidence"] == "observed"


def test_7_http_sse_api_and_loopback_guard(tmp_path: Path) -> None:
    assert validate_loopback_host("127.0.0.1") == "127.0.0.1"
    for bad_host in ("0.0.0.0", "192.168.1.5", "::"):
        with pytest.raises(ValueError):
            validate_loopback_host(bad_host)

    caps = tmp_path / "caps"
    data = tmp_path / "data"
    caps.mkdir()
    data.mkdir()
    shutil.copyfile(CAPTURES_DIR / "draft_CHAT4.pcap", caps / "draft_CHAT4.pcap")
    shutil.copyfile(REPO_ROOT / "data" / "matches.csv", data / "matches.csv")

    app = create_app(
        captures_dir=caps,
        data_dir=data,
        templates_path=tmp_path / "__missing__.json",
        heartbeat_interval=0.15,
        auto_scan=False,
    )

    def _parse_sse(body: str) -> list[tuple[int, str, dict]]:
        out: list[tuple[int, str, dict]] = []
        cid = 0
        cev = ""
        for ln in body.splitlines():
            if ln.startswith("id: "):
                cid = int(ln[4:])
            elif ln.startswith("event: "):
                cev = ln[7:]
            elif ln.startswith("data: "):
                out.append((cid, cev, json.loads(ln[6:])))
        return out

    with TestClient(app) as client:
        r_home = client.get("/")
        assert r_home.status_code == 200
        assert "FIxLag Packet Mapper" in r_home.text
        assert "Friends' IP addresses" in r_home.text

        assert client.get("/api/overview").status_code == 200
        assert client.get("/api/servers").status_code == 200
        assert client.get("/api/correlations").status_code == 200
        assert client.get("/api/devices").status_code == 200
        assert "draft_CHAT4.pcap" in [p["name"] for p in client.get("/api/pcaps").json()["pcaps"]]

        # Initial SSE stream (max_events=2)
        r_sse = client.get("/events?max_events=2")
        assert r_sse.status_code == 200
        assert "text/event-stream" in r_sse.headers["content-type"]
        assert r_sse.headers.get("cache-control") == "no-cache"
        assert r_sse.headers.get("x-accel-buffering") == "no"
        frames = _parse_sse(r_sse.text)
        assert len(frames) == 2
        assert frames[0][1] == "snapshot"
        assert frames[1][1] == "status"
        baseline_id = frames[-1][0]

        # Replay draft_CHAT4.pcap via /api/source and verify live telemetry & Last-Event-ID replay.
        r_src = client.post("/api/source", json={"mode": "pcap", "path": str(caps / "draft_CHAT4.pcap"), "follow": False})
        assert r_src.status_code == 200

        deadline = time.monotonic() + 10.0
        live_snap = {}
        while time.monotonic() < deadline:
            live_snap = client.get("/api/live/packets").json()
            if not live_snap["status"]["capture_alive"] and live_snap["status"]["packets_processed"] > 0:
                break
            time.sleep(0.05)

        assert live_snap["status"]["packets_processed"] > 1000
        lit = {st["lane"] for st in live_snap["pipeline_stages"] if st["active"]}
        assert {"LOBBY_TCP", "PROBE_30190", "UDP_CONNECT", "KCP_CONTROL", "PING_ECHO", "BATTLE_TICK", "TCP_MIRROR"} <= lit

        r_replay = client.get("/events?once=1", headers={"Last-Event-ID": str(baseline_id)})
        assert r_replay.status_code == 200
        replayed = _parse_sse(r_replay.text)
        assert any(ev in ("packet_batch", "match_update", "history_updated") for _, ev, _ in replayed)
        assert all(eid > baseline_id for eid, _, _ in replayed)

        # Save a note via POST /api/notes and trigger background rescan via POST /api/rescan.
        matches = client.get("/api/matches").json()["matches"]
        assert matches
        mk = matches[0]["match_key"]
        r_note = client.post("/api/notes", json={"match_key": mk, "host": "MY friend", "displayed_ping_ms": 38.5, "note": "api test"})
        assert r_note.status_code == 200
        assert r_note.json()["ok"] is True

        assert client.post("/api/notes", json={"match_key": ""}).status_code == 400
        assert client.post("/api/notes", json={"match_key": mk, "displayed_ping_ms": "bad"}).status_code == 400

        r_scan = client.post("/api/rescan", json={"force": False})
        assert r_scan.status_code == 200
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            ov = client.get("/api/overview").json()
            if not ov["scan"]["scanning"] and ov["total_servers"] >= 1:
                break
            time.sleep(0.05)

        srvs = client.get("/api/servers").json()["servers"]
        assert any(s["ip"] == "154.93.118.110" for s in srvs)

        r_stop = client.post("/api/source", json={"mode": "stop"})
        assert r_stop.status_code == 200
        assert r_stop.json()["status"]["source_mode"] == "IDLE"


def test_8_pick_loopback_port_fallback() -> None:
    blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    blocker.bind(("127.0.0.1", 0))
    blocker.listen(1)
    try:
        busy_port = blocker.getsockname()[1]
        with pytest.raises(OSError):
            pick_loopback_port(busy_port, allow_fallback=False)
        fallback = pick_loopback_port(busy_port, allow_fallback=True)
        assert fallback != busy_port
        assert fallback > busy_port
        assert pick_loopback_port(fallback, allow_fallback=False) == fallback
    finally:
        blocker.close()
