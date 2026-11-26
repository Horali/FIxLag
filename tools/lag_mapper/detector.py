"""Live 7-lane MLBB packet detector, multipath tracker, :30190 probe detector, and match enricher."""

from __future__ import annotations

import statistics
import time
from collections import defaultdict, deque
from typing import Any

from tools.chat_viewer.session import MatchStore, SessionRouter
from tools.chat_viewer.templates import TemplateResolver

from .classifier import PROBE_PORT, classify_ip, is_public_ipv4
from .pcap_net import NetPacket, classify_link
from .rtt import RttTracker
from .tcp_lobby import LOBBY_PORT, TcpLobbyDecoder

LANES: tuple[str, ...] = (
    "LOBBY_TCP",
    "PROBE_30190",
    "UDP_CONNECT",
    "KCP_CONTROL",
    "PING_ECHO",
    "BATTLE_TICK",
    "TCP_MIRROR",
)

_LANE_LABELS: dict[str, str] = {
    "LOBBY_TCP": "Lobby :30101",
    "PROBE_30190": "Probe :30190",
    "UDP_CONNECT": "UDP Connect 01 71/72",
    "KCP_CONTROL": "KCP Roster 1230/1202",
    "PING_ECHO": "Echo Ping 0x3f5",
    "BATTLE_TICK": "Battle 01 75",
    "TCP_MIRROR": "TCP Mirror +50",
}

_CONNECT_PREFIXES = (b"\x01\x71", b"\x01\x72", b"\x01\x73", b"\x01\x76")
_KCP_PREFIXES = (b"\x01\x51", b"\x41\x51", b"\x01\x52", b"\x41\x52")
_UNSET = object()


class LagPacketEngine:
    """Unified packet processor driving live detection feed, RTT, probes, TCP lobby, and match state."""

    def __init__(
        self,
        *,
        templates: TemplateResolver | None = None,
        zstd_path: Any = _UNSET,
        enable_zstd: bool = True,
        live_mode: bool = False,
        record_feed: bool = True,
        max_feed: int = 400,
    ) -> None:
        self.templates = templates if templates is not None else TemplateResolver()
        self.session_store = MatchStore(max_replay_log=256)
        self.router = SessionRouter(store=self.session_store, templates=self.templates)
        self.rtt = RttTracker()
        self.lobby = (
            TcpLobbyDecoder(enable_zstd=enable_zstd, live_mode=live_mode)
            if zstd_path is _UNSET
            else TcpLobbyDecoder(zstd_path=zstd_path, enable_zstd=enable_zstd, live_mode=live_mode)
        )
        self.record_feed = record_feed
        self.feed: deque[dict[str, Any]] = deque(maxlen=max_feed)
        self.start_ts: float | None = None
        self.last_ts: float | None = None
        self.packets_processed = 0
        self.skipped_truncated = 0

        self.lanes: dict[str, dict[str, Any]] = {
            lane: {"lane": lane, "label": _LANE_LABELS[lane], "packets": 0, "bytes": 0, "last_ts": None}
            for lane in LANES
        }
        self.multipath = {
            "wifi_out_pkts": 0,
            "wifi_in_pkts": 0,
            "cell_out_pkts": 0,
            "cell_in_pkts": 0,
            "other_out_pkts": 0,
            "other_in_pkts": 0,
            "wifi_bytes": 0,
            "cell_bytes": 0,
            "other_bytes": 0,
        }
        self._ep_flows: dict[tuple[str, int], dict[str, Any]] = {}
        self._tcp_5k: dict[tuple[str, int], dict[str, Any]] = {}
        self._tcp_mirror_promoted: set[tuple[str, int]] = set()
        self._last_active_ep: tuple[str, int] | None = None

        self._probe_out_sent: dict[tuple[str, str], tuple[float, str, str]] = {}
        self._probes_by_ip: dict[str, dict[str, Any]] = {}
        self._probe_sweeps: list[dict[str, Any]] = []

        self._seen_convs: set[tuple[tuple[str, int], str]] = set()
        self._last_battle_feed_ts: dict[tuple[str, int], float] = {}
        self._last_mirror_feed_ts: dict[tuple[str, int], float] = {}
        self._last_match_sig: dict[str, tuple[Any, ...]] = {}

    def reset(self) -> None:
        """Reset all protocol decoders, counters, and feeds."""
        self.session_store = MatchStore(max_replay_log=256)
        self.router = SessionRouter(store=self.session_store, templates=self.templates)
        self.rtt.reset()
        self.lobby.reset()
        self.feed.clear()
        self.start_ts = None
        self.last_ts = None
        self.packets_processed = 0
        self.skipped_truncated = 0
        for lane in LANES:
            self.lanes[lane] = {
                "lane": lane,
                "label": _LANE_LABELS[lane],
                "packets": 0,
                "bytes": 0,
                "last_ts": None,
            }
        for k in self.multipath:
            self.multipath[k] = 0
        self._ep_flows.clear()
        self._tcp_5k.clear()
        self._tcp_mirror_promoted.clear()
        self._last_active_ep = None
        self._probe_out_sent.clear()
        self._probes_by_ip.clear()
        self._probe_sweeps.clear()
        self._seen_convs.clear()
        self._last_battle_feed_ts.clear()
        self._last_mirror_feed_ts.clear()
        self._last_match_sig.clear()

    def _bump_lane(self, lane: str, ts: float, size_bytes: int) -> None:
        st = self.lanes[lane]
        st["packets"] += 1
        st["bytes"] += size_bytes
        st["last_ts"] = ts

    def _emit_feed(
        self,
        out: list[dict[str, Any]],
        *,
        ts: float,
        lane: str,
        summary: str,
        rule_matched: str,
        remote: str,
        link: str,
        size_bytes: int,
    ) -> None:
        if not self.record_feed:
            return
        rel_s = round(max(0.0, ts - (self.start_ts or ts)), 3)
        ev = {
            "ts": ts,
            "rel_s": rel_s,
            "lane": lane,
            "summary": summary,
            "rule_matched": rule_matched,
            "remote": remote,
            "link": link,
            "size_bytes": size_bytes,
        }
        self.feed.append(ev)
        out.append(ev)

    def _handle_lobby_events(self, raw_events: list[dict[str, Any]], out: list[dict[str, Any]]) -> None:
        for ev in raw_events:
            ev_type = ev.get("type", "LOBBY_EVENT")
            ts = float(ev.get("ts") or self.last_ts or 0.0)
            gw = str(ev.get("gateway_ip") or "")
            link = str(ev.get("link") or "Other")
            summary = str(ev.get("summary") or ev_type)
            self._emit_feed(
                out,
                ts=ts,
                lane="LOBBY_TCP",
                summary=summary,
                rule_matched=ev_type,
                remote=f"{gw}:{LOBBY_PORT}" if gw else f":{LOBBY_PORT}",
                link=link,
                size_bytes=0,
            )

    def flush(self) -> list[dict[str, Any]]:
        """Flush buffered TCP :30101 Zstd frames and emit decoded lobby events."""
        out: list[dict[str, Any]] = []
        self._handle_lobby_events(self.lobby.flush(), out)
        self._promote_tcp_mirrors()
        return out

    def _promote_tcp_mirrors(self) -> None:
        """Promote TCP `:port+50` flows whose matching UDP `:port` match endpoint appeared later."""
        for (rip, rport), info in self._tcp_5k.items():
            if (rip, rport) in self._tcp_mirror_promoted:
                continue
            if (rip, rport - 50) in self._ep_flows:
                self._tcp_mirror_promoted.add((rip, rport))
                self.lanes["TCP_MIRROR"]["packets"] += info["pkts"]
                self.lanes["TCP_MIRROR"]["bytes"] += info["bytes"]
                prev_ts = self.lanes["TCP_MIRROR"]["last_ts"]
                if prev_ts is None or info["last_ts"] > prev_ts:
                    self.lanes["TCP_MIRROR"]["last_ts"] = info["last_ts"]

    def on_packet(self, pkt: NetPacket, *, skipped_truncated: int = 0) -> dict[str, Any]:
        """Classify and process one IPv4 UDP/TCP packet, returning newly generated live events."""
        if self.start_ts is None:
            self.start_ts = pkt.ts
        self.last_ts = max(self.last_ts or pkt.ts, pkt.ts)
        self.packets_processed += 1
        self.skipped_truncated = skipped_truncated

        feed_events: list[dict[str, Any]] = []
        rtt_events: list[dict[str, Any]] = []
        match_changed = False

        if pkt.proto == "tcp":
            if pkt.sport == LOBBY_PORT or pkt.dport == LOBBY_PORT:
                remote_ip = pkt.src_ip if pkt.sport == LOBBY_PORT else pkt.dst_ip
                local_ip = pkt.dst_ip if pkt.sport == LOBBY_PORT else pkt.src_ip
                _, link_group = classify_link(local_ip, pkt.ifindex)
                first_lobby = self.lanes["LOBBY_TCP"]["packets"] == 0
                self._bump_lane("LOBBY_TCP", pkt.ts, len(pkt.payload))
                if first_lobby:
                    self._emit_feed(
                        feed_events,
                        ts=pkt.ts,
                        lane="LOBBY_TCP",
                        summary=f"TCP :{LOBBY_PORT} lobby stream opened ({remote_ip})",
                        rule_matched="TCP :30101",
                        remote=f"{remote_ip}:{LOBBY_PORT}",
                        link=link_group,
                        size_bytes=len(pkt.payload),
                    )
                lobby_evs = self.lobby.on_tcp_packet(pkt)
                self._handle_lobby_events(lobby_evs, feed_events)
            elif (5000 <= pkt.sport <= 6049) or (5000 <= pkt.dport <= 6049):
                self._on_tcp_5k(pkt, feed_events)
            return {"feed": feed_events, "rtt": rtt_events, "match_changed": False}

        # UDP paths
        if pkt.sport == PROBE_PORT or pkt.dport == PROBE_PORT:
            self._on_udp_30190(pkt, feed_events)
            return {"feed": feed_events, "rtt": rtt_events, "match_changed": False}

        if (5000 <= pkt.sport <= 5999 and pkt.sport != 5353) or (
            5000 <= pkt.dport <= 5999 and pkt.dport != 5353
        ):
            match_changed = self._on_udp_match(pkt, feed_events, rtt_events, skipped_truncated)

        return {"feed": feed_events, "rtt": rtt_events, "match_changed": match_changed}

    def _on_udp_30190(self, pkt: NetPacket, out: list[dict[str, Any]]) -> None:
        is_out = pkt.dport == PROBE_PORT
        remote_ip = pkt.dst_ip if is_out else pkt.src_ip
        local_ip = pkt.src_ip if is_out else pkt.dst_ip
        if not is_public_ipv4(remote_ip):
            return

        iface_label, link_group = classify_link(local_ip, pkt.ifindex)
        self._bump_lane("PROBE_30190", pkt.ts, len(pkt.payload))
        cls = classify_ip(remote_ip)

        rec = self._probes_by_ip.get(remote_ip)
        if rec is None:
            rec = {
                "ip": remote_ip,
                "provider": cls["provider"],
                "city": cls["city"],
                "confidence": cls["confidence"],
                "first_ts": pkt.ts,
                "last_ts": pkt.ts,
                "out_pkts": 0,
                "in_pkts": 0,
                "rtts": [],
                "links": set(),
                "ifaces": set(),
            }
            self._probes_by_ip[remote_ip] = rec
        rec["first_ts"] = min(rec["first_ts"], pkt.ts)
        rec["last_ts"] = max(rec["last_ts"], pkt.ts)
        rec["links"].add(link_group)
        rec["ifaces"].add(iface_label)

        # Group sweeps separated by > 30s quiet window.
        if not self._probe_sweeps or (pkt.ts - self._probe_sweeps[-1]["last_ts"]) > 30.0:
            self._probe_sweeps.append(
                {"first_ts": pkt.ts, "last_ts": pkt.ts, "ips": {remote_ip}, "reply_count": 0}
            )
        else:
            sw = self._probe_sweeps[-1]
            sw["last_ts"] = max(sw["last_ts"], pkt.ts)
            sw["ips"].add(remote_ip)

        if is_out:
            rec["out_pkts"] += 1
            self._probe_out_sent[(local_ip, remote_ip)] = (pkt.ts, iface_label, link_group)
            if rec["out_pkts"] == 1:
                self._emit_feed(
                    out,
                    ts=pkt.ts,
                    lane="PROBE_30190",
                    summary=f"Probe sweep -> {remote_ip} ({cls['provider']} / {cls['city']})",
                    rule_matched="UDP :30190 out",
                    remote=f"{remote_ip}:{PROBE_PORT}",
                    link=link_group,
                    size_bytes=len(pkt.payload),
                )
        else:
            rec["in_pkts"] += 1
            sent = self._probe_out_sent.pop((local_ip, remote_ip), None)
            rtt_ms: float | None = None
            if sent is not None:
                dt = (pkt.ts - sent[0]) * 1000.0
                if 0.5 <= dt <= 5000.0:
                    rtt_ms = round(dt, 1)
                    rec["rtts"].append(rtt_ms)
                    self._probe_sweeps[-1]["reply_count"] += 1
            if rtt_ms is not None or rec["in_pkts"] == 1:
                rtt_txt = f" ({rtt_ms:.1f} ms)" if rtt_ms is not None else ""
                self._emit_feed(
                    out,
                    ts=pkt.ts,
                    lane="PROBE_30190",
                    summary=f"Probe reply <- {remote_ip} ({cls['city']}){rtt_txt}",
                    rule_matched="UDP :30190 reply",
                    remote=f"{remote_ip}:{PROBE_PORT}",
                    link=link_group,
                    size_bytes=len(pkt.payload),
                )

    def _on_tcp_5k(self, pkt: NetPacket, out: list[dict[str, Any]]) -> None:
        is_out = 5000 <= pkt.dport <= 6049
        remote_ip = pkt.dst_ip if is_out else pkt.src_ip
        remote_port = pkt.dport if is_out else pkt.sport
        local_ip = pkt.src_ip if is_out else pkt.dst_ip
        if not is_public_ipv4(remote_ip):
            return

        iface_label, link_group = classify_link(local_ip, pkt.ifindex)
        key = (remote_ip, remote_port)
        info = self._tcp_5k.get(key)
        if info is None:
            info = {
                "ip": remote_ip,
                "port": remote_port,
                "pkts": 0,
                "out_pkts": 0,
                "in_pkts": 0,
                "bytes": 0,
                "ifaces": defaultdict(int),
                "links": defaultdict(int),
                "first_ts": pkt.ts,
                "last_ts": pkt.ts,
            }
            self._tcp_5k[key] = info
        info["pkts"] += 1
        info["out_pkts" if is_out else "in_pkts"] += 1
        info["bytes"] += len(pkt.payload)
        info["ifaces"][iface_label] += 1
        info["links"][link_group] += 1
        info["last_ts"] = max(info["last_ts"], pkt.ts)

        # Only treat as MLBB TCP input mirror when remote_port == match_port + 50.
        if (remote_ip, remote_port - 50) in self._ep_flows:
            if key not in self._tcp_mirror_promoted:
                self._tcp_mirror_promoted.add(key)
                self.lanes["TCP_MIRROR"]["packets"] += info["pkts"]
                self.lanes["TCP_MIRROR"]["bytes"] += info["bytes"]
                self.lanes["TCP_MIRROR"]["last_ts"] = pkt.ts
            else:
                self._bump_lane("TCP_MIRROR", pkt.ts, len(pkt.payload))

            last_f = self._last_mirror_feed_ts.get(key, -1e18)
            if pkt.ts - last_f >= 1.0:
                self._last_mirror_feed_ts[key] = pkt.ts
                self._emit_feed(
                    out,
                    ts=pkt.ts,
                    lane="TCP_MIRROR",
                    summary=f"TCP :{remote_port} input mirror ({info['out_pkts']} out / {info['in_pkts']} in pkts)",
                    rule_matched="TCP :match_port+50",
                    remote=f"{remote_ip}:{remote_port}",
                    link=link_group,
                    size_bytes=len(pkt.payload),
                )

    def _on_udp_match(
        self,
        pkt: NetPacket,
        feed_out: list[dict[str, Any]],
        rtt_out: list[dict[str, Any]],
        skipped_truncated: int,
    ) -> bool:
        is_out = 5000 <= pkt.dport <= 5999 and pkt.dport != 5353
        remote_ip = pkt.dst_ip if is_out else pkt.src_ip
        remote_port = pkt.dport if is_out else pkt.sport
        local_ip = pkt.src_ip if is_out else pkt.dst_ip
        if not is_public_ipv4(remote_ip):
            return False

        direction = "out" if is_out else "in"
        ep = (remote_ip, remote_port)
        self._last_active_ep = ep
        iface_label, link_group = classify_link(local_ip, pkt.ifindex)
        pkt_len = len(pkt.payload)

        if link_group == "Wi-Fi":
            self.multipath["wifi_out_pkts" if is_out else "wifi_in_pkts"] += 1
            self.multipath["wifi_bytes"] += pkt_len
        elif link_group == "Cellular":
            self.multipath["cell_out_pkts" if is_out else "cell_in_pkts"] += 1
            self.multipath["cell_bytes"] += pkt_len
        else:
            self.multipath["other_out_pkts" if is_out else "other_in_pkts"] += 1
            self.multipath["other_bytes"] += pkt_len

        ef = self._ep_flows.get(ep)
        if ef is None:
            ef = {
                "wifi_out_pkts": 0,
                "wifi_in_pkts": 0,
                "cell_out_pkts": 0,
                "cell_in_pkts": 0,
                "other_out_pkts": 0,
                "other_in_pkts": 0,
                "wifi_bytes": 0,
                "cell_bytes": 0,
                "other_bytes": 0,
                "ifaces": defaultdict(int),
                "local_ips": set(),
                "first_ts": pkt.ts,
                "last_ts": pkt.ts,
            }
            self._ep_flows[ep] = ef
            self._promote_tcp_mirrors()

        if link_group == "Wi-Fi":
            ef["wifi_out_pkts" if is_out else "wifi_in_pkts"] += 1
            ef["wifi_bytes"] += pkt_len
        elif link_group == "Cellular":
            ef["cell_out_pkts" if is_out else "cell_in_pkts"] += 1
            ef["cell_bytes"] += pkt_len
        else:
            ef["other_out_pkts" if is_out else "other_in_pkts"] += 1
            ef["other_bytes"] += pkt_len
        ef["ifaces"][iface_label] += 1
        ef["local_ips"].add(local_ip)
        ef["last_ts"] = max(ef["last_ts"], pkt.ts)

        prev_sigs = dict(self._last_match_sig)
        self.router.on_packet(pkt.to_udp_packet(), skipped_truncated=skipped_truncated)

        new_samples = self.rtt.on_udp_packet(pkt, ep=ep, direction=direction)
        for sample in new_samples:
            self._bump_lane("PING_ECHO", sample.ts, pkt_len)
            rtt_out.append(
                {
                    "ep": f"{ep[0]}:{ep[1]}",
                    "ts": sample.ts,
                    "rel_s": round(max(0.0, sample.ts - (self.start_ts or sample.ts)), 2),
                    "rtt_ms": round(sample.rtt_ms, 1),
                    "link": sample.link_group,
                    "local_ip": sample.local_ip,
                }
            )
            self._emit_feed(
                feed_out,
                ts=sample.ts,
                lane="PING_ECHO",
                summary=f"0x3f5 echo RTT {sample.rtt_ms:.1f} ms via {sample.link_group} ({sample.local_ip})",
                rule_matched="0x3f5 -> mid=0",
                remote=f"{ep[0]}:{ep[1]}",
                link=sample.link_group,
                size_bytes=pkt_len,
            )

        prefix = pkt.payload[:2]
        if prefix in _CONNECT_PREFIXES:
            self._bump_lane("UDP_CONNECT", pkt.ts, pkt_len)
            conv_hex = pkt.payload[2:6].hex() if len(pkt.payload) >= 6 else ""
            ckey = (ep, f"{prefix.hex()}:{conv_hex}")
            if ckey not in self._seen_convs:
                self._seen_convs.add(ckey)
                cls = classify_ip(remote_ip)
                cmd_name = {
                    b"\x01\x71": "connect 01 71",
                    b"\x01\x72": "rebind/ack 01 72",
                    b"\x01\x73": "keepalive 01 73",
                    b"\x01\x76": "multipath 01 76",
                }.get(prefix, prefix.hex())
                self._emit_feed(
                    feed_out,
                    ts=pkt.ts,
                    lane="UDP_CONNECT",
                    summary=f"UDP {cmd_name} conv={conv_hex} ({cls['provider']} / {cls['city']})",
                    rule_matched=f"UDP {prefix[:1].hex()} {prefix[1:2].hex()}",
                    remote=f"{ep[0]}:{ep[1]}",
                    link=link_group,
                    size_bytes=pkt_len,
                )
        elif prefix in _KCP_PREFIXES:
            self._bump_lane("KCP_CONTROL", pkt.ts, pkt_len)
        elif prefix == b"\x01\x75":
            self._bump_lane("BATTLE_TICK", pkt.ts, pkt_len)
            last_b = self._last_battle_feed_ts.get(ep, -1e18)
            if pkt.ts - last_b >= 1.0:
                self._last_battle_feed_ts[ep] = pkt.ts
                sess = next((m for m in reversed(self.session_store.get_matches()) if m.ep == ep), None)
                tick_txt = f"tick={sess.battle.max_tick_seen}, mode={sess.battle.mode}" if sess else "battle frame"
                self._emit_feed(
                    feed_out,
                    ts=pkt.ts,
                    lane="BATTLE_TICK",
                    summary=f"Battle 01 75 ({tick_txt})",
                    rule_matched="01 75 03 01 46",
                    remote=f"{ep[0]}:{ep[1]}",
                    link=link_group,
                    size_bytes=pkt_len,
                )

        # Detect meaningful match roster/phase updates for KCP feed & SSE fan-out.
        match_changed = False
        for m in self.session_store.get_matches():
            sig = (
                m.battle_id,
                m.phase,
                m.mode_label,
                len(m.players_by_uid),
                m.rebind_count,
                m.local_uid,
                m.local_camp,
                tuple(sorted((p.uid, p.hero_id) for p in m.players_by_uid.values())),
            )
            if prev_sigs.get(m.match_id) != sig:
                self._last_match_sig[m.match_id] = sig
                match_changed = True
                if prefix in _KCP_PREFIXES:
                    self._emit_feed(
                        feed_out,
                        ts=pkt.ts,
                        lane="KCP_CONTROL",
                        summary=(
                            f"KCP {m.phase} {m.mode_label or 'MLBB'} "
                            f"players={len(m.players_by_uid)} battle={m.battle_id or '-'}"
                        ),
                        rule_matched="KCP 01 51 / 41 51",
                        remote=f"{m.ep[0]}:{m.ep[1]}",
                        link=link_group,
                        size_bytes=pkt_len,
                    )
        return match_changed

    def get_probes_list(self) -> list[dict[str, Any]]:
        """Return sorted list of detected `:30190` probe targets."""
        out: list[dict[str, Any]] = []
        for rec in self._probes_by_ip.values():
            rtts = rec["rtts"]
            out.append(
                {
                    "ip": rec["ip"],
                    "provider": rec["provider"],
                    "city": rec["city"],
                    "confidence": rec["confidence"],
                    "first_ts": rec["first_ts"],
                    "last_ts": rec["last_ts"],
                    "out_pkts": rec["out_pkts"],
                    "in_pkts": rec["in_pkts"],
                    "min_rtt_ms": round(min(rtts), 1) if rtts else None,
                    "median_rtt_ms": round(statistics.median(rtts), 1) if rtts else None,
                    "links": sorted(rec["links"]),
                    "ifaces": sorted(rec["ifaces"]),
                }
            )
        out.sort(key=lambda r: (r["first_ts"], r["ip"]))
        return out

    def _enrich_players_and_party(self, m: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        raw_players = m.get("players") or []
        local_uid = m.get("local_uid")
        local_camp = m.get("local_camp")
        ally_camp = local_camp if local_camp in (1, 2) else 1

        local_room_id: int | None = None
        for p in raw_players:
            if local_uid is not None and p.get("uid") == local_uid:
                local_room_id = p.get("room_id")
                break

        enriched: list[dict[str, Any]] = []
        ally_party_players: list[dict[str, Any]] = []
        enemy_rooms: dict[int, int] = defaultdict(int)
        enemy_no_room = 0

        for p in raw_players:
            name = str(p.get("name") or "")
            geo = self.lobby.lobby_geo_by_name.get(name, "")
            ep_row = dict(p)
            ep_row["lobby_geo"] = geo
            ep_row["is_local"] = local_uid is not None and p.get("uid") == local_uid
            enriched.append(ep_row)

            camp = p.get("camp")
            rid = p.get("room_id")
            if camp == ally_camp:
                if local_room_id is not None and rid == local_room_id:
                    ally_party_players.append(ep_row)
                elif local_room_id is None and ep_row["is_local"]:
                    ally_party_players.append(ep_row)
            elif camp in (1, 2):
                if isinstance(rid, int) and rid > 0:
                    enemy_rooms[rid] += 1
                else:
                    enemy_no_room += 1

        if not ally_party_players:
            ally_party_players = [p for p in enriched if p.get("camp") == ally_camp]

        party_cc_counts: dict[str, int] = defaultdict(int)
        for p in ally_party_players:
            cc = str(p.get("country") or "").upper()
            if cc:
                party_cc_counts[cc] += 1

        party_label = str(m.get("party_label") or "")
        if not party_label and m.get("pvp_type") == 6:
            party_label = "Custom"
        if party_cc_counts:
            cc_parts = []
            for cc, cnt in sorted(party_cc_counts.items(), key=lambda kv: (-kv[1], kv[0])):
                cc_parts.append(f"{cnt} {cc}" if cnt > 1 else cc)
            mix_core = " + ".join(cc_parts)
            party_mix_label = f"{party_label}: {mix_core}" if party_label else mix_core
        else:
            party_mix_label = party_label or "Unknown"

        enemy_stacks = sorted(enemy_rooms.values(), reverse=True)
        if enemy_no_room:
            enemy_stacks.extend([1] * enemy_no_room)

        return enriched, {
            "ally_party_players": ally_party_players,
            "ally_party_countries": dict(sorted(party_cc_counts.items())),
            "party_mix_label": party_mix_label,
            "enemy_stack_sizes": enemy_stacks,
        }

    def build_match_records(self, *, source_name: str, origin: str) -> list[dict[str, Any]]:
        """Build full lag-enriched match records across all decoded sessions."""
        matches = self.session_store.get_matches_snapshot()
        all_probes = self.get_probes_list()
        out: list[dict[str, Any]] = []

        for m in matches:
            ip = str(m.get("server_ip") or "")
            port = int(m.get("server_port") or 0)
            if not is_public_ipv4(ip):
                continue

            ep = (ip, port)
            first_ts = float(m.get("first_ts") or 0.0)
            last_ts = float(m.get("last_ts") or first_ts)
            cls = classify_ip(ip)
            rtt_sum = self.rtt.summarize_endpoint(ep, start_ts=first_ts - 1.0, end_ts=last_ts + 2.0)

            ef = self._ep_flows.get(ep, {})
            tcp_m = self._tcp_5k.get((ip, port + 50))
            players, party_meta = self._enrich_players_and_party(m)

            matched_handover = None
            best_h_dist = 1e18
            for ho in self.lobby.handovers:
                if ho["target_ip"] == ip and ho["target_port"] == port:
                    dist = abs(first_ts - float(ho["ts"]))
                    if dist < best_h_dist and float(ho["ts"]) <= first_ts + 30.0:
                        best_h_dist = dist
                        matched_handover = dict(ho)

            assoc_probes = [
                p for p in all_probes if (first_ts - 120.0) <= float(p["first_ts"]) <= last_ts
            ]

            bid = str(m.get("battle_id") or "").strip()
            match_key = f"bid:{bid}" if bid else f"ep:{ip}:{port}:{int(first_ts)}"

            wifi_pkts = int(ef.get("wifi_out_pkts", 0)) + int(ef.get("wifi_in_pkts", 0))
            cell_pkts = int(ef.get("cell_out_pkts", 0)) + int(ef.get("cell_in_pkts", 0))
            other_pkts = int(ef.get("other_out_pkts", 0)) + int(ef.get("other_in_pkts", 0))
            ifaces_dict = ef.get("ifaces") or {}

            out.append(
                {
                    "match_key": match_key,
                    "origin": origin,
                    "source_name": source_name,
                    "match_id": m.get("match_id"),
                    "battle_id": bid or None,
                    "server_ip": ip,
                    "server_port": port,
                    "subnet": cls["subnet"],
                    "provider": cls["provider"],
                    "city": cls["city"],
                    "confidence": cls["confidence"],
                    "cluster_key": cls["cluster_key"],
                    "approx_coords": cls["approx_coords"],
                    "first_ts": first_ts,
                    "last_ts": last_ts,
                    "duration_s": round(max(0.0, last_ts - first_ts), 1),
                    "phase": m.get("phase") or "IDLE",
                    "mode_label": m.get("mode_label") or "",
                    "pvp_type": m.get("pvp_type"),
                    "map_id": m.get("map_id"),
                    "party_label": m.get("party_label") or "",
                    "party_mix_label": party_meta["party_mix_label"],
                    "local_party_size": m.get("local_party_size"),
                    "ally_party_countries": party_meta["ally_party_countries"],
                    "ally_party_players": party_meta["ally_party_players"],
                    "enemy_stack_sizes": party_meta["enemy_stack_sizes"],
                    "country_counts": m.get("country_counts") or {},
                    "local_uid": m.get("local_uid"),
                    "local_camp": m.get("local_camp"),
                    "players": players,
                    "battle_mode": m.get("battle_mode"),
                    "max_tick_seen": m.get("max_tick_seen"),
                    "convs": m.get("convs") or [],
                    "rebind_count": int(m.get("rebind_count") or 0),
                    "ifaces": sorted(ifaces_dict, key=lambda k: -ifaces_dict[k]),
                    "multipath": {
                        "wifi_out_pkts": int(ef.get("wifi_out_pkts", 0)),
                        "wifi_in_pkts": int(ef.get("wifi_in_pkts", 0)),
                        "cell_out_pkts": int(ef.get("cell_out_pkts", 0)),
                        "cell_in_pkts": int(ef.get("cell_in_pkts", 0)),
                        "other_out_pkts": int(ef.get("other_out_pkts", 0)),
                        "other_in_pkts": int(ef.get("other_in_pkts", 0)),
                        "wifi_pkts": wifi_pkts,
                        "cell_pkts": cell_pkts,
                        "other_pkts": other_pkts,
                    },
                    "rtt": rtt_sum,
                    "tcp_mirror": (
                        {
                            "port": tcp_m["port"],
                            "pkts": tcp_m["pkts"],
                            "out_pkts": tcp_m["out_pkts"],
                            "in_pkts": tcp_m["in_pkts"],
                            "bytes": tcp_m["bytes"],
                            "ifaces": sorted(tcp_m["ifaces"]),
                        }
                        if tcp_m is not None
                        else None
                    ),
                    "handover": matched_handover,
                    "probes": assoc_probes,
                    "probe_count": len(assoc_probes),
                    "host": "",
                    "displayed_ping_ms": None,
                    "note": cls["note"],
                    "label": "",
                    "csv_party": "",
                }
            )
        return out

    def get_live_packets_snapshot(self) -> dict[str, Any]:
        """Return full live detector telemetry (7 lanes, multipath, RTT series, probes, feed)."""
        wifi_total = self.multipath["wifi_out_pkts"] + self.multipath["wifi_in_pkts"]
        cell_total = self.multipath["cell_out_pkts"] + self.multipath["cell_in_pkts"]
        other_total = self.multipath["other_out_pkts"] + self.multipath["other_in_pkts"]
        grand_total = wifi_total + cell_total + other_total

        ep = self._last_active_ep
        if ep is not None:
            rtt_summary = self.rtt.summarize_endpoint(ep)
            ep_cls = classify_ip(ep[0])
            active_ep_info = {
                "ep": f"{ep[0]}:{ep[1]}",
                "ip": ep[0],
                "port": ep[1],
                "provider": ep_cls["provider"],
                "city": ep_cls["city"],
                "confidence": ep_cls["confidence"],
            }
        else:
            rtt_summary = {"links": {"Wi-Fi": {}, "Cellular": {}, "Combined": {}}, "by_iface_ip": {}, "series": []}
            active_ep_info = None

        live_matches = self.build_match_records(source_name="Live session", origin="live")
        return {
            "lanes": [dict(self.lanes[k]) for k in LANES],
            "pipeline_stages": [
                {
                    "lane": lane,
                    "label": _LANE_LABELS[lane],
                    "active": self.lanes[lane]["packets"] > 0,
                    "packets": self.lanes[lane]["packets"],
                    "bytes": self.lanes[lane]["bytes"],
                }
                for lane in LANES
            ],
            "multipath": {
                **self.multipath,
                "wifi_pkts": wifi_total,
                "cell_pkts": cell_total,
                "other_pkts": other_total,
                "total_pkts": grand_total,
                "wifi_pct": round((wifi_total / grand_total) * 100.0, 1) if grand_total else 0.0,
                "cell_pct": round((cell_total / grand_total) * 100.0, 1) if grand_total else 0.0,
            },
            "active_endpoint": active_ep_info,
            "rtt": rtt_summary,
            "probes": self.get_probes_list(),
            "probe_sweeps": [
                {
                    "first_ts": sw["first_ts"],
                    "last_ts": sw["last_ts"],
                    "target_count": len(sw["ips"]),
                    "reply_count": sw["reply_count"],
                }
                for sw in self._probe_sweeps
            ],
            "handovers": list(self.lobby.handovers),
            "lobby_stats": {
                "zstd_available": self.lobby.zstd_available,
                "raw_frames": self.lobby.raw_frames,
                "zstd_frames": self.lobby.zstd_frames,
                "skipped_zstd_frames": self.lobby.skipped_zstd_frames,
                "dropped_pii_frames": self.lobby.dropped_pii_frames,
                "geo_player_count": len(self.lobby.lobby_geo_by_name),
            },
            "feed": list(self.feed),
            "active_match": live_matches[-1] if live_matches else None,
        }
