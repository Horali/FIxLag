# FIxLag Server & Live Packet Mapper — Engineering Specification

**Target package:** `tools/lag_mapper/` + `tests/test_lag_mapper.py`
**Bind address:** Strictly `http://127.0.0.1:8766` (default port `8766` so it can run alongside `tools/chat_viewer` on `8765`)
**Capture mode:** Strictly passive PCAP only (live rooted `adb exec-out` tcpdump or local `.pcap` files). Never touch game memory, inject code, or interact with anti-cheat surfaces (see `docs/handoff.md` §9).

---

## 1. Goals & Honest Protocol Boundaries

Queen Hora wants a localhost web tool to:
1. **Map all visited MLBB match servers** (provider, city/subnet classification, match counts, Wi-Fi vs cellular UDP RTT) across historical captures (`captures/*.pcap`), logged matches (`data/matches.csv`), and live sessions.
2. **Watch packet detection live** — showing each protocol stage as it fires (`:30101` lobby TCP, `:30190` ping sweep, `01 71/72` UDP connect/rebind, `KCP` roster & draft, `0x3f5` echo ping, `01 75` battle ticks, `TCP :port+50` input mirror) and the live Wi-Fi vs cellular multipath split.
3. **Analyze Lobby, Party, Mode & Ping Impact** — showing the current or selected match's game mode, party grouping, party members' countries/lobby regions, manual/saved host attribution, and how party composition + host correlate with the selected match server and measured ping.

### Honest protocol limits (must be shown clearly in UI & docs)
- **Friends' IP addresses are NOT visible on the wire.** MLBB uses a client-server architecture through Moonton servers, not peer-to-peer links.
- **What IS passively visible on the wire:**
  - Every player's `sThisLoginCountry` ISO code (`ID`, `MY`, `SG`, `MV`, `IN`, etc.), `uiZoneId`, and `bRobot` flag (`mid=1230` / `1202` / `1203`).
  - Exact party grouping per camp via `ulRoomID` (who queued together in a room, exact stack size `Solo`..`5-stack`, and enemy stacks).
  - Match game mode via `iPVPType` + `uiMapID` (`Ranked`, `Classic`, `Brawl`, `Custom Draft`, etc.).
  - Pre-match lobby `:30101` coarse region/city strings (`country|region|city`, e.g. `my|Johor|Johor Baharu`) for players loaded in lobby cards.
  - Pre-match server handover (`mid=20008` on TCP `:30101`), cold-start `:30190` probe sweeps, and live per-link UDP RTT (`0x3f5` echo) + TCP `:port+50` input mirroring.
- **Party Host ("who clicked Create Lobby"):** Not confirmed reliably on match UDP (`ulRoomID` identifies the group, not who created it). Support an inline UI selector (`Me (ID)` / `MY friend` / `SG friend` / etc.) persisted per match in local `data/lag_mapper_notes.json` and seeded from `data/matches.csv` `host`.

### Hard technical & privacy rules
- **Zero new pip dependencies:** Python `3.12`, already-installed `starlette`, `uvicorn`, `pytest`, `httpx`, and pure-Python stdlib (`zlib`, `csv`, `json`, `ipaddress`, `statistics`, `subprocess`, `threading`, `asyncio`).
- **Read-only code reuse:** Import helpers read-only from `tools/chat_viewer/` (`kcp.py`, `protocol.py`, `session.py`, `ingest.py`) and `tools/draft_probe.py` (`KNOWN_IP`, `PREFIX_HINTS`, `PRIVATE_V4`, `IFACE_NAMES`, `IGNORED_PORTS`). **Do NOT modify `tools/chat_viewer/` or `tools/draft_probe.py`.**
- **Zstd on TCP `:30101`:** Decompress `flag=0x10` (`28 b5 2f fd`) frames using `C:\msys64\ucrt64\bin\zstd.EXE -d --stdout` (or `shutil.which("zstd")` / optional `zstandard` if present). If neither exists, skip `0x10` Zstd frames gracefully without crashing.
- **Privacy & PII filtering:** **NEVER** decode, log, cache, or display account/auth packets — explicitly drop/ignore `mid=10208` (contains email/login strings) and redact any email/token patterns. Persist caches and notes only inside gitignored `data/`.

---

## 2. Verified Wire Formats to Implement

### 2.1 PCAP & Link Layer Parser (`tools/lag_mapper/pcap_net.py`)
Reuse/extend incremental PCAP parsing to emit both **IPv4 UDP** and **IPv4 TCP** packets (`NetPacket`):
- Support PCAP magics `0xa1b2c3d4`, `0xa1b23c4d`, `0xd4c3b2a1`, `0x4d3cb2a1` (incremental chunk boundary safe across arbitrary reads, `InvalidPcapMagicError` on invalid header).
- Skip truncated records (`orig_len > incl_len`) and increment `skipped_truncated`.
- Support link types:
  - `101` (RAW IPv4)
  - `1` (Ethernet, stripping stacked `0x8100` VLAN tags)
  - `113` (Linux SLL v1)
  - `276` (Linux SLL2 — extract 4-byte `ifindex` at offset 4..8)
- Parse IPv4 (`proto=17` UDP and `proto=6` TCP) extracting: `ts`, `src_ip`, `dst_ip`, `sport`, `dport`, `proto` (`"udp"` | `"tcp"`), `payload`, `ifindex` (`int | None`), `tcp_seq` (`int`), `tcp_flags` (`int`).
- **Interface attribution (`classify_link(local_ip, ifindex)`):**
  - If `ifindex == 44` -> `"wlan0"` (`"Wi-Fi"`); if `ifindex in (62, 63, 123)` -> `"rmnet_data0"` (`"Cellular"`); if `ifindex == 14` -> `"rmnet_ipa0"` (`"Cellular"`).
  - Fallback when `ifindex is None` (e.g., PCAPdroid RAWcaptures like `draft_LIVE6.pcap`): private RFC1918 `192.168.0.0/16` or `172.16.0.0/12` -> `"Wi-Fi"`; carrier NAT `10.0.0.0/8` or `100.64.0.0/10` -> `"Cellular"`.
  - Allow per-capture UI/query distinction by both `(iface_label, local_ip)`.

### 2.2 ADB Live Capture (`tools/lag_mapper/ingest.py`)
- Reuse `find_adb`, `list_adb_devices` pattern from `tools/chat_viewer/ingest.py` (`C:\Users\child\AppData\Local\Android\Sdk\platform-tools\adb.exe`, always `-s <serial>`).
- Default BPF filter covering every MLBB network surface:
  ```text
  (udp portrange 5000-5999 and not port 5353) or udp port 30190 or tcp port 30101 or tcp portrange 5000-6049
  ```
  (Note: `6049` covers the outbound `TCP :match_port+50` input mirror!)
- Optional `.pcap` tee to `captures/live_lag_YYYYMMDD_HHMMSS.pcap`, plus static PCAP replay and live growing-file follow.

### 2.3 Per-Interface UDP RTT from `0x3f5` (`1013`) Ping Echoes (`tools/lag_mapper/rtt.py`)
Verified directly against `captures/draft_LIVE6.pcap`:
- **Outbound echo request** (to match `ep`, on `01 51` or `01 75` or inside KCP):
  Contains SDP envelope `70 00 f5 07` (`mid=1013`) with nested `('b', 5)` (`tag=0x45`, length varint, body `70 00 <client_ts_varint> [0x80...]`).
  Extract exact `<client_ts_varint>` integer.
- **Inbound echo reply** (from match `ep`, KCP `01 51` reassembled payload):
  Contains `70 00 00` (`mid=0` ack/echo) and `('b', 6)` (`tag=0x46`, length varint, body `70 00 <client_ts_varint> ...`).
  Extract exact `<client_ts_varint>`.
- **Matching rule:**
  Record latest outbound send `(out_ts, link_key)` keyed by `(ep, local_ip, client_ts_varint)` (fallback `(ep, client_ts_varint)` if NAT rewrote local IP). On matching inbound, compute `rtt_ms = (in_ts - out_ts) * 1000.0`, accepting `0.5 <= rtt_ms <= 5000.0`.
- **Metrics computed per match & per link (`Wi-Fi`, `Cellular`, `Combined`):**
  `sample_count`, `min_ms`, `median_ms`, `p95_ms`, `max_ms`, `jitter_ms` (median of `|rtt[i] - rtt[i-1]|`), plus downsampled `(rel_s, rtt_ms, link)` points (up to 180 points/link) for the SVG sparkline.
- **Verified benchmark (`draft_LIVE6.pcap` Match 1 `149.104.112.216:5507`):**
  - Wi-Fi `192.168.1.17`: ~1,004 samples, median ~39.3 ms, p95 ~55.6 ms.
  - Cellular `10.156.63.86`: ~1,009 samples, median ~54.0 ms, p95 ~68.3 ms.

### 2.4 Pre-Match Probe Sweep `:30190` Detector
- Track all UDP packets where `sport == 30190 or dport == 30190`.
- Record unique candidate server IPs, probe send timestamp, first reply timestamp + probe RTT (`ms`) when an inbound `:30190` response matches the outbound destination, interface/link used, and provider/city guess.
- Associate probe sweeps with subsequent matches that start within 120 seconds (or record standalone pre-match sweeps when no match started yet).

### 2.5 TCP `:30101` Lobby Gateway Decoder (`tools/lag_mapper/tcp_lobby.py`)
- Reassemble bidirectional TCP streams per `(src_ip, sport, dst_ip, dport)` ordered by `tcp_seq` (bounded buffer <= 4 MiB/stream, trimming overlap safely).
- Parse outer frames `[flag:1][total_len:3 BE]`:
  - `flag == 0x00`: body is `frame[4:total_len]`
  - `flag == 0x10`: if body starts with `\x28\xb5\x2f\xfd`, decompress via batch/streaming `zstd -d` helper (note: spawning `zstd.EXE` per frame on 1,890 frames in `draft_LIVE6.pcap` would be slow if repeated naive subprocesses — **cache decompressed frames or fast-pre-filter by frame length / skip `10208` / only run `zstd` synchronously in background scan or batch stdin if possible, or benchmark `zstd.EXE` speed first!** Wait: check `mid` extraction — for `draft_LIVE6.pcap`, `1890` subprocess calls took ~16s total; to stay super snappy, skip huge non-relevant frames only AFTER checking? No, `mid` is inside Zstd; optimize by keeping a worker thread / caching results per PCAP in `data/lag_mapper_cache.json`!).
- Allowlisted `mid` handlers (strictly drop `mid == 10208` before string extraction!):
  - `mid=20008` (match handover): extract `ip:port` regex `r"\b(?:\d{1,3}\.){3}\d{1,3}:\d{4,5}\b"` (and gateway IP) + timestamp -> emits `LOBBY_HANDOVER` event linking lobby to upcoming match server.
  - `mid=10144`, `mid=11169`, `mid=11499` (room/player geo cards): parse readable player handle + coarse geo pattern `r"\b[a-z]{2}\|[A-Za-z0-9 _-]+\|[A-Za-z0-9 _-]+\b"` (and Country / Province labels) -> stores in `lobby_geo_by_name[name]`, used only to enrich matched party/match players.
  - `mid=10017` (telemetry trace): extract `client_room_trace` / phase keywords when present -> emits lightweight `LOBBY_TRACE` event to live detector feed.

### 2.6 Match Roster, Mode, Party Grouping & Battle/Input Streams
- Feed UDP `5000..5999` (excluding `5353`) into `KcpStreamReassembler` and `parse_mlbb_struct`:
  - Parse `mid=1001` (outbound `local_uid`), `mid=1242`, `mid=1230`, `mid=1202`, `mid=1203`, and `Play_<battle_id>_1` login banner.
  - Extract `mode_label` (`format_mode_label`), `local_camp`, `local_uid`, players (`uid`, `name`, `camp`, `seat`, `is_bot`, `country`, `zone_id`, `room_id`), and per-camp `ulRoomID` grouping (`local_party_size`, `party_label`, `ally_party_players`, `enemy_stack_sizes`).
- Detect TCP `dport == match_port + 50` (simultaneous input mirror flow on `5000..6049`, outbound-only telemetry) and record `tcp_mirror_port`, `tcp_mirror_pkts`, `tcp_mirror_bytes`, `tcp_mirror_ifaces`.
- Track packet & flow stats per match (`wifi_out_pkts`, `wifi_in_pkts`, `cell_out_pkts`, `cell_in_pkts`, `convs`, `rebind_count`, `battle_mode` (`LZW-16 0x42` vs `raw 0x52`), `max_tick_seen`).

### 2.7 Server Classification & `data/matches.csv` Ingestion (`tools/lag_mapper/classifier.py`, `aggregator.py`)
- Import `KNOWN_IP`, `PREFIX_HINTS`, `PRIVATE_V4` from `tools/draft_probe.py`.
- Add extra verified subnets observed across captures without inventing unverified providers:
  - Keep `149.104.112.0/24` as `"Observed (Singapore/BGP?)"` (`"observed"` / `"prefix"` confidence) unless RDAP/whois verified — **do not guess provider names**!
  - Mark confidence clearly: `"known"` (exact IP in `KNOWN_IP`), `"prefix"` (matches `PREFIX_HINTS` `/24` or `/16`), `"csv"` (from `data/matches.csv`), `"observed"` (new unmapped subnet).
- Ingest `data/matches.csv` using its actual header:
  `ts,label,host,displayed_ping_ms,endpoint,port,provider,city_geo,confidence,ifaces,out_pkts,in_pkts,duration_s,other_endpoints,party,note`
- Deduplicate `data/matches.csv` rows against decoded `captures/*.pcap` matches when `(endpoint, port)` match AND ISO timestamp is within +/- 180 seconds (merging CSV `host`, `displayed_ping_ms`, `label`, `note`, and parsed `party` text into the richer PCAP match record).

### 2.8 Live Packet Detector Feed (`tools/lag_mapper/detector.py`)
- Emit structured detection events (`ts`, `rel_s`, `lane`, `summary`, `rule_matched`, `remote`, `link`, `size_bytes`) across 8 named protocol lanes:
  1. `LOBBY_TCP` (`tcp/30101`: Zstd/raw TLV, `mid=20008` handover, `mid=10017` trace, geo cards)
  2. `PROBE_30190` (`udp/30190`: candidate server probe targets & reply RTT)
  3. `UDP_CONNECT` (`01 71` / `01 72` / `01 73` / `01 76` conv setup & multipath rebind)
  4. `KCP_CONTROL` (`01 51` / `41 51`: roster `1242`/`1230`/`1202`/`1203`, `Play_<bid>_1`, `1101` draft/loading)
  5. `PING_ECHO` (`0x3f5` (`1013`) outbound request <-> inbound `mid=0` echo RTT)
  6. `BATTLE_TICK` (`01 75` `03 01 46`: `0x42` LZW-16 or `0x52` raw tick stream — coalesce into 1 Hz summary events so UI stays responsive)
  7. `TCP_MIRROR` (`tcp/match_port+50` outbound 4-way simultaneous input mirror)
- Maintain live lane counters (packets, bytes, last seen ts), Wi-Fi vs Cellular % breakdown, and a bounded 400-event ring buffer broadcast throttled over SSE.

---

## 3. Target Module Architecture

```
tools/lag_mapper/
  __init__.py
  __main__.py      # CLI: python -m tools.lag_mapper [--port 8766] [--pcap X] [--follow] [--serial S] [--no-browser]
  pcap_net.py      # Incremental PCAP reader for IPv4 UDP + TCP across RAW/Eth/SLL/SLL2
  tcp_lobby.py     # Sequence-ordered TCP :30101 stream reassembler + batch/cached Zstd + allowlisted mids
  rtt.py           # 0x3f5 (1013) outbound/inbound echo matcher per link (Wi-Fi vs Cellular + jitter)
  classifier.py    # KNOWN_IP + PREFIX_HINTS (imported from draft_probe.py) + observed subnets
  detector.py      # Live 8-lane packet classification + bounded event feed + multipath counters
  aggregator.py    # Background captures/*.pcap indexer (cached in data/lag_mapper_cache.json), matches.csv + notes merge, Server Map & Party-vs-Ping correlations
  ingest.py        # ADB live tcpdump pipeline + PCAP replay/follow controller
  server.py        # Loopback-only (127.0.0.1:8766) Starlette + Uvicorn REST + SSE app
  ui.py            # Self-contained single-page dark UI (4 tabs, SVG regional map, SVG live RTT chart)
tests/test_lag_mapper.py
```

---

## 4. HTTP & SSE API Contract

All bound strictly to `127.0.0.1` (`validate_loopback_host`).
- `GET /`: Self-contained SPA HTML.
- `GET /events`: SSE stream (`snapshot`, `status`, `packet_batch`, `match_update`, `rtt_point`, `history_updated`) with `Last-Event-ID` replay, `once=1`, `max_events=N` query support.
- `GET /api/overview`: Global totals (servers count, total matches, captures scan status, live status, active match summary).
- `GET /api/servers`: Aggregated visited servers (`ip`, `subnet`, `provider`, `city`, `confidence`, `ports`, `match_count`, `modes`, `wifi_median_ms`, `cell_median_ms`, `overall_median_ms`, `displayed_pings`, `approx_coords`, `last_seen_ts`).
- `GET /api/matches`: Deduplicated matches from `captures/*.pcap` + `data/matches.csv` + live session, merged with `data/lag_mapper_notes.json`.
- `GET /api/correlations`: Aggregated **Party Composition & Host -> Server & Ping** groups (comparing multi-stack / international party groups against Solo baseline RTT & displayed ping).
- `GET /api/live/packets`: Current lane counters, pipeline stage flags, multipath stats, per-link RTT series, `:30190` probes, and recent packet detection feed items.
- `GET /api/pcaps`, `GET /api/devices`: Available `.pcap` files in `captures/` and `adb devices -l`.
- `POST /api/source`: `{"mode": "adb", "serial": "...", "tee": true}` | `{"mode": "pcap", "path": "...", "follow": false}` | `{"mode": "stop"}`.
- `POST /api/notes`: Save user `host` tag (e.g. `"me"`, `"MY friend"`, `"SG friend"`) and free-text `note` / `displayed_ping_ms` for a `match_key` into `data/lag_mapper_notes.json` (never modifying `matches.csv` unless explicitly desired; keeping notes cleanly separated is safer and idempotent).
- `POST /api/rescan`: Trigger background re-index of `captures/*.pcap` and `data/matches.csv`.

---

## 5. Browser UI Design (4 Tabs)

Consistent dark palette matching `tools/chat_viewer/` (`#0b0f16` bg, `#121822` panel, blue/cyan/green/amber/red status pills):
1. **Tab 1 — Server Map & List:**
   - Top KPI strip: Total Servers Seen, Total Matches Logged, Best Observed Server RTT, Currently Active Server.
   - Clean SVG regional hub visualization placing observed city clusters (Jakarta, Singapore, Kuala Lumpur, Bangkok, Manila, India/Mumbai-Delhi, Almaty, Istanbul, Dallas/US, Europe/Unknown) with node size = match count and color = median RTT band (`<30ms` green, `30-60ms` amber, `>60ms` red), plus hover/click filtering on the server table.
   - Sortable Server Table (`IP`, `/24`, `Provider`, `City`, `Confidence`, `Matches`, `Wi-Fi Med`, `Cell Med`, `Displayed Ping`, `Modes`).
2. **Tab 2 — Live Packet Detector:**
   - Source bar (ADB Phone Live + optional `.pcap` tee OR Local PCAP Replay/Follow + Stop).
   - **Live Protocol Pipeline Strip:** 7 chips (`Lobby :30101` -> `Probe :30190` -> `UDP Connect 01 71/72` -> `KCP Roster 1230/1202` -> `Echo Ping 0x3f5` -> `Battle 01 75` -> `TCP Mirror +50`) lighting up with packet counts as detected!
   - **Dual-link Multipath + Live RTT SVG Sparkline:** Wi-Fi vs Cellular packet share bar + real-time dual-line SVG plot of `0x3f5` RTT (`Wi-Fi` cyan vs `Cellular` amber) + min/med/p95/jitter readouts.
   - **Packet Detection Stream:** Filterable by protocol lane (`All`, `Lobby`, `Probes`, `Handshake`, `Roster`, `Ping`, `Ticks`, `Mirror`) showing timestamp, lane badge, link (`Wi-Fi`/`Cell`), rule matched (`e.g. TCP :30101 Zstd mid=20008 handover -> 149.104.112.216:5507`), and parsed payload summary.
3. **Tab 3 — Lobby, Party & Ping Impact:**
   - **Explicit Privacy & Protocol Notice Banner:** States clearly that friends' IP addresses do not exist on MLBB traffic (client-server only); shows country codes (`sThisLoginCountry`), party groups (`ulRoomID`), and `:30101` lobby city strings instead.
   - **Selected / Live Match Party Card:** Game Mode, Party Size (`Solo`..`5-stack`), Ally Party members (name, hero if picked, country badge, optional lobby city badge), Enemy Camp summary, assigned Server IP/Provider/City, Wi-Fi vs Cell RTT, and an editable **Party Host** + **Displayed Ping / Notes** form (`POST /api/notes`).
   - **Party Country Mix & Host -> Server & Ping Correlation Table:** Groups historical + live matches by `(Mode, Party Mix / Countries, Host)` -> shows which Servers/Cities were selected, match count, median UDP RTT vs Solo ID baseline (`+X ms` delta), and `:30190` probe targets seen.
4. **Tab 4 — All Matches:**
   - Unified searchable/filterable ledger of all PCAP-decoded matches, `data/matches.csv` rows (merged/deduped), and current live sessions. Selecting any row opens its Party & Server breakdown.

---

## 6. Verification Requirements

1. **`pytest -v tests/test_lag_mapper.py` (must pass 100%):**
   - `PCAP` UDP + TCP + SLL2 link parsing across all 4 linktypes & truncated frame handling.
   - `0x3f5` (`1013`) echo RTT calculation on `captures/draft_LIVE6.pcap` verifying Wi-Fi vs Cellular split (`n >= 900` each, Wi-Fi median ~39 ms < Cellular median ~54 ms).
   - `:30190` probe sweep detection on captures that contain `:30190` probes (`captures/all.pcap` or `captures/mlbb_*.pcap` — verify exact fixture present in `captures/`).
   - `TCP :30101` reassembly + Zstd decompression on `captures/draft_LIVE6.pcap` verifying `mid=20008` handover `149.104.112.216:5507`, coarse lobby geo extraction, AND strict skipping of `mid=10208` / zero email leakage in API output.
   - `TCP :port+50` simultaneous input mirror detection on `captures/draft_LIVE6.pcap` or `draft_CHAT4.pcap`.
   - `data/matches.csv` ingestion + PCAP deduplication + `POST /api/notes` persistence in `tmp_path`.
   - Starlette `TestClient` tests for `/`, `/events` (`Last-Event-ID`, `once=1`, `max_events`), `/api/overview`, `/api/servers`, `/api/matches`, `/api/correlations`, `/api/live/packets`, `/api/source`, and loopback `validate_loopback_host("0.0.0.0")` rejection.
2. **Real Browser / Headless Check:**
   - Start server briefly on `127.0.0.1:8766` (or free ephemeral port) indexing real `captures/` + `data/matches.csv`, load in Chromium/Playwright or preview tool, verify zero console/page errors, click through all 4 tabs, confirm Server Map, Packet Detector pipeline, Party Correlation table, and All Matches populate cleanly.
