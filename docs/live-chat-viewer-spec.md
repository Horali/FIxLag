# Localhost Live Passive Chat Viewer — Engineering Specification

**Repo:** `C:\Users\child\PROJECTS\FIxLag` (branch `main`, GitHub `Horali`)  
**Goal:** A **localhost-only** (`127.0.0.1`) passive web viewer that merges **draft**, **loading**, and **battle** chat (both ally and opposing team) into one chronological per-match log in near real time. Zero external services, zero cloud, and nothing written into game memory (pure passive PCAP).

---

## 1. Environment & Existing Repo Context

- **Host:** Windows, Python `3.12.6`.
  - Installed packages (verified): `starlette 1.2.1`, `uvicorn 0.49.0`, `pytest 7.4.3`, `httpx 0.28.1`.
  - Not installed: `fastapi`, `lz4`.
  - **Design choice:** Build directly on **`starlette` + `uvicorn`** and a small **pure-Python raw LZ4 block decoder** so the viewer and its full test suite run with **zero extra `pip install`s**.
- **Device:** Rooted Android phone (`adb` at `C:\Users\child\AppData\Local\Android\Sdk\platform-tools\adb.exe`; always pass `-s <serial>`, inspect `adb devices -l` first; `adb shell su -c` works directly; `tcpdump 4.99.6` at `/system/bin/tcpdump`).
- **Existing references to read first:**
  - [`docs/handoff.md`](handoff.md) — device/root setup, ADB serial rules, and hard constraints.
  - [`docs/chat-research.md`](chat-research.md) — verified channel enums (`ENChatType`), memory cross-checks, and `0x42` vs `0x52` wire proof.
  - [`tools/parse_pcap.py`](../tools/parse_pcap.py) — PCAP global/linktype parsing (SLL2 `276`, SLL `113`, Ethernet `1`, Raw IP `101`).
  - [`tools/chat_extract.py`](../tools/chat_extract.py) — payload extraction utilities.
  - [`tools/decode_lzw_chat.py`](../tools/decode_lzw_chat.py) — offline LZW-16 battle tick decoder and `01 06 43` chat sub-event parser.
- **Layout:** Keep all existing scripts in `tools/` intact. Place the new implementation cleanly under `tools/chat_viewer/` (package) with an entry point runnable via `python -m tools.chat_viewer` (and optionally a thin `tools/live_chat_viewer.py` launcher).

---

## 2. Architecture Overview

```text
Android (adb exec-out, binary-clean)            Host (Python 3.12, single process)
┌─────────────────────────────────┐             ┌──────────────────────────────────────────────────┐
│ su -c 'tcpdump -i any -U -s 0   │  stdout     │ Reader Thread (pipe OR growing local .pcap file) │
│   -w - "udp portrange 5000-5999 │ ──────────► │  └─ optional tee → captures/live_<ts>.pcap       │
│   and not port 5353" 2>/dev/null│             │  └─ Incremental PcapReader (partial-record safe) │
└─────────────────────────────────┘             │       ▼                                          │
                                                │ SessionRouter  (endpoint + battleid + phase FSM) │
                                                │  ├─ KcpReassembler per (ep, conv) [0151 + 4151]  │
                                                │  │    └─ frg==0 → LZ4(comp==1) → cd08 / roster   │
                                                │  └─ TickReorderBuffer + Lzw16Decoder per match   │
                                                │       └─ dedup tick → contiguous → 0x42/0x52     │
                                                │       ▼                                          │
                                                │ MatchStore (in-memory events + template lookup)  │
                                                │  └─ loop.call_soon_threadsafe → per-client Queue │
                                                │       ▼                                          │
                                                │ Starlette + Uvicorn (127.0.0.1)                  │
                                                │  ├─ GET /events (SSE + Last-Event-ID + 1s ping)  │
                                                │  └─ GET /       (single self-contained HTML UI)  │
                                                └──────────────────────────────────────────────────┘
```

---

## 3. Ingest Architecture (Live + Replay)

1. **Primary live ingest (binary-clean ADB stream):**
   - Do **not** use `adb shell` (line-ending translation turns `\n` into `\r\n` and corrupts binary PCAP data) and do **not** poll `adb pull` (re-copies multi-megabyte captures every tick).
   - Stream stdout directly via `adb exec-out`:
     ```sh
     adb -s <serial> exec-out "su -c 'tcpdump -i any -U -s 0 -w - \"udp portrange 5000-5999 and not port 5353\" 2>/dev/null'"
     ```
   - Validate the first 4 bytes immediately against PCAP magic (`\xd4\xc3\xb2\xa1`, `\xa1\xb2\xc3\xd4`, `\x4d\x3c\xb2\xa1`, `\xa1\xb2\x3c\x4d`) so any `su` stderr bleed or permissions failure fails loudly at startup instead of silently misparsing.
   - Support an optional raw byte tee to `captures/live_<YYYYMMDD_HHMMSS>.pcap` for post-match replay and debugging.
2. **Secondary ingest (`--pcap <path>`):**
   - Support both static replay (read to EOF) and tailing an actively growing local `.pcap` file (`--follow`) using the exact same byte-stream parser.
3. **Threading & ASGI isolation:**
   - Run ingest + decoding in a dedicated background `threading.Thread` (avoiding Windows `ProactorEventLoop` subprocess quirks and keeping LZW/LZ4 CPU work off the ASGI event loop).
   - Push decoded chat, gap, and status events to per-subscriber bounded `asyncio.Queue`s (`maxsize=512`; drop slow/dead subscribers) via `loop.call_soon_threadsafe`.

---

## 4. Incremental Partial-Record-Safe PCAP Reader

1. **Global header (24 bytes):** Read once on stream start to extract `endian` (`<` or `>`), timestamp precision (`us` vs `ns` from magic), and `linktype` (`276` Linux SLL2, `113` Linux SLL, `1` Ethernet, `101` Raw IP).
2. **Partial-record safety:**
   - Maintain a persistent unconsumed byte buffer `buf` and byte cursor `offset`.
   - On each incoming read chunk:
     - Loop while `len(buf) >= 16`: unpack `(ts_sec, ts_sub, incl_len, orig_len)`.
     - If `len(buf) < 16 + incl_len`: **break without consuming** and wait for more bytes. Never advance past a half-written record header or half-written packet body.
     - Slice `rec = buf[16 : 16 + incl_len]`, remove `16 + incl_len` bytes from `buf`, advance `offset += 16 + incl_len`, and dispatch.
3. **Snaplen truncation guard:**
   - Skip records where `orig_len > incl_len` before KCP or LZW decoding so truncated packets can never inject bogus fragments or poison the LZW dictionary.

---

## 5. Session Separation & Multi-Match FSM

### 5.1 Match Traffic Filter & Why Single Keys Fail
Filter UDP flows where either `sport` or `dport` is in `5000..5999` and `!= 5353` (mDNS). Classify direction by port (`sport in 5000..5999` = inbound from server; `dport in 5000..5999` = outbound to server).

Do **not** split sessions on any single naive key:
- **Port alone fails:** `captures/draft_RELOG.pcap` contains two distinct matches on port `5007` (`164.52.109.153:5007` then `164.52.38.98:5007`).
- **Outer `conv` alone fails twice per match:** (1) Wi-Fi and cellular use two distinct `conv` values simultaneously for the same match; (2) mid-match Wi-Fi drop/rebind opens a third `conv` (`captures/draft_LIVE1.pcap` at `t=328..332s`: `30497419` $\to$ `2a440a29` at tick `4631`) with zero LZW dictionary reset.
- **`tick == 0` alone fails:** Draft and loading run 1–3 minutes on `01 51` *before* `tick 0` ever exists, and mid-match captures never see `tick 0`.

### 5.2 Composite Session Key & Transition Rules
Identify matches by `(server_ip, server_port)` + authoritative `battleid` + phase FSM (`DRAFT` $\to$ `LOADING` $\to$ `BATTLE`):
- **Authoritative `battleid` extraction:**
  - From LZ4-decoded inbound `01 51` login reply (`mid=0`): ASCII substring `Play_<battleid>_1` (e.g. `Play_704578279919062684_1` in `captures/draft_LIVE6.pcap`).
  - Also corroborated by `msg_uid` (`<battleid>-<uid>-<ts>`) inside free-text `ev=0x06` (`4b` TLV field).
- **Rules when packets arrive for the same `(server_ip, server_port)`:**
  1. **Single-path rebind:** New `conv` via `01 71`/`01 72` while live ticks continue (same `battleid`, no `03 02` draft phase) $\Rightarrow$ register `conv` under the **same** session; **do not** reset `TickReorderBuffer` or `Lzw16Decoder`.
  2. **Full mid-match reconnect:** Same `battleid`, both paths dropped and client relogged into the ongoing match $\Rightarrow$ stay in the **same** match log, deduplicate replayed chat by `(phase, tick_or_ts_bucket, msg_uid_or_content)`, and if catch-up ticks restart from `tick 0`, reset only `TickReorderBuffer` + `Lzw16Decoder` cleanly while preserving earlier match chat.
  3. **New match on reused `(server_ip, server_port)`:** Start a new match session if any of:
     - a different `battleid` is observed;
     - `01 51 cd 08` with draft phase `03 02` arrives after `BATTLE` was already active;
     - `tick == 0` arrives after an idle gap `> 15 s` when prior `max_tick > 100`.

---

## 6. Draft & Loading Decoder (`01 51` / `41 51` KCP + LZ4)

### 6.1 Extended KCP Header (`0x01` vs `0x41`)
Packets on the KCP subchannel use **both** 24-byte and 28-byte headers (ignoring `0x41` silently drops real fragments, e.g. `sn=7` of `sn=5..20` in `captures/draft_LIVE6.pcap`, and crashes LZ4):
- **`01 51` / `01 52` (24-byte header):**
  `[b0=0x01][cmd=0x51|0x52][conv:4][una:4 LE][ts:4 LE][sn:4 LE][wnd:2 LE][frg:1][comp:1][len:2 LE]`
- **`41 51` / `41 52` (28-byte header):**
  `[b0=0x41][cmd=0x51|0x52][conv:4][ext:4][una:4 LE][ts:4 LE][sn:4 LE][wnd:2 LE][frg:1][comp:1][len:2 LE]`
- A single UDP datagram may pack multiple concatenated KCP segments (`01 51`/`01 52`/`41 51`/`41 52`) or `01 75` subframes; parse iteratively until payload exhaustion.

### 6.2 Safe Per-`conv` KCP Reassembly & Raw LZ4 Block Decode
Streaming LZ4 before `frg == 0` is **unsafe** because KCP splits `<ulen_varint> + <raw_lz4_block>` at 500-byte boundaries (mid-token or mid-16-bit match offset) and LZ4 back-references reach up to 64 KiB back across out-of-order fragments.
1. Key the KCP reassembler strictly by **`(server_ep, conv)`** (`sn` spaces are independent across Wi-Fi and cellular).
2. Store `segs[sn] = (frg, comp, body)`.
3. Emit a reassembled message **only** when a contiguous run `sn_0 .. sn_k` exists such that:
   - `frg` strictly decrements `k, k-1, ..., 1, 0` (`segs[sn_k].frg == 0`), and
   - `sn_0 == 0` OR `(sn_0 - 1 in segs and segs[sn_0 - 1].frg == 0)` (guaranteeing no leading fragment holding `<ulen_varint>` was missed).
4. Concatenate `body` over `sn_0..sn_k`. If `comp == 0x01`:
   - Parse varint `ulen` from byte 0.
   - Run pure-Python raw LZ4 block decompression on the remainder (handling 4-bit literal length + `0xFF` extension, 16-bit LE backward offset, and 4-bit match length `+ 4` + `0xFF` extension, byte-by-byte copy for overlapping `offset < match_len`).
   - Verify `len(out) == ulen`.
5. Deduplicate completed KCP messages across Wi-Fi and cellular **after** reassembly (by payload hash / `(mid, inner_seq)`).

### 6.3 Draft/Loading Event Extraction
Inspect reassembled/decompressed KCP payloads:
- Login reply (`mid=0`): scan for `Play_<battleid>_1` to bind `battleid`.
- Roster frames (`mid=1242` / `da 09`, `mid=1202` / `b2 09`): extract `account_uid` $\leftrightarrow$ player name and camp slot mapping.
- Room/Draft/Loading container (`70 00 cd 08`, `mid=1101`):
  - Phase marker preceding `70 51`: `03 02 46` = `DRAFT` (`ch=4`), `03 03 46` = `LOADING` (`ch=22`).
  - Sender group wrapper: `70 51 <cnt> 70 00 <slot_varint> 01 <ev> 43 <elen_varint> <ebody> ...` (plus `ev=0x36` / `ev=0x0b` slot associations).
  - For every `ev == 0x06`: extract channel (`70 00 <ch>`), text (`41 <strlen_varint> <utf8>`), and optional `msg_uid` (`4b <len_varint> <battleid-uid-ts>`).

---

## 7. Battle Decoder (`01 75` + Reorder Buffer + LZW-16 / Raw)

1. **Coalesced subframes:** Iterate `01 75 <conv:4> <plen_le16:2> <subframe>` records inside each datagram (1–3 subframes per datagram).
2. **Tick envelope (`03 01 46 <ln_varint> <inner>`):**
   - Check `inner[0] == 0x70`. Read base tick `seq` if `inner[1] == 0x00` (`read_varint`), else `seq = 0`. Skip optional `01 <byte>` pair.
   - Read repeated `<tag> <flen_varint> <chunk>` entries until `0x80`, incrementing `tick_idx` per tagged tick (`0x42..0x46` LZW-16; `0x52`/`0x53` raw).
3. **Deduplicate & reorder *before* LZW mutation:**
   - Each match maintains `pending: dict[int, tuple[int, bytes]]` and `next_tick`.
   - `on_tick(tick_idx, tag, chunk)`: if `tick_idx < next_tick` or `tick_idx in pending`, discard immediately (first arrival across Wi-Fi/cellular wins). Otherwise insert into `pending`.
   - Drain strictly in order: `while next_tick in pending: pop next_tick, decode(next_tick), next_tick += 1`. Never mutate the LZW dictionary out of order.
4. **LZW-16 decoder (`0x42`..`0x46`) & `0x52`/`0x53` raw:**
   - Uncompressed `0x52`/`0x53`: pass bytes directly to TLV sub-event scanner.
   - LZW-16 `0x42`..`0x46`: big-endian 16-bit codewords, initial table `{i: bytes([i]) for i in 0..255}`, clear code `0x0100`, next code starts at `0x0101` (14-bit `0x4000` cap), **reset `prev = None` at every tick boundary**.
5. **Mid-match start & permanent-gap resync (`WAIT_CLEAR`):**
   - If the first `0x42` tick observed for a match has `first_tick > 0`, or if `pending` stalls with `max(pending) - next_tick > 75` ticks (~5 s unrecoverable loss across both paths):
     - Enter `WAIT_CLEAR`, record `blind_from = next_tick`, discard un-decodable pre-sync buffered ticks, and emit an inline UI gap banner: `"Cannot decode battle chat before next LZW reset (from tick T0)"`.
     - As contiguous ticks advance, scan each tick's 16-bit big-endian word array for `0x0100` (**note:** `0x0100` occurs **mid-tick**, e.g. word index 7 in `captures/live_chat_check.pcap` tick `4590`, right after `0x3FD0`).
     - At `0x0100`, discard words before it, reset `table = {0..255}`, `next_code = 0x0101`, `prev = None`, decode words after `0x0100` (scanning the partial suffix defensively for complete `01 06 43` TLVs), and verify `T_sync + 1` decodes with zero `KeyError` and starts with `0x70`.
     - Only once `T_sync + 1` verifies cleanly, transition to `SYNCED_MIDMATCH` and update the gap banner with exact `[T0 .. T_sync - 1]`.
   - For `0x52` raw matches, start in `SYNCED` immediately even if `first_tick > 0`.
6. **Battle sub-event extraction:** Scan decoded tick bytes (`0x70 ...`) for `01 06 43 <elen_varint> <ebody>` (using the enclosing `70 00 <sender_slot_varint> 01 06 ...` pattern if present, plus `4b <msg_uid>`), yielding `ch=2` (Team) and `ch=3` (All). Note: other sub-events like `ev=0x0d` (2-byte raw joystick) do not begin with `0x70`, so scan carefully without assuming every `01 <ev> 43` body starts with `0x70`.

---

## 8. Passive Side Attribution, Roster & Template Expansion

1. **Local `account_uid`:** Extract passively from outbound `01 51 mid=1001` (`e9 07`, field `70 00 <uid_varint>`) or outbound `01 75 mid=0x44c` (`cc 08`) chat/inputs.
2. **Roster & camp mapping:**
   - Decode LZ4-compressed `01 51` roster frames (`mid=1242 = da 09`, `mid=1202 = b2 09`) to map `account_uid` $\leftrightarrow$ `playerName` and camp (`0x10..0x14` Camp 1 vs `0x20..0x24` Camp 2).
   - Also correlate `ev=0x36` (draft lock/pick slot events linking `uid` $\leftrightarrow$ camp/slot) and `ev=0x0b` (`0x10..0x14` vs `0x20..0x24`).
   - Label every message `SELF`, `ALLY`, or `ENEMY` whenever the local camp is known; on a mid-match start before local camp is identified, label `CAMP 1` / `CAMP 2` and re-tag/notify once local camp resolves (e.g. from the first outbound `0x44c` chat or `ev=0x36` match).
3. **Slash-template expansion:**
   - `1/<text>`: free text $\to$ display `<text>`.
   - `2/...`, `3/<str_id>/<hero_id>`, `5/<...>`, `7/<id>/<arg>`, `8/<id>/0`: structured quick-chat/draft suggestions. Load optional local lookup JSON (`data/chat_templates.json` if present) to expand into readable text (e.g. `Ban Kaja`), and always preserve/fallback cleanly to the raw template tag when the table or an ID is missing.

---

## 9. Local Web Server & Single-Page UI (`127.0.0.1` only)

- **Bind strictly to `127.0.0.1`** (default e.g. `127.0.0.1:8765`, configurable via `--port`). No external CDNs, fonts, or network calls.
- **HTTP & SSE endpoints (Starlette + Uvicorn):**
  - `GET /` — serves the single self-contained HTML/CSS/JS UI.
  - `GET /events` — Server-Sent Events (`text/event-stream`, `Cache-Control: no-cache`, `X-Accel-Buffering: no`):
    - Assign monotonic integer `id` to every emitted event; honor `Last-Event-ID` header on browser reconnect to replay missed match events from RAM with zero PCAP re-parsing.
    - Emit a `status` heartbeat every `1.0 s` containing `source_mode`, `capture_alive`, `last_pkt_age_s` (measured with host `time.monotonic()` to avoid phone-vs-PC clock skew), active match ID, phase/FSM state, `next_tick`, `dict_next_code` (`0xXXXX`), and gap info.
  - `GET /api/matches` — returns list of discovered matches and their cached chat/gap records.
  - `GET /api/pcaps` — lists `.pcap` files in `captures/` for quick offline/replay selection.
  - `POST /api/source` — switches ingest source cleanly (live ADB `<serial>` vs local `.pcap` path, optional `--follow`).
- **UI features:**
  - Explicit status & staleness bar: `LIVE (adb)` vs `REPLAY (file)`, FSM badge (`IDLE`, `DRAFT`, `LOADING`, `BATTLE SYNCED`, `WAIT_CLEAR`, `DESYNC`, `CAPTURE STOPPED`), and automatic **`STALE (Ns since last packet)`** warning when `last_pkt_age_s > 3 s` in battle or `> 5 s` in draft, plus a **browser-side 3 s SSE watchdog** (`SERVER DISCONNECTED`) if even heartbeats stop.
  - Chat log: newest at the bottom, smart auto-scroll (pauses when the user scrolls up, shows a "jump to latest" pill), match selector, filters by phase (`draft`/`loading`/`battle`), channel (`draft`/`loading`/`team`/`all`), side (`self`/`ally`/`enemy`), and sender search.
  - Clear visual distinction between Ally/Self (blue tint/badge) and Enemy (red tint/badge), plus inline warning banners for undecoded mid-match tick gaps.

---

## 10. Verification & Regression Suite (`pytest`)

Run `pytest` offline against the real archived captures in `captures/` plus synthetic edge-case tests:

1. **`captures/draft_CHAT4.pcap`:** Decodes all 13 battle chat messages (`ticks 141..1612`, including enemy `'team rex'` at tick `578`) plus draft (`'1/team chat'`, enemy `'1/hi'`) and loading (`'1/hahahahqtest'`, `'1/tetahqjq'`) merged into 1 match.
2. **`captures/draft_DRAFT.pcap`:** Decodes all 28 draft `cd 08` messages (`'1/team draft'`, enemy `'1/Hi hi'`, `'1/I love Hora'`, templates) plus battle chat (`'Hi'` at tick `1067`, `'Team Hora'` at tick `1180`, etc.) merged into 1 match.
3. **`captures/draft_LIVE6.pcap`:** Handles `41 51` 28-byte KCP headers, decompresses LZ4 blocks `sn=0..1`, `sn=5..20`, and `sn=159..182` (`24,088` bytes) with zero errors, extracts `battleid = 704578279919062684`, and extracts all 3 draft chat templates (`'8/48273/0'`, `'5/6/133'`, `'7/154830/ 8'`) with camp slots (`0x13` vs `0x23`/`0x24`).
4. **`captures/live_chat_check.pcap`:** Mid-match start (`tick 4447`) enters `WAIT_CLEAR`, emits a gap banner, resyncs mid-tick on `0x0100` at `tick 4590`, and decodes all 74 remaining ticks (`4590..4663`) cleanly with zero errors.
5. **`captures/draft_CHAT3.pcap`:** Raw uncompressed `0x52` ticks decode cleanly.
6. **`captures/draft_LIVE1.pcap`:** Mid-match Wi-Fi drop + 3rd `conv` (`30497419` $\to$ `2a440a29` at tick `4631`) stays in 1 match with zero LZW reset.
7. **`captures/draft_RELOG.pcap`:** Two separate matches sharing port `5007` (`164.52.109.153:5007` and `164.52.38.98:5007`) split cleanly into 2 matches.
8. **Chunked partial-read fuzz test:** Feeding a PCAP incrementally in irregular `1..37`-byte chunks produces the exact same match/event sequence as whole-file decoding.
9. **HTTP/SSE integration test (`starlette.testclient.TestClient`):** Verifies `GET /`, `GET /api/matches`, `GET /api/pcaps`, and `GET /events` including `Last-Event-ID` replay.
