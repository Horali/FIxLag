# FIxLag — Project Handoff

## Summary
Personal research into why MLBB ping varies in parties and passive local PCAP tools to inspect match traffic and ally/enemy chat.
Finding: ping variance is server-side (city/provider/IP); client-side tools only measure and observe.

## Current state
- Research phase complete; `tools/parse_pcap.py` and `tools/draft_probe.py` work via rooted ADB on SM-S936B (`RRCY1032Y6F`).
- `tools/chat_viewer` runs a `127.0.0.1` web + SSE viewer for live ADB tcpdump or saved `.pcap` replays (`mid=1242`/`1230`/`1202`/`1203`, mode, country, bot, party size, hero picks).
- Past Games deduplicates `live:` vs `pcap:` records by `battle_id` (fallback `(ip, port, first_ts <= 5s)`), prefers richer/newer `.pcap` records, auto-indexes teed captures on stop, and pushes `history_updated` SSE events.
- Specification ready for FIxLag Server & Live Packet Mapper (`127.0.0.1:8766`): [docs/lag-mapper-spec.md](docs/lag-mapper-spec.md).
- Test suite (`pytest -v tests/test_chat_viewer.py`): 16 tests passing.

## Active tasks
_(none)_

## Where to look
- Research & root/ADB setup: [docs/handoff.md](docs/handoff.md)
- Overview & commands: [README.md](README.md)
- Full measurement notes: [plan.md](plan.md)
- Passive chat viewer: [tools/chat_viewer/](tools/chat_viewer/__main__.py)
- Viewer tests: [tests/test_chat_viewer.py](tests/test_chat_viewer.py)
- Server & packet mapper spec: [docs/lag-mapper-spec.md](docs/lag-mapper-spec.md)

## Rules & conventions
- Always pass `-s <serial>` to `adb`; phone root uses `su -c`.
- Bind web tools strictly to `127.0.0.1`; passive PCAP only (never touch game memory).
- Commits: small Conventional Commits to `main` under GitHub `Horali`; zero AI attribution; never commit `captures/`, `data/`, `.venv/`.
