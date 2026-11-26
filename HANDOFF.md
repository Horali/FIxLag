# FIxLag — Project Handoff

## Summary
Personal research into why MLBB ping varies in parties and passive local PCAP tools to inspect match traffic and ally/enemy chat.
Finding: ping variance is server-side (city/provider/IP); client-side tools only measure and observe.

## Current state
- Research phase complete; `tools/parse_pcap.py` and `tools/draft_probe.py` work via rooted ADB on SM-S936B (`RRCY1032Y6F`).
- `tools/chat_viewer` runs a `127.0.0.1` web + SSE viewer for live ADB tcpdump or saved `.pcap` replays.
- Hero picks update live in both Classic and Ranked draft via `ev=0x34`, `ev=0x45`, and `mid=1203`, publishing `match_update` over SSE.
- Past Games deduplicates `live:` vs `pcap:` records by `battle_id` (fallback `(ip, port, first_ts <= 5s)`), prefers richer/newer `.pcap` records, auto-indexes teed captures on stop, and pushes `history_updated` SSE events.
- Test suite (`pytest -v tests/test_chat_viewer.py`): 15 tests passing.

## Active tasks
_(none)_

## Where to look
- Research & root/ADB setup: [docs/handoff.md](docs/handoff.md)
- Overview & commands: [README.md](README.md)
- Full measurement notes: [plan.md](plan.md)
- Passive chat viewer: [tools/chat_viewer/](tools/chat_viewer/__main__.py)
- Viewer tests: [tests/test_chat_viewer.py](tests/test_chat_viewer.py)

## Rules & conventions
- Always pass `-s <serial>` to `adb`; phone root uses `su -c`.
- Bind web tools strictly to `127.0.0.1`; passive PCAP only (never touch game memory).
- Commits: small Conventional Commits to `main` under GitHub `Horali`; zero AI attribution; never commit `captures/`, `data/`, `.venv/`.
