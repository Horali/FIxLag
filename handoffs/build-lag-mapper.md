Status: active
Needs user: no
Updated: 2026-11-27 04:55
Agent: T3 Code, execution

## Goal and why
Build `tools/lag_mapper/` and `tests/test_lag_mapper.py` per [docs/lag-mapper-spec.md](../docs/lag-mapper-spec.md).
Queen Hora needs a `127.0.0.1:8766` passive tool to map MLBB servers, watch live packets, and study party ping effects.

## Current state
- Read specification, handoff constraints, `data/matches.csv`, and read-only helpers in `tools/chat_viewer/` and `tools/draft_probe.py`.
- Verified `pytest -v tests/test_chat_viewer.py` passes (16/16) and `C:\msys64\ucrt64\bin\zstd.EXE` decompresses 445 `:30101` frames in ~52 ms.

## Next steps
1. Implement `pcap_net.py`, `classifier.py`, `rtt.py`, and `tcp_lobby.py` in `tools/lag_mapper/`.
2. Implement `detector.py`, `aggregator.py`, and `ingest.py`.
3. Implement `ui.py`, `server.py`, and `__main__.py`.
4. Add `tests/test_lag_mapper.py`, run both test suites, and verify live `127.0.0.1:8766` UI in headless Chromium.
5. Close this task file and update [HANDOFF.md](../HANDOFF.md).

## Open problems
None.

## Decisions and lessons (keep)
- Batch `tcp/30101` Zstd `0x10` frames by reading `Frame_Content_Size` so `zstd.EXE -d --stdout` runs once per capture instead of per frame.
- Drop `mid=10208` before any UTF-8 or regex extraction to prevent account PII leakage.

## Where to look
- Spec: [docs/lag-mapper-spec.md](../docs/lag-mapper-spec.md)
- Read-only helpers: [tools/draft_probe.py](../tools/draft_probe.py), [tools/chat_viewer/session.py](../tools/chat_viewer/session.py)
