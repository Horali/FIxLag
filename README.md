verdict: doesnt work/not worth 🚮

# FIxLag

Personal research into why MLBB ping is inconsistent when playing in parties,
and whether anything client-side can fix it. Short answer: mostly no. The ping
you get is the server you're given.

**Start here:** [`docs/handoff.md`](docs/handoff.md) — current state, device and
root setup, tooling, measured findings, open questions, and how to continue.

**Full research:** [`plan.md`](plan.md) — ~1150 lines. The measured sections are
§5.6–5.12; §11 covers the solution space and why a "stabilizer" app adds nothing.

**Capture parser:** [`tools/parse_pcap.py`](tools/parse_pcap.py) — PCAPdroid or
tcpdump captures, SLL2-aware, reports the interface each flow used.

**Draft-pick classifier:** [`tools/draft_probe.py`](tools/draft_probe.py) — starts
a labelled capture through the root daemon and names the match endpoint at draft
pick, before a match is played.

**Live passive chat viewer:** [`tools/chat_viewer/`](tools/chat_viewer/__main__.py) — localhost-only
(`127.0.0.1`) Starlette + Uvicorn web viewer merging draft, loading, and battle
chat (ally + enemy) from live ADB `tcpdump` or local `.pcap` files:

```sh
# Replay a saved capture
python -m tools.chat_viewer --pcap captures/draft_CHAT4.pcap

# Tail an actively growing .pcap on custom port
python -m tools.chat_viewer --pcap captures/live.pcap --follow --port 8765

# Live stream from rooted Android via binary-clean adb exec-out (+ tee copy)
python -m tools.chat_viewer --adb <serial> --tee

# Run regression & HTTP/SSE integration suite
pytest -v tests/test_chat_viewer.py
```

**Setup on a fresh clone:**

```sh
pip install -r requirements.txt
```

**Chat templates (`data/chat_templates.json`):** the packet decoder is fully in
`tools/chat_viewer/` (`kcp.py`, `protocol.py`, `battle.py`). Quick-chat, draft
and hero messages arrive as numeric codes (for example `/11011`). The viewer
turns them into text with `data/chat_templates.json`. This file is game text,
so it is not in the repo. Without it the viewer still works, but shows raw codes.
Build it once from your own game install:

```sh
# Rooted phone with MLBB installed
python tools/dump_chat_templates.py --adb <serial>

# Or a Document.unity3d you copied off the phone
# (/sdcard/Android/data/com.mobile.legends/files/dragon2017/assets/Document/android/Document.unity3d)
python tools/dump_chat_templates.py --document path/to/Document.unity3d
```

**Tests:** the replay tests use private `captures/*.pcap` files (they hold real
player names), so they skip on a fresh clone. The synthetic tests still run.

**Next experiment:** [`docs/experiment-restart-vs-host.md`](docs/experiment-restart-vs-host.md).

Commits: Conventional Commits, small, `main`, no AI attribution.
