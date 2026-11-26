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

**Next experiment:** [`docs/experiment-restart-vs-host.md`](docs/experiment-restart-vs-host.md).

Commits: Conventional Commits, small, `main`, no AI attribution.
