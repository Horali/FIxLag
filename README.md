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

**Next experiment:** [`docs/experiment-restart-vs-host.md`](docs/experiment-restart-vs-host.md).

Commits: Conventional Commits, small, `main`, no AI attribution.
