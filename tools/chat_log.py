"""Produce a merged chat log from a capture: battle ticks + draft/loading plaintext.

Battle chat lives inside the LZW-16 tick stream (`01 75` / `03 01 46`), so it is
decoded here. Draft and loading chat arrive as plaintext containers
`70 00 <ch> 41 <len> <bytes>` on the KCP subchannel, so they are found by direct
scan. Both are normalised into one record shape and sorted by wall time.

Usage:
    python tools/chat_log.py captures/draft_LIVE6.pcap
    python tools/chat_log.py captures/draft_LIVE6.pcap --out data/chatlog.txt
"""

import argparse
import collections
import sys
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import chat_extract as ce
import decode_lzw_chat as D
import draft_probe as dp

CHANNELS = {2: "TEAM", 3: "ALL", 4: "DRAFT", 22: "LOAD"}


def wall(ts):
    return datetime.fromtimestamp(ts).strftime("%H:%M:%S")


def plaintext_records(path):
    """Draft/loading/battle chat that sits in the clear."""
    out = []
    for ts, proto, src, sport, dst, dport, body, cut in ce.iter_payloads(path):
        if proto != "udp":
            continue
        i = 0
        while True:
            i = body.find(b"\x70\x00", i)
            if i < 0 or i + 4 > len(body):
                break
            ch = body[i + 2]
            if body[i + 3] == 0x41 and ch in CHANNELS:
                n = body[i + 4]
                if 1 <= n <= 200 and i + 5 + n <= len(body):
                    raw = body[i + 5:i + 5 + n]
                    try:
                        text = raw.decode("utf-8")
                    except UnicodeDecodeError:
                        text = raw.hex()
                    out.append({
                        "ts": ts, "phase": "draft" if ch in (4, 22) else "battle",
                        "channel": CHANNELS[ch], "uid": None, "tick": None,
                        "text": text, "src": "wire-plain",
                    })
                    i += 5 + n
                    continue
            i += 3
    return out


def battle_records(path, port):
    ticks, _other, _non = D.extract_ticks(path, port)
    decoded, next_code, missing = D.decode_lzw16_ticks(ticks)
    out = []
    if not decoded:
        return out, (len(ticks), next_code, missing)
    for idx in sorted(decoded):
        ts, data = decoded[idx]
        if data == b"\x70\x80":
            continue
        try:
            events = D.parse_chat_subevents(data)
        except Exception:
            continue
        for ev_type, body in events:
            if ev_type != 0x06:
                continue
            try:
                info = D.decode_chat_body(body)
            except Exception:
                continue
            ch = info.get("chan")
            text = info.get("text")
            uid = info.get("uid")
            if ch is None:
                continue
            out.append({
                "ts": ts, "phase": "battle",
                "channel": CHANNELS.get(ch, "ch%d" % ch),
                "uid": uid, "tick": idx, "text": text if text is not None else "",
                "src": "wire-lzw",
            })
    return out, (len(ticks), next_code, missing)


def match_ports(path, min_packets=2000):
    rep = dp.classify(str(path))
    return [(c["ip"], c["port"]) for c in rep["candidates"]
            if (c["out"] + c["in"]) >= min_packets]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("--out")
    args = ap.parse_args()

    path = Path(args.pcap)
    rows = plaintext_records(path)

    stats = []
    for _ip, port in match_ports(path):
        try:
            recs, info = battle_records(path, port)
        except Exception as exc:
            # Raw (0x52) matches carry chat in the clear, so the plaintext scan
            # already covered them; a tick-decode failure is not fatal here.
            stats.append((port, 0, "raw/failed", 0))
            print("note: port %d tick decode skipped (%s)" % (port, exc), file=sys.stderr)
            continue
        stats.append((port, info[0], hex(info[1]) if info[1] else "?", info[2]))
        rows.extend(recs)

    # Deduplicate: the same message appears on both transports and often on both links.
    seen = set()
    unique = []
    for r in sorted(rows, key=lambda r: (r["ts"], r["channel"], r["text"] or "")):
        key = (round(r["ts"], 1), r["channel"], r["uid"], r["text"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(r)

    lines = []
    lines.append("=== %s ===" % path.name)
    for port, ticks, nxt, missing in stats:
        lines.append("port %-5d ticks=%-6d final_code=%-7s missing=%d"
                     % (port, ticks, nxt, len(missing or [])))
    lines.append("%-8s %-6s %-5s %-22s %s" % ("time", "phase", "chan", "uid", "text"))
    for r in unique:
        lines.append("%-8s %-6s %-5s %-22s %s"
                     % (wall(r["ts"]), r["phase"], r["channel"],
                        (r["uid"] or "-")[:22], r["text"]))

    out = "\n".join(lines)
    print(out)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(out + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
