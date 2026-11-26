"""Decode MLBB match-UDP LZW-16 tick streams (03 01 46 / 70 00 <seq> 42 <len>)
and extract every decoded chat/event frame with zero dictionary errors.
"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(r"C:\Users\child\PROJECTS\FIxLag\tools")))
import chat_extract as ce  # noqa: E402


def read_varint(buf, i):
    val = 0
    shift = 0
    while i < len(buf):
        b = buf[i]
        i += 1
        val |= (b & 0x7F) << shift
        if not (b & 0x80):
            return val, i
        shift += 7
    raise ValueError("truncated varint")


def extract_ticks(pcap_path, match_port):
    """Return (ticks_dict, other_inner_chunks, non_0175_samples)."""
    pkts = list(ce.iter_payloads(pcap_path))
    # Skip snaplen-truncated packets: a partial frame parses into a bogus tick
    # and poisons the dictionary for everything after it.
    in_udp = [(ts, s, sp, d, dp, b) for ts, pr, s, sp, d, dp, b, cut in pkts
              if pr == "udp" and sp == match_port and not cut]

    ticks = {}
    other_inner = []
    seen_other = set()
    non_0175 = []

    for ts, s, sp, d, dp, b in in_udp:
        if b[:2] != b"\x01\x75":
            non_0175.append((ts, len(b), b[:24].hex()))
            continue
        i = 0
        while i < len(b):
            if b[i:i + 2] == b"\x01\x75" and i + 8 <= len(b):
                plen = int.from_bytes(b[i + 6:i + 8], "little")
                sub = b[i + 8:i + 8 + plen]
                j = sub.find(b"\x03\x01\x46")
                if j >= 0:
                    try:
                        ln, k = read_varint(sub, j + 3)
                    except ValueError:
                        # Snaplen-truncated frame: abandon this packet, keep the rest.
                        break
                    inner = sub[k:k + ln]
                    if inner and inner[0] == 0x70:
                        pos = 1
                        if pos >= len(inner):
                            continue
                        if inner[pos] == 0x00:
                            seq, pos = read_varint(inner, pos + 1)
                        else:
                            seq = 0
                        if pos + 1 < len(inner) and inner[pos] == 0x01:
                            pos += 2
                        t_idx = seq
                        while pos < len(inner) and inner[pos] != 0x80:
                            tag = inner[pos]
                            pos += 1
                            flen, pos = read_varint(inner, pos)
                            if tag in (0x42, 0x43, 0x44, 0x45, 0x46):
                                ticks.setdefault(t_idx, (ts, inner[pos:pos + flen]))
                                t_idx += 1
                            else:
                                if inner not in seen_other:
                                    seen_other.add(inner)
                                    other_inner.append((ts, inner.hex()))
                            pos += flen
                    else:
                        if inner not in seen_other:
                            seen_other.add(inner)
                            other_inner.append((ts, inner.hex()))
                elif sub not in seen_other:
                    seen_other.add(sub)
                    other_inner.append((ts, "NO030146:" + sub[:40].hex()))
                i += 8 + plen
            else:
                break
    return ticks, other_inner, non_0175


def decode_lzw16_ticks(ticks):
    """Decode ticks 0..max_tick using 16-bit big-endian LZW starting at 0x0101 (0x0100 clear)."""
    if not ticks:
        return {}, 0, []
    min_t, max_t = min(ticks), max(ticks)
    missing = [i for i in range(min_t, max_t + 1) if i not in ticks]
    if min_t != 0:
        return None, 0, missing
    # Decode as far as the first gap: a missing tick breaks the dictionary chain,
    # but everything before it is still valid and worth reading.
    first_gap = min(missing) if missing else max_t + 1

    table = {i: bytes([i]) for i in range(256)}
    next_code = 0x0101
    decoded = {}

    for idx in range(first_gap):
        ts, raw = ticks[idx]
        if len(raw) % 2 != 0:
            raise ValueError(f"odd byte count at tick {idx}: {len(raw)}")
        words = [int.from_bytes(raw[k:k + 2], "big") for k in range(0, len(raw), 2)]
        out = bytearray()
        prev = None
        for w in words:
            if w == 0x0100:
                table = {i: bytes([i]) for i in range(256)}
                next_code = 0x0101
                prev = None
                continue
            if w in table:
                entry = table[w]
            elif w == next_code and prev is not None:
                entry = prev + prev[:1]
            else:
                raise KeyError(f"bad LZW code {hex(w)} at tick {idx} (next_code={hex(next_code)})")
            out.extend(entry)
            if prev is not None:
                table[next_code] = prev + entry[:1]
                next_code += 1
            prev = entry
        decoded[idx] = (ts, bytes(out))
    return decoded, next_code, missing


def parse_chat_subevents(data):
    """Inspect decoded tick bytes for sub-events (01 <ev_type> 43 <len> <body>)."""
    events = []
    # Find all occurrences of 01 <ev_type> 43 <len> 70 ...
    i = 0
    while i + 4 < len(data):
        if data[i] == 0x01 and data[i + 2] == 0x43:
            ev_type = data[i + 1]
            try:
                elen, k = read_varint(data, i + 3)
            except ValueError:
                i += 1
                continue
            body = data[k:k + elen]
            if len(body) == elen and elen > 0 and body[0] == 0x70:
                events.append((ev_type, body))
                i = k + elen
                continue
        i += 1
    return events


def decode_chat_body(body):
    """Parse MLBB 01 06 chat body: 70 00 <ch> 41 <len> <text> ..."""
    res = {"raw_hex": body.hex()}
    pos = 0
    if body[pos:pos + 2] == b"\x70\x00":
        pos += 2
        res["chan"] = body[pos]
        pos += 1
    while pos < len(body):
        t = body[pos]
        if t == 0x80:
            break
        if t == 0x41:
            ln, pos = read_varint(body, pos + 1)
            res["text"] = body[pos:pos + ln].decode("utf-8", "replace")
            pos += ln
        elif t == 0x4B:
            ln, pos = read_varint(body, pos + 1)
            res["msg_uid"] = body[pos:pos + ln].decode("utf-8", "replace")
            pos += ln
        elif t == 0x43:
            ln, pos = read_varint(body, pos + 1)
            res["f43"] = body[pos:pos + ln].hex()
            pos += ln
        elif (t & 0xF0) == 0x00 or t in (0x02, 0x05, 0x08, 0x09, 0x0C):
            val, pos = read_varint(body, pos + 1)
            res[f"f{t:02x}"] = val
        else:
            pos += 1
    return res


def analyze(pcap_path, match_port):
    print(f"=== {pcap_path} (port {match_port}) ===")
    ticks, other_inner, non_0175 = extract_ticks(pcap_path, match_port)
    print(f"ticks={len(ticks)} range={min(ticks) if ticks else None}..{max(ticks) if ticks else None} other_inner={len(other_inner)} non_0175={len(non_0175)}")
    if not ticks or min(ticks) != 0:
        print("Cannot run from tick 0 (mid-match capture or no ticks).")
        return
    decoded, next_code, missing = decode_lzw16_ticks(ticks)
    print(f"Decoded {len(decoded)} ticks cleanly! final next_code={hex(next_code)} missing={missing}")

    ev_counts = {}
    chat_events = []
    interesting = []
    for idx in sorted(decoded):
        ts, data = decoded[idx]
        if data == b"\x70\x80":
            continue
        evs = parse_chat_subevents(data)
        for ev_type, body in evs:
            ev_counts[ev_type] = ev_counts.get(ev_type, 0) + 1
            if ev_type == 0x06 or b"\x41" in body:
                info = decode_chat_body(body)
                chat_events.append((idx, ts, ev_type, info))
        if not evs:
            interesting.append((idx, ts, data))

    print("Sub-event counts (01 <type> 43 ...):", {hex(k): v for k, v in sorted(ev_counts.items())})
    print(f"Chat/text sub-events ({len(chat_events)}):")
    for idx, ts, ev_type, info in chat_events:
        ch = info.get("chan")
        txt = info.get("text")
        uid = info.get("msg_uid")
        f08 = info.get("f08")
        f09 = info.get("f09")
        f0c = info.get("f0c")
        f02 = info.get("f02")
        f05 = info.get("f05")
        print(
            f"  tick={idx:4d} {ce.ts_str(ts)} ({ts:.3f}) ev={hex(ev_type)} ch={ch} "
            f"f02={f02} f05={f05} f08={f08} f09={f09} f0c={f0c} uid={uid!r} text={txt!r}"
        )
        if txt is None:
            print("    raw:", info["raw_hex"])

    print(f"Non-empty ticks without 01 <type> 43 header: {len(interesting)}")
    for idx, ts, data in interesting[:10]:
        print(f"  tick={idx:4d} {ce.ts_str(ts)} len={len(data)} hex={data.hex()}")


if __name__ == "__main__":
    base = pathlib.Path(r"C:\Users\child\PROJECTS\FIxLag\captures")
    if len(sys.argv) >= 3:
        analyze(pathlib.Path(sys.argv[1]), int(sys.argv[2]))
    elif len(sys.argv) == 2:
        # No port given: try each port seen in the capture directory default set.
        analyze(pathlib.Path(sys.argv[1]), 5007)
    else:
        analyze(base / "draft_CHAT4.pcap", 5007)
