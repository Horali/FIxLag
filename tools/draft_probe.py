"""Draft-pick match-server classifier for MLBB.

Runs a bounded packet capture on the phone through the root command daemon,
pulls the pcap, and says which endpoint the match is on -- early enough to see
it at draft pick instead of after a full match.

The daemon (docs/handoff.md §3) is the only root channel on this device: adb
shell is uid 2000 and cannot read conntrack or bind a raw socket. Every
privileged action here goes through /sdcard/cmd.sh.

Usage:
    python tools/draft_probe.py devices
    python tools/draft_probe.py start --label A --seconds 1500 [--serial X]
    python tools/draft_probe.py peek  --label A
    python tools/draft_probe.py finish --label A --host me --ping 42 \
        --party "5q: me(ID), MY, PH, IN, SG"
    python tools/draft_probe.py classify captures/all.pcap
    python tools/draft_probe.py ping 148.153.165.218

The capture is all UDP at -s 96. It is continuous, so it also catches the
port-30190 latency sweep if it fires, and any concurrent relay flow.

A pcap still being written by tcpdump is safe to classify: the reader stops at
the last complete record.
"""

import argparse
import csv
import datetime
import ipaddress
import os
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(HERE))
import parse_pcap as pp  # noqa: E402

ADB = Path(r"C:\Users\child\AppData\Local\Android\Sdk\platform-tools\adb.exe")
MATCH_PORT_LO = 5000
MATCH_PORT_HI = 5999
PROBE_PORT = 30190
CAPTURES = REPO / "captures"
DATA = REPO / "data"

# Endpoints that have actually been observed on this device. Values:
# (provider, city estimate, role note). Roles are what the study saw, not proof
# of physical location -- see plan.md §6.2.
KNOWN_IP = {
    "216.133.157.51": ("Zenlayer", "Jakarta", "main server, 20.8 ms floor"),
    "216.133.157.52": ("Zenlayer/Bunny", "Jakarta", "23.5 ms floor"),
    "103.157.33.33": ("Omni Cloud", "Jakarta", "probe sweep target"),
    "103.157.33.34": ("Omni Cloud", "Jakarta", "sub-Indo, 20.2 ms floor"),
    "103.157.33.137": ("Omni Cloud", "Jakarta", "custom match, sub-Indo"),
    "148.153.165.218": ("CDS Global Cloud", "Jakarta (geo disputed)", "solo classic, 35.4 ms"),
    "148.153.100.254": ("CDS Global Cloud", "Jakarta", "probe sweep target"),
    "138.113.116.210": ("Meteverse", "Jakarta", "probe sweep target"),
    "138.113.116.245": ("Meteverse", "Jakarta", "probe sweep target"),
    "156.59.164.174": ("Zenlayer", "Kuala Lumpur", "MY-hosted brawl, 37.6 ms"),
    "156.59.62.2": ("Zenlayer", "Kuala Lumpur", "probe sweep target"),
    "161.202.213.215": ("IBM Cloud", "Singapore", "lobby gateway, TCP 30101"),
    "161.202.220.150": ("IBM Cloud", "Singapore", "concurrent flow, UDP 10011"),
    "169.53.7.247": ("IBM Cloud", "Dallas", "237.6 ms"),
    "169.53.7.245": ("IBM Cloud", "Dallas", "251.7 ms"),
}

# Prefix fallback for endpoints not in the table above. Provider guess only,
# derived from the sweep targets recorded in plan.md §5.8. Tagged "prefix" in
# output so it is never mistaken for an observed endpoint.
PREFIX_HINTS = (
    ("161.202.", "IBM Cloud", "Singapore"),
    ("169.53.7.", "IBM Cloud", "Dallas"),
    ("169.51.", "IBM Cloud", "Lelystad?"),
    ("103.157.33.", "Omni Cloud", "Jakarta"),
    ("148.153.", "CDS Global Cloud", "Jakarta (geo disputed)"),
    ("164.52.", "CDS Global Cloud", "Singapore?"),
    ("216.133.157.", "Zenlayer", "Jakarta"),
    ("138.113.116.", "Meteverse", "Jakarta"),
    ("156.59.62.", "Zenlayer", "Kuala Lumpur"),
    ("156.59.174.", "Zenlayer", "Bangkok"),
    ("156.59.", "Zenlayer", "SEA, city unclear"),
    ("162.128.", "Zenlayer", "Istanbul"),
    ("128.14.", "Zenlayer", "US"),
    ("103.96.77.", "unknown", "Sydney?"),
    ("95.56.249.", "Kazakhtelecom", "Almaty"),
    ("43.133.", "Tencent Cloud", "Tokyo?"),
    ("15.220.", "AWS", "Delhi (ap-south-1)"),
)

PRIVATE_V4 = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
    "169.254.0.0/16", "100.64.0.0/10", "0.0.0.0/8", "224.0.0.0/4",
    "240.0.0.0/4", "192.0.2.0/24", "198.18.0.0/15",
)]
PRIVATE_V6 = [ipaddress.ip_network(n) for n in (
    "::1/128", "fe80::/10", "fc00::/7", "ff00::/8", "::/96",
)]

# mDNS lives at 5353, inside the 5xxx match-port band. Never a match server.
IGNORED_PORTS = {5353}
# Auxiliary flows only matter as relays/probes; drop the noise by protocol.
AUX_IGNORED_PORTS = {53, 443, 853, 123}

IFACE_NAMES = dict(pp.IFACE_NAMES)
IFACE_NAMES.update({1: "wlan0", 2: "rmnet_data0"})


# --------------------------------------------------------------------------- #
# adb plumbing
# --------------------------------------------------------------------------- #

def adb_base(serial):
    cmd = [str(ADB)]
    if serial:
        cmd += ["-s", serial]
    return cmd


def run(cmd, timeout=60, check=True):
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if check and p.returncode != 0:
        raise SystemExit("command failed (%d): %s\n%s"
                         % (p.returncode, " ".join(cmd), p.stderr.strip()))
    return p


def list_devices():
    p = run([str(ADB), "devices", "-l"], check=False)
    out = []
    for line in p.stdout.splitlines()[1:]:
        line = line.strip()
        if not line or line.startswith("*"):
            continue
        parts = line.split()
        out.append((parts[0], line))
    return out


def pick_serial(explicit):
    if explicit:
        return explicit
    devs = [d for d in list_devices() if "unauthorized" not in d[1]]
    if not devs:
        raise SystemExit(
            "no adb device. Plug the S25+ in and check `adb devices -l`.\n"
            "Multiple devices are normal on this machine -- if more than one\n"
            "shows up, pass --serial explicitly."
        )
    preferred = [d for d in devs if "SM_S936B" in d[1] or "SM-S936B" in d[1]]
    if len(preferred) == 1:
        return preferred[0][0]
    if len(devs) == 1:
        return devs[0][0]
    raise SystemExit(
        "cannot choose a device; pass --serial. Attached:\n  "
        + "\n  ".join(d[1] for d in devs)
    )


def root_run(serial, script, timeout=120, attempts=3):
    """Run a shell script as root via the /sdcard/cmd.sh daemon."""
    marker = "MPMARK-%d" % int(time.time() * 1000)
    body = script.rstrip("\n") + "\necho %s\n" % marker

    with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False, newline="\n") as f:
        f.write(body)
        staged = f.name

    try:
        run(adb_base(serial) + ["push", staged, "/sdcard/stage.sh"])
        for attempt in range(attempts):
            run(adb_base(serial) + ["shell", "rm -f /sdcard/cmd.out"])
            with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False, newline="\n") as f:
                f.write("sh /sdcard/stage.sh\n")
                trigger = f.name
            try:
                run(adb_base(serial) + ["push", trigger, "/sdcard/cmd.sh"])
            finally:
                os.unlink(trigger)

            deadline = time.time() + timeout
            while time.time() < deadline:
                time.sleep(1.5)
                p = run(adb_base(serial) + ["shell", "cat /sdcard/cmd.out"],
                        check=False)
                out = p.stdout or ""
                if marker in out:
                    return out.split(marker)[0].rstrip("\n")
                if "__DONE__" in out and attempt == attempts - 1:
                    return out.replace("__DONE__", "").rstrip("\n")
            # timed out on this attempt; retry
        raise SystemExit("root daemon did not answer. Is the poller alive?\n"
                         "Recreate it per docs/handoff.md §3.")
    finally:
        os.unlink(staged)


# --------------------------------------------------------------------------- #
# pcap classification
# --------------------------------------------------------------------------- #

def is_public(addr):
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    if ip.is_multicast or ip.is_unspecified or ip.is_loopback:
        return False
    nets = PRIVATE_V4 if ip.version == 4 else PRIVATE_V6
    return not any(ip in net for net in nets)


def describe(ip):
    if ip in KNOWN_IP:
        prov, city, note = KNOWN_IP[ip]
        return prov, city, note, "known"
    for prefix, prov, city in PREFIX_HINTS:
        if ip.startswith(prefix):
            return prov, city, "prefix match only", "prefix"
    return "unknown", "unknown", "no data", "unknown"


def read_flows(path):
    """Return flows dict and capture metadata. Truncation-safe."""
    data = Path(path).read_bytes()
    if len(data) < 24:
        return {}, {"packets": 0, "linktype": None, "start": None, "complete_bytes": len(data)}
    endian, snaplen, linktype = pp.read_global_header(data)

    off = 24
    total = 0
    start = None
    flows = {}
    while off + 16 <= len(data):
        ts_sec, ts_usec, incl, _orig = struct.unpack(endian + "IIII", data[off:off + 16])
        off += 16
        if off + incl > len(data):
            break  # packet still being written
        pkt = data[off:off + incl]
        off += incl
        total += 1
        ts = ts_sec + ts_usec / 1e6
        if start is None:
            start = ts

        ethertype, payload, if_idx = pp.network_offset(pkt, linktype)
        parsed = pp.parse_udp(ethertype, payload)
        if parsed is None:
            continue
        src, dst, sport, dport, l4len = parsed
        key = (src, sport, dst, dport)
        f = flows.get(key)
        if f is None:
            f = flows[key] = {"pkts": 0, "bytes": 0, "first": ts, "last": ts,
                              "ifaces": {}}
        f["pkts"] += 1
        f["bytes"] += l4len
        f["last"] = ts
        name = IFACE_NAMES.get(if_idx, pp.iface_name(if_idx))
        f["ifaces"][name] = f["ifaces"].get(name, 0) + 1

    return flows, {"packets": total, "linktype": linktype, "start": start,
                   "complete_bytes": off}


def endpoint_table(flows):
    """Collapse flows into per-endpoint stats keyed by (ip, port)."""
    eps = {}
    for (src, sport, dst, dport), f in flows.items():
        if is_public(dst):
            key = (dst, dport)
            direction = "out"
        elif is_public(src):
            key = (src, sport)
            direction = "in"
        else:
            continue
        e = eps.get(key)
        if e is None:
            e = eps[key] = {"out": 0, "in": 0, "first": f["first"],
                            "last": f["last"], "ifaces": {}}
        e[direction] += f["pkts"]
        e["first"] = min(e["first"], f["first"])
        e["last"] = max(e["last"], f["last"])
        for k, v in f["ifaces"].items():
            e["ifaces"][k] = e["ifaces"].get(k, 0) + v
    return eps


def classify(path, min_pkts=8):
    """Return a report dict for one capture."""
    flows, meta = read_flows(path)
    eps = endpoint_table(flows)

    candidates, probes, aux = [], [], []
    for (ip, port), e in eps.items():
        total = e["out"] + e["in"]
        if total == 0:
            continue
        prov, city, note, source = describe(ip)
        row = {
            "ip": ip, "port": port, "out": e["out"], "in": e["in"],
            "total": total, "first": e["first"], "last": e["last"],
            "dur": e["last"] - e["first"],
            "ifaces": sorted(e["ifaces"], key=lambda k: -e["ifaces"][k]),
            "provider": prov, "city": city, "note": note, "source": source,
        }
        if port == PROBE_PORT:
            probes.append(row)
        elif port in IGNORED_PORTS:
            continue
        elif MATCH_PORT_LO <= port <= MATCH_PORT_HI:
            candidates.append(row)
        elif total >= 20 and port not in AUX_IGNORED_PORTS:
            aux.append(row)

    candidates.sort(key=lambda r: -r["total"])
    aux.sort(key=lambda r: -r["total"])
    probes.sort(key=lambda r: r["first"])

    primary = None
    for c in candidates:
        if c["total"] >= min_pkts:
            primary = c
            break

    return {"meta": meta, "candidates": candidates, "probes": probes,
            "aux": aux, "primary": primary}


def fmt_ep(r):
    ifaces = ",".join(r["ifaces"]) or "-"
    return ("%-16s %-6d out=%-6d in=%-6d total=%-6d %-22s %-18s %-12s [%s]"
            % (r["ip"], r["port"], r["out"], r["in"], r["total"],
               r["provider"], r["city"], r["source"], ifaces))


def print_report(rep, label=None, elapsed=None):
    meta = rep["meta"]
    head = "capture: %d packets, linktype=%s" % (meta["packets"], meta["linktype"])
    if label:
        head = "[%s] " % label + head
    if elapsed is not None:
        head += ", +%.0fs" % elapsed
    print(head)

    prim = rep["primary"]
    if prim:
        print("PRIMARY  %s:%d  %s / %s  (%s)"
              % (prim["ip"], prim["port"], prim["provider"], prim["city"], prim["note"]))
        print("         out=%d in=%d over %.1fs on %s"
              % (prim["out"], prim["in"], prim["dur"], ",".join(prim["ifaces"])))
    elif rep["candidates"]:
        print("PRIMARY  not confirmed yet (fewest packets so far: %s:%d total=%d)"
              % (rep["candidates"][0]["ip"], rep["candidates"][0]["port"],
                 rep["candidates"][0]["total"]))
    else:
        print("PRIMARY  none. The match server is not connected yet, or the"
              " capture started after draft pick.")

    if len(rep["candidates"]) > 1:
        print("other 5xxx endpoints (multi-server architecture is normal):")
        for c in rep["candidates"]:
            if c is not prim:
                print("  " + fmt_ep(c))

    if rep["aux"]:
        print("other public UDP flows (relay / probe traffic):")
        for a in rep["aux"]:
            print("  " + fmt_ep(a))

    if rep["probes"]:
        base = meta["start"] or rep["probes"][0]["first"]
        rel = rep["probes"][0]["first"] - base
        print("port %d probes: %d distinct target(s), first at +%.1fs"
              % (PROBE_PORT, len(rep["probes"]), rel))
        for p in rep["probes"][:12]:
            print("  %-16s %s / %s" % (p["ip"], p["provider"], p["city"]))
    else:
        print("port %d probes: none in this capture" % PROBE_PORT)


# --------------------------------------------------------------------------- #
# commands
# --------------------------------------------------------------------------- #

def remote_done(serial, label):
    p = run(adb_base(serial) + ["shell", "ls /sdcard/draft_%s.done" % label],
            check=False)
    return p.returncode == 0 and "draft_" in (p.stdout or "")


def capture_seconds(serial, label):
    """Seconds the capture has been running, from the on-device log."""
    p = run(adb_base(serial) + ["shell", "cat /sdcard/draft_%s.log" % label],
            check=False)
    out = p.stdout or ""
    started = None
    for line in out.splitlines():
        if line.startswith("START "):
            started = int(line.split()[1])
        if line.startswith("END "):
            return int(line.split()[1]) - (started or 0)
    if started is None:
        return None
    return int(time.time()) - started


def pull(serial, label):
    CAPTURES.mkdir(exist_ok=True)
    local = CAPTURES / ("draft_%s.pcap" % label)
    run(adb_base(serial) + ["pull", "/sdcard/draft_%s.pcap" % label, str(local)],
        timeout=180)
    return local


def cmd_start(args):
    serial = pick_serial(args.serial)
    CAPTURES.mkdir(exist_ok=True)
    src = HERE / "draft_capture.sh"
    if not src.exists():
        raise SystemExit("missing %s" % src)
    run(adb_base(serial) + ["push", str(src), "/sdcard/draft_capture.sh"])
    out = root_run(serial,
                   "nohup sh /sdcard/draft_capture.sh %d %s >/dev/null 2>&1 &"
                   % (args.seconds, args.label),
                   timeout=30)
    if out.strip():
        print(out)
    time.sleep(2)
    running = run(adb_base(serial) + ["shell", "pidof tcpdump"], check=False)
    if not (running.stdout or "").strip():
        raise SystemExit("tcpdump is not running. Check /sdcard/draft_%s.log."
                         % args.label)
    print("capture %s started on %s, pid %s, budget %ds"
          % (args.label, serial, running.stdout.strip(), args.seconds))
    print("queue with the party now. Run `peek` after the draft starts.")


def cmd_peek(args):
    serial = pick_serial(args.serial)
    local = pull(serial, args.label)
    rep = classify(local)
    elapsed = capture_seconds(serial, args.label)
    print_report(rep, args.label, elapsed)
    if remote_done(serial, args.label):
        print("(capture has already ended)")


def cmd_finish(args):
    serial = pick_serial(args.serial)
    root_run(serial, "p=$(pidof tcpdump); [ -n \"$p\" ] && kill $p; "
                     "sleep 1; echo stopped", timeout=30)
    local = pull(serial, args.label)
    rep = classify(local)
    print_report(rep, args.label)
    if not rep["primary"]:
        print("not logging a row: no confirmed endpoint.")
        return
    prim = rep["primary"]
    others = ";".join("%s:%d" % (c["ip"], c["port"])
                      for c in rep["candidates"] if c is not prim)
    DATA.mkdir(exist_ok=True)
    path = DATA / "matches.csv"
    new = not path.exists()
    with path.open("a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if new:
            w.writerow(["ts", "label", "host", "displayed_ping_ms", "endpoint",
                        "port", "provider", "city_geo", "confidence", "ifaces",
                        "out_pkts", "in_pkts", "duration_s", "other_endpoints",
                        "party", "note"])
        w.writerow([
            datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
            args.label, args.host or "",
            args.ping if args.ping is not None else "",
            prim["ip"], prim["port"], prim["provider"], prim["city"],
            prim["source"], ",".join(prim["ifaces"]), prim["out"], prim["in"],
            round(prim["dur"], 1), others, args.party or "", args.note or "",
        ])
    print("logged to %s" % path)


def cmd_classify(args):
    print_report(classify(args.pcap))


def cmd_ping(args):
    serial = pick_serial(args.serial)
    out = root_run(serial, "ping -c %d -i 0.2 -W 2 %s 2>&1"
                           % (args.count, args.ip), timeout=args.count + 60)
    print(out.strip())
    rtt = [ln for ln in out.splitlines() if "min/avg/max" in ln]
    if rtt:
        print("\nfrom phone: " + rtt[-1].split("=")[-1].strip())


def cmd_devices(_args):
    devs = list_devices()
    if not devs:
        print("no devices attached")
        return
    for serial, line in devs:
        print(line)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p):
        p.add_argument("--serial", help="adb serial (required when >1 device)")

    p = sub.add_parser("devices", help="list attached devices")
    p.set_defaults(func=cmd_devices)

    p = sub.add_parser("start", help="start a labelled capture on the phone")
    common(p)
    p.add_argument("--label", required=True, help="arm label, e.g. A")
    p.add_argument("--seconds", type=int, default=1500)
    p.set_defaults(func=cmd_start)

    p = sub.add_parser("peek", help="pull the running capture and classify it")
    common(p)
    p.add_argument("--label", required=True)
    p.set_defaults(func=cmd_peek)

    p = sub.add_parser("finish", help="stop, pull, classify, log a row")
    common(p)
    p.add_argument("--label", required=True)
    p.add_argument("--host", help="who hosted / led the party")
    p.add_argument("--ping", type=float, help="displayed in-game ping, ms")
    p.add_argument("--party", help="party composition")
    p.add_argument("--note")
    p.set_defaults(func=cmd_finish)

    p = sub.add_parser("classify", help="classify an existing pcap")
    p.add_argument("pcap")
    p.set_defaults(func=cmd_classify)

    p = sub.add_parser("ping", help="ICMP from the phone, via root")
    common(p)
    p.add_argument("ip")
    p.add_argument("--count", type=int, default=20)
    p.set_defaults(func=cmd_ping)

    args = ap.parse_args()
    try:
        args.func(args)
    except KeyboardInterrupt:
        raise SystemExit(130)


if __name__ == "__main__":
    main()
