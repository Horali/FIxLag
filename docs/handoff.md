# Handoff — MLBB ping research

**Repo:** `https://github.com/Horali/FIxLag` (private)
**Read first:** this file, then `plan.md` (the full research, ~1150 lines), then skim `tools/parse_pcap.py`.
**Status:** research phase complete-ish; no product built; root tooling working.
**Last session:** 2026-11-24.

---

## 1. What this project is

A personal, zero-cost investigation into why the user's Mobile Legends ping is inconsistent when playing in parties, and whether anything client-side can fix it.

**The user:** Surabaya, Indonesia. Samsung Galaxy S25+ (SM-S936B). Plays mostly party (trio/5q) with friends from Indonesia, Malaysia, Singapore, India, Maldives, Philippines, and one in North America. Normally 15–25 ms on Indonesian matches, 40–50 ms when it goes wrong, 230–250 ms on NA.

**The environment gotcha that matters most:** this machine has `adb` at `C:\Users\child\AppData\Local\Android\Sdk\platform-tools\adb.exe` and **multiple devices connected** (emulator, an Infinix, and the S25+). **Always pass `-s <serial>`.** The S25+ serial is usually `RRCY1032Y6F`, but confirm with `adb devices -l` first.

---

## 2. TL;DR of findings

| Finding | Status |
|---|---|
| Ping differences are **server-side**, not the local link | **Measured** |
| Lobby ping measures a **Singapore** gateway and does **not** predict in-game ping | **Measured** |
| The **host's country** sets the server region (ID host → Jakarta, MY host → KL) | **Measured** |
| Each city has **multiple providers** (Jakarta: Zenlayer, Omni Cloud, CDS Global Cloud, Meteverse) with different quality | **Measured** |
| Quality varies **per individual IP**, even inside one /24 (e.g. `169.53.7.247` good, `169.53.7.245` bad) | **Measured** |
| **Network Boost is adaptive multipath** — duplicates the match over Wi-Fi + cellular when comparable, collapses to the better link when one is clearly worse | **Measured** |
| Match server is **not** connected at the accept screen, but **is** connected at **draft pick** | **Measured** |
| The port-30190 probe sweep is **sporadic**; it did not fire during a 25-min capture containing a full match. Trigger unknown | **Measured (negative)** |
| Nothing client-side can force which server you get | **Established** |

**The bottom line:** the ping you get is the server you're given. The ~10 ms difference between "main" (Zenlayer Jakarta, 24.8 ms) and "sub-Indo" (CDS Global Cloud, 35.4 ms) is provider routing, measured three independent ways.

---

## 3. Device and root — read this before touching anything

**Device:** SM-S936B (Galaxy S25+), `pa2q`, Snapdragon 8 Elite (SM8750), Android 17, **One UI 9.0**, kernel `6.6.127`, security patch 2026-10-05. Bootloader **locked** (`green`, `flash.locked=1`), Knox **intact** (`warranty_bit=0`).

**Root:** DirtyFrag (CVE-2026-43284) provides **ephemeral** KernelSU root. It is **gone after any reboot** and must be re-run from the app.

### The critical constraint

**`adb shell` does NOT get root.** KernelSU hooks `execve` and only redirects `su` for allowlisted UIDs. The allowlist (`/data/adb/ksu/.allowlist`) contains **only `com.termux`**. There is **no `ksud` daemon** (`runtime_mode: late-load`, no init hook), so new grants cannot be brokered.

**Do not try to fix this.** Do not hand-edit the allowlist binary (risk of corrupting the only working grant). Do not "enable shell su" — it does not work on this device. This has already been investigated at length; see `plan.md` §5.11.

### The working root channel

**Termux holds root.** `su -c id` inside Termux returns `uid=0(root) context=u:r:ksu:s0`. adb can drive Termux via UI input, and from that a **command daemon** was built:

```
/sdcard/cmd.sh   ← write a shell script here with adb
/sdcard/cmd.out  ← the daemon runs it as root and writes stdout/stderr here
```

**Recovery procedure after a reboot** (in order):

1. Confirm the device: `adb devices -l`, then use `-s <serial>` on everything.
2. Open the **DirtyFrag** app → confirm **Auto reboot is OFF** and **KernelSU Modules: Disabled** → **Run exploit**. Wait for the app log to complete.
3. Open **Termux** and run: `su 0 sh /sdcard/daemon.sh &`
   - If `/sdcard/daemon.sh` is missing, recreate it (contents below).
4. Verify: push `echo ALIVE; id` to `/sdcard/cmd.sh`, wait 5 s, read `/sdcard/cmd.out`. It must say `uid=0(root)`.

**Daemon contents** (`/sdcard/daemon.sh`):

```sh
#!/system/bin/sh
while true; do
  if [ -f /sdcard/cmd.sh ]; then
    mv /sdcard/cmd.sh /sdcard/cmd.run 2>/dev/null
    sh /sdcard/cmd.run > /sdcard/cmd.out 2>&1
    rm -f /sdcard/cmd.run
    echo "__DONE__" >> /sdcard/cmd.out
  fi
  sleep 1
done
```

**Driving Termux from adb** (only needed to start the daemon after a reboot):

```powershell
adb -s <serial> shell "am start -n com.termux/.HomeActivity"
adb -s <serial> shell "input text 'su 0 sh /sdcard/daemon.sh &'"
adb -s <serial> shell "input keyevent 66"
```

**Gotchas:**
- Redirection must happen **inside** the script. A trailing `> /sdcard/x` on the typed command is executed by Termux's unprivileged shell and fails with "Operation not permitted".
- The Termux `RUN_COMMAND` intent is **blocked** (shell lacks `com.termux.permission.RUN_COMMAND`, and `pm grant` does not take). Don't go down that road.
- Wireless ADB works (`adb tcpip 5555`), but the phone's IP **changes** (seen at `.6` and `.17`). Re-check it; the dorm network may also change.

---

## 4. Tooling

**On the device (all via the root daemon):**

| Tool | Path | Notes |
|---|---|---|
| `tcpdump` | `/system/bin/tcpdump` | v4.99.6, libpcap 1.10.6 — already present |
| `conntrack` | `/proc/net/nf_conntrack` | root-only; shell gets permission denied |
| `iptables`, `ip route`, `ip addr` | standard | work as root |
| interfaces | `wlan0` (Wi-Fi), `rmnet_data0` (cellular) | SLL2 ifindex: 44 = wlan0, 62 = rmnet_data0, 14 = rmnet_ipa0 |

**Laptop:**

- `tools/parse_pcap.py` — parses PCAPdroid **or** tcpdump captures (raw IP / Ethernet / SLL / SLL2), prints top UDP flows **with interface attribution**, the port-30190 probe list, and match-server flows. Usage: `python tools/parse_pcap.py <file.pcap> [--probe]`.
- `adb` path above; always `-s <serial>`.

**Capture recipe (no proxy, real timing):**

```sh
# via the root daemon
timeout 1500 tcpdump -i any -n -s 128 -w /sdcard/all.pcap 'udp'
```

Then `adb pull /sdcard/all.pcap captures/all.pcap` and run the parser. Note `-i any` uses **LINUX-SLL2** link type, which the parser handles.

**Server watcher (passive, logs every new UDP destination):** `/sdcard/watch5.sh`, logs to `/sdcard/servers.txt` with a `HB` heartbeat every 10 s and a `BOOT` line. Start it via the daemon with `nohup sh /sdcard/watch5.sh > /dev/null 2>&1 &`. It logs **all apps**, not just MLBB, so filter by port when reading.

---

## 5. Repo layout

```
plan.md                  the research (read §5.6–5.12 for the measured findings)
tools/parse_pcap.py      capture parser (PCAPdroid + tcpdump, SLL2 aware)
docs/handoff.md          this file
.gitignore               ignores *.log, captures/, screen*.png, *.pcap
captures/                local PCAPs, NOT committed
```

Commit style: Conventional Commits, small, imperative, no AI attribution, push to `main`. See `~/.claude/CLAUDE.md`.

---

## 6. What was measured (the numbers to trust)

**Server quality, same phone, same link, same minute (Wi-Fi):**

| Server | Provider | City | min RTT |
|---|---|---|---|
| `216.133.157.51` | Zenlayer | Jakarta | **20.8 ms** |
| `216.133.157.52` | Zenlayer/Bunny | Jakarta | 23.5 ms |
| `103.157.33.34` | Omni Cloud | Jakarta | 20.2 ms |
| `148.153.165.218` | CDS Global Cloud | Jakarta (geo disputed) | **35.4 ms** |
| `169.53.7.247` | IBM Cloud | Dallas | 237.6 ms |
| `169.53.7.245` | IBM Cloud | Dallas | 251.7 ms (avg 292, jitter 36) |

**RTT triplet for the CDS server** (three methods agreeing): ICMP 35.4 ms, game-UDP gap estimation 38.8 ms, in-game display ~40 ms. Overhead ≈ 4–5 ms.

**Multipath:** during a 9-minute match the client sent ~22,100 packets on Wi-Fi *and* ~22,800 on cellular to the same server:port, both directions. For the Dallas server it used cellular only (30 ms better than Wi-Fi at the time).

**Lobby vs in-game:** lobby TCP goes to `161.202.213.215:30101` (Singapore, IBM Cloud). Lobby ping ≈ ICMP to that gateway + overhead. It is a *different, farther* endpoint than the match server, which is why it doesn't predict in-game ping.

**Probe sweep:** UDP to port **30190** across 9–63 servers per sweep (Jakarta, Singapore, KL, Bangkok, Sydney, Almaty, Istanbul, Frankfurt, Netherlands, Dallas, Miami…). Observed live in a lobby once, and post-match twice, but **not** during a 25-minute match capture. Trigger unknown.

---

## 7. Open questions (in priority order)

1. **Why does hosting yourself give a worse server than a friend hosting?** The user's strongest observation: same 5-stack (Malay, Maldivian, Singaporean, Indian teammates), user hosting → 40 ms; user left + restarted MLBB, Malaysian friend became host → **19 ms**. Not explained. Two candidate causes, separable: (a) the app restart flushed cached server-latency state, (b) host identity changes the matchmaking input, (c) luck.
2. **What determines which provider you get within a city?** Solo brawl → Zenlayer; solo classic → CDS; hosted customs → Omni Cloud. Mode, party, load, or random — unknown.
3. **What triggers the 30190 probe sweep, and does its output drive placement?** Never observed during a match.
4. **Is there repeatable way to preview/bias the server?** Currently no: not connected at accept, connected at draft.

---

## 8. How to continue

**The cheapest next test (highest value):** the restart hypothesis. Three matches, each classified in ~5 seconds at **draft pick** using the root daemon (no full match needed if the user bails at draft):

| # | Condition | Question |
|---|---|---|
| 1 | user hosts, no restart | baseline |
| 2 | user hosts, **after app restart** | does restart change the server? |
| 3 | friend hosts | does host identity change it? |

Classification command (via the daemon, dump to `/sdcard/r.txt`):

```sh
grep -i udp /proc/net/nf_conntrack 2>/dev/null | grep -E "dport=5[0-9][0-9][0-9] " | grep -v 5353
```

Match ports seen so far: **5006, 5007, 5505, 5506, 5507, 5511, 5513, 5515, 5516, 5522**. Treat any UDP flow to a public IP on a 5xxx port as the match server.

**If the user plays passively:** start the watcher, let them play, then read `/sdcard/servers.txt` and correlate timestamps with what they report. That's the lowest-effort mode and it's what the user prefers.

**Do not** re-open the "can we build a stabilizer / ExitLag clone" question. It has been answered: MLBB already does local multipath duplication, and the only missing piece (better routing) requires paid infrastructure. See `plan.md` §11 and §5.12.

---

## 9. Hard constraints

- **No paid infrastructure.** No VPS, no VPN subscription, no servers.
- **No game modification**, no memory reading, no matchmaking manipulation. Anti-cheat risk to a long-standing account; the user has drawn this line and it should stay drawn.
- **No bootloader unlock**, no permanent root. Knox must stay intact.
- **Don't capture or correlate other players' data.** MLBB is client-server so teammates' IPs aren't visible anyway; don't go looking.
- **PCAPdroid is for identification only.** Its non-root capture proxies L4 and distorts timing (and it produced 300 ms spikes that vanished without it). Prefer the root `tcpdump`.
- **Displayed in-game ping is the user's ground truth**; ICMP is a proxy; never subtract one from the other and call it server overhead.

---

## 10. User preferences (from `~/.claude/CLAUDE.md`)

- Address as **"Queen Hora"** at least once per response, relaxed tone, no roleplay.
- Plain simple English; the user is learning.
- **Think before doing**: say honestly if an idea is weak or has a catch, and suggest the better version.
- Don't write code when they only want to discuss; ask first.
- Commits: Conventional Commits, small, pushed to `main` of `Horali/FIxLag`, **no AI attribution of any kind**.
- They are clearly technical — they have corrected me on KernelSU internals and were right. Trust their domain knowledge over assumptions.
