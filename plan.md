# MLBB Ping Optimization — Revised Research & Feasibility Plan

**Status:** Research revision complete. No implementation started.
**Revision:** 3 (supersedes revisions 1–2)
**Date:** 2026-11-14
**Subject:** Personal, zero-cost tooling to understand, predict, and possibly improve MLBB ping when playing in parties
**Environment:** Samsung Galaxy S25+ (SM-S936B, Android 17), Windows laptop, ADB over USB, no paid infrastructure

> **Revision note.** Revision 1 drew conclusions the evidence did not support — it mapped ping values to physical data centers, declared latency floors, and promoted Network Boost to the leading cause of instability. Revision 2 removed those claims and rebuilt the measurement methodology around what can be observed without root. **Revision 3 integrates your follow-up answers**, which resolve the "circularity" problem (your server labels come from player flags, not ping) and surface a strong new signal: the number of Indonesian players in the party correlates with getting your main server. A full change list is in §15.

---

## 0. Executive summary

### 0.1 What the evidence supports

1. **Your ping is stable within a match and varies between matches.** You reported this directly, and it is the single most informative fact available. It largely rules out mid-match path switching (Network Boost, Samsung auto-switch) as the cause of the variation you care about.
2. **Your server labels are not circular — they come from player flags, not ping.** You identify an Indonesian match by opponents' flags and language, and a Singapore match by flags or by an SG host in a custom room. That is a genuine independent signal, and it removes the blocking concern from revision 2. **But it identifies the player pool, not the server's physical location** — an Indonesian-pool match can still be hosted outside Indonesia. So "sub-Indonesian" means *"Indonesian-pool match where my ping is 30–45 ms"*, and the cause could be a farther Indonesian facility, a non-Indonesian facility serving an Indonesian pool, a worse route, or server load.
3. **Network Boost helps you.** You report that without it, ping is much worse. Moonton's own Q&A describes Network Boost as choosing the best network in real time between Wi-Fi and cellular. It is therefore a **path selector**, and your evidence says it is selecting a better path than your dorm Wi-Fi alone. Revision 1's recommendation to disable it was wrong.
4. **Bandwidth is not your constraint.** Dorm Wi-Fi at ~12 Mbps and home Wi-Fi at ~500 kbps both produce 15–20 ms. MLBB's throughput is on the order of tens of kilobits per second, so both links are far above what the game needs. Latency here is dominated by round-trip time and queuing, not capacity. Upgrading bandwidth will not fix ping.
5. **Party composition influences placement probabilistically, not deterministically.** You often get your main server at ~20 ms even as the only Indonesian, but you report that 2–3 Indonesians in the lobby makes the main server more reliable — with 2 being "a bit of a gacha" and 3 usually fine, though sometimes still 30–40 ms. That is a real signal and the most actionable one available. **It may also be a confounder** (you may simply play with more Indonesians at different hours), so it needs a controlled test rather than acceptance.

### 0.2 What remains unknown

- **Which IPs MLBB actually connects to** during lobby and during a match. None have been captured yet.
- **Whether those IPs are in Indonesia, Singapore, or elsewhere.** IP geolocation is an estimate, not proof.
- **Why an Indonesian-pool match sometimes gives 15–25 ms and sometimes 30–45 ms.** This is now the central question, and it is much narrower than revision 2's version of it.
- **Whether the party-size effect is causal.** Your 2-vs-3 Indonesian observation is the strongest lead you have given, but party composition may correlate with time of day, which may itself drive placement.
- **Whether placement depends on your effective public IP**, which may change depending on whether Network Boost is using Wi-Fi or cellular.
- **Why the behaviour changes between seasons**, and whether that is a Moonton policy change, a capacity change, or something on your side.

### 0.3 What is realistically achievable

| Goal | Assessment | Basis |
|---|---|---|
| Identify which endpoints MLBB uses, per match | **Likely achievable**, pending a capability probe | Depends on whether MLBB uses connected UDP sockets — unverified |
| Classify endpoints by network ownership and probable region | **Achievable with stated uncertainty** | ASN + GeoIP + latency bounds; never certainty |
| Distinguish lobby endpoint from match endpoint | **Likely achievable** | Different lifetimes and traffic patterns |
| Separate "network path" from "server-side" contributions | **Only partially**, and not by subtraction | ICMP and displayed ping are not commensurable |
| Explain the between-match variation | **Achievable if endpoints differ**; harder if they don't | Depends on Phase 1 results |
| Increase the probability of getting your main server | **Possibly**, via path and timing experiments | Only if placement correlates with something you control |
| Reduce latency below what the server gives you | **No** | Not a software problem |
| Force a specific server | **No** | Matchmaker decision; VPN is the only lever and carries ToS risk |

**The honest reframing:** the realistic optimization target is not "lower ping." It is **"raise the probability of being placed on the server that gives you 15–25 ms, and stop being surprised when you are not."** That is a measurable, achievable goal. "Make a Singapore server feel like a Jakarta server" is not.

---

## 1. Evidence ledger

Every substantive claim in this document is tagged. This is the discipline revision 1 lacked.

| Tag | Meaning |
|---|---|
| **[VERIFIED]** | Confirmed by official documentation or a primary source, with a link |
| **[OBSERVED]** | Reported by you, or directly observable on your device |
| **[INFERRED]** | A reasoned conclusion from verified facts; could be wrong |
| **[ANECDOTAL]** | Community reports; directionally useful, not proof |
| **[UNKNOWN]** | No reliable basis; must be measured |

### 1.1 Claims about MLBB

| # | Claim | Tag | Source / basis |
|---|---|---|---|
| M1 | MLBB is a Unity-based MOBA using dedicated servers, not peer-to-peer | [VERIFIED] | Wikipedia; consistent across sources |
| M2 | MLBB has regional clients/regions and a permanent per-account Server/Zone ID | [VERIFIED] | Game UI; secondary source |
| M3 | Matchmaking pool is influenced by connection origin (IP) | [INFERRED] | One secondary source states this; consistent with community reports. **Not officially documented.** |
| M4 | Moonton operates an Indonesian data center, built with Telkomsel, associated with Speed Mode | [INFERRED] | Indonesian press report. Details (location, scope, which players it serves) unverified. |
| M5 | Network Boost "chooses the best network in real time" between Wi-Fi and cellular, and requires both enabled | [VERIFIED-ish] | Moonton Q&A relayed via official channels. Semi-official; treat as strong but not formal documentation. |
| M6 | Speed Mode routes traffic differently at the cost of more data | [ANECDOTAL] | Multiple secondary sources; no official spec found |
| M7 | In-match traffic is UDP; lobby/auth traffic is TCP/HTTPS | [INFERRED] | Consistent with genre norms and community reports. Not directly observed on your device yet. |
| M8 | The displayed in-game ping is raw network RTT | **[UNKNOWN]** | No documentation. It may include server processing, tick alignment, or smoothing. **Do not assume.** |
| M9 | The displayed lobby ping measures the same endpoint as in-game ping | **[UNKNOWN]** | Almost certainly not, but unverified |
| M10 | Room master / party leader determines the match server | **[UNKNOWN]** | Your own evidence argues against it as a general rule |
| M11 | Cross-region parties are placed on a compromise server | **[ANECDOTAL]** | Community reports; contradicted in part by your main-server observations |
| M12 | An all-Indonesian party always receives an Indonesian server | **[UNKNOWN]** | No evidence either way |
| M13 | MLBB server tick rate and netcode behaviour | **[UNKNOWN]** | Not public; do not estimate |

### 1.2 Claims about measurement

| # | Claim | Tag | Source / basis |
|---|---|---|---|
| T1 | `adb shell` (the `shell` user) can read `/proc/net/udp` on non-rooted Android, while ordinary apps cannot | [VERIFIED-ish] | User report on a fully updated device; consistent with Android's app-side `/proc/net` restrictions. **Must be re-probed on your S25+.** |
| T2 | `/proc/net/udp` populates `rem_address` **only for connected sockets** | [VERIFIED] | proc_net(5): "the remote address and port number pair (if connected)" |
| T3 | Whether MLBB uses connected or unconnected (`sendto`) UDP sockets | **[UNKNOWN]** | Decisive for the ADB approach. Must be probed. |
| T4 | `/proc/net/udp` may be incomplete for UDP 5-tuples | [ANECDOTAL] | Developer reports; mechanism unclear. Probe required. |
| T5 | Android 13+ restricts netlink and `/proc/net` for apps (not shell) | [VERIFIED] | Termux issue tracker; Android platform behaviour |
| T6 | PCAPdroid non-root capture **proxies** connections via L4 sockets, altering headers, sizes, and timing | [VERIFIED] | Official PCAPdroid docs |
| T7 | PCAPdroid's own docs say non-root capture is unsuitable for packet timing analysis | [VERIFIED] | Official PCAPdroid docs |
| T8 | Android permits only one active `VpnService` at a time | [VERIFIED] | Android platform behaviour; PCAPdroid FAQ |
| T9 | ICMP RTT is not equivalent to UDP application latency | [VERIFIED] | Networking fundamentals; ICMP may be rate-limited, deprioritized, or blocked, and may take a different path |
| T10 | IP geolocation databases are estimates and can be wrong for CGNAT, anycast, and mobile ranges | [VERIFIED] | Well-documented limitation of GeoIP |

### 1.3 Claims about your setup

| # | Observation | Tag |
|---|---|---|
| U1 | You play from Surabaya | [OBSERVED] |
| U2 | You use dorm Wi-Fi (ISP unknown) and mobile data, sometimes both | [OBSERVED] |
| U3 | Dorm Wi-Fi measured ~12 Mbps down at some point; home Wi-Fi ~500 kbps | [OBSERVED] |
| U4 | Network Boost is ON and materially improves your ping | [OBSERVED] |
| U5 | Samsung "switch to mobile data" is ON; adaptive Wi-Fi state unknown | [OBSERVED] |
| U6 | Speed Mode state uncertain; you perceive slight benefit | [OBSERVED] |
| U7 | Your parties are mostly Indian, Malaysian, and Filipino players, plus some Indonesian; you are usually host | [OBSERVED] |
| U8 | You usually get ~20 ms even as the sole Indonesian; sometimes you get 40–50 ms instead | [OBSERVED] |
| U9 | Rank bracket: Honor / Immortal | [OBSERVED] |
| U10 | Mostly party play, trio or 5-stack; rarely solo | [OBSERVED] |
| U11 | Variation is between matches/sessions, not within a match | [OBSERVED] |
| U12 | Hosting used to give you the main server more often than it does now | [OBSERVED] |
| U13 | You identify an Indonesian match by opponents' flags/language, and a Singapore match by flags or by an SG host in a custom room | [OBSERVED] — **resolves the circularity concern** |
| U14 | "Sub-Indonesian" = Indonesian-pool match where your ping is 30–40 ms instead of 15–25 ms | [OBSERVED] |
| U15 | 2–3 Indonesians in the lobby usually gives the main server; 2 is "a bit of a gacha"; 3 has "been fine" — but sometimes still 30–40 ms | [OBSERVED] |
| U16 | Ping behaviour changes substantially between seasons | [OBSERVED] |
| U17 | Dorm Wi-Fi (~12 Mbps) and hometown Wi-Fi (~500 kbps) give the same 15–20 ms with Network Boost | [OBSERVED] |
| U18 | You will not play without Network Boost, because it is much worse | [OBSERVED] — constrains experiment design |

---

## 2. Your reported situation, structured

This is the dataset the tool must explain. Note that it is currently **self-reported and unverified**, and that is fine as a starting point — but it must not be treated as ground truth about server location.

| Condition | Observed ping | How you identify it | What it establishes |
|---|---|---|---|
| Indonesian-pool match, good outcome | 15–25 ms | Indo flags / language | Pool is Indonesian; **some** server is nearby |
| Indonesian-pool match, worse outcome | 30–40 ms, avg ~45 ms | Indo flags / language | Pool is Indonesian; **the nearby server is not being used** |
| Singapore-pool match, good host | ~30 ms | SG flags, or SG host in custom room | Pool is SG; server plausibly SG |
| Singapore-pool match, bad host | ~50 ms | SG flags, or SG host in custom room | Pool is SG; facility or route differs |
| 2–3 Indonesians in lobby | usually 15–25 ms | Party composition | Composition correlates with outcome |
| 2 Indonesians in lobby | "gacha" | Party composition | Weak or noisy effect |
| Recent seasons | 30–45 ms more often | Time | Something changed |

**Three things stand out.**

First, **the flag-based identification is a genuine independent signal**, and it removes the circularity that revision 2 flagged as blocking. You are not inferring location from ping. That matters, and it upgrades the quality of every observation in this table.

Second, **the same pool produces two different ping bands.** An Indonesian match at 15–25 ms and an Indonesian match at 30–45 ms cannot both be using the nearest server. Something within the Indonesian path differs — facility, route, or load. This is now the central question, and it is much narrower than "is it Indonesia or Singapore?"

Third, **party composition correlates with the outcome.** More Indonesians → better ping, more reliably. That is either a causal effect of the matchmaker's party-region weighting, or a confounder (you may play with more Indonesians at different hours). Distinguishing those two is a specific, tractable test, and it is the most promising lead in the whole dataset.

---

## 3. A more accurate model of MLBB networking — with explicit uncertainty

### 3.1 What is reasonably established

```
[Phone] --TCP/HTTPS--> [auth / lobby / matchmaking gateway]   ← "lobby ping" probably measures here
   |
   |  match found
   v
[Phone] --UDP--> [match server, assigned by matchmaker]        ← "in-game ping" probably measures here
```

- The lobby and the match almost certainly involve **different endpoints**. This is the most likely explanation for lobby ping and in-game ping differing, and it is consistent with your observation that they have recently converged (both endpoints may now sit in the same facility or region for you).
- The match server is **assigned**, not chosen by the client. There is no documented client-side control over it.
- Your region's player pool, server inventory, and assignment policy are **not public**.

### 3.2 What is genuinely unknown

| Question | Why it matters | How to resolve |
|---|---|---|
| Are "main" and "sub-Indonesian" different IPs? | If yes, it is placement. If no, it is path or load. | Phase 1 endpoint capture |
| Do those IPs belong to different ASNs/providers? | Distinguishes different facilities from different routes | ASN lookup |
| Are "sub-Indonesian" IPs actually Indonesian? | Your entire mental model depends on it | GeoIP + latency bound + ASN |
| Does the lobby endpoint differ from the match endpoint? | Explains lobby vs in-game divergence | Phase 1, separated by phase |
| Does your effective public IP change with link type? | Could change matchmaking pool if M3 is true | Compare public IP on Wi-Fi vs cellular |
| Is placement time-dependent? | Would suggest load-driven assignment | Log timestamps |

### 3.3 The competing explanations for a 30–45 ms Indonesian-pool match

These are structurally distinct, and they have **different fixes**:

1. **Different Indonesian facility.** You are on a second Indonesian data center, farther from Surabaya. Fix: none client-side; only placement probability.
2. **Different route to the same facility.** Same server, worse path. Fix: possibly, via path selection or ISP.
3. **Same facility and route, worse server-side conditions.** Congestion or a different server instance. Fix: none client-side.
4. **A non-Indonesian facility serving an Indonesian pool.** The players are Indonesian, but the match is hosted elsewhere. Fix: none client-side.

**The flag caveat matters here.** Player flags reflect account region, not server location. A match where every opponent shows an Indonesian flag can still be hosted outside Indonesia. So explanation 4 stays live even though the pool is unambiguously Indonesian.

**Revision 1 collapsed these into one story. They must be separated by measurement, because only #2 is actionable.**

---

## 4. Measurement methodology

This is the core of the revision. The rule is: **measure each layer separately, never subtract one from another and call the difference a component.**

### 4.1 The five layers

| Layer | What it is | Measurable? | Method | Trust level |
|---|---|---|---|---|
| **L1** | ICMP RTT to a candidate IP | Yes | `ping` from phone or PC | Network-layer only; may be deprioritized or blocked |
| **L2** | Observed UDP traffic (flow, timing, volume) | Partly | Socket tables, capture | Flow existence and timing reliable; payload opaque |
| **L3** | MLBB displayed **lobby** latency | Yes, by you | Manual entry | Semantics unknown |
| **L4** | MLBB displayed **in-game** latency | Yes, by you | Manual entry | Semantics unknown |
| **L5** | Server-side processing, tick alignment, queueing | **No** | — | Not independently measurable |

### 4.2 The subtraction fallacy — explicitly rejected

Revision 1 proposed:

```
overhead = in-game ping − ICMP RTT
```

**This is invalid and is removed.** Reasons:

- ICMP may be **rate-limited, deprioritized, or blocked** by the server or an intermediate hop, making it *higher* than the UDP path.
- ICMP and UDP may take **different paths**.
- ICMP measures **network only**; displayed ping includes **server processing and tick alignment**.
- The two are measured at **different times**, under different load.
- Displayed ping may be **smoothed or quantized**, so it is not a clean sample.

The correct statement is: *"ICMP RTT to this IP was X ms; displayed ping was Y ms."* That is two observations. It is **not** a decomposition, and the difference must not be reported as "server overhead."

### 4.3 What can legitimately be concluded

| Comparison | Valid conclusion | Invalid conclusion |
|---|---|---|
| Same IP, ICMP RTT across conditions (Wi-Fi vs cellular) | The path changed by Δ ms | "The game will be Δ ms faster" |
| Same IP, ICMP stable but displayed ping varies | Variation is **not** in the ICMP-visible path | "It is server processing" |
| Different IPs, both with ICMP measured | Different endpoints, possibly different facilities | "The server is in city X" |
| Displayed ping across matches, same IP | Server-side or path variation | Which of the two |
| Traceroute hop latencies | Where latency is added along the path | That the game uses that exact path |

### 4.4 Practical measurement plan per match

For each match, record:

1. **Phase-separated endpoint observations** — lobby phase and in-match phase kept separate, with timestamps.
2. **Displayed lobby ping** and **displayed in-game ping** — entered manually (or via screenshot OCR later; not initially).
3. **ICMP RTT** to each observed endpoint, measured *after* the match from the same link, with at least 20 samples.
4. **TCP SYN RTT** to the same IP on a couple of ports, as a cross-check against ICMP treatment.
5. **Traceroute** to the match endpoint, to see the path and where latency accrues.
6. **Link state** — Wi-Fi vs cellular vs both, SSID/BSSID, signal, carrier.
7. **Party composition and host.**
8. **Time of day.**

### 4.5 What we will explicitly *not* claim

- That a displayed ping equals network RTT.
- That the difference between displayed ping and ICMP is server processing.
- That an IP's registered country is where the server physically is.
- That a 10-match sample proves a difference.

### 4.6 Worked example: why dorm Wi-Fi and hometown Wi-Fi give the same ping

You observed that dorm Wi-Fi (~12 Mbps) and hometown Wi-Fi (~500 kbps) both give 15–20 ms with Network Boost on, and found this counter-intuitive. It is actually expected, and the explanation matters because it tells you where *not* to spend effort.

**Bandwidth is not latency.** MLBB's in-match throughput is on the order of tens of kilobits per second — a few kilobytes per second. A 500 kbps link is roughly ten times more than the game needs; a 12 Mbps link is roughly two hundred times more. Neither is close to saturation, so neither adds queuing delay. Throughput and round-trip time are different properties, and only one of them affects ping.

**Network Boost may be choosing cellular in both cases.** Moonton describes Network Boost as picking the best network in real time [M5]. If your dorm Wi-Fi has high latency or contention — likely, since it is shared among many students — Network Boost may be selecting cellular for the match. At home, a 500 kbps link may also lose to cellular. If both cases end up on the same cellular path, the ping is the same and the Wi-Fi difference becomes irrelevant. This is the most plausible explanation, and it is directly testable.

**The local link may simply be a small term.** If the server is 12 ms away and your local link contributes 3–5 ms, improving the local link to 1 ms changes the total by a few milliseconds — inside the noise of what you observe. The dominant term is distance plus path, not the last hop.

**How to test it — short diagnostic runs, not full games:**

1. **Wi-Fi only** — mobile data off, Network Boost off — ping the match endpoint and a public anchor for 60 seconds.
2. **Cellular only** — Wi-Fi off — same measurement.
3. **Both, Network Boost on** — same measurement.
4. In each case also ping the local gateway and `1.1.1.1`, to separate the local link's contribution from the path's.

If Wi-Fi-only is materially worse than cellular-only, Network Boost is masking a weak dorm network, and the "same ping" really means "both cases used cellular." If all three are similar, the local link is not your bottleneck and you can stop worrying about it.

**This is diagnostic only.** You do not need to play a match without Network Boost. A minute of pinging per condition answers the question.

---

## 5. ADB feasibility and capture options

### 5.1 The `/proc/net/udp` question — the decisive unknown

The approach is attractive because it is **read-only, root-free, and adds zero latency**. But it hinges on one thing:

> **Does MLBB use connected UDP sockets?**

`/proc/net/udp` populates `rem_address` **only for connected sockets** [VERIFIED, proc_net(5)]. If MLBB uses unconnected sockets with `sendto`, every row will show `00000000:0000` and the method yields **no destination IP at all**.

There are also secondary risks: the table may be incomplete for UDP 5-tuples [ANECDOTAL], and Samsung/One UI behaviour is unverified [UNKNOWN].

**Therefore: probe before building. Do not assume.**

### 5.2 Capability probe (Phase 0 deliverable)

Run these on the S25+ and record results. This is not implementation — it is a handful of shell commands.

```
# Platform
adb shell getprop ro.build.version.release
adb shell getprop ro.build.version.sdk
adb shell getprop ro.product.model

# MLBB identity
adb shell dumpsys package com.mobile.legends | grep -E "userId|versionName"

# Can shell read the tables at all?
adb shell cat /proc/net/udp
adb shell cat /proc/net/udp6
adb shell cat /proc/net/tcp

# Alternative sources (may fail)
adb shell cat /proc/net/nf_conntrack
adb shell netstat -un
```

Then, **during an actual match**, repeatedly dump `/proc/net/udp` and `/proc/net/udp6` and look for rows whose UID column matches MLBB's.

**Decision tree:**

| Probe result | Interpretation | Path forward |
|---|---|---|
| Rows with MLBB UID **and non-zero `rem_address`** | Connected sockets; method works | **Primary method.** Build collector. |
| Rows with MLBB UID but `rem_address` all zeros | Unconnected sockets | ADB alone insufficient → fallback |
| No rows with MLBB UID | Table restricted, or app uses a different netns | → fallback |
| `cat` fails entirely | `/proc/net` restricted for shell on this ROM | → fallback |

### 5.3 Capture options compared

| Method | Works without root | Adds latency? | Fidelity | Changes the path? | Verdict |
|---|---|---|---|---|---|
| **ADB `/proc/net/udp`** | Yes (if connected sockets) | **No** | Endpoint IP + UID only; no timing | No | **Preferred if probe passes** |
| **PCAPdroid (no-dump mode)** | Yes | **Yes** — proxies via L4 sockets | Endpoint IP reliable; timing distorted | Yes (becomes the VPN) | Identification fallback only |
| **PC as Wi-Fi hotspot + Wireshark** | Yes | Small (one extra hop) | Full packets, accurate timing | **Yes** — phone routes via laptop | Best for packet-level truth; not for latency |
| **Router capture** | N/A | No | Full | No | Unavailable on dorm Wi-Fi |
| **Root tcpdump** | No | No | Full | No | **Excluded** (no root) |

**Critical interaction:** PCAPdroid installs a `VpnService`, and Android allows only one at a time [VERIFIED]. A VPN also typically binds to a single underlying network, which can **interfere with Network Boost's dual-path selection**. So captures taken under PCAPdroid may not represent normal gameplay. Note this in every capture's metadata.

**Recommended strategy:** try ADB first (zero interference). If it fails, use PCAPdroid **only to learn the IP**, then measure RTT separately on the normal path with Network Boost restored. Never use PCAPdroid timing as latency data.

### 5.4 Polling design

- Match sockets persist for the whole match (10–20 min), so **1 Hz polling is sufficient for match endpoints**.
- Lobby/gateway sockets may be short-lived; poll faster during lobby transitions if needed.
- **Do not spawn `adb shell` per poll** — process startup dominates. Instead, push a small polling loop to `/data/local/tmp/` and stream its output, or hold a persistent `adb shell` session.
- USB ADB has negligible battery and CPU cost; wireless ADB should be avoided during measurement to eliminate a confound.

### 5.5 IPv4/IPv6 correctness

- `/proc/net/udp` and `/proc/net/udp6` are separate files; **both must be read**.
- Addresses are hex, **little-endian per 32-bit word**. IPv4: `0100007F:1C23` → `127.0.0.1:7203`. IPv6 uses four such words and is easy to get wrong — validate the parser against a known-good tool before trusting it.
- If MLBB uses IPv6, an IPv4-only collector will silently miss everything.

### 5.6 Phase 0 probe results — verified on this device (2026-11-14)

The capability probe was run against the actual phone. Results:

| Check | Result | Status |
|---|---|---|
| adb authorization | OK, `adb` 37.0.1, device `RRCY1032Y6F` | **Verified** |
| Device / OS | SM-S936B, **Android 17** (SDK 37), build `CP2A.260605.016.S936BXXUDDZJB` | **Verified** |
| MLBB package | `com.mobile.legends`, **UID 10372**, v2.2.23.12351 | **Verified** |
| `shell` can read `/proc/net/udp` | Yes — 25 rows returned | **Verified** |
| `rem_address` populated for connected sockets | **Yes** — two QUIC sockets to Google on `:443` showed real remotes | **Verified** |
| `shell` can read `/proc/net/udp6` | Yes — 6 rows | **Verified** |
| MLBB uses native IPv6 | **No** — its `tcp6` sockets are IPv4-mapped (`::ffff:x.x.x.x`) on `:443` | **Verified** |
| Lobby phase transport | **TCP only** — zero MLBB UDP sockets while sitting in the lobby | **Verified** |
| Lobby/gateway endpoint | `161.202.213.215:30101` → **IBM Cloud (SoftLayer), AS36351, Singapore** | **Verified** |
| Match-phase UDP sockets | Not yet observed | **Pending a match** |

**What this settles.** The zero-overhead ADB method is structurally viable on this device: the table is readable, and connected sockets expose their remote addresses. The only remaining question is whether MLBB's *match* sockets are connected — which needs one match to answer.

**What it changes in the model.** The lobby is TCP-only, so the "lobby ping" you see is measured over TCP or by a short-lived probe, not over the match protocol. That is direct evidence that lobby ping and in-game ping are different measurements and should never be compared as if they were the same quantity (§4.1).

**A note on the Singapore gateway.** The login/gateway being in Singapore does *not* mean matches are hosted there. It is one endpoint among several. It does show that Moonton's SEA authentication path hubs in Singapore, which is consistent with — but not proof of — the idea that SEA match infrastructure may also be regionalised there.

### 5.7 Match-phase result: the ADB method cannot identify the server (verified 2026-11-14)

A custom match was started (user-hosted, one Philippine friend). During loading, MLBB opened two UDP sockets:

```
0.0.0.0:40060   rem 00000000:0000   st 07
0.0.0.0:48438   rem 00000000:0000   st 07
```

**Both are unconnected.** `rem_address` is zero and the local address is `0.0.0.0` — the game uses `sendto` on unbound sockets. `/proc/net/udp` therefore gives the local port but **never the destination**.

Fallbacks tested and rejected:

| Method | Result |
|---|---|
| `/proc/net/nf_conntrack` | `-r--r----- root root` → **permission denied** for shell |
| `netstat -uan` | Lists the sockets, but foreign address is `0.0.0.0:*` — same data, same limitation |
| `ss -un` | Netlink **permission denied**; partial output only |
| `logcat` | No server or IP lines from MLBB |
| `/proc/<pid>/net/udp` | Same network namespace as `/proc/net/udp` — no new information |

**Conclusion: without root, the kernel will not tell us where MLBB sends its packets.** The zero-overhead method is dead for endpoint identification. This was flagged as the decisive risk in §5.1; it is now resolved negatively.

**Revised recommendation — capture, don't inspect:**

1. **PCAPdroid** (free, open source), no-dump mode, app filter on MLBB. It sees the destination IP because it intercepts at the IP layer regardless of socket type. Costs: occupies the single VPN slot, proxies traffic, and may interfere with Network Boost during the capture. Use for **identification runs only**, then measure RTT separately with normal settings.
2. **Laptop-hosted hotspot + Wireshark.** No phone-side app and no VPN slot, but this laptop has Wi-Fi only (no Ethernet), so Wi-Fi→hotspot sharing may not work, and it inserts a hop that changes the path. Identification only.

**What this does not invalidate:** the ICMP/RTT methodology, party-composition logging, and network-quality measurements all still work. Only *endpoint identification* needs a different tool.

### 5.8 First successful capture: server identified, and a global probe sweep discovered (2026-11-14)

PCAPdroid was installed and a capture taken during a user-hosted custom match with one Philippine friend (745 KB, 4,193 packets, link type raw IP).

**The match server was identified:**

```
103.157.33.137:5522   ↔  phone   2,427 packets over 33.4 s
→ Jakarta, Indonesia · AS141109 PT Omni Cloud Indonesia
```

So this match ran on an **Indonesian** server, not Singapore — consistent with the user's own "sub indo" label, and the first time that label has been corroborated by an actual IP.

**A second, unexpected behaviour: a global latency probe sweep.**

Immediately after the match ended (return to lobby), MLBB sent **12 single UDP packets to port 30190, roughly one per second**, to servers around the world:

| Target IP | Location | Provider |
|---|---|---|
| `138.113.116.210` | **Jakarta, ID** | Meteverse |
| `161.202.206.8` | Singapore | IBM Cloud |
| `164.52.101.74` | Singapore | CDS Global Cloud |
| `156.59.62.2` | Kuala Lumpur, MY | Zenlayer |
| `156.59.174.66` | Bangkok, TH | Zenlayer |
| `103.96.77.3` | Sydney, AU | — |
| `95.56.249.147` | Almaty, KZ | Kazakhtelecom |
| `162.128.95.191` | Istanbul, TR | Zenlayer |
| `158.177.179.120` | Frankfurt, DE | IBM Cloud |
| `169.51.41.168` | Lelystad, NL | IBM Cloud |
| `128.14.211.34` | Dallas, US | Zenlayer |
| `128.14.216.62` | Miami, US | Zenlayer |

Some targets replied from a different source port (e.g. `95.56.249.147:39161`, `156.59.62.2:60537`).

**Interpretation (hypothesis, not established):** this looks like a **regional latency probe** — the client measures round-trip time to a set of regional servers, presumably to decide which region's pool to place the player in. If so, it is the first direct view of the mechanism behind the user's "unpredictable" placement: the game is measuring latency to servers worldwide, and those measurements vary with network conditions.

**A testable sub-hypothesis that would explain the two Indonesian ping bands.** The probe list contains a Jakarta server from **Meteverse** (`138.113.116.210`), while the match actually ran on a Jakarta server from **Omni Cloud** (`103.157.33.137`). Two different Indonesian providers would mean two different Indonesian facilities — which is exactly the shape of the user's "main server" (15–25 ms) versus "sub indo" (30–45 ms) distinction. **This is now the single most promising explanation for the core symptom.**

**Caveats.** The capture ran under PCAPdroid's VPN, so the latency during that match is not representative (the VPN proxies traffic and likely disabled Network Boost). The *server IP* is valid; the *ping* is not. Also, the probe sweep occurred after the match, not before it, so its causal role in placement is inferred rather than observed.

**Second capture (2026-11-14, 23:17–23:26).** A second custom match, this time with a **Vietnamese** friend, produced a **63-server probe sweep** over 27 seconds — a different and far larger list than the first sweep's 12. Notable entries:

| Target | Location | Provider |
|---|---|---|
| `103.157.33.33` | Jakarta, ID | Omni Cloud (same /24 as the match server) |
| `148.153.100.254` | Jakarta, ID | CDS Global Cloud |
| `138.113.116.245` | Jakarta, ID | Meteverse |
| `161.202.218.136` and many `161.202.x` | Singapore | IBM Cloud |
| `43.133.218.215` | Tokyo, JP | Tencent Cloud |
| `15.220.137.149` | Delhi, IN | AWS (ap-south-1) |
| `103.96.77.3` | Sydney, AU | — |
| `162.128.95.191` | Istanbul, TR | Zenlayer |

**At least three distinct Jakarta providers** appear (Omni Cloud, CDS Global Cloud, Meteverse). That strengthens the two-facility hypothesis: "Indonesian server" is not one thing, and the ping difference between them is exactly the shape of the user's main-vs-sub-Indo symptom.

**Two concurrent match connections were also observed:**

```
+210.3s  →  161.202.220.150:10011   Singapore, IBM Cloud
+213.7s  →  103.157.33.34:5507      Jakarta, Omni Cloud
```

Both ran for the full match with similar packet volumes. This is not a reconnect — it looks like a **multi-server or relay architecture**, where the client holds connections to more than one regional server. If the user's experienced latency depends on the worse of two paths, that is itself a source of instability. Mechanism unknown; flagged as an open question.

**VPN caveat, now confirmed as material.** PCAPdroid's non-root capture proxies L4 sockets, which inflates latency and, more importantly, **distorts the game's own latency probes**. Since those probes appear to feed placement, running PCAPdroid during play may change matchmaking. **Use it only for short identification captures, never during normal play.** ICMP measurements taken from `adb shell` bypass the VPN (the app filter scopes it to MLBB), so they remain valid for characterising the real path.

**Lobby ping vs in-game ping — explained with numbers (2026-11-14, 23:30).** With the VPN off, the user reported lobby ping **55–60 ms** but in-match ping **40–45 ms** — the lobby reading being *higher*. Measurement confirms why:

| Phase | Endpoint | ICMP min | Displayed |
|---|---|---|---|
| Lobby | `161.202.213.215` — Singapore, IBM Cloud | 46.5 ms | 55–60 ms |
| Match | `103.157.33.34` — Jakarta, Omni Cloud | 28.3 ms | 40–45 ms |

The lobby gateway is in **Singapore**; the match server was in **Jakarta**. The ~18 ms gap between the two ICMP minima is the Singapore↔Jakarta distance, and the displayed pings track it with a consistent ~10–17 ms of application overhead.

**Conclusion: lobby ping is not a predictor of in-game ping — it measures a different and farther endpoint.** This is the first quantitative confirmation of the §3.1 hypothesis, and it explains the user's observation that lobby and custom-room readings do not translate to classic/ranked performance.

**Network state that night deteriorated badly.** By 23:30, ICMP to the Jakarta server showed **20% packet loss**, avg 220 ms, max 906 ms. Any placement conclusion drawn from that session is confounded by congestion; the endpoint findings remain valid, the latency findings do not.

**Third capture (2026-11-14, 23:35–23:46): solo brawl — the main server identified.**

```
216.133.157.51:5506   →   Jakarta, Indonesia · AS62610 Zenlayer
16,385 packets over 10.4 minutes
```

The user confirms this is their **main server** — the 22–33 ms experience they consider normal. This is the first capture of a match they identify as "main," and it ran on **Zenlayer Jakarta**, not Omni Cloud Jakarta.

**This is the strongest evidence yet for the provider hypothesis:**

| Match | Server | Provider | User's experience |
|---|---|---|---|
| Solo brawl | `216.133.157.51` | **Zenlayer**, Jakarta | **main server, 22–33 ms** |
| Custom (PH friend) | `103.157.33.137` | Omni Cloud, Jakarta | sub-Indo, 30–40 ms |
| Custom (VN friend) | `103.157.33.34` | Omni Cloud, Jakarta | sub-Indo, 30–45 ms |

Same city, different provider, different experience. **"Main vs sub-Indo" may be a provider difference rather than a city difference** — which would mean the user has never been on a Surabaya server, and the variable is *which Jakarta facility*.

**Important confound:** the main-server match was **solo**, while both sub-Indo matches were **custom rooms with foreign friends**. Provider and party composition are entangled. Disentangling them requires either a solo match landing on Omni Cloud, or a custom match landing on Zenlayer.

**Probe sweep:** 14 probes after the brawl, again a different subset — the pool is larger than any single sweep, so the client appears to sample it rather than exhaustively test it each time.

**Fourth capture (2026-11-14, 23:55): MY-hosted brawl — the host's region wins.**

```
156.59.164.174:5515   →   Kuala Lumpur, Malaysia · AS21859 Zenlayer
ICMP min 37.6 ms · avg 47.4 ms · 0% loss
```

The user confirmed in-game that it was a Malaysian server. **This confirms that the host's region determines the server region.** When the user (Indonesia) hosted custom rooms, the server was Jakarta; when a Malaysian friend hosted, it was Kuala Lumpur.

**The refined model after four captures:**

| Condition | Server city | Provider | ICMP floor |
|---|---|---|---|
| Solo brawl | Jakarta | **Zenlayer** | 22 ms |
| User-hosted custom (PH / VN friends) | Jakarta | **Omni Cloud** | 21 ms |
| MY-hosted brawl | **Kuala Lumpur** | Zenlayer | 38 ms |

Two separate variables are now visible:

1. **Region** — follows the **host's country**. Indonesia host → Jakarta; Malaysia host → KL.
2. **Provider within that region** — not yet explained. Solo brawl gave Zenlayer; user-hosted parties gave Omni Cloud, both in Jakarta.

That second variable is the most promising remaining lead, because it is the difference between the user's "main server" (Zenlayer, 22–33 ms) and "sub-Indo" (Omni Cloud, 30–45 ms) *within the same city*.

**Practical consequence for the user:** joining a friend's lobby is not inherently better or worse — it depends on **where that friend is**. An Indonesian host keeps you in Jakarta; a Malaysian host moves you to KL (+16 ms on the floor); a Singaporean host would move you to Singapore.

---

## 6. Endpoint identification and classification

### 6.1 Finding an IP is not finding a server

An observed remote IP could be a game server, a matchmaking gateway, a load balancer, a CDN edge, a relay, an anti-cheat endpoint, or a telemetry collector. Revision 1 treated "remote IP" as "match server." That was unjustified.

### 6.2 Confidence tiers

Every endpoint gets a tier. Reports must show the tier.

| Tier | Meaning | Evidence required |
|---|---|---|
| **T0 — Observed** | This IP was contacted by MLBB at this time | Socket table or capture, with timestamp and UID |
| **T1 — Network** | This IP belongs to ASN/prefix X | ASN lookup, PTR record |
| **T2 — Geo estimate** | GeoIP places it in country/city Y | GeoIP database — **an estimate** |
| **T3 — Role inference** | Probably a match server / gateway | Lifetime, port pattern, traffic volume, recurrence |
| **T4 — Physical location** | The machine is at Z | **Usually unknown.** Do not claim. |

**Rule:** reports may say *"observed, ASN 12345 (Provider), GeoIP: Singapore, role: probable match server."* They may **not** say *"the server is in Singapore."*

### 6.3 Improving classification beyond GeoIP

| Technique | What it adds | Limits |
|---|---|---|
| **ASN / prefix lookup** | Hosting provider and network | Ownership ≠ location |
| **Reverse DNS (PTR)** | Often reveals cloud region (e.g. `ap-southeast-1`) | Not always present |
| **Latency distance bound** | RTT bounds physical distance: `d ≤ (RTT/2) × 200,000 km/s` | A bound, not a location; queuing inflates RTT |
| **Traceroute last responsive hop** | Rough path terminus | ICMP filtering hides hops |
| **Persistence across matches** | Long-lived IPs are likely gateways; ephemeral ones likely match servers | Heuristic |
| **Port and flow shape** | Game traffic is high-rate, small-packet, bidirectional | Heuristic |
| **Cross-referencing with a second vantage point** | A second network (e.g. cellular vs Wi-Fi) seeing the same IP corroborates | Requires both links |

**Latency bounding is the strongest independent check you have.** If ICMP RTT to an endpoint is 18 ms from Surabaya, one-way propagation is ≤9 ms, so the path is ≤~1,800 km of fibre. That does not prove Indonesia, but it **rules out** distant facilities and constrains the GeoIP answer. Combining a distance bound with ASN and GeoIP is far stronger than GeoIP alone.

### 6.4 The circularity problem — largely resolved

Revision 2 flagged this as blocking. Your follow-up resolves most of it.

**Your labels are based on player flags and language, not on ping.** That is an independent signal about the **matchmaking pool**, and it is legitimate evidence. The circularity is gone.

**A residual gap remains:** player flags identify the *pool*, not the *server's physical location*. A match where every opponent shows an Indonesian flag can still be hosted in Singapore, because pool membership and hosting facility are different things.

The correct interpretation is therefore:

| Your label | What it actually establishes |
|---|---|
| "Indonesian match" | The **pool** is Indonesian |
| "Sub-Indonesian" | Indonesian pool, **worse ping** — cause unknown |
| "SG match" | The **pool** is Singaporean (or the host is SG) |

The tool must keep `user_label` (pool inference) separate from `country_geo` (endpoint estimate), because they answer different questions. If a "sub-Indonesian" match's endpoint geolocates to Singapore, that is a **finding**, not a contradiction — it would mean the Indonesian pool is sometimes hosted outside Indonesia.

---

## 7. Hypothesis matrix

Confidence is **pre-measurement** and reflects current evidence only. Ranking is by explanatory value, **not** by ease of fix.

### 7.1 Summary

| ID | Hypothesis | Confidence | Primary discriminating test | Actionable? |
|---|---|---|---|---|
| **H1** | Different matches use **different endpoints/facilities** | **Medium-High** | Endpoint IP differs between fast and slow matches | Indirectly (placement probability) |
| **H2** | Different matches take **different routes** to the same endpoint | Medium | Same IP, different ICMP RTT/traceroute across sessions | Possibly |
| **H3** | Placement is **load/timing dependent** | Medium | Ping outcome vs time of day, day of week | Possibly (play at better times) |
| **H4** | Your **effective public IP changes** with link path, shifting the pool | Medium | Public IP on Wi-Fi vs cellular; correlate with outcome | Possibly (force a path) |
| **H5** | **Server-side conditions** differ between matches | Medium | Same IP + same ICMP RTT, different displayed ping | No |
| **H6** | **Party composition** shifts placement; more Indonesians → closer server | **Medium-High** | Outcome vs Indonesian count, controlling for hour | **Possibly yes** (who you queue with) |
| **H7** | **Host identity** determines placement | Low | Same party, rotate host, compare outcomes | Maybe |
| **H8** | **Network Boost** selects different paths between sessions | Low-Medium | Outcome vs which link was active | Possibly |
| **H9** | **Local link quality** (dorm Wi-Fi contention) adds variance | Low-Medium | Within-match jitter, bufferbloat test | Yes (path hygiene) |
| **H10** | **Lobby and in-game ping measure different things** | Medium-High | Compare both, per match | No (interpretation only) |
| **H11** | "Sub-Indonesian" matches are hosted **outside Indonesia** despite an Indonesian pool | Medium | Endpoint ASN/GeoIP for sub-Indo matches | Reframes the problem |

### 7.2 Detail on the leading hypotheses

**H1 — Different endpoints/facilities.**
*Explanation:* the matchmaker assigns servers from a pool; different matches land on different machines, possibly in different facilities.
*Why it fits:* your outcomes cluster into distinct bands (15–25, 30–45, 30/50) rather than forming a continuum. Stable-within-match, different-between-match is exactly what endpoint variation looks like.
*Evidence now:* only your reported clustering. No IPs captured.
*Test:* capture the match endpoint for ≥10 matches spanning both fast and slow outcomes. Compare IPs and ASNs.
*If confirmed:* the fast/slow difference is placement, and the only lever is probability — not latency tuning.
*If refuted:* endpoints are identical, so the cause is route or server load (H2/H5).

**H2 — Different routes to the same endpoint.**
*Explanation:* BGP or ISP load balancing sends you along different paths at different times.
*Why it fits:* would produce the same symptom with identical IPs.
*Evidence now:* none.
*Test:* for matches with the *same* endpoint IP, compare ICMP RTT and traceroute across sessions.
*If confirmed:* route work becomes legitimate — this is the one case where a tunnel or ISP change can genuinely help.
*If refuted:* rules out the path as a cause.

**H3 — Load/timing dependence.**
*Explanation:* at peak hours the preferred facility fills, and you are placed elsewhere.
*Why it fits:* your recent shift (U12) and the "sometimes I don't get my main server" pattern.
*Evidence now:* anecdotal.
*Test:* log outcome against local time and day; look for a time-of-day effect with adequate sample.
*If confirmed:* **directly actionable** — shift play sessions.
*If refuted:* placement is not load-driven.

**H4 — Effective public IP changes with path.**
*Explanation:* Network Boost selects between Wi-Fi and cellular. Those have different public IPs, which may geolocate differently. If matchmaking is IP-influenced (M3), the pool could change with the path.
*Why it fits:* explains non-determinism without invoking server-side randomness; ties your Network Boost observation to placement.
*Evidence now:* none, but mechanically plausible.
*Test:* record public IP and link type per session; correlate with outcome.
*If confirmed:* **potentially controllable** by forcing a link.
*If refuted:* placement is independent of your IP.

**H5 — Server-side conditions.**
*Explanation:* same facility and route, but a busier or different server instance.
*Why it fits:* would explain residual variation after H1/H2 are excluded.
*Evidence now:* none.
*Test:* only inferable by elimination — same IP, same ICMP RTT, different displayed ping.
*If confirmed:* nothing client-side helps. Stop optimizing.
*If refuted:* variation is fully explained by endpoint or route.

**H6 — Party composition shifts placement.**
*Explanation:* the matchmaker derives a party-level region or latency profile. More Indonesian members pull that profile toward Indonesia, so the party lands in a pool with a nearby server. With fewer, the profile tips elsewhere — or the search widens simply to find a match at all.
*Why it fits:* your 2-vs-3 Indonesian observation is exactly this shape. It also explains why hosting does not reliably help: the host is one input, not the decision.
*Evidence now:* your report (U15), plus the earlier observation that you often get the main server even as the sole Indonesian.
*Test:* log the Indonesian count in the party for every match, and compare outcome rates at 1, 2, 3, 4, and 5 Indonesians — **controlling for hour of day**, because composition may correlate with when you play.
*If confirmed:* **the most actionable finding available.** You could deliberately balance lobbies toward 3+ Indonesians.
*If refuted:* composition is not the driver, and placement is load- or route-driven (H3/H2).

**H11 — "Sub-Indonesian" matches are hosted outside Indonesia.**
*Explanation:* the pool is Indonesian, but the match runs on a facility elsewhere — a regional cluster serving several pools, or overflow capacity.
*Why it fits:* it explains a 30–45 ms outcome with an unambiguously Indonesian pool, without requiring a second Indonesian data center to exist. Your SG outcome is also ~30 ms, so the bands overlap.
*Evidence now:* the overlap, and the fact that flags prove pool membership but not hosting location.
*Test:* endpoint ASN/GeoIP for matches you label "sub-Indonesian". A Singapore or Malaysian ASN would support this; an Indonesian ASN would refute it.
*If confirmed:* the question becomes why the Indonesian pool is sometimes hosted abroad — most likely capacity or load (H3).
*If refuted:* pool and facility match, and the 30–45 ms outcome is a second Indonesian facility or a worse route (H1/H2).

### 7.3 Hypotheses demoted from revision 1

| Revision 1 claim | Why demoted |
|---|---|
| Network Boost is the leading cause of instability | Your evidence says it *helps*; Moonton describes it as real-time path selection; and your variation is between matches, not within them |
| Samsung auto-switch is a leading cause | Same reasoning; it is a path selector, and you have not reported mid-match flapping |
| 15–20 ms proves an Indonesian DC | Ping magnitude cannot establish location |
| 40–50 ms proves a distant SG DC | Same; could be route or load |
| 15–20 ms is a physical floor | Displayed ping semantics are unknown; a floor cannot be declared |

---

## 8. Statistical approach

### 8.1 Why 10 matches is not enough

Revision 1 said "≥10 matches per arm." That is a reasonable **exploratory** sample, not evidence. Latency data is skewed, and matches within a session are correlated (same network conditions, same hours). Treating 10 matches as 10 independent samples overstates confidence.

### 8.2 Sample size guidance

For a two-arm comparison of mean ping, approximate matches per arm:

| Effect to detect | SD ≈ 5 ms | SD ≈ 8 ms | SD ≈ 12 ms |
|---|---|---|---|
| 5 ms | ~16 | ~40 | ~90 |
| 10 ms | ~5 | ~10 | ~23 |
| 15 ms | ~3 | ~5 | ~10 |

*(Normal approximation, 80% power, α = 0.05. Treat as planning guidance, not precision.)*

**Practical reading:** a 10 ms effect with moderate variance needs ~10 matches per arm. A 5 ms effect needs far more. If your outcomes are as bimodal as they appear (15–25 vs 30–45), you may not need means at all — **a proportion test ("how often did I get the main server?") is more powerful and more meaningful than a mean.**

### 8.3 Recommended analysis

- **Primary metric:** proportion of matches landing in the "main server" band, per condition. This matches your actual goal.
- **Secondary:** median in-game ping per match, with IQR. Report medians, not means — latency distributions are skewed.
- **Unit of analysis:** the **match**, not the packet. Never treat thousands of packets as thousands of samples.
- **Clustering:** group by session; use a cluster bootstrap over sessions for confidence intervals.
- **Pre-registration:** decide the comparison and the stopping rule *before* collecting, to avoid optional stopping.
- **Sequential monitoring:** if you must peek, use a sequential design with alpha spending rather than repeated naive tests.
- **Confounders:** record time of day, link type, and party composition for every match; do not compare arms collected at different hours.

### 8.4 Escalation when results are ambiguous

1. Increase n in the same design.
2. Tighten the comparison (same hour, same party, same link) to reduce variance.
3. Switch from mean ping to outcome proportion.
4. If still ambiguous, report **"no detectable effect at this sample size"** — that is a legitimate result, and better than a false positive.

---

## 9. Architecture

Unchanged in spirit from revision 1: **Python + ADB + SQLite, local to the Windows laptop.** No new stack, no server, no subscription.

### 9.1 Components

```
┌──────────────────────┐
│ Galaxy S25+ (MLBB)   │
└──────────┬───────────┘
           │ USB ADB (read-only)
           ▼
┌──────────────────────────────────────────────────┐
│ Collector (Python 3.12, local)                   │
│                                                  │
│  probe.py      capability probe (Phase 0)        │
│  endpoints.py  socket/lobby/match endpoint watch │
│  rtt.py        ICMP + TCP-SYN probes             │
│  path.py       traceroute capture                │
│  enrich.py     ASN / PTR / GeoIP                 │
│  session.py    match segmentation, phase split   │
│  store.py      SQLite                            │
│  report.py     CLI tables + comparisons          │
└──────────────────────────────────────────────────┘
```

### 9.2 Schema

```
sessions(id, started_at, ended_at, link_type, ssid, carrier,
         public_ip, network_boost, speed_mode, notes)

matches(id, session_id, started_at, ended_at, mode, party_size,
        host_name, user_label, notes)

endpoints(id, ip, first_seen, last_seen, asn, org, country_geo,
          city_geo, ptr, role_guess, confidence_tier)

observations(id, match_id, phase,           -- 'lobby' | 'ingame'
             ts, endpoint_id, displayed_ping_avg, displayed_ping_min,
             displayed_ping_max, source)    -- 'manual' | 'ocr'

rtt_probes(id, ts, endpoint_id, method,     -- 'icmp' | 'tcp_syn'
           rtt_avg, rtt_min, rtt_max, jitter, loss_pct)

party_members(match_id, name, country, carrier, public_ip_geo)

path_traces(id, ts, endpoint_id, hops_json)
```

**Key design decisions:**
- `phase` is mandatory on observations — lobby and in-game are never merged.
- `user_label` is stored separately from `country_geo` so disagreements are visible.
- `confidence_tier` is stored per endpoint and shown in every report.
- `displayed_ping` and `rtt_probes` are separate tables — **never joined into a derived "overhead" field.**

### 9.3 Explicitly out of scope initially

- GUI/dashboard (CLI first; validate measurement before polish)
- OCR of in-game ping (manual entry is fine and less error-prone at this stage)
- Any modification of MLBB, its files, or its memory
- Any automated in-game action

---

## 10. Implementation roadmap

Each phase has an acceptance criterion. **Stop and reassess if a phase's criterion fails** — do not build on an unvalidated assumption.

### Phase 0 — Intake and capability probe

**Work:** install Android Platform Tools; enable USB debugging; run the §5.2 probe; record U1–U13; document the timeline of the change in U12.

**Acceptance:** every probe question answered with a recorded result, including whether MLBB's UDP sockets expose remote addresses.

**Gate:** if the ADB method fails, adopt the PCAPdroid fallback (§5.3) before proceeding.

### Phase 1 — Endpoint identification

**Work:** build the socket watcher with phase separation; push a polling loop to the device; capture endpoints for at least 10 matches spanning both fast and slow outcomes.

**Acceptance:** for ≥8 of 10 matches, a match-phase endpoint is identified with a timestamp; lobby endpoints are distinguishable from match endpoints.

**Gate:** if match endpoints cannot be identified, stop and reassess the whole approach.

### Phase 2 — Enrichment and classification

**Work:** ASN/PTR/GeoIP lookup; latency distance bounds; role inference; assign confidence tiers.

**Acceptance:** every captured endpoint has ASN, GeoIP, PTR (where available), a distance bound, and a tier. **A first answer to H11** — are your "sub-Indonesian" endpoints Indonesian by ASN/GeoIP?

### Phase 3 — Match logging with phase separation

**Work:** manual entry of lobby and in-game ping, party composition, host, link type; session segmentation.

**Acceptance:** ≥20 matches logged with complete fields; lobby and in-game observations stored separately.

### Phase 4 — Network quality probes

**Work:** ICMP and TCP-SYN RTT per endpoint; traceroute; jitter and loss; bufferbloat test on the dorm Wi-Fi; Wi-Fi vs cellular comparison.

**Acceptance:** a per-match network profile, and a clear statement of whether the local link contributes meaningful variance.

### Phase 5 — Analysis and reporting

**Work:** CLI reports answering: does the endpoint change between fast and slow matches? Does ASN change? Does time of day matter? Does link type matter? Does host matter?

**Acceptance:** a defensible answer to H1, H2, H3, H4, and H11 with stated confidence and sample size — **including "insufficient evidence" where that is the truth.**

### Phase 6 — Controlled experiments

**Work:** only for hypotheses that survived Phase 5. Pre-register each comparison; randomize order where possible; collect to the planned sample size.

**Acceptance:** at least one of (a) a measured effect with a confidence interval, or (b) a well-powered null result.

### Phase 7 — Conditional route experiments

**Work:** only if Phase 4/5 show a **route** problem (same endpoint, materially different RTT across sessions). Candidates in §11.

**Acceptance:** measured before/after with the same methodology, reported honestly even if worse.

---

## 11. Optimization options — conditional and evidence-gated

The distinction that matters: **which options can actually change the path MLBB uses, versus which only tell you about it.**

### 11.1 Diagnostic only (no effect on the path)

| Option | Purpose |
|---|---|
| ADB socket reads | Identify endpoints |
| ICMP / TCP-SYN probes | Measure network RTT |
| Traceroute | Locate where latency accrues |
| PCAPdroid / hotspot capture | Packet-level identification |
| Bufferbloat test | Quantify local link quality |
| GeoIP / ASN lookup | Classify endpoints |

### 11.2 Can change the path (test only with evidence)

| Option | Mechanism | Cost | Likely outcome |
|---|---|---|---|
| **Switch Wi-Fi ↔ cellular** | Different ISP, different route, possibly different public IP | Free (data plan) | **Most promising free lever.** Also tests H4. |
| **Network Boost on/off** | Real-time path selection between links [M5] | Free | **Keep ON** per your evidence; test to confirm and to learn which link it prefers |
| **Samsung switch-to-mobile-data** | Allows cellular to carry traffic when Wi-Fi is poor | Free | Complementary to Network Boost; test interaction |
| **IPv4 vs IPv6** | Different routing and peering | Free | Test only if endpoints have both families |
| **Cloudflare WARP** | WireGuard tunnel to Cloudflare edge | Free; occupies the VPN slot | **May help or hurt.** Community reports are split. Conflicts with PCAPdroid and may interfere with Network Boost. |
| **PC as hotspot/relay** | Route phone traffic through laptop | Free; needs laptop Wi-Fi + Ethernet | Adds a hop. Only helps if the laptop's uplink is materially better. |
| **Different DNS** | Resolver choice | Free | **Unlikely to matter** for UDP game traffic; may affect gateway selection if hostnames are used |
| **Change ISP / second SIM** | Different peering | **Costs money** | Most reliable route fix, but out of the zero-cost scope |

### 11.3 Explicitly excluded

| Option | Reason |
|---|---|
| VPN to change matchmaking region | ToS risk; adds latency; Moonton prohibits matchmaking manipulation |
| Root / custom ROM | Knox, banking apps, anti-cheat, warranty — and unnecessary |
| Game file or memory modification | Prohibited; risks the account |
| Paid "ping booster" services | Either a VPN in disguise or placebo; violates the no-subscription constraint |
| Third-party servers/relays | Violates the no-paid-infrastructure constraint |

### 11.4 The realistic optimization thesis

Given the evidence, the most likely available improvement is **not latency reduction** but **placement probability**:

1. If **H3** (timing) holds → play at better hours.
2. If **H4** (public IP) holds → force the link that yields the better pool.
3. If **H2** (route) holds → a tunnel may help for the specific bad route.
4. If **H1** alone holds → nothing helps; the outcome is assigned. Accept it, or change who you queue with.

**Revision 1 implied a tool could lower ping. This revision states plainly: it probably cannot. It can tell you which of the four worlds you are in, and only two of them are actionable.**

---

## 12. Risks, constraints, and ethics

| Risk | Severity | Mitigation |
|---|---|---|
| Moonton ToS — third-party tools for unfair advantage | Medium | Read-only, local, no game modification, no matchmaking manipulation, no region spoofing |
| VPN use read as matchmaking manipulation | Medium | No region-change VPNs. WARP only as a neutral route experiment, if at all |
| Rooting side effects | High | Not doing it |
| PCAPdroid distorts timing and occupies the VPN slot | Medium | Identification only; never latency data |
| PCAPdroid may interfere with Network Boost | Medium | Record capture conditions; validate findings without capture |
| ADB USB debugging left enabled | Low | Disable when not measuring; prefer USB over wireless ADB |
| Privacy — GeoIP lookups expose your IP | Low | Use an offline GeoLite2 database |
| Over-engineering before validation | Medium | Phase 0/1 are cheap and may answer the question outright |
| Confirmation bias in self-reported labels | **High** | Store `user_label` separately from measured `country_geo`; report disagreements |
| Dorm network is shared and uncontrolled | Medium | Log time of day; expect contention; do not attribute dorm-wide effects to MLBB |

---

## 13. Remaining unknowns and limitations

**Blocking unknowns (must be resolved before the architecture is committed):**
1. ~~Do MLBB's match-phase UDP sockets expose remote addresses?~~ **Resolved: no** (§5.7). Endpoint identification now runs through PCAPdroid, which **works** — the first match server was captured on 2026-11-14 (§5.8).
2. Does the party-size effect (H6) survive controlling for hour of day? (§7.2)
3. **Are there two Indonesian server providers** (Omni Cloud vs Meteverse), and does the choice between them explain the "main" vs "sub indo" ping bands? (§5.8)

**Material unknowns (affect interpretation):**
4. What the displayed in-game ping actually measures.
5. Whether lobby and in-game endpoints differ for you.
6. Whether your public IP changes between Wi-Fi and cellular.
7. Whether placement is time-dependent.
8. What changed between seasons (U16), and when.

**Structural limitations (will not be resolved by this project):**
- Server-side processing cannot be isolated without protocol knowledge.
- IP geolocation cannot prove physical location.
- The matchmaker is opaque and not controllable.
- No root means no packet-level capture on the phone itself.
- A shared dorm network is an uncontrolled variable.
- Even a well-powered result is about *your* conditions, not MLBB in general.

---

## 14. References

| Source | Used for | Status |
|---|---|---|
| [proc_net(5) — Arch manual](https://man.archlinux.org/man/proc_net.5.en) | `rem_address` populated only if connected; UID field | **Verified** |
| [PCAPdroid — Quick Start](https://emanuele-f.github.io/PCAPdroid/quick_start) | Non-root capture proxies L3/L4; unsuitable for timing | **Verified** |
| [PCAPdroid — FAQ](https://emanuele-f.github.io/PCAPdroid/faq) | VPN requirement; egress-only; no other-VPN capture without root | **Verified** |
| [Termux issue #2993](https://github.com/termux/termux-app/issues/2993) | Android 13+ netlink/`/proc/net` restrictions for apps | **Verified** |
| [Stack Overflow — UDP 5-tuples via ADB](https://stackoverflow.com/questions/52071613/how-to-get-complete-list-of-udp-connections-made-by-each-application-using-adb-o) | Report that `/proc/net/udp` may omit UDP destinations and be incomplete | **Anecdotal** (page itself blocked; relied on search excerpt) |
| [e.foundation — ADB network monitoring](https://community.e.foundation/t/adb-network-monitoring-unlisted-uid-1020/71096/8) | `cat /proc/net/udp` readable via `adb shell` on a current device | **Anecdotal but specific** |
| [MLBB Network Boost Q&A (Reddit mirror)](https://www.reddit.com/r/MobileLegendsGame/comments/ig5wks/mlbb_qa_on_network_boost/) | "Chooses the best network in real time"; requires both Wi-Fi and 4G | **Semi-official** |
| [MLBB Network Boost Q&A (official FB)](https://www.facebook.com/MobileLegendsGameSingapore/posts/mlbb-qanetworkq-why-is-there-no-significant-improvement-sometimes-even-more-lag-/782136005857132/) | Same statement, official channel | **Semi-official** |
| [MLBB Server/Region — GameMarket.gg](https://gamemarket.gg/news/mobile-legends-bang-bang/mlbb-server-and-region-how-to-change-location-the-right-way) | Server ID vs matchmaking region vs location; IP-influenced region | **Secondary** |
| [Moonton Indonesian DC — VIVA](https://www.viva.co.id/gaya-hidup/digilife/1072432-pusat-data-ada-di-indonesia-ini-keuntungan-untuk-pemain-ml) | Indonesian data center built with Telkomsel | **Secondary** |
| [Mobile Legends — Wikipedia](https://en.wikipedia.org/wiki/Mobile_Legends:_Bang_Bang) | Developer, platforms, dedicated-server MOBA context | **Verified** |
| [GSMArena — One UI 8 for S25](https://www.gsmarena.com/samsung_galaxy_s25_series_android_16_one_ui_8_stable_update_usa-news-69579.php) | S25 series on Android 16 / One UI 8 | **Verified** |
| [Cloudflare WARP latency benchmark](https://github.com/Antoinebr/warp-latency-benchmark) | Tooling to measure WARP latency delta | **Verified (tool)** |
| r/CloudFlare — WARP latency reports | WARP can increase latency substantially | **Anecdotal** |
| r/MobileLegendsGame — party ping threads | Cross-region parties raise ping | **Anecdotal** |

**Deliberately excluded:** SEO pages asserting specific MLBB server cities, and any page claiming MLBB runs on "Valve-hosted" infrastructure. Where a city or IP matters, this plan treats it as something to measure.

---

## 15. Revision summary

### What changed and why

| # | Revision 1 | Revision 2 | Reason |
|---|---|---|---|
| 1 | Mapped 15–20 / 30 / 40–50 ms to Indonesian and Singapore data centers | Presents these as **hypotheses**; no location inferred from ping | No match-server IPs had ever been captured |
| 2 | Declared 15–20 ms and ~28 ms "physical floors" | Removed; propagation latency kept only as context, with a distance-bound technique | Displayed ping semantics are unknown; a floor cannot be asserted |
| 3 | Treated party/region behaviour as established | Downgraded to hypotheses with confidence levels; added the assumption list the review required | Community reports are anecdotal |
| 4 | Made Network Boost and Samsung auto-switch the leading cause | **Reversed**: your evidence says Network Boost helps; Moonton describes it as a path selector; demoted to H8 | Directly contradicted by your report |
| 5 | `adb shell ping` as the measurement | Five-layer methodology; ICMP demoted to one network-layer signal among several | ICMP ≠ UDP application latency |
| 6 | `overhead = in-game ping − ICMP RTT` | **Removed as invalid**; replaced with non-subtractable separate observations | Category error |
| 7 | Assumed `/proc/net/udp` works | Added the connected-socket dependency, a capability probe, a decision tree, and fallbacks | `rem_address` exists only for connected sockets |
| 8 | "Remote IP = match server" | Confidence tiers T0–T4; ASN/PTR/GeoIP/distance-bound classification | An IP may be a gateway, relay, or load balancer |
| 9 | Hypothesis matrix ranked partly by fixability | Ranked by evidence; each hypothesis has 7 required fields; added H11 (label circularity) | Review requirement |
| 10 | "≥10 matches per arm" | Sample-size table, cluster-aware analysis, proportion-based primary metric, pre-registration | 10 matches is exploratory, not evidence |
| 11 | Optimization framed as latency reduction | Reframed as **placement probability**; options split into "changes the path" vs "diagnostic only" | Only some levers are real |
| 12 | Generic references | Evidence ledger with verification tags per claim; semi-official and anecdotal sources labelled | Review requirement |
| 13 | — | Added your reported data as a structured dataset, including the bandwidth observation and the recent-shift timeline | New information |
| 14 | — | Added the **circularity problem** in the "sub-indo" label as a blocking unknown | Highest-impact unresolved issue |

### Revision 3 changes (this revision)

| # | Revision 2 | Revision 3 | Reason |
|---|---|---|---|
| 15 | Circularity flagged as blocking | **Largely resolved**: labels come from player flags, not ping | Your answer |
| 16 | "Sub-Indonesian" possibly not Indonesian | Reframed: Indonesian **pool**, unknown hosting facility | Flags prove pool membership, not server location |
| 17 | Party composition a low-confidence hypothesis | **H6 upgraded to Medium-High**; now the leading actionable lead | Your 2-vs-3 Indonesian observation |
| 18 | No explanation for the bandwidth paradox | Added §4.6: bandwidth ≠ latency; Network Boost may select cellular in both cases | Your dorm-vs-home observation |
| 19 | Season variation not modelled | Added U16 and a dating action | Your report |
| 20 | Central question: "Indonesia or Singapore?" | Central question: **"why does one Indonesian pool give two ping bands?"** | Narrowed by the flag evidence |

### What was preserved

The original direction, the Python + ADB + SQLite architecture, the phase structure, the local-only and zero-cost constraints, the hypothesis-matrix format, the practical tone, and the commitment to no root and no game modification.

### The one-sentence version

Revision 1 asked *"how do we lower your ping?"* Revision 2 asked *"which of three structurally different things is happening?"* Revision 3 can finally ask something specific enough to answer: **"why does the same Indonesian pool sometimes give you 15–25 ms and sometimes 30–45 ms — and does the number of Indonesians in your lobby change the odds?"** That question is measurable with a spreadsheet and a handful of shell commands, which is what a good plan should reduce to.

---

## 16. Immediate next actions (no implementation)

1. **Start logging party composition per match.** For every match record: number of Indonesians, who hosted, hour of day, and outcome band (main 15–25 ms / sub-Indo 30–45 ms / SG). This is the highest-value data in the project and it needs no tooling — a spreadsheet works. It directly tests H6, now the leading actionable hypothesis.
2. **Run the Phase 0 capability probe** (§5.2) when the phone is connected. Three results decide the architecture: can shell read the table, are remote addresses populated, and is IPv6 in use.
3. **Run the three link diagnostics** (§4.6) — Wi-Fi only, cellular only, both — for 60 seconds each. This answers your dorm-Wi-Fi question without touching normal gameplay.
4. **Capture the public IP on each link** — Wi-Fi only, cellular only — to test H4.
5. **Date the season shift** (U16). Which season did the behaviour change in? Any game update, ISP change, or dorm network change around then?
6. **Do not change settings yet.** Network Boost stays on. Changing variables before baseline measurement destroys the baseline.
