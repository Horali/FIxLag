# Experiment — restart vs host

**Question:** why did the same 5-stack give **~40 ms** when you hosted, and
**19 ms** when the Malaysian friend hosted after you restarted MLBB?

**Status:** designed, not run. Tooling built (`tools/draft_probe.py`).
**Date:** 2026-11-24.

---

## 1. Read this before you burn a night on it

### 1.1 The 19 ms number is the weakest thing in the whole project

Every endpoint ever measured from this phone, on this link, has a floor:

| Endpoint | Provider | City (estimate) | Best ICMP min |
|---|---|---|---|
| `103.157.33.34` | Omni Cloud | Jakarta | 20.2 ms |
| `216.133.157.51` | Zenlayer | Jakarta | 20.8 ms |
| `216.133.157.51` (per-link run) | Zenlayer | Jakarta | 24.8 ms |
| `148.153.165.218` | CDS Global Cloud | Jakarta (disputed) | 35.4 ms |
| `156.59.164.174` | Zenlayer | Kuala Lumpur | 37.6 ms |

Three independent methods agree that displayed ping sits **~4–5 ms above**
network RTT (CDS: ICMP 35.4, UDP-gap 38.8, display ~40 — plan.md §5.12). So a
**19 ms** display implies a network RTT of roughly **14–15 ms**.

That is below every floor you have ever measured — including a Jakarta server.

Two ways to read it, and they point in opposite directions:

1. **The number was not a match-RTT reading.** The lobby/party value, or a
   pre-sync loading value, or a recalled reading of a different match. In that
   case there is nothing to explain, and this experiment is chasing a ghost.
2. **The number was real.** Then there is a facility closer than anything in
   the captures — plausibly the Telkomsel-associated Indonesian DC (plan.md
   M4), which no capture has ever landed on. That would be the single most
   interesting endpoint in the project.

**What is not possible:** that a **Kuala Lumpur** server produced 19 ms from
your dorm. The measured KL floor from this phone is 37.6 ms. Whatever happened
that night, the server was not in KL — so the arm does not only test "host
identity", it tests whether the MY party was placed somewhere unexpected.

That is why the arm must be re-run **with a capture**, not from memory. A new
19 ms with an IP attached is a finding. Another recalled 19 ms is nothing.

### 1.2 The three-arm sketch confounds three things

Your sketch:

| # | Condition | Supposed to test |
|---|---|---|
| 1 | you host, no restart | baseline |
| 2 | you host, **after restart** | restart effect |
| 3 | friend hosts | host identity |

A force-stop **kicks you out of the party**. To host again after a restart you
must re-invite everyone, which re-forms the party and re-queues. So arm 2
changes: restart **+** party reformation **+** queue time. Arm 3 changes: host
**+** everybody re-joins **+** you are no longer leader. Nothing is isolated,
and three matches in one night also drift in time-of-day and server load.

### 1.3 Statistics are not the point here

Do not read this as a sample of three. The measured quantity is **which
endpoint appears**, which is a binary identity, not a noisy millisecond. Four
classifications either show the endpoint changing or they do not:

- **Same endpoint across arms** → neither restart nor host moves placement.
  You stop wondering, which is worth more than the 40 ms itself.
- **Endpoint differs** → you have a lead, not a rate. Four samples cannot tell
  you "usually"; they can tell you "happened".

---

## 2. The corrected ladder — one variable per step, one sitting

Same party, same link (Network Boost on, as always), same hour, arms back to
back. Each arm ends at **draft pick**, where the client is already connected
(measured, plan.md §5.8) and the server can be identified in ~30 s.

| Arm | Who queues | Restart before arm | Isolates |
|---|---|---|---|
| **A** | you | no | baseline: your host identity, warm app |
| **B** | MY friend | no | **host identity only** (you leave, join theirs; nobody restarts) |
| **C** | MY friend | **yes — you force-stop, relaunch, rejoin** | **restart only**, host held constant |
| **D** | you | no | drift control: if D ≠ A, the night moved under you |

**How to read it**

- A vs B → host identity.
- B vs C → restart, with the host fixed. **This is the arm your original
  sketch could not do.** It is the only clean test of "restarting the app
  changes the server".
- A vs D → noise/time-of-day. If A and D disagree, throw the night out.
- C vs the friend-hosted 40 ms story → the actual question.

If you only get two arms, run **B and C** — that pair answers the restart half
without touching your own host identity.

### 2.1 The round trip is not the finding — the IP is

Every arm records:

1. the endpoint IP (from the capture, at draft),
2. the reported in-game ping (later, in the match),
3. a **separate ICMP** measurement to that same IP from the phone.

Point 3 is what turns "19 ms" into a number you can check. If the display says
19 and ICMP says 21, the display is roughly raw RTT and the 19 was a real
server. If the display says 19 and ICMP says 34, the display is not RTT and
the 19 was never a measurement of anything.

---

## 3. Do the free test first: does the probe sweep fire on app launch?

The restart hypothesis needs a mechanism. The only plausible one: the client
re-runs its port-30190 latency sweep on startup and feeds fresh measurements
into placement, so a restart changes the input.

That is testable in **two minutes, with no match and no friends**.

```
python tools/draft_probe.py start --label LAUNCH --seconds 300
# force-stop MLBB, then launch it, sit in the lobby for ~90 s
python tools/draft_probe.py peek --label LAUNCH
python tools/draft_probe.py finish --label LAUNCH --note "sweep on launch?"
```

| Result | Reading | Consequence |
|---|---|---|
| 30190 packets appear within seconds of the launch | restart has a mechanism | run arm C |
| no 30190 packets, only lobby TCP | restart has no known mechanism | deprioritise the restart hypothesis; run A/B/D only |

This also chips at open question 3 in the handoff (what triggers the sweep),
which is worth knowing regardless of how this experiment ends.

---

## 4. Procedure

One arm at a time. The capture runs the whole match, so you classify at draft
and then decide whether to play.

```powershell
# 0. confirm the device (multiple ADB devices are normal here)
python tools/draft_probe.py devices
$S = "RRCY1032Y6F"

# 1. start the labelled capture
python tools/draft_probe.py start --label A --seconds 1500 --serial $S

# 2. queue with the party. When the draft starts:
python tools/draft_probe.py peek --label A --serial $S
#    -> PRIMARY  <ip>:<port>  <provider> / <city>

# 3a. if you play it out, finish after the match
python tools/draft_probe.py finish --label A --serial $S --host me `
    --ping 41 --party "5q: me(ID), MY, PH, IN, SG"

# 3b. independent network RTT to the same endpoint, from the phone
python tools/draft_probe.py ping 148.153.165.218 --serial $S

# 4. repeat for B, C, D
```

`finish` writes a row to `data/matches.csv` (git-ignored):

`ts, label, host, displayed_ping_ms, endpoint, port, provider, city_geo,
confidence, ifaces, out_pkts, in_pkts, duration_s, other_endpoints, party, note`

`confidence` is the plan.md §6.2 tier: `known` means the IP has been observed
on this device before; `prefix` means only the provider range is known.

### 4.1 Do not chain dodges

Leaving at draft is a dodge. Ranked drafts can cost credit score or a short
queue ban; doing it three times in one evening is a bad trade for a test you
can run with two.

Recommended: classify at draft, then **play the match**. You get the ping
reading anyway, which is the number you actually care about, and the capture
is already running. Dodge only when the draft lands on an endpoint you have
already classified that night.

---

## 5. Outcome table

| What you see | What it means | Next |
|---|---|---|
| A, B, C all on the same endpoint | neither host nor restart moves placement; the 40-vs-19 story does not reproduce | close open question 1 as "not reproducible"; the variance is time/mode/load |
| B and C differ, A and B agree | **restart moves placement** | run the launch-sweep test, then a few more C/A pairs |
| A and B differ, B and C agree | **host identity moves placement** | refine: which member's region dominates (min-max test, plan.md §5.9) |
| A and D differ | the night drifted | discard, rerun on another evening |
| C lands on a 19 ms-class server (nothing seen before) | you found the closer facility | capture it properly, ping it, geolocate it — that is a real lead |
| MY-hosted arm lands in KL again | consistent with §5.8, and the 19 ms was not KL | the 19 ms was either a non-RTT reading or a third location |

---

## 6. Limits, stated plainly

- **One party, one night, one link.** Not a rate, not a season.
- **Endpoint identity is not physical location.** GeoIP places a network, not a
  building (plan.md §6.1–6.2). "Jakarta" here means "provider believed to be in
  Jakarta".
- **Queue time and server load are uncontrolled.** They are the most likely
  source of a difference that has nothing to do with your arms.
- **Your friends' connections are half the input.** In a min-max matchmaker
  their latency profile decides the region as much as yours does, and you
  cannot measure it from your side.
- **Network Boost stays on.** Turning it off changes the path and contradicts
  every prior measurement (plan.md §5.12).
- **The probe sweep is sampled, not exhausted.** A sweep of 9 targeted servers
  and a sweep of 63 have both been seen (plan.md §5.8), so "no probe to X"
  never proves X was unmeasured.
