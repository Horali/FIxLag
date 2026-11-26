"""Self-contained single-page HTML/CSS/JS viewer UI (zero external requests)."""

INDEX_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>MLBB Passive Live Chat Viewer</title>
<style>
  :root {
    --bg: #0c1017;
    --surface: #141a24;
    --surface-2: #1b2331;
    --border: #2a3447;
    --text: #e6edf7;
    --muted: #8b98ae;
    --ally-bg: rgba(45, 127, 249, 0.12);
    --ally-border: #3b82f6;
    --self-bg: rgba(34, 211, 238, 0.14);
    --self-border: #22d3ee;
    --enemy-bg: rgba(239, 68, 68, 0.13);
    --enemy-border: #ef4444;
    --camp-bg: rgba(148, 163, 184, 0.10);
    --camp-border: #64748b;
    --warn-bg: rgba(245, 158, 11, 0.15);
    --warn-border: #f59e0b;
    --ok: #22c55e;
    --err: #ef4444;
  }
  * { box-sizing: border-box; }
  html, body {
    margin: 0; padding: 0; height: 100%;
    background: var(--bg); color: var(--text);
    font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
    font-size: 14px;
  }
  body { display: flex; flex-direction: column; }
  header {
    background: var(--surface); border-bottom: 1px solid var(--border);
    padding: 10px 14px; display: flex; flex-direction: column; gap: 8px;
  }
  .row { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; }
  .title { font-weight: 700; font-size: 15px; letter-spacing: 0.2px; margin-right: 6px; }
  .badge {
    display: inline-flex; align-items: center; gap: 5px;
    padding: 3px 8px; border-radius: 999px; font-size: 12px; font-weight: 600;
    background: var(--surface-2); border: 1px solid var(--border); color: var(--text);
  }
  .badge.ok { border-color: rgba(34, 197, 94, 0.5); color: #86efac; background: rgba(34, 197, 94, 0.12); }
  .badge.warn { border-color: rgba(245, 158, 11, 0.6); color: #fde68a; background: rgba(245, 158, 11, 0.15); }
  .badge.err { border-color: rgba(239, 68, 68, 0.6); color: #fca5a5; background: rgba(239, 68, 68, 0.18); }
  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; }
  select, input[type="text"], button {
    background: var(--surface-2); color: var(--text); border: 1px solid var(--border);
    border-radius: 6px; padding: 5px 8px; font-size: 12px;
  }
  button { cursor: pointer; font-weight: 600; }
  button:hover { border-color: #4b5c7a; background: #222c3d; }
  button.primary { background: #1d4ed8; border-color: #2563eb; }
  button.primary:hover { background: #2563eb; }
  button.danger { background: #7f1d1d; border-color: #b91c1c; }
  label.chk { display: inline-flex; align-items: center; gap: 4px; font-size: 12px; color: var(--muted); cursor: pointer; }
  .controls {
    background: var(--surface); border-bottom: 1px solid var(--border);
    padding: 8px 14px; display: flex; flex-wrap: wrap; align-items: center; gap: 8px;
  }
  .spacer { flex: 1; }
  #errorBanner {
    display: none; padding: 8px 14px; background: rgba(239, 68, 68, 0.16);
    border-bottom: 1px solid var(--err); color: #fecaca; font-size: 12px;
  }
  #logWrap {
    position: relative; flex: 1; overflow-y: auto; padding: 12px 14px 28px;
    display: flex; flex-direction: column; gap: 6px;
  }
  .empty {
    margin: auto; text-align: center; color: var(--muted); max-width: 460px; line-height: 1.5;
  }
  .msg {
    display: grid; grid-template-columns: 74px 68px 56px 140px 1fr;
    gap: 8px; align-items: baseline;
    padding: 7px 10px; border-radius: 8px;
    border-left: 3px solid var(--camp-border); background: var(--camp-bg);
  }
  .msg.side-SELF { border-left-color: var(--self-border); background: var(--self-bg); }
  .msg.side-ALLY { border-left-color: var(--ally-border); background: var(--ally-bg); }
  .msg.side-ENEMY { border-left-color: var(--enemy-border); background: var(--enemy-bg); }
  .msg-time { color: var(--muted); font-size: 11px; white-space: nowrap; }
  .msg-tag {
    font-size: 11px; font-weight: 700; text-transform: uppercase; text-align: center;
    padding: 1px 6px; border-radius: 4px; background: rgba(255,255,255,0.06);
  }
  .side-SELF .msg-tag { color: #67e8f9; }
  .side-ALLY .msg-tag { color: #93c5fd; }
  .side-ENEMY .msg-tag { color: #fca5a5; }
  .msg-chan { font-size: 11px; color: var(--muted); text-transform: uppercase; }
  .msg-sender { font-weight: 600; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .msg-text { word-break: break-word; line-height: 1.4; }
  .msg-raw { display: inline-block; margin-left: 8px; font-size: 11px; color: var(--muted); }
  .gap-banner {
    padding: 8px 12px; border-radius: 8px; border-left: 3px solid var(--warn-border);
    background: var(--warn-bg); color: #fde68a; font-size: 12px;
    display: flex; justify-content: space-between; align-items: center; gap: 10px;
  }
  .gap-banner.resolved { opacity: 0.85; border-left-style: dashed; }
  #jumpLatest {
    display: none; position: fixed; right: 22px; bottom: 20px; z-index: 20;
    background: #2563eb; color: #fff; border: none; border-radius: 999px;
    padding: 8px 14px; font-size: 12px; font-weight: 700; box-shadow: 0 6px 20px rgba(0,0,0,0.45);
  }
  @media (max-width: 720px) {
    .msg { grid-template-columns: 1fr; gap: 3px; }
  }
</style>
</head>
<body>
<header>
  <div class="row">
    <span class="title">MLBB Passive Chat Viewer</span>
    <span id="badgeSource" class="badge">IDLE</span>
    <span id="badgeFsm" class="badge">IDLE</span>
    <span id="badgeStale" class="badge" style="display:none;"></span>
    <span id="badgeSse" class="badge ok">SSE CONNECTED</span>
    <span class="spacer"></span>
    <span id="metaStats" class="mono" style="color:var(--muted);">tick=- dict=0x0101</span>
  </div>
  <div class="row">
    <select id="pcapSelect" title="Saved PCAP in captures/"></select>
    <label class="chk"><input type="checkbox" id="followChk"> Follow</label>
    <button id="btnLoadPcap" class="primary">Load PCAP</button>
    <select id="adbSelect" title="Connected ADB devices"></select>
    <label class="chk"><input type="checkbox" id="teeChk"> Tee PCAP</label>
    <button id="btnStartAdb">Live ADB</button>
    <button id="btnRefresh" title="Refresh PCAP and ADB lists">Refresh</button>
    <button id="btnStop" class="danger">Stop</button>
  </div>
</header>

<div id="errorBanner"></div>

<div class="controls">
  <select id="matchSelect" title="Select match"></select>
  <select id="phaseFilter" title="Filter phase">
    <option value="all">Phase: All</option>
    <option value="draft">Draft</option>
    <option value="loading">Loading</option>
    <option value="battle">Battle</option>
  </select>
  <select id="chanFilter" title="Filter channel">
    <option value="all">Channel: All</option>
    <option value="draft">Draft</option>
    <option value="loading">Loading</option>
    <option value="team">Team</option>
    <option value="all_chat">All Chat</option>
  </select>
  <select id="sideFilter" title="Filter side">
    <option value="all">Side: All</option>
    <option value="ALLY_GROUP">Ally + Self</option>
    <option value="SELF">Self</option>
    <option value="ALLY">Ally</option>
    <option value="ENEMY">Enemy</option>
    <option value="CAMP">Unresolved Camp</option>
  </select>
  <input type="text" id="searchInput" placeholder="Filter sender or text...">
  <label class="chk"><input type="checkbox" id="rawChk"> Show raw tags</label>
  <span class="spacer"></span>
  <span id="matchSummary" class="mono" style="color:var(--muted);"></span>
</div>

<div id="logWrap">
  <div class="empty">Waiting for packets... Pick a PCAP or connect a rooted ADB device above.</div>
</div>
<button id="jumpLatest">Jump to latest</button>

<script>
(() => {
  const state = {
    matches: new Map(),
    matchOrder: [],
    selectedMatchId: null,
    status: {},
    lastEventId: null,
    lastHeartbeatMs: Date.now(),
    autoScroll: true,
    unreadCount: 0,
  };

  const el = {
    badgeSource: document.getElementById("badgeSource"),
    badgeFsm: document.getElementById("badgeFsm"),
    badgeStale: document.getElementById("badgeStale"),
    badgeSse: document.getElementById("badgeSse"),
    metaStats: document.getElementById("metaStats"),
    errorBanner: document.getElementById("errorBanner"),
    pcapSelect: document.getElementById("pcapSelect"),
    followChk: document.getElementById("followChk"),
    adbSelect: document.getElementById("adbSelect"),
    teeChk: document.getElementById("teeChk"),
    matchSelect: document.getElementById("matchSelect"),
    phaseFilter: document.getElementById("phaseFilter"),
    chanFilter: document.getElementById("chanFilter"),
    sideFilter: document.getElementById("sideFilter"),
    searchInput: document.getElementById("searchInput"),
    rawChk: document.getElementById("rawChk"),
    matchSummary: document.getElementById("matchSummary"),
    logWrap: document.getElementById("logWrap"),
    jumpLatest: document.getElementById("jumpLatest"),
  };

  function fmtTime(ts) {
    if (!ts) return "--:--:--";
    const d = new Date(ts * 1000);
    return d.toTimeString().slice(0, 8);
  }

  function ensureMatch(summary) {
    if (!summary || !summary.match_id) return null;
    const id = summary.match_id;
    let m = state.matches.get(id);
    if (!m) {
      m = { summary: summary, events: [], gaps: [] };
      state.matches.set(id, m);
      state.matchOrder.push(id);
      if (!state.selectedMatchId) state.selectedMatchId = id;
    } else {
      m.summary = summary;
      if (Array.isArray(summary.events)) m.events = summary.events;
      if (Array.isArray(summary.gaps)) m.gaps = summary.gaps;
    }
    return m;
  }

  function upsertEvent(ev) {
    let m = state.matches.get(ev.match_id);
    if (!m) {
      m = ensureMatch({ match_id: ev.match_id, events: [], gaps: [] });
    }
    const idx = m.events.findIndex((x) => x.seq_id === ev.seq_id);
    if (idx >= 0) m.events[idx] = ev;
    else m.events.push(ev);
  }

  function upsertGap(gap) {
    let m = state.matches.get(gap.match_id);
    if (!m) {
      m = ensureMatch({ match_id: gap.match_id, events: [], gaps: [] });
    }
    const idx = m.gaps.findIndex((g) => g.gap_id === gap.gap_id);
    if (idx >= 0) m.gaps[idx] = gap;
    else m.gaps.push(gap);
  }

  function renderStatus() {
    const s = state.status || {};
    const mode = s.source_mode || "IDLE";
    el.badgeSource.textContent = mode + (s.source_detail ? ` (${s.source_detail})` : "");
    el.badgeSource.className = "badge " + (s.capture_alive ? "ok" : (mode === "CAPTURE STOPPED" ? "err" : ""));

    const fsm = s.fsm_state || s.phase || "IDLE";
    const fsmLabel = fsm === "SYNCED" ? "BATTLE SYNCED" : fsm;
    el.badgeFsm.textContent = fsmLabel;
    if (fsm === "WAIT_CLEAR" || fsm === "VERIFYING_SYNC") el.badgeFsm.className = "badge warn";
    else if (fsm === "DESYNC" || mode === "CAPTURE STOPPED") el.badgeFsm.className = "badge err";
    else if (fsm === "SYNCED" || fsm === "SYNCED_MIDMATCH") el.badgeFsm.className = "badge ok";
    else el.badgeFsm.className = "badge";

    const age = s.last_pkt_age_s;
    const isLive = mode === "LIVE (adb)" || mode === "FOLLOW (file)";
    const threshold = (s.phase === "BATTLE") ? 3.0 : 5.0;
    if (isLive && s.capture_alive && typeof age === "number" && age > threshold) {
      el.badgeStale.style.display = "inline-flex";
      el.badgeStale.className = "badge warn";
      el.badgeStale.textContent = `STALE (${Math.floor(age)}s since last packet)`;
    } else {
      el.badgeStale.style.display = "none";
    }

    const tickTxt = (s.next_tick !== null && s.next_tick !== undefined) ? s.next_tick : "-";
    const ageTxt = (typeof age === "number") ? `age=${age.toFixed(1)}s` : "age=-";
    el.metaStats.textContent = `tick=${tickTxt} dict=${s.dict_next_code || "0x0101"} ${ageTxt}`;

    if (s.last_error) {
      el.errorBanner.style.display = "block";
      el.errorBanner.textContent = s.last_error;
    } else {
      el.errorBanner.style.display = "none";
    }
  }

  function renderMatchSelect() {
    const prev = state.selectedMatchId;
    el.matchSelect.innerHTML = "";
    if (state.matchOrder.length === 0) {
      const opt = document.createElement("option");
      opt.value = "";
      opt.textContent = "No matches yet";
      el.matchSelect.appendChild(opt);
      el.matchSummary.textContent = "";
      return;
    }
    for (const id of state.matchOrder) {
      const m = state.matches.get(id);
      const s = m.summary || {};
      const opt = document.createElement("option");
      opt.value = id;
      const ep = s.server_ip ? `${s.server_ip}:${s.server_port}` : "?";
      const bid = s.battle_id ? ` #${s.battle_id}` : "";
      opt.textContent = `${id} · ${ep}${bid} (${m.events.length})`;
      el.matchSelect.appendChild(opt);
    }
    if (prev && state.matches.has(prev)) {
      el.matchSelect.value = prev;
    } else {
      state.selectedMatchId = state.matchOrder[state.matchOrder.length - 1];
      el.matchSelect.value = state.selectedMatchId;
    }
    const active = state.matches.get(state.selectedMatchId);
    if (active && active.summary) {
      const s = active.summary;
      el.matchSummary.textContent = `${s.phase || "IDLE"} · ${s.decoded_ticks || 0} ticks · ${s.players ? s.players.length : 0} players`;
    }
  }

  function matchesFilters(ev) {
    const pf = el.phaseFilter.value;
    if (pf !== "all" && ev.phase !== pf) return false;
    const cf = el.chanFilter.value;
    if (cf === "all_chat" && ev.channel_name !== "all") return false;
    else if (cf !== "all" && cf !== "all_chat" && ev.channel_name !== cf) return false;

    const sf = el.sideFilter.value;
    if (sf === "ALLY_GROUP" && ev.side !== "SELF" && ev.side !== "ALLY") return false;
    else if (sf === "CAMP" && !ev.side.startsWith("CAMP") && ev.side !== "UNKNOWN") return false;
    else if (sf !== "all" && sf !== "ALLY_GROUP" && sf !== "CAMP" && ev.side !== sf) return false;

    const q = el.searchInput.value.trim().toLowerCase();
    if (q) {
      const hay = `${ev.sender_name} ${ev.display_text} ${ev.raw_text}`.toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  }

  function renderLog(forceScroll) {
    const m = state.matches.get(state.selectedMatchId);
    el.logWrap.innerHTML = "";
    if (!m || (m.events.length === 0 && m.gaps.length === 0)) {
      const div = document.createElement("div");
      div.className = "empty";
      div.textContent = "Waiting for packets... Pick a PCAP or connect a rooted ADB device above.";
      el.logWrap.appendChild(div);
      return;
    }

    const timeline = [];
    for (const g of m.gaps) timeline.push({ kind: "gap", ts: g.ts || 0, item: g });
    for (const ev of m.events) {
      if (matchesFilters(ev)) timeline.push({ kind: "ev", ts: ev.ts || 0, item: ev });
    }
    timeline.sort((a, b) => a.ts - b.ts);

    const showRaw = el.rawChk.checked;
    const frag = document.createDocumentFragment();
    for (const row of timeline) {
      if (row.kind === "gap") {
        const g = row.item;
        const div = document.createElement("div");
        div.className = "gap-banner" + (g.resolved ? " resolved" : "");
        const span = document.createElement("span");
        span.textContent = g.message;
        const tag = document.createElement("span");
        tag.className = "mono";
        tag.textContent = g.resolved ? `RESYNCED @ ${g.sync_tick}` : "WAIT_CLEAR";
        div.appendChild(span);
        div.appendChild(tag);
        frag.appendChild(div);
        continue;
      }
      const ev = row.item;
      const div = document.createElement("div");
      div.className = `msg side-${ev.side.split(" ")[0]}`;

      const tm = document.createElement("span");
      tm.className = "msg-time mono";
      tm.textContent = ev.tick !== null && ev.tick !== undefined ? `${fmtTime(ev.ts)} #${ev.tick}` : fmtTime(ev.ts);

      const side = document.createElement("span");
      side.className = "msg-tag";
      side.textContent = ev.side;

      const ch = document.createElement("span");
      ch.className = "msg-chan mono";
      ch.textContent = ev.channel_name;

      const sender = document.createElement("span");
      sender.className = "msg-sender";
      sender.textContent = ev.sender_name || "unknown";
      sender.title = ev.sender_uid ? `uid=${ev.sender_uid}` : "";

      const body = document.createElement("span");
      body.className = "msg-text";
      body.textContent = ev.display_text;
      if (showRaw && ev.raw_text && ev.raw_text !== ev.display_text) {
        const raw = document.createElement("span");
        raw.className = "msg-raw mono";
        raw.textContent = `[${ev.raw_text}]`;
        body.appendChild(raw);
      }

      div.appendChild(tm);
      div.appendChild(side);
      div.appendChild(ch);
      div.appendChild(sender);
      div.appendChild(body);
      frag.appendChild(div);
    }
    el.logWrap.appendChild(frag);
    if (forceScroll || state.autoScroll) {
      el.logWrap.scrollTop = el.logWrap.scrollHeight;
      state.unreadCount = 0;
      el.jumpLatest.style.display = "none";
    }
  }

  async function refreshSources() {
    try {
      const [pcapsRes, devsRes] = await Promise.all([fetch("/api/pcaps"), fetch("/api/devices")]);
      const pcapsData = await pcapsRes.json();
      const devsData = await devsRes.json();

      el.pcapSelect.innerHTML = "";
      const pcaps = pcapsData.pcaps || [];
      if (pcaps.length === 0) {
        const o = document.createElement("option");
        o.value = ""; o.textContent = "No .pcap in captures/";
        el.pcapSelect.appendChild(o);
      } else {
        for (const p of pcaps) {
          const o = document.createElement("option");
          o.value = p.path; o.textContent = p.name;
          el.pcapSelect.appendChild(o);
        }
      }

      el.adbSelect.innerHTML = "";
      const devs = devsData.devices || [];
      if (devs.length === 0) {
        const o = document.createElement("option");
        o.value = ""; o.textContent = "No ADB device";
        el.adbSelect.appendChild(o);
      } else {
        for (const d of devs) {
          const o = document.createElement("option");
          o.value = d.serial;
          o.textContent = `${d.serial} (${d.model || d.state})`;
          el.adbSelect.appendChild(o);
        }
      }
    } catch (_e) {}
  }

  async function loadInitialMatches() {
    try {
      const res = await fetch("/api/matches");
      const data = await res.json();
      state.matches.clear();
      state.matchOrder = [];
      state.selectedMatchId = null;
      for (const m of (data.matches || [])) ensureMatch(m);
      if (data.status) state.status = data.status;
      renderStatus();
      renderMatchSelect();
      renderLog(true);
    } catch (_e) {}
  }

  async function switchSource(body) {
    const res = await fetch("/api/source", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const data = await res.json();
    if (!res.ok) {
      state.status.last_error = data.error || "Failed to switch source";
      renderStatus();
      return;
    }
    if (data.status) state.status = data.status;
    renderStatus();
  }

  function connectSse() {
    const es = new EventSource("/events");
    const markAlive = (ev) => {
      state.lastHeartbeatMs = Date.now();
      if (ev && ev.lastEventId) state.lastEventId = ev.lastEventId;
      el.badgeSse.className = "badge ok";
      el.badgeSse.textContent = "SSE CONNECTED";
    };

    es.addEventListener("status", (ev) => {
      markAlive(ev);
      state.status = JSON.parse(ev.data);
      renderStatus();
    });

    es.addEventListener("source_reset", (ev) => {
      markAlive(ev);
      const d = JSON.parse(ev.data);
      state.matches.clear();
      state.matchOrder = [];
      state.selectedMatchId = null;
      if (d.status) state.status = d.status;
      renderStatus();
      renderMatchSelect();
      renderLog(true);
    });

    es.addEventListener("snapshot", (ev) => {
      markAlive(ev);
      const d = JSON.parse(ev.data);
      state.matches.clear();
      state.matchOrder = [];
      state.selectedMatchId = null;
      for (const m of (d.matches || [])) ensureMatch(m);
      if (d.status) state.status = d.status;
      renderStatus();
      renderMatchSelect();
      renderLog(true);
    });

    es.addEventListener("match_new", (ev) => {
      markAlive(ev);
      const m = JSON.parse(ev.data);
      ensureMatch(m);
      state.selectedMatchId = m.match_id;
      renderMatchSelect();
      renderLog(true);
    });

    es.addEventListener("match_update", (ev) => {
      markAlive(ev);
      const m = JSON.parse(ev.data);
      ensureMatch(m);
      renderMatchSelect();
      if (m.match_id === state.selectedMatchId) renderLog(false);
    });

    es.addEventListener("chat", (ev) => {
      markAlive(ev);
      const msg = JSON.parse(ev.data);
      upsertEvent(msg);
      renderMatchSelect();
      if (msg.match_id === state.selectedMatchId) {
        if (!state.autoScroll) {
          state.unreadCount += 1;
          el.jumpLatest.textContent = `Jump to latest (${state.unreadCount})`;
          el.jumpLatest.style.display = "block";
        }
        renderLog(false);
      }
    });

    es.addEventListener("gap", (ev) => {
      markAlive(ev);
      const g = JSON.parse(ev.data);
      upsertGap(g);
      renderMatchSelect();
      if (g.match_id === state.selectedMatchId) renderLog(false);
    });

    es.onerror = () => {
      el.badgeSse.className = "badge err";
      el.badgeSse.textContent = "SERVER DISCONNECTED";
    };
  }

  setInterval(() => {
    if (Date.now() - state.lastHeartbeatMs > 3000) {
      el.badgeSse.className = "badge err";
      el.badgeSse.textContent = "SERVER DISCONNECTED";
    }
  }, 1000);

  el.logWrap.addEventListener("scroll", () => {
    const gap = el.logWrap.scrollHeight - el.logWrap.scrollTop - el.logWrap.clientHeight;
    state.autoScroll = gap < 36;
    if (state.autoScroll) {
      state.unreadCount = 0;
      el.jumpLatest.style.display = "none";
    }
  });

  el.jumpLatest.addEventListener("click", () => {
    state.autoScroll = true;
    state.unreadCount = 0;
    el.logWrap.scrollTop = el.logWrap.scrollHeight;
    el.jumpLatest.style.display = "none";
  });

  el.matchSelect.addEventListener("change", () => {
    state.selectedMatchId = el.matchSelect.value;
    renderMatchSelect();
    renderLog(true);
  });

  for (const ctrl of [el.phaseFilter, el.chanFilter, el.sideFilter, el.rawChk]) {
    ctrl.addEventListener("change", () => renderLog(false));
  }
  el.searchInput.addEventListener("input", () => renderLog(false));

  document.getElementById("btnLoadPcap").addEventListener("click", () => {
    const p = el.pcapSelect.value;
    if (p) switchSource({ mode: "pcap", path: p, follow: el.followChk.checked });
  });
  document.getElementById("btnStartAdb").addEventListener("click", () => {
    const s = el.adbSelect.value;
    if (s) switchSource({ mode: "adb", serial: s, tee: el.teeChk.checked });
  });
  document.getElementById("btnRefresh").addEventListener("click", refreshSources);
  document.getElementById("btnStop").addEventListener("click", () => switchSource({ mode: "stop" }));

  refreshSources();
  loadInitialMatches();
  connectSse();
})();
</script>
</body>
</html>
"""
