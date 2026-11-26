"""Self-contained dark 4-tab UI for FIxLag Server & Live Packet Mapper."""

from __future__ import annotations

INDEX_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="icon" href="data:,">
<title>FIxLag — Server Map &amp; Live Packet Mapper</title>
<style>
  :root {
    --bg: #0b0f16;
    --panel: #121822;
    --panel-2: #182130;
    --panel-hover: #1f2a3d;
    --border: #263246;
    --text: #eef3fb;
    --muted: #8b9bb4;
    --blue: #3b82f6;
    --blue-bg: rgba(59, 130, 246, 0.14);
    --cyan: #22d3ee;
    --cyan-bg: rgba(34, 211, 238, 0.14);
    --green: #22c55e;
    --green-bg: rgba(34, 197, 94, 0.15);
    --amber: #f59e0b;
    --amber-bg: rgba(245, 158, 11, 0.15);
    --red: #ef4444;
    --red-bg: rgba(239, 68, 68, 0.15);
    --slate: #64748b;
    --slate-bg: rgba(148, 163, 184, 0.12);
  }
  * { box-sizing: border-box; }
  html, body {
    margin: 0; padding: 0; height: 100%;
    background: var(--bg); color: var(--text);
    font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
    font-size: 13.5px; -webkit-font-smoothing: antialiased;
  }
  body { display: flex; flex-direction: column; overflow: hidden; }
  button, input, select {
    font-family: inherit; font-size: 12.5px; color: var(--text);
    background: var(--panel-2); border: 1px solid var(--border);
    border-radius: 8px; outline: none;
  }
  button { cursor: pointer; padding: 6px 11px; font-weight: 600; transition: background 0.15s, border-color 0.15s; }
  button:hover { background: var(--panel-hover); border-color: #3d5070; }
  button.primary { background: #2563eb; border-color: #3b82f6; color: #fff; }
  button.primary:hover { background: #1d4ed8; }
  button.danger { background: #991b1b; border-color: #dc2626; color: #fff; }
  button.danger:hover { background: #b91c1c; }
  input[type="text"], input[type="number"], select { padding: 6px 9px; }
  input:focus, select:focus { border-color: var(--blue); }

  /* Header */
  .topbar {
    height: 54px; flex-shrink: 0; background: var(--panel); border-bottom: 1px solid var(--border);
    padding: 0 16px; display: flex; align-items: center; gap: 12px;
  }
  .brand { display: flex; align-items: center; gap: 9px; font-weight: 700; font-size: 14.5px; white-space: nowrap; }
  .brand-dot {
    width: 26px; height: 26px; border-radius: 7px;
    background: linear-gradient(135deg, #06b6d4, #2563eb);
    display: grid; place-items: center; font-size: 13px; font-weight: 800; color: #fff;
  }
  .tabs {
    display: inline-flex; background: var(--bg); padding: 3px; border-radius: 10px;
    border: 1px solid var(--border); gap: 2px; overflow-x: auto;
  }
  .tab-btn {
    background: transparent; border: none; border-radius: 7px; padding: 5px 12px;
    font-size: 12.5px; font-weight: 600; color: var(--muted); white-space: nowrap;
    display: inline-flex; align-items: center; gap: 6px;
  }
  .tab-btn:hover { color: var(--text); background: rgba(255,255,255,0.04); }
  .tab-btn.active { background: var(--panel-2); color: var(--text); box-shadow: 0 1px 3px rgba(0,0,0,0.35); }
  .live-dot { width: 7px; height: 7px; border-radius: 50%; background: var(--muted); }
  .live-dot.on { background: var(--green); box-shadow: 0 0 8px var(--green); }
  .spacer { flex: 1; }
  .pill {
    display: inline-flex; align-items: center; gap: 5px; padding: 4px 9px; border-radius: 999px;
    font-size: 11.5px; font-weight: 600; background: var(--panel-2); border: 1px solid var(--border); color: var(--muted);
    white-space: nowrap;
  }
  .pill.ok { background: var(--green-bg); border-color: rgba(34,197,94,0.45); color: #86efac; }
  .pill.warn { background: var(--amber-bg); border-color: rgba(245,158,11,0.45); color: #fde68a; }
  .pill.err { background: var(--red-bg); border-color: rgba(239,68,68,0.45); color: #fca5a5; }
  .pill.info { background: var(--blue-bg); border-color: rgba(59,130,246,0.45); color: #93c5fd; }
  .pill.cyan { background: var(--cyan-bg); border-color: rgba(34,211,238,0.45); color: #a5f3fc; }

  /* Main Views */
  .content { flex: 1; min-height: 0; overflow-y: auto; padding: 16px; }
  .tab-panel { display: none; flex-direction: column; gap: 14px; max-width: 1440px; margin: 0 auto; }
  .tab-panel.active { display: flex; }

  .kpi-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; }
  .kpi-card {
    background: var(--panel); border: 1px solid var(--border); border-radius: 12px;
    padding: 12px 14px; display: flex; flex-direction: column; gap: 4px;
  }
  .kpi-lbl { font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; color: var(--muted); }
  .kpi-val { font-size: 20px; font-weight: 800; color: var(--text); }
  .kpi-sub { font-size: 11.5px; color: var(--muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

  .card {
    background: var(--panel); border: 1px solid var(--border); border-radius: 12px;
    padding: 14px; display: flex; flex-direction: column; gap: 10px;
  }
  .card-head { display: flex; align-items: center; justify-content: space-between; gap: 10px; flex-wrap: wrap; }
  .card-title { font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; color: var(--muted); }
  .two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }

  /* Tables */
  .tbl-wrap { overflow-x: auto; border: 1px solid var(--border); border-radius: 10px; background: var(--panel-2); }
  table { width: 100%; border-collapse: collapse; font-size: 12.5px; }
  th, td { padding: 8px 10px; text-align: left; border-bottom: 1px solid rgba(38,50,70,0.7); }
  th {
    background: rgba(11,15,22,0.55); color: var(--muted); font-size: 11px; font-weight: 700;
    text-transform: uppercase; letter-spacing: 0.4px; white-space: nowrap; user-select: none;
  }
  th.sortable { cursor: pointer; }
  th.sortable:hover { color: var(--text); }
  tr:last-child td { border-bottom: none; }
  tr.clickable { cursor: pointer; }
  tr.clickable:hover td { background: rgba(59, 130, 246, 0.10); }
  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; }

  /* SVG Map */
  .map-wrap { position: relative; background: radial-gradient(circle at 48% 60%, #142033 0%, #0d131d 75%); border: 1px solid var(--border); border-radius: 11px; overflow: hidden; }
  .map-svg { width: 100%; height: 320px; display: block; }
  .map-tip {
    position: absolute; display: none; pointer-events: none; z-index: 10;
    background: rgba(11,15,22,0.95); border: 1px solid var(--border); border-radius: 8px;
    padding: 7px 10px; font-size: 12px; box-shadow: 0 8px 24px rgba(0,0,0,0.5);
  }
  .cluster-node { cursor: pointer; transition: opacity 0.15s; }
  .cluster-node:hover { opacity: 0.92; }

  /* Source Bar & Pipeline */
  .source-bar { display: flex; flex-wrap: wrap; align-items: center; gap: 10px; }
  .source-group { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }
  .chk { display: inline-flex; align-items: center; gap: 5px; font-size: 12px; color: var(--muted); cursor: pointer; user-select: none; }
  .pipeline { display: grid; grid-template-columns: repeat(7, minmax(0, 1fr)); gap: 8px; }
  .stage-chip {
    background: var(--panel-2); border: 1px solid var(--border); border-radius: 10px;
    padding: 9px 10px; display: flex; flex-direction: column; gap: 4px; opacity: 0.65; transition: all 0.2s;
  }
  .stage-chip.lit {
    opacity: 1; border-color: rgba(34, 211, 238, 0.55); background: rgba(34, 211, 238, 0.08);
    box-shadow: inset 0 0 0 1px rgba(34, 211, 238, 0.16);
  }
  .stage-name { font-size: 11.5px; font-weight: 700; color: var(--text); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .stage-cnt { font-size: 11px; color: var(--muted); }
  .stage-chip.lit .stage-cnt { color: #a5f3fc; }

  /* Multipath Bar & Sparkline */
  .split-track { height: 12px; border-radius: 999px; background: var(--bg); overflow: hidden; display: flex; border: 1px solid var(--border); }
  .split-wifi { background: var(--cyan); transition: width 0.2s; }
  .split-cell { background: var(--amber); transition: width 0.2s; }
  .split-other { background: var(--slate); transition: width 0.2s; }
  .spark-svg { width: 100%; height: 170px; display: block; background: #0d131d; border: 1px solid var(--border); border-radius: 10px; }

  /* Feed */
  .filter-pills { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; }
  .f-pill {
    background: var(--panel-2); border: 1px solid var(--border); border-radius: 999px;
    padding: 4px 10px; font-size: 11.5px; font-weight: 600; color: var(--muted);
  }
  .f-pill.active { background: var(--blue-bg); border-color: var(--blue); color: #bfdbfe; }
  .feed-box {
    max-height: 360px; overflow-y: auto; border: 1px solid var(--border); border-radius: 10px;
    background: #0d131d; display: flex; flex-direction: column;
  }
  .feed-row {
    display: grid; grid-template-columns: 74px 115px 74px 145px 155px 1fr; gap: 8px; align-items: center;
    padding: 6px 10px; border-bottom: 1px solid rgba(38,50,70,0.5); font-size: 12px;
  }
  .feed-row:last-child { border-bottom: none; }

  /* Privacy Banner & Party Cards */
  .notice-banner {
    background: rgba(59, 130, 246, 0.10); border: 1px solid rgba(59, 130, 246, 0.42);
    border-radius: 11px; padding: 11px 14px; font-size: 12.5px; line-height: 1.5; color: #dbeafe;
  }
  .party-grid { display: grid; grid-template-columns: 1.3fr 1fr; gap: 12px; }
  .player-list { display: flex; flex-direction: column; gap: 6px; }
  .player-row {
    display: flex; align-items: center; gap: 8px; flex-wrap: wrap;
    background: var(--panel-2); border: 1px solid var(--border); border-radius: 8px; padding: 6px 10px;
  }
  .form-grid { display: grid; grid-template-columns: 1fr 140px; gap: 8px; }
  .empty-box { padding: 24px; text-align: center; color: var(--muted); font-size: 12.5px; }

  @media (max-width: 1100px) {
    .kpi-grid { grid-template-columns: repeat(2, 1fr); }
    .pipeline { grid-template-columns: repeat(4, 1fr); }
    .two-col, .party-grid { grid-template-columns: 1fr; }
    .feed-row { grid-template-columns: 65px 100px 68px 1fr; }
  }
</style>
</head>
<body>
<header class="topbar">
  <div class="brand">
    <div class="brand-dot">FL</div>
    <span>FIxLag Packet Mapper</span>
  </div>
  <nav class="tabs" aria-label="Primary tabs">
    <button class="tab-btn active" data-tab="servers" id="tab-btn-servers">Server Map &amp; List</button>
    <button class="tab-btn" data-tab="live" id="tab-btn-live"><span class="live-dot" id="live-dot"></span>Live Packet Detector</button>
    <button class="tab-btn" data-tab="party" id="tab-btn-party">Lobby, Party &amp; Ping</button>
    <button class="tab-btn" data-tab="matches" id="tab-btn-matches">All Matches <span id="matches-count-pill" class="pill" style="padding:1px 6px;font-size:10.5px;">0</span></button>
  </nav>
  <div class="spacer"></div>
  <span class="pill" id="zstd-pill">Zstd: checking</span>
  <span class="pill" id="scan-pill">Scan: idle</span>
  <button id="rescan-btn" title="Rescan captures/*.pcap and data/matches.csv">Rescan</button>
  <span class="pill" id="status-pill">IDLE</span>
</header>

<main class="content">
  <!-- TAB 1: SERVER MAP & LIST -->
  <section class="tab-panel active" id="panel-servers">
    <div class="kpi-grid">
      <div class="kpi-card">
        <div class="kpi-lbl">Total Servers Seen</div>
        <div class="kpi-val" id="kpi-servers">0</div>
        <div class="kpi-sub" id="kpi-servers-sub">Distinct public match IPs</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-lbl">Total Matches Logged</div>
        <div class="kpi-val" id="kpi-matches">0</div>
        <div class="kpi-sub" id="kpi-matches-sub">PCAP + CSV deduplicated</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-lbl">Best Observed Server RTT</div>
        <div class="kpi-val" id="kpi-best-rtt">-</div>
        <div class="kpi-sub" id="kpi-best-sub">No RTT samples yet</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-lbl">Currently Active Server</div>
        <div class="kpi-val" id="kpi-active-srv">Idle</div>
        <div class="kpi-sub" id="kpi-active-sub">Start live ADB or PCAP replay in Tab 2</div>
      </div>
    </div>

    <div class="card">
      <div class="card-head">
        <span class="card-title">Regional Server Hub Map (from Surabaya)</span>
        <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
          <span class="pill ok">&lt; 30 ms</span>
          <span class="pill warn">30 - 60 ms</span>
          <span class="pill err">&gt; 60 ms</span>
          <span class="pill">No RTT</span>
          <button id="clear-cluster-btn" style="display:none;">Show All Clusters</button>
        </div>
      </div>
      <div class="map-wrap">
        <svg id="hub-map-svg" class="map-svg" viewBox="0 0 800 360" role="img" aria-label="MLBB Server Hub Map"></svg>
        <div id="map-tooltip" class="map-tip"></div>
      </div>
    </div>

    <div class="card">
      <div class="card-head">
        <span class="card-title" id="server-table-title">Visited Match Servers</span>
        <input type="text" id="server-search" placeholder="Filter IP, provider, city, mode..." style="width:240px;">
      </div>
      <div class="tbl-wrap">
        <table>
          <thead>
            <tr>
              <th class="sortable" data-sort="ip">IP</th>
              <th class="sortable" data-sort="subnet">/24</th>
              <th class="sortable" data-sort="provider">Provider</th>
              <th class="sortable" data-sort="city">City</th>
              <th class="sortable" data-sort="confidence">Confidence</th>
              <th class="sortable" data-sort="match_count">Matches</th>
              <th class="sortable" data-sort="wifi_median_ms">Wi-Fi Med</th>
              <th class="sortable" data-sort="cell_median_ms">Cell Med</th>
              <th class="sortable" data-sort="displayed_ping_median_ms">Displayed Ping</th>
              <th>Modes</th>
            </tr>
          </thead>
          <tbody id="servers-tbody"></tbody>
        </table>
      </div>
    </div>
  </section>

  <!-- TAB 2: LIVE PACKET DETECTOR -->
  <section class="tab-panel" id="panel-live">
    <div class="card">
      <div class="source-bar">
        <div class="source-group">
          <select id="adb-select" style="min-width:190px;"><option value="">No ADB devices</option></select>
          <button id="refresh-devices-btn">Refresh ADB</button>
          <label class="chk"><input type="checkbox" id="adb-tee-chk" checked> Tee .pcap</label>
          <button class="primary" id="start-adb-btn">Start ADB Live</button>
        </div>
        <div class="source-group">
          <select id="pcap-select" style="min-width:220px;"><option value="">Select local .pcap...</option></select>
          <label class="chk"><input type="checkbox" id="pcap-follow-chk"> Follow</label>
          <button class="primary" id="start-pcap-btn">Replay PCAP</button>
          <button class="danger" id="stop-source-btn">Stop</button>
        </div>
        <span id="source-err" class="pill err" style="display:none;"></span>
      </div>
    </div>

    <div class="card">
      <div class="card-head">
        <span class="card-title">Live Protocol Pipeline</span>
        <span class="pill" id="live-packets-total">0 packets</span>
      </div>
      <div class="pipeline" id="pipeline-strip"></div>
    </div>

    <div class="two-col">
      <div class="card">
        <div class="card-head">
          <span class="card-title">Dual-Link Multipath &amp; Lobby Telemetry</span>
          <span class="pill cyan" id="live-active-ep">No active match</span>
        </div>
        <div class="split-track">
          <div class="split-wifi" id="split-wifi" style="width:0%"></div>
          <div class="split-cell" id="split-cell" style="width:0%"></div>
          <div class="split-other" id="split-other" style="width:0%"></div>
        </div>
        <div style="display:flex;gap:10px;flex-wrap:wrap;font-size:12px;" id="multipath-readout">
          <span class="pill cyan">Wi-Fi: 0 (0%)</span>
          <span class="pill warn">Cellular: 0 (0%)</span>
        </div>
        <div id="live-rtt-stats" style="display:flex;gap:8px;flex-wrap:wrap;font-size:12px;"></div>
        <div id="live-lobby-readout" style="font-size:12px;color:var(--muted);line-height:1.5;"></div>
      </div>

      <div class="card">
        <div class="card-head">
          <span class="card-title">Live 0x3f5 Echo RTT Sparkline (Wi-Fi vs Cellular)</span>
          <div style="display:flex;gap:6px;">
            <span class="pill cyan">Wi-Fi</span>
            <span class="pill warn">Cellular</span>
          </div>
        </div>
        <svg id="rtt-spark-svg" class="spark-svg" viewBox="0 0 640 170" role="img" aria-label="Live RTT Sparkline"></svg>
      </div>
    </div>

    <div class="card">
      <div class="card-head">
        <span class="card-title">Packet Detection Stream</span>
        <div class="filter-pills" id="lane-filters">
          <button class="f-pill active" data-lane="ALL">All</button>
          <button class="f-pill" data-lane="LOBBY_TCP">Lobby</button>
          <button class="f-pill" data-lane="PROBE_30190">Probes</button>
          <button class="f-pill" data-lane="UDP_CONNECT">Handshake</button>
          <button class="f-pill" data-lane="KCP_CONTROL">Roster</button>
          <button class="f-pill" data-lane="PING_ECHO">Ping</button>
          <button class="f-pill" data-lane="BATTLE_TICK">Ticks</button>
          <button class="f-pill" data-lane="TCP_MIRROR">Mirror</button>
          <input type="text" id="feed-search" placeholder="Search feed..." style="width:160px;">
          <label class="chk"><input type="checkbox" id="feed-autoscroll" checked> Auto-scroll</label>
        </div>
      </div>
      <div class="feed-box" id="packet-feed-box">
        <div class="empty-box">No packets decoded yet. Select a PCAP or start ADB Live.</div>
      </div>
    </div>
  </section>

  <!-- TAB 3: LOBBY, PARTY & PING -->
  <section class="tab-panel" id="panel-party">
    <div class="notice-banner" id="privacy-notice-banner">
      <strong>Protocol &amp; Privacy Boundary:</strong> Friends' IP addresses are <strong>NOT</strong> visible on the wire.
      MLBB uses client-server routing through Moonton match servers, not peer-to-peer links.
      What IS visible passively: every player's <span class="mono">sThisLoginCountry</span>, <span class="mono">uiZoneId</span>, exact party grouping via <span class="mono">ulRoomID</span>, and pre-match <span class="mono">:30101</span> coarse lobby regions.
      Auth packets (<span class="mono">mid=10208</span>) are dropped before decoding.
    </div>

    <div class="card">
      <div class="card-head">
        <span class="card-title">Selected / Live Match Party &amp; Server Attribution</span>
        <select id="party-match-select" style="min-width:340px;max-width:100%;"></select>
      </div>
      <div class="party-grid">
        <div style="display:flex;flex-direction:column;gap:10px;">
          <div id="selected-match-meta" style="display:flex;gap:6px;flex-wrap:wrap;"></div>
          <div class="card-title">Ally Party Members</div>
          <div class="player-list" id="ally-party-list"></div>
          <div class="card-title">Enemy Camp</div>
          <div id="enemy-camp-summary" style="font-size:12.5px;color:var(--muted);"></div>
        </div>
        <div style="display:flex;flex-direction:column;gap:10px;">
          <div class="card-title">Server, Handover, Mirror &amp; :30190 Probes</div>
          <div id="selected-server-box" style="background:var(--panel-2);border:1px solid var(--border);border-radius:10px;padding:10px;font-size:12.5px;line-height:1.6;"></div>
          <div class="card-title">Party Host &amp; Displayed Ping / Notes</div>
          <form id="notes-form" style="display:flex;flex-direction:column;gap:8px;background:var(--panel-2);border:1px solid var(--border);border-radius:10px;padding:10px;">
            <div class="form-grid">
              <input type="text" id="note-host-input" placeholder="Host (e.g. me, MY friend, SG friend)">
              <input type="number" step="0.1" id="note-ping-input" placeholder="Ping ms">
            </div>
            <div style="display:flex;gap:5px;flex-wrap:wrap;">
              <button type="button" class="f-pill host-preset" data-host="me">me (ID)</button>
              <button type="button" class="f-pill host-preset" data-host="MY friend">MY friend</button>
              <button type="button" class="f-pill host-preset" data-host="SG friend">SG friend</button>
              <button type="button" class="f-pill host-preset" data-host="IN friend">IN friend</button>
              <button type="button" class="f-pill host-preset" data-host="MV friend">MV friend</button>
            </div>
            <input type="text" id="note-text-input" placeholder="Notes on party, lobby host, or ping feel...">
            <div style="display:flex;align-items:center;gap:8px;">
              <button type="submit" class="primary" id="save-note-btn">Save Note</button>
              <span id="note-save-status" class="pill" style="display:none;"></span>
            </div>
          </form>
        </div>
      </div>
    </div>

    <div class="card">
      <div class="card-head">
        <span class="card-title">Party Country Mix &amp; Host -&gt; Server &amp; Ping Correlation</span>
        <span class="pill info" id="corr-baseline-pill">Baseline: -</span>
      </div>
      <div class="tbl-wrap">
        <table>
          <thead>
            <tr>
              <th>Mode</th>
              <th>Party Mix</th>
              <th>Host</th>
              <th>Matches</th>
              <th>Selected Servers &amp; Cities</th>
              <th>Median UDP RTT</th>
              <th>Displayed Ping</th>
              <th>Delta vs Baseline</th>
              <th>:30190 Probes</th>
            </tr>
          </thead>
          <tbody id="corr-tbody"></tbody>
        </table>
      </div>
    </div>
  </section>

  <!-- TAB 4: ALL MATCHES -->
  <section class="tab-panel" id="panel-matches">
    <div class="card">
      <div class="card-head">
        <span class="card-title">Unified Match Ledger (PCAP + CSV + Live)</span>
        <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
          <div class="filter-pills" id="origin-filters">
            <button class="f-pill active" data-origin="ALL">All</button>
            <button class="f-pill" data-origin="pcap">PCAP</button>
            <button class="f-pill" data-origin="csv">CSV</button>
            <button class="f-pill" data-origin="live">Live</button>
          </div>
          <input type="text" id="matches-search" placeholder="Search IP, mode, host, player, source..." style="width:250px;">
        </div>
      </div>
      <div class="tbl-wrap">
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Origin / Source</th>
              <th>Mode</th>
              <th>Party Mix</th>
              <th>Host</th>
              <th>Server IP &amp; City</th>
              <th>Wi-Fi / Cell Med</th>
              <th>Displayed</th>
              <th>Mirror / Probes</th>
              <th>Note</th>
            </tr>
          </thead>
          <tbody id="matches-tbody"></tbody>
        </table>
      </div>
    </div>
  </section>
</main>

<script>
(function() {
  "use strict";

  const state = {
    tab: "servers",
    overview: null,
    servers: [],
    clusters: {},
    matches: [],
    correlations: { baseline_ms: null, baseline_label: "", groups: [] },
    live: null,
    selectedCluster: null,
    serverSort: { col: "match_count", dir: -1 },
    laneFilter: "ALL",
    originFilter: "ALL",
    selectedMatchKey: null,
    feedItems: [],
    liveRttPoints: [],
    liveSeq: 0,
    lastEventId: 0
  };

  function esc(v) {
    return String(v == null ? "" : v)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function fmtTs(ts) {
    if (!ts) return "-";
    const d = new Date(ts * 1000);
    return d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
  }

  function fmtMs(v) {
    return typeof v === "number" && Number.isFinite(v) ? v.toFixed(1) + " ms" : "-";
  }

  function rttColor(ms) {
    if (typeof ms !== "number" || !Number.isFinite(ms)) return "#64748b";
    if (ms < 30) return "#22c55e";
    if (ms <= 60) return "#f59e0b";
    return "#ef4444";
  }

  function confClass(conf) {
    if (conf === "known") return "ok";
    if (conf === "prefix") return "warn";
    if (conf === "csv") return "info";
    return "cyan";
  }

  function switchTab(tabName) {
    state.tab = tabName;
    document.querySelectorAll(".tab-btn").forEach((b) => {
      b.classList.toggle("active", b.dataset.tab === tabName);
    });
    document.querySelectorAll(".tab-panel").forEach((p) => {
      p.classList.toggle("active", p.id === "panel-" + tabName);
    });
  }

  document.querySelectorAll(".tab-btn").forEach((b) => {
    b.addEventListener("click", () => switchTab(b.dataset.tab));
  });

  async function apiGet(url) {
    const res = await fetch(url, { cache: "no-store" });
    if (!res.ok) throw new Error(url + " HTTP " + res.status);
    return res.json();
  }

  async function apiPost(url, body) {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body || {})
    });
    return res.json();
  }

  function renderHeaderStatus(status, scan, zstdAvail) {
    const pill = document.getElementById("status-pill");
    const dot = document.getElementById("live-dot");
    const alive = Boolean(status && status.capture_alive);
    dot.classList.toggle("on", alive);
    const mode = (status && status.source_mode) || "IDLE";
    const detail = (status && status.source_detail) || "";
    const err = status && status.last_error;
    pill.textContent = err ? "ERR: " + err.slice(0, 36) : (detail ? mode + ": " + detail : mode);
    pill.className = "pill " + (err ? "err" : alive ? "ok" : (mode !== "IDLE" ? "info" : ""));

    const zPill = document.getElementById("zstd-pill");
    zPill.textContent = zstdAvail ? "Zstd: ready" : "Zstd: absent (0x10 skipped)";
    zPill.className = "pill " + (zstdAvail ? "ok" : "warn");

    const sPill = document.getElementById("scan-pill");
    if (scan && scan.scanning) {
      sPill.textContent = "Scanning " + (scan.done || 0) + "/" + (scan.total || 0);
      sPill.className = "pill info";
    } else {
      sPill.textContent = "Scan: ready";
      sPill.className = "pill";
    }
  }

  function renderOverview() {
    const ov = state.overview;
    if (!ov) return;
    document.getElementById("kpi-servers").textContent = String(ov.total_servers || 0);
    document.getElementById("kpi-matches").textContent = String(ov.total_matches || 0);
    document.getElementById("matches-count-pill").textContent = String(ov.total_matches || 0);

    const best = ov.best_server;
    document.getElementById("kpi-best-rtt").textContent = best ? fmtMs(best.rtt_ms) : "-";
    document.getElementById("kpi-best-sub").textContent = best ? (best.ip + " (" + best.provider + " / " + best.city + ")") : "No RTT samples yet";

    const st = ov.live_status || {};
    const activeSrv = st.active_server || "Idle";
    document.getElementById("kpi-active-srv").textContent = activeSrv;
    document.getElementById("kpi-active-sub").textContent = st.active_server
      ? ((st.phase || "IDLE") + " · " + (st.packets_processed || 0) + " pkts")
      : "Start live ADB or PCAP replay in Tab 2";

    renderHeaderStatus(st, ov.scan, ov.zstd_available);
  }

  function renderHubMap() {
    const svg = document.getElementById("hub-map-svg");
    const clusters = state.clusters || {};
    const origin = clusters.surabaya || { x: 430, y: 298, label: "Surabaya (You)" };

    const byCluster = {};
    for (const srv of state.servers) {
      const ck = srv.cluster_key || "europe_unknown";
      if (!byCluster[ck]) byCluster[ck] = { count: 0, servers: 0, rtts: [], providers: new Set() };
      byCluster[ck].count += srv.match_count || 0;
      byCluster[ck].servers += 1;
      if (typeof srv.effective_rtt_ms === "number") byCluster[ck].rtts.push(srv.effective_rtt_ms);
      if (srv.provider) byCluster[ck].providers.add(srv.provider);
    }

    let html = "";
    // Subtle background grid & range rings
    for (let x = 80; x < 800; x += 120) {
      html += `<line x1="${x}" y1="0" x2="${x}" y2="360" stroke="#1b2638" stroke-width="1"/>`;
    }
    for (let y = 60; y < 360; y += 75) {
      html += `<line x1="0" y1="${y}" x2="800" y2="${y}" stroke="#1b2638" stroke-width="1"/>`;
    }
    for (const r of [90, 180, 290]) {
      html += `<circle cx="${origin.x}" cy="${origin.y}" r="${r}" fill="none" stroke="#1d2b40" stroke-dasharray="4 5"/>`;
    }

    // Draw spokes and nodes for each cluster
    for (const [ck, c] of Object.entries(clusters)) {
      if (ck === "surabaya") continue;
      const stats = byCluster[ck];
      const active = Boolean(stats && stats.count > 0);
      const selected = state.selectedCluster === ck;
      const rtts = active ? stats.rtts.slice().sort((a, b) => a - b) : [];
      const medRtt = rtts.length ? rtts[Math.floor(rtts.length / 2)] : null;
      const color = active ? rttColor(medRtt) : "#475569";
      const radius = active ? Math.min(26, 10 + stats.count * 2.5) : 5;
      const opacity = active ? 1 : 0.35;

      if (active) {
        html += `<line x1="${origin.x}" y1="${origin.y}" x2="${c.x}" y2="${c.y}" stroke="${color}" stroke-opacity="0.42" stroke-width="${selected ? 2.6 : 1.5}" stroke-dasharray="5 4"/>`;
      }
      html += `<g class="cluster-node" data-cluster="${esc(ck)}" opacity="${opacity}">`;
      if (selected) {
        html += `<circle cx="${c.x}" cy="${c.y}" r="${radius + 6}" fill="none" stroke="#3b82f6" stroke-width="2.2"/>`;
      }
      html += `<circle cx="${c.x}" cy="${c.y}" r="${radius}" fill="${color}" fill-opacity="0.24" stroke="${color}" stroke-width="2"/>`;
      if (active) {
        html += `<text x="${c.x}" y="${c.y + 4}" text-anchor="middle" fill="#eef3fb" font-size="11" font-weight="700">${stats.count}</text>`;
      }
      const rttLabel = medRtt != null ? ` (${medRtt.toFixed(0)}ms)` : "";
      html += `<text x="${c.x}" y="${c.y + radius + 13}" text-anchor="middle" fill="${active ? "#cbd5e1" : "#64748b"}" font-size="10.5" font-weight="${active ? "600" : "400"}">${esc(c.label)}${esc(rttLabel)}</text>`;
      html += `</g>`;
    }

    // Home Surabaya pin
    html += `<g><polygon points="${origin.x},${origin.y - 8} ${origin.x + 8},${origin.y} ${origin.x},${origin.y + 8} ${origin.x - 8},${origin.y}" fill="#22d3ee" stroke="#0b0f16" stroke-width="1.5"/>`;
    html += `<text x="${origin.x}" y="${origin.y + 20}" text-anchor="middle" fill="#a5f3fc" font-size="11" font-weight="700">${esc(origin.label)}</text></g>`;

    svg.innerHTML = html;

    const tip = document.getElementById("map-tooltip");
    svg.querySelectorAll(".cluster-node").forEach((node) => {
      const ck = node.dataset.cluster;
      node.addEventListener("click", () => {
        state.selectedCluster = (state.selectedCluster === ck) ? null : ck;
        document.getElementById("clear-cluster-btn").style.display = state.selectedCluster ? "inline-flex" : "none";
        renderHubMap();
        renderServersTable();
      });
      node.addEventListener("mouseenter", (ev) => {
        const c = clusters[ck];
        const st = byCluster[ck];
        if (!c) return;
        let msg = `<strong>${esc(c.label)}</strong><br>`;
        if (st) {
          const med = st.rtts.length ? fmtMs(st.rtts.slice().sort((a,b)=>a-b)[Math.floor(st.rtts.length/2)]) : "no RTT";
          msg += `${st.servers} IP(s), ${st.count} match(es), med ${esc(med)}`;
        } else {
          msg += "No matches observed yet";
        }
        tip.innerHTML = msg;
        tip.style.display = "block";
        const rect = svg.getBoundingClientRect();
        tip.style.left = Math.min(rect.width - 180, Math.max(8, ev.clientX - rect.left + 12)) + "px";
        tip.style.top = Math.max(8, ev.clientY - rect.top - 14) + "px";
      });
      node.addEventListener("mouseleave", () => { tip.style.display = "none"; });
    });
  }

  function renderServersTable() {
    const tbody = document.getElementById("servers-tbody");
    const q = (document.getElementById("server-search").value || "").trim().toLowerCase();
    const { col, dir } = state.serverSort;

    let rows = state.servers.filter((s) => {
      if (state.selectedCluster && s.cluster_key !== state.selectedCluster) return false;
      if (!q) return true;
      return [s.ip, s.subnet, s.provider, s.city, (s.modes || []).join(" ")].some(
        (f) => String(f || "").toLowerCase().includes(q)
      );
    });

    rows.sort((a, b) => {
      const va = a[col];
      const vb = b[col];
      if (va == null && vb == null) return 0;
      if (va == null) return 1;
      if (vb == null) return -1;
      if (typeof va === "number" && typeof vb === "number") return (va - vb) * dir;
      return String(va).localeCompare(String(vb)) * dir;
    });

    const titleEl = document.getElementById("server-table-title");
    titleEl.textContent = state.selectedCluster && state.clusters[state.selectedCluster]
      ? "Visited Match Servers — " + state.clusters[state.selectedCluster].label
      : "Visited Match Servers (" + rows.length + ")";

    if (!rows.length) {
      tbody.innerHTML = `<tr><td colspan="10" class="empty-box">No visited servers match this filter.</td></tr>`;
      return;
    }

    tbody.innerHTML = rows.map((s) => {
      const dispTxt = s.displayed_ping_median_ms != null ? fmtMs(s.displayed_ping_median_ms) : "-";
      const modesTxt = (s.modes && s.modes.length) ? s.modes.join(", ") : "-";
      return `<tr class="clickable" data-ip="${esc(s.ip)}">
        <td class="mono">${esc(s.ip)}</td>
        <td class="mono">${esc(s.subnet)}</td>
        <td>${esc(s.provider)}</td>
        <td>${esc(s.city)}</td>
        <td><span class="pill ${confClass(s.confidence)}">${esc(s.confidence)}</span></td>
        <td><strong>${s.match_count}</strong></td>
        <td class="mono">${esc(fmtMs(s.wifi_median_ms))}</td>
        <td class="mono">${esc(fmtMs(s.cell_median_ms))}</td>
        <td class="mono">${esc(dispTxt)}</td>
        <td>${esc(modesTxt)}</td>
      </tr>`;
    }).join("");

    tbody.querySelectorAll("tr.clickable").forEach((tr) => {
      tr.addEventListener("click", () => {
        document.getElementById("matches-search").value = tr.dataset.ip || "";
        renderMatchesTable();
        switchTab("matches");
      });
    });
  }

  function renderLive() {
    const live = state.live;
    if (!live) return;
    if (live.status) renderHeaderStatus(live.status, state.overview ? state.overview.scan : null, state.overview ? state.overview.zstd_available : true);

    const stages = live.pipeline_stages || [];
    const totalPkts = (live.status && live.status.packets_processed) || 0;
    document.getElementById("live-packets-total").textContent = totalPkts.toLocaleString() + " packets";

    document.getElementById("pipeline-strip").innerHTML = stages.map((st) => `
      <div class="stage-chip ${st.active ? "lit" : ""}">
        <div class="stage-name">${esc(st.label)}</div>
        <div class="stage-cnt">${Number(st.packets || 0).toLocaleString()} pkts · ${((st.bytes || 0) / 1024).toFixed(1)} KB</div>
      </div>
    `).join("");

    const mp = live.multipath || {};
    const wp = mp.wifi_pct || 0;
    const cp = mp.cell_pct || 0;
    const op = Math.max(0, 100 - wp - cp);
    document.getElementById("split-wifi").style.width = wp + "%";
    document.getElementById("split-cell").style.width = cp + "%";
    document.getElementById("split-other").style.width = op + "%";
    document.getElementById("multipath-readout").innerHTML = `
      <span class="pill cyan">Wi-Fi: ${Number(mp.wifi_pkts || 0).toLocaleString()} (${wp}%)</span>
      <span class="pill warn">Cellular: ${Number(mp.cell_pkts || 0).toLocaleString()} (${cp}%)</span>
      <span class="pill">Out/In W: ${mp.wifi_out_pkts || 0}/${mp.wifi_in_pkts || 0} · C: ${mp.cell_out_pkts || 0}/${mp.cell_in_pkts || 0}</span>
    `;

    const ep = live.active_endpoint;
    const epPill = document.getElementById("live-active-ep");
    if (ep) {
      const locTxt = ep.city && ep.city.startsWith(ep.provider) ? ep.city : `${ep.provider} (${ep.city})`;
      epPill.textContent = `${ep.ep} · ${locTxt}`;
    } else {
      epPill.textContent = "No active match";
    }

    const links = (live.rtt && live.rtt.links) || {};
    const statParts = [];
    for (const name of ["Wi-Fi", "Cellular", "Combined"]) {
      const b = links[name];
      if (!b || !b.sample_count) continue;
      const cls = name === "Wi-Fi" ? "cyan" : (name === "Cellular" ? "warn" : "info");
      statParts.push(`<span class="pill ${cls}">${name}: n=${b.sample_count}, med=${fmtMs(b.median_ms)}, p95=${fmtMs(b.p95_ms)}, jit=${fmtMs(b.jitter_ms)}</span>`);
    }
    document.getElementById("live-rtt-stats").innerHTML = statParts.join("") || `<span class="pill">Waiting for 0x3f5 ping echoes...</span>`;

    const ls = live.lobby_stats || {};
    const hoCount = (live.handovers || []).length;
    const probeCount = (live.probes || []).length;
    document.getElementById("live-lobby-readout").textContent =
      `:30101 frames raw=${ls.raw_frames || 0} zstd=${ls.zstd_frames || 0} (skipped=${ls.skipped_zstd_frames || 0}, dropped mid=10208=${ls.dropped_pii_frames || 0}) · handovers=${hoCount} · geo cards=${ls.geo_player_count || 0} · :30190 targets=${probeCount}`;

    renderSparkline();
    renderFeed();
  }

  function renderSparkline() {
    const svg = document.getElementById("rtt-spark-svg");
    const baseSeries = (state.live && state.live.rtt && state.live.rtt.series) || [];
    const merged = baseSeries.length ? baseSeries : state.liveRttPoints;
    const w = 640, h = 170, padL = 42, padR = 14, padT = 14, padB = 22;

    if (!merged.length) {
      svg.innerHTML = `<text x="320" y="90" text-anchor="middle" fill="#64748b" font-size="12">No 0x3f5 RTT samples in active session</text>`;
      return;
    }

    const wifiPts = merged.filter((p) => p.link === "Wi-Fi");
    const cellPts = merged.filter((p) => p.link === "Cellular");
    const minT = merged[0].rel_s;
    const maxT = Math.max(minT + 1, merged[merged.length - 1].rel_s);
    const maxRtt = Math.max(60, Math.min(350, ...merged.map((p) => p.rtt_ms || 0)) * 1.15);

    const xOf = (t) => padL + ((t - minT) / (maxT - minT)) * (w - padL - padR);
    const yOf = (ms) => h - padB - (Math.min(maxRtt, Math.max(0, ms)) / maxRtt) * (h - padT - padB);

    let out = "";
    for (const ref of [25, 50, 100, 150]) {
      if (ref > maxRtt) continue;
      const y = yOf(ref);
      out += `<line x1="${padL}" y1="${y.toFixed(1)}" x2="${w - padR}" y2="${y.toFixed(1)}" stroke="#1e293b" stroke-dasharray="3 4"/>`;
      out += `<text x="6" y="${(y + 4).toFixed(1)}" fill="#64748b" font-size="10">${ref}ms</text>`;
    }

    function poly(pts, stroke) {
      if (!pts.length) return "";
      const coords = pts.map((p) => `${xOf(p.rel_s).toFixed(1)},${yOf(p.rtt_ms).toFixed(1)}`).join(" ");
      return `<polyline fill="none" stroke="${stroke}" stroke-width="1.8" points="${coords}"/>`;
    }
    out += poly(wifiPts, "#22d3ee");
    out += poly(cellPts, "#f59e0b");
    out += `<text x="${padL}" y="${h - 6}" fill="#64748b" font-size="10">+${minT.toFixed(0)}s</text>`;
    out += `<text x="${w - padR}" y="${h - 6}" text-anchor="end" fill="#64748b" font-size="10">+${maxT.toFixed(0)}s</text>`;
    svg.innerHTML = out;
  }

  function renderFeed() {
    const box = document.getElementById("packet-feed-box");
    const q = (document.getElementById("feed-search").value || "").trim().toLowerCase();
    const lane = state.laneFilter;
    const rows = state.feedItems.filter((item) => {
      if (lane !== "ALL" && item.lane !== lane) return false;
      if (!q) return true;
      return [item.lane, item.summary, item.rule_matched, item.remote, item.link].some(
        (x) => String(x || "").toLowerCase().includes(q)
      );
    });

    if (!rows.length) {
      box.innerHTML = `<div class="empty-box">No packet detections match the current filter.</div>`;
      return;
    }

    const laneBadge = (ln) => {
      if (ln === "PING_ECHO") return "cyan";
      if (ln === "LOBBY_TCP") return "info";
      if (ln === "PROBE_30190") return "warn";
      if (ln === "TCP_MIRROR") return "ok";
      return "";
    };

    box.innerHTML = rows.slice(-250).map((it) => `
      <div class="feed-row">
        <span class="mono" style="color:var(--muted);">+${Number(it.rel_s || 0).toFixed(2)}s</span>
        <span><span class="pill ${laneBadge(it.lane)}" style="padding:2px 7px;font-size:10.5px;">${esc(it.lane)}</span></span>
        <span><span class="pill" style="padding:2px 7px;font-size:10.5px;">${esc(it.link)}</span></span>
        <span class="mono" style="color:var(--muted);">${esc(it.rule_matched)}</span>
        <span class="mono">${esc(it.remote)}</span>
        <span>${esc(it.summary)}</span>
      </div>
    `).join("");

    if (document.getElementById("feed-autoscroll").checked) {
      box.scrollTop = box.scrollHeight;
    }
  }

  function renderPartyTab() {
    const sel = document.getElementById("party-match-select");
    const matches = state.matches;
    if (!matches.length) {
      sel.innerHTML = `<option value="">No matches available yet</option>`;
      document.getElementById("selected-match-meta").innerHTML = "";
      document.getElementById("ally-party-list").innerHTML = `<div class="empty-box">No match decoded yet.</div>`;
      document.getElementById("enemy-camp-summary").textContent = "-";
      document.getElementById("selected-server-box").textContent = "-";
    } else {
      if (!state.selectedMatchKey || !matches.some((m) => m.match_key === state.selectedMatchKey)) {
        const withRoster = matches.find((m) => (m.players && m.players.length > 0) || (m.ally_party_players && m.ally_party_players.length > 0));
        state.selectedMatchKey = (withRoster || matches[0]).match_key;
      }
      sel.innerHTML = matches.map((m) => {
        const lbl = `${fmtTs(m.first_ts)} · ${m.mode_label || m.origin} · ${m.party_mix_label || "-"} -> ${m.server_ip}:${m.server_port} (${m.city})`;
        return `<option value="${esc(m.match_key)}" ${m.match_key === state.selectedMatchKey ? "selected" : ""}>${esc(lbl)}</option>`;
      }).join("");

      const m = matches.find((x) => x.match_key === state.selectedMatchKey) || matches[0];
      const meta = [
        `<span class="pill info">${esc(m.mode_label || m.origin)}</span>`,
        `<span class="pill cyan">${esc(m.party_mix_label || m.party_label || "Unknown")}</span>`,
        m.host ? `<span class="pill ok">Host: ${esc(m.host)}</span>` : `<span class="pill">Host: Unspecified</span>`,
        m.battle_id ? `<span class="pill mono">BID ${esc(m.battle_id)}</span>` : ""
      ].join("");
      document.getElementById("selected-match-meta").innerHTML = meta;

      const allies = (m.ally_party_players && m.ally_party_players.length)
        ? m.ally_party_players
        : (m.players || []).filter((p) => p.camp === (m.local_camp || 1));

      document.getElementById("ally-party-list").innerHTML = allies.length
        ? allies.map((p) => `
          <div class="player-row">
            <strong>${esc(p.name || ("uid:" + p.uid))}</strong>
            ${p.is_local ? `<span class="pill cyan">YOU</span>` : ""}
            ${p.hero_name ? `<span class="pill warn">${esc(p.hero_name)}</span>` : ""}
            ${p.country ? `<span class="pill info">${esc(p.country)}</span>` : ""}
            ${p.zone_id ? `<span class="pill mono">z${esc(p.zone_id)}</span>` : ""}
            ${p.lobby_geo ? `<span class="pill ok">${esc(p.lobby_geo)}</span>` : ""}
            ${p.is_bot ? `<span class="pill err">BOT</span>` : ""}
          </div>
        `).join("")
        : `<div class="empty-box">${esc(m.csv_party || "No KCP player roster in this record")}</div>`;

      const enemies = (m.players || []).filter((p) => p.camp && p.camp !== (m.local_camp || 1));
      const stackTxt = (m.enemy_stack_sizes && m.enemy_stack_sizes.length)
        ? "Stacks: " + m.enemy_stack_sizes.map((s) => s + "q").join(" + ")
        : "";
      const enemyNames = enemies.map((p) => `${p.name || p.uid}${p.country ? " [" + p.country + "]" : ""}${p.is_bot ? " (BOT)" : ""}`).join(", ");
      document.getElementById("enemy-camp-summary").textContent = enemies.length
        ? `${enemies.length} players (${stackTxt}) — ${enemyNames}`
        : "No enemy camp roster recorded.";

      const links = (m.rtt && m.rtt.links) || {};
      const w = links["Wi-Fi"] || {};
      const c = links["Cellular"] || {};
      const mir = m.tcp_mirror;
      const ho = m.handover;
      document.getElementById("selected-server-box").innerHTML = `
        <div><strong>Server:</strong> <span class="mono">${esc(m.server_ip)}:${esc(m.server_port)}</span> (${esc(m.subnet)})</div>
        <div><strong>Classification:</strong> ${esc(m.provider)} / ${esc(m.city)} <span class="pill ${confClass(m.confidence)}">${esc(m.confidence)}</span></div>
        <div><strong>Wi-Fi RTT:</strong> ${esc(fmtMs(w.median_ms))} (n=${w.sample_count || 0}, jit=${esc(fmtMs(w.jitter_ms))}) · <strong>Cell RTT:</strong> ${esc(fmtMs(c.median_ms))} (n=${c.sample_count || 0})</div>
        <div><strong>Handover (:30101):</strong> ${ho ? esc(ho.target_ep + " via " + ho.gateway_ip) : "not captured"}</div>
        <div><strong>TCP Input Mirror:</strong> ${mir ? esc(":" + mir.port + " (" + mir.pkts + " pkts)") : "none"} · <strong>:30190 Probes:</strong> ${m.probe_count || 0} target(s)</div>
      `;

      document.getElementById("note-host-input").value = m.host || "";
      document.getElementById("note-ping-input").value = m.displayed_ping_ms != null ? String(m.displayed_ping_ms) : "";
      document.getElementById("note-text-input").value = m.note || "";
    }

    // Correlations table
    const corr = state.correlations || {};
    const basePill = document.getElementById("corr-baseline-pill");
    basePill.textContent = (corr.baseline_label || "Baseline") + ": " + fmtMs(corr.baseline_ms);

    const ctbody = document.getElementById("corr-tbody");
    const groups = corr.groups || [];
    if (!groups.length) {
      ctbody.innerHTML = `<tr><td colspan="9" class="empty-box">No correlation groups yet.</td></tr>`;
      return;
    }
    ctbody.innerHTML = groups.map((g) => {
      const srvs = (g.servers || []).map((s) => `${s.ip} (${s.city}, ${s.count}x)`).join("; ");
      const d = g.delta_vs_baseline_ms;
      const dTxt = typeof d === "number" ? ((d >= 0 ? "+" : "") + d.toFixed(1) + " ms") : "-";
      const dCls = typeof d === "number" ? (d > 8 ? "err" : (d < -3 ? "ok" : "info")) : "";
      return `<tr>
        <td>${esc(g.mode)}</td>
        <td>${esc(g.party_mix)}</td>
        <td><strong>${esc(g.host)}</strong></td>
        <td>${g.match_count}</td>
        <td class="mono" style="font-size:11.5px;">${esc(srvs)}</td>
        <td class="mono">${esc(fmtMs(g.median_udp_rtt_ms))}</td>
        <td class="mono">${esc(fmtMs(g.median_displayed_ping_ms))}</td>
        <td><span class="pill ${dCls}">${esc(dTxt)}</span></td>
        <td>${g.max_probe_targets || 0}</td>
      </tr>`;
    }).join("");
  }

  function renderMatchesTable() {
    const tbody = document.getElementById("matches-tbody");
    const q = (document.getElementById("matches-search").value || "").trim().toLowerCase();
    const orig = state.originFilter;

    const rows = state.matches.filter((m) => {
      if (orig !== "ALL" && m.origin !== orig) return false;
      if (!q) return true;
      const pNames = (m.players || []).map((p) => p.name || "").join(" ");
      return [m.server_ip, m.provider, m.city, m.mode_label, m.party_mix_label, m.host, m.source_name, m.note, pNames].some(
        (f) => String(f || "").toLowerCase().includes(q)
      );
    });

    if (!rows.length) {
      tbody.innerHTML = `<tr><td colspan="10" class="empty-box">No matches found.</td></tr>`;
      return;
    }

    tbody.innerHTML = rows.map((m) => {
      const links = (m.rtt && m.rtt.links) || {};
      const wMed = links["Wi-Fi"] && links["Wi-Fi"].median_ms;
      const cMed = links["Cellular"] && links["Cellular"].median_ms;
      const mirTxt = m.tcp_mirror ? ":" + m.tcp_mirror.port : "-";
      return `<tr class="clickable" data-key="${esc(m.match_key)}">
        <td class="mono">${esc(fmtTs(m.first_ts))}</td>
        <td><span class="pill ${m.origin === "live" ? "ok" : (m.origin === "csv" ? "info" : "")}">${esc(m.origin)}</span> ${esc(m.source_name)}</td>
        <td>${esc(m.mode_label || "-")}</td>
        <td>${esc(m.party_mix_label || "-")}</td>
        <td>${esc(m.host || "-")}</td>
        <td><span class="mono">${esc(m.server_ip)}:${esc(m.server_port)}</span><br><span style="color:var(--muted);font-size:11px;">${esc(m.provider)} · ${esc(m.city)}</span></td>
        <td class="mono">${esc(fmtMs(wMed))} / ${esc(fmtMs(cMed))}</td>
        <td class="mono">${esc(fmtMs(m.displayed_ping_ms))}</td>
        <td class="mono">${esc(mirTxt)} / ${m.probe_count || 0}p</td>
        <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${esc(m.note || "")}</td>
      </tr>`;
    }).join("");

    tbody.querySelectorAll("tr.clickable").forEach((tr) => {
      tr.addEventListener("click", () => {
        state.selectedMatchKey = tr.dataset.key;
        renderPartyTab();
        switchTab("party");
      });
    });
  }

  async function refreshAllData() {
    const seqAtStart = state.liveSeq;
    try {
      const [ov, srv, ms, corr, live] = await Promise.all([
        apiGet("/api/overview"),
        apiGet("/api/servers"),
        apiGet("/api/matches"),
        apiGet("/api/correlations"),
        apiGet("/api/live/packets")
      ]);
      state.overview = ov;
      state.servers = srv.servers || [];
      state.clusters = srv.clusters || {};
      state.matches = ms.matches || [];
      state.correlations = corr;
      if (state.liveSeq === seqAtStart) {
        state.live = live;
        if (live && Array.isArray(live.feed) && (live.feed.length > 0 || state.feedItems.length === 0)) {
          state.feedItems = live.feed;
        }
        renderLive();
      }
      renderOverview();
      renderHubMap();
      renderServersTable();
      renderPartyTab();
      renderMatchesTable();
    } catch (_err) {
      // Errors surface in status pill without noisy console errors
    }
  }

  async function refreshSources() {
    try {
      const [pcaps, devs] = await Promise.all([apiGet("/api/pcaps"), apiGet("/api/devices")]);
      const pSel = document.getElementById("pcap-select");
      const curP = pSel.value;
      const pList = pcaps.pcaps || [];
      pSel.innerHTML = pList.length
        ? pList.map((p) => `<option value="${esc(p.path)}">${esc(p.name)} (${(p.size_bytes / 1048576).toFixed(1)} MB)</option>`).join("")
        : `<option value="">No .pcap files in captures/</option>`;
      if (curP && pList.some((p) => p.path === curP)) pSel.value = curP;

      const dSel = document.getElementById("adb-select");
      const dList = devs.devices || [];
      dSel.innerHTML = dList.length
        ? dList.map((d) => `<option value="${esc(d.serial)}">${esc(d.serial)} (${esc(d.model || d.state)})</option>`).join("")
        : `<option value="">No ADB devices</option>`;
    } catch (_err) {
      // Ignore transient startup refresh error
    }
  }

  // Event listeners
  document.querySelectorAll("th.sortable").forEach((th) => {
    th.addEventListener("click", () => {
      const col = th.dataset.sort;
      if (state.serverSort.col === col) {
        state.serverSort.dir *= -1;
      } else {
        state.serverSort = { col, dir: col === "ip" || col === "city" || col === "provider" ? 1 : -1 };
      }
      renderServersTable();
    });
  });

  document.getElementById("server-search").addEventListener("input", renderServersTable);
  document.getElementById("clear-cluster-btn").addEventListener("click", () => {
    state.selectedCluster = null;
    document.getElementById("clear-cluster-btn").style.display = "none";
    renderHubMap();
    renderServersTable();
  });

  document.getElementById("rescan-btn").addEventListener("click", async () => {
    await apiPost("/api/rescan", { force: true });
    await refreshAllData();
  });

  document.getElementById("refresh-devices-btn").addEventListener("click", refreshSources);

  function showSourceError(msg) {
    const el = document.getElementById("source-err");
    if (!msg) {
      el.style.display = "none";
      el.textContent = "";
    } else {
      el.style.display = "inline-flex";
      el.textContent = msg;
    }
  }

  document.getElementById("start-pcap-btn").addEventListener("click", async () => {
    const path = document.getElementById("pcap-select").value;
    const follow = document.getElementById("pcap-follow-chk").checked;
    if (!path) { showSourceError("Select a .pcap file"); return; }
    showSourceError("");
    state.liveSeq += 1;
    state.feedItems = [];
    state.liveRttPoints = [];
    const res = await apiPost("/api/source", { mode: "pcap", path, follow });
    if (res.error) showSourceError(res.error);
  });

  document.getElementById("start-adb-btn").addEventListener("click", async () => {
    const serial = document.getElementById("adb-select").value;
    const tee = document.getElementById("adb-tee-chk").checked;
    if (!serial) { showSourceError("No ADB device selected"); return; }
    showSourceError("");
    state.liveSeq += 1;
    state.feedItems = [];
    state.liveRttPoints = [];
    const res = await apiPost("/api/source", { mode: "adb", serial, tee });
    if (res.error) showSourceError(res.error);
  });

  document.getElementById("stop-source-btn").addEventListener("click", async () => {
    showSourceError("");
    state.liveSeq += 1;
    await apiPost("/api/source", { mode: "stop" });
    await refreshAllData();
  });

  document.querySelectorAll("#lane-filters .f-pill").forEach((btn) => {
    btn.addEventListener("click", () => {
      state.laneFilter = btn.dataset.lane;
      document.querySelectorAll("#lane-filters .f-pill").forEach((b) => b.classList.toggle("active", b === btn));
      renderFeed();
    });
  });
  document.getElementById("feed-search").addEventListener("input", renderFeed);

  document.querySelectorAll("#origin-filters .f-pill").forEach((btn) => {
    btn.addEventListener("click", () => {
      state.originFilter = btn.dataset.origin;
      document.querySelectorAll("#origin-filters .f-pill").forEach((b) => b.classList.toggle("active", b === btn));
      renderMatchesTable();
    });
  });
  document.getElementById("matches-search").addEventListener("input", renderMatchesTable);

  document.getElementById("party-match-select").addEventListener("change", (ev) => {
    state.selectedMatchKey = ev.target.value;
    renderPartyTab();
  });

  document.querySelectorAll(".host-preset").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.getElementById("note-host-input").value = btn.dataset.host || "";
    });
  });

  document.getElementById("notes-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    if (!state.selectedMatchKey) return;
    const host = document.getElementById("note-host-input").value;
    const rawPing = document.getElementById("note-ping-input").value;
    const note = document.getElementById("note-text-input").value;
    const res = await apiPost("/api/notes", {
      match_key: state.selectedMatchKey,
      host,
      displayed_ping_ms: rawPing === "" ? null : Number(rawPing),
      note
    });
    const st = document.getElementById("note-save-status");
    st.style.display = "inline-flex";
    if (res.ok) {
      st.className = "pill ok";
      st.textContent = "Saved";
      await refreshAllData();
    } else {
      st.className = "pill err";
      st.textContent = res.error || "Failed";
    }
  });

  function connectSse() {
    const es = new EventSource("/events");
    es.addEventListener("snapshot", (ev) => {
      try {
        const d = JSON.parse(ev.data);
        if (d.overview) state.overview = d.overview;
        if (d.live) {
          state.live = d.live;
          state.feedItems = d.live.feed || [];
          renderLive();
        }
        renderOverview();
      } catch (_e) {}
    });
    es.addEventListener("status", (ev) => {
      try {
        const st = JSON.parse(ev.data);
        if (state.overview) state.overview.live_status = st;
        if (state.live) state.live.status = st;
        renderOverview();
      } catch (_e) {}
    });
    es.addEventListener("packet_batch", (ev) => {
      try {
        const d = JSON.parse(ev.data);
        const items = d.items || [];
        if (items.length) {
          state.liveSeq += 1;
          state.feedItems = state.feedItems.concat(items).slice(-400);
          renderFeed();
        }
      } catch (_e) {}
    });
    es.addEventListener("rtt_point", (ev) => {
      try {
        const d = JSON.parse(ev.data);
        const pts = d.points || [];
        if (pts.length) {
          state.liveSeq += 1;
          state.liveRttPoints = state.liveRttPoints.concat(pts).slice(-360);
          renderSparkline();
        }
      } catch (_e) {}
    });
    es.addEventListener("match_update", async () => {
      const seq = ++state.liveSeq;
      try {
        const live = await apiGet("/api/live/packets");
        if (state.liveSeq !== seq) return;
        state.live = live;
        if (live && Array.isArray(live.feed) && live.feed.length > 0) {
          state.feedItems = live.feed;
        }
        renderLive();
      } catch (_e) {}
    });
    es.addEventListener("history_updated", () => {
      refreshAllData();
    });
  }

  refreshAllData();
  refreshSources();
  connectSse();
})();
</script>
</body>
</html>
"""
