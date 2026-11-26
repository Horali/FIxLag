"""Self-contained single-page HTML/CSS/JS viewer UI with Live & Past Games modes."""

INDEX_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>MLBB Passive Chat Viewer</title>
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
    --blue-bg: rgba(59, 130, 246, 0.12);
    --cyan: #22d3ee;
    --cyan-bg: rgba(34, 211, 238, 0.13);
    --red: #ef4444;
    --red-bg: rgba(239, 68, 68, 0.13);
    --red-strong: rgba(239, 68, 68, 0.25);
    --green: #22c55e;
    --green-bg: rgba(34, 197, 94, 0.14);
    --amber: #f59e0b;
    --amber-bg: rgba(245, 158, 11, 0.14);
    --slate-bg: rgba(148, 163, 184, 0.10);
  }
  * { box-sizing: border-box; }
  html, body {
    margin: 0; padding: 0; height: 100%;
    background: var(--bg); color: var(--text);
    font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
    font-size: 14px;
    -webkit-font-smoothing: antialiased;
  }
  body { display: flex; flex-direction: column; overflow: hidden; }
  button, input, select {
    font-family: inherit; font-size: 13px; color: var(--text);
    background: var(--panel-2); border: 1px solid var(--border);
    border-radius: 8px; outline: none;
  }
  button { cursor: pointer; padding: 7px 12px; font-weight: 600; transition: background 0.15s, border-color 0.15s; }
  button:hover { background: var(--panel-hover); border-color: #3c4e6b; }
  button.primary { background: #2563eb; border-color: #3b82f6; color: #fff; }
  button.primary:hover { background: #1d4ed8; }
  button.danger { background: #991b1b; border-color: #dc2626; color: #fff; }
  button.danger:hover { background: #b91c1c; }
  button.ghost { background: transparent; border-color: transparent; color: var(--muted); padding: 5px 8px; }
  button.ghost:hover { background: var(--panel-2); color: var(--text); }
  input[type="text"], select { padding: 7px 10px; }
  input[type="text"]:focus, select:focus { border-color: var(--blue); }

  /* Top Bar */
  .topbar {
    height: 54px; flex-shrink: 0;
    background: var(--panel); border-bottom: 1px solid var(--border);
    padding: 0 16px; display: flex; align-items: center; gap: 14px;
    position: relative; z-index: 30;
  }
  .brand { display: flex; align-items: center; gap: 8px; font-weight: 700; font-size: 15px; letter-spacing: 0.2px; }
  .brand-dot {
    width: 26px; height: 26px; border-radius: 7px;
    background: linear-gradient(135deg, #2563eb, #06b6d4);
    display: grid; place-items: center; font-size: 14px; font-weight: 800; color: #fff;
  }
  .tabs {
    display: inline-flex; background: var(--bg); padding: 3px; border-radius: 10px;
    border: 1px solid var(--border); gap: 2px;
  }
  .tab-btn {
    background: transparent; border: none; border-radius: 7px; padding: 5px 12px;
    font-size: 13px; font-weight: 600; color: var(--muted);
    display: inline-flex; align-items: center; gap: 6px;
  }
  .tab-btn:hover { color: var(--text); background: rgba(255,255,255,0.04); }
  .tab-btn.active { background: var(--panel-2); color: var(--text); box-shadow: 0 1px 3px rgba(0,0,0,0.3); }
  .live-dot { width: 7px; height: 7px; border-radius: 50%; background: var(--muted); }
  .live-dot.on { background: var(--green); box-shadow: 0 0 8px var(--green); }
  .count-pill {
    font-size: 11px; padding: 1px 6px; border-radius: 999px;
    background: rgba(59, 130, 246, 0.2); color: #93c5fd;
  }
  .spacer { flex: 1; }
  .status-pill {
    display: inline-flex; align-items: center; gap: 7px;
    padding: 5px 11px; border-radius: 999px; font-size: 12px; font-weight: 600;
    background: var(--panel-2); border: 1px solid var(--border); color: var(--muted);
  }
  .status-pill.ok { background: var(--green-bg); border-color: rgba(34, 197, 94, 0.45); color: #86efac; }
  .status-pill.warn { background: var(--amber-bg); border-color: rgba(245, 158, 11, 0.5); color: #fde68a; }
  .status-pill.err { background: var(--red-bg); border-color: rgba(239, 68, 68, 0.5); color: #fca5a5; }
  .status-pill.info { background: var(--blue-bg); border-color: rgba(59, 130, 246, 0.45); color: #93c5fd; }

  /* Diagnostics Popover */
  .diag-pop {
    display: none; position: absolute; right: 16px; top: 58px; width: 340px;
    background: var(--panel); border: 1px solid var(--border); border-radius: 12px;
    box-shadow: 0 16px 40px rgba(0,0,0,0.55); padding: 14px; z-index: 50;
  }
  .diag-pop.open { display: block; }
  .diag-title { font-size: 12px; font-weight: 700; text-transform: uppercase; color: var(--muted); margin-bottom: 8px; letter-spacing: 0.5px; }
  .diag-grid { display: grid; grid-template-columns: 125px 1fr; gap: 5px 8px; font-size: 12px; margin-bottom: 12px; }
  .diag-k { color: var(--muted); }
  .diag-v { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; word-break: break-all; }
  .diag-divider { border-top: 1px solid var(--border); margin: 10px 0; }
  .diag-pcap { display: flex; flex-direction: column; gap: 8px; }

  /* Layout */
  .workspace { flex: 1; display: flex; min-height: 0; }
  .sidebar {
    width: 330px; flex-shrink: 0; background: var(--panel); border-right: 1px solid var(--border);
    display: flex; flex-direction: column; min-height: 0;
  }
  .sidebar-section { padding: 14px; display: flex; flex-direction: column; gap: 10px; min-height: 0; flex: 1; }
  .card {
    background: var(--panel-2); border: 1px solid var(--border); border-radius: 11px;
    padding: 12px; display: flex; flex-direction: column; gap: 10px;
  }
  .card-title { font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; color: var(--muted); }
  .row { display: flex; align-items: center; gap: 8px; }
  .chk { display: inline-flex; align-items: center; gap: 6px; font-size: 12px; color: var(--muted); cursor: pointer; user-select: none; }
  .hint { font-size: 12px; color: var(--muted); line-height: 1.4; }
  .err-box {
    display: none; background: var(--red-bg); border: 1px solid rgba(239,68,68,0.45);
    color: #fecaca; border-radius: 8px; padding: 8px 10px; font-size: 12px; line-height: 1.4;
  }

  /* Past Games List */
  .seg-small { display: flex; gap: 4px; }
  .pill-btn {
    background: var(--panel-2); border: 1px solid var(--border); border-radius: 999px;
    padding: 4px 10px; font-size: 12px; font-weight: 600; color: var(--muted);
  }
  .pill-btn:hover { color: var(--text); }
  .pill-btn.active { background: var(--blue-bg); border-color: var(--blue); color: #bfdbfe; }
  .pill-btn.danger-active { background: var(--red-strong); border-color: var(--red); color: #fecaca; }

  .scan-bar {
    display: none; flex-direction: column; gap: 5px;
    background: var(--panel-2); border: 1px solid var(--border); border-radius: 8px; padding: 8px 10px;
    font-size: 11px; color: var(--muted);
  }
  .scan-track { height: 4px; border-radius: 99px; background: var(--bg); overflow: hidden; }
  .scan-fill { height: 100%; width: 0%; background: var(--blue); transition: width 0.2s; }

  .games-list { flex: 1; overflow-y: auto; display: flex; flex-direction: column; gap: 8px; padding-right: 2px; }
  .game-card {
    text-align: left; width: 100%; background: var(--panel-2); border: 1px solid var(--border);
    border-radius: 10px; padding: 10px 11px; display: flex; flex-direction: column; gap: 5px;
  }
  .game-card:hover { background: var(--panel-hover); border-color: #3d5070; }
  .game-card.active { border-color: var(--blue); background: rgba(59, 130, 246, 0.14); }
  .game-top { display: flex; align-items: center; gap: 6px; font-size: 11px; color: var(--muted); }
  .origin-tag {
    font-size: 10px; font-weight: 700; padding: 1px 6px; border-radius: 5px;
    background: rgba(255,255,255,0.06); color: var(--muted); max-width: 150px;
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  }
  .origin-tag.live { background: var(--green-bg); color: #86efac; }
  .game-title { font-weight: 700; font-size: 13px; color: var(--text); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .game-badges { display: flex; flex-wrap: wrap; gap: 5px; align-items: center; }
  .mini-badge { font-size: 11px; padding: 1px 7px; border-radius: 999px; background: rgba(255,255,255,0.06); color: var(--muted); }
  .mini-badge.enemy-team { background: var(--red-strong); color: #fecaca; font-weight: 700; }
  .mini-badge.gap { background: var(--amber-bg); color: #fde68a; }
  .game-preview { font-size: 12px; color: var(--muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .del-btn { margin-left: auto; background: transparent; border: none; color: var(--muted); padding: 2px 5px; font-size: 12px; border-radius: 5px; }
  .del-btn:hover { background: var(--red-bg); color: #fca5a5; }

  /* Main Chat Area */
  .main { flex: 1; display: flex; flex-direction: column; min-width: 0; min-height: 0; position: relative; }
  .match-header {
    background: var(--panel); border-bottom: 1px solid var(--border);
    padding: 12px 18px; display: flex; flex-direction: column; gap: 10px; flex-shrink: 0;
  }
  .mh-top { display: flex; flex-wrap: wrap; align-items: center; gap: 10px; }
  .mh-title { font-size: 16px; font-weight: 700; }
  .mh-sub { font-size: 12px; color: var(--muted); }
  .roster-bar { display: flex; flex-wrap: wrap; gap: 6px 14px; align-items: center; font-size: 12px; }
  .team-group { display: flex; flex-wrap: wrap; align-items: center; gap: 4px; }
  .team-lbl { font-size: 11px; font-weight: 700; text-transform: uppercase; margin-right: 2px; }
  .team-lbl.ally { color: #93c5fd; }
  .team-lbl.enemy { color: #fca5a5; }
  .player-chip {
    padding: 2px 8px; border-radius: 999px; font-size: 11.5px;
    background: var(--blue-bg); border: 1px solid rgba(59,130,246,0.3); color: #dbeafe;
  }
  .player-chip.you { background: var(--cyan-bg); border-color: rgba(34,211,238,0.5); color: #cffafe; font-weight: 700; }
  .player-chip.enemy { background: var(--red-bg); border: 1px solid rgba(239,68,68,0.35); color: #fee2e2; }

  .chip-hero { color: #fde68a; font-weight: 600; opacity: 0.95; }
  .chip-cc { font-size: 10px; font-weight: 700; opacity: 0.78; margin-left: 5px; letter-spacing: 0.4px; }
  .chip-bot {
    font-size: 9.5px; font-weight: 700; padding: 0 4px; border-radius: 4px; margin-left: 5px;
    background: var(--amber-bg); border: 1px solid rgba(245,158,11,0.4); color: #fde68a;
  }
  .mini-badge.mode { background: var(--blue-bg); color: #bfdbfe; }

  .filters-row { display: flex; flex-wrap: wrap; align-items: center; gap: 6px; }
  .filter-sep { width: 1px; height: 20px; background: var(--border); margin: 0 4px; }

  .feed {
    flex: 1; overflow-y: auto; padding: 16px 18px 34px;
    display: flex; flex-direction: column; gap: 8px;
  }
  .empty-state {
    margin: auto; max-width: 420px; text-align: center;
    background: var(--panel); border: 1px solid var(--border); border-radius: 14px;
    padding: 26px 24px; display: flex; flex-direction: column; gap: 10px; align-items: center;
  }
  .empty-title { font-size: 16px; font-weight: 700; }
  .empty-desc { font-size: 13px; color: var(--muted); line-height: 1.5; }

  .phase-divider {
    display: flex; align-items: center; gap: 10px; margin: 10px 0 4px;
    color: var(--muted); font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.7px;
  }
  .phase-divider::before, .phase-divider::after { content: ""; flex: 1; height: 1px; background: var(--border); }

  .chat-card {
    display: flex; gap: 11px; padding: 10px 13px; border-radius: 11px;
    background: var(--slate-bg); border-left: 3px solid #64748b;
  }
  .chat-card.side-SELF { background: var(--cyan-bg); border-left-color: var(--cyan); }
  .chat-card.side-ALLY { background: var(--blue-bg); border-left-color: var(--blue); }
  .chat-card.side-ENEMY { background: var(--red-bg); border-left-color: var(--red); }

  .avatar {
    width: 32px; height: 32px; border-radius: 50%; flex-shrink: 0;
    display: grid; place-items: center; font-weight: 700; font-size: 13px;
    background: rgba(255,255,255,0.08); color: var(--text); margin-top: 1px;
  }
  .side-SELF .avatar { background: rgba(34,211,238,0.22); color: #a5f3fc; }
  .side-ALLY .avatar { background: rgba(59,130,246,0.25); color: #bfdbfe; }
  .side-ENEMY .avatar { background: rgba(239,68,68,0.25); color: #fecaca; }

  .chat-body { flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 4px; }
  .chat-meta { display: flex; flex-wrap: wrap; align-items: center; gap: 7px; }
  .sender-name { font-weight: 700; font-size: 13.5px; color: var(--text); }
  .hero-tag {
    font-size: 11px; font-weight: 600; padding: 1px 7px; border-radius: 999px;
    background: rgba(245, 158, 11, 0.14); border: 1px solid rgba(245, 158, 11, 0.32);
    color: #fde68a;
  }
  .side-tag {
    font-size: 10.5px; font-weight: 700; padding: 1px 7px; border-radius: 999px;
    background: rgba(255,255,255,0.07); color: var(--muted);
  }
  .side-SELF .side-tag { background: rgba(34,211,238,0.18); color: #67e8f9; }
  .side-ALLY .side-tag { background: rgba(59,130,246,0.2); color: #93c5fd; }
  .side-ENEMY .side-tag { background: rgba(239,68,68,0.2); color: #fca5a5; }
  .chan-tag {
    font-size: 10.5px; font-weight: 700; padding: 1px 7px; border-radius: 5px;
    background: rgba(255,255,255,0.05); color: var(--muted); text-transform: uppercase;
  }
  .chan-tag.secret { background: var(--red-strong); color: #fecaca; border: 1px solid rgba(239,68,68,0.45); }
  .chat-time { margin-left: auto; font-size: 11.5px; color: var(--muted); }
  .chat-text { font-size: 14.5px; line-height: 1.45; color: var(--text); word-break: break-word; }
  .chat-code-note { font-size: 11px; color: var(--muted); margin-left: 6px; font-family: ui-monospace, monospace; }

  .gap-card {
    background: var(--amber-bg); border: 1px solid rgba(245, 158, 11, 0.35);
    border-left: 3px solid var(--amber); border-radius: 10px;
    padding: 9px 13px; color: #fde68a; font-size: 12.5px;
    display: flex; align-items: center; justify-content: space-between; gap: 10px;
  }

  #jumpLatest {
    display: none; position: absolute; right: 24px; bottom: 20px; z-index: 25;
    background: #2563eb; border: none; color: #fff; border-radius: 999px;
    padding: 8px 15px; font-size: 12.5px; font-weight: 700; box-shadow: 0 8px 24px rgba(0,0,0,0.5);
  }

  .mobile-menu-btn { display: none; }
  @media (max-width: 860px) {
    .mobile-menu-btn { display: inline-flex; }
    .sidebar {
      position: fixed; left: 0; top: 54px; bottom: 0; z-index: 40;
      transform: translateX(-100%); transition: transform 0.2s ease;
    }
    .sidebar.open { transform: translateX(0); box-shadow: 12px 0 32px rgba(0,0,0,0.6); }
  }
</style>
</head>
<body>
<header class="topbar">
  <button id="btnMobileSidebar" class="ghost mobile-menu-btn" title="Toggle sidebar">Menu</button>
  <div class="brand">
    <div class="brand-dot">C</div>
    <span>MLBB Chat</span>
  </div>
  <div class="tabs">
    <button id="tabLive" class="tab-btn active"><span id="liveDot" class="live-dot"></span> Live</button>
    <button id="tabHistory" class="tab-btn">Past Games <span id="historyCountPill" class="count-pill">0</span></button>
  </div>
  <div class="spacer"></div>
  <button id="statusPill" class="status-pill" title="Click for diagnostics & advanced file loading">Offline</button>
</header>

<div id="diagPop" class="diag-pop">
  <div class="diag-title">Stream Diagnostics</div>
  <div id="diagGrid" class="diag-grid"></div>
  <div class="diag-divider"></div>
  <div class="diag-title">Open Local PCAP File</div>
  <div class="diag-pcap">
    <select id="pcapSelect"></select>
    <div class="row">
      <label class="chk"><input type="checkbox" id="followChk"> Follow growing file</label>
      <div class="spacer"></div>
      <button id="btnLoadPcap" class="primary">Open</button>
    </div>
  </div>
</div>

<div class="workspace">
  <aside id="sidebar" class="sidebar">
    <!-- LIVE SIDEBAR -->
    <div id="sidebarLive" class="sidebar-section">
      <div class="card">
        <div class="row">
          <span class="card-title">Phone Capture</span>
          <div class="spacer"></div>
          <button id="btnRefreshDevices" class="ghost" title="Refresh USB/ADB devices">Refresh</button>
        </div>
        <select id="adbSelect"></select>
        <label class="chk"><input type="checkbox" id="teeChk" checked> Save capture file (.pcap)</label>
        <button id="btnToggleCapture" class="primary">Start Live Capture</button>
        <div id="captureHint" class="hint">Ready — connect phone with USB debugging and tap Start when in draft or match.</div>
        <div id="liveErrorBox" class="err-box"></div>
      </div>

      <div class="card-title" style="margin-top:4px;">Current Session Games</div>
      <div id="liveMatchesList" class="games-list"></div>
      <button id="btnBrowsePast" class="pill-btn" style="width:100%; padding:8px;">Browse Past Games &rarr;</button>
    </div>

    <!-- PAST GAMES SIDEBAR -->
    <div id="sidebarHistory" class="sidebar-section" style="display:none;">
      <div class="row">
        <input type="text" id="historySearch" placeholder="Search players or chat..." style="flex:1; min-width:0;">
        <button id="btnRescan" class="ghost" title="Scan captures/ for new .pcap files">Rescan</button>
      </div>
      <div class="seg-small">
        <button id="histOnlyChat" class="pill-btn active">With chat (<span id="cntWithChat">0</span>)</button>
        <button id="histAllCaps" class="pill-btn">All captures (<span id="cntAllCaps">0</span>)</button>
      </div>
      <div id="scanBar" class="scan-bar">
        <div class="row"><span id="scanLabel">Indexing captures...</span></div>
        <div class="scan-track"><div id="scanFill" class="scan-fill"></div></div>
      </div>
      <div id="historyList" class="games-list"></div>
    </div>
  </aside>

  <main class="main">
    <div id="matchHeader" class="match-header" style="display:none;">
      <div class="mh-top">
        <span id="mhTitle" class="mh-title">Match</span>
        <span id="mhSub" class="mh-sub"></span>
      </div>
      <div id="rosterBar" class="roster-bar" style="display:none;"></div>
      <div class="filters-row">
        <button class="pill-btn active" data-side-filter="all">All</button>
        <button class="pill-btn" data-side-filter="ALLY_GROUP">Your Team</button>
        <button class="pill-btn" data-side-filter="ENEMY">Enemy</button>
        <button class="pill-btn" data-side-filter="ENEMY_TEAM">Enemy Team Only</button>
        <div class="filter-sep"></div>
        <button class="pill-btn active" data-phase-filter="all">All Phases</button>
        <button class="pill-btn" data-phase-filter="draft">Draft</button>
        <button class="pill-btn" data-phase-filter="loading">Loading</button>
        <button class="pill-btn" data-phase-filter="battle">Battle</button>
        <div class="spacer"></div>
        <button id="btnToggleCodes" class="pill-btn">Quick-chat codes (0)</button>
        <input type="text" id="chatSearch" placeholder="Search messages..." style="width:170px;">
      </div>
    </div>

    <div id="feed" class="feed"></div>
    <button id="jumpLatest">&darr; Jump to latest</button>
  </main>
</div>

<script>
(() => {
  const state = {
    activeTab: "live",
    userPickedTab: false,
    liveMatches: new Map(),
    liveOrder: [],
    selectedLiveId: null,
    historyGames: [],
    historyCounts: { withChat: 0, all: 0 },
    historyScan: { scanning: false, done: 0, total: 0, current_file: "" },
    includeEmptyHistory: false,
    selectedHistoryId: null,
    loadedHistoryGames: new Map(),
    status: {},
    sseOk: true,
    lastHeartbeatMs: Date.now(),
    sideFilter: "all",
    phaseFilter: "all",
    showCodesByGame: new Map(),
    autoScroll: true,
    unread: 0,
    scanPollTimer: null,
  };

  const el = {
    tabLive: document.getElementById("tabLive"),
    tabHistory: document.getElementById("tabHistory"),
    liveDot: document.getElementById("liveDot"),
    historyCountPill: document.getElementById("historyCountPill"),
    statusPill: document.getElementById("statusPill"),
    diagPop: document.getElementById("diagPop"),
    diagGrid: document.getElementById("diagGrid"),
    pcapSelect: document.getElementById("pcapSelect"),
    followChk: document.getElementById("followChk"),
    sidebar: document.getElementById("sidebar"),
    sidebarLive: document.getElementById("sidebarLive"),
    sidebarHistory: document.getElementById("sidebarHistory"),
    adbSelect: document.getElementById("adbSelect"),
    teeChk: document.getElementById("teeChk"),
    btnToggleCapture: document.getElementById("btnToggleCapture"),
    captureHint: document.getElementById("captureHint"),
    liveErrorBox: document.getElementById("liveErrorBox"),
    liveMatchesList: document.getElementById("liveMatchesList"),
    historySearch: document.getElementById("historySearch"),
    histOnlyChat: document.getElementById("histOnlyChat"),
    histAllCaps: document.getElementById("histAllCaps"),
    cntWithChat: document.getElementById("cntWithChat"),
    cntAllCaps: document.getElementById("cntAllCaps"),
    scanBar: document.getElementById("scanBar"),
    scanLabel: document.getElementById("scanLabel"),
    scanFill: document.getElementById("scanFill"),
    historyList: document.getElementById("historyList"),
    matchHeader: document.getElementById("matchHeader"),
    mhTitle: document.getElementById("mhTitle"),
    mhSub: document.getElementById("mhSub"),
    rosterBar: document.getElementById("rosterBar"),
    btnToggleCodes: document.getElementById("btnToggleCodes"),
    chatSearch: document.getElementById("chatSearch"),
    feed: document.getElementById("feed"),
    jumpLatest: document.getElementById("jumpLatest"),
  };

  function fmtDateTime(ts) {
    if (!ts) return "Unknown time";
    const d = new Date(ts * 1000);
    return d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", hour12: false });
  }

  function fmtClock(ts) {
    if (!ts) return "--:--:--";
    return new Date(ts * 1000).toTimeString().slice(0, 8);
  }

  function fmtDuration(sec) {
    if (!sec || sec < 1) return "";
    const m = Math.floor(sec / 60);
    const s = Math.floor(sec % 60);
    return m > 0 ? `${m}m ${s}s` : `${s}s`;
  }

  function currentGameKey() {
    if (state.activeTab === "history") return state.selectedHistoryId ? `h:${state.selectedHistoryId}` : null;
    return state.selectedLiveId ? `l:${state.selectedLiveId}` : null;
  }

  function activeGameRecord() {
    if (state.activeTab === "history") {
      return state.selectedHistoryId ? state.loadedHistoryGames.get(state.selectedHistoryId) || null : null;
    }
    return state.selectedLiveId ? state.liveMatches.get(state.selectedLiveId) || null : null;
  }

  function shouldShowCodes(game) {
    const key = currentGameKey();
    if (key && state.showCodesByGame.has(key)) return state.showCodesByGame.get(key);
    const evs = (game && game.events) || [];
    const typed = evs.filter((e) => !e.is_template).length;
    return typed === 0 && evs.length > 0;
  }

  function ensureLiveMatch(summary) {
    if (!summary || !summary.match_id) return null;
    const id = summary.match_id;
    let m = state.liveMatches.get(id);
    if (!m) {
      m = Object.assign({ events: [], gaps: [], players: [] }, summary);
      state.liveMatches.set(id, m);
      state.liveOrder.push(id);
      if (!state.selectedLiveId) state.selectedLiveId = id;
    } else {
      const prevEv = m.events || [];
      const prevGap = m.gaps || [];
      Object.assign(m, summary);
      if (!Array.isArray(summary.events)) m.events = prevEv;
      if (!Array.isArray(summary.gaps)) m.gaps = prevGap;
    }
    return m;
  }

  function setTab(tab, byUser) {
    state.activeTab = tab;
    if (byUser) state.userPickedTab = true;
    el.tabLive.classList.toggle("active", tab === "live");
    el.tabHistory.classList.toggle("active", tab === "history");
    el.sidebarLive.style.display = tab === "live" ? "flex" : "none";
    el.sidebarHistory.style.display = tab === "history" ? "flex" : "none";
    renderTopStatus();
    renderSidebar();
    renderMain();
  }

  function renderTopStatus() {
    const s = state.status || {};
    const mode = s.source_mode || "IDLE";
    const isLiveStream = mode === "LIVE (adb)" || mode === "FOLLOW (file)";
    const isCapturing = isLiveStream && !!s.capture_alive;
    el.liveDot.classList.toggle("on", isCapturing);

    // Phone capture button + hint
    if (isCapturing) {
      el.btnToggleCapture.textContent = "Stop Capture";
      el.btnToggleCapture.className = "danger";
      el.captureHint.textContent = s.active_match_id
        ? "Capturing live match packets — messages update automatically."
        : "Connected and listening — start a match on your phone to see chat here.";
    } else {
      el.btnToggleCapture.textContent = "Start Live Capture";
      el.btnToggleCapture.className = "primary";
      el.captureHint.textContent = "Ready — connect phone with USB debugging and tap Start when in draft or match.";
    }

    if (s.last_error) {
      el.liveErrorBox.style.display = "block";
      el.liveErrorBox.textContent = s.last_error;
    } else {
      el.liveErrorBox.style.display = "none";
    }

    // Status pill text in plain English
    const age = s.last_pkt_age_s;
    const staleThreshold = s.phase === "BATTLE" ? 3.0 : 5.0;
    let cls = "status-pill";
    let label = "Offline";
    if (!state.sseOk) {
      cls = "status-pill err";
      label = "Disconnected";
    } else if (isLiveStream && s.capture_alive) {
      if (typeof age === "number" && age > staleThreshold) {
        cls = "status-pill warn";
        label = `No packets for ${Math.floor(age)}s`;
      } else if (s.active_match_id) {
        cls = "status-pill ok";
        label = "Live · Capturing";
      } else {
        cls = "status-pill ok";
        label = "Live · Waiting for match";
      }
    } else if (mode === "CAPTURE STOPPED") {
      cls = "status-pill err";
      label = "Capture stopped";
    } else if (state.activeTab === "history" && activeGameRecord()) {
      cls = "status-pill info";
      label = "Viewing Past Game";
    } else if (mode === "REPLAY (file)") {
      cls = "status-pill info";
      label = "Viewing Replay";
    }
    el.statusPill.className = cls;
    el.statusPill.textContent = label;

    // Diagnostics grid
    const rows = [
      ["Source", mode + (s.source_detail ? ` (${s.source_detail})` : "")],
      ["Phase / FSM", `${s.phase || "IDLE"} / ${s.fsm_state || "IDLE"}`],
      ["Battle Tick", s.next_tick !== null && s.next_tick !== undefined ? String(s.next_tick) : "-"],
      ["LZW Dict", s.dict_next_code || "0x0101"],
      ["Last Packet Age", typeof age === "number" ? `${age.toFixed(1)}s` : "-"],
      ["Packets / Cut", `${s.packets_processed || 0} / ${s.skipped_truncated || 0}`],
    ];
    el.diagGrid.innerHTML = rows
      .map(([k, v]) => `<div class="diag-k">${k}</div><div class="diag-v">${String(v).replace(/</g, "&lt;")}</div>`)
      .join("");
  }

  function fmtMatchup(ally, enemy, ip, port) {
    if (ally && ally.length && enemy && enemy.length) {
      const a = ally.length === 1 ? ally[0] : `${ally[0]} +${ally.length - 1}`;
      const e = enemy.length === 1 ? enemy[0] : `${enemy[0]} +${enemy.length - 1}`;
      return `${a} vs ${e}`;
    }
    if (ally && ally.length) return `${ally[0]} (+${ally.length - 1} allies)`;
    if (ip) return `Match · ${ip}:${port}`;
    return "Match";
  }

  function renderSidebar() {
    el.historyCountPill.textContent = String(state.historyCounts.withChat || 0);
    el.cntWithChat.textContent = String(state.historyCounts.withChat || 0);
    el.cntAllCaps.textContent = String(state.historyCounts.all || 0);
    el.histOnlyChat.classList.toggle("active", !state.includeEmptyHistory);
    el.histAllCaps.classList.toggle("active", state.includeEmptyHistory);

    // Live session matches
    el.liveMatchesList.innerHTML = "";
    if (state.liveOrder.length === 0) {
      const d = document.createElement("div");
      d.className = "hint";
      d.textContent = "No games in the active session yet.";
      el.liveMatchesList.appendChild(d);
    } else {
      for (const id of state.liveOrder) {
        const m = state.liveMatches.get(id);
        const players = m.players || [];
        const localCamp = m.local_camp || 1;
        const ally = players.filter((p) => p.camp === localCamp).map((p) => p.name);
        const enemy = players.filter((p) => p.camp && p.camp !== localCamp).map((p) => p.name);
        const evs = m.events || [];
        const typed = evs.filter((e) => !e.is_template).length;
        const enemyTeam = evs.filter((e) => e.side === "ENEMY" && (e.channel === 2 || e.channel === 4)).length;

        const btn = document.createElement("button");
        btn.className = "game-card" + (state.selectedLiveId === id ? " active" : "");
        btn.onclick = () => {
          state.selectedLiveId = id;
          state.autoScroll = true;
          renderSidebar();
          renderMain();
        };

        const top = document.createElement("div");
        top.className = "game-top";
        top.innerHTML = `<span>${fmtDateTime(m.first_ts)}</span><span class="origin-tag live">${m.phase || "ACTIVE"}</span>`;
        const title = document.createElement("div");
        title.className = "game-title";
        title.textContent = fmtMatchup(ally, enemy, m.server_ip, m.server_port);
        const badges = document.createElement("div");
        badges.className = "game-badges";
        if (m.mode_label) {
          const mb = document.createElement("span");
          mb.className = "mini-badge mode";
          mb.textContent = m.mode_label;
          badges.appendChild(mb);
        }
        if (m.party_label) {
          const pb = document.createElement("span");
          pb.className = "mini-badge";
          pb.textContent = m.party_label;
          badges.appendChild(pb);
        }
        const mc = document.createElement("span");
        mc.className = "mini-badge";
        mc.textContent = `${typed || evs.length} messages`;
        badges.appendChild(mc);
        if (enemyTeam > 0) {
          const eb = document.createElement("span");
          eb.className = "mini-badge enemy-team";
          eb.textContent = `Enemy Team (${enemyTeam})`;
          badges.appendChild(eb);
        }

        btn.appendChild(top);
        btn.appendChild(title);
        btn.appendChild(badges);
        el.liveMatchesList.appendChild(btn);
      }
    }

    // Scan bar
    const sc = state.historyScan || {};
    if (sc.scanning) {
      el.scanBar.style.display = "flex";
      const pct = sc.total > 0 ? Math.round((sc.done / sc.total) * 100) : 10;
      el.scanLabel.textContent = `Indexing captures ${sc.done}/${sc.total}${sc.current_file ? ` · ${sc.current_file}` : ""}`;
      el.scanFill.style.width = `${pct}%`;
    } else {
      el.scanBar.style.display = "none";
    }

    // History list
    el.historyList.innerHTML = "";
    const q = el.historySearch.value.trim().toLowerCase();
    const filtered = state.historyGames.filter((g) => {
      if (!q) return true;
      const hay = [
        g.source_name,
        g.mode_label || "",
        g.party_label || "",
        ...(g.ally_players || []),
        ...(g.enemy_players || []),
        g.preview || "",
      ].join(" ").toLowerCase();
      return hay.includes(q);
    });

    if (filtered.length === 0) {
      const d = document.createElement("div");
      d.className = "hint";
      d.textContent = sc.scanning ? "Scanning captures/..." : "No matching past games found.";
      el.historyList.appendChild(d);
      return;
    }

    for (const g of filtered) {
      const card = document.createElement("div");
      card.className = "game-card" + (state.selectedHistoryId === g.game_id ? " active" : "");
      card.style.cursor = "pointer";
      card.onclick = () => selectHistoryGame(g.game_id);

      const top = document.createElement("div");
      top.className = "game-top";
      const dt = document.createElement("span");
      dt.textContent = fmtDateTime(g.started_at);
      const tag = document.createElement("span");
      tag.className = "origin-tag" + (g.origin === "live" ? " live" : "");
      tag.textContent = g.origin === "live" ? "LIVE SAVED" : g.source_name;
      top.appendChild(dt);
      top.appendChild(tag);
      if (g.origin === "live") {
        const del = document.createElement("button");
        del.className = "del-btn";
        del.title = "Remove saved live game";
        del.textContent = "Delete";
        del.onclick = async (e) => {
          e.stopPropagation();
          await fetch(`/api/history/${encodeURIComponent(g.game_id)}`, { method: "DELETE" });
          state.loadedHistoryGames.delete(g.game_id);
          if (state.selectedHistoryId === g.game_id) state.selectedHistoryId = null;
          await loadHistory(false);
        };
        top.appendChild(del);
      }

      const title = document.createElement("div");
      title.className = "game-title";
      title.textContent = fmtMatchup(g.ally_players, g.enemy_players, g.server_ip, g.server_port);

      const badges = document.createElement("div");
      badges.className = "game-badges";
      if (g.mode_label) {
        const b = document.createElement("span");
        b.className = "mini-badge mode";
        b.textContent = g.mode_label;
        badges.appendChild(b);
      }
      if (g.party_label) {
        const b = document.createElement("span");
        b.className = "mini-badge";
        b.textContent = g.party_label;
        badges.appendChild(b);
      }
      if (g.typed_count > 0) {
        const b = document.createElement("span");
        b.className = "mini-badge";
        b.textContent = `${g.typed_count} typed`;
        badges.appendChild(b);
      } else if (g.quickchat_count > 0) {
        const b = document.createElement("span");
        b.className = "mini-badge";
        b.textContent = `${g.quickchat_count} quick-chats`;
        badges.appendChild(b);
      } else {
        const b = document.createElement("span");
        b.className = "mini-badge";
        b.textContent = "No chat";
        badges.appendChild(b);
      }
      if (g.enemy_team_count > 0) {
        const b = document.createElement("span");
        b.className = "mini-badge enemy-team";
        b.textContent = `Enemy Team (${g.enemy_team_count})`;
        badges.appendChild(b);
      }
      if (g.has_gaps) {
        const b = document.createElement("span");
        b.className = "mini-badge gap";
        b.textContent = "Mid-match";
        badges.appendChild(b);
      }

      card.appendChild(top);
      card.appendChild(title);
      card.appendChild(badges);
      if (g.preview) {
        const prev = document.createElement("div");
        prev.className = "game-preview";
        prev.textContent = g.preview;
        card.appendChild(prev);
      }
      el.historyList.appendChild(card);
    }
  }

  function friendlySender(ev) {
    const raw = ev.sender_name || "";
    if (!raw || raw.startsWith("slot 0x")) {
      if (ev.side === "SELF") return "You";
      if (ev.side === "ALLY") return "Teammate";
      if (ev.side === "ENEMY") return "Enemy";
      return "Player";
    }
    return raw;
  }

  function heroForEvent(ev, heroByUid) {
    if (ev.sender_uid && heroByUid && heroByUid.has(ev.sender_uid)) return heroByUid.get(ev.sender_uid);
    if (ev.sender_hero) return ev.sender_hero;
    return "";
  }

  function sideBadgeLabel(side) {
    if (side === "SELF") return "You";
    if (side === "ALLY") return "Ally";
    if (side === "ENEMY") return "Enemy";
    return side || "Player";
  }

  function channelBadge(ev) {
    if (ev.side === "ENEMY" && (ev.channel === 2 || ev.channel === 4)) {
      return { text: "ENEMY TEAM", secret: true };
    }
    if (ev.channel === 2) return { text: "TEAM", secret: false };
    if (ev.channel === 3) return { text: "ALL CHAT", secret: false };
    if (ev.phase === "draft" || ev.channel === 4) return { text: "DRAFT", secret: false };
    if (ev.phase === "loading" || ev.channel === 22) return { text: "LOADING", secret: false };
    return { text: (ev.channel_name || "CHAT").toUpperCase(), secret: false };
  }

  function formatGapText(g) {
    if (g.resolved && g.from_tick !== null && g.to_tick !== null) {
      return `Joined mid-match — ticks ${g.from_tick} to ${g.to_tick} couldn't be decoded. Resynced at tick ${g.sync_tick}.`;
    }
    return `Joined mid-match — waiting for next LZW reset to decode chat (from tick ${g.from_tick}).`;
  }

  function renderMain() {
    const game = activeGameRecord();
    if (!game) {
      el.matchHeader.style.display = "none";
      el.feed.innerHTML = "";
      const box = document.createElement("div");
      box.className = "empty-state";
      if (state.activeTab === "history") {
        box.innerHTML = `<div class="empty-title">Pick a past game on the left</div>
          <div class="empty-desc">All saved live matches and indexed captures in <code>captures/</code> appear in the sidebar.</div>`;
      } else {
        box.innerHTML = `<div class="empty-title">No live match active</div>
          <div class="empty-desc">Tap <strong>Start Live Capture</strong> when your phone is in draft or a match, or browse your archived matches.</div>`;
        const btn = document.createElement("button");
        btn.className = "primary";
        btn.textContent = "Browse Past Games";
        btn.onclick = () => setTab("history", true);
        box.appendChild(btn);
      }
      el.feed.appendChild(box);
      return;
    }

    el.matchHeader.style.display = "flex";
    const srcLabel = game.source_name || (state.status.source_mode === "REPLAY (file)" ? "Replay" : "Live Match");
    const dur = fmtDuration((game.last_ts || 0) - (game.first_ts || 0));
    el.mhTitle.textContent = `${fmtDateTime(game.first_ts)} · ${srcLabel}`;
    el.mhSub.textContent = [
      game.mode_label || "",
      game.party_label || "",
      dur,
      game.server_ip ? `${game.server_ip}:${game.server_port}` : "",
    ].filter(Boolean).join(" · ");

    // Roster chips
    const players = game.players || [];
    const heroByUid = new Map();
    for (const p of players) {
      if (p.uid && p.hero_name) heroByUid.set(p.uid, p.hero_name);
    }
    const localCamp = game.local_camp || 1;
    const allies = players.filter((p) => p.camp === localCamp);
    const enemies = players.filter((p) => p.camp && p.camp !== localCamp);
    const appendPlayerChip = (grp, p, isEnemy) => {
      const isYou = !isEnemy && Boolean(game.local_uid && p.uid === game.local_uid);
      const chip = document.createElement("span");
      chip.className = "player-chip" + (isYou ? " you" : isEnemy ? " enemy" : "");
      const label = isYou ? `${p.name || p.uid} (You)` : (p.name || `uid:${p.uid}`);
      chip.appendChild(document.createTextNode(label));
      if (p.hero_name) {
        const hs = document.createElement("span");
        hs.className = "chip-hero";
        hs.textContent = ` · ${p.hero_name}`;
        chip.appendChild(hs);
      }
      if (p.country) {
        const cs = document.createElement("span");
        cs.className = "chip-cc";
        cs.textContent = p.country;
        chip.appendChild(cs);
      }
      if (p.is_bot) {
        const bs = document.createElement("span");
        bs.className = "chip-bot";
        bs.textContent = "BOT";
        chip.appendChild(bs);
      }
      const tips = [];
      if (p.uid) tips.push(`uid: ${p.uid}`);
      if (p.zone_id) tips.push(`zone: ${p.zone_id}`);
      if (p.party_size >= 2) tips.push(`Party of ${p.party_size}`);
      if (tips.length) chip.title = tips.join(" · ");
      grp.appendChild(chip);
    };
    if (allies.length || enemies.length) {
      el.rosterBar.style.display = "flex";
      el.rosterBar.innerHTML = "";
      if (allies.length) {
        const grp = document.createElement("div");
        grp.className = "team-group";
        grp.innerHTML = `<span class="team-lbl ally">Your Team</span>`;
        for (const p of allies) appendPlayerChip(grp, p, false);
        el.rosterBar.appendChild(grp);
      }
      if (enemies.length) {
        const grp = document.createElement("div");
        grp.className = "team-group";
        grp.innerHTML = `<span class="team-lbl enemy">Enemy Team</span>`;
        for (const p of enemies) appendPlayerChip(grp, p, true);
        el.rosterBar.appendChild(grp);
      }
    } else {
      el.rosterBar.style.display = "none";
    }

    const events = game.events || [];
    const gaps = game.gaps || [];
    const codeCount = events.filter((e) => e.is_template).length;
    const showCodes = shouldShowCodes(game);
    el.btnToggleCodes.textContent = `Quick-chat codes (${codeCount})`;
    el.btnToggleCodes.classList.toggle("active", showCodes);

    const q = el.chatSearch.value.trim().toLowerCase();
    const filteredEvents = events.filter((ev) => {
      if (!showCodes && ev.is_template) return false;
      if (state.phaseFilter !== "all" && ev.phase !== state.phaseFilter) return false;
      if (state.sideFilter === "ALLY_GROUP" && ev.side !== "SELF" && ev.side !== "ALLY") return false;
      else if (state.sideFilter === "ENEMY" && ev.side !== "ENEMY") return false;
      else if (state.sideFilter === "ENEMY_TEAM" && !(ev.side === "ENEMY" && (ev.channel === 2 || ev.channel === 4))) return false;
      if (q) {
        const hay = `${friendlySender(ev)} ${heroForEvent(ev, heroByUid)} ${ev.display_text} ${ev.raw_text}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });

    const timeline = [];
    for (const g of gaps) timeline.push({ kind: "gap", ts: g.ts || 0, item: g });
    for (const ev of filteredEvents) timeline.push({ kind: "ev", ts: ev.ts || 0, item: ev });
    timeline.sort((a, b) => (a.ts - b.ts) || ((a.item.seq_id || 0) - (b.item.seq_id || 0)));

    const prevScrollTop = el.feed.scrollTop;
    el.feed.innerHTML = "";
    if (timeline.length === 0) {
      const box = document.createElement("div");
      box.className = "empty-state";
      box.innerHTML = `<div class="empty-title">No messages match these filters</div>
        <div class="empty-desc">${codeCount > 0 && !showCodes ? "This match has quick-chat codes hidden — toggle Quick-chat codes above to inspect them." : "Try clearing filters or waiting for players to chat."}</div>`;
      el.feed.appendChild(box);
      return;
    }

    const phaseNames = { draft: "Draft Pick", loading: "Loading Screen", battle: "In-Game Battle" };
    let lastPhase = null;
    const frag = document.createDocumentFragment();
    for (const row of timeline) {
      if (row.kind === "gap") {
        const g = row.item;
        const div = document.createElement("div");
        div.className = "gap-card";
        div.innerHTML = `<span>${formatGapText(g)}</span>`;
        frag.appendChild(div);
        continue;
      }
      const ev = row.item;
      if (ev.phase && ev.phase !== lastPhase) {
        lastPhase = ev.phase;
        const pd = document.createElement("div");
        pd.className = "phase-divider";
        pd.textContent = phaseNames[ev.phase] || ev.phase;
        frag.appendChild(pd);
      }

      const card = document.createElement("div");
      card.className = `chat-card side-${String(ev.side || "UNKNOWN").split(" ")[0]}`;
      const sender = friendlySender(ev);
      const av = document.createElement("div");
      av.className = "avatar";
      av.textContent = (sender[0] || "?").toUpperCase();

      const body = document.createElement("div");
      body.className = "chat-body";

      const meta = document.createElement("div");
      meta.className = "chat-meta";

      const nm = document.createElement("span");
      nm.className = "sender-name";
      nm.textContent = sender;
      if (ev.sender_uid) nm.title = `uid: ${ev.sender_uid}`;

      const st = document.createElement("span");
      st.className = "side-tag";
      st.textContent = sideBadgeLabel(ev.side);

      const cb = channelBadge(ev);
      const ch = document.createElement("span");
      ch.className = "chan-tag" + (cb.secret ? " secret" : "");
      ch.textContent = cb.text;

      const tm = document.createElement("span");
      tm.className = "chat-time";
      tm.textContent = fmtClock(ev.ts);
      if (ev.tick !== null && ev.tick !== undefined) tm.title = `Tick #${ev.tick}`;

      meta.appendChild(nm);
      const heroName = heroForEvent(ev, heroByUid);
      if (heroName) {
        const hr = document.createElement("span");
        hr.className = "hero-tag";
        hr.textContent = heroName;
        if (ev.sender_hero_id) hr.title = `hero_id: ${ev.sender_hero_id}`;
        meta.appendChild(hr);
      }
      meta.appendChild(st);
      meta.appendChild(ch);
      meta.appendChild(tm);

      const txt = document.createElement("div");
      txt.className = "chat-text";
      txt.textContent = ev.display_text || ev.raw_text;
      if (ev.is_template && ev.raw_text && ev.raw_text !== ev.display_text) {
        const note = document.createElement("span");
        note.className = "chat-code-note";
        note.textContent = `[${ev.raw_text}]`;
        txt.appendChild(note);
      }

      body.appendChild(meta);
      body.appendChild(txt);
      card.appendChild(av);
      card.appendChild(body);
      frag.appendChild(card);
    }
    el.feed.appendChild(frag);
    if (state.autoScroll) {
      el.feed.scrollTop = el.feed.scrollHeight;
      state.unread = 0;
      el.jumpLatest.style.display = "none";
    } else {
      el.feed.scrollTop = prevScrollTop;
    }
  }

  async function selectHistoryGame(gameId, forceReload = false) {
    const prevSelected = state.selectedHistoryId;
    state.selectedHistoryId = gameId;
    if (gameId !== prevSelected) state.autoScroll = true;
    renderSidebar();
    if (forceReload || !state.loadedHistoryGames.has(gameId)) {
      const res = await fetch(`/api/history/${encodeURIComponent(gameId)}`);
      if (res.ok) {
        const data = await res.json();
        state.loadedHistoryGames.set(gameId, data);
      }
    }
    renderTopStatus();
    renderMain();
    el.sidebar.classList.remove("open");
  }

  async function loadHistory(autoSelectFirst, forceReloadSelected = false) {
    try {
      const prevSelectedId = state.selectedHistoryId;
      const prevSelectedGame = prevSelectedId
        ? (state.historyGames.find((g) => g.game_id === prevSelectedId) || state.loadedHistoryGames.get(prevSelectedId))
        : null;
      const wasScanning = !!(state.historyScan && state.historyScan.scanning);

      const res = await fetch(`/api/history?include_empty=${state.includeEmptyHistory ? 1 : 0}`);
      if (!res.ok) return;
      const data = await res.json();
      state.historyGames = data.games || [];
      state.historyCounts = { withChat: data.total_with_chat || 0, all: data.total_all || 0 };
      state.historyScan = data.scan || { scanning: false, done: 0, total: 0, current_file: "" };
      const scanFinished = wasScanning && !state.historyScan.scanning;
      if (scanFinished) state.loadedHistoryGames.clear();

      if (state.historyScan.scanning && !state.scanPollTimer) {
        state.scanPollTimer = setInterval(() => loadHistory(false), 1500);
      } else if (!state.historyScan.scanning && state.scanPollTimer) {
        clearInterval(state.scanPollTimer);
        state.scanPollTimer = null;
      }

      if (autoSelectFirst && !state.userPickedTab && state.liveOrder.length === 0 && !state.status.capture_alive && state.historyGames.length > 0) {
        setTab("history", false);
      }
      if (state.activeTab === "history") {
        if (!state.selectedHistoryId && state.historyGames.length > 0) {
          await selectHistoryGame(state.historyGames[0].game_id);
          return;
        }
        if (state.selectedHistoryId) {
          const stillListed = state.historyGames.some((g) => g.game_id === state.selectedHistoryId);
          if (!stillListed) {
            const prevBid = prevSelectedGame && prevSelectedGame.battle_id;
            const replacement = (prevBid && state.historyGames.find((g) => g.battle_id === prevBid)) || state.historyGames[0] || null;
            state.selectedHistoryId = replacement ? replacement.game_id : null;
            if (state.selectedHistoryId) {
              await selectHistoryGame(state.selectedHistoryId, true);
              return;
            }
            renderSidebar();
            renderMain();
            return;
          }
          if (scanFinished || forceReloadSelected) {
            await selectHistoryGame(state.selectedHistoryId, true);
            return;
          }
        }
      }
      renderSidebar();
    } catch (_e) {}
  }

  async function refreshDevicesAndPcaps() {
    try {
      const [devRes, pcapRes] = await Promise.all([fetch("/api/devices"), fetch("/api/pcaps")]);
      const devs = (await devRes.json()).devices || [];
      const pcaps = (await pcapRes.json()).pcaps || [];

      el.adbSelect.innerHTML = "";
      if (devs.length === 0) {
        const o = document.createElement("option");
        o.value = ""; o.textContent = "No phone connected";
        el.adbSelect.appendChild(o);
      } else {
        for (const d of devs) {
          const o = document.createElement("option");
          o.value = d.serial;
          o.textContent = d.model ? `${d.model} (${d.serial})` : `${d.serial} (${d.state})`;
          el.adbSelect.appendChild(o);
        }
      }

      el.pcapSelect.innerHTML = "";
      for (const p of pcaps) {
        const o = document.createElement("option");
        o.value = p.path;
        o.textContent = `${p.name} (${(p.size_bytes / 1048576).toFixed(1)} MB)`;
        el.pcapSelect.appendChild(o);
      }
    } catch (_e) {}
  }

  async function postSource(body) {
    const res = await fetch("/api/source", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const data = await res.json();
    if (!res.ok) {
      state.status.last_error = data.error || "Request failed";
      renderTopStatus();
      return;
    }
    if (data.status) state.status = data.status;
    renderTopStatus();
  }

  function connectSse() {
    const es = new EventSource("/events");
    const alive = () => {
      state.sseOk = true;
      state.lastHeartbeatMs = Date.now();
    };

    es.addEventListener("status", (ev) => {
      alive();
      state.status = JSON.parse(ev.data);
      renderTopStatus();
    });

    es.addEventListener("source_reset", (ev) => {
      alive();
      const d = JSON.parse(ev.data);
      state.liveMatches.clear();
      state.liveOrder = [];
      state.selectedLiveId = null;
      state.loadedHistoryGames.clear();
      if (d.status) state.status = d.status;
      renderTopStatus();
      renderSidebar();
      renderMain();
      loadHistory(false);
    });

    es.addEventListener("snapshot", (ev) => {
      alive();
      const d = JSON.parse(ev.data);
      state.liveMatches.clear();
      state.liveOrder = [];
      state.selectedLiveId = null;
      for (const m of (d.matches || [])) ensureLiveMatch(m);
      if (d.status) state.status = d.status;
      renderTopStatus();
      renderSidebar();
      if (state.liveOrder.length > 0) setTab("live", false);
      else renderMain();
    });

    es.addEventListener("match_new", (ev) => {
      alive();
      const m = JSON.parse(ev.data);
      ensureLiveMatch(m);
      state.selectedLiveId = m.match_id;
      renderSidebar();
      if (state.activeTab === "live") renderMain();
    });

    es.addEventListener("match_update", (ev) => {
      alive();
      const m = JSON.parse(ev.data);
      ensureLiveMatch(m);
      renderSidebar();
      if (state.activeTab === "live" && m.match_id === state.selectedLiveId) renderMain();
    });

    es.addEventListener("chat", (ev) => {
      alive();
      const msg = JSON.parse(ev.data);
      let m = state.liveMatches.get(msg.match_id);
      if (!m) m = ensureLiveMatch({ match_id: msg.match_id, events: [], gaps: [], players: [] });
      const idx = m.events.findIndex((x) => x.seq_id === msg.seq_id);
      if (idx >= 0) m.events[idx] = msg;
      else m.events.push(msg);
      renderSidebar();
      if (state.activeTab === "live" && msg.match_id === state.selectedLiveId) {
        if (!state.autoScroll) {
          state.unread += 1;
          el.jumpLatest.textContent = `\u2193 Jump to latest (${state.unread})`;
          el.jumpLatest.style.display = "block";
        }
        renderMain();
      }
    });

    es.addEventListener("gap", (ev) => {
      alive();
      const g = JSON.parse(ev.data);
      let m = state.liveMatches.get(g.match_id);
      if (!m) m = ensureLiveMatch({ match_id: g.match_id, events: [], gaps: [], players: [] });
      const idx = m.gaps.findIndex((x) => x.gap_id === g.gap_id);
      if (idx >= 0) m.gaps[idx] = g;
      else m.gaps.push(g);
      renderSidebar();
      if (state.activeTab === "live" && g.match_id === state.selectedLiveId) renderMain();
    });

    es.addEventListener("history_updated", () => {
      alive();
      state.loadedHistoryGames.clear();
      loadHistory(false, true);
      refreshDevicesAndPcaps();
    });

    es.onerror = () => {
      state.sseOk = false;
      renderTopStatus();
    };
  }

  setInterval(() => {
    if (Date.now() - state.lastHeartbeatMs > 3000) {
      state.sseOk = false;
      renderTopStatus();
    }
  }, 1000);

  // Event listeners
  el.tabLive.onclick = () => setTab("live", true);
  el.tabHistory.onclick = () => { setTab("history", true); loadHistory(false); };
  document.getElementById("btnBrowsePast").onclick = () => { setTab("history", true); loadHistory(false); };
  document.getElementById("btnMobileSidebar").onclick = () => el.sidebar.classList.toggle("open");

  el.statusPill.onclick = (e) => { e.stopPropagation(); el.diagPop.classList.toggle("open"); };
  document.addEventListener("click", (e) => {
    if (!el.diagPop.contains(e.target) && e.target !== el.statusPill) el.diagPop.classList.remove("open");
  });

  document.getElementById("btnRefreshDevices").onclick = refreshDevicesAndPcaps;
  el.btnToggleCapture.onclick = () => {
    const s = state.status || {};
    const isCapturing = (s.source_mode === "LIVE (adb)" || s.source_mode === "FOLLOW (file)") && s.capture_alive;
    if (isCapturing) {
      postSource({ mode: "stop" });
      return;
    }
    const serial = el.adbSelect.value;
    if (!serial) {
      state.status.last_error = "No connected Android device found via ADB.";
      renderTopStatus();
      return;
    }
    setTab("live", true);
    postSource({ mode: "adb", serial, tee: el.teeChk.checked });
  };

  document.getElementById("btnLoadPcap").onclick = () => {
    const p = el.pcapSelect.value;
    if (!p) return;
    el.diagPop.classList.remove("open");
    setTab("live", true);
    postSource({ mode: "pcap", path: p, follow: el.followChk.checked });
  };

  el.histOnlyChat.onclick = () => { state.includeEmptyHistory = false; loadHistory(false); };
  el.histAllCaps.onclick = () => { state.includeEmptyHistory = true; loadHistory(false); };
  el.historySearch.oninput = () => renderSidebar();
  document.getElementById("btnRescan").onclick = async () => {
    state.loadedHistoryGames.clear();
    await fetch("/api/history/scan", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
    await loadHistory(false, true);
  };

  document.querySelectorAll("[data-side-filter]").forEach((btn) => {
    btn.onclick = () => {
      state.sideFilter = btn.getAttribute("data-side-filter");
      document.querySelectorAll("[data-side-filter]").forEach((b) => b.classList.remove("active", "danger-active"));
      btn.classList.add(state.sideFilter === "ENEMY_TEAM" ? "danger-active" : "active");
      renderMain();
    };
  });

  document.querySelectorAll("[data-phase-filter]").forEach((btn) => {
    btn.onclick = () => {
      state.phaseFilter = btn.getAttribute("data-phase-filter");
      document.querySelectorAll("[data-phase-filter]").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      renderMain();
    };
  });

  el.btnToggleCodes.onclick = () => {
    const key = currentGameKey();
    const game = activeGameRecord();
    if (!key || !game) return;
    state.showCodesByGame.set(key, !shouldShowCodes(game));
    renderMain();
  };

  el.chatSearch.oninput = () => renderMain();

  el.feed.addEventListener("scroll", () => {
    const gap = el.feed.scrollHeight - el.feed.scrollTop - el.feed.clientHeight;
    state.autoScroll = gap < 36;
    if (state.autoScroll) {
      state.unread = 0;
      el.jumpLatest.style.display = "none";
    }
  });
  el.jumpLatest.onclick = () => {
    state.autoScroll = true;
    state.unread = 0;
    el.feed.scrollTop = el.feed.scrollHeight;
    el.jumpLatest.style.display = "none";
  };

  (async () => {
    await refreshDevicesAndPcaps();
    try {
      const res = await fetch("/api/matches");
      const d = await res.json();
      for (const m of (d.matches || [])) ensureLiveMatch(m);
      if (d.status) state.status = d.status;
      renderTopStatus();
      renderSidebar();
      renderMain();
    } catch (_e) {}
    await loadHistory(true);
    connectSse();
  })();
})();
</script>
</body>
</html>
"""
