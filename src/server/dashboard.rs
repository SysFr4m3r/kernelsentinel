pub const PAGE: &str = r####"
<title>Sentinel Fleet</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap">
<style>
:root{
  --ground:#eef1f5;--panel:#fff;--panel2:#f6f8fa;--ink:#111820;--muted:#586472;--faint:#8a95a2;--line:#dce2ea;
  --accent:#0c8399;--accent-dim:#0c839922;
  --crit:#cf2447;--high:#bd5a17;--med:#9a6c12;--low:#256d8a;--info:#6a7885;--ok:#2f8f5b;
  --crit-bg:#cf24471a;--high-bg:#bd5a171a;--med-bg:#9a6c121a;--low-bg:#256d8a1a;--info-bg:#6a78851a;--ok-bg:#2f8f5b1a;
  --shadow:0 1px 2px #0b111a0d,0 8px 24px #0b111a0a;
}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){
  --ground:#0d1015;--panel:#141a21;--panel2:#0f151b;--ink:#e7edf3;--muted:#8996a4;--faint:#5c6774;--line:#242e3a;
  --accent:#42c1d4;--accent-dim:#42c1d422;
  --crit:#f0506e;--high:#f2914b;--med:#e6b84f;--low:#5fa9c8;--info:#7f8d9c;--ok:#54c98a;
  --crit-bg:#f0506e1f;--high-bg:#f2914b1c;--med-bg:#e6b84f1a;--low-bg:#5fa9c81a;--info-bg:#7f8d9c17;--ok-bg:#54c98a17;
  --shadow:0 1px 2px #0006,0 10px 30px #0004;
}}
:root[data-theme="dark"]{
  --ground:#0d1015;--panel:#141a21;--panel2:#0f151b;--ink:#e7edf3;--muted:#8996a4;--faint:#5c6774;--line:#242e3a;
  --accent:#42c1d4;--accent-dim:#42c1d422;
  --crit:#f0506e;--high:#f2914b;--med:#e6b84f;--low:#5fa9c8;--info:#7f8d9c;--ok:#54c98a;
  --crit-bg:#f0506e1f;--high-bg:#f2914b1c;--med-bg:#e6b84f1a;--low-bg:#5fa9c81a;--info-bg:#7f8d9c17;--ok-bg:#54c98a17;
  --shadow:0 1px 2px #0006,0 10px 30px #0004;
}
*{box-sizing:border-box;margin:0}
body{background:var(--ground);color:var(--ink);font-family:"IBM Plex Sans",system-ui,sans-serif;font-size:14px;line-height:1.5;-webkit-font-smoothing:antialiased}
.mono{font-family:"IBM Plex Mono",ui-monospace,monospace;font-variant-numeric:tabular-nums}
.wrap{max-width:1140px;margin:0 auto;padding:20px 22px 60px}
.top{display:flex;align-items:center;gap:14px;flex-wrap:wrap;padding-bottom:16px;border-bottom:1px solid var(--line);margin-bottom:20px}
.brand{display:flex;align-items:center;gap:10px}
.glyph{width:25px;height:25px;flex:none}
.brand h1{font-size:15px;font-weight:600;letter-spacing:.14em;text-transform:uppercase}
.brand h1 span{color:var(--accent)}
.live{display:flex;align-items:center;gap:7px;font-size:11px;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);padding:4px 10px;border:1px solid var(--line);border-radius:100px}
.dot{width:7px;height:7px;border-radius:50%;background:var(--ok);animation:pulse 2.4s infinite}
@keyframes pulse{0%{box-shadow:0 0 0 0 var(--ok-bg)}70%{box-shadow:0 0 0 7px transparent}100%{box-shadow:0 0 0 0 transparent}}
@media (prefers-reduced-motion:reduce){.dot{animation:none}}
.who{margin-left:auto;display:flex;align-items:center;gap:9px;font-size:12px;color:var(--muted)}
.avatar{width:26px;height:26px;border-radius:50%;background:var(--accent-dim);color:var(--accent);display:grid;place-items:center;font-weight:600;font-size:12px;font-family:"IBM Plex Mono",monospace}
.who b{color:var(--ink);font-weight:600}
.navlink{background:var(--panel);border:1px solid var(--line);color:var(--muted);font:inherit;font-size:12px;cursor:pointer;border-radius:8px;padding:6px 11px}
.navlink:hover{color:var(--accent);border-color:var(--accent)}
.navlink:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.audit{width:100%;border-collapse:collapse;font-size:12.5px}
.audit th{text-align:left;font-size:10px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);font-weight:600;padding:0 12px 9px}
.audit td{padding:10px 12px;border-top:1px solid var(--line);vertical-align:top}
.audit tr:hover td{background:var(--panel2)}
.audit .sv{font-family:"IBM Plex Mono",monospace;font-weight:600;font-size:11px}
.audit .who{font-weight:600;color:var(--ink)}
.audit .whn{color:var(--faint);white-space:nowrap}
.audit .nt{color:var(--muted)}
.audit .hst{font-family:"IBM Plex Mono",monospace}
.audit-wrap{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:8px 6px;box-shadow:var(--shadow);overflow-x:auto}
.themebtn{display:inline-grid;place-items:center;width:32px;height:32px;border-radius:8px;border:1px solid var(--line);background:var(--panel);color:var(--muted);cursor:pointer;padding:0}
.themebtn:hover{color:var(--accent);border-color:var(--accent)}
.themebtn:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
/* default (dark host / dark toggle): show the sun (click for light) */
.themebtn .moon{display:none}
.themebtn .sun,.themebtn .sun-rays{display:initial}
/* when the page is LIGHT, show the moon (click for dark) */
:root[data-theme="light"] .themebtn .moon{display:initial}
:root[data-theme="light"] .themebtn .sun,:root[data-theme="light"] .themebtn .sun-rays{display:none}
@media (prefers-color-scheme:light){:root:not([data-theme="dark"]) .themebtn .moon{display:initial}
:root:not([data-theme="dark"]) .themebtn .sun,:root:not([data-theme="dark"]) .themebtn .sun-rays{display:none}}
.summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;margin-bottom:18px}
.stat{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px 14px;box-shadow:var(--shadow)}
.stat .n{font-size:24px;font-weight:600;line-height:1}
.stat .k{font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);margin-top:6px}
.stat.crit .n{color:var(--crit)}.stat.ok .n{color:var(--ok)}
.sect-h{font-size:11px;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);margin-bottom:11px;display:flex;justify-content:space-between;align-items:baseline}
.sect-h .hint{color:var(--faint);text-transform:none;letter-spacing:0;font-size:11.5px}
.hosts{display:flex;flex-direction:column;gap:9px}
.host{width:100%;text-align:left;color:inherit;font:inherit;cursor:pointer;background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--sv);border-radius:10px;padding:13px 15px;display:grid;grid-template-columns:64px 1fr auto;gap:14px;align-items:center;box-shadow:var(--shadow);transition:background .12s,border-color .12s}
.host:hover{background:var(--panel2);border-color:var(--accent)}
.host:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.gauge{width:56px;height:56px;position:relative;display:grid;place-items:center}
.gauge svg{position:absolute;inset:0;transform:rotate(-90deg)}
.gauge .val{font-family:"IBM Plex Mono",monospace;font-weight:600;font-size:18px}
.hmeta .name{font-weight:600;font-size:15px;font-family:"IBM Plex Mono",monospace}
.hmeta .role{color:var(--muted);font-size:12.5px;margin-top:1px}
.hmeta .role .ip{color:var(--faint)}
.hmini{display:flex;flex-direction:column;align-items:flex-end;gap:6px}
.band{font-size:10px;letter-spacing:.09em;text-transform:uppercase;font-weight:700;color:var(--sv)}
.sevmini{display:flex;gap:3px}
.sevmini i{width:16px;height:6px;border-radius:2px;background:var(--line)}
.hcount{font-size:11.5px;color:var(--faint)}
.hidden{display:none}
.back{background:none;border:1px solid var(--line);color:var(--muted);font:inherit;cursor:pointer;border-radius:8px;padding:6px 12px;display:inline-flex;align-items:center;gap:7px;margin-bottom:16px}
.back:hover{border-color:var(--accent);color:var(--accent)}
.hostbar{display:flex;align-items:center;gap:14px;flex-wrap:wrap;background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--sv);border-radius:11px;padding:14px 16px;margin-bottom:18px;box-shadow:var(--shadow)}
.hostbar .big{font-family:"IBM Plex Mono",monospace;font-weight:600;font-size:30px;color:var(--sv);line-height:1}
.hostbar .hn{font-family:"IBM Plex Mono",monospace;font-weight:600;font-size:17px}
.hostbar .hr{color:var(--muted);font-size:12.5px;margin-top:2px}
.hostbar .tags{margin-left:auto;display:flex;gap:8px;flex-wrap:wrap;font-size:11.5px;color:var(--muted)}
.hostbar .tags span{border:1px solid var(--line);border-radius:100px;padding:3px 10px}
.grid{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1.12fr);gap:18px}
@media (max-width:820px){.grid{grid-template-columns:1fr}}
.feed{display:flex;flex-direction:column;gap:8px}
.inc{width:100%;text-align:left;color:inherit;font:inherit;background:var(--panel);border:1px solid var(--line);border-left:3px solid var(--sv);border-radius:9px;padding:11px 13px;cursor:pointer;display:grid;grid-template-columns:auto 1fr auto;gap:4px 12px;align-items:center;box-shadow:var(--shadow);transition:background .12s,border-color .12s}
.inc:hover{background:var(--panel2)}.inc[aria-selected="true"]{border-color:var(--accent);background:var(--panel2)}
.inc:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.inc .badge{grid-row:1/3;font-family:"IBM Plex Mono",monospace;font-weight:600;width:42px;height:42px;border-radius:8px;display:grid;place-items:center;font-size:16px;background:var(--sv-bg);color:var(--sv)}
.inc .subj{font-weight:600}.inc .subj em{font-style:normal;color:var(--faint);font-weight:400}
.inc .sv-tag{font-size:10px;letter-spacing:.08em;text-transform:uppercase;color:var(--sv);font-weight:600;justify-self:end}
.inc .line{grid-column:2/4;color:var(--muted);font-size:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.inc .chips{grid-column:2/4;display:flex;gap:5px;flex-wrap:wrap;margin-top:3px}
.tk{font-family:"IBM Plex Mono",monospace;font-size:10.5px;padding:1px 6px;border-radius:5px;background:var(--accent-dim);color:var(--accent);font-weight:500}
.detail{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:18px;box-shadow:var(--shadow);position:sticky;top:16px}
.detail.empty{color:var(--faint);text-align:center;padding:50px 18px}
.d-head{display:flex;align-items:flex-start;gap:14px;padding-bottom:14px;border-bottom:1px solid var(--line)}
.d-badge{font-family:"IBM Plex Mono",monospace;font-weight:600;font-size:20px;width:54px;height:54px;border-radius:10px;display:grid;place-items:center;flex:none;background:var(--sv-bg);color:var(--sv)}
.d-head .t{flex:1;min-width:0}.d-head .scn{font-size:15px;font-weight:600}
.d-head .meta{color:var(--muted);font-size:12px;margin-top:3px;word-break:break-word}
.d-sv{font-size:11px;letter-spacing:.09em;text-transform:uppercase;color:var(--sv);font-weight:700;text-align:right;flex:none}
.sec{margin-top:16px}.sec>h4{font-size:11px;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);margin-bottom:9px}
.chain{display:flex;flex-wrap:wrap;align-items:center;gap:4px;font-size:12.5px}
.node{font-family:"IBM Plex Mono",monospace;padding:3px 8px;border-radius:6px;background:var(--panel2);border:1px solid var(--line);white-space:nowrap}
.node.tip{background:var(--sv-bg);border-color:transparent;color:var(--sv);font-weight:600}
.arrow{color:var(--faint)}
.sig{display:grid;grid-template-columns:auto 1fr auto;gap:10px;align-items:baseline;padding:9px 0;border-bottom:1px dashed var(--line)}
.sig:last-child{border-bottom:0}
.sig .id{font-family:"IBM Plex Mono",monospace;font-size:12px;font-weight:600;color:var(--accent)}
.sig .txt{color:var(--muted);font-size:12px;min-width:0;overflow-wrap:anywhere}
.sig .pts{font-family:"IBM Plex Mono",monospace;font-weight:600;white-space:nowrap}
/* The command that produced a signal. Monospace, dimmed, prefixed with a
   prompt glyph so it reads as "this is what ran" at a glance. */
.yrow{display:grid;grid-template-columns:auto 1fr;gap:9px;align-items:start;padding:7px 0;border-bottom:1px dashed var(--line)}
.yrow:last-of-type{border-bottom:0}
.yrow code.cmd{margin-top:0}
.ymark{font-family:"IBM Plex Mono",monospace;font-size:10px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;
  padding:3px 7px;border-radius:4px;white-space:nowrap;color:#c0392b;background:#c0392b18;border:1px solid #c0392b44}
.ymark.ok{color:var(--muted);background:transparent;border-color:var(--line)}
.ymark.raced{color:var(--faint);background:transparent;border-color:var(--line)}
.yrules{grid-column:2;display:flex;gap:5px;flex-wrap:wrap;margin-top:5px}
.faintnote{color:var(--faint);font-size:11.5px}
.ynote{color:var(--faint);font-size:11px;margin-top:9px}
.sigtime{display:block;margin-top:5px;font-size:11px;color:var(--faint);letter-spacing:.02em}
.sigtime i{font-style:normal;color:var(--accent);margin-left:6px}
.itime{font-size:11px;color:var(--faint);white-space:nowrap;margin-left:auto;align-self:center}
.d-head .when{color:var(--faint);font-size:11.5px;margin-top:3px}
.atag{display:inline-block;font-family:"IBM Plex Mono",monospace;font-size:10px;font-weight:600;
  letter-spacing:.06em;text-transform:uppercase;padding:2px 7px;border-radius:100px;vertical-align:middle;
  border:1px solid transparent}
.atag.live{color:#1f9d55;background:#1f9d5518;border-color:#1f9d5533}
.atag.stale{color:#c47f17;background:#c47f1718;border-color:#c47f1733}
.atag.silent{color:#c0392b;background:#c0392b18;border-color:#c0392b44}
.atag.unknown{color:var(--faint);border-color:var(--line)}
.host.dark{opacity:.72}
.host.dark .name{color:var(--muted)}
.hostwarn{margin:10px 0 16px;padding:10px 13px;border-radius:7px;font-size:12.5px;line-height:1.5;
  color:var(--ink);background:#c0392b14;border:1px solid #c0392b40;border-left:3px solid #c0392b}
.hostwarn b{color:#c0392b}
.hostwarn.hidden{display:none}
code.cmd{display:block;margin-top:5px;font-family:"IBM Plex Mono",monospace;font-size:11.5px;
  color:var(--ink);background:var(--panel2);border:1px solid var(--line);border-left:2px solid var(--accent);
  border-radius:4px;padding:5px 8px;overflow-wrap:anywhere;white-space:pre-wrap}
code.cmd::before{content:"$ ";color:var(--faint)}
/* A scan target is a path, not something that was typed. */
code.cmd.path::before{content:"";}
code.cmd.hero{margin-top:8px;font-size:12px}
.cmds{margin-top:10px;display:flex;flex-direction:column;gap:5px}
.cmdrow{display:grid;grid-template-columns:auto 1fr;gap:8px;align-items:start}
.cmdrow .cpid{font-size:11px;color:var(--faint);padding-top:8px;min-width:44px;text-align:right}
.cmdrow code.cmd{margin-top:0}
.math{display:flex;align-items:center;gap:8px;flex-wrap:wrap;font-family:"IBM Plex Mono",monospace;font-size:12.5px;color:var(--muted);background:var(--panel2);border:1px solid var(--line);border-radius:8px;padding:10px 12px}
.math b{color:var(--ink)}.math .eq{color:var(--sv);font-weight:600;font-size:15px}.math .note{color:var(--faint);font-size:11px}
.attgrid{display:flex;flex-direction:column;gap:7px}.att{display:flex;align-items:center;gap:10px}
.att .id{font-family:"IBM Plex Mono",monospace;font-weight:600;font-size:12px;color:var(--accent);background:var(--accent-dim);padding:2px 7px;border-radius:5px;min-width:78px;text-align:center}
.att .nm{font-size:13px}
.inc.resolved{opacity:.5}
.inc .rtag{grid-column:2/4;font-size:10px;letter-spacing:.06em;text-transform:uppercase;color:var(--ok);font-weight:600;margin-top:2px}
.resolvebar{display:flex;gap:10px;align-items:center;margin-top:16px;padding-top:14px;border-top:1px solid var(--line)}
.resolvebar input{flex:1;padding:8px 10px;border:1px solid var(--line);border-radius:8px;background:var(--panel2);color:var(--ink);font:inherit;font-size:12px}
.resolvebar input:focus{outline:2px solid var(--accent);outline-offset:1px}
.resolvebtn{border:0;border-radius:8px;padding:8px 14px;background:var(--ok);color:#fff;font:inherit;font-weight:600;cursor:pointer;white-space:nowrap}
.resolvebtn:hover{filter:brightness(1.08)}
.resolved-note{margin-top:16px;padding-top:14px;border-top:1px solid var(--line);color:var(--muted);font-size:12px}
.resolved-note b{color:var(--ok)}
.adduser{display:flex;gap:8px;align-items:center;flex-wrap:wrap;background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px;box-shadow:var(--shadow)}
.adduser input,.adduser select{padding:8px 10px;border:1px solid var(--line);border-radius:8px;background:var(--panel2);color:var(--ink);font:inherit;font-size:12px}
.adduser input{flex:1;min-width:120px}
.uerr{color:var(--crit);font-size:12px}
.udel{background:none;border:1px solid var(--line);color:var(--muted);border-radius:7px;padding:3px 9px;font:inherit;font-size:11px;cursor:pointer}
.udel:hover{border-color:var(--crit);color:var(--crit)}
.who .avatar{cursor:default}
.foot{margin-top:26px;padding-top:16px;border-top:1px solid var(--line);color:var(--faint);font-size:11.5px;line-height:1.65}
.foot code{font-family:"IBM Plex Mono",monospace;color:var(--muted);background:var(--panel2);padding:1px 5px;border-radius:4px}

.login{position:fixed;inset:0;display:grid;place-items:center;background:var(--ground);z-index:10}
.login form{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:28px;
  width:320px;box-shadow:var(--shadow);text-align:center}
.login .glyph{width:34px;height:34px;margin:0 auto 12px}
.login h2{font-size:15px;font-weight:600;letter-spacing:.1em;text-transform:uppercase;margin-bottom:4px}
.login h2 span{color:var(--accent)}
.login p{color:var(--muted);font-size:12px;margin-bottom:18px}
.login input{width:100%;padding:10px 12px;border:1px solid var(--line);border-radius:8px;
  background:var(--panel2);color:var(--ink);font:inherit;margin-bottom:10px}
.login input:focus{outline:2px solid var(--accent);outline-offset:1px}
.login button{width:100%;padding:10px;border:0;border-radius:8px;background:var(--accent);color:#fff;
  font:inherit;font-weight:600;cursor:pointer}
.login .err{color:var(--crit);font-size:12px;min-height:16px;margin-top:8px}
</style>
<div class="login" id="login">
  <form id="loginform">
    <svg class="glyph" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path d="M12 2 3.5 5.2v6.2c0 4.7 3.3 8.4 8.5 10.4 5.2-2 8.5-5.7 8.5-10.4V5.2L12 2Z" stroke="var(--accent)" stroke-width="1.6" stroke-linejoin="round"/>
      <path d="M8 12.2l2.6 2.6L16 9.4" stroke="var(--accent)" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>
    <h2>Kernel<span>Sentinel</span></h2>
    <p>Sign in to view fleet reports</p>
    <input type="text" id="lu" placeholder="Username" autocomplete="username" autofocus>
    <input type="password" id="pw" placeholder="Password" autocomplete="current-password">
    <button type="submit">Sign in</button>
    <div class="err" id="loginerr"></div>
  </form>
</div>
<div class="wrap">
  <header class="top">
    <div class="brand">
      <svg class="glyph" viewBox="0 0 24 24" fill="none" aria-hidden="true">
        <path d="M12 2 3.5 5.2v6.2c0 4.7 3.3 8.4 8.5 10.4 5.2-2 8.5-5.7 8.5-10.4V5.2L12 2Z" stroke="var(--accent)" stroke-width="1.6" stroke-linejoin="round"/>
        <path d="M8 12.2l2.6 2.6L16 9.4" stroke="var(--accent)" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
      <h1>Kernel<span>Sentinel</span></h1>
    </div>
    <span class="live"><span class="dot"></span><span id="agentcount">agents</span></span>
    <button id="userslink" class="navlink hidden" type="button">Users</button>
    <button id="auditlink" class="navlink" type="button">Audit log</button>
    <button id="themebtn" class="themebtn" type="button" title="Toggle light / dark" aria-label="Toggle theme">
      <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" aria-hidden="true">
        <circle class="sun" cx="12" cy="12" r="4.2"/>
        <g class="sun-rays"><path d="M12 2.5V4.5M12 19.5V21.5M4.5 12H2.5M21.5 12H19.5M5.6 5.6 7 7M17 17l1.4 1.4M18.4 5.6 17 7M7 17l-1.4 1.4"/></g>
        <path class="moon" d="M20 13.5A7.5 7.5 0 0 1 10.5 4 7.5 7.5 0 1 0 20 13.5Z" fill="currentColor" stroke="none"/>
      </svg>
    </button>
    <div class="who"><span>signed in as</span><b id="whoami">—</b><button id="logoutbtn" class="navlink" type="button" title="Sign out">Sign out</button><span class="avatar" id="avatar">?</span></div>
  </header>
  <div id="fleet">
    <div class="summary" id="fstats"></div>
    <div class="sect-h"><span>Hosts</span><span class="hint">ranked by risk score · click a host to audit its activity</span></div>
    <div class="hosts" id="hostlist"></div>
  </div>
  <div id="hostview" class="hidden">
    <button class="back" id="back">← all hosts</button>
    <div class="hostbar" id="hostbar"></div>
    <div class="hostwarn hidden" id="hostwarn"></div>
    <div class="grid">
      <section>
        <div class="sect-h"><span>Incidents</span><span class="hint" id="hicount"></span></div>
        <div class="feed" id="feed"></div>
      </section>
      <section>
        <div class="sect-h"><span>Detail</span><span class="hint">click to inspect</span></div>
        <div class="detail empty" id="detail">Select an incident to see its lineage, signals, and ATT&amp;CK mapping.</div>
      </section>
    </div>
  </div>
  <div id="auditview" class="hidden">
    <button class="back" id="auditback">← all hosts</button>
    <div class="sect-h"><span>Resolution audit trail</span><span class="hint">who resolved what, newest first · from durable history</span></div>
    <div class="audit-wrap"><table class="audit"><thead><tr><th>Resolved</th><th>Host</th><th>Incident</th><th>By</th><th>Note</th></tr></thead><tbody id="auditbody"></tbody></table></div>
  </div>
  <div id="usersview" class="hidden">
    <button class="back" id="usersback">← all hosts</button>
    <div class="sect-h"><span>Users</span><span class="hint">admins manage accounts · viewers can see reports but not manage users</span></div>
    <div class="audit-wrap" style="margin-bottom:16px"><table class="audit"><thead><tr><th>Username</th><th>Role</th><th></th></tr></thead><tbody id="usersbody"></tbody></table></div>
    <div class="adduser"><input id="nu" placeholder="Username"><input id="np" type="password" placeholder="Password (min 8)"><select id="nr"><option value="admin">admin</option><option value="viewer">viewer</option></select><button id="addbtn" class="resolvebtn" type="button">Add user</button><span id="userserr" class="uerr"></span></div>
  </div>
  <p class="foot">
    Fleet monitoring is read-only by design: each host runs the root collector, which ships NDJSON
    <em>outbound</em> to this central server over TLS with a per-host key. There is no channel back to a
    host, so the dashboard can view and audit activity but can never reach into one &mdash; no
    &ldquo;connect&rdquo; or &ldquo;spawn shell&rdquo; exists to abuse. Admins authenticate to view reports.
    <br>Incidents are real detections from committed captures; the multi-host layout is illustrative of the design.
  </p>
</div>
<script>
// theme: honor a saved choice, else follow the OS. Toggle flips and persists.
(function(){
  const saved=localStorage.getItem('ks-theme');
  if(saved)document.documentElement.setAttribute('data-theme',saved);
  document.getElementById('themebtn').addEventListener('click',()=>{
    const cur=document.documentElement.getAttribute('data-theme');
    const dark=cur?cur==='dark':matchMedia('(prefers-color-scheme: dark)').matches;
    const next=dark?'light':'dark';
    document.documentElement.setAttribute('data-theme',next);
    localStorage.setItem('ks-theme',next);
  });
})();
const SV={CRITICAL:'crit',HIGH:'high',MEDIUM:'med',LOW:'low',INFO:'info',OK:'ok'};
const svVar=s=>`var(--${SV[s]})`,svBg=s=>`var(--${SV[s]}-bg)`;
const order=['CRITICAL','HIGH','MEDIUM','LOW','INFO'];
const names={T1003:"OS Credential Dumping",T1036:"Masquerading","T1055.008":"Ptrace System Calls",T1068:"Exploitation for Privilege Escalation",T1098:"Account Manipulation",T1543:"Create/Modify System Process","T1547.006":"Kernel Modules and Extensions",T1548:"Abuse Elevation Control","T1548.001":"Setuid and Setgid",T1552:"Unsecured Credentials","T1574.006":"Dynamic Linker Hijacking",T1611:"Escape to Host",T1620:"Reflective Code Loading"};
let HOSTS=[];

async function api(path){const r=await fetch(path,{credentials:'same-origin'});if(r.status===401)throw'auth';if(!r.ok)throw r.status;return r.json();}

document.getElementById('loginform').addEventListener('submit',async e=>{
  e.preventDefault();
  const u=document.getElementById('lu').value;const pw=document.getElementById('pw').value;
  const r=await fetch('/api/login',{method:'POST',credentials:'same-origin',
    headers:{'Content-Type':'application/x-www-form-urlencoded'},
    body:'username='+encodeURIComponent(u)+'&password='+encodeURIComponent(pw)});
  if(r.ok){showLogin(false);boot();}
  else{document.getElementById('loginerr').textContent='Incorrect password';}
});

let ME={username:'',role:''};
// The gate starts visible (CSS `display:grid`), so every authenticated path
// must dismiss it explicitly. Forgetting that on reload showed a login form on
// top of a fully loaded dashboard: the session was valid the whole time, but it
// read as being logged out.
function showLogin(on){document.getElementById('login').style.display=on?'grid':'none';}
function loginVisible(){return document.getElementById('login').style.display!=='none';}
async function boot(){
  try{HOSTS=await api('/api/fleet');}catch(e){if(e==='auth'){showLogin(true);return;}HOSTS=[];}
  showLogin(false);
  try{ME=await api('/api/me');}catch(e){}
  document.getElementById('whoami').textContent=ME.username||'—';
  document.getElementById('avatar').textContent=(ME.username||'?').slice(0,1).toUpperCase();
  document.getElementById('userslink').classList.toggle('hidden',ME.role!=='admin');
  renderFleet();
  startLive();
}

// Live updates via long-poll: hold a request open; the server answers the moment
// an agent ships an incident, then we refresh the active view in place and poll
// again. Near-real-time, and robust behind proxies.
let LIVE=false;
function startLive(){ if(LIVE)return; LIVE=true; poll(); }
async function poll(){
  try{
    const r=await fetch('/api/poll',{credentials:'same-origin'});
    if(r.status===401){ LIVE=false; return; }   // session ended
    if(r.status===200){ await liveRefresh(); }   // an incident arrived
    // 204 = timeout, just re-poll
  }catch(e){ await new Promise(r=>setTimeout(r,3000)); }
  poll();
}
let refreshing=false;
async function liveRefresh(){
  if(refreshing)return; refreshing=true;
  try{HOSTS=await api('/api/fleet');}catch(e){refreshing=false;return;}
  renderFleet();
  if(!hostview.classList.contains('hidden')&&currentHost){const h=HOSTS.find(x=>x.host===currentHost.host);if(h)openHost(h);}
  else if(!auditview.classList.contains('hidden'))openAudit();
  refreshing=false;
}
document.getElementById('logoutbtn').addEventListener('click',async()=>{await fetch('/api/logout',{method:'POST',credentials:'same-origin'});location.reload();});
document.getElementById('userslink').addEventListener('click',openUsers);
document.getElementById('usersback').addEventListener('click',()=>showView(fleet));
document.getElementById('addbtn').addEventListener('click',async()=>{
  const u=document.getElementById('nu').value,pw=document.getElementById('np').value,r=document.getElementById('nr').value;
  const resp=await fetch('/api/users',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u,password:pw,role:r})});
  if(resp.ok){document.getElementById('nu').value='';document.getElementById('np').value='';document.getElementById('userserr').textContent='';openUsers();}
  else{document.getElementById('userserr').textContent=await resp.text();}
});
async function openUsers(){
  let users=[];try{users=await api('/api/users');}catch(e){}
  showView(usersview);
  const body=document.getElementById('usersbody');
  body.innerHTML=users.map(u=>`<tr><td class="hst">${esc(u.username)}</td><td>${esc(u.role)}</td><td style="text-align:right">${u.username===ME.username?'<span style="color:var(--faint);font-size:11px">you</span>':'<button class="udel" data-u="'+esc(u.username)+'">delete</button>'}</td></tr>`).join('');
  body.querySelectorAll('.udel').forEach(b=>b.addEventListener('click',async()=>{
    const resp=await fetch('/api/users/delete',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:b.dataset.u})});
    if(resp.ok)openUsers();else alert(await resp.text());
  }));
}
// Absolute UTC, so an incident time is unambiguous across timezones. "2m ago"
// answers "is this happening now"; the absolute stamp answers "what do I put in
// the report", and an investigation needs both.
function tsabs(ms){if(!ms)return '';const d=new Date(ms);
  const p=n=>String(n).padStart(2,'0');
  return `${d.getUTCFullYear()}-${p(d.getUTCMonth()+1)}-${p(d.getUTCDate())} ${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())} UTC`;}
// Event time when the agent could supply one, else the server's receive time.
// The two are labelled differently: conflating "when it happened" with "when we
// heard about it" is how a delayed report becomes a wrong timeline.
function incTime(d){
  if(d.ts)return {ms:d.ts,exact:true};
  if(d._received)return {ms:d._received*1000,exact:false};
  return {ms:0,exact:false};
}
// Offsets inside one incident come from the kernel's boot clock, so they are
// exact even when no wall-clock mapping exists (a replayed capture).
function offset(ns){
  if(ns<1000)return '+0ms';
  if(ns<1e9)return '+'+Math.round(ns/1e6)+'ms';
  if(ns<60e9)return '+'+(ns/1e9).toFixed(2)+'s';
  return '+'+Math.round(ns/60e9)+'m';
}
function tsago(sec){if(!sec)return '—';const d=Math.max(0,Math.floor(Date.now()/1000-sec));
  if(d<60)return d+'s ago';if(d<3600)return Math.floor(d/60)+'m ago';if(d<86400)return Math.floor(d/3600)+'h ago';return Math.floor(d/86400)+'d ago';}

// An agent that stopped reporting is a finding, not an absence of one: it is
// what a root-level attacker leaves behind after unloading the sensors. So a
// silent host counts toward "need attention" and only a live, clean agent
// counts as healthy.
function isDark(h){return h.status==='silent'||h.status==='stale';}
function renderFleet(){
  const dark=HOSTS.filter(isDark).length,
    atRisk=HOSTS.filter(h=>h.score>=50||isDark(h)).length,
    worst=HOSTS.length?Math.max(...HOSTS.map(h=>h.score)):0,
    clean=HOSTS.filter(h=>h.score===0&&!isDark(h)).length,
    openInc=HOSTS.reduce((a,h)=>a+h.n,0),
    drops=HOSTS.reduce((a,h)=>a+(h.drops||0),0);
  document.getElementById('agentcount').textContent=HOSTS.length+' agent'+(HOSTS.length===1?'':'s')+' reporting';
  const stats=[['Hosts',HOSTS.length,''],['Need attention',atRisk,'crit'],['Healthy',clean,'ok'],['Open incidents',openInc,''],['Worst score',worst,'crit']];
  if(dark)stats.splice(2,0,['Not reporting',dark,'crit']);
  // Dropped events are missed detections; say so rather than implying coverage.
  if(drops)stats.push(['Events dropped',drops,'crit']);
  document.getElementById('fstats').innerHTML=stats.map(([k,n,c])=>`<div class="stat ${c}"><div class="n mono">${n}</div><div class="k">${k}</div></div>`).join('');
  const hostlist=document.getElementById('hostlist');
  if(!HOSTS.length){hostlist.innerHTML='<div class="stat" style="text-align:center;color:var(--faint)">No agents have reported yet. Point an agent at this server with <code>kernelsentinel ship</code>.</div>';return;}
  hostlist.innerHTML=HOSTS.map((h,i)=>{const sv=isDark(h)?'var(--faint)':svVar(h.band);const bandtxt=h.score===0?'no findings':h.band;
    return `<button class="host ${isDark(h)?'dark':''}" data-i="${i}" style="--sv:${sv}">${gauge(h.score,sv)}<div class="hmeta"><div class="name">${esc(h.host)} ${agentTag(h)}</div><div class="role">${esc(h.kernel||'linux')} <span class="ip">${h.ip?'· '+esc(h.ip):''}</span></div></div><div class="hmini"><span class="band">${bandtxt}</span>${sevmini(h.counts)}<span class="hcount">${h.n?h.n+' incident'+(h.n>1?'s':''):'clean'} · ${tsago(h.last_seen)}</span></div></button>`;}).join('');
}
// Liveness is shown as its own pill, never folded into the risk score: a dead
// agent and a compromised host are different problems.
function agentTag(h){
  const st=h.status||'unknown';
  if(st==='live')return '<span class="atag live">live</span>';
  if(st==='stale')return `<span class="atag stale">no report ${tsago(h.last_heartbeat)}</span>`;
  if(st==='silent')return `<span class="atag silent">not reporting since ${tsago(h.last_heartbeat)}</span>`;
  return '<span class="atag unknown" title="This agent ships incidents but no heartbeat — likely an older build. Liveness is unknown, not bad.">no heartbeat</span>';
}
function dur(sec){
  if(sec<60)return sec+'s';
  if(sec<3600)return Math.floor(sec/60)+'m';
  if(sec<86400)return Math.floor(sec/3600)+'h';
  return Math.floor(sec/86400)+'d';
}
// Content-scan results. A match identifies what the flagged file *is*; it does
// not change the score, and the section says so rather than letting a reader
// assume the number moved. "Raced" is shown too: a memfd outlives its process by
// nothing at all, and quietly omitting a lost race would read as "clean".
function yaraSec(d){
  const rs=d.yara||[];
  if(!rs.length)return '';
  const hit=rs.filter(r=>r.outcome==='matched');
  const rows=rs.map(r=>{
    if(r.outcome==='matched')
      return `<div class="yrow hit"><span class="ymark">match</span><code class="cmd path">${esc(r.target)}</code><div class="yrules">${(r.rules||[]).map(n=>`<span class="tk">${esc(n)}</span>`).join('')}</div></div>`;
    if(r.outcome==='clean')
      return `<div class="yrow"><span class="ymark ok">clean</span><code class="cmd path">${esc(r.target)}</code></div>`;
    return `<div class="yrow"><span class="ymark raced">not scanned</span><code class="cmd path">${esc(r.target)}</code><div class="yrules faintnote">${esc(r.reason||'target was gone')}</div></div>`;
  }).join('');
  return `<div class="sec"><h4>Content scan${hit.length?` — ${hit.length} match`+(hit.length>1?'es':''):''}</h4>${rows}<div class="ynote">Identification only — matches do not change the score.</div></div>`;
}
function gauge(score,sv){const r=24,c=2*Math.PI*r,off=c*(1-score/100);return `<div class="gauge"><svg viewBox="0 0 56 56"><circle cx="28" cy="28" r="${r}" fill="none" stroke="var(--line)" stroke-width="5"/><circle cx="28" cy="28" r="${r}" fill="none" stroke="${sv}" stroke-width="5" stroke-linecap="round" stroke-dasharray="${c.toFixed(1)}" stroke-dashoffset="${off.toFixed(1)}"/></svg><span class="val" style="color:${sv}">${score}</span></div>`;}
function sevmini(counts){counts=counts||{};return `<div class="sevmini">`+order.map(s=>`<i style="background:${counts[s]>0?svVar(s):'var(--line)'}" title="${s} ${counts[s]||0}"></i>`).join('')+`</div>`;}

const fleet=document.getElementById('fleet'),hostview=document.getElementById('hostview'),auditview=document.getElementById('auditview'),usersview=document.getElementById('usersview');
// Every string below originates on a monitored host: process names, file paths,
// argv. A host is exactly what an attacker controls, so none of it may reach
// innerHTML raw -- otherwise a file named `/tmp/<img onerror=...>` executes
// script in the admin's authenticated session, which is a path from a
// compromised host back into the panel. Escape at every interpolation.
const ESCMAP={'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'};
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,c=>ESCMAP[c]);}
function showView(el){[fleet,hostview,auditview,usersview].forEach(v=>v&&v.classList.add('hidden'));el.classList.remove('hidden');window.scrollTo(0,0);}
document.getElementById('hostlist').addEventListener('click',e=>{const b=e.target.closest('.host');if(b)openHost(HOSTS[+b.dataset.i]);});
document.getElementById('back').addEventListener('click',()=>showView(fleet));

let currentHost=null;
async function openHost(h){
  currentHost=h;
  let incs=[];try{incs=await api('/api/host/'+encodeURIComponent(h.host));}catch(e){}
  showView(hostview);
  const sv=isDark(h)?'var(--faint)':svVar(h.band);const hb=document.getElementById('hostbar');hb.style.setProperty('--sv',sv);
  const tel=[];
  if(h.agent_version)tel.push('agent '+esc(h.agent_version));
  if(h.uptime_secs)tel.push('up '+dur(h.uptime_secs));
  if(h.events!=null)tel.push(h.events.toLocaleString()+' events');
  hb.innerHTML=`<span class="big">${h.score}</span><div><div class="hn">${esc(h.host)} ${agentTag(h)}</div><div class="hr">${esc(h.kernel||'linux')} ${h.ip?'· '+esc(h.ip):''}${tel.length?' · '+tel.join(' · '):''}</div></div><div class="tags"><span>${h.n} incident${h.n!==1?'s':''}</span><span>seen ${tsago(h.last_seen)}</span></div>`;
  // A drop is an event the kernel could not hand us: a hole in coverage, and
  // the one number that must never be presented quietly.
  const warn=document.getElementById('hostwarn');
  if(h.drops>0){warn.className='hostwarn';warn.innerHTML=`<b>${h.drops.toLocaleString()} events dropped</b> on this host since the agent started — the ring buffer overflowed, so some activity was never seen. Detections from this window are incomplete.`;}
  else if(h.status==='silent'||h.status==='stale'){warn.className='hostwarn';warn.innerHTML=`<b>Agent not reporting</b> — last heartbeat ${tsago(h.last_heartbeat)}. Findings below may be stale, and an agent that stops is itself worth investigating.`;}
  else{warn.className='hostwarn hidden';warn.innerHTML='';}
  const feed=document.getElementById('feed');const det=document.getElementById('detail');
  document.getElementById('hicount').textContent=incs.length?`${incs.length} on this host`:'';
  if(!incs.length){
    // "No detections" means different things depending on whether the agent is
    // actually reporting. Claiming health while the agent is dark would be the
    // exact false reassurance the heartbeat exists to prevent.
    const live=(h.status==='live'),unknown=(h.status==='unknown');
    const msg=live?'No detections on this host in the current window. Agent healthy, reporting.'
      :unknown?'No detections recorded. This agent sends no heartbeat, so its health cannot be confirmed.'
      :'No detections recorded — but this agent is not reporting, so absence of findings is not evidence of safety.';
    feed.innerHTML=`<div class="detail empty" style="position:static">${msg}</div>`;
    det.className='detail empty';
    det.textContent=live?'Nothing to inspect — this host is clean.':'Nothing to inspect — and this host is not currently reporting.';
    return;}
  feed.innerHTML=incs.map((d,i)=>{const line=(d.lineage||[]).length?d.lineage.map(esc).join('  ›  '):'(no lineage recorded)';const chips=(d.attack||[]).map(t=>`<span class="tk">${esc(t)}</span>`).join('');const rtag=d._resolved?'<span class="rtag">✓ resolved</span>':'';const t=incTime(d);
    const ttag=t.ms?`<span class="itime" title="${t.exact?'when it happened on the host':'when the server received it — the agent did not supply an event time'}">${tsago(Math.floor(t.ms/1000))}${t.exact?'':' (received)'}</span>`:'';return `<button class="inc ${d._resolved?'resolved':''}" role="option" aria-selected="false" data-i="${i}" style="--sv:${svVar(d.severity)};--sv-bg:${svBg(d.severity)}"><span class="badge">${d.score}</span><span class="subj">${esc((d.subject&&d.subject.comm)||'—')} <em>pid ${d.subject?d.subject.pid:'?'}</em></span><span class="sv-tag">${esc(d.severity)}</span><span class="line mono">${line}</span><span class="chips">${chips}${ttag}</span>${rtag}</button>`;}).join('');
  det.className='detail empty';det.textContent='Select an incident to see its lineage, signals, and ATT&CK mapping.';
  feed.querySelectorAll('.inc').forEach(btn=>btn.addEventListener('click',()=>{feed.querySelectorAll('.inc').forEach(b=>b.setAttribute('aria-selected','false'));btn.setAttribute('aria-selected','true');renderInc(incs[+btn.dataset.i]);}));
}
function renderInc(d){const det=document.getElementById('detail');det.className='detail';det.style.setProperty('--sv',svVar(d.severity));det.style.setProperty('--sv-bg',svBg(d.severity));const ld=(d.lineage_detail&&d.lineage_detail.length)?d.lineage_detail:null;
  const chain=ld?ld.map((n,i)=>{const tip=i===ld.length-1;const cmd=n.cmdline||n.exe||'';return(i?'<span class="arrow">→</span>':'')+`<span class="node ${tip?'tip':''}"${cmd?` title="${esc(cmd)}"`:''}>${esc(n.comm)}(${n.pid})</span>`;}).join('')
    :((d.lineage||[]).length?d.lineage.map((n,i)=>{const tip=i===d.lineage.length-1;return(i?'<span class="arrow">→</span>':'')+`<span class="node ${tip?'tip':''}">${esc(n)}</span>`;}).join(''):'<span class="node">process exited before lineage was captured</span>');
  // The chain as commands: what an analyst actually wants to read.
  const cmds=ld?ld.filter(n=>n.cmdline).map(n=>`<div class="cmdrow"><span class="cpid mono">${n.pid}</span><code class="cmd">${esc(n.cmdline)}</code></div>`).join(''):'';const sorted=(d.signals||[]).slice().sort((a,b)=>a.ts_ns-b.ts_ns);
  const t0=sorted.length?sorted[0].ts_ns:0;
  const sigs=sorted.map(s=>{
    const when=s.ts?tsabs(s.ts).slice(11):'';          // HH:MM:SS UTC
    const off=sorted.length>1?offset(s.ts_ns-t0):'';
    const stamp=(when||off)?`<span class="sigtime mono">${when}${when&&off?' ':''}${off?`<i>${off}</i>`:''}</span>`:'';
    return `<div class="sig"><span class="id">${esc(s.id)}</span><span class="txt">${esc(s.detail)}${s.cmdline?`<code class="cmd">${esc(s.cmdline)}</code>`:''}${stamp}</span><span class="pts">+${s.score}</span></div>`;
  }).join('');const b=d.score_breakdown||{};const mult=(b.context_mult&&Math.abs(b.context_mult-1)>0.001)?`<span>×</span><b>${b.context_mult.toFixed(2)}</b>`:'';const note=b.context_note?`<span class="note">(${esc(b.context_note)})</span>`:'';const att=(d.attack||[]).map(t=>`<div class="att"><span class="id">${esc(t)}</span><span class="nm">${esc(names[t]||t)}</span></div>`).join('');det.innerHTML=`<div class="d-head"><div class="d-badge">${d.score}</div><div class="t"><div class="scn">${esc(d.subject&&d.subject.comm||'incident')}</div><div class="meta mono">pid ${d.subject?d.subject.pid:'?'}${d.subject&&d.subject.exe?' · '+esc(d.subject.exe):''} · uid ${d.subject?d.subject.uid:'?'}</div><div class="meta when">${(()=>{const t=incTime(d);return t.ms?(t.exact?tsabs(t.ms):tsabs(t.ms)+' (server receive time — agent supplied none)'):'time unknown';})()}</div>${d.subject&&d.subject.cmdline?`<code class="cmd hero">${esc(d.subject.cmdline)}</code>`:''}</div><div class="d-sv">${esc(d.severity)}<br><span style="color:var(--faint);font-weight:400">${d.score}/100</span></div></div><div class="sec"><h4>Process lineage</h4><div class="chain">${chain}</div>${cmds?`<div class="cmds">${cmds}</div>`:''}</div><div class="sec"><h4>Signals (${(d.signals||[]).length})</h4>${sigs}</div>${yaraSec(d)}<div class="sec"><h4>Score</h4><div class="math"><span>base</span><b>${b.base??d.score}</b><span>+ chain</span><b>${b.chain_bonus??0}</b>${mult}<span class="eq">= ${d.score}</span>${note}</div></div><div class="sec"><h4>MITRE ATT&CK</h4><div class="attgrid">${att}</div></div>${resolveControl(d)}`;
  const rb=det.querySelector('.resolvebtn');
  if(rb)rb.addEventListener('click',()=>resolveIncident(d._id,det.querySelector('.rnote').value));}

function resolveControl(d){
  if(d._resolved){const when=d._resolved_at?new Date(d._resolved_at*1000).toISOString().slice(0,16).replace('T',' '):'';
    return `<div class="resolved-note">✓ <b>Resolved</b> by ${esc(d._resolved_by||'admin')} ${when?'· '+when+' UTC':''}${d._note?' · “'+esc(d._note)+'”':''}</div>`;}
  return `<div class="resolvebar"><input class="rnote" placeholder="Note (optional): false positive, acknowledged…"><button class="resolvebtn">Mark resolved</button></div>`;
}
async function resolveIncident(id,note){
  if(id==null)return;
  await fetch('/api/resolve',{method:'POST',credentials:'same-origin',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({host:currentHost.host,id,note:note||''})});
  // Refresh: re-fetch fleet (host score may have dropped) and re-open the host.
  try{HOSTS=await api('/api/fleet');}catch(e){}
  const fresh=HOSTS.find(h=>h.host===currentHost.host);
  if(fresh){openHost(fresh);}else{document.getElementById('back').click();renderFleet();}
}

document.getElementById('auditlink').addEventListener('click',openAudit);
document.getElementById('auditback').addEventListener('click',()=>{document.getElementById('auditview').classList.add('hidden');fleet.classList.remove('hidden');window.scrollTo(0,0);});
async function openAudit(){
  let rows=[];try{rows=await api('/api/audit');}catch(e){}
  showView(auditview);
  const body=document.getElementById('auditbody');
  if(!rows.length){body.innerHTML='<tr><td colspan="5" style="color:var(--faint);text-align:center;padding:30px">No incidents have been resolved yet.</td></tr>';return;}
  body.innerHTML=rows.map(r=>{
    const when=r.resolved_at?new Date(r.resolved_at*1000).toISOString().slice(0,16).replace('T',' ')+' UTC':'—';
    return `<tr><td class="whn">${when}</td><td class="hst">${esc(r.host)}</td>
      <td><span class="sv" style="color:${svVar(r.severity)}">${esc(r.severity)} ${r.score}</span> ${esc(r.subject||'')}</td>
      <td class="who">${esc(r.resolved_by||'admin')}</td><td class="nt">${r.note?'“'+esc(r.note)+'”':'—'}</td></tr>`;
  }).join('');
}
boot();
// Safety-net poll in case SSE is unavailable (e.g. a proxy buffers it).
setInterval(()=>{if(!loginVisible()){liveRefresh();}},60000);
</script>
"####;

#[cfg(test)]
mod tests {
    use super::PAGE;

    /// The login gate defaults to visible in CSS, so every authenticated path
    /// must dismiss it. When `boot()` stopped doing that, a reload rendered the
    /// full dashboard and then covered it with a login form -- the session had
    /// been valid the whole time, which made it look like sessions were broken.
    /// These are string checks, not behaviour, but they catch the exact
    /// deletion that caused the regression.
    #[test]
    fn boot_dismisses_the_login_gate() {
        let boot = PAGE
            .split("async function boot()")
            .nth(1)
            .expect("boot() must exist");
        let body = &boot[..boot.find("\n}").unwrap_or(boot.len())];
        assert!(
            body.contains("showLogin(false)"),
            "boot() must hide the login gate for an existing session, or a \
             reload shows the login form over a working dashboard"
        );
    }

    /// The gate's visibility is set through one helper; a raw style assignment
    /// elsewhere is how the two paths drifted apart in the first place.
    #[test]
    fn login_visibility_goes_through_the_helper() {
        assert!(PAGE.contains("function showLogin(on)"));
        assert_eq!(
            PAGE.matches("getElementById('login').style.display")
                .count(),
            2,
            "only showLogin() and loginVisible() may touch the gate's display"
        );
    }
}
