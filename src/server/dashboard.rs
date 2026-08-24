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
    <input type="password" id="pw" placeholder="Admin password" autocomplete="current-password" autofocus>
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
    <button id="auditlink" class="navlink" type="button">Audit log</button>
    <button id="themebtn" class="themebtn" type="button" title="Toggle light / dark" aria-label="Toggle theme">
      <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" aria-hidden="true">
        <circle class="sun" cx="12" cy="12" r="4.2"/>
        <g class="sun-rays"><path d="M12 2.5V4.5M12 19.5V21.5M4.5 12H2.5M21.5 12H19.5M5.6 5.6 7 7M17 17l1.4 1.4M18.4 5.6 17 7M7 17l-1.4 1.4"/></g>
        <path class="moon" d="M20 13.5A7.5 7.5 0 0 1 10.5 4 7.5 7.5 0 1 0 20 13.5Z" fill="currentColor" stroke="none"/>
      </svg>
    </button>
    <div class="who"><span>signed in as</span><b>admin@soc</b><span class="avatar">A</span></div>
  </header>
  <div id="fleet">
    <div class="summary" id="fstats"></div>
    <div class="sect-h"><span>Hosts</span><span class="hint">ranked by risk score · click a host to audit its activity</span></div>
    <div class="hosts" id="hostlist"></div>
  </div>
  <div id="hostview" class="hidden">
    <button class="back" id="back">← all hosts</button>
    <div class="hostbar" id="hostbar"></div>
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
  const pw=document.getElementById('pw').value;
  const r=await fetch('/api/login',{method:'POST',credentials:'same-origin',
    headers:{'Content-Type':'application/x-www-form-urlencoded'},
    body:'password='+encodeURIComponent(pw)});
  if(r.ok){document.getElementById('login').style.display='none';boot();}
  else{document.getElementById('loginerr').textContent='Incorrect password';}
});

async function boot(){
  try{HOSTS=await api('/api/fleet');}catch(e){if(e==='auth'){document.getElementById('login').style.display='grid';return;}HOSTS=[];}
  renderFleet();
}
function tsago(sec){if(!sec)return '—';const d=Math.max(0,Math.floor(Date.now()/1000-sec));
  if(d<60)return d+'s ago';if(d<3600)return Math.floor(d/60)+'m ago';if(d<86400)return Math.floor(d/3600)+'h ago';return Math.floor(d/86400)+'d ago';}

function renderFleet(){
  const atRisk=HOSTS.filter(h=>h.score>=50).length,worst=HOSTS.length?Math.max(...HOSTS.map(h=>h.score)):0,
    clean=HOSTS.filter(h=>h.score===0).length,openInc=HOSTS.reduce((a,h)=>a+h.n,0);
  document.getElementById('agentcount').textContent=HOSTS.length+' agent'+(HOSTS.length===1?'':'s')+' reporting';
  document.getElementById('fstats').innerHTML=[['Hosts',HOSTS.length,''],['Need attention',atRisk,'crit'],['Healthy',clean,'ok'],['Open incidents',openInc,''],['Worst score',worst,'crit']].map(([k,n,c])=>`<div class="stat ${c}"><div class="n mono">${n}</div><div class="k">${k}</div></div>`).join('');
  const hostlist=document.getElementById('hostlist');
  if(!HOSTS.length){hostlist.innerHTML='<div class="stat" style="text-align:center;color:var(--faint)">No agents have reported yet. Point an agent at this server with <code>kernelsentinel ship</code>.</div>';return;}
  hostlist.innerHTML=HOSTS.map((h,i)=>{const sv=svVar(h.band);const bandtxt=h.score===0?'no findings':h.band;
    return `<button class="host" data-i="${i}" style="--sv:${sv}">${gauge(h.score,sv)}<div class="hmeta"><div class="name">${h.host}</div><div class="role">${h.kernel||'linux'} <span class="ip">${h.ip?'· '+h.ip:''}</span></div></div><div class="hmini"><span class="band">${bandtxt}</span>${sevmini(h.counts)}<span class="hcount">${h.n?h.n+' incident'+(h.n>1?'s':''):'clean'} · ${tsago(h.last_seen)}</span></div></button>`;}).join('');
}
function gauge(score,sv){const r=24,c=2*Math.PI*r,off=c*(1-score/100);return `<div class="gauge"><svg viewBox="0 0 56 56"><circle cx="28" cy="28" r="${r}" fill="none" stroke="var(--line)" stroke-width="5"/><circle cx="28" cy="28" r="${r}" fill="none" stroke="${sv}" stroke-width="5" stroke-linecap="round" stroke-dasharray="${c.toFixed(1)}" stroke-dashoffset="${off.toFixed(1)}"/></svg><span class="val" style="color:${sv}">${score}</span></div>`;}
function sevmini(counts){counts=counts||{};return `<div class="sevmini">`+order.map(s=>`<i style="background:${counts[s]>0?svVar(s):'var(--line)'}" title="${s} ${counts[s]||0}"></i>`).join('')+`</div>`;}

const fleet=document.getElementById('fleet'),hostview=document.getElementById('hostview');
document.getElementById('hostlist').addEventListener('click',e=>{const b=e.target.closest('.host');if(b)openHost(HOSTS[+b.dataset.i]);});
document.getElementById('back').addEventListener('click',()=>{hostview.classList.add('hidden');fleet.classList.remove('hidden');window.scrollTo(0,0);});

let currentHost=null;
async function openHost(h){
  currentHost=h;
  let incs=[];try{incs=await api('/api/host/'+encodeURIComponent(h.host));}catch(e){}
  fleet.classList.add('hidden');hostview.classList.remove('hidden');window.scrollTo(0,0);
  const sv=svVar(h.band);const hb=document.getElementById('hostbar');hb.style.setProperty('--sv',sv);
  hb.innerHTML=`<span class="big">${h.score}</span><div><div class="hn">${h.host}</div><div class="hr">${h.kernel||'linux'} ${h.ip?'· '+h.ip:''}</div></div><div class="tags"><span>${h.n} incident${h.n!==1?'s':''}</span><span>seen ${tsago(h.last_seen)}</span></div>`;
  const feed=document.getElementById('feed');const det=document.getElementById('detail');
  document.getElementById('hicount').textContent=incs.length?`${incs.length} on this host`:'';
  if(!incs.length){feed.innerHTML='<div class="detail empty" style="position:static">No detections on this host in the current window. Agent healthy, reporting.</div>';det.className='detail empty';det.textContent='Nothing to inspect — this host is clean.';return;}
  feed.innerHTML=incs.map((d,i)=>{const line=(d.lineage||[]).length?d.lineage.join('  ›  '):'(no lineage recorded)';const chips=(d.attack||[]).map(t=>`<span class="tk">${t}</span>`).join('');const rtag=d._resolved?'<span class="rtag">✓ resolved</span>':'';return `<button class="inc ${d._resolved?'resolved':''}" role="option" aria-selected="false" data-i="${i}" style="--sv:${svVar(d.severity)};--sv-bg:${svBg(d.severity)}"><span class="badge">${d.score}</span><span class="subj">${(d.subject&&d.subject.comm)||'—'} <em>pid ${d.subject?d.subject.pid:'?'}</em></span><span class="sv-tag">${d.severity}</span><span class="line mono">${line}</span><span class="chips">${chips}</span>${rtag}</button>`;}).join('');
  det.className='detail empty';det.textContent='Select an incident to see its lineage, signals, and ATT&CK mapping.';
  feed.querySelectorAll('.inc').forEach(btn=>btn.addEventListener('click',()=>{feed.querySelectorAll('.inc').forEach(b=>b.setAttribute('aria-selected','false'));btn.setAttribute('aria-selected','true');renderInc(incs[+btn.dataset.i]);}));
}
function renderInc(d){const det=document.getElementById('detail');det.className='detail';det.style.setProperty('--sv',svVar(d.severity));det.style.setProperty('--sv-bg',svBg(d.severity));const chain=(d.lineage||[]).length?d.lineage.map((n,i)=>{const tip=i===d.lineage.length-1;return(i?'<span class="arrow">→</span>':'')+`<span class="node ${tip?'tip':''}">${n}</span>`;}).join(''):'<span class="node">process exited before lineage was captured</span>';const sigs=(d.signals||[]).slice().sort((a,b)=>a.ts_ns-b.ts_ns).map(s=>`<div class="sig"><span class="id">${s.id}</span><span class="txt">${s.detail}</span><span class="pts">+${s.score}</span></div>`).join('');const b=d.score_breakdown||{};const mult=(b.context_mult&&Math.abs(b.context_mult-1)>0.001)?`<span>×</span><b>${b.context_mult.toFixed(2)}</b>`:'';const note=b.context_note?`<span class="note">(${b.context_note})</span>`:'';const att=(d.attack||[]).map(t=>`<div class="att"><span class="id">${t}</span><span class="nm">${names[t]||t}</span></div>`).join('');det.innerHTML=`<div class="d-head"><div class="d-badge">${d.score}</div><div class="t"><div class="scn">${d.subject&&d.subject.comm||'incident'}</div><div class="meta mono">pid ${d.subject?d.subject.pid:'?'}${d.subject&&d.subject.exe?' · '+d.subject.exe:''} · uid ${d.subject?d.subject.uid:'?'}</div></div><div class="d-sv">${d.severity}<br><span style="color:var(--faint);font-weight:400">${d.score}/100</span></div></div><div class="sec"><h4>Process lineage</h4><div class="chain">${chain}</div></div><div class="sec"><h4>Signals (${(d.signals||[]).length})</h4>${sigs}</div><div class="sec"><h4>Score</h4><div class="math"><span>base</span><b>${b.base??d.score}</b><span>+ chain</span><b>${b.chain_bonus??0}</b>${mult}<span class="eq">= ${d.score}</span>${note}</div></div><div class="sec"><h4>MITRE ATT&CK</h4><div class="attgrid">${att}</div></div>${resolveControl(d)}`;
  const rb=det.querySelector('.resolvebtn');
  if(rb)rb.addEventListener('click',()=>resolveIncident(d._id,det.querySelector('.rnote').value));}

function resolveControl(d){
  if(d._resolved){const when=d._resolved_at?new Date(d._resolved_at*1000).toISOString().slice(0,16).replace('T',' '):'';
    return `<div class="resolved-note">✓ <b>Resolved</b> by ${d._resolved_by||'admin'} ${when?'· '+when+' UTC':''}${d._note?' · “'+d._note+'”':''}</div>`;}
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
  fleet.classList.add('hidden');hostview.classList.add('hidden');
  document.getElementById('auditview').classList.remove('hidden');window.scrollTo(0,0);
  const body=document.getElementById('auditbody');
  if(!rows.length){body.innerHTML='<tr><td colspan="5" style="color:var(--faint);text-align:center;padding:30px">No incidents have been resolved yet.</td></tr>';return;}
  body.innerHTML=rows.map(r=>{
    const when=r.resolved_at?new Date(r.resolved_at*1000).toISOString().slice(0,16).replace('T',' ')+' UTC':'—';
    return `<tr><td class="whn">${when}</td><td class="hst">${r.host}</td>
      <td><span class="sv" style="color:${svVar(r.severity)}">${r.severity} ${r.score}</span> ${r.subject||''}</td>
      <td class="who">${r.resolved_by||'admin'}</td><td class="nt">${r.note?'“'+r.note+'”':'—'}</td></tr>`;
  }).join('');
}
boot();
setInterval(()=>{if(document.getElementById('login').style.display==='none'||!document.getElementById('login').offsetParent){if(!hostview.classList.contains('hidden'))return;boot();}},15000);
</script>
"####;
