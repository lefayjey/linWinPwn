/* linWinPwn Web Console - frontend
   Everything is driven from the web:
     - menus/options = buttons (sidebar + action rail)
     - every question the script asks (">> " prompts, choice lists, y/N,
       "press ENTER to continue", tool consoles) = a form under the output
   The terminal is only an output view; typing in it is optional. */
(() => {
"use strict";

const TOKEN = new URLSearchParams(location.search).get("token") || "";
const qs  = (s, r=document) => r.querySelector(s);
const qsa = (s, r=document) => [...r.querySelectorAll(s)];
const api = (p, opt={}) => fetch(p + (p.includes("?")?"&":"?") + "token=" + encodeURIComponent(TOKEN),
  Object.assign({headers:{"Content-Type":"application/json","X-Auth-Token":TOKEN}}, opt));
const esc = s => String(s).replace(/[&<>"]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));

const ICONS = {globe:"🌐",sitemap:"🗂",certificate:"🏷",server:"🖧",shield:"🛡",key:"🔑",
  ticket:"🎫",folder:"📁",bug:"🐞",database:"🗄",unlock:"🔓",pencil:"✎",terminal:"⌨",
  network:"📡",fingerprint:"🔏",gear:"⚙"};

/* Menu headers printed by linWinPwn.sh -> menu id in menus.json (null = main) */
const HEADER_MAP = {
  "Main menu":null, "AD Enum menu":"ad", "ADCS menu":"adcs", "SCCM menu":"sccm",
  "GPO menu":"gpo", "BruteForce menu":"brute", "Kerberos Attacks menu":"kerberos",
  "SMB Shares menu":"shares", "Vuln Checks menu":"vulns", "MSSQL Enumeration menu":"mssql",
  "Password Dump menu":"pwd", "Modification menu":"modif", "Command Execution menu":"cmdexec",
  "Network Scan menu":"netscan", "Auth menu":"auth", "Config menu":"config",
};

let MENUS = [];
let CURRENT = null;            // menu shown in the action rail
let CUR_MENU = null;           // menu the script is actually in (from its headers)
let SESSION_RUNNING = false;
let RUN_STATE = "off";         // off | running | ready | input
let LAST_CFG = null;

/* ======================= terminals ======================= */
function makeTerm(elId, wsPath, opts={}) {
  const term = new Terminal({
    fontFamily:'ui-monospace,"JetBrains Mono",Menlo,Consolas,monospace',
    fontSize:13, cursorBlink:true, scrollback:10000, convertEol:false,
    theme:{background:"#05080c",foreground:"#d7e2f0",cursor:"#39d0d8",
           black:"#0b0f14",brightBlack:"#56687e",green:"#49c17a",cyan:"#39d0d8",
           yellow:"#f0a63a",red:"#e0625f",blue:"#7fa6e0",magenta:"#c58af0"}
  });
  const fit = new FitAddon.FitAddon();
  term.loadAddon(fit);
  try { term.loadAddon(new WebLinksAddon.WebLinksAddon()); } catch(e){}
  term.open(qs(elId));
  setTimeout(()=>{try{fit.fit();}catch(e){}}, 30);

  let ws=null, retry=null, connected=false;
  function connect() {
    const proto = location.protocol==="https:"?"wss":"ws";
    ws = new WebSocket(`${proto}://${location.host}${wsPath}?token=${encodeURIComponent(TOKEN)}`);
    ws.onopen = () => { connected=true; sendResize(); opts.onopen && opts.onopen(); };
    ws.onmessage = ev => { term.write(ev.data); opts.onoutput && opts.onoutput(ev.data); };
    ws.onclose = () => { connected=false; opts.onclose && opts.onclose();
      if(opts.autoReconnect){ clearTimeout(retry); retry=setTimeout(connect,1500);} };
    ws.onerror = () => {};
  }
  function sendResize(){ if(ws&&connected) ws.send("\x00json:"+JSON.stringify(
    {type:"resize",rows:term.rows,cols:term.cols})); }
  function send(d){ if(ws&&connected){ ws.send(d); return true;} return false; }
  term.onData(d => { if(!opts.typeable || opts.typeable()) send(d); });
  window.addEventListener("resize", ()=>{try{fit.fit();sendResize();}catch(e){}});

  return { term, connect, send,
           reconnect(){ try{ws&&ws.close();}catch(e){} connect(); },
           refit(){ try{fit.fit();sendResize();}catch(e){} } };
}

const lwpTerm = makeTerm("#termLwp","/ws/linwinpwn",{
  autoReconnect:false,
  typeable:()=>qs("#lwpTypeable").checked,
  onoutput:onLwpOutput,
});
let shellTerm = null;

/* ======================= output analysis ======================= */
const ANSI_RE = /\x1b\[[0-9;?]*[ -\/]*[@-~]|\x1b\][^\x07\x1b]*(\x07|\x1b\\)|\x1b[()][0-9A-B]|\x1b[=>]/g;
let PLAIN = "";              // ANSI-stripped rolling buffer
let LINE_ACC = "";           // partial line for history parsing
let analyzeTimer = null, consoleTimer = null;
let PROMPT_SIG = null;       // avoid re-rendering the same prompt (keeps user typing)

function onLwpOutput(data) {
  const clean = data.replace(ANSI_RE, "").replace(/\r(?!\n)/g, "\n").replace(/\r/g, "");
  PLAIN = (PLAIN + clean).slice(-20000);
  // history: complete lines only
  LINE_ACC += clean;
  const parts = LINE_ACC.split("\n"); LINE_ACC = parts.pop();
  parts.forEach(l => {
    const m = l.match(/\[i\] (?:Running|Printing) command: (.+)$/);
    if (m) addHistory(m[1].trim());
  });
  if (RUN_STATE !== "input") setRunState("running");
  clearTimeout(analyzeTimer); clearTimeout(consoleTimer);
  analyzeTimer = setTimeout(analyze, 220);
}

function analyze() {
  if (!SESSION_RUNNING) return;
  const lines = PLAIN.slice(-8000).split("\n");
  const last = lines[lines.length-1];
  const lastTrim = last.trim();

  /* 1) question: read -rp ">> " */
  if (lastTrim === ">>") {
    const ctx = collectContext(lines, lines.length-2, 14);
    return showQuestion(ctx);
  }

  /* 2) menu prompt or choice list: read -rp "> " */
  if (lastTrim === ">") {
    const block = blockAbove(lines, lines.length-2, 90);
    // module menu?
    for (let i=block.length-1;i>=0;i--) {
      const h = block[i].match(/\[([A-Za-z0-9 ]+ menu)\]/);
      if (h && h[1] in HEADER_MAP) { return menuReady(HEADER_MAP[h[1]]); }
    }
    return showChoice(block);
  }

  /* 3) "press ENTER to continue" (read -rp "") */
  if (lastTrim === "") {
    const prev = lastNonEmpty(lines, lines.length-2);
    if (prev && /press ENTER to continue/i.test(prev.text)) {
      const ctx = collectContext(lines, prev.idx-1, 6).lines;
      return showPanel({kind:"continue", title:prev.text.replace(/^\[\*\]\s*/,""),
        context:ctx.join("\n"), input:false, sig:"c"+PLAIN.length});
    }
  }

  /* 4) unterminated line that stays still = a tool console waiting for input
        (evil-winrm, smbclient, mssqlclient, ldap consoles...) */
  if (lastTrim.length > 0) {
    consoleTimer = setTimeout(() => {
      const nowLast = PLAIN.split("\n").pop();
      if (nowLast === last) showPanel({kind:"console", title:"The program is waiting for input",
        context:last, input:true, placeholder:"command / answer", sig:"k"+PLAIN.length});
    }, 900);
    return;
  }
  hidePanel(); setRunState("running");
}

function lastNonEmpty(lines, from){
  for (let i=from;i>=0 && i>from-6;i--) if (lines[i].trim()) return {idx:i, text:lines[i].trim()};
  return null;
}
/* lines above a prompt, stopping at the previous answered prompt / command */
function blockAbove(lines, from, max) {
  const out=[];
  for (let i=from;i>=0 && out.length<max;i--) {
    const t = lines[i];
    if (/^>{1,2} \S/.test(t.trim())) break;   // previous answered prompt: "> 3" / ">> foo"
    out.unshift(t);
  }
  return out;
}
function collectContext(lines, from, max) {
  const out=[];
  for (let i=from;i>=0 && out.length<max;i--) {
    const t = lines[i].trim();
    if (!t) { if (out.length) break; else continue; }
    if (/^>{1,2}( |$)/.test(t) || /(Running|Printing) command:/.test(t) || /\[[A-Za-z0-9 ]+ menu\]/.test(t)) break;
    out.unshift(t);
  }
  return {lines:out};
}

/* ======================= prompt panel ======================= */
function showQuestion(ctx) {
  const L = ctx.lines.length ? ctx.lines : ["The script is asking for a value"];
  // title: a real question line wins ("Please specify/choose...", "...?"),
  // then a "[*]/[!]/Invalid" line, then the last line. The rest is context.
  const find = re => { for (let i=L.length-1;i>=0;i--) if (re.test(L[i])) return i; return -1; };
  let ti = find(/Please (specify|choose|type|provide|enter|select)|Would you|\?\s*\)?\s*$|press Enter/i);
  if (ti < 0) ti = find(/^(\[\*\]|\[!\]|\[-\]|Invalid)/);
  if (ti < 0) ti = L.length-1;
  const title = L[ti].replace(/^\[[*!\-]\]\s*/,"");
  const others = L.filter((_,i)=>i!==ti);
  const context = others.join("\n");
  const full = L.join(" ");

  const spec = {kind:"question", title, context, input:true, choices:[], sig:"q"+PLAIN.length};
  // short single values listed above the question (IPs, names...) = suggestions
  const sugg = others.filter(t => /^[^\s:]{1,60}$/.test(t) && !/^[-=]+$/.test(t)).slice(0,12);
  if (sugg.length) spec.choices = sugg.map(s=>[s,s]);
  // default value
  let d = full.match(/press Enter to (?:choose )?default value:?\s*'?([^')]+?)'?\s*\)/i)
       || full.match(/\(default(?: value)?:?\s*'?([^')]+?)'?\s*\)/i)
       || full.match(/press Enter to ([^)]+)\)/i);
  if (d) spec.def = d[1].trim();
  // yes / no
  if (/\(y\/n\)/i.test(full)) spec.choices = [["y","Yes"],["n","No"]];
  // 'A' or 'B' / between 'A' and 'B'
  const alt = full.match(/'([^']+)' or '([^']+)'/) || full.match(/between '([^']+)' and '([^']+)'/);
  if (alt) spec.choices = [[alt[1],alt[1]],[alt[2],alt[2]]];
  // secret?
  spec.secret = /password|ntlm|hash|aes key|\bkey of\b|secret/i.test(title) && !/file|wordlist|path|list/i.test(title);
  spec.placeholder = spec.def ? `empty = ${spec.def}` : "your answer";
  showPanel(spec);
}

function showChoice(block) {
  const opts=[]; let title="Choose an option"; const ctx=[];
  block.forEach(raw => {
    const t = raw.trim(); if (!t || /^-{5,}$/.test(t)) return;
    const m = t.match(/^([\w.*]{1,6})\)\s*(.+)$/);
    if (m) opts.push([m[1]==="*"?"":m[1], m[2]]);
    else if (/Please (choose|specify|select)|provide/i.test(t)) title = t.replace(/^\[[*i]\]\s*/,"");
    else ctx.push(t);
  });
  showPanel({kind:"choice", title, context:ctx.slice(-3).join("\n"), choices:opts.filter(o=>o[0]!==""),
    input:true, placeholder:"or type a value / custom query", sig:"m"+PLAIN.length});
}

function showPanel(spec) {
  if (PROMPT_SIG === spec.sig) return;
  PROMPT_SIG = spec.sig;
  const p = qs("#promptPanel");
  qs("#ppKind").textContent = {question:"question",choice:"choice",continue:"waiting",console:"console"}[spec.kind];
  qs("#ppTitle").textContent = spec.title;
  qs("#ppContext").textContent = spec.context || "";
  const ch = qs("#ppChoices"); ch.innerHTML="";
  (spec.choices||[]).forEach(([key,label]) => {
    const b=document.createElement("button"); b.type="button"; b.className="pp-choice";
    b.innerHTML = key!==label ? `<span class="k">${esc(key)}</span>${esc(label)}` : esc(label);
    b.onclick=()=>answer(key);
    ch.appendChild(b);
  });
  const inp = qs("#ppInput");
  qs("#ppInputRow").classList.toggle("hidden", !spec.input);
  inp.value=""; inp.type = spec.secret ? "password" : "text";
  inp.placeholder = spec.placeholder || "";
  qs("#ppReveal").classList.toggle("hidden", !spec.secret);
  qs("#ppDefault").innerHTML = spec.def ? `Default: <b>${esc(spec.def)}</b>` :
    (spec.kind==="continue" ? "Click when you are ready." : "");
  qs("#ppEnter").textContent = spec.kind==="continue" ? "Continue ⏎" :
    spec.def ? "Use default ⏎" : "Send empty ⏎";
  p.classList.remove("hidden");
  setRunState("input");
  lwpTerm.refit();
  if (!qs('#mainTabs button[data-tab="lwp"]').classList.contains("active"))
    qs('#mainTabs button[data-tab="lwp"]').classList.add("attn");
  setTimeout(()=> spec.input ? inp.focus() : qs("#ppEnter").focus(), 30);
}

function hidePanel() {
  if (qs("#promptPanel").classList.contains("hidden")) return;
  qs("#promptPanel").classList.add("hidden");
  qs('#mainTabs button[data-tab="lwp"]').classList.remove("attn");
  PROMPT_SIG = null;
  lwpTerm.refit();
}

function answer(text) {
  lwpTerm.send(text + "\r");
  hidePanel();
  setRunState("running");
}

function menuReady(menuId) {
  hidePanel();
  CUR_MENU = menuId;
  const m = MENUS.find(x=>x.id===menuId);
  qs("#lwpCrumb").innerHTML = `menu: <b>${m ? esc(m.title) : "Main menu"}</b>`;
  setRunState("ready");
}

function setRunState(s) {
  if (!SESSION_RUNNING) s = "off";
  if (RUN_STATE === s) return;
  RUN_STATE = s;
  const el = qs("#runState");
  el.className = "state state-" + s;
  el.textContent = {off:"no session", running:"running…", ready:"ready", input:"waiting for your answer"}[s];
  qsa("#actionList .act").forEach(b => b.disabled = (s !== "ready"));
  qs("#lwpHome").disabled = s !== "ready" || CUR_MENU === null;
  qs("#lwpStop").disabled = s === "off";
  qs("#lwpReset").disabled = s === "off";
}

/* ======================= menu tree & actions ======================= */
function renderTree(filter="") {
  const tree = qs("#menuTree"); tree.innerHTML="";
  const f = filter.trim().toLowerCase();
  MENUS.forEach(m => {
    if (f && !(m.title.toLowerCase().includes(f) ||
               m.actions.some(a=>a.label.toLowerCase().includes(f)))) return;
    const el = document.createElement("div");
    el.className = "menu-item" + (CURRENT && CURRENT.id===m.id ? " active":"");
    const n = m.actions.filter(a=>!["A","m","P"].includes(a.key)).length;
    el.innerHTML = `<span class="mi-ico">${ICONS[m.icon]||"▸"}</span>
      <span class="mi-title">${esc(m.title)}</span><span class="mi-count">${n}</span>`;
    el.onclick = () => openMenu(m);
    tree.appendChild(el);
  });
}

function openMenu(m) {
  CURRENT = m;
  renderTree(qs("#menuFilter").value);
  qs("#railTitle").textContent = m.title;
  qs("#railDesc").textContent = m.desc || "";
  renderActions(m);
  switchTab("lwp");
}

function renderActions(m) {
  const list = qs("#actionList"); list.innerHTML="";
  const f = qs("#menuFilter").value.trim().toLowerCase();
  const pick = arr => f ? arr.filter(a=>a.label.toLowerCase().includes(f)||m.title.toLowerCase().includes(f)) : arr;
  const batch = pick(m.actions.filter(a=>a.key==="A"));
  const utils = pick(m.actions.filter(a=>a.key==="m"||a.key==="P"));
  const normal = pick(m.actions.filter(a=>!["A","m","P"].includes(a.key)));
  const sep = t => { const s=document.createElement("div"); s.className="act-sep"; s.textContent=t; list.appendChild(s); };
  const add = a => {
    const btn = document.createElement("button");
    btn.className = "act";
    let badges = "";
    if (a.noisy)   badges += `<span class="badge b-noisy">noisy</span>`;
    if (a.key==="A") badges += `<span class="badge b-batch">batch</span>`;
    if (a.console) badges += `<span class="badge b-console">console</span>`;
    if (a.prompts) badges += `<span class="badge b-prompt">form</span>`;
    btn.innerHTML = `<span class="k">${esc(a.key)}</span><span class="lbl">${esc(a.label)}</span>${badges}`;
    btn.disabled = RUN_STATE !== "ready";
    btn.title = RUN_STATE !== "ready" ? "Wait until the script is back at a menu" : a.label;
    btn.onclick = () => runAction(m, a);
    list.appendChild(btn);
  };
  if (batch.length){ sep("Quick run"); batch.forEach(add); }
  if (normal.length){ sep("Actions"); normal.forEach(add); }
  if (utils.length){ sep("Utilities"); utils.forEach(add); }
}

/* Key sequence from the menu the script is REALLY in (read from its output). */
function keySequence(m, a) {
  const keys = [];
  if (m.direct) {                         // DNS: option of the main menu
    if (CUR_MENU !== null) keys.push("back");
    keys.push(m.enter);
    return keys;
  }
  if (CUR_MENU !== m.id) {
    if (CUR_MENU !== null) keys.push("back");
    keys.push(m.enter);
  }
  keys.push(a.key);
  return keys;
}

async function runAction(m, a) {
  if (RUN_STATE !== "ready") return;
  const keys = keySequence(m, a);
  // the script will be inside this menu after the keys (confirmed again by its header)
  CUR_MENU = m.direct ? null : m.id;
  qs("#lwpCrumb").innerHTML = `menu: <b>${esc(m.direct ? "Main menu" : m.title)}</b>`;
  setRunState("running");
  const r = await api("/api/action",{method:"POST",body:JSON.stringify({keys})});
  const j = await r.json().catch(()=>({}));
  if (!j.ok) note(`action failed: ${j.error||r.status}`);
}

function note(msg){ lwpTerm.term.write(`\r\n\x1b[33m[web] ${msg}\x1b[0m\r\n`); }

/* ======================= history ======================= */
const HISTORY = [];
function addHistory(cmd) {
  if (HISTORY.length && HISTORY[HISTORY.length-1].cmd === cmd) return;
  HISTORY.push({cmd, ts:new Date().toLocaleTimeString()});
  qs("#histCount").textContent = HISTORY.length;
  const li = document.createElement("li");
  li.innerHTML = `<button class="btn btn-ghost sm">copy</button><span class="ts">${esc(HISTORY[HISTORY.length-1].ts)}</span>${esc(cmd)}`;
  li.querySelector("button").onclick = () => navigator.clipboard?.writeText(cmd);
  qs("#histList").appendChild(li);
}


/* ======================= BloodHound inventory ======================= */
/* Defensive only: inventory + AD hygiene. No attack path analysis here. */
const SEV_LABEL = {high:"high", medium:"medium", low:"low", info:"info"};

async function bhDiscover() {
  const ul = qs("#bhFoundList");
  ul.innerHTML = `<li class="dim">scanning…</li>`;
  const j = await api("/api/bh/discover").then(r=>r.json()).catch(()=>({}));
  ul.innerHTML = "";
  const rows = [];
  (j.folders||[]).forEach(f => rows.push({label:`📁 ${f.path||"/"}`, sub:`${f.count} json`, path:f.path}));
  (j.files||[]).filter(f=>f.name.toLowerCase().endsWith(".zip"))
    .forEach(f => rows.push({label:`${f.uploaded?"⬆":"🗜"} ${f.name}`,
                             sub:(f.uploaded?"uploaded · ":"") + fmtSize(f.size), path:f.path}));
  if (!rows.length) { ul.innerHTML = `<li class="dim">no BloodHound output found yet</li>`; return; }
  rows.slice(0,40).forEach(r => {
    const li = document.createElement("li");
    li.innerHTML = `<span>${esc(r.label)}</span><span class="sz">${esc(r.sub)}</span>`;
    li.onclick = () => bhScan(r.path);
    ul.appendChild(li);
  });
}

function bhBusy(msg) {
  qs("#bhError").classList.add("hidden");
  qs("#bhFoundList").innerHTML = `<li class="dim">${esc(msg)}</li>`;
}
function bhFail(msg) {
  const e = qs("#bhError"); e.textContent = msg; e.classList.remove("hidden");
  bhDiscover();
}

async function bhScan(path) {
  bhBusy("analysing " + path + " …");
  const r = await api("/api/bh/scan",{method:"POST",body:JSON.stringify({path})});
  const j = await r.json().catch(()=>({}));
  if (!j.ok) return bhFail(j.error || ("HTTP " + r.status));
  bhRender(j.report);
}

async function bhUpload(file) {
  if (!file) return;
  bhBusy("uploading " + file.name + " …");
  const fd = new FormData(); fd.append("file", file);
  const r = await fetch(`/api/bh/upload?token=${encodeURIComponent(TOKEN)}`,
    {method:"POST", headers:{"X-Auth-Token":TOKEN}, body:fd});
  const j = await r.json().catch(()=>({}));
  if (!j.ok) return bhFail(j.error || ("HTTP " + r.status));
  bhRender(j.report);
}

function bhRender(rep) {
  qs("#bhSrc").classList.add("hidden");
  qs("#bhReport").classList.remove("hidden");
  const st = rep.stats;
  qs("#bhLabel").innerHTML = `<b>${esc(st.domains.join(", ") || rep.label)}</b>` +
    (st.collected ? ` · collected ${esc(String(st.collected).slice(0,10))}` : "") +
    ` · ${esc(rep.label)}`;
  qs("#bhSevChips").innerHTML = ["high","medium","low","info"]
    .filter(k => rep.severity[k])
    .map(k => `<span class="sev-chip sev-${k}">${rep.severity[k]} ${SEV_LABEL[k]}</span>`).join("");

  const stat = (v, l, s="") => `<div class="stat"><div class="v">${v}</div><div class="l">${l}</div>` +
    (s ? `<div class="s">${s}</div>` : "") + `</div>`;
  qs("#bhStats").innerHTML =
    stat(st.users_enabled, "enabled users", `${st.users} total`) +
    stat(st.computers_enabled, "enabled computers", `${st.computers} total`) +
    stat(st.domain_admins, "domain admins") +
    stat(st.dcs, "domain controllers") +
    stat(st.groups, "groups") +
    stat(st.ous, "OUs") +
    stat(st.gpos, "GPOs") +
    stat(rep.seconds < 1 ? Math.max(1, Math.round(rep.seconds*1000)) + "ms" : rep.seconds + "s",
         "parse time", `${st.objects} objects`);

  const bars = (rows, nameKey, max, warnFn) => {
    const top = Math.max(1, ...rows.map(r=>r.count));
    return rows.slice(0,max).map(r => {
      const w = Math.round(100 * r.count / top);
      const warn = warnFn && warnFn(r) ? " warn" : "";
      return `<div class="bar-row"><span class="nm" title="${esc(r[nameKey])}">${esc(r[nameKey])}</span>` +
             `<span class="bar-track"><span class="bar-fill${warn}" style="width:${w}%"></span></span>` +
             `<span class="n">${r.count}</span></div>`;
    }).join("") || `<div class="dim">none</div>`;
  };
  qs("#bhPriv").innerHTML = bars(rep.privileged_groups.filter(r=>r.count>0), "group", 10,
    r => r.group === "Domain Admins" && r.count > 10);
  const oldOs = /windows (xp|vista|7|8|2000|server 2003|server 2008|server 2012)|2003|2008|2012/i;
  qs("#bhOs").innerHTML = bars(rep.os_breakdown, "os", 10, r => oldOs.test(r.os));

  qs("#bhCount").textContent = `· ${rep.checks.length} checks`;
  const box = qs("#bhChecks"); box.innerHTML = "";
  rep.checks.forEach((c, i) => {
    const el = document.createElement("div");
    el.className = "chk";
    const pct = c.pct !== null && c.pct !== undefined ? ` (${c.pct}%)` : "";
    el.innerHTML =
      `<div class="chk-head"><span class="sev-chip sev-${c.severity}">${SEV_LABEL[c.severity]}</span>` +
      `<span class="t">${esc(c.title)}</span>` +
      `<span class="c">${c.count}${pct}</span><span class="chev">▸</span></div>` +
      `<div class="chk-body hidden">` +
        `<p>${esc(c.why)}</p>` +
        `<p class="fix"><b>Fix.</b> ${esc(c.fix)}</p>` +
        (c.items.length ? `<ul class="chk-items">` + c.items.map(it =>
            `<li><span class="nm">${esc(it.name||"")}</span>` +
            (it.detail ? `<span class="dt">${esc(it.detail)}</span>` : "") + `</li>`).join("") +
          `</ul>` + (c.truncated ? `<div class="chk-more">showing ${c.items.length} of ${c.count} — full list in the .md export</div>` : "")
         : "") +
      `</div>`;
    const head = el.querySelector(".chk-head"), body = el.querySelector(".chk-body");
    head.onclick = () => {
      body.classList.toggle("hidden");
      el.querySelector(".chev").textContent = body.classList.contains("hidden") ? "▸" : "▾";
    };
    if (i < 3) head.click();          // open the first few
    box.appendChild(el);
  });
  qs(".bh").scrollTop = 0;
}

function wireBh() {
  qs("#bhFile").onchange = e => bhUpload(e.target.files[0]);
  const drop = qs("#bhDrop");
  ["dragenter","dragover"].forEach(ev => drop.addEventListener(ev, e => {
    e.preventDefault(); drop.classList.add("over"); }));
  ["dragleave","drop"].forEach(ev => drop.addEventListener(ev, e => {
    e.preventDefault(); drop.classList.remove("over"); }));
  drop.addEventListener("drop", e => bhUpload(e.dataTransfer.files[0]));
  qs("#bhRescan").onclick = bhDiscover;
  qs("#bhNew").onclick = () => {
    qs("#bhReport").classList.add("hidden");
    qs("#bhSrc").classList.remove("hidden");
    qs("#bhFile").value = "";
    bhDiscover();
  };
  qs("#bhExport").onclick = () =>
    location.href = `/api/bh/export?token=${encodeURIComponent(TOKEN)}`;
}

/* ======================= config / session ======================= */
function readConfig() {
  const v = id => (qs("#"+id)?.value||"").trim();
  const ck = id => qs("#"+id)?.checked||false;
  const activeAuth = qs("#authTabs button.active")?.dataset.auth;
  const cfg = {
    target:v("f_target"), domain:v("f_domain"), user:v("f_user"),
    targets:v("f_targets"), interface:v("f_interface"), attacker_ip:v("f_attacker_ip"),
    dns_ip:v("f_dns_ip"), ldap_port:v("f_ldap_port"), dc_domain:v("f_dc_domain"),
    user_wordlist:v("f_user_wordlist"), pass_wordlist:v("f_pass_wordlist"), output:v("f_output"),
    ldaps:ck("c_ldaps"), ldap_sign:ck("c_ldap_sign"), ldap_bind:ck("c_ldap_bind"),
    force_kerb:ck("c_force_kerb"), use_ip:ck("c_use_ip"), dns_tcp:ck("c_dns_tcp"),
    auto_config:ck("c_auto_config"), verbose:ck("c_verbose"), no_exec:ck("c_no_exec"),
    offline:ck("c_offline"), auto:ck("c_auto"),
  };
  if (activeAuth==="password") cfg.password=v("f_password");
  if (activeAuth==="hash")     cfg.hash=v("f_hash");
  if (activeAuth==="kerb")     cfg.kerb=v("f_kerb");
  if (activeAuth==="aeskey")   cfg.aeskey=v("f_aeskey");
  if (activeAuth==="cert")   { cfg.cert=v("f_cert"); cfg.certpass=v("f_certpass"); }
  return cfg;
}

async function startSession(cfgOverride) {
  const err = qs("#cfgError"); err.classList.add("hidden");
  const cfg = cfgOverride || readConfig();
  const r = await api("/api/session/start",{method:"POST",body:JSON.stringify(cfg)});
  const j = await r.json().catch(()=>({}));
  if (!j.ok) { err.textContent = j.error||("HTTP "+r.status); err.classList.remove("hidden");
    qs("#cfgBody").parentElement.classList.remove("collapsed"); return; }
  LAST_CFG = cfg;
  afterStart(j);
}
function afterStart(j) {
  SESSION_RUNNING = true; CUR_MENU = null; PLAIN = ""; LINE_ACC = ""; PROMPT_SIG = null;
  hidePanel(); RUN_STATE = "off"; setRunState("running");
  setTopStatus(true);
  lwpTerm.term.clear();
  lwpTerm.reconnect();
  setTimeout(()=>note(`$ ${j.cmdline}`), 300);
  qs("#cfgBody").parentElement.classList.add("collapsed");
}

async function stopSession() {
  await api("/api/session/stop",{method:"POST"});
  sessionEnded();
}
function sessionEnded() {
  SESSION_RUNNING=false; CUR_MENU=null;
  hidePanel(); setRunState("off"); setTopStatus(false);
}
function setTopStatus(on){
  qs("#statusText").textContent = on ? "session running" : "session stopped";
  qs("#statusDot").className = "dot " + (on ? "dot-on" : "dot-off");
  qs("#btnStop").disabled = !on;
  qs("#btnStart").textContent = on ? "Restart session ⟳" : "Start session ▸";
}

/* Stop = Ctrl+C for the running command only (server sends SIGINT to the
   processes started by the script, then forces them if they ignore it).
   The script goes back to its menu and the session keeps running. */
async function stopTask() {
  if (!SESSION_RUNNING) return;
  const r = await api("/api/session/stop_task",{method:"POST"});
  const j = await r.json().catch(()=>({}));
  if (!j.ok) { note(`stop failed: ${j.error||r.status}`); return; }
  if (!j.stopped.length) {
    // nothing running: if a question is open, answer it with Ctrl+C semantics = go back
    note(RUN_STATE==="input" ? "nothing is running (answer or leave the form)" : "nothing is running");
    return;
  }
  const names = [...new Set(j.stopped.map(p=>p.cmd.split(" ")[0].split("/").pop()).filter(Boolean))];
  note(`^C stopped: ${names.slice(0,6).join(", ")}`);
}

/* Reset = kill the whole session and start it again with the same config. */
async function resetSession() {
  if (!SESSION_RUNNING) return;
  note("resetting the session…");
  const r = await api("/api/session/restart",{method:"POST"});
  const j = await r.json().catch(()=>({}));
  if (!j.ok) { note(`reset failed: ${j.error||r.status}`); return; }
  afterStart(j);
}

/* ======================= tabs ======================= */
function switchTab(name){
  qsa("#mainTabs button").forEach(b=>b.classList.toggle("active",b.dataset.tab===name));
  qsa(".tabpane").forEach(p=>p.classList.toggle("hidden",p.dataset.tab!==name));
  if (name==="lwp") { qs('#mainTabs button[data-tab="lwp"]').classList.remove("attn"); lwpTerm.refit(); }
  if (name==="shell"){
    if (!shellTerm){ shellTerm = makeTerm("#termShell","/ws/shell",{autoReconnect:true}); shellTerm.connect(); }
    else shellTerm.refit();
  }
  if (name==="loot") loadLoot(lootPath);
  if (name==="bh" && !BH_LOADED) { BH_LOADED = true; bhDiscover(); }
}

/* ======================= loot browser ======================= */
let lootPath="";
let BH_LOADED=false;
async function loadLoot(path){
  lootPath = path||"";
  qs("#lootPath").textContent = "/"+lootPath;
  const r = await api("/api/files?path="+encodeURIComponent(lootPath));
  const j = await r.json().catch(()=>({}));
  const list = qs("#lootList"); list.innerHTML="";
  if (!j.ok){ list.innerHTML=`<li>· ${esc(j.error||"error")}</li>`; return; }
  if (!j.dir) return;
  if (!j.entries.length) list.innerHTML=`<li>· (empty)</li>`;
  j.entries.forEach(e=>{
    const li=document.createElement("li");
    li.innerHTML=`<span class="ic">${e.dir?"📁":"📄"}</span><span>${esc(e.name)}</span>`+
      (e.dir?"":`<span class="sz">${fmtSize(e.size)}</span>`);
    const rel=(lootPath?lootPath+"/":"")+e.name;
    li.onclick=()=> e.dir ? loadLoot(rel) : previewFile(rel);
    list.appendChild(li);
  });
}
async function previewFile(path){
  const r = await api("/api/files?path="+encodeURIComponent(path));
  const j = await r.json().catch(()=>({}));
  const view = qs("#lootView");
  const dl = `<a href="/api/download?path=${encodeURIComponent(path)}&token=${encodeURIComponent(TOKEN)}">download</a>`;
  if (!j.ok){ view.textContent=j.error||"error"; return; }
  if (j.too_big){ view.innerHTML=`File too large to preview. ${dl}`; return; }
  if (j.binary){ view.innerHTML =
    `<div>${esc(path)}</div><div style="margin-top:8px;color:var(--dim)">` +
    `Binary file, ${fmtSize(j.size)} — no text preview. ${dl}</div>`; return; }
  // linWinPwn writes colour codes into its logs: strip them for reading
  const text = (j.content||"").replace(ANSI_RE, "");
  view.innerHTML = `<div style="margin-bottom:8px">${esc(path)} · ${dl}</div>` + esc(text||"(empty)");
}
function fmtSize(n){ if(n<1024)return n+"B"; if(n<1048576)return (n/1024).toFixed(1)+"K";
  return (n/1048576).toFixed(1)+"M"; }

/* ======================= wiring ======================= */
function wire(){
  qs("#btnStart").onclick = () => startSession();
  qs("#btnStop").onclick  = stopSession;
  qs("#lwpClear").onclick = ()=>lwpTerm.term.clear();
  qs("#lwpHome").onclick  = ()=>{ if (RUN_STATE==="ready" && CUR_MENU!==null){ setRunState("running");
      api("/api/action",{method:"POST",body:JSON.stringify({keys:["back"]})}); } };
  qs("#lwpStop").onclick = stopTask;
  qs("#lwpReset").onclick = resetSession;
  qs("#lwpTypeable").onchange = e => { if (e.target.checked) lwpTerm.term.focus(); };
  qs("#menuFilter").oninput = e=>{ renderTree(e.target.value); if (CURRENT) renderActions(CURRENT); };

  qs("#promptPanel").onsubmit = e => { e.preventDefault(); answer(qs("#ppInput").value); };
  qs("#ppEnter").onclick = () => answer("");
  qs("#ppReveal").onclick = () => { const i=qs("#ppInput"); i.type = i.type==="password"?"text":"password"; i.focus(); };

  qsa("#mainTabs button").forEach(b=>b.onclick=()=>switchTab(b.dataset.tab));
  qsa(".panel-head[data-toggle]").forEach(h=>h.onclick=()=>h.parentElement.classList.toggle("collapsed"));
  qsa("#authTabs button").forEach(b=>b.onclick=()=>{
    qsa("#authTabs button").forEach(x=>x.classList.remove("active"));
    b.classList.add("active");
    qsa(".authpane").forEach(p=>p.classList.toggle("hidden",p.dataset.pane!==b.dataset.auth));
  });
  qs("#lootUp").onclick=()=>{ if(lootPath) loadLoot(lootPath.split("/").slice(0,-1).join("/")); };
  qs("#lootRefresh").onclick=()=>loadLoot(lootPath);
  qs("#histCopyAll").onclick=()=>navigator.clipboard?.writeText(HISTORY.map(h=>h.cmd).join("\n"));
  qs("#histClear").onclick=()=>{ HISTORY.length=0; qs("#histList").innerHTML=""; qs("#histCount").textContent="0"; };
  qs("#f_target").addEventListener("keydown",e=>{ if(e.key==="Enter") startSession(); });
  wireBh();
}

async function init(){
  wire();
  const cfg = await api("/api/config").then(r=>r.json()).catch(()=>({}));
  if (cfg && cfg.script_present===false)
    qs("#brandMeta").textContent = "⚠ linWinPwn.sh not found next to web_ui/";
  MENUS = await api("/api/menus").then(r=>r.json()).then(d=>d.menus).catch(()=>[]);
  renderTree();
  if (MENUS.length) openMenu(MENUS.find(m=>m.id==="ad")||MENUS[0]);

  // reattach to a session already running (page reload): scrollback replays the state
  const s = await api("/api/session/status").then(r=>r.json()).catch(()=>null);
  if (s && s.running) { SESSION_RUNNING=true; setTopStatus(true); setRunState("running");
    qs("#cfgBody").parentElement.classList.add("collapsed"); lwpTerm.connect(); }

  setInterval(async()=>{
    const s = await api("/api/session/status").then(r=>r.json()).catch(()=>null);
    if (s && SESSION_RUNNING && !s.running) { sessionEnded(); note("the linWinPwn process exited"); }
  }, 3000);
}

document.addEventListener("DOMContentLoaded", init);
})();
