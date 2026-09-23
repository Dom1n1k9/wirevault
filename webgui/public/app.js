// WireVault dashboard client.
// Plain JS talking to the TS server over WebSockets.
const wsProto = location.protocol === "https:" ? "wss" : "ws";
const ws = new WebSocket(`${wsProto}://${location.host}`);

const $ = (id) => document.getElementById(id);
let reqId = 0;
const pending = new Map();

function call(method, params = {}) {
  return new Promise((resolve, reject) => {
    const id = ++reqId;
    pending.set(id, { resolve, reject });
    ws.send(JSON.stringify({ id, method, params }));
  });
}

const esc = (s) => String(s ?? "").replace(/[&<>"']/g,
  (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const sevCls = (s) => ["info", "warning", "critical"].includes(s) ? s : "info";

function renderPeers(peers) {
  const tb = $("peers").querySelector("tbody");
  tb.innerHTML = "";
  for (const p of peers ?? []) {
    const tr = document.createElement("tr");
    const state = p.online ? '<span class="ok">● online</span>' : '<span class="fade">○ offline</span>';
    tr.innerHTML = `<td>${esc(p.name)}</td><td class="fade">${esc(p.endpoint)}</td>
      <td>${(p.rx / 1024).toFixed(1)}K</td><td>${(p.tx / 1024).toFixed(1)}K</td><td>${state}</td>`;
    tb.appendChild(tr);
  }
  if (!peers?.length) tb.innerHTML = '<tr><td colspan="5" class="fade">no peers</td></tr>';
}

function renderFilter(f) {
  $("filter").innerHTML = `<div class="row"><span>Rules applied</span><b>${f?.rules_applied ?? 0}</b></div>
    <div class="row"><span>Blocked hits</span><b>${f?.blocked ?? 0}</b></div>`;
}

function renderIncidents(incidents) {
  const box = $("incidents");
  box.innerHTML = "";
  for (const i of incidents ?? []) {
    const el = document.createElement("div");
    el.className = "row";
    el.innerHTML = `<span class="sev ${sevCls(i.severity)}">${esc(i.severity)}</span>
      <span>${esc(i.kind)}</span><span>${esc(i.summary)}</span>
      <span class="fade">${timeStr(i.ts)}${i.acked ? " ✓" : ""}</span>`;
    box.appendChild(el);
  }
  if (!incidents?.length) box.innerHTML = '<div class="fade">no incidents</div>';
}

function timeStr(ts) { return new Date(ts * 1000).toLocaleTimeString(); }

function setConn(ok) {
  $("conn").classList.toggle("on", ok);
  $("conn-txt").textContent = ok ? "connected" : "offline";
}

async function refresh() {
  try {
    const peers = await call("peer.list");
    renderPeers(peers.peers);
    const filt = await call("filter.current");
    renderFilter(filt);
    const inc = await call("watch.incidents", { limit: 25 });
    renderIncidents(inc.incidents);
    const sys = await call("system.info");
    $("system").textContent = `${sys.version} · ${sys.host} · ${sys.iface}`;
  } catch (e) {
    $("system").textContent = "daemon offline: " + e.message;
  }
}

ws.onopen = () => { setConn(true); refresh(); setInterval(refresh, 5000); };
ws.onclose = () => setConn(false);

ws.onmessage = (e) => {
  let msg;
  try { msg = JSON.parse(e.data); } catch { return; }
  if (msg.t === "result" && pending.has(msg.id)) {
    const p = pending.get(msg.id);
    pending.delete(msg.id);
    p.resolve(msg.result);
  } else if (msg.t === "error" && pending.has(msg.id)) {
    const p = pending.get(msg.id);
    pending.delete(msg.id);
    p.reject(new Error(msg.error));
  } else if (msg.event === "incident") {
    // live threat/incident pushed from the daemon -> refresh the feed
    refresh();
  } else if (msg.event === "wg.status") {
    // live peer snapshot from the daemon
    refresh();
  }
};

$("apply").onclick = async () => {
  try {
    await call("wg.apply");
    refresh();
  } catch (e) { alert("apply failed: " + e.message); }
};
