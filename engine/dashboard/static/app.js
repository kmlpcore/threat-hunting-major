/* Threat Hunting Engine dashboard — vanilla JS, no external dependencies.
   Reads only through the Query API (/api/q/...), writes only through the Command API (/api/c/...). */
"use strict";

const SOURCES = ["windows_security", "sysmon", "zeek_conn", "zeek_dns", "proxy", "cloudtrail", "host_metrics", "dhcp"];
// Planted indicators from scenarios/default.yaml (generator config, not ground truth labels).
const IOC_HINTS = [
  ["203.0.113.80", "C2 of the encoded PowerShell cradle"],
  ["update-check.badcdn.example", "payload domain"],
  ["badcdn.example", "registered domain (matches both campaigns)"],
  ["198.51.100.77", "cryptomining pool"],
  ["exfil-dns.example", "DNS tunnel domain (registered domain of 400 TXT queries)"],
  ["203.0.113.200", "exfiltration destination"],
  ["198.51.100.23", "password-spray source"],
];
const TEXT_HINTS = ["powershell enc hidden bypass", "certutil urlcache split", "psexesvc whoami domain admins",
  "xmrig stratum donate", "mshta hta", "Invoice docm"];

const $ = (sel, el = document) => el.querySelector(sel);

// ---------- theme: dark (default) or light; printing always uses light
const root = document.documentElement;
const isLight = () => root.getAttribute("data-theme") === "light";
function setTheme(light, save = true) {
  if (light) root.setAttribute("data-theme", "light"); else root.removeAttribute("data-theme");
  const b = document.getElementById("theme-toggle");
  if (b) b.textContent = light ? "Dark mode" : "Light mode";
  if (save) { try { localStorage.setItem("th-theme", light ? "light" : "dark"); } catch (e) { /* storage blocked */ } }
}
let themeBeforePrint = null;
window.addEventListener("beforeprint", () => { themeBeforePrint = isLight(); setTheme(true, false); });
window.addEventListener("afterprint", () => { if (themeBeforePrint !== null) setTheme(themeBeforePrint, false); themeBeforePrint = null; });
document.addEventListener("DOMContentLoaded", () => {
  setTheme(isLight(), false);
  document.getElementById("theme-toggle").addEventListener("click", () => setTheme(!isLight()));
});
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const fmtN = (n) => (n == null ? "–" : Number(n).toLocaleString());
const fmtB = (b) => {
  if (b == null) return "–";
  const u = ["B", "KB", "MB", "GB", "TB"]; let i = 0; let v = Number(b);
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(v >= 100 || i === 0 ? 0 : 1)} ${u[i]}`;
};
const pct = (a, b) => (b ? Math.round((100 * a) / b) : 0);
const fmtT = (t) => (t ? new Date(t).toISOString().replace("T", " ").slice(0, 19) : "–");
const ago = (t) => {
  if (!t) return "–"; const s = Math.max(0, (Date.now() - new Date(t).getTime()) / 1000);
  return s < 60 ? `${Math.round(s)}s ago` : s < 3600 ? `${Math.round(s / 60)}m ago` : `${Math.round(s / 3600)}h ago`;
};

async function q(path, params) {
  const url = new URL(`/api/q/${path}`, location.origin);
  Object.entries(params || {}).forEach(([k, v]) => {
    if (v === undefined || v === null || v === "") return;
    (Array.isArray(v) ? v : [v]).forEach((x) => url.searchParams.append(k, x));
  });
  const r = await fetch(url);
  const body = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(body.detail ? JSON.stringify(body.detail) : `HTTP ${r.status}`);
  return body;
}
async function cmd(type, payload) {
  const r = await fetch(`/api/c/commands/${type}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload || {}) });
  const body = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(body.detail ? JSON.stringify(body.detail) : `HTTP ${r.status}`);
  return body;
}
function toast(msg, ms = 3500) {
  const t = document.createElement("div"); t.className = "toast"; t.innerHTML = msg;
  document.body.appendChild(t); setTimeout(() => t.remove(), ms);
}
function drawer(html) {
  const d = $("#drawer"); d.innerHTML = `<button class="ghost close" onclick="closeDrawer()">Close</button>${html}`; d.classList.add("open");
}
window.closeDrawer = () => $("#drawer").classList.remove("open");
function setLive(ok, text) { $("#live-dot").classList.toggle("off", !ok); $("#live-text").textContent = text; }

function table(rows, cols, opts = {}) {
  if (!rows || !rows.length) return `<div class="empty">${opts.empty || "No rows"}</div>`;
  cols = cols || Object.keys(rows[0]).filter((k) => !k.startsWith("_"));
  const cell = (v, c) => {
    if (v == null) return `<td class="muted">–</td>`;
    if (Array.isArray(v)) return `<td class="trunc mono" title="${esc(v.join(", "))}">${esc(v.join(", "))}</td>`;
    if (typeof v === "object") return `<td class="trunc mono">${esc(JSON.stringify(v))}</td>`;
    if (typeof v === "number") return `<td class="num">${c.includes("bytes") ? fmtB(v) : Number.isInteger(v) ? fmtN(v) : v.toFixed(3)}</td>`;
    const s = String(v);
    return `<td class="${s.length > 60 ? "trunc mono" : ""}" title="${esc(s)}">${esc(s)}</td>`;
  };
  return `<div class="scroll"><table><thead><tr>${cols.map((c) => `<th>${esc(c)}</th>`).join("")}</tr></thead>
    <tbody>${rows.map((r) => `<tr>${cols.map((c) => cell(r[c], c)).join("")}</tr>`).join("")}</tbody></table></div>`;
}

/* ======================================================================= pages */
const pages = {};
let timer = null;

pages.overview = {
  title: "Overview", sub: "Ingest → summaries → index → artefacts → seal, live from the read models",
  async render(el) {
    const [pipe, storage, feats, act] = await Promise.all([q("pipeline"), q("storage"), q("features"), q("activity", { limit: 14 })]);
    const t = pipe.total || {};
    const featsActive = feats.items.filter((f) => f.registered).length;
    const stageOn = (k) => (t.partitions && t[k] === t.partitions ? "on" : "");
    el.innerHTML = `
      <p class="lede">Retrospective hunting over archived logs without re-hydrating them: raw events are normalised to ECS and landed as Parquet,
      then summarised, indexed and turned into artefacts <em>before</em> each hour partition is sealed and released to the archive tier.</p>
      <div class="grid g6">
        ${kpi("Raw events", fmtN(storage.raw.rows), `${fmtN(storage.raw.partitions)} hour partitions`)}
        ${kpi("Raw Parquet", fmtB(storage.raw.bytes), `native input ${fmtB(storage.incoming_native.bytes)}`)}
        ${kpi("Summary / raw", storage.ratios.summary_to_raw != null ? `${(storage.ratios.summary_to_raw * 100).toFixed(1)}%` : "–", `${fmtN(storage.summary.rows)} summary rows`, true)}
        ${kpi("Index", fmtB(storage.index.bytes), `${fmtN(storage.index.objects)} bloom + BM25 objects`)}
        ${kpi("Features", `${featsActive} / ${feats.items.length}`, "registered / defined")}
        ${kpi("Sealed", `${pct(t.sealed || 0, t.partitions || 0)}%`, `${fmtN(t.sealed)} of ${fmtN(t.partitions)}`, true)}
      </div>
      <div class="card"><h2>Architecture (milestones M0–M9) <span class="hint">green = complete for every partition</span></h2>
        <div class="flow">
          <div class="step on"><b>Sources</b><span>8 native formats, 9 planted attacks</span></div>
          <div class="step on"><b>Normalise (M1)</b><span>ECS + entity resolution</span></div>
          <div class="step ${stageOn("landed")}"><b>Raw Parquet</b><span>zstd · WORM · hour partitions</span></div>
          <div class="step ${stageOn("summary")}"><b>Summaries (M2)</b><span>Iceberg · drop policy ${esc(storage.policy_version)}</span></div>
          <div class="step ${stageOn("index")}"><b>Index (M3)</b><span>bloom sidecars + BM25</span></div>
          <div class="step ${stageOn("features")}"><b>Artefacts (M4)</b><span>versioned features</span></div>
          <div class="step ${stageOn("sealed")}"><b>Seal → archive</b><span>tag-gated lifecycle</span></div>
        </div>
        <div class="flow" style="margin-top:8px">
          <div class="step on"><b>Rules (M5)</b><span>Sigma → tiers · cost</span></div>
          <div class="step on"><b>TI (M6)</b><span>tactical · operational · strategic</span></div>
          <div class="step on"><b>Feeds (M7)</b><span>connectors → retro-sweeps</span></div>
          <div class="step on"><b>Retention (M8)</b><span>15 years · WORM · drill</span></div>
          <div class="step on"><b>Evaluation (M9)</b><span>docs/evaluation.md</span></div>
        </div>
      </div>
      <div class="grid g2">
        <div class="card"><h2>Pipeline by source <span class="hint">share of partitions per stage</span></h2>${pipelineBars(pipe)}</div>
        <div class="card"><h2>Live activity <span class="hint"><a href="#activity">all events →</a></span></h2>${feed(act.items)}</div>
      </div>`;
  },
};

function kpi(label, value, foot, accent) {
  return `<div class="card kpi ${accent ? "accent" : ""}"><div class="label">${label}</div><div class="value">${value}</div><div class="foot">${foot || ""}</div></div>`;
}
function pipelineBars(pipe) {
  const stages = ["landed", "summary", "index", "features", "sealed"];
  const rows = Object.entries(pipe.sources || {}).map(([src, c]) => `
    <div class="stage-row"><div class="mono small">${esc(src)}</div>
      ${stages.map((s) => `<div class="bar ${c[s] === c.partitions ? "ok" : ""}" title="${s}: ${c[s] || 0}/${c.partitions}"><i style="width:${pct(c[s] || 0, c.partitions)}%"></i></div>`).join("")}
      <div class="num small muted">${fmtN(c.partitions)}</div></div>`).join("");
  return `<div class="stage-row head"><div>source</div>${stages.map((s) => `<div>${s}</div>`).join("")}<div class="num">parts</div></div>${rows || '<div class="empty">No data yet: run the seed step</div>'}`;
}
function feed(items) {
  if (!items || !items.length) return `<div class="empty">No events yet</div>`;
  const cls = { PartitionSealed: "ok", ArtefactsBuilt: "ok", SummariesBuilt: "info", IndexBuilt: "info", CommandFailed: "bad", BatchNormalised: "warn" };
  return `<div class="feed">${items.map((e) => `<div class="ev"><span class="t">${ago(e.occurred_at)}</span>
    <span><span class="pill ${cls[e.event_type] || ""} k">${esc(e.event_type)}</span></span><span>${esc(e.summary)}</span></div>`).join("")}</div>`;
}

/* ----------------------------------------------------------------------- hunt */
pages.hunt = {
  title: "Hunt", sub: "Tier-3 search: bloom-prune partitions → index lookup → restore only the matching row groups",
  async render(el) {
    if (el.dataset.ready) return;   // keep results between refreshes
    el.dataset.ready = "1";
    el.innerHTML = `
      <div class="grid g2">
        <div class="card"><h2>IOC sweep <span class="hint">exact match, 100% recall on indexed fields</span></h2>
          <div class="row"><input id="ioc" placeholder="IP, domain, hash, user or host" style="flex:1" value="203.0.113.80">
          <button id="ioc-go">Sweep</button></div>
          <div class="chips" style="margin-top:10px">${IOC_HINTS.map(([v, l]) => `<button class="chip" title="${esc(l)}" data-ioc="${esc(v)}">${esc(v)}</button>`).join("")}</div>
        </div>
        <div class="card"><h2>Free-text hunt <span class="hint">BM25 over command lines, URLs, user agents, messages</span></h2>
          <div class="row"><input id="txt" placeholder="e.g. powershell enc hidden" style="flex:1" value="powershell enc hidden bypass">
          <button id="txt-go">Search</button></div>
          <div class="chips" style="margin-top:10px">${TEXT_HINTS.map((v) => `<button class="chip" data-txt="${esc(v)}">${esc(v)}</button>`).join("")}</div>
        </div>
      </div>
      <div id="hunt-out"><div class="card empty">Pick an indicator or query above. Planted attack indicators are offered as chips.</div></div>`;
    $("#ioc-go").onclick = () => runHunt("ioc", $("#ioc").value);
    $("#txt-go").onclick = () => runHunt("search", $("#txt").value);
    $("#ioc").onkeydown = (e) => e.key === "Enter" && runHunt("ioc", $("#ioc").value);
    $("#txt").onkeydown = (e) => e.key === "Enter" && runHunt("search", $("#txt").value);
    el.querySelectorAll("[data-ioc]").forEach((b) => (b.onclick = () => { $("#ioc").value = b.dataset.ioc; runHunt("ioc", b.dataset.ioc); }));
    el.querySelectorAll("[data-txt]").forEach((b) => (b.onclick = () => { $("#txt").value = b.dataset.txt; runHunt("search", b.dataset.txt); }));
  },
  keep: true,
};

async function runHunt(kind, value) {
  const out = $("#hunt-out");
  out.innerHTML = `<div class="card"><span class="spin"></span> ${kind === "ioc" ? "Sweeping" : "Searching"} for <code>${esc(value)}</code>…</div>`;
  try {
    const res = kind === "ioc" ? await q("ioc", { value, limit: 300 }) : await q("search", { q: value, limit: 25 });
    const s = res.stats;
    const ratio = s.restore_ratio != null ? s.restore_ratio * 100 : 0;
    const cols = ["@timestamp", "event.dataset", "host.name", "user.name", "event.action", "source.ip", "destination.ip",
      "process.name", "process.command_line", "dns.question.name", "url.full"].concat(kind === "search" ? ["_score"] : []);
    out.innerHTML = `
      <div class="card"><h2>${kind === "ioc" ? `IOC <code>${esc(res.value)}</code> <span class="pill info">${esc(res.ioc_type)}</span>` : `BM25 <code>${esc(res.query)}</code>`}
        <span class="hint">tier ${res.tier} · ${s.duration_ms} ms</span></h2>
        <div class="funnel">
          <div class="f"><div class="n">${fmtN(s.partitions_in_range)}</div><div class="l">partitions in range</div></div>
          <div class="f"><div class="n">${fmtN(s.partitions_after_bloom)}</div><div class="l">after bloom pruning${s.partition_prune_ratio != null && kind === "ioc" ? ` (−${Math.round(s.partition_prune_ratio * 100)}%)` : ""}</div></div>
          <div class="f"><div class="n">${fmtN(s.indexes_opened)}</div><div class="l">index segments opened</div></div>
          <div class="f"><div class="n">${fmtN(s.hits)}</div><div class="l">matching events</div></div>
          <div class="f"><div class="n">${fmtN(s.row_groups_restored)}</div><div class="l">row groups restored from ${fmtN(s.files_restored)} files</div></div>
        </div>
        <div style="margin-top:14px"><b>${fmtB(s.bytes_restored)}</b> restored instead of <b>${fmtB(s.full_rehydration_bytes)}</b> for a full rehydration of the same range
          <span class="pill ok">${ratio.toFixed(2)}% restore ratio</span>
          ${kind === "ioc" ? `<span class="pill">${fmtN(s.bloom_false_positive_partitions)} bloom false-positive partitions</span>` : ""}</div>
        <div class="costbar"><i style="width:${Math.max(0.3, ratio)}%"></i></div>
        ${(s.notes || []).map((n) => `<div class="small muted">${esc(n)}</div>`).join("")}
      </div>
      <div class="card"><h2>Events <span class="hint">${fmtN(res.events.length)} shown · click a row for the full record</span></h2>${table(res.events, cols, { empty: "No matches" })}</div>`;
    out.querySelectorAll("tbody tr").forEach((tr, i) => (tr.onclick = () => drawer(`<h3>Event</h3><pre class="json">${esc(JSON.stringify(res.events[i], null, 2))}</pre>`)));
  } catch (e) {
    out.innerHTML = `<div class="card"><span class="pill bad">error</span> ${esc(e.message)}</div>`;
  }
}

/* ----------------------------------------------------------------------- partitions */
pages.partitions = {
  title: "Partitions", sub: "Every hour partition per source, coloured by the furthest stage it has completed",
  async render(el) {
    const [parts, pipe] = await Promise.all([q("partitions", { limit: 5000 }), q("pipeline")]);
    const items = parts.items;
    if (!items.length) { el.innerHTML = `<div class="card empty">No partitions yet</div>`; return; }
    const days = [...new Set(items.map((p) => p.date))].sort();
    const by = {}; items.forEach((p) => (by[p.partition_id] = p));
    const reg = pipe.registered_features || [];
    const state = (p) => {
      if (!p) return "";
      const s = p.stages || {};
      if (s.reseal_pending) return "reseal";
      if (p.sealed && s.sealed !== false) return "sealed";
      const fs = Object.keys(s.features || {});
      if (s.index && s.summary && fs.length) return "features";
      if (s.index) return "index";
      if (s.summary) return "summary";
      return "landed";
    };
    const cols = days.length * 24;
    const rows = SOURCES.filter((s) => items.some((p) => p.source === s)).map((src) => {
      const cells = [];
      days.forEach((d) => { for (let h = 0; h < 24; h++) {
        const pid = `source=${src}/date=${d}/hour=${String(h).padStart(2, "0")}`; const p = by[pid];
        cells.push(`<div class="cell ${state(p)} ${p && p.stages && p.stages.late_data ? "late" : ""}" data-pid="${p ? esc(pid) : ""}" title="${esc(pid)}${p ? ` · ${p.rows} rows` : " · no data"}"></div>`);
      } });
      return `<div class="lbl mono">${esc(src)}</div><div class="cells" style="grid-template-columns:repeat(${cols},1fr)">${cells.join("")}</div>`;
    }).join("");
    el.innerHTML = `
      <div class="card"><h2>${fmtN(items.length)} partitions · ${days.length} days × 24 hours <span class="hint">click a cell for its health and seal manifest</span></h2>
        <div class="heat" style="grid-template-columns:130px 1fr">${rows}
          <div></div><div class="daylbls" style="grid-template-columns:repeat(${days.length},1fr)">${days.map((d) => `<div>${d}</div>`).join("")}</div></div>
        <div class="legend" style="margin-top:10px">
          <span><i style="background:var(--s-none)"></i>no data</span><span><i style="background:var(--s-landed)"></i>landed</span>
          <span><i style="background:var(--s-summary)"></i>summarised</span><span><i style="background:var(--s-index)"></i>indexed</span>
          <span><i style="background:var(--s-features)"></i>artefacts built</span><span><i style="background:var(--s-sealed)"></i>sealed</span>
          <span><i style="background:var(--warn)"></i>reseal pending</span><span><i style="box-shadow:inset 0 0 0 2px var(--late)"></i>late data</span>
          <span class="muted">registered features: ${reg.length}</span></div></div>`;
    el.querySelectorAll(".cell[data-pid]").forEach((c) => c.dataset.pid && (c.onclick = () => showPartition(c.dataset.pid)));
  },
};

async function showPartition(pid) {
  drawer(`<span class="spin"></span> loading ${esc(pid)}`);
  const [h, seal] = await Promise.all([q(`partitions/${pid}/health`), q(`partitions/${pid}/seal`).catch(() => null)]);
  drawer(`<h3 class="mono">${esc(pid)}</h3>
    <div class="row">${h.sealed ? `<span class="pill ok">sealed v${seal ? seal.seal_version : "?"}</span>` : `<span class="pill warn">not sealed</span>`}
      ${(h.stages || {}).late_data ? `<span class="pill" style="color:var(--late)">late data</span>` : ""}</div>
    <p class="small muted">${fmtN(h.rows)} rows · ${h.files} files · ${fmtB(h.bytes)} · ${fmtT(h.min_ts)} → ${fmtT(h.max_ts)}</p>
    <h4>Stages</h4><pre class="json">${esc(JSON.stringify(h.stages, null, 2))}</pre>
    ${seal ? `<h4>Seal manifest</h4><pre class="json">${esc(JSON.stringify({ seal_version: seal.seal_version, sealed_at: seal.sealed_at, rows: seal.rows, files: seal.files, job_versions: seal.job_versions, snapshot_ids: seal.snapshot_ids }, null, 2))}</pre>` : ""}`);
}

/* ----------------------------------------------------------------------- storage */
pages.storage = {
  title: "Storage", sub: "What the derived layers cost relative to raw (M2 exit criterion: summary-to-raw ratio)",
  async render(el) {
    const s = await q("storage");
    const max = Math.max(s.raw.bytes, s.incoming_native.bytes, s.summary.bytes, s.artefacts.bytes, s.index.bytes, 1);
    const bar = (label, bytes, sub, color) => `<div class="hbar"><div>${label}<div class="small muted">${sub || ""}</div></div>
      <div class="track"><i style="width:${Math.max(0.5, (100 * bytes) / max)}%;background:${color}"></i></div><div class="num">${fmtB(bytes)}</div></div>`;
    const r = s.ratios;
    el.innerHTML = `
      <div class="grid g4">
        ${kpi("Summary / raw", r.summary_to_raw != null ? `${(r.summary_to_raw * 100).toFixed(2)}%` : "–", `${s.summary.tables.filter((t) => t.exists).length} Iceberg tables`, true)}
        ${kpi("Artefacts / raw", r.artefacts_to_raw != null ? `${(r.artefacts_to_raw * 100).toFixed(2)}%` : "–", `${s.artefacts.tables.length} artefact tables`)}
        ${kpi("Index / raw", r.index_to_raw != null ? `${(r.index_to_raw * 100).toFixed(1)}%` : "–", "bloom sidecars + BM25 segments")}
        ${kpi("All derived / raw", r.derived_to_raw != null ? `${(r.derived_to_raw * 100).toFixed(1)}%` : "–", `drop policy v${esc(s.policy_version)}`)}
      </div>
      <div class="card"><h2>Bytes by layer</h2>
        ${bar("Native input (gzip)", s.incoming_native.bytes, "what the sources produced", "var(--muted)")}
        ${bar("Raw ECS Parquet", s.raw.bytes, `${fmtN(s.raw.rows)} rows, archive-bound`, "var(--accent)")}
        ${bar("Summary tables", s.summary.bytes, `${fmtN(s.summary.rows)} rows (hot)`, "var(--ok)")}
        ${bar("Artefacts", s.artefacts.bytes, `${fmtN(s.artefacts.rows)} rows (hot)`, "var(--s-features)")}
        ${bar("Index", s.index.bytes, `${fmtN(s.index.objects)} objects (hot)`, "var(--accent-2)")}
        <p class="small muted">At prototype volume raw is dominated by per-file Parquet footers (hourly partitions × 120 ECS columns) and keeps <code>event.original</code>;
        ratios improve at production volume where row groups approach 128 MB.</p></div>
      <div class="grid g2">
        <div class="card"><h2>Summary tables (Iceberg)</h2>${table(s.summary.tables, ["table", "rows", "files", "bytes", "snapshot_id"])}</div>
        <div class="card"><h2>Artefact tables (Iceberg)</h2>${table(s.artefacts.tables, ["table", "rows", "files", "bytes", "snapshot_id"], { empty: "No artefacts yet" })}</div>
      </div>`;
  },
};

/* ----------------------------------------------------------------------- summaries */
pages.summaries = {
  title: "Summaries", sub: "Iceberg summary tables built per source-day by the drop/aggregate policy; reads are snapshot-pinned",
  async render(el) {
    if (el.dataset.ready) return; el.dataset.ready = "1";
    const [tables, parts] = await Promise.all([q("summary/tables"), q("partitions/summary")]);
    const days = []; const first = parts.items.map((p) => p.min_ts).sort()[0]; const last = parts.items.map((p) => p.max_ts).sort().slice(-1)[0];
    if (first) { for (let d = new Date(first.slice(0, 10)); d <= new Date(last.slice(0, 10)); d.setUTCDate(d.getUTCDate() + 1)) days.push(d.toISOString().slice(0, 10)); }
    el.innerHTML = `
      <div class="card"><h2>Tables <span class="hint">policy v${esc(tables.policy_version)}</span></h2>${table(tables.items, ["table", "source", "grain", "rows", "files", "bytes", "snapshot_id"])}</div>
      <div class="card"><div class="row">
        <select id="st">${tables.items.map((t) => `<option value="${esc(t.table.replace("summary.", ""))}">${esc(t.table)}</option>`).join("")}</select>
        <select id="sd"><option value="">all days</option>${days.map((d) => `<option>${d}</option>`).join("")}</select>
        <button id="sgo">Load rows</button><span id="smeta" class="small muted"></span></div>
        <div id="sout" style="margin-top:12px"></div></div>`;
    const load = async () => {
      $("#sout").innerHTML = `<span class="spin"></span>`;
      const r = await q(`summary/${$("#st").value}`, { day: $("#sd").value, limit: 300 });
      $("#smeta").textContent = `${r.count} rows · snapshot ${r.snapshot_id}`;
      $("#sout").innerHTML = table(r.items, null);
    };
    $("#sgo").onclick = load; load();
  },
};

/* ----------------------------------------------------------------------- artefacts */
pages.artefacts = {
  title: "Artefacts", sub: "Versioned features built from summaries only. Register a version and it backfills every day without touching raw.",
  async render(el) {
    const [f, pipe] = await Promise.all([q("features"), q("partitions/summary")]);
    const nDays = new Set(); (await q("partitions", { limit: 5000 })).items.forEach((p) => nDays.add(p.date));
    const total = nDays.size || 1;
    const cards = f.items.map((x) => `
      <div class="card fcard">
        <div class="row"><b class="mono">${esc(x.feature)}@${esc(x.version)}</b>
          ${x.registered ? `<span class="pill ok">registered</span>` : `<span class="pill">available</span>`}
          <span class="pill ${x.raw_bytes_read ? "bad" : "ok"}" title="bytes read from the raw bucket while building">raw bytes read: ${fmtN(x.raw_bytes_read)}</span></div>
        <div class="small muted">${esc(x.description)}</div>
        <div class="meta"><span class="pill">inputs: ${x.inputs.map(esc).join(", ")}</span><span class="pill">window ${x.window_days}d</span>
          <span class="pill">${esc(x.output_table)}</span></div>
        <div class="progress"><i style="width:${pct(x.days_built, total)}%"></i></div>
        <div class="row small"><span class="muted">${x.days_built}/${total} days built · ${fmtN(x.rows)} rows</span><span style="flex:1"></span>
          ${x.registered ? `<button class="ghost" data-browse="${esc(x.feature)}" data-v="${esc(x.version)}">Browse</button>`
            : `<button data-activate="${esc(x.feature)}" data-v="${esc(x.version)}">Activate &amp; backfill</button>`}</div>
      </div>`).join("");
    el.innerHTML = `<div class="grid g3">${cards}</div><div id="aout"></div>`;
    el.querySelectorAll("[data-activate]").forEach((b) => (b.onclick = async () => {
      b.disabled = true; b.innerHTML = `<span class="spin"></span> submitting`;
      try { const r = await cmd("RegisterFeature", { feature: b.dataset.activate, version: b.dataset.v });
        toast(`RegisterFeature accepted (${r.command_id.slice(0, 8)}…). The orchestrator now backfills it day by day.`); }
      catch (e) { toast(`<span class="pill bad">error</span> ${esc(e.message)}`); }
    }));
    el.querySelectorAll("[data-browse]").forEach((b) => (b.onclick = () => browseArtefact(b.dataset.browse, b.dataset.v)));
    if (!el.dataset.browsed) { el.dataset.browsed = "1"; browseArtefact("candidates", "2"); }
    else if (window._lastArtefact) browseArtefact(...window._lastArtefact);
  },
};

async function browseArtefact(name, version) {
  window._lastArtefact = [name, version];
  const out = $("#aout"); if (!out) return;
  try {
    const r = await q(`artefacts/${name}`, { version, limit: 400 });
    const note = name === "candidates" ? `<p class="small muted">Candidates are a prefilter (rare + privileged + anomalous). They narrow where to look; rules are never evaluated on candidates alone.</p>` : "";
    out.innerHTML = `<div class="card"><h2 class="mono">artefacts.${esc(name)} <span class="hint">${r.count} rows · snapshot ${r.snapshot_id ?? "–"}</span></h2>${note}${table(r.items, null, { empty: "Not built yet" })}</div>`;
  } catch (e) { out.innerHTML = `<div class="card empty">${esc(e.message)}</div>`; }
}

/* ----------------------------------------------------------------------- sealing */
pages.sealing = {
  title: "Sealing & archive", sub: "Raw moves to the archive tier only after its partition is sealed: the lifecycle rule matches tagged objects only",
  async render(el) {
    const [pipe, seals] = await Promise.all([q("pipeline"), q("seals", { limit: 60 })]);
    const t = pipe.total || {};
    el.innerHTML = `
      <div class="grid g4">
        ${kpi("Sealed partitions", fmtN(t.sealed), `${pct(t.sealed || 0, t.partitions || 0)}% of ${fmtN(t.partitions)}`, true)}
        ${kpi("Awaiting seal", fmtN((t.partitions || 0) - (t.sealed || 0)), "stages incomplete or within watermark grace")}
        ${kpi("Reseal pending", fmtN(t.reseal_pending || 0), "late data landed after seal")}
        ${kpi("Highest seal version", fmtN(seals.max_seal_version || 0), ">1 means a partition was resealed")}
      </div>
      <div class="card"><h2>Lifecycle invariant <span class="hint"><button class="ghost" id="lc">Run spot check</button></span></h2>
        <div id="lcout" class="small muted">Reads the bucket's lifecycle rule and checks tags and storage class on a sample of sealed and unsealed raw objects.</div></div>
      <div class="card"><h2>Recent seals</h2>${table(seals.items.map((s) => ({ partition_id: s.partition_id, seal_version: s.seal_version, rows: s.rows, files: s.files.length, late_files: s.files.filter((f) => f.late).length, sealed_at: fmtT(s.sealed_at) })))}</div>`;
    $("#lc").onclick = async () => {
      $("#lcout").innerHTML = `<span class="spin"></span> checking…`;
      const r = await q("lifecycle", { sample: 30 });
      $("#lcout").innerHTML = `<div class="row" style="margin-bottom:10px">
          <span class="pill ${r.unsealed_in_archive_violations ? "bad" : "ok"}">${r.unsealed_in_archive_violations} unsealed objects in archive</span>
          <span class="pill">${r.checked} objects checked</span><span class="pill info">${r.archived_in_sample} already transitioned</span></div>
        <div class="grid g2"><div><b>Bucket lifecycle rule (raw)</b><pre class="json">${esc(JSON.stringify(r.lifecycle_rules, null, 2))}</pre></div>
        <div><b>Sample</b>${table(r.sample.map((s) => ({ file: s.file.split("/").slice(-4).join("/"), expected: s.expected, tags: Object.entries(s.tags).map(([k, v]) => `${k}=${v}`).join(" "), storage_class: s.storage_class })))}</div></div>`;
    };
  },
};

/* ----------------------------------------------------------------------- activity */
pages.activity = {
  title: "Activity & commands", sub: "Domain events from the projected activity feed; commands go through the Command API",
  async render(el) {
    const [act, pipe] = await Promise.all([q("activity", { limit: 150 }), q("pipeline")]);
    const cmds = Object.entries(pipe.commands || {}).map(([k, v]) => ({ command: k, ...v }));
    el.innerHTML = `
      <div class="grid g2">
        <div class="card"><h2>Send a command</h2>
          <div class="row"><input id="pmsg" value="hello from the dashboard" style="flex:1"><button id="ping">Ping</button></div>
          <p class="small muted">A Ping travels command API → single-writer queue → outbox → Redis Streams → projector → query API. It appears in the feed within a second.</p></div>
        <div class="card"><h2>Commands by status <span class="hint">read model</span></h2>${table(cmds, ["command", "succeeded", "retrying", "failed"])}</div>
      </div>
      <div class="card"><h2>Event feed</h2>${feed(act.items)}</div>`;
    $("#ping").onclick = async () => { const r = await cmd("Ping", { message: $("#pmsg").value }); toast(`Ping accepted: ${r.command_id.slice(0, 8)}…`); };
  },
};

/* ----------------------------------------------------------------------- rules (M5) */
const money = (v, cur = "USD") => (v == null ? "–" : `${Number(v).toFixed(Number(v) < 1 ? 4 : 2)} ${cur}`);
const statusPill = (s) => `<span class="pill ${{ succeeded: "ok", failed: "bad", blocked: "bad", awaiting_approval: "warn", deferred_budget: "warn", queued: "info", planned: "info" }[s] || ""}">${esc(s)}</span>`;

pages.rules = {
  title: "Rules", sub: "Sigma → ECS → coverage planner: each run states its tier, coverage and estimated vs actual cost",
  async render(el) {
    if (!el.dataset.ready) {
      el.dataset.ready = "1";
      const corpus = await q("rules/corpus");
      window._corpus = corpus.items;
      el.innerHTML = `
        <div class="card"><h2>Submit a Sigma rule <span class="hint">unsupported fields or modifiers are rejected at submit</span></h2>
          <div class="row"><select id="rsel" style="flex:1">${corpus.items.map((r, i) => `<option value="${i}">${esc(r.file)}</option>`).join("")}</select>
            <input id="rstart" value="2026-09-07" style="width:120px"><input id="rend" value="2026-09-14" style="width:120px">
            <button class="ghost" id="rdry">Dry run (plan + estimate)</button><button id="rrun">Run</button><button class="ghost" id="rall">Run whole corpus</button></div>
          <textarea id="ryaml" spellcheck="false" style="width:100%;height:190px;margin-top:10px" class="mono small"></textarea>
          <div id="rmsg" class="small muted"></div></div>
        <div class="card"><h2>Runs <span class="hint">click a run for its plan, estimate, approvals and hits</span></h2><div id="rruns"></div></div>`;
      const fill = () => ($("#ryaml").value = window._corpus[$("#rsel").value].yaml);
      $("#rsel").onchange = fill; fill();
      const submit = async (yaml, dry) => {
        const body = { rule_yaml: yaml, start: `${$("#rstart").value}T00:00:00Z`, end: `${$("#rend").value}T00:00:00Z`, dry_run: dry, submitted_by: "dashboard" };
        return cmd("SubmitRule", body);
      };
      $("#rdry").onclick = async () => { try { await submit($("#ryaml").value, true); toast("Plan requested"); } catch (e) { $("#rmsg").innerHTML = `<span class="pill bad">rejected</span> ${esc(e.message)}`; } };
      $("#rrun").onclick = async () => { try { await submit($("#ryaml").value, false); toast("Rule submitted"); } catch (e) { $("#rmsg").innerHTML = `<span class="pill bad">rejected</span> ${esc(e.message)}`; } };
      $("#rall").onclick = async () => { for (const r of window._corpus) await submit(r.yaml, false); toast(`${window._corpus.length} rules submitted`); };
    }
    const runs = await q("runs", { limit: 60 });
    const out = el.querySelector("#rruns"); if (!out) return;
    out.innerHTML = table(runs.items.map((r) => ({ title: r.title, origin: r.origin, status: r.status, tiers: (r.tiers || []).join(","), coverage: r.coverage_pct != null ? `${r.coverage_pct}%` : "–",
      approval: r.approval_level, estimated: money(r.estimated_cost, r.cost_currency || ""), actual: money(r.actual_cost, r.cost_currency || ""), hits: r.hits, restored_bytes: r.bytes_restored })), null, { empty: "No runs yet" });
    out.querySelectorAll("tbody tr").forEach((tr, i) => (tr.onclick = () => showRun(runs.items[i])));
  },
};

async function showRun(r) {
  drawer(`<span class="spin"></span>`);
  const run = await q(`rules/${r.rule_id}/runs/${r.run_id}`);
  const hits = run.status === "succeeded" ? await q(`rules/${r.rule_id}/runs/${r.run_id}/hits`, { limit: 200 }) : null;
  const est = run.estimate || {};
  drawer(`<h3>${esc(run.title || run.rule_id)}</h3>
    <div class="row">${statusPill(run.status)} <span class="pill">tiers ${(run.tiers || []).join(", ")}</span><span class="pill">coverage ${run.coverage_pct ?? "–"}%</span>
      <span class="pill ${run.approval_level === "auto" ? "ok" : run.approval_level === "blocked" ? "bad" : "warn"}">approval: ${esc(run.approval_level)}</span></div>
    <p class="small">Estimated <b>${money(run.estimated_cost, est.currency)}</b> · actual <b>${money(run.actual_cost, est.currency)}</b> · pricing ${esc(est.pricing_version || "")} · modelled scale ×${fmtN(est.scale_factor)}</p>
    ${(est.approval_reasons || []).map((x) => `<div class="small muted">${esc(x)}</div>`).join("")}
    <div class="row" style="margin:10px 0">
      ${["awaiting_approval", "planned"].includes(run.status) && run.approval_level !== "blocked" ? `<button data-ap="hunter">Approve as hunter</button><button class="ghost" data-ap="manager">Approve as manager</button>` : ""}
      ${run.status === "planned" ? `<button class="ghost" id="rexec">Execute</button>` : ""}</div>
    <h4>Plan steps</h4><pre class="json">${esc(JSON.stringify(run.steps, null, 2))}</pre>
    <h4>Cost lines</h4>${table((est.lines || []).map((l) => ({ item: l.item, quantity: l.quantity, unit: l.unit, cost: l.cost })))}
    ${hits ? `<h4>Hits (${hits.count}, ${hits.entities} entity-days, snapshot ${hits.snapshot_id})</h4>${table(hits.items, ["ts", "tier", "capability", "entity_key", "event_id", "count", "evidence"])}` : ""}`);
  document.querySelectorAll("[data-ap]").forEach((b) => (b.onclick = async () => {
    await cmd("ApproveRun", { run_id: run.run_id, approver: `dashboard-${b.dataset.ap}`, role: b.dataset.ap }); toast("Approval recorded"); closeDrawer();
  }));
  const ex = $("#rexec"); if (ex) ex.onclick = async () => { await cmd("ExecuteRule", { run_id: run.run_id }); toast("Execution queued"); closeDrawer(); };
}

/* ----------------------------------------------------------------------- costs */
pages.costs = {
  title: "Costs", sub: "Estimated vs actual cost per run (modelled scale), and estimator accuracy after calibration",
  async render(el) {
    const c = await q("costs");
    const cur = c.currency || "";
    el.innerHTML = `
      <div class="grid g4">
        ${kpi("Runs", fmtN(c.runs), "succeeded")}
        ${kpi("Estimated total", money(c.estimated_total, cur), "before execution")}
        ${kpi("Actual total", money(c.actual_total, cur), "measured quantities, same price table", true)}
        ${kpi("Median estimate error", c.estimate_error.median != null ? `${(c.estimate_error.median * 100).toFixed(1)}%` : "–", c.estimate_error.within_25pct != null ? `${(c.estimate_error.within_25pct * 100).toFixed(0)}% of runs within ±25%` : "")}
      </div>
      <div class="card"><h2>By origin</h2>${table(Object.entries(c.by_origin).map(([k, v]) => ({ origin: k, runs: v.runs, estimated: money(v.estimated, cur), actual: money(v.actual, cur) })))}</div>
      <div class="card"><h2>Runs</h2>${table(c.items.map((x) => ({ title: x.title, origin: x.origin, tiers: (x.tiers || []).join(","), estimated: money(x.estimated_cost, cur), actual: money(x.actual_cost, cur), restored_bytes: x.bytes_restored, objects: x.files_restored, finished: fmtT(x.finished_at) })).reverse())}</div>`;
  },
};

/* ----------------------------------------------------------------------- threat intelligence (M6) */
pages.ti = {
  title: "Threat intelligence", sub: "Tactical (IOCs) · operational (behaviours seen in the org) · strategic (trends), all ATT&CK-validated",
  async render(el) {
    const period = (el.querySelector("#tper") || {}).value || "year";
    const [s, st, pats] = await Promise.all([q("ti/summary"), q("ti/strategic", { period, compare: "yoy" }), q("ti/patterns")]);
    const cmp = st.comparison || [];
    const periods = [...new Set(cmp.map((x) => x.period_start))].sort();
    const tactics = [...new Set(cmp.map((x) => x.tactic))].sort();
    const max = Math.max(1, ...cmp.map((x) => x.observations));
    const cell = (p, t) => { const x = cmp.find((y) => y.period_start === p && y.tactic === t); if (!x) return `<td class="muted">·</td>`;
      const d = x.delta_vs_same_period_last_year; return `<td class="num" style="background:rgba(91,157,255,${(0.1 + (0.6 * x.observations) / max).toFixed(2)})" title="${esc(t)} ${p}: ${x.observations} (yoy ${d >= 0 ? "+" : ""}${d})">${x.observations}</td>`; };
    el.innerHTML = `
      <div class="grid g4">
        ${kpi("Indicators (tactical)", fmtN(s.tactical.indicators), `${fmtN(s.tactical.sighted)} sighted in the org`)}
        ${kpi("Observations (operational)", fmtN(s.operational.rows), Object.entries(s.operational.by_origin).map(([k, v]) => `${k} ${v}`).join(" · "), true)}
        ${kpi("Strategic rows", fmtN(s.strategic.rows), Object.keys(s.strategic.by_period).join(", "))}
        ${kpi("Tactics observed", fmtN(s.strategic.tactics.length), s.strategic.tactics.slice(0, 4).join(", "))}
      </div>
      <div class="card"><h2>ti.strategic: observations per tactic <span class="hint"><select id="tper">${["week", "month", "quarter", "year"].map((p) => `<option ${p === period ? "selected" : ""}>${p}</option>`).join("")}</select> cell tooltip shows year-on-year delta</span></h2>
        ${periods.length ? `<div class="scroll"><table><thead><tr><th>tactic</th>${periods.map((p) => `<th>${p}</th>`).join("")}</tr></thead><tbody>
          ${tactics.map((t) => `<tr><td>${esc(t)}</td>${periods.map((p) => cell(p, t)).join("")}</tr>`).join("")}</tbody></table></div>` : `<div class="empty">No strategic rows yet: run rules first</div>`}</div>
      <div class="card"><h2>Patterns (ti.operational) <span class="hint">LLM output is advisory: review moves it to validated / rejected</span></h2><div id="tpats"></div></div>`;
    $("#tper").onchange = () => pages.ti.render(el);
    $("#tpats").innerHTML = table(pats.items.map((p) => ({ title: p.title, origin: p.origin, techniques: p.techniques.join(", "), observations: p.observations, entities: p.entities, statuses: Object.entries(p.statuses).map(([k, v]) => `${k}:${v}`).join(" "), last_seen: fmtT(p.last_seen) })));
    $("#tpats").querySelectorAll("tbody tr").forEach((tr, i) => (tr.onclick = () => reviewPattern(pats.items[i])));
  },
};

function reviewPattern(p) {
  drawer(`<h3>${esc(p.title)}</h3><p class="small muted">${esc(p.pattern_id)} · ${esc(p.origin)}${p.llm_model ? ` · ${esc(p.llm_model)}` : ""}</p>
    <p>${p.techniques.map((t) => `<span class="pill info">${esc(t)}</span>`).join(" ")}</p>
    <div class="row"><button data-v="validated">Validate</button><button class="ghost" data-v="rejected">Reject</button></div>`);
  document.querySelectorAll("[data-v]").forEach((b) => (b.onclick = async () => {
    await cmd("ReviewPattern", { target_id: p.pattern_id, verdict: b.dataset.v, reviewer: "dashboard-analyst" }); toast(`Pattern ${b.dataset.v}`); closeDrawer();
  }));
}

/* ----------------------------------------------------------------------- feeds (M7) */
pages.feeds = {
  title: "TI feeds", sub: "Connector SDK: every new indicator triggers a batched, cost-estimated IOC retro-sweep over the retention window",
  async render(el) {
    const [f, tac] = await Promise.all([q("ti/feeds"), q("ti/tactical", { limit: 300 })]);
    el.innerHTML = `
      <div class="card"><h2>Connectors <span class="hint">${f.offline ? "offline mode: synthetic samples (TI_FEEDS_OFFLINE=1)" : "online"}</span></h2>
        ${table(f.items.map((x) => ({ connector: x.connector, generation: x.generation, enabled: x.enabled ? "yes" : "no", tlp: x.tlp, pulls: x.pulls ?? 0, last_pull: fmtT(x.last_pull_at), new_last_pull: x.indicators_new, total_new: x.indicators_total_new, warninglisted: x.suppressed, sweep: x.last_sweep_run_id ? x.last_sweep_run_id.slice(0, 8) : "–" })))}
        <div class="row" style="margin-top:10px"><select id="fsel">${f.items.map((x) => `<option>${esc(x.connector)}</option>`).join("")}</select><button id="fpull">Pull now</button>
          <span style="flex:1"></span><input id="iv" placeholder="analyst indicator: IP, domain, URL, hash" style="width:280px"><button class="ghost" id="iadd">Record + sweep</button></div></div>
      <div class="card"><h2>ti.tactical <span class="hint">${fmtN(tac.count)} rows · ${Object.entries(tac.by_source).map(([k, v]) => `${k} ${v}`).join(" · ")}</span></h2>
        ${table(tac.items.map((x) => ({ type: x.type, value: x.value, source: x.source, family: x.malware_family, threat: x.threat_type, confidence: x.confidence, tlp: x.tlp, status: x.status, org_sightings: x.org_sightings, last_sighting: fmtT(x.org_last_sighting) })))}</div>`;
    $("#fpull").onclick = async () => { await cmd("PullFeed", { connector: $("#fsel").value }); toast(`PullFeed ${$("#fsel").value} queued`); };
    $("#iadd").onclick = async () => { await cmd("RecordIndicator", { value: $("#iv").value, analyst: "dashboard" }); toast("Indicator recorded; retro-sweep queued"); };
  },
};

/* ----------------------------------------------------------------------- retention (M8) */
pages.retention = {
  title: "Retention", sub: "≥ 15 years for every layer; WORM raw, legal holds, tagged result snapshots and an annual readability drill",
  async render(el) {
    const r = await q("retention");
    const years = Object.entries(r.data_years || {});
    const maxY = Math.max(1, ...years.map(([, n]) => n));
    const d = r.last_readability_drill;
    el.innerHTML = `
      <div class="grid g4">
        ${kpi("Minimum retention", `${r.minimum_years} years`, `policy v${esc(r.policy_version)}`, true)}
        ${kpi("Data span", r.span_years != null ? `${r.span_years.toFixed(1)} years` : "–", `oldest partition ${esc(r.oldest_partition_date || "–")}`)}
        ${kpi("Legal holds", fmtN(r.legal_holds.length), r.legal_holds.slice(0, 2).join(", "))}
        ${kpi("Readability drill", d ? (d.status === "ok" ? "OK" : "FAILED") : "never", d ? `${d.partitions} partitions · ${(d.years || []).length} years · ${fmtT(d.at)}` : "")}
      </div>
      <div class="card"><h2>Partitions per year</h2>${years.map(([y, n]) => `<div class="hbar"><div>${y}</div><div class="track"><i style="width:${(100 * n) / maxY}%;background:var(--accent)"></i></div><div class="num">${fmtN(n)}</div></div>`).join("") || `<div class="empty">No data</div>`}
        <div class="row" style="margin-top:10px"><button id="drill">Run readability drill</button><button class="ghost" id="retdry">Retention dry run (all layers)</button></div></div>
      <div class="card"><h2>Layers</h2>${table(Object.entries(r.layers).map(([k, v]) => ({ layer: k, years: v.years, cutoff: v.cutoff, object_lock: v.object_lock || "", last_applied: fmtT(v.last_applied), last_result: v.last_result ? `${v.last_result.deleted_rows} rows / ${v.last_result.deleted_objects} objects, ${v.last_result.tagged_snapshots} tags` : "–" })))}</div>
      <div class="card"><h2>Raw Object Lock</h2><pre class="json">${esc(JSON.stringify(r.raw_object_lock, null, 2))}</pre></div>`;
    $("#drill").onclick = async () => { await cmd("ReadabilityDrill", {}); toast("Readability drill queued"); };
    $("#retdry").onclick = async () => { for (const layer of Object.keys(r.layers)) await cmd("ApplyRetention", { layer, dry_run: true }); toast("Retention dry runs queued"); };
  },
};

/* ======================================================================= router */
async function route() {
  const name = (location.hash || "#overview").slice(1);
  const page = pages[name] || pages.overview;
  document.querySelectorAll("#nav a").forEach((a) => a.classList.toggle("active", a.getAttribute("href") === `#${name}`));
  $("#title").textContent = page.title; $("#subtitle").textContent = page.sub;
  // A fresh container per navigation: a refresh still in flight for the previous page
  // can then only write into a detached element, never over the new page.
  clearInterval(timer);
  const old = $("#page"); const el = document.createElement("div");
  el.className = "page"; el.id = "page"; old.replaceWith(el);
  const tick = async () => {
    try { await page.render(el); setLive(true, `live · updated ${new Date().toLocaleTimeString()}`); }
    catch (e) { setLive(false, "API unavailable"); if (!el.innerHTML) el.innerHTML = `<div class="card"><span class="pill bad">error</span> ${esc(e.message)}</div>`; }
  };
  el.innerHTML = `<div class="card"><span class="spin"></span> loading…</div>`;
  await tick();
  if (!page.keep) timer = setInterval(() => { if (!document.hidden && !$("#drawer").classList.contains("open")) tick(); }, name === "partitions" || name === "artefacts" ? 6000 : 4000);
}
window.addEventListener("hashchange", route);
route();
