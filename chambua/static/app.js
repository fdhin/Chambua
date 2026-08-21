/* Chambua — vanilla JS, no framework, no build step. */

"use strict";

/* ---------- state ---------- */

const state = {
  csrf: null,
  records: new Map(), // id -> summary
  issues: [], // {fileId?, filename, reason, retryable, stage}
  retryFiles: new Map(), // fileId -> File
  currentId: null,
  parsed: null,
  remoteLoaded: false,
  urlFilter: { scheme: "all", domain: "", dedupe: true },
  raw: {}, // raw text for the right-pane tabs: {html, plaintext, source}
  leftTab: "details",
  rightTab: "rendered",
};

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

/* ---------- helpers ---------- */

function esc(s) {
  return String(s ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function toast(msg) {
  const el = $("#toast");
  el.textContent = msg;
  el.classList.add("show");
  clearTimeout(toast._t);
  toast._t = setTimeout(() => el.classList.remove("show"), 2500);
}

async function copyText(text, label) {
  try {
    await navigator.clipboard.writeText(text);
    toast((label || "Copied") + " to clipboard");
  } catch {
    toast("Clipboard copy failed");
  }
}

function fmtBytes(n) {
  if (n == null) return "—";
  if (n < 1024) return n + " B";
  const units = ["KB", "MB", "GB"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return v.toFixed(2) + " " + units[i];
}

function fmtDate(iso) {
  if (!iso) return null;
  const d = new Date(iso);
  if (isNaN(d)) return iso;
  return d.toLocaleString(undefined, {
    year: "numeric", month: "short", day: "numeric",
    hour: "2-digit", minute: "2-digit", second: "2-digit",
  });
}

function vtUrlLookup(url) {
  window.open(
    "https://www.virustotal.com/gui/search/" + encodeURIComponent(url),
    "_blank", "noopener"
  );
}

function vtFileLookup(sha256) {
  window.open("https://www.virustotal.com/gui/file/" + sha256, "_blank", "noopener");
}

function confirmDialog(text) {
  const dlg = $("#confirmDialog");
  $("#confirmText").textContent = text;
  return dlg.showModal().then(() => dlg.returnValue === "ok");
}

/* ---------- api ---------- */

async function api(method, path, body) {
  const headers = {};
  if (state.csrf && method !== "GET") headers["X-CSRF-Token"] = state.csrf;
  let payload;
  if (body instanceof FormData) payload = body;
  const res = await fetch(path, {
    method,
    headers,
    body: method === "GET" ? undefined : payload,
  });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const j = await res.json();
      if (j.detail) detail = typeof j.detail === "string" ? j.detail : JSON.stringify(j.detail);
    } catch { /* keep statusText */ }
    throw new Error(detail);
  }
  return res;
}

async function apiJson(method, path) {
  const res = await api(method, path);
  return res.json();
}

/* ---------- bootstrap ---------- */

async function bootstrap() {
  const info = await apiJson("GET", "/api/session");
  state.csrf = info.csrf_token;
  await refreshRecords();
}

/* ---------- upload / ingest ---------- */

async function refreshRecords() {
  const data = await apiJson("GET", "/api/records");
  state.records = new Map(data.records.map((r) => [r.record_id, r]));
  state.issues = data.issues;
  renderFileList();
  updateEmptyState();
}

async function uploadFiles(fileList) {
  const files = Array.from(fileList);
  await Promise.allSettled(files.map((f) => uploadOne(f)));
}

async function uploadOne(file, reuseId) {
  const fileId = reuseId || (crypto.randomUUID ? crypto.randomUUID() : String(Math.random()));
  state.retryFiles.set(fileId, file);
  const fd = new FormData();
  fd.append("files", file, file.name);
  try {
    const res = await api("POST", "/api/records", fd);
    const data = await res.json();
    for (const rec of data.records) state.records.set(rec.record_id, rec);
    for (const issue of data.issues) state.issues.push({ ...issue, fileId });
    renderFileList();
    updateEmptyState();
    const fail = data.issues[0];
    if (fail) toast(`${fail.filename}: ${fail.reason}`);
    const first = data.records[0];
    if (first && state.currentId === null) selectRecord(first.record_id);
  } catch (err) {
    state.issues.push({
      filename: file.name, reason: "upload failed: " + err.message,
      retryable: true, stage: "upload", fileId,
    });
    renderFileList();
  }
}

async function retryIssue(issue) {
  const file = state.retryFiles.get(issue.fileId);
  if (!file) {
    toast("Original file is no longer available — drop it again");
    return;
  }
  state.issues = state.issues.filter((i) => i !== issue);
  renderFileList();
  await uploadOne(file, issue.fileId);
}

/* ---------- session list ---------- */

function renderFileList() {
  const ul = $("#filelistItems");
  ul.innerHTML = "";
  $("#filelistCount").textContent = state.records.size
    ? `(${state.records.size})` : "";
  for (const rec of state.records.values()) {
    const li = document.createElement("li");
    li.dataset.id = rec.record_id;
    if (rec.record_id === state.currentId) li.classList.add("current");
    li.innerHTML = `
      <button class="fl-remove" title="Remove from session">&times;</button>
      <div class="fl-subject">${esc(rec.subject || "(no subject)")}</div>
      <div class="fl-meta">
        <span class="badge grey">${esc(rec.source_kind.toUpperCase())}</span>
        <span>${esc(rec.from || "unknown sender")}</span>
      </div>`;
    li.addEventListener("click", (e) => {
      if (e.target.classList.contains("fl-remove")) return;
      selectRecord(rec.record_id);
    });
    li.querySelector(".fl-remove").addEventListener("click", async (e) => {
      e.stopPropagation();
      await api("DELETE", "/api/records/" + rec.record_id);
      state.records.delete(rec.record_id);
      if (state.currentId === rec.record_id) {
        state.currentId = null;
        state.parsed = null;
        const next = state.records.keys().next();
        if (!next.done) await selectRecord(next.value);
        else resetUi();
      }
      renderFileList();
      updateEmptyState();
    });
    ul.appendChild(li);
  }
  const issueBox = $("#issueList");
  issueBox.innerHTML = "";
  for (const issue of state.issues) {
    const div = document.createElement("div");
    div.className = "issue-entry";
    div.innerHTML = `
      <div class="ie-name">${esc(issue.filename)}</div>
      <div class="ie-reason">${esc(issue.reason)}</div>
      ${issue.retryable ? '<button class="linkish">retry</button>' : ""}`;
    if (issue.retryable) {
      div.querySelector("button").addEventListener("click", () => retryIssue(issue));
    }
    issueBox.appendChild(div);
  }
}

function updateEmptyState() {
  $("#emptyState").hidden = state.records.size > 0;
}

function resetUi() {
  $("#subject").textContent = "Chambua — drop a message to begin";
  $("#subjectMeta").textContent = "Local analysis only — nothing leaves this machine";
  $("#btnPermalink").disabled = true;
  state.remoteLoaded = false;
  for (const panel of $$("#leftPanels .panel")) panel.innerHTML = "";
  $("#renderFrame").srcdoc = "";
  $("#remoteBanner").hidden = true;
  $("#rightPanels").querySelectorAll(".code-view").forEach((v) => (v.innerHTML = ""));
  state.raw = {};
  updateTabStates();
}

/* ---------- record selection ---------- */

async function selectRecord(id) {
  state.currentId = id;
  state.remoteLoaded = false;
  state.raw = {};
  let parsed;
  try {
    parsed = await apiJson("GET", "/api/records/" + id);
  } catch (err) {
    toast("Failed to load record: " + err.message);
    return;
  }
  state.parsed = parsed;
  const rec = state.records.get(id) || {};
  $("#subject").textContent = parsed.details.subject || "(no subject)";
  const metaBits = [
    parsed.details.from?.address,
    fmtDate(parsed.details.timestamp),
    parsed.extracted_from_zip ? `from ${parsed.extracted_from_zip}` : null,
  ].filter(Boolean);
  $("#subjectMeta").textContent = metaBits.join("  ·  ") || rec.source_file || "";
  $("#btnPermalink").disabled = false;
  renderFileList();
  renderDetails();
  renderAuth();
  renderUrls();
  renderAttachments();
  renderTransmission();
  renderXHeaders();
  updateTabStates();
  pickInitialRightTab();
  loadRightTab(state.rightTab);
}

/* ---------- tabs ---------- */

function tabButton(pane, name) {
  return $(`#${pane}Tabs .tab[data-tab="${name}"]`);
}

function switchTab(pane, name) {
  if (pane === "left") state.leftTab = name;
  else state.rightTab = name;
  $$(`#${pane}Tabs .tab`).forEach((b) => b.classList.toggle("active", b.dataset.tab === name));
  $$(`#${pane}Panels .panel`).forEach((p) => p.classList.toggle("active", p.dataset.panel === name));
  if (pane === "right") loadRightTab(name);
}

function updateTabStates() {
  const p = state.parsed;
  const hasHtml = p?.content?.has_html;
  const hasPt = p?.content?.has_plaintext;
  tabButton("right", "rendered").disabled = !hasHtml;
  tabButton("right", "html").disabled = !hasHtml;
  tabButton("right", "plaintext").disabled = !hasPt;
  tabButton("right", "source").disabled = !p;

  // Warning dots: red for hard fail, yellow for neutral/soft signals.
  clearDot("left", "auth");
  clearDot("left", "urls");
  if (p) {
    const auth = p.authentication || {};
    const authResults = [
      auth.spf?.result,
      auth.dkim?.result,
      ...(auth.dkim?.signatures || []).map((s) => s.result),
      auth.dmarc?.result,
    ].filter(Boolean);
    if (authResults.some((r) => r === "fail")) setDot("left", "auth", "red");
    else if (authResults.some((r) => ["neutral", "softfail", "temperror", "permerror"].includes(r)))
      setDot("left", "auth", "yellow");
    const urls = p.urls || [];
    if (urls.some((u) => u.anchor_mismatch)) setDot("left", "urls", "red");
    else if (urls.some((u) => u.differs_from_from_domain)) setDot("left", "urls", "yellow");
  }
}

function setDot(pane, name, color) {
  const btn = tabButton(pane, name);
  if (!btn || btn.querySelector(".dot")) return;
  const dot = document.createElement("span");
  dot.className = "dot " + color;
  btn.appendChild(dot);
}

function clearDot(pane, name) {
  tabButton(pane, name)?.querySelectorAll(".dot").forEach((d) => d.remove());
}

function pickInitialRightTab() {
  const p = state.parsed;
  if (!p) return;
  const currentOk =
    (state.rightTab !== "rendered" && state.rightTab !== "html" && state.rightTab !== "plaintext") ||
    (state.rightTab === "rendered" && p.content.has_html) ||
    (state.rightTab === "html" && p.content.has_html) ||
    (state.rightTab === "plaintext" && p.content.has_plaintext);
  if (currentOk) return;
  if (p.content.has_html) switchTab("right", "rendered");
  else if (p.content.has_plaintext) switchTab("right", "plaintext");
  else switchTab("right", "source");
}

/* ---------- left pane: details ---------- */

function kvRow(label, value, opts = {}) {
  const cls = opts.mono === false ? "v plain" : "v";
  const shown = value === null || value === undefined || value === ""
    ? '<span class="placeholder">—</span>'
    : opts.raw ? value : esc(value);
  return `<div class="k">${esc(label)}</div><div class="${cls}">${shown}</div>`;
}

function renderDetails() {
  const panel = $('#leftPanels .panel[data-panel="details"]');
  const p = state.parsed;
  if (!p) { panel.innerHTML = ""; return; }
  const d = p.details;
  let html = "";
  if (p.parse_warnings && p.parse_warnings.length) {
    html += `<div class="warn-banner">&#9888; Parse warnings: ${esc(p.parse_warnings.join(", "))}</div>`;
  }
  html += '<div class="kv-grid">';
  html += kvRow("From", d.from?.address);
  html += kvRow("Display name", d.from?.display_name);
  html += kvRow("Sender", d.sender);
  html += kvRow("To", (d.to || []).join(", ") || null);
  html += kvRow("Cc", (d.cc || []).join(", ") || null);
  html += kvRow("In-Reply-To", d.in_reply_to);
  html += kvRow("Timestamp", d.timestamp ? `${esc(fmtDate(d.timestamp))}` : null);
  html += kvRow("Reply-To", d.reply_to);
  html += kvRow("Message-ID", d.message_id);
  html += kvRow("Return-Path", d.return_path);
  html += kvRow("Originating IP", d.originating_ip);
  html += kvRow("rDNS", d.rdns);
  html += "</div>";
  panel.innerHTML = html;
}

/* ---------- left pane: authentication ---------- */

function pillFor(result, stamped = true) {
  if (!stamped) return '<span class="pill none">NOT STAMPED</span>';
  const r = (result || "none").toLowerCase();
  const cls = ["pass", "fail", "neutral", "softfail", "none"].includes(r)
    ? r
    : ["temperror", "permerror", "timeout"].includes(r) ? "temperror" : "none";
  return `<span class="pill ${cls}">${esc((result || "none").toUpperCase())}</span>`;
}

function renderAuth() {
  const panel = $('#leftPanels .panel[data-panel="auth"]');
  const p = state.parsed;
  if (!p) { panel.innerHTML = ""; return; }
  const auth = p.authentication || {};
  const stamped = auth.source === "header";
  const live = p.live_verification;

  const section = (title, pill, bodyHtml) => `
    <div class="section">
      <div class="section-head">${title} ${pill}
        <span class="grow"></span>
        <button class="linkish btn-reverify" data-which="all">Re-verify now</button>
      </div>
      <div class="section-body">${bodyHtml}</div>
    </div>`;

  const notStampedNote =
    '<div class="note">Not stamped by receiver — run Re-verify to check now</div>';

  let spfBody;
  if (!stamped && !live) spfBody = notStampedNote;
  else {
    const s = live?.spf || auth.spf || {};
    spfBody = `<div class="kv-grid">
      ${kvRow("Originating IP", s.originating_ip)}
      ${kvRow("rDNS", s.rdns)}
      ${kvRow("Return-Path domain", s.return_path_domain)}
      ${kvRow("SPF record", s.record)}
      ${live ? kvRow("Live check", (live.spf?.fetched_at ? esc(fmtDate(live.spf.fetched_at)) : null)) : ""}
      ${live?.spf?.explanation ? kvRow("Explanation", live.spf.explanation) : ""}
      ${live?.spf?.note ? kvRow("Note", live.spf.note) : ""}
    </div>`;
  }

  let dkimBody;
  if (!stamped && !live) dkimBody = notStampedNote;
  else {
    const sigs = (live?.dkim?.signatures?.length ? live.dkim.signatures : auth.dkim?.signatures) || [];
    const count = sigs.length;
    const summary = count === 0 ? "No signatures"
      : `${count} Signature${count === 1 ? "" : "s"} — ` +
        Object.entries(sigs.reduce((acc, s) => { acc[s.result || "unknown"] = (acc[s.result || "unknown"] || 0) + 1; return acc; }, {}))
          .map(([k, v]) => `${v} ${k.toUpperCase()}`).join(", ");
    dkimBody = `<div class="small muted" style="margin-bottom:8px">${esc(summary)}</div>`;
    if (live && live.dkim?.note) dkimBody += `<div class="note">${esc(live.dkim.note)}</div>`;
    for (const [i, s] of sigs.entries()) {
      dkimBody += `<div class="section" style="margin:0 0 8px">
        <div class="section-head" style="padding:7px 12px">
          Signature ${i + 1} ${pillFor(s.result)}
          ${live?.dkim?.fetched_at ? '<span class="live-label">live ' + esc(fmtDate(live.dkim.fetched_at)) + "</span>" : ""}
        </div>
        <div class="section-body" style="padding:8px 12px"><div class="kv-grid" style="border:none">
          ${kvRow("Selector", s.selector)}
          ${kvRow("Signing domain", s.signing_domain)}
          ${kvRow("Algorithm", s.algorithm)}
          ${kvRow("Verification", s.verification)}
        </div></div>
      </div>`;
    }
  }

  let dmarcBody;
  if (!stamped && !live) dmarcBody = notStampedNote;
  else {
    const dm = live?.dmarc || auth.dmarc || {};
    dmarcBody = `<div class="kv-grid">
      ${kvRow("From domain", dm.from_domain)}
      ${kvRow("DMARC record", dm.record)}
      ${dm.policy ? kvRow("Policy", dm.policy) : ""}
      ${live?.dmarc?.fetched_at ? kvRow("Live check", esc(fmtDate(live.dmarc.fetched_at))) : ""}
      ${live?.dmarc?.note ? kvRow("Note", live.dmarc.note) : ""}
    </div>`;
  }

  const spfPill = live?.spf?.result ? pillFor(live.spf.result) : pillFor(auth.spf?.result, stamped);
  const dkimPill = live?.dkim?.result ? pillFor(live.dkim.result) : pillFor(auth.dkim?.result, stamped);
  const dmarcPill = live?.dmarc?.result ? pillFor(live.dmarc.result) : pillFor(auth.dmarc?.result, stamped);

  let extras = "";
  const extraList = (auth.extras || []).concat(
    (live?.dmarc && live.dmarc.result === "timeout" ? [{ method: "dmarc-live", result: "timeout", properties: null }] : []),
    (live?.spf && live.spf.result === "timeout" ? [{ method: "spf-live", result: "timeout", properties: null }] : []),
    (live?.dkim && live.dkim.result === "timeout" ? [{ method: "dkim-live", result: "timeout", properties: null }] : [])
  );
  if (extraList.length) {
    extras = `<div class="small muted" style="margin-top:4px">Also stamped: ` +
      extraList.map((e) =>
        `<span class="badge grey">${esc(e.method)}=${esc(e.result)}</span>`).join(" ") +
      "</div>";
  }

  panel.innerHTML =
    section("SPF", spfPill, spfBody) +
    section("DKIM", dkimPill, dkimBody) +
    section("DMARC", dmarcPill, dmarcBody) +
    extras;

  panel.querySelectorAll(".btn-reverify").forEach((btn) =>
    btn.addEventListener("click", () => runReverify(btn)));
}

async function runReverify(btn) {
  btn.disabled = true;
  btn.textContent = "Re-verifying…";
  try {
    const result = await apiJson("POST", "/api/records/" + state.currentId + "/reverify");
    state.parsed.live_verification = result;
    renderAuth();
    toast("Live verification complete");
  } catch (err) {
    toast("Re-verify failed: " + err.message);
    btn.disabled = false;
    btn.textContent = "Re-verify now";
  }
}

/* ---------- left pane: urls ---------- */

function renderUrls() {
  const panel = $('#leftPanels .panel[data-panel="urls"]');
  const p = state.parsed;
  if (!p) { panel.innerHTML = ""; return; }
  const urls = p.urls || [];
  if (!urls.length) {
    panel.innerHTML = '<div class="empty-tab">No URLs found in this message</div>';
    return;
  }
  const f = state.urlFilter;
  let list = urls;
  if (f.dedupe) {
    const seen = new Set();
    list = urls.filter((u) => {
      const k = u.url.replace(/\/$/, "");
      if (seen.has(k)) return false;
      seen.add(k);
      return true;
    });
  }
  const scheme = (u) => (u.url.split(":")[0] || "").toLowerCase();
  if (f.scheme !== "all") {
    list = list.filter((u) =>
      f.scheme === "other" ? !["http", "https", "mailto"].includes(scheme(u)) : scheme(u) === f.scheme);
  }
  if (f.domain) {
    const needle = f.domain.toLowerCase();
    list = list.filter((u) => (u.domain || "").toLowerCase().includes(needle));
  }

  const rows = list.map((u) => {
    const domainCell = esc(u.domain || "—");
    const badges = [
      u.anchor_mismatch ? '<span class="badge red">Anchor mismatch</span>' : "",
      u.differs_from_from_domain ? '<span class="badge yellow">&ne; From domain</span>' : "",
    ].filter(Boolean).join(" ");
    return `<div class="url-card">
      <div class="url-raw">${esc(u.url)}</div>
      <div class="url-meta">
        <span><span class="muted">Domain:</span> <span class="mono">${domainCell}</span></span>
        <span><span class="muted">Source:</span> ${esc(u.source)}</span>
        ${badges}
      </div>
      ${u.anchor_text ? `<div class="url-anchor">Anchor text: <code>${esc(u.anchor_text)}</code></div>` : ""}
      <div class="url-defang">
        <code>${esc(u.defanged)}</code>
        <button class="copy-btn" data-copy="${esc(u.defanged)}">Copy</button>
        <button class="linkish vt-url">Look up on VirusTotal</button>
      </div>
    </div>`;
  }).join("");

  panel.innerHTML = `
    <div class="filter-bar">
      <select id="urlScheme">
        <option value="all">All schemes</option>
        <option value="http">http</option>
        <option value="https">https</option>
        <option value="mailto">mailto</option>
        <option value="other">other</option>
      </select>
      <input type="text" id="urlDomain" placeholder="Domain contains…">
      <label><input type="checkbox" id="urlDedupe" checked> Dedupe</label>
      <span class="small muted">${list.length} of ${urls.length}</span>
    </div>
    ${rows}`;

  const schemeSel = $("#urlScheme");
  const domainIn = $("#urlDomain");
  const dedupeCb = $("#urlDedupe");
  schemeSel.value = f.scheme;
  domainIn.value = f.domain;
  dedupeCb.checked = f.dedupe;
  schemeSel.addEventListener("change", () => { f.scheme = schemeSel.value; renderUrls(); });
  domainIn.addEventListener("input", debounce(() => { f.domain = domainIn.value.trim(); renderUrls(); }, 200));
  dedupeCb.addEventListener("change", () => { f.dedupe = dedupeCb.checked; renderUrls(); });
  panel.querySelectorAll("[data-copy]").forEach((b) =>
    b.addEventListener("click", () => copyText(b.dataset.copy, "Defanged URL")));
  panel.querySelectorAll(".vt-url").forEach((b) => {
    const url = b.closest(".url-card").querySelector(".url-raw").textContent;
    b.addEventListener("click", () => vtUrlLookup(url));
  });
}

/* ---------- left pane: attachments ---------- */

function renderAttachments() {
  const panel = $('#leftPanels .panel[data-panel="attachments"]');
  const p = state.parsed;
  if (!p) { panel.innerHTML = ""; return; }
  const atts = p.attachments || [];
  if (!atts.length) {
    panel.innerHTML = '<div class="empty-tab">No attachments</div>';
    return;
  }
  panel.innerHTML = atts.map((a, i) => `
    <div class="att-card">
      <div class="att-head">
        <span class="att-num">${i + 1}.</span>
        <span class="att-name">${esc(a.filename)}</span>
        <span class="att-type">${esc((a.extension || a.mime_type || "?").toUpperCase())}</span>
      </div>
      <div class="att-body">
        <div class="att-row"><span class="lbl">Size</span><span>${esc(fmtBytes(a.size_bytes))}</span><span></span></div>
        <div class="att-row"><span class="lbl">Type</span><span>${esc(a.mime_type || "—")}</span><span></span></div>
        <div class="att-row"><span class="lbl">MD5</span><span>${esc(a.md5)}</span><button class="copy-btn" data-copy="${esc(a.md5)}">Copy</button></div>
        <div class="att-row"><span class="lbl">SHA-1</span><span>${esc(a.sha1)}</span><button class="copy-btn" data-copy="${esc(a.sha1)}">Copy</button></div>
        <div class="att-row"><span class="lbl">SHA-256</span><span>${esc(a.sha256)}</span><button class="copy-btn" data-copy="${esc(a.sha256)}">Copy</button></div>
        ${a.notes ? `<div class="warn-banner" style="margin:8px 0 0">&#9888; ${esc(a.notes)}</div>` : ""}
        <div class="att-actions">
          <button class="linkish vt-file" data-sha="${esc(a.sha256)}">Look up on VirusTotal</button>
          <button class="linkish save-att" data-sha="${esc(a.sha256)}" data-name="${esc(a.filename)}">Save to disk</button>
        </div>
      </div>
    </div>`).join("");

  panel.querySelectorAll("[data-copy]").forEach((b) =>
    b.addEventListener("click", () => copyText(b.dataset.copy, "Hash")));
  panel.querySelectorAll(".vt-file").forEach((b) =>
    b.addEventListener("click", () => vtFileLookup(b.dataset.sha)));
  panel.querySelectorAll(".save-att").forEach((b) =>
    b.addEventListener("click", async () => {
      const ok = await confirmDialog(
        `"${b.dataset.name}" came from a suspect message. Save anyway?`
      );
      if (ok) window.location.href =
        `/api/records/${state.currentId}/attachments/${b.dataset.sha}`;
    }));
}

/* ---------- left pane: transmission ---------- */

function endpointText(ep) {
  if (!ep) return null;
  const host = ep.host || "unknown host";
  return ep.ip ? `${host} (${ep.ip})` : host;
}

function renderTransmission() {
  const panel = $('#leftPanels .panel[data-panel="transmission"]');
  const p = state.parsed;
  if (!p) { panel.innerHTML = ""; return; }
  const hops = p.transmission || [];
  if (!hops.length) {
    panel.innerHTML = '<div class="empty-tab">No Received: headers in this message</div>';
    return;
  }
  const lastTs = hops[hops.length - 1]?.timestamp;
  let html = `
    <div class="timeline-head">
      <span class="muted small">Delivery path — oldest hop first</span>
      <span class="tooltip-info">&#9432;
        <span class="tip">Raw Received: headers are added bottom-up (newest first).
        This timeline is inverted to show the message's journey oldest &rarr; newest.</span>
      </span>
    </div>
    <div class="timeline">`;
  for (const hop of hops) {
    const more = [
      ["Protocol", hop.protocol],
      ["TLS", hop.tls],
      ["ID", hop.id],
      ["For", hop.for],
      ["With", hop.with],
      ["rDNS", hop.received_from?.rdns],
    ].filter(([, v]) => v);
    html += `
      <div class="hop">
        <div class="hop-head">
          <span class="hop-num">HOP ${hop.hop}</span>
          <span class="hop-ts">${esc(fmtDate(hop.timestamp) || "—")}</span>
        </div>
        <div class="hop-endpoints">
          <div class="hop-endpoint"><span class="he-lbl">Received from</span><span class="he-val">${esc(endpointText(hop.received_from) || "—")}</span></div>
          <div class="hop-endpoint"><span class="he-lbl">Received by</span><span class="he-val">${esc(endpointText(hop.received_by) || "—")}</span></div>
        </div>
        ${more.length ? `<button class="hop-toggle" data-target="more">More &#9662;</button>` : ""}
        <div class="hop-more">${more.map(([k, v]) =>
          `<div class="hop-endpoint"><span class="he-lbl">${esc(k)}</span><span class="he-val">${esc(v)}</span></div>`).join("")}</div>
        <button class="hop-toggle" data-target="raw">Show raw &#9662;</button>
        <div class="hop-raw">${esc(hop.raw)}</div>
      </div>`;
  }
  html += `
    <div class="hop-terminal">&#128234; Recipient mailbox
      <span style="margin-left:auto">${esc(fmtDate(lastTs) || "")}</span>
    </div>
  </div>`;
  panel.innerHTML = html;

  panel.querySelectorAll(".hop-toggle").forEach((btn) =>
    btn.addEventListener("click", () => {
      const target = btn.parentElement.querySelector(".hop-" + btn.dataset.target);
      const open = target.classList.toggle("open");
      const label = btn.dataset.target === "raw" ? "Show raw" : "More";
      btn.innerHTML = label + (open ? " &#9652;" : " &#9662;");
    }));
}

/* ---------- left pane: x-headers ---------- */

let xhFilter = "";

function renderXHeaders() {
  const panel = $('#leftPanels .panel[data-panel="xheaders"]');
  const p = state.parsed;
  if (!p) { panel.innerHTML = ""; return; }
  const headers = p.x_headers || [];
  if (!headers.length) {
    panel.innerHTML = '<div class="empty-tab">No X- headers in this message</div>';
    return;
  }
  let list = headers;
  let count = headers.length;
  if (xhFilter) {
    const needle = xhFilter.toLowerCase();
    list = headers.filter((h) =>
      h.name.toLowerCase().includes(needle) || (h.value || "").toLowerCase().includes(needle));
  }
  panel.innerHTML = `
    <div class="xh-search">
      <input type="search" placeholder="Filter X-headers by name or value…" value="${esc(xhFilter)}">
      <span class="count">${list.length === count ? `${count} headers` : `${list.length} / ${count} headers`}</span>
      <button class="linkish" id="xhClear">Clear</button>
    </div>
    ${list.map((h) => `
      <div class="xh-row">
        <div class="xh-name">${esc(h.name)}</div>
        <div class="xh-value">${esc(h.value)}</div>
      </div>`).join("")}`;

  const input = panel.querySelector("input");
  input.addEventListener("input", debounce(() => {
    xhFilter = input.value;
    renderXHeaders();
    const fresh = panel.querySelector("input");
    fresh.focus();
    fresh.setSelectionRange(fresh.value.length, fresh.value.length);
  }, 180));
  $("#xhClear").addEventListener("click", () => { xhFilter = ""; renderXHeaders(); });
}

/* ---------- right pane ---------- */

const MAX_RENDER_LINES = 20000;

function highlightHtmlLine(escaped) {
  return escaped
    .replace(/(&lt;!--[\s\S]*?--&gt;)/g, '<span class="tok-comment">$1</span>')
    .replace(/(&lt;\/?)([\w:-]+)/g, '$1<span class="tok-tag">$2</span>')
    .replace(/([\w:-]+)=(&quot;[^&]*?&quot;|&#39;[^&]*?&#39;)/g,
      '<span class="tok-attr">$1</span>=<span class="tok-str">$2</span>');
}

function renderCode(container, text, { highlight = false, query = "" } = {}) {
  const lines = text.split(/\r?\n/);
  const capped = lines.length > MAX_RENDER_LINES;
  const shown = capped ? lines.slice(0, MAX_RENDER_LINES) : lines;
  const frag = document.createDocumentFragment();
  const q = query.toLowerCase();
  for (const line of shown) {
    const div = document.createElement("div");
    div.className = "code-line";
    let content = esc(line);
    if (q) {
      const idx = content.toLowerCase().indexOf(q);
      if (idx !== -1) {
        content =
          content.slice(0, idx) + "<mark>" +
          content.slice(idx, idx + q.length) + "</mark>" +
          content.slice(idx + q.length);
      }
    } else if (highlight) {
      content = highlightHtmlLine(content);
    }
    div.innerHTML = content || "&nbsp;";
    frag.appendChild(div);
  }
  if (capped) {
    const note = document.createElement("div");
    note.className = "small faint";
    note.style.padding = "10px 4px";
    note.textContent = `… ${lines.length - MAX_RENDER_LINES} more lines not rendered (use Copy all)`;
    frag.appendChild(note);
  }
  container.innerHTML = "";
  container.appendChild(frag);
}

function countMatches(text, query) {
  if (!query) return 0;
  const q = query.toLowerCase();
  return (text.toLowerCase().split(q).length - 1) || 0;
}

async function loadRightTab(name) {
  const p = state.parsed;
  if (!p) return;
  const id = state.currentId;
  if (name === "rendered") {
    const frame = $("#renderFrame");
    const banner = $("#remoteBanner");
    frame.srcdoc = "";
    if (!p.content.has_html) return;
    try {
      const url = `/api/records/${id}/render${state.remoteLoaded ? "?remote=1" : ""}`;
      const html = await (await api("GET", url)).text();
      if (state.currentId !== id) return;
      frame.srcdoc = html;
      banner.hidden = false;
      banner.classList.toggle("loaded", state.remoteLoaded);
      $("#remoteBannerText").textContent = state.remoteLoaded
        ? "Remote content loaded for this record (this session only)."
        : "Remote content blocked.";
    } catch (err) {
      toast("Failed to render: " + err.message);
    }
    return;
  }
  const targets = {
    html: { url: `/api/records/${id}/html`, view: $("#htmlView"), search: $("#htmlSearch"), count: $("#htmlMatchCount"), highlight: true },
    plaintext: { url: `/api/records/${id}/plaintext`, view: $("#ptView"), search: $("#ptSearch"), count: $("#ptMatchCount"), highlight: false },
    source: { url: `/api/records/${id}/source`, view: $("#srcView"), search: $("#srcSearch"), count: $("#srcMatchCount"), highlight: false },
  };
  const t = targets[name];
  if (!t) return;
  if (!state.raw[name]) {
    try {
      state.raw[name] = await (await api("GET", t.url)).text();
    } catch (err) {
      t.view.innerHTML = `<div class="empty-tab">${esc(err.message)}</div>`;
      return;
    }
  }
  if (state.currentId !== id) return;
  const text = state.raw[name];
  const query = t.search.value.trim();
  renderCode(t.view, text, { highlight: t.highlight && !query, query });
  t.count.textContent = query ? `${countMatches(text, query)} matches` : "";
}

function debounce(fn, ms) {
  let t;
  return (...args) => {
    clearTimeout(t);
    t = setTimeout(() => fn(...args), ms);
  };
}

/* ---------- top bar actions ---------- */

function setupChrome() {
  $("#btnFiles").addEventListener("click", () => {
    const fl = $("#filelist");
    fl.hidden = !fl.hidden;
  });
  $("#btnPermalink").addEventListener("click", () => {
    if (state.currentId) copyText(`record://${state.currentId}`, "Record link");
  });
  $("#btnQuit").addEventListener("click", async () => {
    try {
      await api("POST", "/api/shutdown");
      toast("Shutting down — workspace wiped");
      document.body.innerHTML =
        '<div style="display:flex;height:100vh;align-items:center;justify-content:center;color:#8b93a5">' +
        "Shut down. You can close this tab.</div>";
      window.close();
    } catch (err) {
      toast("Shutdown failed: " + err.message);
    }
  });
  $("#btnRemote").addEventListener("click", async () => {
    state.remoteLoaded = true;
    loadRightTab("rendered");
  });
  $("#btnBrowse").addEventListener("click", () => $("#fileInput").click());
  $("#btnBrowseEmpty").addEventListener("click", () => $("#fileInput").click());
  $("#fileInput").addEventListener("change", (e) => {
    uploadFiles(e.target.files);
    e.target.value = "";
  });

  for (const pane of ["left", "right"]) {
    $$(`#${pane}Tabs .tab`).forEach((btn) =>
      btn.addEventListener("click", () => {
        if (btn.disabled) return;
        switchTab(pane, btn.dataset.tab);
      }));
  }

  const searches = [
    ["htmlSearch", "html"],
    ["ptSearch", "plaintext"],
    ["srcSearch", "source"],
  ];
  for (const [inputId, key] of searches) {
    $("#" + inputId).addEventListener("input", debounce((e) => {
      if (!state.raw[key]) return;
      const t = {
        html: { view: $("#htmlView"), highlight: true },
        plaintext: { view: $("#ptView"), highlight: false },
        source: { view: $("#srcView"), highlight: false },
      }[key];
      const query = e.target.value.trim();
      renderCode(t.view, state.raw[key], { highlight: t.highlight && !query, query });
      const countEl = $("#" + inputId.replace("Search", "MatchCount"));
      countEl.textContent = query ? `${countMatches(state.raw[key], query)} matches` : "";
    }, 180));
  }
  $("#htmlCopy").addEventListener("click", () => copyText(state.raw.html || "", "HTML source"));
  $("#ptCopy").addEventListener("click", () => copyText(state.raw.plaintext || "", "Plaintext"));
  $("#srcCopy").addEventListener("click", () => copyText(state.raw.source || "", "Raw source"));

  // Resizable divider.
  const divider = $("#divider");
  const split = $("#split");
  divider.addEventListener("pointerdown", (e) => {
    divider.classList.add("active");
    divider.setPointerCapture(e.pointerId);
    const move = (ev) => {
      const rect = split.getBoundingClientRect();
      const pct = ((ev.clientX - rect.left) / rect.width) * 100;
      const clamped = Math.min(70, Math.max(22, pct));
      $("#leftPane").style.flexBasis = clamped + "%";
    };
    const up = () => {
      divider.classList.remove("active");
      divider.removeEventListener("pointermove", move);
      divider.removeEventListener("pointerup", up);
    };
    divider.addEventListener("pointermove", move);
    divider.addEventListener("pointerup", up);
  });

  // Drag & drop anywhere.
  let dragDepth = 0;
  window.addEventListener("dragenter", (e) => {
    if (![...e.dataTransfer.types].includes("Files")) return;
    dragDepth++;
    $("#dropOverlay").hidden = false;
  });
  window.addEventListener("dragleave", () => {
    if (--dragDepth <= 0) {
      dragDepth = 0;
      $("#dropOverlay").hidden = true;
    }
  });
  window.addEventListener("dragover", (e) => e.preventDefault());
  window.addEventListener("drop", (e) => {
    e.preventDefault();
    dragDepth = 0;
    $("#dropOverlay").hidden = true;
    if (e.dataTransfer.files.length) uploadFiles(e.dataTransfer.files);
  });

  $("#confirmCancel").addEventListener("click", () => {
    $("#confirmDialog").close("cancel");
  });
  $("#confirmOk").addEventListener("click", () => {
    $("#confirmDialog").close("ok");
  });
}

/* ---------- go ---------- */

setupChrome();
bootstrap().catch((err) => {
  $("#subject").textContent = "Failed to start";
  $("#subjectMeta").textContent = String(err.message || err);
});
