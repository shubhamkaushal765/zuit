const API = "/api";

let currentProject = null;

async function fetchJson(path) {
  const r = await fetch(API + path);
  if (!r.ok) throw new Error(`${r.status} ${path}`);
  return r.json();
}

// ── dimension helpers ──────────────────────────────────────────────────────

const DIMENSION_ORDER = [
  "maintainability", "security", "complexity", "documentation", "test_smell",
  "ci_release", "performance", "project_health", "unsafe_soundness", "packaging",
];
const DIMENSION_LABELS = {
  maintainability: "Maintainability",
  security: "Security",
  complexity: "Complexity",
  documentation: "Documentation",
  test_smell: "Test Smell",
  ci_release: "CI / Release",
  performance: "Performance",
  project_health: "Project Health",
  unsafe_soundness: "Unsafe Soundness",
  packaging: "Packaging",
};

function dimensionLabel(key) {
  if (DIMENSION_LABELS[key]) return DIMENSION_LABELS[key];
  return String(key)
    .split("_")
    .map(w => w.length ? w[0].toUpperCase() + w.slice(1) : w)
    .join(" ");
}

function sortDimensions(dims) {
  const knownIdx = new Map(DIMENSION_ORDER.map((d, i) => [d, i]));
  const known = [];
  const unknown = [];
  for (const d of dims) (knownIdx.has(d) ? known : unknown).push(d);
  known.sort((a, b) => knownIdx.get(a) - knownIdx.get(b));
  unknown.sort();
  return [...known, ...unknown];
}

function collectDimensions(items) {
  const set = new Set();
  for (const it of items || []) {
    const scores = it && it.scores;
    if (scores && typeof scores === "object") {
      for (const k of Object.keys(scores)) set.add(k);
    }
  }
  return sortDimensions([...set]);
}

// ── helpers ────────────────────────────────────────────────────────────────

function el(tag, cls) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  return e;
}

function txt(tag, text, cls) {
  const e = el(tag, cls);
  e.textContent = text;
  return e;
}

function showError(container, msg) {
  const p = el("p", "error-msg");
  p.textContent = "Failed to load: " + msg;
  container.appendChild(p);
}

function renderEmptyState(container, title, body, codeHint) {
  container.innerHTML = "";
  const wrap = el("div", "empty-state");
  const glyph = el("div", "empty-state-glyph");
  glyph.textContent = "·";
  wrap.appendChild(glyph);
  wrap.appendChild(txt("h3", title));
  const p = el("p");
  p.textContent = body;
  if (codeHint) {
    p.appendChild(document.createTextNode(" Run "));
    const code = el("code");
    code.textContent = codeHint;
    p.appendChild(code);
    p.appendChild(document.createTextNode(" to populate this view."));
  }
  wrap.appendChild(p);
  container.appendChild(wrap);
}

function severityClass(sev) {
  return (sev || "").toLowerCase();
}

// ── UI helpers (avatar, breadcrumb, skeletons) ─────────────────────────────

function avatarColorFor(name) {
  const palette = ["#2563eb","#dc2626","#15803d","#b45309","#7c3aed","#0891b2","#db2777","#0f766e"];
  let h = 0;
  for (const ch of name || "") h = (h * 31 + ch.charCodeAt(0)) >>> 0;
  return palette[h % palette.length];
}

function makeAvatar(name) {
  const a = el("span", "project-avatar");
  a.textContent = (name || "?").charAt(0).toLowerCase();
  a.style.background = avatarColorFor(name);
  return a;
}

function setBreadcrumb(project, scanIso) {
  const bc = document.getElementById("breadcrumb");
  const div = document.getElementById("header-divider");
  if (!bc || !div) return;
  if (!project) {
    bc.innerHTML = "";
    div.style.visibility = "hidden";
    return;
  }
  div.style.visibility = "visible";
  bc.innerHTML = "";
  const strong = txt("strong", project);
  bc.appendChild(strong);
  if (scanIso) {
    const sep = el("span");
    sep.textContent = " · ";
    sep.style.color = "var(--text-muted)";
    bc.appendChild(sep);
    const ts = el("span");
    ts.style.fontFamily = "var(--font-mono)";
    ts.style.fontSize = "0.75rem";
    ts.textContent = fmtDate(scanIso);
    bc.appendChild(ts);
  }
}

function paintInitialSkeletons() {
  const aside = document.getElementById("projects");
  if (aside && !aside.children.length) {
    for (let i = 0; i < 3; i++) {
      const row = el("div", "project-row");
      const sk = el("div", "skeleton");
      sk.style.height = "14px";
      sk.style.flex = "1";
      row.appendChild(sk);
      aside.appendChild(row);
    }
  }
  const ov = document.getElementById("tab-overview");
  if (ov && !ov.children.length) {
    const sk1 = el("div", "skeleton");
    sk1.style.height = "20px"; sk1.style.width = "180px"; sk1.style.marginBottom = "1rem";
    const sk2 = el("div", "skeleton");
    sk2.style.height = "60px"; sk2.style.marginBottom = "1rem";
    const sk3 = el("div", "skeleton");
    sk3.style.height = "160px";
    ov.appendChild(sk1); ov.appendChild(sk2); ov.appendChild(sk3);
  }
}

function severityLabel(sev) {
  if (!sev) return "";
  return sev.charAt(0).toUpperCase() + sev.slice(1).toLowerCase();
}

function makePill(sev) {
  const span = el("span", "severity-pill " + severityClass(sev));
  span.textContent = severityLabel(sev);
  return span;
}

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];

function fmtDate(iso) {
  if (!iso) return "—";
  try { return new Date(iso).toLocaleString(); } catch (_) { return iso; }
}

function fmtScore(v) {
  if (v == null) return "—";
  return Number(v).toFixed(1);
}

function deltaArrow(delta) {
  if (delta == null) return { sym: "·", cls: "delta-flat" };
  if (delta > 0) return { sym: "▲ +" + fmtScore(delta), cls: "delta-up" };
  if (delta < 0) return { sym: "▼ " + fmtScore(delta), cls: "delta-down" };
  return { sym: "·", cls: "delta-flat" };
}

function makeTable(headers, rows) {
  const table = el("table");
  const thead = el("thead");
  const hrow = el("tr");
  headers.forEach(h => {
    const th = el("th");
    th.textContent = h;
    hrow.appendChild(th);
  });
  thead.appendChild(hrow);
  table.appendChild(thead);

  const tbody = el("tbody");
  rows.forEach(rowFn => {
    const tr = el("tr");
    rowFn(tr);
    tbody.appendChild(tr);
  });
  table.appendChild(tbody);
  return table;
}

function tdText(tr, text) {
  const td = el("td");
  td.textContent = text;
  tr.appendChild(td);
  return td;
}

function tdNode(tr, node) {
  const td = el("td");
  td.appendChild(node);
  tr.appendChild(td);
  return td;
}

// ── Theme initialization ──────────────────────────────────────────────────

function initTheme() {
  const stored = localStorage.getItem("zuit.theme") || "auto";
  const buttons = document.querySelectorAll("#theme-toggle button");

  function applyTheme(mode) {
    if (mode === "auto") {
      document.documentElement.removeAttribute("data-theme");
    } else {
      document.documentElement.dataset.theme = mode;
    }
    buttons.forEach(btn => {
      btn.setAttribute("aria-checked", btn.dataset.themeMode === mode ? "true" : "false");
    });
    localStorage.setItem("zuit.theme", mode);
  }

  buttons.forEach(btn => {
    btn.addEventListener("click", () => {
      const mode = btn.dataset.themeMode;
      applyTheme(mode);
    });
  });

  applyTheme(stored);
}

// ── Sidebar collapse ───────────────────────────────────────────────────────

function setupSidebar() {
  const aside  = document.getElementById("projects");
  const toggle = document.getElementById("sidebar-toggle");
  if (!aside || !toggle) return;

  let userToggledThisSession = false;

  function read() {
    try { return localStorage.getItem("zuit.sidebar"); } catch (_) { return null; }
  }
  function write(v) {
    try { localStorage.setItem("zuit.sidebar", v); } catch (_) {}
  }
  function apply(state) {
    aside.dataset.collapsed = String(state === "collapsed");
    toggle.setAttribute("aria-expanded", String(state !== "collapsed"));
  }

  // Initial state: viewport wins on small; otherwise localStorage; default expanded.
  const stored = read();
  const startCollapsed = window.innerWidth < 768 || stored === "collapsed";
  apply(startCollapsed ? "collapsed" : "expanded");

  toggle.addEventListener("click", () => {
    userToggledThisSession = true;
    const next = aside.dataset.collapsed === "true" ? "expanded" : "collapsed";
    apply(next);
    write(next);
  });

  let last = window.innerWidth;
  window.addEventListener("resize", () => {
    if (userToggledThisSession) return;
    const w = window.innerWidth;
    if (w < 768 && last >= 768) apply("collapsed");
    if (w >= 768 && last < 768) apply(read() === "collapsed" ? "collapsed" : "expanded");
    last = w;
  });
}

// ── init ───────────────────────────────────────────────────────────────────

async function init() {
  paintInitialSkeletons();
  initTheme();
  setupSidebar();
  setBreadcrumb(null, null);  // hide divider until a project is selected

  try {
    const health = await fetchJson("/healthz");
    document.getElementById("version").textContent = "v" + health.version;
  } catch (e) {
    console.error("Failed to fetch healthz:", e);
  }

  try {
    const projects = await fetchJson("/projects");
    renderProjects(projects);
    if (projects.length === 0) {
      document.querySelectorAll(".tab").forEach(tab => {
        renderEmptyState(tab,
          "No projects yet",
          "Each zuit analyze run records its results here.",
          "zuit analyze .");
      });
      setBreadcrumb(null, null);
    } else {
      selectProject(projects[0].hash);
    }
  } catch (e) {
    console.error("Failed to fetch projects:", e);
  }

  bindTabs();
}

function renderProjects(projects) {
  const container = document.getElementById("projects");
  container.innerHTML = "";

  const head = el("div", "project-section-label");
  head.textContent = "Projects";
  container.appendChild(head);

  projects.forEach((project) => {
    const row = el("div", "project-row");
    row.dataset.hash = project.hash;
    row.appendChild(makeAvatar(project.name));

    const btn = document.createElement("button");
    btn.className = "project-name";
    btn.textContent = project.name;
    btn.title = project.root;
    btn.addEventListener("click", () => selectProject(project.hash));
    row.appendChild(btn);

    const deleteBtn = document.createElement("button");
    deleteBtn.className = "project-delete-btn";
    deleteBtn.textContent = "✕";
    deleteBtn.setAttribute("aria-label", `Delete project ${project.name}`);
    deleteBtn.setAttribute("title", "Delete project");
    deleteBtn.addEventListener("click", (event) => {
      event.stopPropagation();
      deleteProject(project.hash, project.name, project.scan_count);
    });
    row.appendChild(deleteBtn);

    if (currentProject === project.hash) row.classList.add("active");

    container.appendChild(row);
  });
}

async function deleteProject(hash, name, scanCount) {
  const msg = `Delete project "${name}"?\n\nThis will remove all ${scanCount} scan(s). This cannot be undone.`;
  if (!confirm(msg)) return;
  try {
    const r = await fetch(`${API}/projects/${hash}`, { method: "DELETE" });
    if (!r.ok) throw new Error(String(r.status));
    // Re-fetch projects list and reset UI.
    const projects = await fetchJson("/projects");
    renderProjects(projects);
    if (projects.length > 0) {
      selectProject(projects[0].hash);
    } else {
      // No projects left — clear all tab content.
      document.querySelectorAll(".tab").forEach(t => { t.innerHTML = ""; });
      currentProject = null;
    }
  } catch (e) {
    console.error("Failed to delete project:", e);
    alert("Failed to delete project");
  }
}

async function selectProject(hash) {
  currentProject = hash;

  // Mark active row precisely (data-hash matches).
  document.querySelectorAll(".project-row").forEach(r => {
    r.classList.toggle("active", r.dataset.hash === hash);
  });

  // Breadcrumb: lookup project name + latest scan timestamp.
  try {
    const projects = await fetchJson("/projects");
    const proj = projects.find(p => p.hash === hash);
    setBreadcrumb(proj ? proj.name : null, proj ? proj.last_scan_at : null);
  } catch (e) {
    console.error("Failed to fetch projects:", e);
  }

  try {
    const scans = await fetchJson(`/projects/${hash}/scans`);
    renderScansTab(scans, hash);
    renderConfigTab(scans, hash);
    renderFindingsTab(scans, hash);
    renderDiffTab(scans, hash);
    renderTrendsTab(hash);
    renderHeatmapTab(hash);
    renderOverviewTab(hash);
  } catch (e) {
    console.error("Failed to fetch scans:", e);
  }
}

// ── Overview tab ───────────────────────────────────────────────────────────

async function renderOverviewTab(hash) {
  const container = document.getElementById("tab-overview");
  container.innerHTML = "";

  let summary;
  try {
    summary = await fetchJson(`/projects/${hash}/summary`);
  } catch (e) {
    showError(container, e.message);
    return;
  }

  const proj = summary.project || {};
  const latest = summary.latest;
  const delta = summary.delta_vs_previous;

  // Project header
  const header = el("div", "overview-header");
  header.appendChild(txt("h2", proj.name || hash));
  const meta = el("div", "overview-meta");
  meta.appendChild(txt("span", proj.root || ""));
  meta.appendChild(txt("span", " · " + (proj.scan_count || 0) + " scans"));
  meta.appendChild(txt("span", " · first seen " + fmtDate(proj.first_seen)));
  header.appendChild(meta);
  container.appendChild(header);

  if (!summary || !summary.latest) {
    renderEmptyState(container, "No scans recorded yet",
      "This project has no scans on disk.", "zuit analyze .");
    return;
  }

  // Grade tiles
  const dims = sortDimensions(Object.keys(latest.scores || {}));

  const tilesRow = el("div", "grade-tiles");
  dims.forEach(dim => {
    const grade = (latest.grades || {})[dim] || "—";
    const score = (latest.scores || {})[dim];
    const scoreDelta = delta ? ((delta.score_deltas || {})[dim] != null ? (delta.score_deltas || {})[dim] : null) : null;
    const arrow = deltaArrow(scoreDelta);

    const tile = el("div", "grade-tile grade-" + grade);
    tile.appendChild(txt("div", grade, "grade-tile-letter grade-" + grade));
    const meta = el("div", "grade-tile-meta");
    meta.appendChild(txt("div", dimensionLabel(dim), "grade-tile-label"));
    meta.appendChild(txt("div", fmtScore(score), "grade-tile-score"));
    meta.appendChild(txt("div", arrow.sym, "grade-tile-delta " + arrow.cls));
    tile.appendChild(meta);
    tilesRow.appendChild(tile);
  });
  container.appendChild(tilesRow);

  // Severity totals
  const sevCounts = latest.severity_counts || {};
  const sevHead = el("div", "section-head");
  sevHead.appendChild(txt("h3", "Findings"));
  const total = SEVERITY_ORDER.reduce((s, k) => s + (Number(sevCounts[k]) || 0), 0);
  sevHead.appendChild(txt("span", `${total} total`, "section-count"));
  container.appendChild(sevHead);

  const strip = el("div", "severity-strip");
  SEVERITY_ORDER.forEach(k => {
    const n = Number(sevCounts[k]) || 0;
    if (!n) return;
    const pill = el("span", "severity-pill " + k);
    pill.textContent = severityLabel(k) + " ";
    const num = el("span", "num");
    num.textContent = n;
    pill.appendChild(num);
    strip.appendChild(pill);
  });
  container.appendChild(strip);

  // Finding count delta callout
  if (delta && delta.finding_count_delta != null && delta.finding_count_delta !== 0) {
    const d = delta.finding_count_delta;
    const callout = el("div", d > 0 ? "delta-callout delta-up" : "delta-callout delta-down");
    callout.textContent = (d > 0 ? "▲ +" : "▼ ") + d + " findings vs previous scan";
    container.appendChild(callout);
  }

  // Top 5 rules
  const topRules = (latest.top_rules || []).slice(0, 5);
  if (topRules.length > 0) {
    const rh = el("div", "section-head");
    rh.appendChild(txt("h3", "Top rules"));
    rh.appendChild(txt("span", `${topRules.length} of ${(latest.top_rules || []).length}`, "section-count"));
    container.appendChild(rh);
    const list = el("div", "top-rules");
    topRules.forEach(r => {
      const row = el("div", "top-rule-row");
      row.appendChild(txt("span", r.rule_id || "", "top-rule-id"));
      row.appendChild(txt("span", r.dimension || "", "top-rule-msg"));
      row.appendChild(txt("span", String(r.count ?? ""), "top-rule-count"));
      row.addEventListener("click", () => {
        const btn = document.querySelector("nav button[data-tab='findings']");
        if (btn) btn.click();
        const filter = document.getElementById("findings-rule-filter");
        if (filter) {
          filter.value = r.rule_id || "";
          filter.dispatchEvent(new Event("input"));
        }
      });
      list.appendChild(row);
    });
    container.appendChild(list);
  }

  // Top 5 files
  const topFiles = (latest.top_files || []).slice(0, 5);
  if (topFiles.length > 0) {
    container.appendChild(txt("h3", "Top Files"));
    const table = makeTable(["File", "Count"], topFiles.map(f => tr => {
      tdText(tr, f.file);
      tdText(tr, String(f.count));
    }));
    container.appendChild(table);
  }

  // Parse failure total
  const parseFailures = summary.parse_failure_total || 0;
  if (parseFailures > 0) {
    const pf = el("div", "parse-failure-callout");
    pf.textContent = "Parse failures: " + parseFailures;
    container.appendChild(pf);
  }
}

// ── Scans tab ──────────────────────────────────────────────────────────────

function renderScansTab(scans, hash) {
  const container = document.getElementById("tab-scans");
  container.innerHTML = "";

  if (scans.length === 0) {
    container.innerHTML = "<p>No scans yet.</p>";
    return;
  }

  const dims = collectDimensions(scans);
  const headers = ["Timestamp", "Label", ...dims.map(dimensionLabel), "Findings", "Action"];

  const table = document.createElement("table");
  const thead = document.createElement("thead");
  const headerRow = document.createElement("tr");

  headers.forEach((h) => {
    const th = document.createElement("th");
    th.textContent = h;
    headerRow.appendChild(th);
  });

  thead.appendChild(headerRow);
  table.appendChild(thead);

  const tbody = document.createElement("tbody");

  scans.forEach((scan) => {
    const row = document.createElement("tr");

    const tsCell = document.createElement("td");
    tsCell.textContent = new Date(scan.captured_at).toLocaleString();
    row.appendChild(tsCell);

    // Label cell: pill + inline edit affordance.
    const labelCell = document.createElement("td");
    labelCell.style.whiteSpace = "nowrap";
    if (scan.label) {
      const pill = el("span", "label-pill");
      pill.textContent = scan.label;
      labelCell.appendChild(pill);
      labelCell.appendChild(document.createTextNode(" "));
    }
    const editBtn = document.createElement("button");
    editBtn.textContent = "[label]";
    editBtn.className = "label-edit-btn";
    editBtn.addEventListener("click", () => editLabel(hash, scan.id, scan.label || ""));
    labelCell.appendChild(editBtn);
    row.appendChild(labelCell);

    dims.forEach((dim) => {
      const cell = document.createElement("td");
      const score = scan.scores[dim];
      cell.textContent = (score !== undefined ? score.toFixed(1) : "—");
      row.appendChild(cell);
    });

    const findingsCell = document.createElement("td");
    let findingTotal = 0;
    if (scan.finding_count_by_severity && typeof scan.finding_count_by_severity === "object") {
      findingTotal = Object.values(scan.finding_count_by_severity).reduce((a, b) => a + b, 0);
    }
    findingsCell.textContent = findingTotal;
    row.appendChild(findingsCell);

    const actionCell = document.createElement("td");
    const deleteBtn = document.createElement("button");
    deleteBtn.textContent = "[delete]";
    deleteBtn.className = "delete-btn";
    deleteBtn.addEventListener("click", () => deleteScan(hash, scan.id));
    actionCell.appendChild(deleteBtn);

    // View link — switch to Findings tab pre-filtered to this scan
    const viewBtn = document.createElement("button");
    viewBtn.textContent = "[view]";
    viewBtn.className = "view-btn";
    viewBtn.addEventListener("click", () => switchToFindingsForScan(scan.id));
    actionCell.appendChild(viewBtn);

    row.appendChild(actionCell);

    tbody.appendChild(row);
  });

  table.appendChild(tbody);
  container.appendChild(table);
}

function switchToFindingsForScan(scanId) {
  // Switch to findings tab
  const btn = document.querySelector("nav button[data-tab='findings']");
  if (btn) btn.click();

  // Set the scan picker in findings tab
  const picker = document.getElementById("findings-scan-picker");
  if (picker) {
    picker.value = scanId;
    picker.dispatchEvent(new Event("change"));
  }
}

// ── Findings tab ───────────────────────────────────────────────────────────

function renderFindingsTab(scans, hash) {
  const container = document.getElementById("tab-findings");
  container.innerHTML = "";

  if (scans.length === 0) {
    container.appendChild(txt("p", "No scans yet."));
    return;
  }

  // Filter bar
  const filterBar = el("div", "filter-bar");

  const scanLabel = txt("label", "Scan: ");
  const scanPicker = el("select");
  scanPicker.id = "findings-scan-picker";
  scans.forEach(scan => {
    const opt = el("option");
    opt.value = scan.id;
    opt.textContent = new Date(scan.captured_at).toLocaleString();
    scanPicker.appendChild(opt);
  });
  scanLabel.appendChild(scanPicker);
  filterBar.appendChild(scanLabel);

  const sevLabel = txt("label", "Severity: ");
  const sevFilter = el("select");
  sevFilter.id = "findings-sev-filter";
  const sevOptions = [["all", "All"]].concat(SEVERITY_ORDER.map(s => [s, severityLabel(s)]));
  sevOptions.forEach(([value, label]) => {
    const opt = el("option");
    opt.value = value;
    opt.textContent = label;
    sevFilter.appendChild(opt);
  });
  sevLabel.appendChild(sevFilter);
  filterBar.appendChild(sevLabel);

  const ruleLabel = txt("label", "Rule: ");
  const ruleFilter = el("input");
  ruleFilter.type = "search";
  ruleFilter.id = "findings-rule-filter";
  ruleFilter.placeholder = "rule substring…";
  ruleLabel.appendChild(ruleFilter);
  filterBar.appendChild(ruleLabel);

  const fileLabel = txt("label", "File: ");
  const fileFilter = el("input");
  fileFilter.type = "search";
  fileFilter.id = "findings-file-filter";
  fileFilter.placeholder = "file substring…";
  fileLabel.appendChild(fileFilter);
  filterBar.appendChild(fileLabel);

  container.appendChild(filterBar);

  const tableContainer = el("div");
  tableContainer.id = "findings-table-container";
  container.appendChild(tableContainer);

  function applyFindingsFilters(allFindings, target) {
    const sevVal = sevFilter.value;
    const ruleVal = ruleFilter.value.toLowerCase();
    const fileVal = fileFilter.value.toLowerCase();

    const filtered = allFindings.filter(f => {
      if (sevVal !== "all" && (f.severity || "").toLowerCase() !== sevVal) return false;
      if (ruleVal && !(f.rule_id || "").toLowerCase().includes(ruleVal)) return false;
      const filePath = (f.location && f.location.file) ? f.location.file : "";
      if (fileVal && !filePath.toLowerCase().includes(fileVal)) return false;
      return true;
    });

    if (filtered.length === 0) {
      target.appendChild(txt("p", "No findings match these filters."));
      return;
    }

    const table = makeTable(["Severity", "Rule", "File:Line", "Message"], filtered.map(f => tr => {
      tdNode(tr, makePill(f.severity));
      tdText(tr, f.rule_id || "");
      const loc = f.location || {};
      const start = loc.start || {};
      tdText(tr, (loc.file || "") + ":" + (start.line || ""));
      tdText(tr, f.message || "");
    }));
    target.appendChild(table);
  }

  // Store findings for re-filtering without re-fetching
  let cachedFindings = [];

  async function loadFindingsWithCache() {
    const scanId = scanPicker.value;
    if (!scanId) return;
    tableContainer.innerHTML = "";
    const loading = txt("p", "Loading…");
    tableContainer.appendChild(loading);

    let scanData;
    try {
      scanData = await fetchJson(`/projects/${hash}/scans/${scanId}`);
    } catch (e) {
      tableContainer.innerHTML = "";
      showError(tableContainer, e.message);
      return;
    }

    tableContainer.innerHTML = "";
    cachedFindings = (scanData.report && scanData.report.findings) ? scanData.report.findings : [];
    applyFindingsFilters(cachedFindings, tableContainer);
  }

  function refilter() {
    tableContainer.innerHTML = "";
    applyFindingsFilters(cachedFindings, tableContainer);
  }

  scanPicker.addEventListener("change", loadFindingsWithCache);
  sevFilter.addEventListener("change", refilter);
  ruleFilter.addEventListener("input", refilter);
  fileFilter.addEventListener("input", refilter);

  // Load first scan automatically
  loadFindingsWithCache();
}

// ── Diff tab ───────────────────────────────────────────────────────────────

function renderDiffTab(scans, hash) {
  const container = document.getElementById("tab-diff");
  container.innerHTML = "";

  if (scans.length < 2) {
    container.appendChild(txt("p", "Need at least two scans to diff."));
    return;
  }

  const controls = el("div", "filter-bar");

  const fromLabel = txt("label", "From: ");
  const fromPicker = el("select");
  fromPicker.id = "diff-from-picker";
  const toLabel = txt("label", "To: ");
  const toPicker = el("select");
  toPicker.id = "diff-to-picker";

  scans.forEach(scan => {
    const optA = el("option");
    optA.value = scan.id;
    optA.textContent = new Date(scan.captured_at).toLocaleString();
    fromPicker.appendChild(optA);

    const optB = el("option");
    optB.value = scan.id;
    optB.textContent = new Date(scan.captured_at).toLocaleString();
    toPicker.appendChild(optB);
  });

  // Default: from = oldest (last in list if desc), to = newest (first)
  fromPicker.value = scans[scans.length - 1].id;
  toPicker.value = scans[0].id;

  fromLabel.appendChild(fromPicker);
  toLabel.appendChild(toPicker);

  const compareBtn = el("button");
  compareBtn.textContent = "Compare";
  compareBtn.className = "compare-btn";

  controls.appendChild(fromLabel);
  controls.appendChild(toLabel);
  controls.appendChild(compareBtn);
  container.appendChild(controls);

  const diffContainer = el("div");
  diffContainer.id = "diff-result";
  container.appendChild(diffContainer);

  async function runDiff() {
    const fromId = fromPicker.value;
    const toId = toPicker.value;
    diffContainer.innerHTML = "";

    if (!fromId || !toId) return;

    const loading = txt("p", "Loading…");
    diffContainer.appendChild(loading);

    let diff;
    try {
      diff = await fetchJson(`/projects/${hash}/diff?from=${encodeURIComponent(fromId)}&to=${encodeURIComponent(toId)}`);
    } catch (e) {
      diffContainer.innerHTML = "";
      showError(diffContainer, e.message);
      return;
    }

    diffContainer.innerHTML = "";
    renderDiffSection(diffContainer, "New (regressions)", diff.new || [], "diff-new");
    renderDiffSection(diffContainer, "Resolved", diff.resolved || [], "diff-resolved");
    renderDiffSection(diffContainer, "Persisting", diff.persisting || [], "diff-persisting");
  }

  compareBtn.addEventListener("click", runDiff);

  // Auto-render on load
  runDiff();
}

function renderDiffSection(container, title, findings, cls) {
  const details = el("details");
  details.open = true;
  const summary = el("summary", cls);
  summary.textContent = title + " (" + findings.length + ")";
  details.appendChild(summary);

  if (findings.length === 0) {
    details.appendChild(txt("p", "(none)"));
  } else {
    const table = makeTable(["Severity", "Rule", "File:Line", "Message"], findings.map(f => tr => {
      tdNode(tr, makePill(f.severity));
      tdText(tr, f.rule_id || "");
      const loc = f.location || {};
      const start = loc.start || {};
      tdText(tr, (loc.file || "") + ":" + (start.line || ""));
      tdText(tr, f.message || "");
    }));
    details.appendChild(table);
  }

  container.appendChild(details);
}

// ── Trends tab ─────────────────────────────────────────────────────────────

async function renderTrendsTab(hash) {
  const container = document.getElementById("tab-trends");
  container.innerHTML = "";

  let trends;
  try {
    trends = await fetchJson(`/projects/${hash}/trends`);
  } catch (e) {
    showError(container, e.message);
    return;
  }

  if (!trends || trends.length === 0) {
    container.appendChild(txt("p", "No scans yet."));
    return;
  }

  const xs = trends.map(s => new Date(s.captured_at).getTime() / 1000);

  // 1. Score sparklines (one per dimension)
  const scoreDims = collectDimensions(trends);

  scoreDims.forEach(dim => {
    const y = trends.map(s => (s.scores && s.scores[dim] != null) ? s.scores[dim] : 0);
    addSparkline(container, dim, xs, y);
  });

  // 2. Findings by severity over time (multi-series)
  const sevColors = {
    critical: "#dc2626",
    high: "#ea580c",
    medium: "#d97706",
    low: "#2563eb",
    info: "#6b7280"
  };

  const sevWrapper = el("div");
  sevWrapper.style.marginBottom = "2rem";
  sevWrapper.appendChild(txt("div", "Findings by severity", "sparkline-title"));
  const sevCanvas = el("div");
  sevCanvas.className = "chart-multi";
  sevWrapper.appendChild(sevCanvas);
  container.appendChild(sevWrapper);

  try {
    const sevSeries = SEVERITY_ORDER.map(sev => ({
      label: severityLabel(sev),
      stroke: sevColors[sev],
      width: 2
    }));
    const sevData = [xs, ...SEVERITY_ORDER.map(sev =>
      trends.map(s => (s.severity_counts && s.severity_counts[sev] != null) ? s.severity_counts[sev] : 0)
    )];
    new uPlot(
      {
        title: "",
        width: 600,
        height: 200,
        series: [{}, ...sevSeries],
        scales: { x: { time: true } },
        axes: [{ label: "Time" }, { label: "Count" }]
      },
      sevData,
      sevCanvas
    );
  } catch (e) {
    console.error("Failed to render severity chart:", e);
    sevCanvas.textContent = "(chart failed)";
  }

  // 3. Files scanned & parse failures over time
  const filesWrapper = el("div");
  filesWrapper.style.marginBottom = "2rem";
  filesWrapper.appendChild(txt("div", "Files scanned & parse failures", "sparkline-title"));
  const filesCanvas = el("div");
  filesCanvas.className = "chart-multi";
  filesWrapper.appendChild(filesCanvas);
  container.appendChild(filesWrapper);

  try {
    new uPlot(
      {
        title: "",
        width: 600,
        height: 200,
        series: [
          {},
          { label: "Files scanned", stroke: "#0066cc", width: 2 },
          { label: "Parse failures", stroke: "#dc2626", width: 2 }
        ],
        scales: { x: { time: true } },
        axes: [{ label: "Time" }, { label: "Count" }]
      },
      [
        xs,
        trends.map(s => s.files_scanned != null ? s.files_scanned : 0),
        trends.map(s => s.parse_failures != null ? s.parse_failures : 0)
      ],
      filesCanvas
    );
  } catch (e) {
    console.error("Failed to render files chart:", e);
    filesCanvas.textContent = "(chart failed)";
  }

  // 4. Scan duration (ms) over time
  const durWrapper = el("div");
  durWrapper.style.marginBottom = "2rem";
  durWrapper.appendChild(txt("div", "Scan duration (ms)", "sparkline-title"));
  const durCanvas = el("div");
  durCanvas.className = "chart-multi";
  durWrapper.appendChild(durCanvas);
  container.appendChild(durWrapper);

  try {
    new uPlot(
      {
        title: "",
        width: 600,
        height: 200,
        series: [
          {},
          { label: "Duration (ms)", stroke: "#7c3aed", width: 2 }
        ],
        scales: { x: { time: true } },
        axes: [{ label: "Time" }, { label: "ms" }]
      },
      [
        xs,
        trends.map(s => s.elapsed_ms != null ? s.elapsed_ms : 0)
      ],
      durCanvas
    );
  } catch (e) {
    console.error("Failed to render duration chart:", e);
    durCanvas.textContent = "(chart failed)";
  }
}

function addSparkline(container, dim, x, y) {
  const wrapper = document.createElement("div");
  wrapper.style.marginBottom = "2rem";

  const title = document.createElement("div");
  title.className = "sparkline-title";
  title.textContent = dimensionLabel(dim);
  wrapper.appendChild(title);

  const canvas = document.createElement("div");
  canvas.className = "sparkline";
  canvas.id = "spark-" + dim;
  wrapper.appendChild(canvas);

  container.appendChild(wrapper);

  try {
    new uPlot(
      {
        title: "",
        width: 600,
        height: 80,
        series: [
          {},
          {
            label: dimensionLabel(dim),
            stroke: "#0066cc",
            fill: "rgba(0, 102, 204, 0.1)",
            scale: "score"
          }
        ],
        scales: {
          x: { time: true },
          score: { min: 0, max: 100 }
        },
        axes: [
          { label: "Time" },
          { label: "Score" }
        ]
      },
      [x, y],
      canvas
    );
  } catch (e) {
    console.error("Failed to render sparkline for " + dim + ":", e);
    canvas.textContent = "(chart failed)";
  }
}

// ── Heatmap tab ────────────────────────────────────────────────────────────

async function renderHeatmapTab(hash) {
  const container = document.getElementById("tab-heatmap");
  container.innerHTML = "";

  let heatmap;
  try {
    heatmap = await fetchJson(`/projects/${hash}/heatmap`);
  } catch (e) {
    showError(container, e.message);
    return;
  }

  if (!heatmap || heatmap.length === 0) {
    container.appendChild(txt("p", "No findings across any scan."));
    return;
  }

  container.appendChild(txt("h2", "Hot Files Heatmap"));

  const nScans = heatmap[0].findings_per_scan.length;
  const maxPeak = Math.max(...heatmap.map(e => e.peak_count), 1);
  const maxWeight = Math.max(...heatmap.map(e => e.total_weight_all_time || 0), 1);

  const table = el("table", "heatmap-table");
  // Header row.
  const thead = el("thead");
  const hrow = el("tr");
  const thFile = el("th"); thFile.textContent = "File"; hrow.appendChild(thFile);
  for (let i = 0; i < nScans; i++) {
    const th = el("th"); th.textContent = "S" + (i + 1); hrow.appendChild(th);
  }
  const thTotal = el("th"); thTotal.textContent = "Total"; hrow.appendChild(thTotal);
  const thWeight = el("th"); thWeight.textContent = "Weight"; thWeight.title = "Severity-weighted sum (info=1, low=2, medium=5, high=10, critical=20)"; hrow.appendChild(thWeight);
  const thPeak = el("th"); thPeak.textContent = "Peak"; hrow.appendChild(thPeak);
  thead.appendChild(hrow);
  table.appendChild(thead);

  const tbody = el("tbody");
  heatmap.forEach(entry => {
    const tr = el("tr");
    const tdPath = el("td", "heatmap-path"); tdPath.textContent = entry.path; tr.appendChild(tdPath);
    entry.findings_per_scan.forEach(count => {
      const td = el("td", "heatmap-cell");
      td.textContent = count > 0 ? String(count) : "";
      // Shade intensity proportional to peak across all files.
      const intensity = maxPeak > 0 ? Math.round((count / maxPeak) * 100) : 0;
      td.style.backgroundColor = `hsl(0,80%,${100 - intensity * 0.5}%)`;
      if (intensity > 60) td.style.color = "#fff";
      tr.appendChild(td);
    });
    const tdTotal = el("td"); tdTotal.textContent = String(entry.total_findings_all_time); tr.appendChild(tdTotal);
    const weight = entry.total_weight_all_time || 0;
    const tdWeight = el("td", "heatmap-weight");
    tdWeight.textContent = String(weight);
    // Shade weight column proportional to max weight.
    const wIntensity = maxWeight > 0 ? Math.round((weight / maxWeight) * 100) : 0;
    tdWeight.style.backgroundColor = `hsl(30,80%,${100 - wIntensity * 0.5}%)`;
    if (wIntensity > 60) tdWeight.style.color = "#fff";
    tr.appendChild(tdWeight);
    const tdPeak = el("td"); tdPeak.textContent = String(entry.peak_count); tr.appendChild(tdPeak);
    tbody.appendChild(tr);
  });
  table.appendChild(tbody);
  container.appendChild(table);
}

// ── Label edit ──────────────────────────────────────────────────────────────

async function editLabel(hash, scanId, current) {
  const newLabel = prompt("Set scan label (leave blank to clear):", current);
  if (newLabel === null) return; // cancelled
  try {
    const r = await fetch(
      `${API}/projects/${hash}/scans/${encodeURIComponent(scanId)}/label?_label=${encodeURIComponent(newLabel)}`,
      { method: "PUT" }
    );
    if (!r.ok) throw new Error(`${r.status}`);
    selectProject(hash); // refresh
  } catch (e) {
    console.error("Failed to set label:", e);
    alert("Failed to set label");
  }
}

// ── Config tab ─────────────────────────────────────────────────────────────

async function renderConfigTab(scans, hash) {
  const container = document.getElementById("tab-config");
  container.innerHTML = "";

  if (scans.length === 0) {
    container.innerHTML = "<p>No scans yet.</p>";
    return;
  }

  const label = document.createElement("label");
  label.textContent = "Select scan: ";
  label.style.display = "block";
  label.style.marginBottom = "1rem";

  const select = document.createElement("select");
  select.addEventListener("change", async () => {
    if (!select.value) return;
    try {
      const [scanId, configHash] = select.value.split("|");
      const config = await fetchJson(`/projects/${hash}/configs/${configHash}`);
      const pre = container.querySelector("pre");
      if (pre) {
        pre.textContent = config.toml || "(empty)";
      }
    } catch (e) {
      console.error("Failed to fetch config:", e);
    }
  });

  scans.forEach((scan) => {
    const option = document.createElement("option");
    option.value = `${scan.id}|${scan.config_hash}`;
    option.textContent = new Date(scan.captured_at).toLocaleString();
    select.appendChild(option);
  });

  label.appendChild(select);
  container.appendChild(label);

  const pre = document.createElement("pre");
  pre.textContent = "(select a scan)";
  container.appendChild(pre);
}

// ── delete & tabs ──────────────────────────────────────────────────────────

async function deleteScan(hash, id) {
  if (!confirm("Delete this scan? This cannot be undone.")) {
    return;
  }

  try {
    const r = await fetch(`${API}/projects/${hash}/scans/${id}`, {
      method: "DELETE"
    });
    if (!r.ok) throw new Error(`${r.status}`);
    selectProject(hash);
  } catch (e) {
    console.error("Failed to delete scan:", e);
    alert("Failed to delete scan");
  }
}

function bindTabs() {
  const buttons = document.querySelectorAll("nav#tabs button[data-tab]");
  const tabs = document.querySelectorAll(".tab");

  // Wire static aria-controls / aria-labelledby + give each tab an id.
  buttons.forEach(btn => {
    const tabId = btn.getAttribute("data-tab");
    const panelId = `tab-${tabId}`;
    if (!btn.id) btn.id = `tab-btn-${tabId}`;
    btn.setAttribute("aria-controls", panelId);
    const panel = document.getElementById(panelId);
    if (panel) panel.setAttribute("aria-labelledby", btn.id);
  });

  function activate(tabId) {
    buttons.forEach(b => {
      const isActive = b.getAttribute("data-tab") === tabId;
      b.setAttribute("aria-selected", String(isActive));
      b.tabIndex = isActive ? 0 : -1;
    });
    tabs.forEach(t => { t.hidden = t.id !== `tab-${tabId}`; });
  }

  buttons.forEach(btn => {
    btn.addEventListener("click", () => activate(btn.getAttribute("data-tab")));
    btn.addEventListener("keydown", (e) => {
      const list = Array.from(buttons);
      const idx = list.indexOf(btn);
      if (e.key === "ArrowRight" || e.key === "ArrowLeft") {
        e.preventDefault();
        const dir = e.key === "ArrowRight" ? 1 : -1;
        const next = list[(idx + dir + list.length) % list.length];
        next.focus();
        activate(next.getAttribute("data-tab"));
      } else if (e.key === "Home") {
        e.preventDefault();
        list[0].focus(); activate(list[0].getAttribute("data-tab"));
      } else if (e.key === "End") {
        e.preventDefault();
        const last = list[list.length - 1];
        last.focus(); activate(last.getAttribute("data-tab"));
      }
    });
  });

  // Initial: prefer Overview, otherwise first tab.
  const initial = document.querySelector("nav#tabs button[data-tab='overview']")
                 || buttons[0];
  if (initial) activate(initial.getAttribute("data-tab"));
}

document.addEventListener("DOMContentLoaded", init);
