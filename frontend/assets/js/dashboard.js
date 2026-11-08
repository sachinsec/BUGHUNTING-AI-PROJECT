(() => {
  const $ = (selector) => document.querySelector(selector);
  const byId = (id) => document.getElementById(id);
  const state = { scopes: [], activeView: "overview", loading: false, activeScanId: null, activeScanModule: null, pollTimer: null, tool: null };
  const targetViews = new Set(["programs", "scope-manager"]);
  const reconViews = new Set(["reconnaissance", "subdomains", "live-hosts", "url-intelligence", "endpoints", "parameters", "technologies"]);
  const labels = {
    overview: ["Overview", "Overview", "Your authorized programs and attack surface at a glance."],
    programs: ["Programs", "Programs", "Register authorized targets and keep scope boundaries explicit."],
    "scope-manager": ["Scope Manager", "Scope Manager", "Review authorization boundaries and exclusions."],
    "authorization-reviews": ["Authorization Reviews", "Authorization Reviews", "Evidence review and explicit decisions for public program scope."],
    reconnaissance: ["Reconnaissance", "Reconnaissance", "Recon stages will appear here when scan APIs are available."],
    subdomains: ["Subdomains", "Subdomains", "Discovered subdomains from completed scans."],
    "live-hosts": ["Live Hosts", "Live Hosts", "Live host results from authorized scans."],
    "url-intelligence": ["URL Intelligence", "URL Intelligence", "Historical URLs and collected routes."],
    endpoints: ["Endpoints", "Endpoints", "Discovered application endpoints."],
    parameters: ["Parameters", "Parameters", "Parameters extracted from in-scope endpoints."],
    technologies: ["Technologies", "Technologies", "Technology fingerprints from live hosts."],
    "vulnerability-scanner": ["Vulnerability Scanner", "Vulnerability Scanner", "Approved security checks and their execution status."],
    findings: ["Findings", "Findings", "Potential and manually verified security findings."],
    "http-history": ["HTTP History", "HTTP History", "Redacted request and response records from approved scans."],
    "ai-analyst": ["AI Analyst", "AI Analyst", "Evidence-based analysis using the configured local Ollama service."],
    reports: ["Reports", "Reports", "Reports generated from stored scan and finding data."],
    "tool-management": ["Tool Management", "Tool Management", "Local tool availability and adapter status."],
    settings: ["Settings", "Settings", "Local application configuration."],
  };
  const reconModules = {
    reconnaissance: { title: "Reconnaissance", kicker: "RECON ORCHESTRATOR", description: "Run registered discovery stages in sequence. Katana crawling runs only when you approve it.", resultTitle: "Latest subdomain assets", columns: ["HOSTNAME", "SOURCE", "DISCOVERED", "DATA TYPE"], api: "recon" },
    subdomains: { title: "Subdomains", kicker: "PASSIVE SUBDOMAIN ENUMERATION", description: "Subfinder queries passive sources, limited to 2 requests per second.", resultTitle: "Discovered subdomains", columns: ["HOSTNAME", "SOURCE", "DISCOVERED", "DATA TYPE"], api: "subdomains" },
    "live-hosts": { title: "Live Hosts", kicker: "AUTHORIZED HTTP PROBING", description: "HTTPX probes only pre-resolved public addresses and does not follow redirects.", resultTitle: "Live host results", columns: ["HOSTNAME", "URL", "STATUS", "TITLE", "DATA TYPE"], api: "live-hosts" },
    "url-intelligence": { title: "URL Intelligence", kicker: "HISTORICAL URL COLLECTION", description: "GAU and Waybackurls collect archived URLs; each URL is filtered against the registered scope.", resultTitle: "Historical URLs", columns: ["URL", "SOURCE", "DISCOVERED", "DATA TYPE"], api: "url-intelligence" },
    endpoints: { title: "Endpoints", kicker: "APPROVED WEB CRAWLING", description: "Katana is rate limited and requires explicit approval before it crawls an application.", resultTitle: "Crawled endpoints", columns: ["ENDPOINT URL", "METHOD", "SOURCE", "DATA TYPE"], api: "endpoints" },
    parameters: { title: "Parameters", kicker: "QUERY INTELLIGENCE", description: "Parameter names are derived from stored URLs. Values are replaced with placeholders; no payloads are submitted.", resultTitle: "Discovered parameters", columns: ["ENDPOINT", "PARAMETER", "PARAMETERIZED URL", "SOURCE"], api: "parameters" },
    technologies: { title: "Technologies", kicker: "TECHNOLOGY FINGERPRINTING", description: "WhatWeb runs at low aggression with redirect following disabled.", resultTitle: "Technology fingerprints", columns: ["HOSTNAME", "TECHNOLOGY", "VERSION", "DETECTED", "DATA TYPE"], api: "technologies" },
  };

  function escapeText(value) {
    return String(value ?? "").replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[char]));
  }

  function toast(message, error = false) {
    const item = document.createElement("div");
    item.className = `toast${error ? " error" : ""}`;
    item.textContent = message;
    byId("toast-region").append(item);
    window.setTimeout(() => item.remove(), 4200);
  }

  function dateLabel(value) {
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return "—";
    return new Intl.DateTimeFormat(undefined, { year: "numeric", month: "short", day: "numeric" }).format(date);
  }

  function renderOverviewPrograms() {
    const container = byId("overview-program-list");
    if (!state.scopes.length) {
      container.innerHTML = '<div class="loading-line"><span></span>No authorized programs yet. Add a program to define scope.</div>';
      return;
    }
    container.innerHTML = state.scopes.slice(0, 4).map((scope) => `
      <div class="program-row">
        <span class="program-mark">${escapeText((scope.program_name || scope.root_domain).slice(0, 1).toUpperCase())}</span>
        <span class="program-name"><strong>${escapeText(scope.program_name || scope.root_domain)}</strong><small>${escapeText(scope.root_domain)}</small></span>
        <span class="scope-badge${scope.local_lab_mode ? " lab" : ""}">${scope.local_lab_mode ? "LAB MODE" : escapeText(scope.authorization_status || "PENDING")}</span>
      </div>`).join("");
  }

  async function loadDashboardRecon() {
    try {
      const [subdomains, hosts, endpoints, jobs] = await Promise.all([
        BugHunterApi.subdomains(), BugHunterApi.liveHosts(), BugHunterApi.endpoints(), BugHunterApi.reconJobs(),
      ]);
      byId("metric-subdomains").textContent = (subdomains.results || []).filter((item) => !item.simulated).length;
      byId("metric-live-hosts").textContent = (hosts.results || []).filter((item) => !item.simulated).length;
      byId("metric-endpoints").textContent = (endpoints.results || []).filter((item) => !item.simulated).length;
      renderDashboardScans(jobs || []);
    } catch (error) {
      ["metric-subdomains", "metric-live-hosts", "metric-endpoints"].forEach((id) => { byId(id).textContent = "—"; });
      byId("dashboard-scan-list").innerHTML = `<div class="load-error">Could not load scan history: ${escapeText(error.message)}</div>`;
    }
  }

  function renderDashboardScans(scans) {
    const container = byId("dashboard-scan-list");
    if (!scans.length) {
      container.innerHTML = '<div class="empty-state"><div class="empty-illustration"><span class="empty-ring"></span><span class="empty-cross">＋</span></div><strong>No reconnaissance runs yet</strong><p>Start a scope-validated workflow for a registered program.</p><button class="button button-secondary button-small" data-go="reconnaissance">Open reconnaissance <span>↗</span></button></div>';
      container.querySelector("[data-go]").addEventListener("click", () => navigate("reconnaissance"));
      return;
    }
    container.innerHTML = scans.slice(0, 4).map((scan) => `<div class="dashboard-scan-row">
      <span class="dashboard-scan-number">R-${String(scan.id).padStart(4, "0")}</span>
      <span class="dashboard-scan-copy"><strong>${escapeText(scan.stage.replaceAll("_", " "))}</strong><small>${dateLabel(scan.created_at)} · ${escapeText(scan.status)}</small></span>
      <span class="${scan.simulated ? "simulation-badge" : "real-badge"}">${scan.simulated ? "MOCK" : escapeText(scan.progress + "%")}</span>
    </div>`).join("");
  }

  async function loadDashboardVulnerabilityStats() {
    try {
      const stats = await BugHunterApi.vulnerabilityStats();
      byId("metric-potential-findings").textContent = stats.potential;
      byId("metric-verified-findings").textContent = stats.verified;
      byId("severity-total").innerHTML = `${stats.real_total}<small>REAL FINDINGS</small>`;
      byId("finding-stats-mode").textContent = `${stats.simulated} SIMULATED`;
      const breakdown = Object.entries(stats.by_severity || {}).filter(([, count]) => count).map(([severity, count]) => `${severity}: ${count}`).join(" · ");
      const simulatedBreakdown = Object.entries(stats.simulated_by_severity || {}).filter(([, count]) => count).map(([severity, count]) => `${severity}: ${count}`).join(" · ");
      byId("severity-summary").textContent = stats.total ? `Real: ${breakdown || "no findings"}. Simulated: ${simulatedBreakdown || "none"}.` : "No persisted findings yet.";
    } catch (error) {
      byId("metric-potential-findings").textContent = "ERROR";
      byId("metric-verified-findings").textContent = "ERROR";
      byId("severity-total").innerHTML = `—<small>ERROR</small>`;
      byId("finding-stats-mode").textContent = "API ERROR";
      byId("severity-summary").textContent = `Could not load vulnerability statistics: ${error.message}`;
    }
  }

  function renderTargets() {
    const query = byId("target-search").value.trim().toLowerCase();
    const filtered = state.scopes.filter((scope) => `${scope.program_name} ${scope.root_domain} ${scope.included_assets.join(" ")}`.toLowerCase().includes(query));
    const body = byId("target-table-body");
    byId("target-count").textContent = `${filtered.length} ${filtered.length === 1 ? "PROGRAM" : "PROGRAMS"}`;
    byId("program-nav-count").textContent = state.scopes.length;
    if (!filtered.length) {
      body.innerHTML = "";
      byId("target-empty").classList.remove("hidden");
      const title = query ? "No matching programs" : "No authorized programs";
      byId("target-empty").querySelector("strong").textContent = title;
      byId("target-empty").querySelector("p").textContent = query ? "Try a different program name or domain." : "Add a program with documented authorization to begin organizing its scope.";
      return;
    }
    byId("target-empty").classList.add("hidden");
    body.innerHTML = filtered.map((scope) => {
      const assets = scope.included_assets.length + (scope.include_subdomains ? 1 : 0);
      const auth = scope.local_lab_mode ? '<span class="mode-pill lab">LOCAL ONLY</span>' : `<span class="mode-pill">${escapeText(scope.authorization_status || "PENDING")}</span>`;
      return `<tr>
        <td><div class="table-program"><span class="program-mark">${escapeText((scope.program_name || scope.root_domain).slice(0, 1).toUpperCase())}</span><span><strong>${escapeText(scope.program_name || scope.root_domain)}</strong><small>${escapeText(scope.root_domain)}</small></span></div></td>
        <td><span class="asset-count">${assets}<small> ${scope.include_subdomains ? "incl. subdomains" : "explicit assets"}</small></span></td>
        <td><span class="asset-count">${scope.excluded_subdomains.length}</span></td>
        <td><span class="mode-pill${scope.local_lab_mode ? " lab" : ""}">${scope.local_lab_mode ? "LOCAL LAB" : "AUTHORIZED"}</span></td>
        <td>${auth}${scope.local_lab_mode ? "" : `<button class="text-button table-subline" data-open-authorization="${scope.id}">Manage review</button>`}<small class="table-subline">${dateLabel(scope.created_at)}</small></td>
        <td><div class="row-actions"><button class="delete-button" data-delete-scope="${scope.id}" aria-label="Delete ${escapeText(scope.program_name || scope.root_domain)}" title="Remove scope">×</button></div></td>
      </tr>`;
    }).join("");
  }

  async function renderToolManagement() {
    const content = byId("placeholder-content");
    content.innerHTML = '<article class="panel"><div class="panel-heading"><div><div class="panel-kicker">LOCAL EXECUTION</div><h2>Security tool detection</h2></div><button class="button button-secondary" id="tool-check">Check again</button></div><div class="table-scroll"><table><thead><tr><th>TOOL</th><th>STATE</th><th>MODE</th><th>VERSION</th><th>EXECUTABLE</th></tr></thead><tbody id="tool-status-body"><tr><td colspan="5" class="table-loading">Checking installed tools…</td></tr></tbody></table></div></article>';
    const load = async (check = false) => {
      const data = check ? await BugHunterApi.checkTools() : await BugHunterApi.toolStatus();
      const rows = data.tools || [];
      byId("tool-status-body").innerHTML = rows.map((tool) => `<tr><td>${escapeText(tool.command || tool.name)}${tool.command ? `<small class="table-subline">${escapeText(tool.name)}</small>` : ""}</td><td><span class="${tool.status === "INSTALLED" ? "real-badge" : tool.status === "MOCK" ? "simulation-badge" : "mode-pill"}">${escapeText(tool.status || (tool.available ? "INSTALLED" : "NOT_INSTALLED"))}</span></td><td>${escapeText((tool.mode || data.execution_mode).toUpperCase())}</td><td>${escapeText(tool.version || "—")}</td><td class="hostname-cell">${escapeText(tool.path || tool.install_hint || tool.error || "—")}</td></tr>`).join("");
    };
    byId("tool-check").addEventListener("click", () => load(true).catch((error) => toast(error.message, true)));
    try { await load(); } catch (error) { content.insertAdjacentHTML("beforeend", `<p class="recon-alert error">${escapeText(error.message)}</p>`); }
  }

  function findingStatusLabel(finding) {
    if (finding.simulated) return `${finding.status} · SIMULATED ${finding.execution_mode}`;
    return `${finding.status} · MANUAL ${finding.execution_mode}`;
  }

  function findingRows(findings) {
    if (!findings.length) return '<tr><td colspan="6" class="table-loading">No findings match these filters.</td></tr>';
    return findings.map((finding) => `<tr data-open-finding="${finding.id}" tabindex="0" role="button"><td>${escapeText(finding.title)}</td><td>${escapeText(finding.target)}</td><td>${escapeText(finding.severity)}</td><td>${escapeText(finding.status)}</td><td><span class="${finding.simulated ? "simulation-badge" : "real-badge"}">${escapeText(findingStatusLabel(finding))}</span></td><td>${dateLabel(finding.updated_at)}</td></tr>`).join("");
  }

  async function loadFindingList() {
    const container = byId("placeholder-content");
    const body = byId("finding-table-body");
    if (!body) return;
    body.innerHTML = '<tr><td colspan="6" class="table-loading">Loading findings from SQLite…</td></tr>';
    const filters = {
      severity: byId("finding-filter-severity").value,
      status: byId("finding-filter-status").value,
      target: byId("finding-filter-target").value.trim(),
    };
    try {
      const findings = await BugHunterApi.vulnerabilities(filters);
      body.innerHTML = findingRows(findings);
      byId("finding-count").textContent = `${findings.length} FINDING${findings.length === 1 ? "" : "S"}`;
      if (!findings.length) byId("finding-details").innerHTML = '<div class="history-empty">No persisted findings match your filters.</div>';
    } catch (error) {
      body.innerHTML = `<tr><td colspan="6" class="table-loading">Could not load findings: ${escapeText(error.message)}</td></tr>`;
      byId("finding-count").textContent = "API ERROR";
    }
  }

  async function showFindingDetails(id) {
    const detail = byId("finding-details");
    detail.innerHTML = '<div class="loading-line"><span></span>Loading finding evidence…</div>';
    try {
      const finding = await BugHunterApi.vulnerability(id);
      const statuses = ["POTENTIAL", "VERIFIED", "FALSE_POSITIVE", "RESOLVED"];
      detail.innerHTML = `<div class="panel-heading"><div><div class="panel-kicker">FINDING #${finding.id} · ${escapeText(finding.severity)}</div><h2>${escapeText(finding.title)}</h2></div><span class="${finding.simulated ? "simulation-badge" : "real-badge"}">${escapeText(findingStatusLabel(finding))}</span></div><div class="finding-detail-copy"><p><strong>Target:</strong> ${escapeText(finding.target)}</p><p>${escapeText(finding.description || "No description recorded.")}</p><p><strong>Source:</strong> ${escapeText(finding.source)} · <strong>Created:</strong> ${dateLabel(finding.created_at)}</p><h3>Evidence</h3><pre>${escapeText(JSON.stringify(finding.evidence, null, 2))}</pre>${finding.reviewer ? `<p><strong>Reviewer:</strong> ${escapeText(finding.reviewer)}</p>` : ""}${finding.reviewer_notes ? `<p>${escapeText(finding.reviewer_notes)}</p>` : ""}<form id="finding-status-form" data-finding-id="${finding.id}" class="review-form"><div class="form-row"><label class="field-label" for="finding-new-status">Update status</label><select name="status" id="finding-new-status">${statuses.map((status) => `<option ${status === finding.status ? "selected" : ""}>${status}</option>`).join("")}</select></div><div class="form-row"><label class="field-label" for="finding-reviewer">Reviewer name (required for verification)</label><input name="reviewer" id="finding-reviewer" maxlength="120" value="${escapeText(finding.reviewer || "")}"></div><div class="form-row"><label class="field-label" for="finding-review-notes">Reviewer notes</label><textarea name="reviewer_notes" id="finding-review-notes" rows="2" maxlength="4000">${escapeText(finding.reviewer_notes || "")}</textarea></div><button class="button button-secondary" type="submit">Save finding status</button></form></div>`;
    } catch (error) {
      detail.innerHTML = `<p class="form-error">Could not load finding details: ${escapeText(error.message)}</p>`;
    }
  }

  async function renderFindingsManagement() {
    byId("placeholder-fallback").classList.add("hidden");
    const scopeOptions = state.scopes.map((scope) => `<option value="${scope.id}">${escapeText(scope.program_name || scope.root_domain)} · ${escapeText(scope.root_domain)}</option>`).join("");
    byId("placeholder-content").innerHTML = `<div class="scope-notice"><span class="notice-icon">⚑</span><div><strong>Finding records are persisted by the FastAPI service.</strong><p>Potential, verified, simulated, and manual provenance are kept distinct.</p></div><span class="notice-lock">SQLITE</span></div><div class="lower-grid"><article class="panel"><div class="panel-heading"><div><div class="panel-kicker">FINDING RECORD</div><h2>Add a finding</h2></div></div><form id="finding-create-form" class="review-form"><div class="form-row"><label class="field-label" for="finding-title">Title</label><input name="title" id="finding-title" required maxlength="250"></div><div class="form-row"><label class="field-label" for="finding-target">Target</label><input name="target" id="finding-target" required maxlength="2048" placeholder="host or URL"></div><div class="form-row"><label class="field-label" for="finding-severity">Severity</label><select name="severity" id="finding-severity"><option>INFO</option><option>LOW</option><option>MEDIUM</option><option>HIGH</option><option>CRITICAL</option></select></div><div class="form-row"><label class="field-label" for="finding-scope">Associated scope <span>OPTIONAL</span></label><select name="scope_id" id="finding-scope"><option value="">No scope link</option>${scopeOptions}</select></div><div class="form-row"><label class="field-label" for="finding-description">Description</label><textarea name="description" id="finding-description" rows="3" maxlength="8000"></textarea></div><div class="form-row"><label class="field-label" for="finding-evidence">Evidence JSON</label><textarea name="evidence" id="finding-evidence" rows="4" placeholder='{"request":"…","response":"…"}'></textarea></div><div id="finding-create-error" class="form-error hidden" role="alert"></div><button class="button button-primary" type="submit">Save potential finding</button></form></article><article class="panel"><div class="panel-heading"><div><div class="panel-kicker">SQLITE FINDINGS</div><h2>Findings</h2></div><button class="text-button" id="finding-refresh">Refresh</button></div><div class="table-toolbar"><select id="finding-filter-severity"><option value="">All severities</option><option>INFO</option><option>LOW</option><option>MEDIUM</option><option>HIGH</option><option>CRITICAL</option></select><select id="finding-filter-status"><option value="">All statuses</option><option>POTENTIAL</option><option>VERIFIED</option><option>FALSE_POSITIVE</option><option>RESOLVED</option></select><input id="finding-filter-target" type="search" placeholder="Filter target"><span class="table-count" id="finding-count">Loading…</span></div><div class="table-scroll"><table><thead><tr><th>FINDING</th><th>TARGET</th><th>SEVERITY</th><th>STATUS</th><th>ORIGIN</th><th>UPDATED</th></tr></thead><tbody id="finding-table-body"><tr><td colspan="6" class="table-loading">Loading findings…</td></tr></tbody></table></div></article></div><article class="panel finding-detail-panel" id="finding-details"><div class="history-empty">Select a finding to inspect details and evidence.</div></article>`;
    const root = byId("placeholder-content");
    root.querySelector("#finding-create-form").addEventListener("submit", createFindingFromForm);
    root.querySelector("#finding-refresh").addEventListener("click", loadFindingList);
    root.querySelector("#finding-filter-severity").addEventListener("change", loadFindingList);
    root.querySelector("#finding-filter-status").addEventListener("change", loadFindingList);
    root.querySelector("#finding-filter-target").addEventListener("input", debounce(loadFindingList, 250));
    root.querySelector("#finding-table-body").addEventListener("click", (event) => {
      const row = event.target.closest("[data-open-finding]");
      if (row) showFindingDetails(row.dataset.openFinding);
    });
    root.addEventListener("submit", (event) => {
      if (event.target.id === "finding-status-form") updateFindingFromForm(event);
    });
    await loadFindingList();
  }

  async function createFindingFromForm(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const values = new FormData(form);
    const errorEl = byId("finding-create-error");
    errorEl.classList.add("hidden");
    let evidence = {};
    try { evidence = values.get("evidence").trim() ? JSON.parse(values.get("evidence")) : {}; }
    catch (_) { errorEl.textContent = "Evidence must be valid JSON."; errorEl.classList.remove("hidden"); return; }
    try {
      const created = await BugHunterApi.createVulnerability({
        title: values.get("title").trim(), target: values.get("target").trim(), severity: values.get("severity"),
        scope_id: values.get("scope_id") ? Number(values.get("scope_id")) : null,
        description: values.get("description").trim(), evidence,
      });
      toast(created.simulated ? "Finding stored as a simulated MOCK record." : "Potential finding saved to SQLite.");
      form.reset();
      await Promise.all([loadFindingList(), loadDashboardVulnerabilityStats()]);
    } catch (error) { errorEl.textContent = error.message; errorEl.classList.remove("hidden"); }
  }

  async function updateFindingFromForm(event) {
    event.preventDefault();
    const form = event.target;
    const values = new FormData(form);
    try {
      const updated = await BugHunterApi.updateVulnerability(form.dataset.findingId, {
        status: values.get("status"), reviewer: values.get("reviewer").trim() || null,
        reviewer_notes: values.get("reviewer_notes").trim(),
      });
      toast(updated.simulated ? "Simulated finding status updated; provenance remains simulated." : "Finding status updated.");
      await Promise.all([loadFindingList(), loadDashboardVulnerabilityStats(), showFindingDetails(updated.id)]);
    } catch (error) { toast(error.message, true); }
  }

  function debounce(callback, delay) {
    let timer;
    return (...args) => { window.clearTimeout(timer); timer = window.setTimeout(() => callback(...args), delay); };
  }

  async function renderVulnerabilityScanner() {
    byId("placeholder-fallback").classList.add("hidden");
    byId("placeholder-content").innerHTML = '<div class="loading-line"><span></span>Loading scanner and finding status from the API…</div>';
    try {
      const [toolState, stats, catalog] = await Promise.all([
        BugHunterApi.toolStatus(), BugHunterApi.vulnerabilityStats(), BugHunterApi.vulnerabilityTechniques(),
      ]);
      const nuclei = (toolState.tools || []).find((tool) => String(tool.name).toLowerCase() === "nuclei") || null;
      const mock = toolState.execution_mode === "mock" || nuclei?.simulated;
      const toolLabel = mock ? "MOCK ADAPTER" : nuclei?.available ? "AVAILABLE" : escapeText(nuclei?.status || "UNKNOWN");
      const executable = mock ? "No scanner binary is executed in MOCK mode." : (nuclei?.path || nuclei?.install_hint || "Not configured");
      const categories = (catalog.categories || []).map((category) => `<details class="panel"><summary><strong>${escapeText(category.title)}</strong><span class="table-count">${category.checks.length} REVIEW CHECKS</span></summary><ul class="technique-check-list">${category.checks.map((check) => `<li><strong>${escapeText(check.title)}</strong><small>Manual review · save evidence as a potential finding when applicable</small></li>`).join("")}</ul></details>`).join("");
      byId("placeholder-content").innerHTML = `<div class="dashboard-grid"><article class="panel"><div class="panel-heading"><div><div class="panel-kicker">VULNERABILITY ENGINE</div><h2>Nuclei executable status</h2></div><span class="${mock ? "simulation-badge" : nuclei?.available ? "real-badge" : "mode-pill"}">${toolLabel}</span></div><div class="finding-detail-copy"><p><strong>Execution mode:</strong> ${escapeText((toolState.execution_mode || "unknown").toUpperCase())}</p><p><strong>Executable:</strong> ${escapeText(executable)}</p><p><strong>Version:</strong> ${escapeText(nuclei?.version || "Unavailable")}</p><p>${escapeText(nuclei?.error || nuclei?.install_hint || (mock ? "Mock adapter only; it does not produce real scanner findings." : "Tool status came from the local backend."))}</p><div class="scope-notice"><div><strong>No scan has been launched by this status check.</strong><p>This page reads the tool and finding APIs. Active scanning remains gated by approved authorization and explicit scan consent.</p></div></div><button class="button button-primary" data-open-findings>Open Findings</button></div></article><article class="panel"><div class="panel-heading"><div><div class="panel-kicker">PERSISTED FINDINGS</div><h2>Live statistics</h2></div></div><div class="finding-detail-copy"><p>Total: <strong>${stats.total}</strong></p><p>Potential real: <strong>${stats.potential}</strong></p><p>Manually verified real: <strong>${stats.verified}</strong></p><p>Simulated: <strong>${stats.simulated}</strong></p></div></article></div><section class="panel"><div class="panel-heading"><div><div class="panel-kicker">WEB APPLICATION SECURITY REVIEW</div><h2>Testing techniques</h2><p class="page-subtitle">${catalog.categories.length} areas · ${catalog.categories.reduce((n, category) => n + category.checks.length, 0)} checks. This is a review guide; it does not run tests or assert findings.</p></div></div><div class="technique-catalog">${categories}</div></section>`;
      byId("placeholder-content").querySelector("[data-open-findings]").addEventListener("click", () => navigate("findings"));
    } catch (error) {
      byId("placeholder-content").innerHTML = `<article class="panel"><p class="form-error">Could not load vulnerability APIs: ${escapeText(error.message)}</p><button class="button button-secondary" id="retry-vulnerability-scanner">Retry</button></article>`;
      byId("retry-vulnerability-scanner").addEventListener("click", renderVulnerabilityScanner);
    }
  }

  async function renderSettings() {
    const content = byId("placeholder-content");
    content.innerHTML = '<article class="panel"><div class="panel-heading"><div><div class="panel-kicker">RUNTIME CONFIGURATION</div><h2>Execution mode</h2></div></div><div id="settings-details" class="loading-line"><span></span>Loading runtime settings…</div></article>';
    try {
      const [settings, info] = await Promise.all([BugHunterApi.settings(), BugHunterApi.systemInfo()]);
      const warning = settings.scan_mode === "mock" ? '<div class="scope-notice"><strong>MOCK MODE ACTIVE</strong><p>All generated observations are simulated and must not be treated as findings.</p></div>' : settings.scan_mode === "local_lab" ? '<div class="scope-notice"><strong>LOCAL_LAB MODE ACTIVE</strong><p>Only registered loopback scopes and their exact approved ports can be scanned.</p></div>' : '';
      byId("settings-details").innerHTML = `${warning}<p>Profile: <strong>${escapeText(info.profile)}</strong> · Platform: <strong>${escapeText(info.platform)}</strong></p><label class="field-label" for="scan-mode-select">Tool execution mode</label><select id="scan-mode-select">${settings.allowed_modes.map((mode) => `<option value="${mode}" ${settings.scan_mode === mode ? "selected" : ""}>${mode.toUpperCase()}</option>`).join("")}</select><p class="field-help">REAL mode never falls back to simulation. Missing tools produce an explicit unavailable state.</p><div id="settings-save-state" role="status"></div>`;
      byId("scan-mode-select").addEventListener("change", async (event) => {
        event.target.disabled = true;
        try { await BugHunterApi.setScanMode(event.target.value); toast("Execution mode saved."); await refreshHealth(); await renderSettings(); }
        catch (error) { toast(error.message, true); event.target.value = settings.scan_mode; event.target.disabled = false; }
      });
    } catch (error) { byId("settings-details").textContent = `Settings unavailable: ${error.message}`; }
  }

  function selectedReviewScope() {
    return state.scopes.find((scope) => String(scope.id) === String(byId("review-scope")?.value));
  }

  function populateReviewFormFromScope() {
    const scope = selectedReviewScope();
    if (!scope) return;
    byId("review-program").value = scope.program_name || "";
    byId("review-asset").value = scope.root_domain;
    byId("review-exclusions").value = (scope.excluded_subdomains || []).join("\n");
    loadAuthorizationReviews();
  }

  async function renderAuthorizationView() {
    const select = byId("review-scope");
    const previous = select.value;
    const publicScopes = state.scopes.filter((scope) => !scope.local_lab_mode);
    select.innerHTML = publicScopes.map((scope) => `<option value="${scope.id}">${escapeText(scope.program_name || scope.root_domain)} · ${escapeText(scope.root_domain)}</option>`).join("") || '<option value="">No public scopes are registered</option>';
    select.value = publicScopes.some((scope) => String(scope.id) === previous) ? previous : (publicScopes[0]?.id ?? "");
    populateReviewFormFromScope();
    if (!publicScopes.length) byId("authorization-review-list").innerHTML = '<div class="history-empty">Register a public scope before requesting an authorization review. Local Lab scopes do not use public review records.</div>';
  }

  async function loadAuthorizationReviews() {
    const scope = selectedReviewScope();
    const container = byId("authorization-review-list");
    if (!scope) return;
    container.innerHTML = '<div class="loading-line"><span></span>Loading review evidence…</div>';
    try {
      const reviews = await BugHunterApi.authorizationReviews(scope.id);
      if (!reviews.length) {
        container.innerHTML = '<div class="history-empty">No reviews yet. Submit scope evidence to create a PENDING review.</div>';
        return;
      }
      container.innerHTML = reviews.map((review) => {
        const expired = review.status === "APPROVED" && review.expires_at && new Date(review.expires_at) <= new Date();
        const status = expired ? "EXPIRED" : review.status;
        const excluded = Array.isArray(review.excluded_assets) ? review.excluded_assets : JSON.parse(review.excluded_assets || "[]");
        return `<article class="authorization-review-card"><div class="panel-heading"><div><div class="panel-kicker">REVIEW #${review.id} · ${escapeText(review.platform_name || "Platform unspecified")}</div><h2>${escapeText(review.program_name)} · ${escapeText(review.authorized_asset)}</h2></div><span class="mode-pill">${status}</span></div><div class="finding-detail-copy"><p><strong>Subdomains:</strong> ${review.allow_subdomains ? "Allowed by this review" : "Not allowed"}</p><p><strong>Policy:</strong> <a href="${escapeText(review.policy_url)}" target="_blank" rel="noopener noreferrer">${escapeText(review.policy_url)}</a></p><p><strong>Exclusions:</strong> ${escapeText(excluded.join(", ") || "None recorded")}</p><p><strong>Evidence:</strong> ${escapeText(review.evidence_notes || "No reviewer notes supplied.")}</p><p><strong>Submitted:</strong> ${dateLabel(review.created_at)} · <strong>Expires:</strong> ${review.expires_at ? dateLabel(review.expires_at) : "No expiration"}</p>${review.reviewed_at ? `<p><strong>Reviewed:</strong> ${dateLabel(review.reviewed_at)} by ${escapeText(review.reviewer || "Unknown reviewer")}</p><p><strong>Decision:</strong> ${escapeText(review.decision || "")}</p>` : ""}${status === "PENDING" ? `<div class="review-decision" data-review-id="${review.id}"><input class="reviewer-name" maxlength="120" placeholder="Reviewer name"><input class="reviewer-decision" maxlength="2000" placeholder="Decision notes"><button class="button button-secondary button-small" data-review-decision="APPROVED">Approve</button><button class="button button-secondary button-small" data-review-decision="REJECTED">Reject</button></div>` : ""}</div></article>`;
      }).join("");
    } catch (error) {
      container.innerHTML = `<div class="form-error">Could not load authorization reviews: ${escapeText(error.message)}</div>`;
    }
  }

  async function submitAuthorizationReview(event) {
    event.preventDefault();
    const scope = selectedReviewScope();
    if (!scope) return;
    const errorEl = byId("authorization-form-error");
    errorEl.classList.add("hidden");
    const expiryValue = byId("review-expires").value;
    try {
      const review = await BugHunterApi.createAuthorizationReview(scope.id, {
        program_name: byId("review-program").value.trim(),
        platform_name: byId("review-platform").value.trim(),
        authorized_asset: byId("review-asset").value.trim(),
        allow_subdomains: byId("review-subdomains").checked,
        policy_url: byId("review-policy").value.trim(),
        excluded_assets: splitAssets(byId("review-exclusions").value),
        evidence_notes: byId("review-evidence").value.trim(),
        expires_at: expiryValue ? new Date(expiryValue).toISOString() : null,
      });
      toast(`Review #${review.id} submitted as PENDING; no scans are authorized yet.`);
      byId("review-evidence").value = "";
      byId("review-expires").value = "";
      await Promise.all([loadAuthorizationReviews(), refreshScopes()]);
    } catch (error) { errorEl.textContent = error.message; errorEl.classList.remove("hidden"); }
  }

  async function decideAuthorizationReview(reviewId, decision, controls) {
    const reviewer = controls.querySelector(".reviewer-name").value.trim();
    const notes = controls.querySelector(".reviewer-decision").value.trim();
    if (reviewer.length < 2 || notes.length < 3) { toast("Enter a reviewer name and a clear decision note.", true); return; }
    try {
      await BugHunterApi.decideAuthorizationReview(reviewId, { status: decision, reviewer, decision: notes });
      toast(`Authorization review ${decision.toLowerCase()}.`);
      await Promise.all([loadAuthorizationReviews(), refreshScopes()]);
    } catch (error) { toast(error.message, true); }
  }

  function renderReconPrograms() {
    const select = byId("recon-scope-select");
    if (!select) return;
    const previous = select.value;
    select.innerHTML = '<option value="">Select an authorized program…</option>' + state.scopes.map((scope) =>
      `<option value="${scope.id}">${escapeText(scope.program_name || scope.root_domain)} · ${escapeText(scope.root_domain)}</option>`).join("");
    select.value = state.scopes.some((scope) => String(scope.id) === previous) ? previous : (state.scopes[0]?.id ?? "");
    if (reconViews.has(state.activeView)) renderReconControls();
  }

  function moduleRows(module, results) {
    const rows = {
      reconnaissance: (item) => [item.hostname, item.source || "Subfinder", dateLabel(item.discovered_at), dataBadge(item.simulated)],
      subdomains: (item) => [item.hostname, item.source || "Not supplied", dateLabel(item.discovered_at), dataBadge(item.simulated)],
      "live-hosts": (item) => [item.hostname, item.url, item.status_code ?? "—", item.title || "—", dataBadge(item.simulated)],
      "url-intelligence": (item) => [item.url, (item.sources || []).join(", ") || "Archive", dateLabel(item.discovered_at), dataBadge(item.simulated)],
      endpoints: (item) => [item.url, item.method || "GET", item.source || "Katana", dataBadge(item.simulated)],
      parameters: (item) => [item.endpoint_url, item.parameter_name, item.parameterized_url, item.source],
      technologies: (item) => [item.hostname, item.technology, item.version || "—", dateLabel(item.detected_at), dataBadge(item.simulated)],
    };
    return (results || []).map((item) => rows[module](item));
  }

  function dataBadge(simulated) {
    return simulated ? "SIMULATED" : "TOOL RESULT";
  }

  function renderReconResults(module, results) {
    const tbody = byId("subdomain-results-body");
    byId("subdomain-result-count").textContent = `${results.length} ${results.length === 1 ? "RESULT" : "RESULTS"}`;
    byId("subdomain-result-mode").textContent = results.some((item) => item.simulated) ? "SIMULATED DATA" : (results.length ? "RECORDED RESULTS" : "");
    const config = reconModules[module];
    byId("subdomain-results-title").textContent = config.resultTitle;
    byId("recon-results-head").innerHTML = `<tr>${config.columns.map((label) => `<th>${label}</th>`).join("")}</tr>`;
    if (!results.length) {
      tbody.innerHTML = `<tr><td colspan="${config.columns.length}" class="table-loading">No ${config.resultTitle.toLowerCase()} are recorded for this program.</td></tr>`;
      return;
    }
    tbody.innerHTML = moduleRows(module, results).map((cells) => `<tr>${cells.map((value) => {
      const text = String(value ?? "");
      if (text === "SIMULATED" || text === "TOOL RESULT") return `<td><span class="${text === "SIMULATED" ? "simulation-badge" : "real-badge"}">${text}</span></td>`;
      return `<td class="${text.startsWith("http") || text.includes(".") ? "hostname-cell" : ""}">${escapeText(text)}</td>`;
    }).join("")}</tr>`).join("");
  }

  function renderScanHistory(scans, module) {
    const container = byId("subdomain-scan-history");
    if (!scans.length) {
      container.innerHTML = `<div class="history-empty">No ${reconModules[module].title} runs have been recorded for this program.</div>`;
      return;
    }
    container.innerHTML = scans.map((scan) => `<div class="history-row">
      <strong>SCAN-${String(scan.id).padStart(4, "0")}</strong>
      <span class="history-stage">${escapeText(scan.stage.replaceAll("_", " "))}${scan.error ? ` · ${escapeText(scan.error)}` : ""}</span>
      <span class="history-date">${dateLabel(scan.created_at)}</span>
      <span class="${scan.simulated ? "simulation-badge" : "real-badge"}">${scan.simulated ? "MOCK" : escapeText(scan.status.toUpperCase())}</span>
    </div>`).join("");
  }

  function renderScanStatus(scan, module = state.activeView) {
    const statusText = { queued: "Queued", running: "Running", completed: "Completed", failed: "Failed", cancelled: "Cancelled" };
    const stageText = { queued: "Queued for a local worker.", validating_scope: "Validating registered authorization and destination.", subfinder: "Running passive Subfinder sources.", httpx_probe: "Checking approved public host addresses.", collecting_archives: "Querying historical URL sources.", katana_crawl: "Crawling approved application paths.", whatweb_fingerprint: "Fingerprinting technology with WhatWeb.", processing_results: "Filtering and storing scope-matched results.", validating_urls: "Filtering URLs against program scope.", validating_endpoints: "Filtering endpoints against program scope.", completed: "Stage completed.", completed_with_filtered_results: "Completed; unsafe or out-of-scope results were filtered.", scope_validation_failed: "Scope validation failed.", tool_unavailable: "Required tool is unavailable.", timed_out: "The configured timeout was reached.", cancelled: "Cancellation completed.", endpoints_skipped_no_approval: "Crawl skipped because approval was not provided." };
    const terminalSuccess = scan.status === "completed";
    const terminalError = scan.status === "failed" || scan.status === "cancelled";
    byId("job-status").textContent = statusText[scan.status] || scan.status;
    if (Array.isArray(scan.stages)) {
      const resolvedStages = scan.stages.filter((item) => ["completed", "skipped", "failed", "cancelled"].includes(item.status)).length;
      byId("job-progress-label").textContent = `${resolvedStages}/${scan.stages.length} stages resolved`;
      byId("job-progress-bar").style.width = `${Math.round(100 * resolvedStages / Math.max(scan.stages.length, 1))}%`;
    } else {
      byId("job-progress-label").textContent = statusText[scan.status] || scan.status;
      byId("job-progress-bar").style.width = scan.status === "completed" ? "100%" : "0%";
    }
    byId("job-stage-label").textContent = scan.error || stageText[scan.stage] || scan.stage.replaceAll("_", " ");
    byId("recon-mode").textContent = scan.simulated ? "SIMULATED RUN" : (scan.status.toUpperCase());
    byId("recon-mode").classList.toggle("lab", scan.simulated);
    if (Array.isArray(scan.stages)) {
      byId("recon-stage-list").innerHTML = scan.stages.map((item) => `<span class="stage-chip ${item.status === "completed" ? "done" : item.status === "running" ? "current" : item.status === "failed" || item.status === "cancelled" ? item.status : ""}"><i></i>${escapeText(item.name.replaceAll("_", " "))}</span>`).join("");
    } else {
      const labels = scan.module === "live_hosts" ? ["Scope check", "HTTPX probes", "Store hosts"] : scan.module === "urls" ? ["Scope check", "Archive sources", "Filter URLs"] : scan.module === "endpoints" ? ["Scope check", "Katana crawl", "Filter endpoints"] : scan.module === "technologies" ? ["Scope check", "WhatWeb", "Store fingerprints"] : ["Scope check", "Subfinder", "Parse results"];
      const current = scan.stage.includes("validating") || scan.stage.includes("scope") ? 0 : scan.stage.includes("process") || scan.stage.includes("validating_") ? 2 : scan.status === "completed" ? 2 : 1;
      byId("recon-stage-list").innerHTML = labels.map((label, index) => `<span class="stage-chip ${terminalSuccess || index < current ? "done" : terminalError && index === current ? scan.status : !terminalError && index === current ? "current" : ""}"><i></i>${label}</span>`).join("");
    }
    const active = scan.status === "queued" || scan.status === "running";
    state.activeScanId = active ? scan.id : null;
    state.activeScanModule = active ? module : null;
    byId("cancel-subdomain-scan").classList.toggle("hidden", !active);
    const start = byId("start-subdomain-scan");
    if (start) start.disabled = active || !byId("recon-scope-select").value;
    if (scan.error) showReconAlert(scan.error, "error");
    else if (scan.simulated) showReconAlert("This is a simulated development run. Results are labeled and are not real discovered assets.", "info");
    else if (terminalSuccess) showReconAlert("Stage completed. Only authorized, scope-matched results were stored.", "success");
    if (active) startPolling(scan.id, module);
    else stopPolling();
  }

  function showReconAlert(message, kind) {
    const alert = byId("recon-alert");
    alert.textContent = message;
    alert.className = `recon-alert ${kind || ""}`;
    alert.classList.remove("hidden");
  }

  function stopPolling() {
    if (state.pollTimer) window.clearInterval(state.pollTimer);
    state.pollTimer = null;
  }

  function statusRequest(module, scanId) {
    const requests = { reconnaissance: BugHunterApi.reconJob, subdomains: BugHunterApi.subdomainScan,
      "live-hosts": BugHunterApi.liveHostScan, "url-intelligence": BugHunterApi.urlScan,
      endpoints: BugHunterApi.endpointScan, technologies: BugHunterApi.technologyScan };
    return requests[module](scanId);
  }

  function startPolling(scanId, module) {
    if (state.pollTimer) window.clearInterval(state.pollTimer);
    state.pollTimer = window.setInterval(async () => {
      try {
        const scan = await statusRequest(module, scanId);
        renderScanStatus(scan);
        if (scan.results) renderReconResults(module === "reconnaissance" ? "subdomains" : module, scan.results);
        if (!state.activeScanId) {
          stopPolling();
          await loadRecon();
        }
      } catch (error) {
        showReconAlert(error.message, "error");
        stopPolling();
      }
    }, 1000);
  }

  async function loadRecon() {
    renderReconControls();
    const module = state.activeView;
    const scopeId = byId("recon-scope-select").value;
    stopPolling();
    state.activeScanId = null;
    byId("cancel-subdomain-scan").classList.add("hidden");
    if (!scopeId) {
      state.tool = null;
      const startButton = byId("start-subdomain-scan");
      if (startButton) startButton.disabled = true;
      byId("job-status").textContent = "Waiting for enumeration";
      byId("job-progress-label").textContent = "—";
      byId("job-progress-bar").style.width = "0";
      byId("job-stage-label").textContent = "Register an authorized program before starting reconnaissance.";
      byId("recon-stage-list").innerHTML = "";
      renderReconResults(module, []);
      byId("subdomain-scan-history").innerHTML = '<div class="history-empty">Register an authorized program to enable scan history.</div>';
      setStatus(byId("subfinder-tool-state"), "WAITING", "pending");
      byId("subfinder-tool-version").textContent = "Select a registered program";
      byId("recon-alert").classList.add("hidden");
      return;
    }
    byId("recon-alert").classList.add("hidden");
    byId("subdomain-results-body").innerHTML = '<tr><td colspan="5" class="table-loading">Loading recorded results…</td></tr>';
    try {
      const responseData = await fetchReconData(module, scopeId);
      const data = module === "reconnaissance" ? { scans: responseData } : responseData;
      if (module === "reconnaissance") {
        const subdomainData = await BugHunterApi.subdomains(scopeId);
        data.results = subdomainData.results || [];
        data.tools = subdomainData.tool ? { subfinder: subdomainData.tool } : {};
      }
      const results = data.results || [];
      renderReconResults(module === "reconnaissance" ? "subdomains" : module, results);
      renderScanHistory(data.scans || [], module);
      state.tool = data.tool || data.tools || null;
      renderReconTool(data);
      const active = (data.scans || []).find((scan) => scan.status === "queued" || scan.status === "running");
      if (active) {
        const full = await statusRequest(module, active.id);
        renderScanStatus(full, module);
        if (full.results) renderReconResults(module === "reconnaissance" ? "subdomains" : module, full.results);
      } else if (data.scans?.length) {
        renderScanStatus(data.scans[0], module);
        if (data.scans[0].results) renderReconResults(module === "reconnaissance" ? "subdomains" : module, data.scans[0].results);
      } else {
        byId("job-status").textContent = "Waiting for enumeration";
        byId("job-progress-label").textContent = "—";
        byId("job-progress-bar").style.width = "0";
        byId("job-stage-label").textContent = module === "parameters" ? "Parameters are derived from recorded URLs and endpoints." : "Select an authorized program and start discovery.";
        byId("recon-stage-list").innerHTML = "";
        byId("recon-mode").textContent = "NO SCAN";
      }
    } catch (error) {
      showReconAlert(error.message, "error");
      byId("subdomain-results-body").innerHTML = `<tr><td colspan="5" class="table-loading">Could not load results: ${escapeText(error.message)}</td></tr>`;
    }
  }

  function fetchReconData(module, scopeId) {
    const requests = { reconnaissance: BugHunterApi.reconJobs, subdomains: BugHunterApi.subdomains,
      "live-hosts": BugHunterApi.liveHosts, "url-intelligence": BugHunterApi.historicalUrls,
      endpoints: BugHunterApi.endpoints, parameters: BugHunterApi.parameters, technologies: BugHunterApi.technologies };
    return requests[module](scopeId);
  }

  function renderReconTool(data) {
    const tool = data.tool || null;
    const tools = data.tools ? Object.values(data.tools) : (tool ? [tool] : []);
    if (!tools.length) {
      setStatus(byId("subfinder-tool-state"), "DERIVED DATA", "pending");
      byId("subfinder-tool-version").textContent = "No external tool required";
      byId("subfinder-tool-mode").textContent = "Local SQLite result processing";
      byId("subfinder-tool-notice").textContent = "Parameter names are extracted from stored URLs; no requests are sent.";
      return;
    }
    const mock = tools.some((item) => item.simulated);
    const installed = tools.filter((item) => item.available && !item.simulated).length;
    const missing = tools.filter((item) => !item.available && !item.simulated);
    setStatus(byId("subfinder-tool-state"), mock ? "MOCK ADAPTER" : missing.length ? "NOT INSTALLED" : "INSTALLED", mock ? "pending" : missing.length ? "error" : "ok");
    byId("subfinder-tool-version").textContent = mock ? "Simulated adapter · no binary required" : `${installed} available · ${missing.length} missing`;
    byId("subfinder-tool-mode").textContent = mock ? "No network requests are made" : (tool?.command || tool?.executable_name || tool?.version || "Local security tools");
    byId("subfinder-tool-notice").textContent = mock ? "Development output is explicitly simulated." : missing.map((item) => item.install_hint || item.name).join("; ") || "Tool status comes from the local backend.";
  }

  function renderReconControls() {
    const module = state.activeView;
    const config = reconModules[module];
    if (!config) return;
    byId("recon-control-kicker").textContent = config.kicker;
    byId("recon-control-title").textContent = "Select a registered program";
    byId("recon-control-description").textContent = config.description;
    const scopeId = byId("recon-scope-select").value;
    const selected = state.scopes.find((item) => String(item.id) === String(scopeId));
    let extra = "";
    if (module === "live-hosts" && selected?.local_lab_mode) extra = `<input class="host-input" id="lab-target-url" aria-label="Approved local lab URL" placeholder="http://localhost:8080"><small class="field-help">Use an exact loopback URL with a port configured on this program.</small>`;
    if (module === "endpoints") extra = `<input class="host-input" id="endpoint-host-input" aria-label="Authorized application hostname" value="${escapeText(selected?.root_domain || "")}" placeholder="app.example.com"><label class="approval-option"><input type="checkbox" id="endpoint-approval"><span>I approve active crawling for this target.</span></label>`;
    if (module === "reconnaissance") extra = '<label class="approval-option"><input type="checkbox" id="pipeline-crawl-approval"><span>Include active Katana crawl</span></label>';
    const action = module === "parameters" ? "Refresh parameters" : module === "reconnaissance" ? "Start full reconnaissance" : module === "endpoints" ? "Start approved crawl" : `Start ${config.title.toLowerCase()}`;
    byId("recon-controls").innerHTML = `<select id="recon-scope-select" aria-label="Select authorized program"><option value="">Select an authorized program…</option>${state.scopes.map((item) => `<option value="${item.id}">${escapeText(item.program_name || item.root_domain)} · ${escapeText(item.root_domain)}</option>`).join("")}</select>${extra}<button class="button button-primary" id="start-subdomain-scan" data-recon-action="start" ${!scopeId || state.activeScanId ? "disabled" : ""}>${action} <span>→</span></button><button class="button button-secondary hidden" id="cancel-subdomain-scan" data-recon-action="cancel">Cancel</button>`;
    byId("recon-scope-select").value = scopeId;
  }

  async function beginReconAction() {
    const scopeId = byId("recon-scope-select").value;
    if (!scopeId) return;
    byId("start-subdomain-scan").disabled = true;
    byId("recon-alert").classList.add("hidden");
    try {
      const module = state.activeView;
      let scan;
      if (module === "reconnaissance") scan = await BugHunterApi.startRecon(Number(scopeId), Boolean(byId("pipeline-crawl-approval")?.checked));
      else if (module === "subdomains") scan = await BugHunterApi.startSubdomainScan(Number(scopeId));
      else if (module === "live-hosts") scan = await BugHunterApi.startLiveHosts(Number(scopeId), byId("lab-target-url")?.value.trim() || undefined);
      else if (module === "url-intelligence") scan = await BugHunterApi.startHistoricalUrls(Number(scopeId));
      else if (module === "endpoints") scan = await BugHunterApi.startEndpoints(Number(scopeId), byId("endpoint-host-input").value.trim(), Boolean(byId("endpoint-approval").checked));
      else if (module === "technologies") scan = await BugHunterApi.startTechnologies(Number(scopeId));
      else return loadRecon();
      state.activeScanModule = module;
      renderScanStatus(scan, module);
      if (scan.results) renderReconResults(module === "reconnaissance" ? "subdomains" : module, scan.results);
      await loadReconHistoryOnly(module);
    } catch (error) {
      showReconAlert(error.message, "error");
      byId("start-subdomain-scan").disabled = false;
    }
  }

  async function loadReconHistoryOnly(module) {
    try {
      const data = await fetchReconData(module, byId("recon-scope-select").value);
      renderScanHistory(data.scans || [], module);
    } catch (_) { /* the current job status remains visible */ }
  }

  async function cancelReconAction() {
    if (!state.activeScanId) return;
    byId("cancel-subdomain-scan").disabled = true;
    try {
      const cancel = { reconnaissance: BugHunterApi.cancelRecon, subdomains: BugHunterApi.cancelSubdomainScan,
        "live-hosts": BugHunterApi.cancelLiveHosts, "url-intelligence": BugHunterApi.cancelUrlScan,
        endpoints: BugHunterApi.cancelEndpoints, technologies: BugHunterApi.cancelTechnologies }[state.activeScanModule];
      await cancel(state.activeScanId);
      showReconAlert("Cancellation requested. Waiting for the running process to stop.", "info");
    } catch (error) {
      showReconAlert(error.message, "error");
    } finally {
      byId("cancel-subdomain-scan").disabled = false;
    }
  }

  async function refreshScopes() {
    state.loading = true;
    try {
      state.scopes = await BugHunterApi.scopes();
      byId("metric-programs").textContent = state.scopes.length;
      renderOverviewPrograms();
      renderTargets();
      renderReconPrograms();
      loadDashboardRecon();
      loadDashboardVulnerabilityStats();
      if (reconViews.has(state.activeView)) loadRecon();
      if (state.activeView === "authorization-reviews") renderAuthorizationView();
    } catch (error) {
      byId("overview-program-list").innerHTML = `<div class="load-error">${escapeText(error.message)} <button class="text-button" id="retry-scopes">Retry</button></div>`;
      byId("target-table-body").innerHTML = `<tr><td colspan="6" class="table-loading">Could not load scopes: ${escapeText(error.message)}</td></tr>`;
      byId("target-count").textContent = "API ERROR";
    } finally {
      state.loading = false;
    }
  }

  function setStatus(element, label, kind = "ok") {
    element.textContent = label;
    element.classList.toggle("is-error", kind === "error");
    element.classList.toggle("state-pending", kind === "pending");
  }

  async function refreshHealth() {
    const pill = byId("api-status");
    try {
      const health = await BugHunterApi.health();
      const system = await BugHunterApi.systemInfo();
      pill.classList.remove("is-error", "is-loading");
      pill.innerHTML = `<span class="status-dot"></span><span>API · ${escapeText(system.platform)} · ${escapeText(system.execution_mode.toUpperCase())}</span>`;
      byId("mock-mode-banner").classList.toggle("hidden", system.execution_mode !== "mock");
      setStatus(byId("backend-state"), "OPERATIONAL");
      const ai = health.ai === "connected" ? "AVAILABLE" : health.ai === "connected_model_missing" ? "MODEL MISSING" : "UNAVAILABLE";
      setStatus(byId("ollama-state"), ai, health.ai === "connected" ? "ok" : "error");
      byId("ollama-detail").textContent = `${health.ollama_model || "Ollama"} · ${health.ai_install_hint ? "setup required" : "local service"}`;
      const tools = Array.isArray(health.tools) ? health.tools : [];
      const simulated = tools.some((tool) => tool.simulated);
      const installed = tools.filter((tool) => tool.available && !tool.simulated).length;
      byId("tool-summary").textContent = simulated ? "Development adapters · simulated" : `${installed} installed · ${tools.length} detected`;
      setStatus(byId("tool-state"), simulated ? "MOCK MODE" : `${installed} AVAILABLE`, simulated ? "pending" : (installed ? "ok" : "error"));
    } catch (error) {
      pill.classList.add("is-error");
      pill.innerHTML = '<span class="status-dot"></span><span>API unavailable</span>';
      setStatus(byId("backend-state"), "UNAVAILABLE", "error");
      setStatus(byId("ollama-state"), "UNKNOWN", "error");
      setStatus(byId("tool-state"), "UNKNOWN", "error");
      byId("ollama-detail").textContent = "Health endpoint could not be reached";
      byId("tool-summary").textContent = error.message;
    }
  }

  function navigate(view) {
    const data = labels[view] || labels.overview;
    state.activeView = view;
    document.querySelectorAll(".nav-link").forEach((link) => link.classList.toggle("active", link.dataset.view === view));
    byId("breadcrumb-current").textContent = data[0];
    byId("view-overview").classList.toggle("hidden", view !== "overview");
    byId("view-targets").classList.toggle("hidden", !targetViews.has(view));
    byId("view-recon").classList.toggle("hidden", !reconViews.has(view));
    byId("view-authorization").classList.toggle("hidden", view !== "authorization-reviews");
    const isVulnerabilityView = view === "findings" || view === "vulnerability-scanner";
    byId("view-placeholder").classList.toggle("hidden", view === "overview" || targetViews.has(view) || reconViews.has(view) || view === "authorization-reviews");
    if (targetViews.has(view)) {
      byId("target-page-title").textContent = data[1];
      byId("target-search").value = "";
      renderTargets();
    } else if (reconViews.has(view)) {
      byId("recon-title").textContent = reconModules[view].title;
      byId("recon-subtitle").textContent = reconModules[view].description;
      renderReconControls();
      loadRecon();
    } else if (view === "authorization-reviews") {
      renderAuthorizationView();
    } else if (view !== "overview") {
      byId("placeholder-title").textContent = data[1];
      byId("placeholder-description").textContent = data[2];
      byId("placeholder-content").innerHTML = "";
      byId("placeholder-fallback").classList.toggle("hidden", isVulnerabilityView || view === "tool-management" || view === "settings");
      if (view === "findings") renderFindingsManagement();
      else if (view === "vulnerability-scanner") renderVulnerabilityScanner();
      else if (view === "tool-management") renderToolManagement();
      else if (view === "settings") renderSettings();
      else {
        byId("coming-title").textContent = `${data[1]} API is not connected`;
        byId("coming-description").textContent = `The current backend does not expose ${data[1].toLowerCase()} data or actions yet. This section will use live API results when its module is implemented.`;
      }
    }
    closeSidebar();
  }

  function openModal() {
    byId("form-error").classList.add("hidden");
    byId("target-form").reset();
    byId("target-form").elements.include_subdomains.checked = true;
    byId("lab-ports-row").classList.add("hidden");
    byId("target-modal").classList.remove("hidden");
    byId("root-domain").focus();
  }

  function closeModal() {
    byId("target-modal").classList.add("hidden");
  }

  function closeSidebar() {
    byId("sidebar").classList.remove("open");
    document.querySelector(".menu-overlay")?.remove();
  }

  function splitAssets(value) {
    return value.split(/[\n,\r]+/).map((item) => item.trim()).filter(Boolean);
  }

  async function submitTarget(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const values = new FormData(form);
    const payload = {
      program_name: values.get("program_name").trim(),
      root_domain: values.get("root_domain").trim(),
      included_assets: splitAssets(values.get("included_assets")),
      excluded_subdomains: splitAssets(values.get("excluded_subdomains")),
      include_subdomains: values.has("include_subdomains"),
      local_lab_mode: values.has("local_lab_mode"),
      local_lab_ports: splitAssets(values.get("local_lab_ports") || "").map((port) => Number(port)),
      authorization_notes: values.get("authorization_notes").trim(),
      authorization_reference: values.get("authorization_reference").trim(),
      authorization_confirmed: values.has("authorization_confirmed"),
    };
    const submit = byId("submit-target");
    submit.disabled = true;
    submit.textContent = "Saving scope…";
    try {
      await BugHunterApi.createScope(payload);
      closeModal();
      toast("Authorized target registered.");
      await refreshScopes();
      navigate("programs");
    } catch (error) {
      byId("form-error").textContent = error.message;
      byId("form-error").classList.remove("hidden");
    } finally {
      submit.disabled = false;
      submit.innerHTML = 'Save authorized target <span>→</span>';
    }
  }

  async function deleteScope(id) {
    const scope = state.scopes.find((item) => String(item.id) === String(id));
    if (!scope || !window.confirm(`Remove the authorized scope for ${scope.root_domain}? This does not delete scan data.`)) return;
    try {
      await BugHunterApi.deleteScope(id);
      toast("Scope removed.");
      await refreshScopes();
    } catch (error) {
      toast(error.message, true);
    }
  }

  function openAuthorizationScope(id) {
    navigate("authorization-reviews");
    byId("review-scope").value = String(id);
    populateReviewFormFromScope();
  }

  function bindEvents() {
    document.querySelectorAll("[data-view]").forEach((link) => link.addEventListener("click", (event) => {
      event.preventDefault();
      navigate(link.dataset.view);
      history.replaceState(null, "", `#${link.dataset.view}`);
    }));
    document.querySelectorAll("[data-go]").forEach((button) => button.addEventListener("click", () => navigate(button.dataset.go)));
    ["add-target-button", "target-add-button", "empty-add-target"].forEach((id) => byId(id).addEventListener("click", openModal));
    ["modal-close", "modal-cancel"].forEach((id) => byId(id).addEventListener("click", closeModal));
    byId("target-form").addEventListener("submit", submitTarget);
    byId("authorization-review-form").addEventListener("submit", submitAuthorizationReview);
    byId("review-scope").addEventListener("change", populateReviewFormFromScope);
    byId("authorization-refresh").addEventListener("click", loadAuthorizationReviews);
    byId("authorization-review-list").addEventListener("click", (event) => {
      const button = event.target.closest("[data-review-decision]");
      if (button) decideAuthorizationReview(button.closest("[data-review-id]").dataset.reviewId, button.dataset.reviewDecision, button.closest("[data-review-id]"));
    });
    byId("target-form").elements.local_lab_mode.addEventListener("change", (event) => byId("lab-ports-row").classList.toggle("hidden", !event.target.checked));
    byId("recon-controls").addEventListener("change", (event) => {
      if (event.target.id === "recon-scope-select") loadRecon();
    });
    byId("recon-controls").addEventListener("click", (event) => {
      const action = event.target.closest("[data-recon-action]")?.dataset.reconAction;
      if (action === "start") beginReconAction();
      if (action === "cancel") cancelReconAction();
    });
    byId("recon-refresh").addEventListener("click", loadRecon);
    byId("target-search").addEventListener("input", renderTargets);
    byId("target-table-body").addEventListener("click", (event) => {
      const button = event.target.closest("[data-delete-scope]");
      if (button) deleteScope(button.dataset.deleteScope);
      const review = event.target.closest("[data-open-authorization]");
      if (review) openAuthorizationScope(review.dataset.openAuthorization);
    });
    ["refresh-button", "target-refresh-button"].forEach((id) => byId(id).addEventListener("click", () => Promise.all([refreshScopes(), refreshHealth()])));
    byId("docs-button").addEventListener("click", () => window.open("/docs", "_blank", "noopener"));
    byId("menu-toggle").addEventListener("click", () => {
      byId("sidebar").classList.add("open");
      const overlay = document.createElement("div");
      overlay.className = "menu-overlay";
      overlay.addEventListener("click", closeSidebar);
      document.body.append(overlay);
    });
    byId("target-modal").addEventListener("click", (event) => { if (event.target === event.currentTarget) closeModal(); });
    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape") { closeModal(); closeSidebar(); }
    });
    byId("overview-program-list").addEventListener("click", (event) => {
      if (event.target.id === "retry-scopes") refreshScopes();
    });
  }

  document.addEventListener("DOMContentLoaded", () => {
    bindEvents();
    const initial = window.location.hash.slice(1);
    navigate(labels[initial] ? initial : "overview");
    Promise.all([refreshScopes(), refreshHealth()]);
  });
})();
