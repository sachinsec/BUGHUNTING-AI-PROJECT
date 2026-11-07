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
        <span class="scope-badge${scope.local_lab_mode ? " lab" : ""}">${scope.local_lab_mode ? "LAB MODE" : "AUTHORIZED"}</span>
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
      return `<tr>
        <td><div class="table-program"><span class="program-mark">${escapeText((scope.program_name || scope.root_domain).slice(0, 1).toUpperCase())}</span><span><strong>${escapeText(scope.program_name || scope.root_domain)}</strong><small>${escapeText(scope.root_domain)}</small></span></div></td>
        <td><span class="asset-count">${assets}<small> ${scope.include_subdomains ? "incl. subdomains" : "explicit assets"}</small></span></td>
        <td><span class="asset-count">${scope.excluded_subdomains.length}</span></td>
        <td><span class="mode-pill${scope.local_lab_mode ? " lab" : ""}">${scope.local_lab_mode ? "LOCAL LAB" : "AUTHORIZED"}</span></td>
        <td>${dateLabel(scope.created_at)}</td>
        <td><div class="row-actions"><button class="delete-button" data-delete-scope="${scope.id}" aria-label="Delete ${escapeText(scope.program_name || scope.root_domain)}" title="Remove scope">×</button></div></td>
      </tr>`;
    }).join("");
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
    byId("subfinder-tool-mode").textContent = mock ? "No network requests are made" : (tool?.version || "Local security tools");
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
      else if (module === "live-hosts") scan = await BugHunterApi.startLiveHosts(Number(scopeId));
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
      if (reconViews.has(state.activeView)) loadRecon();
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
      pill.classList.remove("is-error", "is-loading");
      pill.innerHTML = '<span class="status-dot"></span><span>API connected</span>';
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
    byId("view-placeholder").classList.toggle("hidden", view === "overview" || targetViews.has(view) || reconViews.has(view));
    if (targetViews.has(view)) {
      byId("target-page-title").textContent = data[1];
      byId("target-search").value = "";
      renderTargets();
    } else if (reconViews.has(view)) {
      byId("recon-title").textContent = reconModules[view].title;
      byId("recon-subtitle").textContent = reconModules[view].description;
      renderReconControls();
      loadRecon();
    } else if (view !== "overview") {
      byId("placeholder-title").textContent = data[1];
      byId("placeholder-description").textContent = data[2];
      byId("coming-title").textContent = `${data[1]} API is not connected`;
      byId("coming-description").textContent = `The current backend does not expose ${data[1].toLowerCase()} data or actions yet. This section will use live API results when its module is implemented.`;
    }
    closeSidebar();
  }

  function openModal() {
    byId("form-error").classList.add("hidden");
    byId("target-form").reset();
    byId("target-form").elements.include_subdomains.checked = true;
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
      authorization_notes: values.get("authorization_notes").trim(),
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
