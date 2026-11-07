(() => {
  const $ = (selector) => document.querySelector(selector);
  const byId = (id) => document.getElementById(id);
  const state = { scopes: [], activeView: "overview", loading: false };
  const targetViews = new Set(["programs", "scope-manager"]);
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

  async function refreshScopes() {
    state.loading = true;
    try {
      state.scopes = await BugHunterApi.scopes();
      byId("metric-programs").textContent = state.scopes.length;
      renderOverviewPrograms();
      renderTargets();
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
    byId("view-placeholder").classList.toggle("hidden", view === "overview" || targetViews.has(view));
    if (targetViews.has(view)) {
      byId("target-page-title").textContent = data[1];
      byId("target-search").value = "";
      renderTargets();
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
