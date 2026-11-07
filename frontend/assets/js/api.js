(() => {
  async function request(path, options = {}) {
    const response = await fetch(path, {
      ...options,
      headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    });
    if (!response.ok) {
      let message = `Request failed (${response.status})`;
      try {
        const body = await response.json();
        message = typeof body.detail === "string" ? body.detail : message;
      } catch (_) { /* retain the HTTP status message */ }
      throw new Error(message);
    }
    return response.status === 204 ? null : response.json();
  }
  const scoped = (path, scopeId) => `${path}${scopeId ? `?scope_id=${encodeURIComponent(scopeId)}` : ""}`;

  window.BugHunterApi = {
    health: () => request("/api/health"),
    systemInfo: () => request("/api/system/info"),
    toolStatus: () => request("/api/tools/status"),
    checkTools: () => request("/api/tools/check", { method: "POST", body: "{}" }),
    settings: () => request("/api/settings"),
    setScanMode: (scan_mode) => request("/api/settings/scan-mode", { method: "PUT", body: JSON.stringify({ scan_mode }) }),
    scopes: () => request("/api/scopes"),
    createScope: (data) => request("/api/scopes", { method: "POST", body: JSON.stringify(data) }),
    verifyAuthorization: (id, data) => request(`/api/scopes/${encodeURIComponent(id)}/verify-authorization`, { method: "POST", body: JSON.stringify(data) }),
    deleteScope: (id) => request(`/api/scopes/${encodeURIComponent(id)}`, { method: "DELETE" }),
    subdomains: (scopeId) => request(scoped("/api/recon/subdomains", scopeId)),
    subdomainScan: (scanId) => request(`/api/recon/subdomains/${encodeURIComponent(scanId)}`),
    startSubdomainScan: (scopeId) => request("/api/recon/subdomains/start", { method: "POST", body: JSON.stringify({ scope_id: scopeId }) }),
    cancelSubdomainScan: (scanId) => request(`/api/recon/subdomains/${encodeURIComponent(scanId)}/cancel`, { method: "POST" }),
    liveHosts: (scopeId) => request(scoped("/api/recon/live-hosts", scopeId)),
    startLiveHosts: (scopeId, target_url) => request("/api/recon/live-hosts/start", { method: "POST", body: JSON.stringify({ scope_id: scopeId, target_url }) }),
    liveHostScan: (scanId) => request(`/api/recon/live-hosts/${encodeURIComponent(scanId)}`),
    cancelLiveHosts: (scanId) => request(`/api/recon/live-hosts/${encodeURIComponent(scanId)}/cancel`, { method: "POST" }),
    historicalUrls: (scopeId) => request(scoped("/api/recon/urls", scopeId)),
    startHistoricalUrls: (scopeId) => request("/api/recon/urls/start", { method: "POST", body: JSON.stringify({ scope_id: scopeId }) }),
    urlScan: (scanId) => request(`/api/recon/urls/${encodeURIComponent(scanId)}`),
    cancelUrlScan: (scanId) => request(`/api/recon/urls/${encodeURIComponent(scanId)}/cancel`, { method: "POST" }),
    endpoints: (scopeId) => request(scoped("/api/recon/endpoints", scopeId)),
    startEndpoints: (scopeId, targetHost, approval) => request("/api/recon/endpoints/start", { method: "POST", body: JSON.stringify({ scope_id: scopeId, target_host: targetHost, approval_confirmed: approval }) }),
    endpointScan: (scanId) => request(`/api/recon/endpoints/${encodeURIComponent(scanId)}`),
    cancelEndpoints: (scanId) => request(`/api/recon/endpoints/${encodeURIComponent(scanId)}/cancel`, { method: "POST" }),
    parameters: (scopeId) => request(scoped("/api/recon/parameters", scopeId)),
    technologies: (scopeId) => request(scoped("/api/recon/technologies", scopeId)),
    startTechnologies: (scopeId) => request("/api/recon/technologies/start", { method: "POST", body: JSON.stringify({ scope_id: scopeId }) }),
    technologyScan: (scanId) => request(`/api/recon/technologies/${encodeURIComponent(scanId)}`),
    cancelTechnologies: (scanId) => request(`/api/recon/technologies/${encodeURIComponent(scanId)}/cancel`, { method: "POST" }),
    reconJobs: (scopeId) => request(scoped("/api/recon/scans", scopeId)),
    startRecon: (scopeId, approval) => request("/api/recon/start", { method: "POST", body: JSON.stringify({ scope_id: scopeId, active_crawl_approved: approval }) }),
    reconJob: (jobId) => request(`/api/recon/scans/${encodeURIComponent(jobId)}`),
    cancelRecon: (jobId) => request(`/api/recon/scans/${encodeURIComponent(jobId)}/cancel`, { method: "POST" }),
  };
})();
