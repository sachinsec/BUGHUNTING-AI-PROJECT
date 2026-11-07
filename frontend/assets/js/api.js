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

  window.BugHunterApi = {
    health: () => request("/api/health"),
    scopes: () => request("/api/scopes"),
    createScope: (data) => request("/api/scopes", { method: "POST", body: JSON.stringify(data) }),
    deleteScope: (id) => request(`/api/scopes/${encodeURIComponent(id)}`, { method: "DELETE" }),
  };
})();
