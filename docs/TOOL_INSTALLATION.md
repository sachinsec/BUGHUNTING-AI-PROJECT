# Optional security tool installation

Core development does not require Kali tools. On Kali, inspect package availability and prefer maintained distro packages when available:

```bash
apt-cache search '^(subfinder|amass|httpx|katana|nuclei|zaproxy)$'
apt-cache policy subfinder amass httpx katana nuclei zaproxy
```

Install only intended tools using Kali packages or upstream release instructions. If your package exposes the ProjectDiscovery scanner as `httpx-toolkit`, the app prefers that command. Set `HTTPX_EXECUTABLE` in `.env` to override command selection. The adapter validates the reported version and rejects unrelated Python `httpx` commands. `whatweb`, `gau`, and `waybackurls` are wired into the reconnaissance adapter registry.

The app detects `subfinder`, `amass`, `httpx-toolkit` or verified ProjectDiscovery `httpx`, `katana`, `nuclei`, `zaproxy`, `gau`, `waybackurls`, and `whatweb`. Missing tools are optional. Adapters use argument arrays, timeouts, no shell, scope checks, and conservative invocation spacing; selected commands also request 2 requests/second. Never run active checks without program permission. Setup scripts do not launch scans.

Ollama instructions are in [Kali installation](./KALI_INSTALLATION.md). The official Linux installer command is `curl -fsSL https://ollama.com/install.sh | sh`; review upstream guidance before running it.
