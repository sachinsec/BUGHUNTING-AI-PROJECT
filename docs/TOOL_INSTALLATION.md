# Optional security tool installation

Core development does not require Kali tools. On Kali, inspect package availability and prefer maintained distro packages when available:

```bash
apt-cache search '^(subfinder|amass|httpx|katana|nuclei|zaproxy)$'
apt-cache policy subfinder amass httpx katana nuclei zaproxy
```

Install only intended tools using Kali packages or upstream release instructions. ProjectDiscovery tools can share names with unrelated software; verify `command -v httpx` and `httpx -version` identify ProjectDiscovery httpx. `whatweb`, `gau`, and `waybackurls` are not yet wired into this adapter registry.

The app detects `subfinder`, `amass`, `httpx`, `katana`, `nuclei`, `zaproxy`, `gau`, `waybackurls`, and `whatweb`. Missing tools are optional. Adapters use argument arrays, timeouts, no shell, scope checks, and conservative invocation spacing; selected commands also request 2 requests/second. Never run active checks without program permission. Setup scripts do not launch scans.

Ollama instructions are in [Kali installation](./KALI_INSTALLATION.md). The official Linux installer command is `curl -fsSL https://ollama.com/install.sh | sh`; review upstream guidance before running it.
