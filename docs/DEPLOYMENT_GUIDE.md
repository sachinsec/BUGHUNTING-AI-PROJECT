# Deployment guide

The project uses portable Python. Paths use `pathlib`; SQLite's relative URL resolves from the project root. Settings load from environment variables or `.env`.

## Configuration

| Setting | Purpose |
| --- | --- |
| `APP_ENV` | Development defaults to mock mode; production defaults to real tool detection. |
| `APP_HOST`, `APP_PORT` | Server bind and port. Keep host at `127.0.0.1` until authentication is implemented. |
| `DATABASE_URL` | SQLite URL, default `sqlite:///./data/bughunter.db`. |
| `OLLAMA_BASE_URL`, `OLLAMA_MODEL` | Local Ollama API and model (`qwen3:4b`). |
| `AI_MAX_CONCURRENCY`, `AI_CONTEXT_LENGTH` | CPU/RAM controls; concurrency is at least one. |
| `SCAN_MODE` | Mock emits explicitly simulated samples; real detects/uses local binaries. |
| `SCAN_TIMEOUT` | Per-tool process timeout in seconds. |

## Deployment boundaries

This phase has scope registration and destination-validation primitives, not a complete scan lifecycle. Real adapters do not orchestrate every recon stage, parse findings, persist evidence, or enforce program-specific rate policies across processes. Keep scans disabled until those later phases land. Nuclei invocation requires an explicit approval argument; no scan execution endpoint is exposed.

Do not expose this unauthenticated app publicly. Use localhost or add authentication and reverse-proxy protections first. Do not put credentials in target URLs. Back up SQLite only after stopping the app or using SQLite's online backup API.

## Migration

Follow [Kali installation](./KALI_INSTALLATION.md). Recreate `.venv` on Kali; virtual environments are not portable across operating systems. Treat Windows mock outputs as samples and never import them as discovered assets or findings.
