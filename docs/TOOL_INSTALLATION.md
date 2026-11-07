# Tool installation and detection

REAL mode calls `shutil.which()` and a bounded version check. Configure executable names in `.env` using `SUBFINDER_EXECUTABLE`, `AMASS_EXECUTABLE`, `HTTPX_EXECUTABLE`, `KATANA_EXECUTABLE`, `GAU_EXECUTABLE`, `WAYBACKURLS_EXECUTABLE`, `NUCLEI_EXECUTABLE`, `WHATWEB_EXECUTABLE`, and `ZAP_EXECUTABLE`. Add the tools to the FastAPI service user's PATH; do not put machine-specific absolute paths in source.

Tool Management and `GET /api/tools/status` report MOCK, INSTALLED, NOT_INSTALLED, or ERROR states plus path/version where detected. `POST /api/tools/check` only detects/version-checks and never launches a scan. Nuclei is detection-only pending a separate approval/template workflow. ZAP is detection-only; its dedicated API client is not implemented.

For httpx, the adapter requires ProjectDiscovery-style version output and ignores unrelated executables such as Python HTTPX CLI. Set `HTTPX_EXECUTABLE` to a suitable executable name when necessary. Follow tool vendors' installation instructions and verify downloaded binaries according to their guidance.
