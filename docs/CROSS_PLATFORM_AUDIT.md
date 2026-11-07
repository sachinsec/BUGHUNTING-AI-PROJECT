# Cross-platform architecture audit

## Findings before the changes

- Scan mode was read from one global `SCAN_MODE`/`APP_ENV` configuration. Every non-production environment defaulted to mock; Linux development therefore also silently selected mock by default.
- ToolManager chose mock adapters from that mode. The UI surfaced simulated labels in some recon views, but Settings and Tool Management were placeholders, so operators could not inspect or change the mode there.
- A persisted scan mode did not record which runtime profile created it. Reusing a Windows SQLite database on Linux could retain that old mode.
- Tool discovery used PATH in adapters, but executable override configuration was only available for httpx. The environment checker omitted GAU, Waybackurls, and WhatWeb from its binary list.
- Authorization review validation existed but one duplicate function definition weakened the required reviewer/reference/time check.
- Local Lab validation allowed private-network hostnames and had no exact-port model, which was broader than a loopback-only lab boundary.
- This checkout contains no Kali tool binaries; real Linux process execution cannot be validated from Windows.

## Changes made

- Added explicit Windows development, Linux development, and Kali production profiles. Profile and scan mode are reported by `/api/system/info`; startup persists the profile alongside the selected mode and resets stale cross-profile mode state to the new profile default.
- Added REAL, MOCK, and LOCAL_LAB choices in Settings. Production Kali accepts REAL only. REAL detection/execution never falls back to mock.
- Centralized per-tool executable override variables, PATH detection, version checks, explicit detection states, and new system/tool status APIs. ProjectDiscovery httpx is version-checked to reject unrelated executables.
- Connected dashboard Settings and Tool Management to these APIs and added an always-visible MOCK warning.
- Local Lab scopes now require loopback hosts and exact configured ports; public and LAN destinations are rejected. Public scope scans still require a separate manual authorization review.
- Updated platform setup scripts and environment examples, and documented migration/testing boundaries.

## Verification boundary

The automated suite and syntax checks ran on Windows only. Kali setup, Linux adapter execution, local Ollama inference, and real security-tool integration remain unverified until run on Kali using the commands in `KALI_INSTALLATION.md`.
