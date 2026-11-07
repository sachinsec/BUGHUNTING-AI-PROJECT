# Deployment guide

The project shares a single FastAPI/SQLite codebase across these profiles:

| Profile | Purpose | Default mode | Mock allowed |
| --- | --- | --- | --- |
| `DEVELOPMENT_WINDOWS` | Windows development | MOCK | Yes, explicit and labeled |
| `DEVELOPMENT_LINUX` | Linux adapter development | REAL | Yes, explicit only |
| `PRODUCTION_KALI` | Kali runtime | REAL | No |

Use `.env.windows.example` or `.env.kali.example`. `APP_PROFILE` is validated. The active mode is persisted with the profile so a copied Windows database cannot silently carry MOCK into Kali. The Settings page persists operator mode changes.

Filesystem locations use `pathlib`; SQLite is configured by `DATABASE_URL`. Security binaries are resolved with `shutil.which()` and each has a configurable executable variable. Child processes use argument lists and `shell=False`, bounded timeouts and structured return information. The application does not invoke sudo.

Before production, follow [Kali installation](./KALI_INSTALLATION.md), inspect `/api/system/info` and `/api/tools/status`, and run tests on Kali. This workspace has only been tested on Windows; Linux/Kali compatibility and real Kali execution are not claimed yet. Real mode reports missing tools without mock substitution. Public targets require separate authorization review and scope/DNS validation. Local Lab is restricted to loopback and explicitly configured ports. Keep this unauthenticated service bound to localhost.
