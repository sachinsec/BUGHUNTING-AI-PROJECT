import time

from app.config import SCAN_MODE, SCAN_TIMEOUT
from app.core.scope_manager import validate_domain_in_scope


class ToolUnavailable(RuntimeError):
    pass


class ToolAdapter:
    name = "tool"
    executable = ""

    def __init__(self, timeout: int = SCAN_TIMEOUT):
        self.timeout = timeout

    def detect(self) -> dict:
        raise NotImplementedError

    def run(self, target: str, scope) -> dict:
        raise NotImplementedError


class MockToolAdapter(ToolAdapter):
    """Development adapter; all returned payloads carry simulation metadata."""
    def __init__(self, name: str):
        super().__init__()
        self.name = name

    def detect(self) -> dict:
        return {"name": self.name, "available": True, "mode": "mock", "simulated": True,
                "version": "mock-adapter"}

    def run(self, target: str, scope) -> dict:
        accepted = validate_domain_in_scope(target, scope, resolve=False)
        return {"tool": self.name, "target": accepted, "mode": "mock", "simulated": True,
                "results": [{"kind": "sample_asset", "value": "mock." + accepted, "simulated": True}],
                "message": "Sample JSON only; no network requests were made and this is not a discovered asset."}


class SubprocessToolAdapter(ToolAdapter):
    """Safe generic adapter. Subclasses supply fixed argument construction; no shell is used."""
    def __init__(self, executable: str, name: str, timeout: int = SCAN_TIMEOUT, min_interval: float = 1.0):
        super().__init__(timeout)
        self.executable = executable
        self.name = name
        self.min_interval = min_interval
        self._last_execution = 0.0

    def arguments(self, target: str) -> list[str]:
        return [self.executable, target]

    def version_arguments(self) -> list[str]:
        return [self.executable, "--version"]

    def stdin_input(self, target: str) -> str | None:
        return None

    def detect(self) -> dict:
        import shutil
        import subprocess

        binary = shutil.which(self.executable)
        if not binary:
            return {"name": self.name, "available": False, "mode": "real", "version": None,
                    "install_hint": f"Install {self.name} using the Kali tool installation guide."}
        try:
            version_argv = self.version_arguments()
            version_argv[0] = binary
            result = subprocess.run(version_argv, capture_output=True, text=True,
                                    timeout=min(self.timeout, 10), check=False)
            version = (result.stdout or result.stderr).strip().splitlines()[0][:200]
        except (OSError, subprocess.TimeoutExpired):
            version = "version unavailable"
        return {"name": self.name, "available": True, "mode": "real", "version": version, "path": binary}

    def run(self, target: str, scope) -> dict:
        import subprocess
        import shutil

        accepted = validate_domain_in_scope(target, scope, resolve=True)
        binary = shutil.which(self.executable)
        if not binary:
            raise ToolUnavailable(f"{self.name} is not installed")
        argv = self.arguments(accepted)
        argv[0] = binary
        delay = self.min_interval - (time.monotonic() - self._last_execution)
        if delay > 0:
            time.sleep(delay)
        self._last_execution = time.monotonic()
        try:
            completed = subprocess.run(argv, capture_output=True, text=True, timeout=self.timeout,
                                       check=False, shell=False, input=self.stdin_input(accepted))
        except subprocess.TimeoutExpired as exc:
            return {"tool": self.name, "target": accepted, "mode": "real", "simulated": False,
                    "returncode": None, "stdout": exc.stdout or "", "stderr": "Tool execution timed out."}
        return {"tool": self.name, "target": accepted, "mode": "real", "simulated": False,
                "returncode": completed.returncode, "stdout": completed.stdout, "stderr": completed.stderr}


class SubfinderAdapter(SubprocessToolAdapter):
    def __init__(self):
        super().__init__("subfinder", "Subfinder")

    def arguments(self, target: str) -> list[str]:
        return [self.executable, "-d", target, "-silent"]

    def version_arguments(self) -> list[str]:
        return [self.executable, "-version"]


class AmassAdapter(SubprocessToolAdapter):
    def __init__(self):
        super().__init__("amass", "Amass")

    def arguments(self, target: str) -> list[str]:
        return [self.executable, "enum", "-passive", "-d", target]

    def version_arguments(self) -> list[str]:
        return [self.executable, "-version"]


class HttpxAdapter(SubprocessToolAdapter):
    def __init__(self):
        super().__init__("httpx", "ProjectDiscovery httpx")

    def arguments(self, target: str) -> list[str]:
        return [self.executable, "-u", target, "-json", "-silent", "-rl", "2"]

    def version_arguments(self) -> list[str]:
        return [self.executable, "-version"]


class KatanaAdapter(SubprocessToolAdapter):
    def __init__(self):
        super().__init__("katana", "Katana")

    def arguments(self, target: str) -> list[str]:
        return [self.executable, "-u", "https://" + target, "-jsonl", "-silent", "-rl", "2"]

    def version_arguments(self) -> list[str]:
        return [self.executable, "-version"]


class NucleiAdapter(SubprocessToolAdapter):
    def __init__(self):
        super().__init__("nuclei", "Nuclei")

    def run(self, target: str, scope, active_approved: bool = False) -> dict:
        if not active_approved:
            raise PermissionError("Nuclei execution requires explicit human approval")
        return super().run(target, scope)

    def arguments(self, target: str) -> list[str]:
        return [self.executable, "-u", "https://" + target, "-jsonl", "-rl", "2",
                "-severity", "info,low,medium,high,critical"]

    def version_arguments(self) -> list[str]:
        return [self.executable, "-version"]


class ZAPAdapter(SubprocessToolAdapter):
    def __init__(self):
        super().__init__("zaproxy", "OWASP ZAP")

    def run(self, target: str, scope) -> dict:
        raise NotImplementedError("ZAP execution requires a dedicated API client and approval flow")


class GauAdapter(SubprocessToolAdapter):
    def __init__(self):
        super().__init__("gau", "GAU")

    def arguments(self, target: str) -> list[str]:
        return [self.executable, "--subs", target]


class WaybackurlsAdapter(SubprocessToolAdapter):
    def __init__(self):
        super().__init__("waybackurls", "Waybackurls")

    def arguments(self, target: str) -> list[str]:
        return [self.executable]

    def stdin_input(self, target: str) -> str:
        return target + "\n"


class WhatWebAdapter(SubprocessToolAdapter):
    def __init__(self):
        super().__init__("whatweb", "WhatWeb")

    def arguments(self, target: str) -> list[str]:
        return [self.executable, "--log-json=-", "https://" + target]


class GenericToolAdapter(SubprocessToolAdapter):
    pass


REAL_ADAPTERS = {"subfinder": SubfinderAdapter, "amass": AmassAdapter, "httpx": HttpxAdapter,
                 "katana": KatanaAdapter, "nuclei": NucleiAdapter, "zap": ZAPAdapter,
                 "gau": GauAdapter, "waybackurls": WaybackurlsAdapter, "whatweb": WhatWebAdapter}


class ToolManager:
    def __init__(self, mode: str = SCAN_MODE):
        self.mode = mode
        self.adapters = {name: (MockToolAdapter(name) if mode == "mock" else adapter())
                         for name, adapter in REAL_ADAPTERS.items()}

    def availability(self) -> list[dict]:
        if self.mode not in {"mock", "real"}:
            return [{"name": "scanner", "available": False, "mode": self.mode,
                     "message": "Set SCAN_MODE=mock or SCAN_MODE=real."}]
        availability = [adapter.detect() for adapter in self.adapters.values()]
        if self.mode == "mock":
            availability.append({"name": "scanner", "available": True, "mode": "mock",
                                 "simulated": True, "notice": "All mock results are simulated."})
        return availability
