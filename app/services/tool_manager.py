import time
import re

from app.config import HTTPX_EXECUTABLE, SCAN_MODE, SCAN_TIMEOUT
from app.core.scope_manager import validate_domain_in_scope


class ToolUnavailable(RuntimeError):
    pass


def _run_bounded_process(argv: list[str], timeout: int, cancel_event=None, input_data: str | None = None) -> dict:
    """Run a fixed argv with timeout/cancellation and never include stderr in returned data."""
    import subprocess

    try:
        process = subprocess.Popen(argv, stdin=subprocess.PIPE if input_data is not None else None,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=False)
    except OSError as exc:
        raise ToolUnavailable("Security tool could not be started") from exc
    deadline = time.monotonic() + timeout
    first_communicate = True
    while True:
        if cancel_event is not None and cancel_event.is_set():
            process.terminate()
            try:
                process.communicate(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()
            return {"cancelled": True, "returncode": process.returncode, "stdout": ""}
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            process.kill()
            process.communicate()
            return {"timed_out": True, "returncode": process.returncode, "stdout": ""}
        try:
            stdout, _stderr = process.communicate(input=input_data if first_communicate else None,
                                                   timeout=min(0.2, remaining))
            return {"returncode": process.returncode, "stdout": stdout[:5_000_000]}
        except subprocess.TimeoutExpired:
            first_communicate = False


class ToolAdapter:
    name = "tool"
    executable = ""

    def __init__(self, timeout: int = SCAN_TIMEOUT):
        self.timeout = timeout

    def detect(self) -> dict:
        raise NotImplementedError

    def run(self, target: str, scope, cancel_event=None) -> dict:
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
        except (OSError, subprocess.TimeoutExpired, IndexError):
            version = "version unavailable"
        return {"name": self.name, "available": True, "mode": "real", "version": version, "path": binary}

    def run(self, target: str, scope, cancel_event=None) -> dict:
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
        result = _run_bounded_process(argv, self.timeout, cancel_event, self.stdin_input(accepted))
        return result | {"tool": self.name, "target": accepted, "mode": "real", "simulated": False}


class SubfinderAdapter(SubprocessToolAdapter):
    def __init__(self):
        super().__init__("subfinder", "Subfinder")

    def arguments(self, target: str) -> list[str]:
        return [self.executable, "-d", target, "-json", "-silent", "-rl", "2",
                "-timeout", "15", "-max-time", "5", "-max-results", "1000", "-duc"]

    def version_arguments(self) -> list[str]:
        return [self.executable, "-version"]

    def run(self, target: str, scope, cancel_event=None) -> dict:
        """Run passive enumeration with bounded time, low request rate, and cooperative cancellation."""
        import shutil
        import subprocess

        accepted = validate_domain_in_scope(target, scope, resolve=True)
        binary = shutil.which(self.executable)
        if not binary:
            raise ToolUnavailable("Subfinder is not installed")
        delay = self.min_interval - (time.monotonic() - self._last_execution)
        if delay > 0:
            time.sleep(delay)
        argv = self.arguments(accepted)
        argv[0] = binary
        try:
            process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       text=True, shell=False)
        except OSError as exc:
            raise ToolUnavailable("Subfinder could not be started") from exc
        self._last_execution = time.monotonic()
        deadline = self._last_execution + self.timeout
        while True:
            if cancel_event is not None and cancel_event.is_set():
                process.terminate()
                try:
                    process.communicate(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate()
                return {"tool": self.name, "target": accepted, "mode": "real", "simulated": False,
                        "cancelled": True, "returncode": process.returncode, "stdout": ""}
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                process.kill()
                process.communicate()
                return {"tool": self.name, "target": accepted, "mode": "real", "simulated": False,
                        "timed_out": True, "returncode": process.returncode, "stdout": ""}
            try:
                stdout, _stderr = process.communicate(timeout=min(0.2, remaining))
                return {"tool": self.name, "target": accepted, "mode": "real", "simulated": False,
                        "returncode": process.returncode, "stdout": stdout[:5_000_000]}
            except subprocess.TimeoutExpired:
                continue


class AmassAdapter(SubprocessToolAdapter):
    def __init__(self):
        super().__init__("amass", "Amass")

    def arguments(self, target: str) -> list[str]:
        return [self.executable, "enum", "-passive", "-d", target]

    def version_arguments(self) -> list[str]:
        return [self.executable, "-version"]


class HttpxAdapter(SubprocessToolAdapter):
    def __init__(self):
        super().__init__(HTTPX_EXECUTABLE or "httpx-toolkit", "ProjectDiscovery httpx")
        self._resolved_path = None

    def arguments(self, target: str) -> list[str]:
        return [self.executable, "-u", target, "-json", "-silent", "-rl", "2"]

    def detect(self) -> dict:
        import shutil
        import subprocess

        candidates = list(dict.fromkeys([HTTPX_EXECUTABLE, "httpx-toolkit", "httpx"]))
        for candidate in candidates:
            if not candidate:
                continue
            binary = shutil.which(candidate)
            if not binary:
                continue
            try:
                result = subprocess.run([binary, "-version"], capture_output=True, text=True,
                                        timeout=min(self.timeout, 10), check=False, shell=False)
                version = (result.stdout or result.stderr).strip().splitlines()[0][:200]
            except (OSError, subprocess.TimeoutExpired, IndexError):
                continue
            if re.search(r"\bhttpx(?:\s+version)?\s+v?\d+\.\d+", version, re.I):
                self.executable = candidate
                self._resolved_path = binary
                return {"name": self.name, "available": True, "mode": "real", "version": version, "path": binary,
                        "command": candidate}
        return {"name": self.name, "available": False, "mode": "real", "version": None,
                "install_hint": f"ProjectDiscovery httpx was not detected. Configure HTTPX_EXECUTABLE (currently {HTTPX_EXECUTABLE or 'auto'}) to httpx-toolkit or the ProjectDiscovery httpx binary."}

    def version_arguments(self) -> list[str]:
        return [self.executable, "-version"]

    def run_many(self, targets: list[str], scope, cancel_event=None) -> dict:
        """Probe approved targets against pre-resolved public IPs; do not follow redirects."""
        import ipaddress
        import json
        import shutil
        import socket
        import subprocess

        inputs = []
        for target in dict.fromkeys(targets):
            hostname = validate_domain_in_scope(target, scope, resolve=False)
            try:
                addresses = {ipaddress.ip_address(item[4][0]) for item in socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)}
            except (OSError, ValueError) as exc:
                raise ValueError("An authorized host could not be safely resolved") from exc
            if not addresses or any(not address.is_global for address in addresses):
                raise ValueError("A destination resolved to a private or reserved address")
            for address in sorted(addresses, key=lambda item: (item.version, int(item))):
                inputs.append(json.dumps({"target": f"https://{hostname}", "ip": str(address)}))
        if not inputs:
            return {"returncode": 0, "stdout": "", "mode": "real", "simulated": False}
        detected = self.detect()
        if not detected.get("available"):
            raise ToolUnavailable("ProjectDiscovery httpx is not installed or could not be verified")
        binary = detected.get("path") or self._resolved_path or shutil.which(self.executable)
        if not binary:
            raise ToolUnavailable("ProjectDiscovery httpx is not installed")
        argv = [binary, "-l", "-", "-j", "-silent", "-sc", "-title", "-ct", "-rl", "2",
                "-timeout", "10", "-retries", "1", "-duc"]
        if cancel_event is not None and cancel_event.is_set():
            return {"cancelled": True, "returncode": None, "stdout": "", "mode": "real", "simulated": False}
        try:
            process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       text=True, shell=False)
        except OSError as exc:
            raise ToolUnavailable("ProjectDiscovery httpx could not be started") from exc
        deadline = time.monotonic() + self.timeout
        input_data = "\n".join(inputs) + "\n"
        first_communicate = True
        while True:
            if cancel_event is not None and cancel_event.is_set():
                process.terminate()
                try:
                    process.communicate(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate()
                return {"cancelled": True, "returncode": process.returncode, "stdout": "",
                        "mode": "real", "simulated": False}
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                process.kill()
                process.communicate()
                return {"timed_out": True, "returncode": process.returncode, "stdout": "",
                        "mode": "real", "simulated": False}
            try:
                stdout, _stderr = process.communicate(input=input_data if first_communicate else None,
                                                      timeout=min(0.2, remaining))
                return {"returncode": process.returncode, "stdout": stdout[:5_000_000],
                        "mode": "real", "simulated": False}
            except subprocess.TimeoutExpired:
                first_communicate = False


class KatanaAdapter(SubprocessToolAdapter):
    def __init__(self):
        super().__init__("katana", "Katana")

    def arguments(self, target: str) -> list[str]:
        return [self.executable, "-u", "https://" + target, "-jsonl", "-silent", "-omit-raw", "-omit-body",
                "-fs", "fqdn", "-exclude", "private-ips", "-d", "2", "-ct", "2m", "-timeout", "10",
                "-retry", "1", "-c", "1", "-p", "1", "-rl", "2", "-duc"]

    def version_arguments(self) -> list[str]:
        return [self.executable, "-version"]

    def run(self, target: str, scope, approval_confirmed: bool = False, cancel_event=None) -> dict:
        if not approval_confirmed:
            raise PermissionError("Katana crawling requires explicit human approval")
        return super().run(target, scope, cancel_event=cancel_event)


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
        return [self.executable, "--subs", "--threads", "2", "--timeout", "20", "--retries", "1", target]


class WaybackurlsAdapter(SubprocessToolAdapter):
    def __init__(self):
        super().__init__("waybackurls", "Waybackurls")

    def arguments(self, target: str) -> list[str]:
        return [self.executable]

    def stdin_input(self, target: str) -> str:
        return target + "\n"

    def version_arguments(self) -> list[str]:
        return [self.executable, "-h"]

    def version_arguments(self) -> list[str]:
        return [self.executable, "-h"]


class WhatWebAdapter(SubprocessToolAdapter):
    def __init__(self):
        super().__init__("whatweb", "WhatWeb")

    def arguments(self, target: str) -> list[str]:
        return [self.executable, "--aggression=1", "--max-threads=1", "--follow-redirect=never",
                "--open-timeout=10", "--read-timeout=10", "--no-errors", "https://" + target]

    def run(self, target: str, scope, cancel_event=None) -> dict:
        import shutil
        import tempfile
        from pathlib import Path

        accepted = validate_domain_in_scope(target, scope, resolve=True)
        binary = shutil.which(self.executable)
        if not binary:
            raise ToolUnavailable("WhatWeb is not installed")
        delay = self.min_interval - (time.monotonic() - self._last_execution)
        if delay > 0:
            time.sleep(delay)
        self._last_execution = time.monotonic()
        with tempfile.TemporaryDirectory(prefix="bughunter-whatweb-") as temp_dir:
            output_file = Path(temp_dir) / "whatweb.json"
            argv = [binary, "--aggression=1", "--max-threads=1", "--follow-redirect=never",
                    "--open-timeout=10", "--read-timeout=10", "--no-errors",
                    f"--log-json={output_file}", "https://" + accepted]
            result = _run_bounded_process(argv, self.timeout, cancel_event)
            if result.get("returncode") == 0 and output_file.is_file():
                result["stdout"] = output_file.read_text(encoding="utf-8", errors="replace")[:5_000_000]
            return result | {"tool": self.name, "target": accepted, "mode": "real", "simulated": False}


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
