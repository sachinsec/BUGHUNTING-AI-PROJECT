import time
import re

from app.config import SCAN_TIMEOUT, TOOL_EXECUTABLES
from app.core.scope_manager import validate_domain_in_scope, validate_real_network_access
from app.core.runtime_settings import get_scan_mode


class ToolUnavailable(RuntimeError):
    pass


def _run_bounded_process(argv: list[str], timeout: int, cancel_event=None, input_data: str | None = None) -> dict:
    """Run a fixed argv with timeout/cancellation and never include stderr in returned data."""
    import subprocess

    started = time.monotonic()
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
            return {"cancelled": True, "returncode": process.returncode, "stdout": "", "stderr": "",
                    "duration_seconds": round(time.monotonic() - started, 3)}
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            process.kill()
            process.communicate()
            return {"timed_out": True, "returncode": process.returncode, "stdout": "", "stderr": "",
                    "duration_seconds": round(time.monotonic() - started, 3)}
        try:
            stdout, stderr = process.communicate(input=input_data if first_communicate else None,
                                                   timeout=min(0.2, remaining))
            return {"returncode": process.returncode, "stdout": stdout[:5_000_000],
                    "stderr": stderr[:100_000], "duration_seconds": round(time.monotonic() - started, 3)}
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
        return {"name": self.name, "available": True, "status": "MOCK", "mode": "mock", "simulated": True,
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
            return {"name": self.name, "available": False, "status": "NOT_INSTALLED", "mode": "real", "version": None,
                    "install_hint": f"Install {self.name} using the Kali tool installation guide."}
        try:
            version_argv = self.version_arguments()
            version_argv[0] = binary
            result = subprocess.run(version_argv, capture_output=True, text=True,
                                    timeout=min(self.timeout, 10), check=False)
            version = (result.stdout or result.stderr).strip().splitlines()[0][:200]
        except (OSError, subprocess.TimeoutExpired, IndexError):
            version = None
        return {"name": self.name, "available": bool(version), "status": "INSTALLED" if version else "ERROR",
                "mode": "real", "version": version, "path": binary,
                "error": None if version else "Binary found but version check failed"}

    def run(self, target: str, scope, cancel_event=None) -> dict:
        import shutil

        accepted = validate_real_network_access(scope, target, resolve=True,
                                                allow_local_lab=self.name not in {"Subfinder", "Amass", "GAU", "Waybackurls"})
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
        super().__init__(TOOL_EXECUTABLES["subfinder"], "Subfinder")

    def arguments(self, target: str) -> list[str]:
        return [self.executable, "-d", target, "-json", "-silent", "-rl", "2",
                "-timeout", "15", "-max-time", "5", "-max-results", "1000", "-duc"]

    def version_arguments(self) -> list[str]:
        return [self.executable, "-version"]

    def run(self, target: str, scope, cancel_event=None) -> dict:
        """Run passive enumeration with bounded time, low request rate, and cooperative cancellation."""
        import shutil
        import subprocess

        accepted = validate_real_network_access(scope, target, resolve=True, allow_local_lab=False)
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
        started = time.monotonic()
        self._last_execution = started
        deadline = started + self.timeout
        while True:
            if cancel_event is not None and cancel_event.is_set():
                process.terminate()
                try:
                    process.communicate(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate()
                return {"tool": self.name, "target": accepted, "mode": "real", "simulated": False,
                        "cancelled": True, "returncode": process.returncode, "stdout": "", "stderr": "",
                        "duration_seconds": round(time.monotonic() - started, 3)}
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                process.kill()
                process.communicate()
                return {"tool": self.name, "target": accepted, "mode": "real", "simulated": False,
                        "timed_out": True, "returncode": process.returncode, "stdout": "", "stderr": "",
                        "duration_seconds": round(time.monotonic() - started, 3)}
            try:
                stdout, stderr = process.communicate(timeout=min(0.2, remaining))
                return {"tool": self.name, "target": accepted, "mode": "real", "simulated": False,
                        "returncode": process.returncode, "stdout": stdout[:5_000_000], "stderr": stderr[:100_000],
                        "duration_seconds": round(time.monotonic() - started, 3)}
            except subprocess.TimeoutExpired:
                continue


class AmassAdapter(SubprocessToolAdapter):
    def __init__(self):
        super().__init__(TOOL_EXECUTABLES["amass"], "Amass")

    def arguments(self, target: str) -> list[str]:
        return [self.executable, "enum", "-passive", "-d", target]

    def version_arguments(self) -> list[str]:
        return [self.executable, "-version"]


class HttpxAdapter(SubprocessToolAdapter):
    def __init__(self):
        super().__init__(TOOL_EXECUTABLES["httpx"], "ProjectDiscovery httpx")
        self._resolved_path = None

    def arguments(self, target: str) -> list[str]:
        return [self.executable, "-u", target, "-json", "-silent", "-rl", "2"]

    def detect(self) -> dict:
        import shutil
        import subprocess
        import os

        configured = self.executable
        candidate = configured
        if not candidate:
            return {"name": self.name, "available": False, "status": "NOT_INSTALLED", "mode": "real",
                    "version": None, "error": "HTTPX_EXECUTABLE is empty.",
                    "install_hint": "Set HTTPX_EXECUTABLE to the ProjectDiscovery executable name or full path, for example httpx-toolkit."}
        binary = shutil.which(candidate)
        basename = configured.replace("\\", "/").rsplit("/", 1)[-1].casefold()
        if not binary and basename in {"httpx-toolkit", "httpx-toolkit.exe"}:
            # The fallback is accepted only after ProjectDiscovery's own banner is verified below.
            candidate = "httpx"
            binary = shutil.which(candidate)
        if not binary:
            return {"name": self.name, "available": False, "status": "NOT_INSTALLED", "mode": "real",
                    "version": None, "command": configured,
                    "error": f"Configured HTTPX executable '{configured}' was not found on PATH.",
                    "install_hint": f"Install ProjectDiscovery httpx or set HTTPX_EXECUTABLE to its executable name or full path (current: {configured})."}
        try:
            result = subprocess.run([binary, "-version"], capture_output=True, text=True,
                                    timeout=min(self.timeout, 10), check=False, shell=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {"name": self.name, "available": False, "status": "ERROR", "mode": "real",
                    "version": None, "path": binary, "command": candidate,
                    "error": f"Configured executable could not be verified: {type(exc).__name__}.",
                    "install_hint": "Check HTTPX_EXECUTABLE and confirm the binary can run with -version."}
        banner = f"{result.stdout or ''}\n{result.stderr or ''}"
        version_match = re.search(
            r"(?:current\s+)?(?:httpx\s+)?version\s*:?\s*(?P<version>v?\d+\.\d+(?:\.\d+)?(?:[-\w.]*)?)",
            banner, re.I,
        )
        is_projectdiscovery = "projectdiscovery.io" in banner.lower() or "github.com/projectdiscovery/httpx" in banner.lower()
        if result.returncode != 0 or not version_match or not is_projectdiscovery:
            return {"name": self.name, "available": False, "status": "ERROR", "mode": "real",
                    "version": None, "path": binary, "command": candidate, "executable_name": os.path.basename(binary),
                    "error": "The configured binary did not identify itself as ProjectDiscovery httpx.",
                    "install_hint": "Set HTTPX_EXECUTABLE to the verified ProjectDiscovery httpx/httpx-toolkit binary; unrelated tools named httpx are rejected."}
        self._resolved_path = binary
        self.executable = candidate
        version = version_match.group("version")
        return {"name": self.name, "available": True, "status": "INSTALLED", "mode": "real",
                "version": version, "path": binary, "command": candidate, "executable_name": os.path.basename(binary)}

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
            accepted = validate_real_network_access(scope, target, resolve=False)
            from urllib.parse import urlsplit
            parsed = urlsplit(accepted if "://" in accepted else "https://" + accepted)
            hostname = parsed.hostname
            if not hostname:
                raise ValueError("Authorized HTTP target is malformed")
            try:
                addresses = {ipaddress.ip_address(item[4][0]) for item in socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)}
            except (OSError, ValueError) as exc:
                raise ValueError("An authorized host could not be safely resolved") from exc
            if scope.local_lab_mode:
                if not addresses or any(not address.is_loopback for address in addresses):
                    raise ValueError("Local Lab targets must resolve exclusively to loopback addresses")
            elif not addresses or any(not address.is_global for address in addresses):
                raise ValueError("A destination resolved to a private or reserved address")
            for address in sorted(addresses, key=lambda item: (item.version, int(item))):
                target_url = accepted if "://" in accepted else f"https://{hostname}"
                inputs.append(json.dumps({"target": target_url, "ip": str(address)}))
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
        started = time.monotonic()
        deadline = started + self.timeout
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
                return {"cancelled": True, "returncode": process.returncode, "stdout": "", "stderr": "",
                        "duration_seconds": round(time.monotonic() - started, 3),
                        "mode": "real", "simulated": False}
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                process.kill()
                process.communicate()
                return {"timed_out": True, "returncode": process.returncode, "stdout": "", "stderr": "",
                        "duration_seconds": round(time.monotonic() - started, 3),
                        "mode": "real", "simulated": False}
            try:
                stdout, stderr = process.communicate(input=input_data if first_communicate else None,
                                                      timeout=min(0.2, remaining))
                return {"returncode": process.returncode, "stdout": stdout[:5_000_000],
                        "stderr": stderr[:100_000], "duration_seconds": round(time.monotonic() - started, 3),
                        "mode": "real", "simulated": False}
            except subprocess.TimeoutExpired:
                first_communicate = False


class KatanaAdapter(SubprocessToolAdapter):
    def __init__(self):
        super().__init__(TOOL_EXECUTABLES["katana"], "Katana")

    def arguments(self, target: str) -> list[str]:
        from urllib.parse import urlsplit
        hostname = urlsplit(target if "://" in target else "https://" + target).hostname or target
        host_scope = rf"^https?://{re.escape(hostname)}(?::\d+)?(?:/|$)"
        args = [self.executable, "-u", "https://" + target, "-jsonl", "-silent", "-omit-raw", "-omit-body",
                "-fs", "fqdn", "-cs", host_scope, "-dr", "-d", "2", "-ct", "2m", "-timeout", "10",
                "-retry", "1", "-c", "1", "-p", "1", "-rl", "2", "-duc"]
        if not getattr(self, "_local_lab_execution", False):
            args.extend(["-exclude", "private-ips"])
        return args

    def version_arguments(self) -> list[str]:
        return [self.executable, "-version"]

    def run(self, target: str, scope, approval_confirmed: bool = False, cancel_event=None) -> dict:
        if not approval_confirmed:
            raise PermissionError("Katana crawling requires explicit human approval")
        self._local_lab_execution = bool(scope.local_lab_mode)
        try:
            return super().run(target, scope, cancel_event=cancel_event)
        finally:
            self._local_lab_execution = False


class NucleiAdapter(SubprocessToolAdapter):
    def __init__(self):
        super().__init__(TOOL_EXECUTABLES["nuclei"], "Nuclei")

    def run(self, target: str, scope, active_approved: bool = False) -> dict:
        if not active_approved:
            raise PermissionError("Nuclei execution requires explicit human approval")
        return super().run(target, scope)

    def arguments(self, target: str) -> list[str]:
        return [self.executable, "-u", "https://" + target, "-jsonl", "-rl", "2",
                "-dr", "-severity", "info,low,medium,high,critical"]

    def version_arguments(self) -> list[str]:
        return [self.executable, "-version"]


class ZAPAdapter(SubprocessToolAdapter):
    def __init__(self):
        super().__init__(TOOL_EXECUTABLES["zap"], "OWASP ZAP")

    def run(self, target: str, scope) -> dict:
        raise NotImplementedError("ZAP execution requires a dedicated API client and approval flow")


class GauAdapter(SubprocessToolAdapter):
    def __init__(self):
        super().__init__(TOOL_EXECUTABLES["gau"], "GAU")

    def arguments(self, target: str) -> list[str]:
        return [self.executable, "--subs", "--threads", "2", "--timeout", "20", "--retries", "1", target]


class WaybackurlsAdapter(SubprocessToolAdapter):
    def __init__(self):
        super().__init__(TOOL_EXECUTABLES["waybackurls"], "Waybackurls")

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
        super().__init__(TOOL_EXECUTABLES["whatweb"], "WhatWeb")

    def arguments(self, target: str) -> list[str]:
        return [self.executable, "--aggression=1", "--max-threads=1", "--follow-redirect=never",
                "--open-timeout=10", "--read-timeout=10", "--no-errors", "https://" + target]

    def run(self, target: str, scope, cancel_event=None) -> dict:
        import shutil
        import tempfile
        from pathlib import Path

        accepted = validate_real_network_access(scope, target, resolve=True)
        binary = shutil.which(self.executable)
        if not binary:
            raise ToolUnavailable("WhatWeb is not installed")
        delay = self.min_interval - (time.monotonic() - self._last_execution)
        if delay > 0:
            time.sleep(delay)
        self._last_execution = time.monotonic()
        with tempfile.TemporaryDirectory(prefix="bughunter-whatweb-") as temp_dir:
            output_file = Path(temp_dir) / "whatweb.json"
            scheme = "http" if scope.local_lab_mode else "https"
            argv = [binary, "--aggression=1", "--max-threads=1", "--follow-redirect=never",
                    "--open-timeout=10", "--read-timeout=10", "--no-errors",
                    f"--log-json={output_file}", f"{scheme}://{accepted}"]
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
    def __init__(self, mode: str | None = None):
        self.mode = mode or get_scan_mode()
        self.adapters = {name: (MockToolAdapter(name) if self.mode == "mock" else adapter())
                         for name, adapter in REAL_ADAPTERS.items()}

    def availability(self) -> list[dict]:
        if self.mode not in {"mock", "real", "local_lab"}:
            return [{"name": "scanner", "available": False, "mode": self.mode,
                     "status": "ERROR", "message": "Select MOCK, REAL, or LOCAL_LAB execution mode."}]
        availability = [adapter.detect() for adapter in self.adapters.values()]
        if self.mode == "mock":
            availability.append({"name": "scanner", "available": True, "mode": "mock",
                                 "simulated": True, "notice": "All mock results are simulated."})
        return availability
