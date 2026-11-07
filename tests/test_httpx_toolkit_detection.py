import os
from types import SimpleNamespace

from app.services import tool_manager
from app.services.tool_manager import HttpxAdapter


def _version_result(stdout, stderr="", returncode=0):
    return SimpleNamespace(stdout=stdout, stderr=stderr, returncode=returncode)


def test_httpx_toolkit_configured_executable_is_detected_and_version_captured(monkeypatch):
    monkeypatch.setitem(tool_manager.TOOL_EXECUTABLES, "httpx", "httpx-toolkit")
    calls = []
    monkeypatch.setattr("shutil.which", lambda command: calls.append(command) or "/usr/bin/httpx-toolkit")
    monkeypatch.setattr("subprocess.run", lambda *args, **kwargs: _version_result(
        "ProjectDiscovery banner\nprojectdiscovery.io\n[INF] Current Version: v1.7.1\n"))

    detected = HttpxAdapter().detect()
    assert calls == ["httpx-toolkit"]
    assert detected["available"] is True
    assert detected["version"] == "v1.7.1"
    assert detected["path"] == "/usr/bin/httpx-toolkit"
    assert detected["command"] == "httpx-toolkit"


def test_httpx_override_can_be_an_absolute_platform_path(monkeypatch, tmp_path):
    configured = str(tmp_path / ("httpx-toolkit.exe" if os.name == "nt" else "httpx-toolkit"))
    monkeypatch.setitem(tool_manager.TOOL_EXECUTABLES, "httpx", configured)
    calls = []
    monkeypatch.setattr("shutil.which", lambda command: calls.append(command) or configured)
    monkeypatch.setattr("subprocess.run", lambda *args, **kwargs: _version_result(
        "projectdiscovery.io\nCurrent Version: v1.6.10\n"))

    detected = HttpxAdapter().detect()
    assert calls == [configured]
    assert detected["available"] is True
    assert detected["path"] == configured
    assert detected["command"] == configured


def test_unrelated_httpx_binary_is_rejected_without_fallback(monkeypatch):
    monkeypatch.setitem(tool_manager.TOOL_EXECUTABLES, "httpx", "httpx")
    calls = []
    monkeypatch.setattr("shutil.which", lambda command: calls.append(command) or "/usr/bin/httpx")
    monkeypatch.setattr("subprocess.run", lambda *args, **kwargs: _version_result("httpx version 0.27.0\n"))

    detected = HttpxAdapter().detect()
    assert calls == ["httpx"]
    assert detected["available"] is False
    assert "did not identify itself" in detected["error"]


def test_missing_httpx_executable_has_configuration_guidance(monkeypatch):
    monkeypatch.setitem(tool_manager.TOOL_EXECUTABLES, "httpx", "httpx-toolkit")
    monkeypatch.setattr("shutil.which", lambda _command: None)

    detected = HttpxAdapter().detect()
    assert detected["available"] is False
    assert detected["status"] == "NOT_INSTALLED"
    assert "HTTPX_EXECUTABLE" in detected["install_hint"]


def test_httpx_toolkit_default_can_fall_back_only_to_verified_projectdiscovery_httpx(monkeypatch):
    monkeypatch.setitem(tool_manager.TOOL_EXECUTABLES, "httpx", "httpx-toolkit")
    calls = []
    monkeypatch.setattr("shutil.which", lambda command: calls.append(command) or
                        ("/usr/bin/httpx" if command == "httpx" else None))
    monkeypatch.setattr("subprocess.run", lambda *args, **kwargs: _version_result(
        "projectdiscovery.io\nCurrent Version: v1.7.1\n"))

    detected = HttpxAdapter().detect()
    assert calls == ["httpx-toolkit", "httpx"]
    assert detected["available"] is True
    assert detected["command"] == "httpx"
    assert detected["path"] == "/usr/bin/httpx"
