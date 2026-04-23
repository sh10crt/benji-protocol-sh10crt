"""
================================================================================
COM5413 — The Benji Protocol
IMF Field Test — Task 2: The Network Cartographer
================================================================================

These tests verify that scan.py meets the output contract defined in
the assessment brief. They are run by the auto-grader at submission and can
be run locally by you at any time.

Run with:
    pytest field_tests/test_task2.py -v

All tests must pass for full marks on the automated component of Task 2.
A failing test tells you exactly what the contract violation is — fix it.
================================================================================
"""

import json
import re
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

# Path resolution — tests run from repo root
SCRIPT = Path("toolkit/task2_network_cartographer/scan.py")
OUTPUT_JSON = Path("field_tests/fixtures/test_recon_results.json")

# ---------------------------------------------------------------------------
# Fixture: lightweight TCP servers with known banners
# ---------------------------------------------------------------------------

BANNER_TEXT = "220 (vsFTPd 2.3.4)\r\n"


def _run_banner_server(host, port, banner, ready_event, stop_event):
    """Serve a single banner response then wait for stop."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.settimeout(1.0)
    srv.bind((host, port))
    srv.listen(1)
    ready_event.set()
    while not stop_event.is_set():
        try:
            conn, _ = srv.accept()
            conn.sendall(banner.encode())
            conn.close()
        except socket.timeout:
            continue
    srv.close()


def _run_silent_server(host, port, ready_event, stop_event):
    """Open port that sends no banner — tests empty banner handling."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.settimeout(1.0)
    srv.bind((host, port))
    srv.listen(1)
    ready_event.set()
    while not stop_event.is_set():
        try:
            conn, _ = srv.accept()
            time.sleep(0.6)  # wait longer than default timeout
            conn.close()
        except socket.timeout:
            continue
    srv.close()


def _find_free_port():
    """Find an available TCP port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture()
def banner_server():
    """Start a TCP server that sends a known banner, yield its port, then stop."""
    port = _find_free_port()
    ready = threading.Event()
    stop = threading.Event()
    t = threading.Thread(
        target=_run_banner_server,
        args=("127.0.0.1", port, BANNER_TEXT, ready, stop),
        daemon=True,
    )
    t.start()
    ready.wait(timeout=5)
    yield port
    stop.set()
    t.join(timeout=3)


@pytest.fixture()
def silent_server():
    """Start a TCP server that sends NO banner, yield its port, then stop."""
    port = _find_free_port()
    ready = threading.Event()
    stop = threading.Event()
    t = threading.Thread(
        target=_run_silent_server,
        args=("127.0.0.1", port, ready, stop),
        daemon=True,
    )
    t.start()
    ready.wait(timeout=5)
    yield port
    stop.set()
    t.join(timeout=3)


@pytest.fixture(autouse=False)
def cleanup_output():
    """Remove output JSON after test."""
    yield
    if OUTPUT_JSON.exists():
        OUTPUT_JSON.unlink()


def run_scanner(args: list[str]) -> subprocess.CompletedProcess:
    """Helper: run scan.py with given arguments."""
    return subprocess.run(
        [sys.executable, str(SCRIPT)] + args, capture_output=True, text=True
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_script_exists():
    """Task 2 script must exist at the expected path."""
    assert SCRIPT.exists(), f"Script not found at {SCRIPT}"


def test_no_input_function_used():
    """Script must not contain input() calls — this breaks automation.
    Comments and docstrings mentioning input() are excluded from this check.
    Only actual function call syntax triggers a failure."""
    source = SCRIPT.read_text()
    non_comment_lines = [
        line for line in source.split("\n") if not line.strip().startswith("#")
    ]
    non_comment_source = "\n".join(non_comment_lines)
    non_comment_source = re.sub(r'""".*?"""', "", non_comment_source, flags=re.DOTALL)
    non_comment_source = re.sub(r"'''.*?'''", "", non_comment_source, flags=re.DOTALL)
    # Remove function definitions and identifiers containing 'input' (e.g. parse_port_input)
    cleaned = re.sub(r"\b\w+input\b", "", non_comment_source)
    assert (
        "input(" not in cleaned
    ), "input() found in script code. All input must use argparse. NO EXCEPTIONS."


def test_no_nmap_or_subprocess():
    """Scanner must use socket — not wrap nmap or shell out to external tools."""
    source = SCRIPT.read_text()
    # Strip docstrings and comments before checking
    non_comment_lines = [
        line for line in source.split("\n") if not line.strip().startswith("#")
    ]
    non_comment_source = "\n".join(non_comment_lines)
    non_comment_source = re.sub(r'""".*?"""', "", non_comment_source, flags=re.DOTALL)
    non_comment_source = re.sub(r"'''.*?'''", "", non_comment_source, flags=re.DOTALL)
    assert (
        "nmap" not in non_comment_source.lower()
    ), "Reference to nmap found in code. Use Python socket, not external scanners."
    assert (
        "subprocess" not in non_comment_source
    ), "subprocess usage found. Use Python socket for scanning."


def test_threading_used():
    """Scanner must use ThreadPoolExecutor for concurrent scanning."""
    source = SCRIPT.read_text()
    assert (
        "ThreadPoolExecutor" in source
    ), "ThreadPoolExecutor not found. Concurrent scanning is required."


def test_script_runs_with_banner_server(banner_server, cleanup_output):
    """Script must execute without Python errors when scanning a live port."""
    port = banner_server
    result = run_scanner(
        [
            "127.0.0.1",
            "--ports",
            str(port),
            "--output",
            str(OUTPUT_JSON),
        ]
    )
    assert result.returncode == 0, f"Script exited with error:\n{result.stderr}"


def test_json_output_to_stdout(banner_server, cleanup_output):
    """Scan results must be printed to stdout as valid JSON."""
    port = banner_server
    result = run_scanner(
        [
            "127.0.0.1",
            "--ports",
            str(port),
            "--output",
            str(OUTPUT_JSON),
        ]
    )
    assert result.returncode == 0, f"Script exited with error:\n{result.stderr}"
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        pytest.fail(f"stdout is not valid JSON:\n{result.stdout[:500]}")
    assert isinstance(data, dict), "JSON root must be an object."


def test_json_file_created(banner_server, cleanup_output):
    """Scan results must be saved to the output JSON file."""
    port = banner_server
    result = run_scanner(
        [
            "127.0.0.1",
            "--ports",
            str(port),
            "--output",
            str(OUTPUT_JSON),
        ]
    )
    assert result.returncode == 0, f"Script exited with error:\n{result.stderr}"
    assert OUTPUT_JSON.exists(), "Output JSON file was not created."
    data = json.loads(OUTPUT_JSON.read_text())
    assert isinstance(data, dict), "JSON file root must be an object."


def test_json_structure(banner_server, cleanup_output):
    """JSON must contain 'target' and 'open_ports' keys with correct types."""
    port = banner_server
    result = run_scanner(
        [
            "127.0.0.1",
            "--ports",
            str(port),
            "--output",
            str(OUTPUT_JSON),
        ]
    )
    assert result.returncode == 0, f"Script exited with error:\n{result.stderr}"
    data = json.loads(result.stdout)
    assert "target" in data, "JSON missing 'target' key."
    assert "open_ports" in data, "JSON missing 'open_ports' key."
    assert isinstance(data["open_ports"], list), "'open_ports' must be a list."


def test_open_port_detected(banner_server, cleanup_output):
    """An open port must appear in the open_ports list."""
    port = banner_server
    result = run_scanner(
        [
            "127.0.0.1",
            "--ports",
            str(port),
            "--output",
            str(OUTPUT_JSON),
        ]
    )
    assert result.returncode == 0, f"Script exited with error:\n{result.stderr}"
    data = json.loads(result.stdout)
    found_ports = [entry["port"] for entry in data["open_ports"]]
    assert (
        port in found_ports
    ), f"Open port {port} not found in results. Got: {found_ports}"


def test_banner_captured(banner_server, cleanup_output):
    """The banner from an open port must be captured in the output."""
    port = banner_server
    result = run_scanner(
        [
            "127.0.0.1",
            "--ports",
            str(port),
            "--output",
            str(OUTPUT_JSON),
        ]
    )
    assert result.returncode == 0, f"Script exited with error:\n{result.stderr}"
    data = json.loads(result.stdout)
    entry = [e for e in data["open_ports"] if e["port"] == port]
    assert len(entry) == 1, f"Expected one entry for port {port}"
    banner = entry[0]["banner"]
    assert "vsFTPd" in banner, f"Expected banner containing 'vsFTPd', got: '{banner}'"


def test_banner_key_always_present(banner_server, silent_server, cleanup_output):
    """Every open_ports entry must have a 'banner' key — empty string if no banner."""
    bp = banner_server
    sp = silent_server
    result = run_scanner(
        [
            "127.0.0.1",
            "--ports",
            f"{bp},{sp}",
            "--output",
            str(OUTPUT_JSON),
        ]
    )
    assert result.returncode == 0, f"Script exited with error:\n{result.stderr}"
    data = json.loads(result.stdout)
    for entry in data["open_ports"]:
        assert (
            "banner" in entry
        ), f"'banner' key missing for port {entry.get('port', '?')}"
        assert isinstance(
            entry["banner"], str
        ), f"'banner' must be a string, got {type(entry['banner']).__name__}"


def test_port_key_is_integer(banner_server, cleanup_output):
    """Port numbers in open_ports must be integers, not strings."""
    port = banner_server
    result = run_scanner(
        [
            "127.0.0.1",
            "--ports",
            str(port),
            "--output",
            str(OUTPUT_JSON),
        ]
    )
    assert result.returncode == 0, f"Script exited with error:\n{result.stderr}"
    data = json.loads(result.stdout)
    for entry in data["open_ports"]:
        assert isinstance(
            entry["port"], int
        ), f"'port' must be int, got {type(entry['port']).__name__}: {entry['port']}"


def test_closed_port_not_in_output(cleanup_output):
    """A closed port must NOT appear in open_ports."""
    closed_port = _find_free_port()
    result = run_scanner(
        [
            "127.0.0.1",
            "--ports",
            str(closed_port),
            "--output",
            str(OUTPUT_JSON),
        ]
    )
    assert result.returncode == 0, f"Script exited with error:\n{result.stderr}"
    data = json.loads(result.stdout)
    found_ports = [entry["port"] for entry in data["open_ports"]]
    assert (
        closed_port not in found_ports
    ), f"Closed port {closed_port} incorrectly reported as open."


def test_target_field_matches_argument(banner_server, cleanup_output):
    """The 'target' field in JSON must match the IP passed as argument."""
    port = banner_server
    result = run_scanner(
        [
            "127.0.0.1",
            "--ports",
            str(port),
            "--output",
            str(OUTPUT_JSON),
        ]
    )
    assert result.returncode == 0, f"Script exited with error:\n{result.stderr}"
    data = json.loads(result.stdout)
    assert (
        data["target"] == "127.0.0.1"
    ), f"Expected target '127.0.0.1', got '{data['target']}'"
