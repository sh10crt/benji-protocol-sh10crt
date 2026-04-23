"""
================================================================================
COM5413 — The Benji Protocol
IMF Field Test — Task 3: The Access Validator
================================================================================

These tests verify that brute.py meets the output contract defined in
the assessment brief. They are run by the auto-grader at submission and can
be run locally by you at any time.

Run with:
    pytest field_tests/test_task3.py -v

All tests must pass for full marks on the automated component of Task 3.
A failing test tells you exactly what the contract violation is — fix it.
================================================================================
"""

import os
import re
import socket
import subprocess
import sys
import threading
from pathlib import Path

import pytest
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

# Path resolution — tests run from repo root
SCRIPT = Path("toolkit/task3_access_validator/brute.py")
FIXTURES_DIR = Path("field_tests/fixtures")
WORDLIST = FIXTURES_DIR / "test_wordlist.txt"
WORDLIST_EMPTY = FIXTURES_DIR / "test_wordlist_empty.txt"
WORDLIST_MESSY = FIXTURES_DIR / "test_wordlist_messy.txt"

# ---------------------------------------------------------------------------
# FTP credentials for fixture server
# ---------------------------------------------------------------------------
FTP_USER = "testuser"
FTP_PASS = "s3cur3p@ss"


def _find_free_port():
    """Find an available TCP port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture()
def ftp_server(tmp_path):
    """Start a real FTP server with known credentials, yield its port, then stop."""
    port = _find_free_port()
    authorizer = DummyAuthorizer()
    authorizer.add_user(FTP_USER, FTP_PASS, str(tmp_path), perm="elradfmw")
    handler = FTPHandler
    handler.authorizer = authorizer
    handler.passive_ports = range(60000, 60100)
    server = FTPServer(("127.0.0.1", port), handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    yield port
    server.close_all()


@pytest.fixture(autouse=False)
def fixtures():
    """Create and tear down wordlist fixtures for each test."""
    FIXTURES_DIR.mkdir(parents=True, exist_ok=True)

    # Wordlist where the correct password is the 3rd entry
    WORDLIST.write_text("wrongpass1\nwrongpass2\n" + FTP_PASS + "\nwrongpass3\n")

    # Wordlist with no correct password
    WORDLIST_EMPTY.write_text("bad1\nbad2\nbad3\n")

    # Wordlist with empty lines and non-ASCII — correct password is present
    WORDLIST_MESSY.write_text("\n\nwrong1\n\np\u00e4sswort\n" + FTP_PASS + "\n\n")

    yield

    for f in [WORDLIST, WORDLIST_EMPTY, WORDLIST_MESSY]:
        if f.exists():
            f.unlink()


def run_brute(args: list[str]) -> subprocess.CompletedProcess:
    """Helper: run brute.py with given arguments."""
    return subprocess.run(
        [sys.executable, str(SCRIPT)] + args,
        capture_output=True,
        text=True,
        timeout=120,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_script_exists():
    """Task 3 script must exist at the expected path."""
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
    assert (
        "input(" not in non_comment_source
    ), "input() found in script code. All input must use argparse. NO EXCEPTIONS."


def test_sleep_present_in_source():
    """time.sleep MUST be present between attempts — the auto-grader checks source.
    This prevents denial-of-service behaviour against the target."""
    source = SCRIPT.read_text()
    assert (
        "time.sleep" in source
    ), "time.sleep not found in source. A delay between attempts is mandatory."


def test_paramiko_used():
    """SSH credential testing must use paramiko."""
    source = SCRIPT.read_text()
    assert (
        "paramiko" in source
    ), "paramiko not found in source. SSH testing must use paramiko."


def test_ftplib_used():
    """FTP credential testing must use ftplib."""
    source = SCRIPT.read_text()
    assert (
        "ftplib" in source
    ), "ftplib not found in source. FTP testing must use ftplib."


def test_ftp_success_message(ftp_server, fixtures):
    """On finding valid credentials, must print the exact success message format."""
    port = ftp_server
    result = run_brute(
        [
            "127.0.0.1",
            "--service",
            "ftp",
            "--user",
            FTP_USER,
            "--wordlist",
            str(WORDLIST),
            "--port",
            str(port),
        ]
    )
    assert result.returncode == 0, f"Script exited with error:\n{result.stderr}"
    assert (
        f"[+] SUCCESS: Password found: {FTP_PASS}" in result.stdout
    ), f"Expected success message not found in stdout:\n{result.stdout}"


def test_ftp_exhaustion_message(ftp_server, fixtures):
    """When all passwords fail, must print the exact exhaustion message format."""
    port = ftp_server
    result = run_brute(
        [
            "127.0.0.1",
            "--service",
            "ftp",
            "--user",
            FTP_USER,
            "--wordlist",
            str(WORDLIST_EMPTY),
            "--port",
            str(port),
        ]
    )
    expected = f"[-] EXHAUSTED: No valid credentials found for user {FTP_USER}"
    assert (
        expected in result.stdout
    ), f"Expected exhaustion message not found in stdout:\n{result.stdout}"


def test_ftp_stops_on_success(ftp_server, fixtures):
    """Script must stop immediately after finding valid credentials.
    The correct password is 3rd in the wordlist — the 4th must not be tried."""
    port = ftp_server
    result = run_brute(
        [
            "127.0.0.1",
            "--service",
            "ftp",
            "--user",
            FTP_USER,
            "--wordlist",
            str(WORDLIST),
            "--port",
            str(port),
        ]
    )
    assert result.returncode == 0, f"Script exited with error:\n{result.stderr}"
    # If it tried wrongpass3 (the 4th entry), it did not stop on success
    assert (
        "wrongpass3" not in result.stdout and "wrongpass3" not in result.stderr
    ), "Script continued testing after finding valid credentials."


def test_handles_messy_wordlist(ftp_server, fixtures):
    """Wordlist with empty lines and non-ASCII characters must not crash the script."""
    port = ftp_server
    result = run_brute(
        [
            "127.0.0.1",
            "--service",
            "ftp",
            "--user",
            FTP_USER,
            "--wordlist",
            str(WORDLIST_MESSY),
            "--port",
            str(port),
        ]
    )
    assert result.returncode == 0, f"Script crashed on messy wordlist:\n{result.stderr}"
    assert (
        f"[+] SUCCESS: Password found: {FTP_PASS}" in result.stdout
    ), f"Expected success message not found with messy wordlist:\n{result.stdout}"


def test_missing_wordlist_handled(fixtures):
    """Script must exit non-zero when the wordlist file does not exist."""
    result = run_brute(
        [
            "127.0.0.1",
            "--service",
            "ftp",
            "--user",
            "anyone",
            "--wordlist",
            "/tmp/this_wordlist_does_not_exist_com5413.txt",
        ]
    )
    assert result.returncode != 0, "Script should exit non-zero for a missing wordlist."


def test_service_argument_validated():
    """--service must only accept 'ssh' or 'ftp'. Other values should be rejected."""
    result = run_brute(
        [
            "127.0.0.1",
            "--service",
            "http",
            "--user",
            "test",
            "--wordlist",
            str(WORDLIST),
        ]
    )
    assert (
        result.returncode != 0
    ), "Script should reject --service http. Only ssh and ftp are valid."
