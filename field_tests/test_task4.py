"""
================================================================================
COM5413 — The Benji Protocol
IMF Field Test — Task 4: The Web Enumerator
================================================================================

These tests verify that web_enum.py meets the output contract defined in
the assessment brief. They are run by the auto-grader at submission and can
be run locally by you at any time.

Run with:
    pytest field_tests/test_task4.py -v

All tests must pass for full marks on the automated component of Task 4.
A failing test tells you exactly what the contract violation is — fix it.
================================================================================
"""

import http.server
import re
import socket
import subprocess
import sys
import threading
from pathlib import Path

import pytest

# Path resolution — tests run from repo root
SCRIPT = Path("toolkit/task4_web_enumerator/web_enum.py")

# ---------------------------------------------------------------------------
# Fixture: lightweight HTTP server with known content
# ---------------------------------------------------------------------------

ROBOTS_CONTENT = "User-agent: *\nDisallow: /secret\n"

HTML_CONTENT = """\
<html>
<head><title>Test Page</title></head>
<body>
<!-- admin panel: /secret-admin -->
<h1>Welcome</h1>
<!-- TODO: remove debug endpoint before release -->
<p>Nothing to see here.</p>
</body>
</html>
"""


class _TestHandler(http.server.BaseHTTPRequestHandler):
    """HTTP handler with known headers and content for testing."""

    server_version = "Apache/2.2.8"

    def do_GET(self):
        if self.path == "/robots.txt":
            self._respond(200, ROBOTS_CONTENT, "text/plain")
        elif self.path == "/admin":
            self._respond(200, "<html><body>Admin</body></html>", "text/html")
        elif self.path == "/phpmyadmin":
            self._respond(404, "Not Found", "text/plain")
        elif self.path == "/login":
            self._respond(200, "<html><body>Login</body></html>", "text/html")
        elif self.path == "/.git":
            self._respond(403, "Forbidden", "text/plain")
        else:
            self._respond(200, HTML_CONTENT, "text/html")

    def _respond(self, code, body, content_type):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("X-Powered-By", "PHP/5.2.4")
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, format, *args):
        pass  # suppress server log noise during tests


def _find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture()
def web_server():
    """Start a test HTTP server with known headers and content."""
    port = _find_free_port()
    server = http.server.HTTPServer(("127.0.0.1", port), _TestHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    yield port
    server.shutdown()


def run_enum(args: list[str]) -> subprocess.CompletedProcess:
    """Helper: run web_enum.py with given arguments."""
    return subprocess.run(
        [sys.executable, str(SCRIPT)] + args,
        capture_output=True,
        text=True,
        timeout=60,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_script_exists():
    """Task 4 script must exist at the expected path."""
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


def test_requests_used():
    """HTTP requests must use the requests library."""
    source = SCRIPT.read_text()
    assert (
        "requests" in source
    ), "requests library not found in source. HTTP must use requests."


def test_beautifulsoup_used():
    """HTML parsing must use BeautifulSoup (bs4)."""
    source = SCRIPT.read_text()
    assert (
        "BeautifulSoup" in source
    ), "BeautifulSoup not found in source. HTML parsing must use bs4."


def test_script_runs_without_error(web_server):
    """Script must execute without Python errors against a valid URL."""
    port = web_server
    result = run_enum([f"http://127.0.0.1:{port}"])
    assert result.returncode == 0, f"Script exited with error:\n{result.stderr}"


def test_headers_section_present(web_server):
    """Output must contain a [HEADERS] section."""
    port = web_server
    result = run_enum([f"http://127.0.0.1:{port}"])
    assert result.returncode == 0, f"Script exited with error:\n{result.stderr}"
    assert "[HEADERS]" in result.stdout, "Output missing [HEADERS] section."


def test_server_header_reported(web_server):
    """Must report the Server header value."""
    port = web_server
    result = run_enum([f"http://127.0.0.1:{port}"])
    assert result.returncode == 0, f"Script exited with error:\n{result.stderr}"
    assert (
        "Apache" in result.stdout
    ), f"Server header 'Apache' not found in output:\n{result.stdout[:500]}"


def test_xpoweredby_header_reported(web_server):
    """Must report the X-Powered-By header value."""
    port = web_server
    result = run_enum([f"http://127.0.0.1:{port}"])
    assert result.returncode == 0, f"Script exited with error:\n{result.stderr}"
    assert (
        "PHP/5.2.4" in result.stdout
    ), f"X-Powered-By 'PHP/5.2.4' not found in output:\n{result.stdout[:500]}"


def test_comments_section_present(web_server):
    """Output must contain a [COMMENTS] section."""
    port = web_server
    result = run_enum([f"http://127.0.0.1:{port}"])
    assert result.returncode == 0, f"Script exited with error:\n{result.stderr}"
    assert "[COMMENTS]" in result.stdout, "Output missing [COMMENTS] section."


def test_html_comments_extracted(web_server):
    """Must extract HTML comments from the page source.
    The test page contains two comments — both must appear in output."""
    port = web_server
    result = run_enum([f"http://127.0.0.1:{port}"])
    assert result.returncode == 0, f"Script exited with error:\n{result.stderr}"
    assert (
        "secret-admin" in result.stdout
    ), "HTML comment containing 'secret-admin' not found in output."
    assert (
        "debug endpoint" in result.stdout
    ), "HTML comment containing 'debug endpoint' not found in output."


def test_sensitive_paths_section_present(web_server):
    """Output must contain a [SENSITIVE PATHS] section."""
    port = web_server
    result = run_enum([f"http://127.0.0.1:{port}"])
    assert result.returncode == 0, f"Script exited with error:\n{result.stderr}"
    assert (
        "[SENSITIVE PATHS]" in result.stdout
    ), "Output missing [SENSITIVE PATHS] section."


def test_sensitive_paths_checked(web_server):
    """Must probe all five required sensitive paths and report status."""
    port = web_server
    result = run_enum([f"http://127.0.0.1:{port}"])
    assert result.returncode == 0, f"Script exited with error:\n{result.stderr}"
    output = result.stdout
    for path in ["/robots.txt", "/admin", "/phpmyadmin", "/login", "/.git"]:
        assert path in output, f"Sensitive path '{path}' not mentioned in output."


def test_sensitive_path_found_status(web_server):
    """Paths that exist must be reported as FOUND with status code."""
    port = web_server
    result = run_enum([f"http://127.0.0.1:{port}"])
    assert result.returncode == 0, f"Script exited with error:\n{result.stderr}"
    output = result.stdout
    # /robots.txt returns 200 — must show FOUND
    robots_line = [l for l in output.split("\n") if "/robots.txt" in l]
    assert len(robots_line) >= 1, "/robots.txt line not found in output"
    assert (
        "FOUND" in robots_line[0].upper() or "200" in robots_line[0]
    ), f"/robots.txt should show FOUND/200, got: {robots_line[0]}"


def test_sensitive_path_not_found_status(web_server):
    """Paths that do not exist must be reported as NOT FOUND with status code."""
    port = web_server
    result = run_enum([f"http://127.0.0.1:{port}"])
    assert result.returncode == 0, f"Script exited with error:\n{result.stderr}"
    output = result.stdout
    # /phpmyadmin returns 404 — must show NOT FOUND
    phpmyadmin_line = [l for l in output.split("\n") if "/phpmyadmin" in l]
    assert len(phpmyadmin_line) >= 1, "/phpmyadmin line not found in output"
    assert (
        "NOT FOUND" in phpmyadmin_line[0].upper() or "404" in phpmyadmin_line[0]
    ), f"/phpmyadmin should show NOT FOUND/404, got: {phpmyadmin_line[0]}"
