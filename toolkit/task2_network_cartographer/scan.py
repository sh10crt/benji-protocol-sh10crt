import argparse
import json
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from typing import List


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="TCP connect scanner with banner grabbing."
    )
    parser.add_argument("target", help="Target IP address.")
    parser.add_argument(
        "--ports",
        default="1-1024",
    )
    parser.add_argument(
        "--threads",
        default=4,  # default number of threads
        type=int,
        help="Number of threads to use for concurrent scanning.",
    )
    parser.add_argument(
        "--output",
        default="output.json",  # Default output file path
        help="Output JSON file path.",
    )
    return parser.parse_args()


def parse_port_input(port_str: str) -> List[int]:
    """Convert a port specification string into a sorted, deduplicated List."""
    ports = []  # type: List[int]
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            # Handle port ranges
            start, end = [int(x.strip()) for x in part.split("-")]
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


def check_port(target: str, port: int, timeout: float = 0.5) -> bool:
    """Attempt a TCP connection to target:port, return true if open."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        result: int = sock.connect_ex((target, port))
        return result == 0
    except socket.timeout:
        return False
    finally:
        sock.close()


def grab_banner(target: str, port: int, timeout: float = 0.5) -> str:
    """Attempt to grab a banner from an open port, return empty string if none."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((target, port))
        time.sleep(0.5)  # Wait for the server to send a banner if it does
        banner = sock.recv(1024).decode("utf-8", errors="ignore")
        return banner.strip()  # Return empty string if no banner received
    except socket.timeout:
        return ""
    finally:
        sock.close()


def main() -> None:
    """Parse arguments, run scanner, write JSON output."""
    args = parse_arguments()

    try:
        ports = parse_port_input(args.ports)
    except ValueError as e:
        print(f"Error parsing ports: {e}", file=sys.stderr)
        sys.exit(1)

    open_ports = []

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(check_port, args.target, p, 0.5): p for p in ports}

        for future in futures:
            port = futures[future]
            if future.result():
                banner = grab_banner(args.target, port, 0.5)
                open_ports.append({"port": port, "banner": banner})

    open_ports.sort(key=lambda x: x["port"])

    output = {
        "target": args.target,
        "open_ports": open_ports,
    }

    # Ensure the directory exists before writing the file
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(output, indent=2))

    print(f"[*] {len(open_ports)} port(s) found.", file=sys.stderr)

    # Also print to stdout
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
