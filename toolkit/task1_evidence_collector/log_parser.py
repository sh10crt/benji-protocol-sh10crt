import argparse
import csv
import re
import sys
from datetime import datetime
from pathlib import Path

# Regex for failed password or invalid user attempts
LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}) .*?: "
    r"(?:Failed password for (?:invalid user )?(?P<failed_user>\S+)|Invalid user (?P<invalid_user>\S+)) "
    r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)

# Configuration for brute-force detection (not used yet but kept for future expansion)
TIME_WINDOW_MINUTES = 5
ATTEMPT_THRESHOLD = 3


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Parses the log file and extracts suspicious login attempts."
    )
    parser.add_argument("input_file", help="Path to the log file to be parsed")
    parser.add_argument(
        "-o",
        "--output",
        default="suspect.csv",
        help="Path to the detailed output CSV file",
    )
    parser.add_argument(
        "-s",
        "--summary",
        default="summary.csv",
        help="Path to the summary CSV file",
    )
    parser.add_argument(
        "-b",
        "--bruteforce",
        default="bruteforce.csv",
        help="Path to the brute force alert CSV file",
    )
    return parser.parse_args()


def parse_log(file_path):
    path = Path(file_path)

    if not path.exists():
        print(f"Error: file {file_path} does not exist", file=sys.stderr)
        sys.exit(1)

    records = []
    current_year = datetime.now().year

    with path.open(encoding="utf-8", errors="ignore") as f:
        for line in f:
            match = LOG_PATTERN.search(line)

            if match:
                # Get username (failed or invalid)
                user = match.group("failed_user") or match.group("invalid_user")

                # FIXED: include year directly in parsing (no warning)
                timestamp_str = f"{match.group('timestamp')} {current_year}"
                timestamp = datetime.strptime(timestamp_str, "%b %d %H:%M:%S %Y")

                # Only capture failed login attempts
                if "Accepted password" not in line:
                    records.append(
                        {
                            "Timestamp": timestamp.strftime("%b %d %H:%M:%S"),
                            "IP_Address": match.group("ip"),
                            "User_Account": user,
                        }
                    )

    return records


def remove_duplicates(records):
    seen = set()
    unique_records = []

    for record in records:
        key = (record["Timestamp"], record["IP_Address"], record["User_Account"])
        if key not in seen:
            seen.add(key)
            unique_records.append(record)

    return unique_records


def write_csv(records, output_path):
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", newline="") as csvfile:
        fieldnames = ["Timestamp", "IP_Address", "User_Account"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()
        writer.writerows(records)


def main():
    args = parse_arguments()

    records = parse_log(args.input_file)
    unique_records = remove_duplicates(records)

    write_csv(unique_records, args.output)


if __name__ == "__main__":
    main()
