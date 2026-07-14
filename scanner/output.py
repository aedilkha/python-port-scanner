"""Save scan results to a file (JSON, CSV or TXT).

The format is picked from the filename extension, so --output results.json
gives JSON, results.csv gives CSV, and anything else falls back to plain text.
"""

import csv
import json
from datetime import datetime


def save_results(target: str, results: dict[int, str], path: str) -> None:
    """Write results to `path`, choosing the format from its extension."""
    if path.endswith(".json"):
        _save_json(target, results, path)
    elif path.endswith(".csv"):
        _save_csv(results, path)
    else:
        _save_txt(target, results, path)


def _save_json(target: str, results: dict[int, str], path: str) -> None:
    data = {
        "target": target,
        "scanned_at": datetime.now().isoformat(timespec="seconds"),
        "ports": [
            {"port": port, "state": state}
            for port, state in sorted(results.items())
        ],
    }
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def _save_csv(results: dict[int, str], path: str) -> None:
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["port", "state"])
        for port, state in sorted(results.items()):
            writer.writerow([port, state])


def _save_txt(target: str, results: dict[int, str], path: str) -> None:
    with open(path, "w") as f:
        f.write(f"Scan of {target} - {datetime.now():%Y-%m-%d %H:%M:%S}\n")
        for port, state in sorted(results.items()):
            f.write(f"{port}/tcp\t{state}\n")