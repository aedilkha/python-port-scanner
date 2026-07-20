#!/usr/bin/env bash
#
# run.sh - convenience wrapper to launch the port scanner.

cd "$(dirname "$0")" || exit 1

# --- help ---
if [ "$1" = "--help" ] || [ "$1" = "-h" ] || [ -z "$1" ]; then
    cat << 'HELP'
Usage: ./run.sh <target> [ports] [type]

Arguments:
  target    IP, hostname, or CIDR (e.g. 192.168.20.11 or 192.168.20.0/24)
  ports     port range or list (default: 1-1024). Ignored in discover mode.
  type      connect | syn | udp | all | discover   (default: connect)

Examples:
  ./run.sh 192.168.20.11                   # connect scan, ports 1-1024
  ./run.sh 192.168.20.11 1-65535           # custom port range
  ./run.sh 192.168.20.11 53,123 udp        # UDP scan
  sudo ./run.sh 192.168.20.11 1-1000 syn   # SYN scan (needs sudo)
  sudo ./run.sh 192.168.20.11 1-1000 all   # TCP + UDP in one go
  ./run.sh 192.168.20.0/24 discover        # host discovery on a subnet

Notes:
  - syn and all use a SYN scan when run as root (sudo), else connect.
  - results are saved to results.json (except discover mode).
HELP
    exit 0
fi

TARGET="$1"

# discovery mode: "discover" as 2nd or 3rd argument
if [ "$2" = "discover" ] || [ "$3" = "discover" ]; then
    python3 scanner/scanner.py --target "$TARGET" --discover
    exit 0
fi

PORTS="${2:-1-1024}"
TYPE="${3:-connect}"

python3 scanner/scanner.py --target "$TARGET" --ports "$PORTS" --type "$TYPE" --output results.json