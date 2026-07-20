#!/usr/bin/env bash
#
# run.sh - convenience wrapper to launch the port scanner.
#
# Usage:
#   ./run.sh <target> [ports] [type]
#
# Examples:
#   ./run.sh 192.168.20.11                   # connect scan, ports 1-1024
#   ./run.sh 192.168.20.11 1-65535           # custom port range
#   ./run.sh 192.168.20.11 53,123 udp        # UDP scan
#   sudo ./run.sh 192.168.20.11 1-1000 syn   # SYN scan (needs sudo)
#   ./run.sh 192.168.20.0/24 discover        # host discovery on a subnet
#
# Make it executable once:  chmod +x run.sh

cd "$(dirname "$0")" || exit 1

TARGET="${1:-127.0.0.1}"   # first arg, default localhost
PORTS="${2:-1-1024}"       # second arg, default 1-1024
TYPE="${3:-connect}"       # third arg: connect | syn | udp | discover

if [ "$TYPE" = "discover" ]; then
    # host discovery mode - the second arg is ignored here
    python3 scanner/scanner.py --target "$TARGET" --discover
else
    python3 scanner/scanner.py --target "$TARGET" --ports "$PORTS" --type "$TYPE" --output results.json
fi