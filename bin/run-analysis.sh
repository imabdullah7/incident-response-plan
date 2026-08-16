#!/usr/bin/env bash
# run-analysis.sh — simple wrapper to run the analyzer
set -euo pipefail

# Resolve script directory so the wrapper can be run from anywhere
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
python3 "$SCRIPT_DIR/../tools/analyze_pcap.py" "$@"
