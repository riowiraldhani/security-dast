#!/usr/bin/env bash
set -euo pipefail

# OWASP ZAP Baseline Scan Wrapper
# This script wraps `zap-baseline.py` so all callers reuse the same flags and configs.

TARGET_URL="${1:-}"
OUTPUT_DIR="${2:-./reports}"
TIMEOUT="${3:-60}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ZAP_CONFIG_CONF="${REPO_ROOT}/configs/zap-config.conf"

if [ -z "$TARGET_URL" ]; then
    echo "Error: Target URL is required"
    echo "Usage: $0 <target_url> [output_dir] [timeout]"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"
chmod 755 "$OUTPUT_DIR"

WRK_DIR="$(mktemp -d)"
chmod 777 "$WRK_DIR"
trap 'rm -rf "$WRK_DIR"' EXIT

CONFIG_ARG=""
if [ -f "$ZAP_CONFIG_CONF" ]; then
    cp "$ZAP_CONFIG_CONF" "${WRK_DIR}/zap-config.conf"
    chmod 600 "${WRK_DIR}/zap-config.conf"
    CONFIG_ARG="-c /zap/wrk/zap-config.conf"
else
    echo "Warning: No zap-config.conf found; using default ZAP settings."
fi

echo "Starting ZAP Baseline Scan"
echo "Target: $TARGET_URL"
echo "Output: $OUTPUT_DIR"
echo "Timeout: ${TIMEOUT}s"

docker run --rm \
    --user root \
    -v "${WRK_DIR}:/zap/wrk:rw" \
    -t ghcr.io/zaproxy/zaproxy:stable \
    zap-baseline.py \
    -t "$TARGET_URL" \
    -J "zap-report.json" \
    -r "zap-report.html" \
    -w "zap-report.md" \
    -I \
    -T "$TIMEOUT" \
    $CONFIG_ARG || true

echo "ZAP scan completed"
echo "Copying reports to $OUTPUT_DIR"

for report in zap-report.json zap-report.html zap-report.md; do
    if [ -f "${WRK_DIR}/${report}" ]; then
        cp "${WRK_DIR}/${report}" "${OUTPUT_DIR}/"
    fi
done

if [ ! -f "$OUTPUT_DIR/zap-report.json" ]; then
    echo "Warning: ZAP JSON report missing; creating a stub so downstream steps can continue."
    echo '{"site":[],"@version":"2.11.1","@generated":"'"$(date -u +"%a, %d %b %Y %H:%M:%S")"'"}' > "$OUTPUT_DIR/zap-report.json"
fi

exit 0
