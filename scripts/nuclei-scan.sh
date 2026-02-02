#!/bin/bash
set -euo pipefail

# Nuclei Vulnerability Scan Wrapper
# This script runs Nuclei with the shared template config so caller repos stay thin.

TARGET_URL="${1}"
OUTPUT_DIR="${2:-./reports}"
SEVERITY="${3:-critical,high,medium}"
NUCLEI_VERSION="${NUCLEI_VERSION:-3.7.0}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
NUCLEI_CACHE_DIR="${NUCLEI_CACHE_DIR:-${OUTPUT_DIR}/.nuclei}"
NUCLEI_BINARY="${NUCLEI_CACHE_DIR}/nuclei"
NUCLEI_TEMPLATES_DIR="${NUCLEI_CACHE_DIR}/templates"
NUCLEI_CONFIG="${REPO_ROOT}/configs/nuclei-templates.yaml"
NUCLEI_DEFAULT_TEMPLATES="${HOME}/nuclei-templates"

if [ -z "$TARGET_URL" ]; then
    echo "Error: Target URL is required"
    echo "Usage: $0 <target_url> [output_dir] [severity]"
    exit 1
fi

if [ ! -f "$NUCLEI_CONFIG" ]; then
    echo "Warning: Nuclei config not found at $NUCLEI_CONFIG; falling back to default template lists"
else
    echo "Using Nuclei template config ($NUCLEI_CONFIG):"
    head -n 40 "$NUCLEI_CONFIG" || true
fi

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

echo "Starting Nuclei Scan"
echo "Target: $TARGET_URL"
echo "Output: $OUTPUT_DIR"
echo "Severity Filter: $SEVERITY"
echo "Using Nuclei ${NUCLEI_VERSION}"

# Ensure cache directory exists
mkdir -p "$NUCLEI_CACHE_DIR"
chmod 775 "$NUCLEI_CACHE_DIR"

download_nuclei() {
    local archive="${NUCLEI_CACHE_DIR}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip"
    if [ -x "$NUCLEI_BINARY" ]; then
        echo "Cached Nuclei binary found"
        return
    fi

    echo "Downloading Nuclei ${NUCLEI_VERSION}"
    curl -fsSL -o "$archive" "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip"
    unzip -o "$archive" -d "$NUCLEI_CACHE_DIR"
    rm -f "$archive"
    chmod +x "$NUCLEI_BINARY"
}

ensure_templates() {
    download_templates
}

templates_populated() {
    find "$NUCLEI_TEMPLATES_DIR" -name '*.yaml' -print -quit >/dev/null 2>&1
}

default_templates_populated() {
    [ -d "$NUCLEI_DEFAULT_TEMPLATES" ] && find "$NUCLEI_DEFAULT_TEMPLATES" -name '*.yaml' -print -quit >/dev/null 2>&1
}

download_templates() {
    mkdir -p "$NUCLEI_TEMPLATES_DIR"
    echo "Refreshing Nuclei templates in $NUCLEI_TEMPLATES_DIR"
    NUCLEI_TEMPLATES_DIR="$NUCLEI_TEMPLATES_DIR" "$NUCLEI_BINARY" -update-templates
    if [ $? -ne 0 ]; then
        echo "Error: Unable to refresh Nuclei templates"
        exit 1
    fi

    if templates_populated; then
        return
    fi

    if [ -d "$NUCLEI_DEFAULT_TEMPLATES" ]; then
        echo "Copying templates from $NUCLEI_DEFAULT_TEMPLATES to $NUCLEI_TEMPLATES_DIR"
        cp -R "$NUCLEI_DEFAULT_TEMPLATES"/. "$NUCLEI_TEMPLATES_DIR"
    fi

    if ! templates_populated; then
        echo "Error: No templates found after the refresh"
        exit 1
    fi
}

download_nuclei
echo "Starting scan with cached binary"
download_templates

ACTIVE_TEMPLATES_DIR="$NUCLEI_TEMPLATES_DIR"
if ! templates_populated && default_templates_populated; then
    echo "Switching to runner cache templates at $NUCLEI_DEFAULT_TEMPLATES"
    ACTIVE_TEMPLATES_DIR="$NUCLEI_DEFAULT_TEMPLATES"
fi

validate_templates() {
    local dir="$1"
    echo "Validating templates directory: $dir"
    local ok=0
    while IFS= read -r -d '' file; do
        ok=1
        echo "Template sample: $file"
        head -n 20 "$file" || true
        echo "---"
        break
    done < <(find "$dir" -name '*.yaml' -print0)

    if [ "$ok" -ne 1 ]; then
        echo "Error: Templates directory $dir contains no YAML files"
        exit 1
    fi

    echo "Validated $(find "$dir" -name '*.yaml' | wc -l) YAML files in $dir."
}

validate_templates "$ACTIVE_TEMPLATES_DIR"

NUCLEI_COMMAND=(
    "$NUCLEI_BINARY"
    -u "$TARGET_URL"
    -severity "$SEVERITY"
    -templates "$ACTIVE_TEMPLATES_DIR"
    -config "$NUCLEI_CONFIG"
    -json-export "$OUTPUT_DIR/nuclei-report.json"
    -markdown-export "$OUTPUT_DIR/nuclei-report.md"
    -stats
    -silent
)

echo "Running: ${NUCLEI_COMMAND[*]}"
"${NUCLEI_COMMAND[@]}"

echo "Nuclei scan completed"
echo "Reports saved to: $OUTPUT_DIR"

# Check if reports were generated
if [ ! -f "$OUTPUT_DIR/nuclei-report.json" ]; then
    echo "Warning: No vulnerabilities found or scan failed"
    # Create empty report
    touch "$OUTPUT_DIR/nuclei-report.json"
fi

exit 0
