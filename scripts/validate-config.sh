#!/usr/bin/env bash
set -euo pipefail

# Configuration Validation Script
# Validates all configuration files before running scans

echo "Validating DAST configuration files..."

# Check if required files exist
REQUIRED_FILES=(
    "configs/zap-config.conf"
    "configs/nuclei-templates.yaml"
    "policies/severity-rules.rego"
    "scripts/zap-baseline.sh"
    "scripts/nuclei-scan.sh"
    "scripts/risk-evaluator.py"
    "scripts/report-generator.py"
)

for file in "${REQUIRED_FILES[@]}"; do
    if [ ! -f "$file" ]; then
        echo "Error: Required file not found: $file"
        exit 1
    fi
    echo "✓ Found: $file"
done

# Validate YAML files
echo ""
echo "Validating YAML syntax..."

if command -v yamllint &> /dev/null; then
    yamllint configs/*.yaml
    echo "✓ YAML files are valid"
else
    echo "Warning: yamllint not installed, skipping YAML validation"
fi

# Validate Python scripts
echo ""
echo "Validating Python scripts..."

if command -v python3 &> /dev/null; then
    for py_file in scripts/*.py; do
        python3 -m py_compile "$py_file"
        echo "✓ $py_file is valid"
    done
else
    echo "Warning: Python3 not installed, skipping Python validation"
fi

# Check script permissions
echo ""
echo "Checking script permissions..."

for script in scripts/*.sh; do
    if [ ! -x "$script" ]; then
        echo "Making $script executable"
        chmod +x "$script"
    fi
    echo "$script is executable"
done

echo ""
echo "All validations passed."
