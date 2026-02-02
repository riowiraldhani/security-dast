#!/usr/bin/env python3
import argparse
import json
from datetime import datetime

TEMPLATE = """
## DAST Security Scan Report

**Application:** {app_name}  
**Current verdict:** {status_badge}  
**Scan time (UTC):** {scan_date}  
**Calculated risk score:** {risk_score}

---

### Issue snapshot

| Severity | Count |
|----------|-------|
| Critical | {critical} |
| High | {high} |
| Medium | {medium} |
| Low | {low} |
| Info | {info} |

**Total constructive findings:** {total}

---

### What should happen now?

{status_message}

---

### Critical / High findings in focus

{critical_high_details}

---

### Attack surface highlights

{attack_surface}

---

### Recommended next steps

{recommendations}

---

### Automated tuning guidance

{tuning_section}

---

### Artifacts

{artifact_summary}
"""

SEVERITY_MAP = {
    'CRITICAL': 5,
    'HIGH': 4,
    'MEDIUM': 3,
    'LOW': 2,
    'INFO': 1
}


def generate_status_badge(status: str) -> str:
    badges = {
        'PASS': '**PASS** - No critical issues detected',
        'WARN': '**WARN** - Review recommended',
        'FAIL': '**FAIL** - Critical issues detected'
    }
    return badges.get(status, 'UNKNOWN STATUS')

def generate_status_message(data: dict, storage_url: str | None, artifacts_url: str | None) -> str:
    status = data['status']
    counts = data['severity_counts']
    risk_score = data['risk_score']
    policy_ref = data.get('policy_reference', 'policies/severity-rules.rego')
    violations = data.get('violations', [])
    recommendations = data.get('recommendations', [])
    fragments = []

    if status == 'FAIL':
        fragments.append(
            f"{counts['CRITICAL']} critical and {counts['HIGH']} high severity findings are blocking a merge (risk score {risk_score})."
        )
    elif status == 'WARN':
        fragments.append(
            f"{counts['MEDIUM']} medium severity findings triggered a WARN state (risk score {risk_score})."
        )
    else:
        fragments.append(f"Status is PASS with risk score {risk_score}.")

    if violations:
        fragments.append(f"Violations: {', '.join(violations)}.")
    if recommendations:
        fragments.append(f"Automatic guidance: {', '.join(recommendations)}.")

    fragments.append(
        f"Consult `reports/evaluation.json` and `{policy_ref}` for the underlying data, and adjust thresholds if needed."
    )
    if storage_url:
        fragments.append(f"Reports are stored at {storage_url}.")
    elif artifacts_url:
        fragments.append(f"Workflow artifacts are available at {artifacts_url}.")

    return " ".join(fragments)

def generate_critical_high_details(findings: list) -> str:
    critical_high = [
        f for f in findings 
        if f['severity'] in ['CRITICAL', 'HIGH']
    ]
    
    if not critical_high:
        return "_No critical or high severity findings._"
    
    details = []
    for i, finding in enumerate(critical_high[:5], 1):
        details.append(f"""
**{i}. [{finding['severity']}] {finding['name']}**
- **Source:** {finding['source']}
- **Description:** {finding['description'][:150]}...
- **Solution:** {finding['solution'][:150]}...
""")
    
    if len(critical_high) > 5:
        details.append(f"\n_... and {len(critical_high) - 5} more. See full report in artifacts._")
    
    return '\n'.join(details)

def generate_recommendations(data: dict) -> str:
    severity_counts = data['severity_counts']
    recommendations = list(dict.fromkeys(data.get('recommendations', []) or []))
    risk_score = data['risk_score']
    medium_threshold = 3
    bullets = []

    if recommendations:
        bullets.extend(f"- {rec}" for rec in recommendations)
    else:
        if severity_counts['CRITICAL'] > 0 or severity_counts['HIGH'] > 0:
            bullets.append(
                "- Resolve the critical/high severity findings and rerun the scan to confirm they are gone."
            )
        if severity_counts['MEDIUM'] > 0:
            bullets.append(
                f"- Reduce the {severity_counts['MEDIUM']} medium findings keeping the risk score above {medium_threshold * 4} ({risk_score})."
            )
        if sum(severity_counts.values()) == 0:
            bullets.append("- Keep scanning on every change to catch regressions early.")

    bullets.append(
        "- Inspect `reports/evaluation.json` to understand which rule produced each recommendation."
    )
    bullets.append(
        "- Tune `configs/zap-config.conf`, `configs/nuclei-templates.yaml`, or `policies/severity-rules.rego` when findings are expected noise."
    )
    bullets.append(
        "- Harden the affected routes (request validation, auth checks, headers) and rerun the scan to collapse recurrent findings."
    )

    return '\n'.join(bullets)

def generate_artifact_summary(artifacts_url: str | None, storage_url: str | None) -> str:
    if storage_url:
        base = storage_url.rstrip('/')
        return (
            f"- [Download ZAP JSON]({base}/zap-report.json)\n"
            f"- [Download ZAP HTML]({base}/zap-report.html)\n"
            f"- [Download Nuclei JSON]({base}/nuclei-report.json)\n"
            f"- [Download OPA evaluation]({base}/evaluation.json)"
        )
    if artifacts_url:
        return (
            f"- [Open the workflow artifacts page]({artifacts_url}) (select the bundle for the latest run)\n"
            f"- ZAP report: `zap-report.json`, `zap-report.html` (on the artifacts page)\n"
            f"- Nuclei report: `nuclei-report.json`\n"
            f"- OPA evaluation: `evaluation.json`")
    return "- Full ZAP/Nuclei/evaluation artifacts are attached to the workflow run for deeper inspection."


def severity_weight(severity: str) -> int:
    return SEVERITY_MAP.get(severity.upper(), 0)


def generate_attack_surface(findings: list, limit: int = 5) -> str:
    clusters = {}
    for finding in findings:
        location = finding.get("location", "Unknown")
        severity = finding.get("severity", "INFO").upper()
        source = finding.get("source", finding.get("scanner", "Unknown"))
        key = (location, severity)
        entry = clusters.setdefault(key, {"count": 0, "scanners": set()})
        entry["count"] += 1
        entry["scanners"].add(source)

    sorted_clusters = sorted(
        clusters.items(),
        key=lambda item: (severity_weight(item[0][1]) * item[1]["count"], item[1]["count"]),
        reverse=True
    )

    lines = []
    for (location, severity), entry in sorted_clusters[:limit]:
        scanners = ", ".join(sorted(entry["scanners"]))
        lines.append(
            f"- `{location}` ({severity}) — {entry['count']} findings from {scanners}."
        )

    if not lines:
        return "_No attack surface highlights available._"

    return "\n".join(lines)


def load_tuning_data(path: str | None) -> dict | None:
    if not path:
        return None
    try:
        with open(path) as fh:
            return json.load(fh)
    except FileNotFoundError:
        return None


def generate_tuning_section(tuning_data: dict | None) -> str:
    if not tuning_data:
        return "- No automated tuning guidance is available yet."

    lines = [f"Generated at {tuning_data.get('generated_at', 'unknown')}"]
    top = tuning_data.get("top_findings", [])
    if not top:
        lines.append("- No high-frequency findings to tune.")
    else:
        for idx, entry in enumerate(top, 1):
            lines.append(
                f"- **{idx}.** {entry['source']} rule {entry['rule']} hit {entry['count']} times "
                f"(severity {entry['severity']})."
            )

    if tuning_data.get("violations"):
        lines.append("")
        lines.append("Violations:")
        lines.extend(f"- {v}" for v in tuning_data["violations"])
    if tuning_data.get("recommendations"):
        lines.append("")
        lines.append("Recommendations:")
        lines.extend(f"- {r}" for r in tuning_data["recommendations"])

    return "\n".join(lines)

def main():
    parser = argparse.ArgumentParser(description='Generate DAST report summary')
    parser.add_argument('--input', required=True, help='Evaluation JSON input')
    parser.add_argument('--output', required=True, help='Markdown output path')
    parser.add_argument('--artifacts-url', required=False, help='Optional URL where artifacts are available')
    parser.add_argument('--storage-url', required=False, help='Optional storage path where artifacts were uploaded')
    parser.add_argument('--tuning-json', required=False, help='Optional tuning helper JSON output')

    args = parser.parse_args()

    with open(args.input) as f:
        data = json.load(f)

    counts = data['severity_counts']
    tuning_data = load_tuning_data(args.tuning_json)
    report = TEMPLATE.format(
        app_name=data['app_name'],
        status_badge=generate_status_badge(data['status']),
        scan_date=datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC'),
        risk_score=data['risk_score'],
        critical=counts['CRITICAL'],
        high=counts['HIGH'],
        medium=counts['MEDIUM'],
        low=counts['LOW'],
        info=counts['INFO'],
        total=data['total_findings'],
        status_message=generate_status_message(data, args.storage_url, args.artifacts_url),
        critical_high_details=generate_critical_high_details(data['findings']),
        attack_surface=generate_attack_surface(data['findings']),
        recommendations=generate_recommendations(data),
        tuning_section=generate_tuning_section(tuning_data),
        artifact_summary=generate_artifact_summary(args.artifacts_url, args.storage_url)
    )

    with open(args.output, 'w') as f:
        f.write(report)

    print(f"Report generated: {args.output}")

if __name__ == '__main__':
    main()
