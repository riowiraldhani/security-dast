#!/usr/bin/env python3
"""Aggregate DAST findings and let OPA decide on PASS/WARN/FAIL."""

import argparse
import json
import os
from datetime import datetime
from pathlib import Path

from opa_utils import ensure_opa_binary, run_opa


def parse_zap_report(report_path: Path):
    if not report_path.exists():
        return []

    with report_path.open() as fh:
        data = json.load(fh)

    findings = []
    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            severity = alert.get("riskdesc", "INFO").split()[0].upper()
            instances = alert.get("instances", [])
            first_instance = instances[0] if instances else {}
            location = first_instance.get("uri") or first_instance.get("requestHeader")
            findings.append({
                "source": "ZAP",
                "name": alert.get("name", "Unknown"),
                "severity": severity,
                "description": alert.get("desc", ""),
                "solution": alert.get("solution", ""),
                "instances": len(instances),
                "location": location or "Unknown",
                "rule_id": alert.get("pluginId") or alert.get("pluginid"),
                "confidence": alert.get("confidence"),
                "scanner": "ZAP"
            })

    return findings


def parse_nuclei_report(report_path: Path):
    if not report_path.exists():
        return []

    findings = []
    with report_path.open() as fh:
        raw = fh.read().strip()
        if not raw:
            return findings

        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            fh.seek(0)
            entries = []
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        else:
            entries = payload if isinstance(payload, list) else [payload]

    for entry in entries:
        if not isinstance(entry, dict):
            continue

        info = entry.get("info", {})
        severity = info.get("severity", "info").upper()
        location = entry.get("matched-at") or entry.get("host") or info.get("reference", [None])[0]
        findings.append({
            "source": "Nuclei",
            "name": info.get("name", "Unknown"),
            "severity": severity,
            "description": info.get("description", ""),
            "solution": info.get("remediation", "Review and patch"),
            "matched_at": entry.get("matched-at", ""),
            "location": location or "Unknown",
            "template_id": info.get("id") or entry.get("template-id"),
            "scanner": "Nuclei"
        })

    return findings


def main():
    parser = argparse.ArgumentParser(description="Aggregate findings and evaluate against OPA policies")
    parser.add_argument("--app-name", required=True, help="Application name for the run")
    parser.add_argument("--zap-report", required=True, type=Path, help="Path to ZAP JSON report")
    parser.add_argument("--nuclei-report", required=True, type=Path, help="Path to Nuclei JSON report")
    parser.add_argument("--output", required=True, type=Path, help="JSON file that stores the final evaluation")
    parser.add_argument("--opa-version", default=os.getenv("OPA_VERSION", "latest"), help="OPA release tag to download or use (default: latest)")
    parser.add_argument("--policy-dir", default=str(Path(__file__).resolve().parent.parent / "policies"), help="Directory containing OPA policies")

    args = parser.parse_args()
    cache_dir = args.output.parent / ".opa-cache"

    findings = parse_zap_report(args.zap_report)
    findings.extend(parse_nuclei_report(args.nuclei_report))

    input_payload = {
        "app_name": args.app_name,
        "findings": findings
    }
    input_path = args.output.parent / "dast-input.json"
    input_path.parent.mkdir(parents=True, exist_ok=True)
    with input_path.open("w") as fh:
        json.dump(input_payload, fh, indent=2)

    policy_dir = Path(args.policy_dir)
    if not policy_dir.is_dir():
        raise SystemExit(f"Policy directory does not exist: {policy_dir}")
    print(f"Using policy directory: {policy_dir}")
    opa_binary = ensure_opa_binary(cache_dir, args.opa_version)
    evaluation = run_opa(opa_binary, input_path, policy_dir)

    final_output = {
        "app_name": args.app_name,
        "status": evaluation.get("status", "FAIL"),
        "risk_score": evaluation.get("risk_score", 0),
        "severity_counts": evaluation.get("severity_counts", {}),
        "total_findings": len(findings),
        "findings": findings,
        "violations": evaluation.get("violations", []),
        "recommendations": evaluation.get("recommendations", []),
        "policy_reference": str(policy_dir / "severity-rules.rego"),
        "analysis_time": datetime.utcnow().isoformat() + "Z"
    }

    with args.output.open("w") as fh:
        json.dump(final_output, fh, indent=2)

    print(f"Evaluation complete: {final_output['status']}")
    print(f"Risk score: {final_output['risk_score']}")
    print(f"Input payload: {input_path}")
    print(f"Policy reference: {final_output['policy_reference']}")


if __name__ == "__main__":
    main()
