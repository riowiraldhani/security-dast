#!/usr/bin/env python3
"""Create tuning guidance from the latest DAST evaluation."""

import argparse
import json
from collections import Counter
from datetime import datetime


def flatten_findings(findings):
    flattened = []
    for finding in findings:
        source = finding.get("scanner") or finding.get("source", "Unknown")
        rule = finding.get("rule_id") or finding.get("template_id") or finding.get("name")
        key = f"{source}:{rule}"
        flattened.append({
            "key": key,
            "source": source,
            "name": finding.get("name", "Unknown"),
            "rule": rule,
            "severity": finding.get("severity", "INFO"),
            "location": finding.get("location") or finding.get("matched_at") or "Unknown",
            "description": finding.get("description", ""),
        })
    return flattened


def summarize_findings(findings, limit):
    counter = Counter()
    details = {}
    for finding in findings:
        counter[finding["key"]] += 1
        details.setdefault(finding["key"], finding)

    summary = []
    for key, count in counter.most_common(limit):
        record = details[key]
        summary.append({
            "source": record["source"],
            "rule": record["rule"],
            "name": record["name"],
            "count": count,
            "severity": record["severity"],
            "location": record["location"],
            "description": record["description"],
        })
    return summary


def build_suggestions(top_findings):
    suggestions = []
    for record in top_findings:
        base = (
            f"{record['source']} rule {record['rule']} ({record['name']}) "
            f"triggered {record['count']} times at {record['location']}."
        )
        scanner = record["source"].lower()
        if scanner == "zap":
            base += " Consider adjusting `configs/zap-config.conf` (IGNORE/WARN/FAIL) or adding a suppression."
        elif scanner == "nuclei":
            base += " Refine `configs/nuclei-templates.yaml` to align template selection with this endpoint."
        else:
            base += " Review whether this finding can be tuned or requires further investigation."
        suggestions.append(base)
    return suggestions


def format_markdown(suggestions, evaluation, timestamp):
    lines = [f"### Automated tuning guidance (generated {timestamp})", ""]
    if suggestions:
        for idx, suggestion in enumerate(suggestions, 1):
            lines.append(f"- **{idx}.** {suggestion}")
    else:
        lines.append("- No recurring findings detected; keep the baseline config as-is.")

    if evaluation.get("violations"):
        lines.append("")
        lines.append("**Recent violations:**")
        for violation in evaluation["violations"]:
            lines.append(f"- {violation}")

    if evaluation.get("recommendations"):
        lines.append("")
        lines.append("**Policy recommendations:**")
        for rec in evaluation["recommendations"]:
            lines.append(f"- {rec}")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Generate tuning guidance from evaluation output.")
    parser.add_argument("--input", required=True, help="Evaluation JSON path")
    parser.add_argument("--output", required=True, help="Markdown summary output path")
    parser.add_argument("--json", required=True, help="JSON summary output path")
    parser.add_argument("--limit", type=int, default=3, help="Top findings to highlight")
    args = parser.parse_args()

    with open(args.input) as fh:
        evaluation = json.load(fh)

    findings = flatten_findings(evaluation.get("findings", []))
    top_findings = summarize_findings(findings, args.limit)
    suggestions = build_suggestions(top_findings)
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    markdown = format_markdown(suggestions, evaluation, timestamp)

    summary_data = {
        "generated_at": timestamp,
        "top_findings": top_findings,
        "violations": evaluation.get("violations", []),
        "recommendations": evaluation.get("recommendations", []),
    }

    with open(args.output, "w") as fh:
        fh.write(markdown)

    with open(args.json, "w") as fh:
        json.dump(summary_data, fh, indent=2)

    print(f"Tuning guidance written to {args.output} and {args.json}")


if __name__ == "__main__":
    main()
