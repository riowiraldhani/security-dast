#!/usr/bin/env python3
"""Run a canonical data set against the current OPA policy to detect drift."""

import argparse
from pathlib import Path

from opa_utils import ensure_opa_binary, run_opa


def main():
    parser = argparse.ArgumentParser(description="Validate severity rules against canonical data.")
    parser.add_argument("--policy-dir", default="policies", help="Path to the policy directory")
    parser.add_argument("--input", default="policies/canonical-input.json", help="Canonical evaluation input")
    parser.add_argument("--expected-status", default="PASS", help="Expected status for the canonical dataset")
    parser.add_argument("--max-risk", type=int, default=5, help="Maximum acceptable risk score")
    parser.add_argument("--opa-version", default="latest", help="OPA release version")
    args = parser.parse_args()

    policy_dir = Path(args.policy_dir)
    if not policy_dir.is_dir():
        raise SystemExit(f"Policy directory does not exist: {policy_dir}")

    input_path = Path(args.input)
    if not input_path.is_file():
        raise SystemExit(f"Canonical input not found: {input_path}")

    cache_dir = Path("reports/.opa-health-cache")
    cache_dir.mkdir(parents=True, exist_ok=True)
    opa_binary = ensure_opa_binary(cache_dir, args.opa_version)
    evaluation = run_opa(opa_binary, input_path, policy_dir)

    status = evaluation.get("status")
    risk = evaluation.get("risk_score", 0)

    print(f"Policy health check status: {status}, risk score: {risk}")
    if status != args.expected_status:
        raise SystemExit(f"Unexpected policy status: {status} (expected {args.expected_status})")

    if risk > args.max_risk:
        raise SystemExit(f"Risk score {risk} exceeded max allowed {args.max_risk}")

    print("Policy health check passed.")


if __name__ == "__main__":
    main()
