#!/usr/bin/env python3
"""Compare risk scores to detect regressions between runs."""

import argparse
import json
import sys


def load_eval(path):
    with open(path) as fh:
        return json.load(fh)


def main():
    parser = argparse.ArgumentParser(description="Guard against risk score regressions.")
    parser.add_argument("--current", required=True, help="Current evaluation JSON")
    parser.add_argument("--previous", required=True, help="Previous evaluation JSON (optional)")
    parser.add_argument("--threshold", type=int, default=5, help="Allowed risk score increase")
    args = parser.parse_args()

    current = load_eval(args.current)
    try:
        previous = load_eval(args.previous)
    except FileNotFoundError:
        print("No previous evaluation found, skipping regression check.")
        return

    current_score = current.get("risk_score", 0)
    previous_score = previous.get("risk_score", 0)
    severity_delta = current_score - previous_score

    print(f"Current risk score: {current_score}, previous: {previous_score}, delta: {severity_delta}")
    if severity_delta > args.threshold:
        print(
            f"Risk score increased by {severity_delta} which exceeds the threshold of {args.threshold}."
        )
        sys.exit(1)

    print("Regression guard passed.")


if __name__ == "__main__":
    main()
