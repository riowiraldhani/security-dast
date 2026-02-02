"""OPA helper utilities shared by evaluation scripts."""

import json
import os
import platform
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path


def ensure_opa_binary(cache_dir: Path, version: str) -> Path:
    env_override = os.getenv("OPA_BINARY")
    if env_override:
        override_path = Path(env_override)
        if override_path.exists():
            return override_path

    which_opa = shutil.which("opa")
    if which_opa:
        return Path(which_opa)

    cache_dir.mkdir(parents=True, exist_ok=True)
    system = platform.system().lower()
    arch_map = {
        "x86_64": "amd64",
        "amd64": "amd64",
        "aarch64": "arm64",
        "arm64": "arm64"
    }
    arch = arch_map.get(platform.machine().lower(), platform.machine().lower())

    binary_path = cache_dir / "opa"
    if binary_path.exists():
        binary_path.chmod(0o755)
        return binary_path

    if version == "latest":
        url = f"https://openpolicyagent.org/downloads/latest/opa_{system}_{arch}"
    else:
        url = f"https://openpolicyagent.org/downloads/v{version}/opa_{system}_{arch}"

    print(f"Downloading OPA from {url}")
    try:
        with urllib.request.urlopen(url) as resp, binary_path.open("wb") as out:
            out.write(resp.read())
    except Exception as exc:  # pragma: no cover - network issues
        print("Failed to download OPA binary:", exc, file=sys.stderr)
        raise

    binary_path.chmod(0o755)
    return binary_path


def run_opa(opa_path: Path, input_path: Path, policy_dir: Path) -> dict:
    cmd = [
        str(opa_path),
        "eval",
        "--format",
        "json",
        "--input",
        str(input_path),
        "--data",
        str(policy_dir),
        "data.dast.evaluation"
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as exc:
        print("OPA evaluation failed")
        print("Command:", exc.cmd)
        print("Return code:", exc.returncode)
        if exc.stdout:
            print("OPA stdout:", exc.stdout)
        if exc.stderr:
            print("OPA stderr:", exc.stderr, file=sys.stderr)
        raise
    payload = result.stdout
    if not payload:
        raise RuntimeError("OPA did not return output")

    parsed = json.loads(payload)
    expressions = parsed.get("result", [])
    if not expressions:
        raise RuntimeError("OPA did not return an evaluation result")

    exprs = expressions[0].get("expressions", [])
    if not exprs:
        raise RuntimeError("OPA response is missing expressions")

    evaluation = exprs[0].get("value", {})
    return evaluation
