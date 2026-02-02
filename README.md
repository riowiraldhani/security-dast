# Security DAST – Centralized Dynamic Application Security Testing

Security DAST keeps scanner binaries, tuning files, and policy logic in one repo so that every application repository can call a reusable workflow instead of reinstalling OWASP ZAP, Nuclei, or OPA. You get consistent PASS/WARN/FAIL decisions, human-readable PR summaries, and auditable artifacts uploaded to your S3/MinIO bucket every time a pull request triggers a scan.

## Key capabilities
- **Shared scan stack:** `scripts/zap-baseline.sh` and `scripts/nuclei-scan.sh` bundle the scanner invocations, configs, and output parsing so callers only need to pass `app_name` + `target_url`.
- **OPA-powered policy:** `scripts/risk-evaluator.py` feeds the findings to Open Policy Agent (binary downloaded from `openpolicyagent.org` by default) and evaluates `policies/severity-rules.rego` to produce severity counts, risk score, violations, and recommendations.
- **Actionable summaries:** `scripts/report-generator.py` builds the Markdown comment shown on every PR, including “What should happen now?”, “Recommended next steps”, attack surface highlights, and direct artifact download links.
- **Automated tuning helpers:** `scripts/tuning-helper.py` analyzes `reports/evaluation.json` and surfaces the highest-frequency violations (with Markdown/JSON outputs) so teams can tune `configs/zap-config.conf`, `configs/nuclei-templates.yaml`, or the policy sooner.
- **Regression guard:** `scripts/regression-guard.py` compares the current risk score with the previous value saved in S3 (`.../latest/evaluation.json`) and fails the job if the delta exceeds your tolerance.
- **Policy health checks:** `.github/workflows/policy-health.yml` runs `scripts/policy-health.py` on a schedule or demand to ensure policy changes don’t unexpectedly flip PASS/WARN semantics.
- **Validation helpers:** `scripts/validate-config.sh` confirms the required configs and scripts exist, linting each Python helper and setting shell scripts executable.

## Repository layout

| Area | Responsibility |
| --- | --- |
| `.github/workflows/reusable-dast.yml` | The callable workflow that orchestrates ZAP, Nuclei, OPA evaluation, artifact uploads, report generation, and PR comments. |
| `configs/` | Scanner tuning: `zap-config.conf` is a tab-delimited list of rule overrides, `nuclei-templates.yaml` limits templates to the categories you care about, and rate limits keep scans stable. |
| `scripts/` | Helpers for running scanners, evaluating results, building summaries, tuning noise, checking regressions, validating policy health, and a config checker. |
| `policies/` | OPA policy definitions (`severity-rules.rego`) and supporting canonical input data used for policy health checks. |
| `reports/` | Runtime output production folder (scans, evaluation, tuning data, storage links). |

## How to integrate Security DAST
1. **Make your target reachable:** GitHub Actions runners must access `target_url` (HTTPS is typical). Whitelist their IPs if your app sits behind a firewall.  
2. **Add a workflow in your repo:** Call `riowiraldhani/security-dast/.github/workflows/reusable-dast.yml@master` from your workflow YAML, passing at least `app_name` and `target_url`. Optional inputs include `scan_timeout`, `nuclei_version`, `nuclei_severity`, `opa_version`, and `policy_dir`.  
3. **Set the required secrets:** Add `GH_TOKEN` (scopes: `contents: read`, `issues: write`, `pull-requests: write`), plus `S3_ACCESS_KEY`, `S3_SECRET_KEY`, and `S3_ENDPOINT` so the workflow can push artifacts into `security-dast/<app_name>/<run_id>/`.  
4. **Read the PR comment:** After each run you get a Markdown summary with verdict, findings, suggested next steps, attack-surface highlights, and storage URLs pointing to your object store.  
5. **Reuse the same setup:** Each repo benefits from the validated tooling here, so there is no need to copy/paste individual scanners or policy files.

### Reusable workflow inputs

| Input | Required | Purpose |
| --- | --- | --- |
| `app_name` | yes | Friendly name that appears in summaries, artifact folders, and S3 paths. |
| `target_url` | yes | The URL scanned by ZAP and Nuclei. |
| `scan_timeout` | no | Seconds before ZAP stops (default 600). |
| `nuclei_version` | no | Nuclei release binary (default `3.7.0`). |
| `nuclei_severity` | no | Comma-delimited severities passed to Nuclei (default `critical,high,medium`). |
| `opa_version` | no | Release tag downloaded from `openpolicyagent.org` (default `latest`). |
| `policy_dir` | no | Directory containing `severity-rules.rego`; defaults to this repo’s `policies`. |

### Secrets
- `GH_TOKEN` (required) – used by `actions/github-script` to post PR comments.  
- `S3_ACCESS_KEY`, `S3_SECRET_KEY`, `S3_ENDPOINT` (all required) – credentials for the object store (S3 or MinIO) where ZAP/Nuclei/evaluation/tuning artifacts are uploaded.

### Sample caller workflow (`.github/workflows/security-scan.yml`)
```yaml
name: Security DAST Scan

on:
  pull_request:
    branches:
      - master
  push:
    branches:
      - master

permissions:
  contents: read
  pull-requests: write
  issues: write

jobs:
  dast:
    uses: riowiraldhani/security-dast/.github/workflows/reusable-dast.yml@master
    with:
      app_name: app-name
      target_url: url-app-name
    secrets:
      GH_TOKEN: ${{ secrets.GH_TOKEN }}
      S3_ACCESS_KEY: ${{ secrets.S3_ACCESS_KEY }}
      S3_SECRET_KEY: ${{ secrets.S3_SECRET_KEY }}
      S3_ENDPOINT: ${{ secrets.S3_ENDPOINT }}
```

## Workflow flow
1. **ZAP Baseline scan:** `scripts/zap-baseline.sh` hits the target, produces JSON/HTML, and stages reports under `reports/zap/`.  
2. **Nuclei scan:** `scripts/nuclei-scan.sh` downloads the configured Nuclei binary, refreshes templates, and emits JSON/Markdown stats.  
3. **OPA evaluation:** `scripts/risk-evaluator.py` merges findings, downloads the public OPA binary (default `opa_version: latest`), and evaluates `policies/severity-rules.rego` to determine status, risk score, severity counts, violations, and recommendations. You can point `--policy-dir` at any other folder as long as it exposes the expected evaluation keys.  
4. **Tuning guidance:** `scripts/tuning-helper.py` reads `reports/evaluation.json` and outputs Markdown/JSON that highlights the most common violations, helping teams refine configs or suppress known noise.  
5. **Regression guard:** `scripts/regression-guard.py` compares the current risk score with `security-dast/<app_name>/latest/evaluation.json` and fails the job if the delta exceeds the threshold (prevents surprising regressions).  
6. **Artifact uploads:** The workflow pushes ZAP, Nuclei, evaluation, and tuning artifacts into `security-dast/<app_name>/<run_id>/` plus updates the `latest` pointer.  
7. **Summary comment:** `scripts/report-generator.py` builds the Markdown summary; `actions/github-script` posts it to the PR along with storage links.  
8. **Policy health checks:** `.github/workflows/policy-health.yml` runs `scripts/policy-health.py` to ensure the policy still returns the expected status/risk for canonical input after every change.

## Customization & policy notes
- **Scanner configs:** Tune `configs/zap-config.conf` and `configs/nuclei-templates.yaml` to match your surface; each is documented inside the file with instructions on using WARN/FAIL annotations and category filters.  
- **Policy tuning:** `policies/severity-rules.rego` defines severity thresholds and risk weights; edit it to shift PASS/WARN/FAIL gates, add new violations/recommendations, or map extra severity labels.  
- **Alternate policies:** Provide a different `policy_dir` (even from another repo or a public policy set) as long as it defines `package dast.evaluation` and emits the expected structure (`status`, `risk_score`, `severity_counts`, `recommendations`, `violations`).
- **OPA binary:** Binary is downloaded from `https://openpolicyagent.org/downloads/`; there is no internal binary dependency unless you override `--opa-version` with a custom build.
- **Validation helpers:** Run `scripts/validate-config.sh` to confirm YAML syntax, Python scripts, and shell permissions before trusting a run.

## Artifacts & auditing
- Each run uploads: `zap-report.json`, `zap-report.html`, `nuclei-report.json`, `evaluation.json`, `tuning-suggestions.md`, `tuning-suggestions.json`, plus the `latest/evaluation.json` pointer.  
- The PR comment includes direct URLs into your bucket so reviewers can download specific reports without hunting through GitHub Actions artifacts.  
- Keep the `${bucket}/security-dast/<app_name>/<run_id>/` structure consistent so auditors can trace findings to a date/time and request.  

## Next steps
1. Copy the sample workflow, adjust `app_name`/`target_url`, and add the secrets in your repo.  
2. Trigger a pull request; the comment will show the verdict, counts, risk score, attack surface notes, and tuned recommendations.  
3. Use the tuning helper outputs to update `configs/` or `policies/`, rerun scans, and verify that the `regression guard` keeps your risk score in check.
4. Run `scripts/validate-config.sh` whenever you update configs/policies to ensure everything continues to parse cleanly.

Need help wiring this into your repos or tweaking the policy? Drop in a follow-up question and I’ll walk you through it.
