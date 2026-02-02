package dast.evaluation

critical_count := count([f | f := input.findings[_]; f.severity == "CRITICAL"])
high_count := count([f | f := input.findings[_]; f.severity == "HIGH"])
medium_count := count([f | f := input.findings[_]; f.severity == "MEDIUM"])
low_count := count([f | f := input.findings[_]; f.severity == "LOW"])
info_count := count([f | f := input.findings[_]; f.severity == "INFO"])

severity_counts := {
    "CRITICAL": critical_count,
    "HIGH": high_count,
    "MEDIUM": medium_count,
    "LOW": low_count,
    "INFO": info_count
}

risk_score := critical_count * 10 +
              high_count * 7 +
              medium_count * 4 +
              low_count * 2 +
              info_count * 1

default status := "FAIL"

status := "FAIL" if {
    critical_count > 0
}

status := "FAIL" if {
    high_count > 0
}

status := "WARN" if {
    critical_count == 0
    high_count == 0
    medium_count > 3
}

status := "WARN" if {
    critical_count == 0
    high_count == 0
    medium_count > 0
    medium_count <= 3
    risk_score > 15
}

status := "PASS" if {
    critical_count == 0
    high_count == 0
    medium_count <= 3
    risk_score <= 15
}

violation contains msg if {
    critical_count > 0
    msg := sprintf("Found %d CRITICAL severity findings", [critical_count])
}

violation contains msg if {
    high_count > 0
    msg := sprintf("Found %d HIGH severity findings", [high_count])
}

violation contains msg if {
    medium_count > 3
    msg := sprintf("Found %d MEDIUM severity findings (threshold: 3)", [medium_count])
}

recommendation contains msg if {
    critical_count > 0
    msg := "Immediately address all CRITICAL vulnerabilities"
}

recommendation contains msg if {
    high_count > 0
    msg := "Prioritize remediation of HIGH severity issues"
}

recommendation contains msg if {
    medium_count > 3
    msg := "Plan to reduce MEDIUM severity findings below policy thresholds"
}

recommendation contains msg if {
    status == "PASS"
    msg := "Continue maintaining the current security posture"
}

recommendations := [msg | recommendation[msg]]
violations := [msg | violation[msg]]

evaluation := {
    "status": status,
    "risk_score": risk_score,
    "severity_counts": severity_counts,
    "critical_count": critical_count,
    "high_count": high_count,
    "medium_count": medium_count,
    "low_count": low_count,
    "info_count": info_count,
    "total_findings": count(input.findings),
    "recommendations": recommendations,
    "violations": violations
}