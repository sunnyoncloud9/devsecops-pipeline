"""
DevSecOps Pipeline — Security Gate
Aggregates results from all security scanning stages and decides
whether the pipeline should pass or fail based on severity thresholds.

Author: Sunny Bhardwaj
GitHub: https://github.com/sunnyoncloud9/devsecops-pipeline
"""

import json
import os
import sys
import glob


# Severity thresholds — pipeline fails if these are exceeded
THRESHOLDS = {
    "CRITICAL": 0,   # Zero critical findings allowed
    "HIGH": 5,       # Up to 5 high findings tolerated
}


def evaluate_gate(reports_dir: str) -> bool:
    """
    Evaluate all security reports and determine pass/fail.
    Returns True if pipeline passes, False otherwise.
    """
    print("=" * 60)
    print("🚦 SECURITY GATE EVALUATION")
    print("=" * 60)

    findings = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
    }

    # Parse Bandit results
    findings = _parse_bandit(reports_dir, findings)

    # Parse pip-audit results
    findings = _parse_pip_audit(reports_dir, findings)

    # Parse Trivy results
    findings = _parse_trivy(reports_dir, findings)

    # Parse Checkov results
    findings = _parse_checkov(reports_dir, findings)

    # Print summary
    print("\n📊 Aggregated Findings:")
    print(f"  CRITICAL : {findings['CRITICAL']}")
    print(f"  HIGH     : {findings['HIGH']}")
    print(f"  MEDIUM   : {findings['MEDIUM']}")
    print(f"  LOW      : {findings['LOW']}")
    print()

    # Evaluate against thresholds
    passed = True
    if findings["CRITICAL"] > THRESHOLDS["CRITICAL"]:
        print(f"❌ FAIL: {findings['CRITICAL']} critical findings exceed threshold of {THRESHOLDS['CRITICAL']}")
        passed = False

    if findings["HIGH"] > THRESHOLDS["HIGH"]:
        print(f"❌ FAIL: {findings['HIGH']} high findings exceed threshold of {THRESHOLDS['HIGH']}")
        passed = False

    print("=" * 60)
    if passed:
        print("✅ SECURITY GATE PASSED")
    else:
        print("🛑 SECURITY GATE FAILED — review findings before merging")
    print("=" * 60)

    return passed


def _parse_bandit(reports_dir: str, findings: dict) -> dict:
    """Parse Bandit SAST results."""
    for path in glob.glob(f"{reports_dir}/**/bandit.json", recursive=True):
        try:
            with open(path) as f:
                data = json.load(f)
            for result in data.get("results", []):
                severity = result.get("issue_severity", "LOW").upper()
                if severity in findings:
                    findings[severity] += 1
            print(f"  [+] Parsed Bandit: {path}")
        except Exception as e:
            print(f"  [!] Could not parse {path}: {e}")
    return findings


def _parse_pip_audit(reports_dir: str, findings: dict) -> dict:
    """Parse pip-audit SCA results."""
    for path in glob.glob(f"{reports_dir}/**/pip-audit.json", recursive=True):
        try:
            with open(path) as f:
                data = json.load(f)
            # pip-audit lists dependencies with vulnerabilities
            deps = data.get("dependencies", data if isinstance(data, list) else [])
            for dep in deps:
                vulns = dep.get("vulns", [])
                # Treat each vulnerability as HIGH by default
                findings["HIGH"] += len(vulns)
            print(f"  [+] Parsed pip-audit: {path}")
        except Exception as e:
            print(f"  [!] Could not parse {path}: {e}")
    return findings


def _parse_trivy(reports_dir: str, findings: dict) -> dict:
    """Parse Trivy container scan results (SARIF format)."""
    for path in glob.glob(f"{reports_dir}/**/trivy-results.sarif", recursive=True):
        try:
            with open(path) as f:
                data = json.load(f)
            for run in data.get("runs", []):
                for result in run.get("results", []):
                    level = result.get("level", "warning")
                    # SARIF levels: error = HIGH/CRITICAL, warning = MEDIUM
                    if level == "error":
                        findings["HIGH"] += 1
                    elif level == "warning":
                        findings["MEDIUM"] += 1
            print(f"  [+] Parsed Trivy: {path}")
        except Exception as e:
            print(f"  [!] Could not parse {path}: {e}")
    return findings


def _parse_checkov(reports_dir: str, findings: dict) -> dict:
    """Parse Checkov IaC scan results."""
    for path in glob.glob(f"{reports_dir}/**/checkov.json", recursive=True):
        try:
            with open(path) as f:
                data = json.load(f)
            # Checkov output can be a list or dict
            results_list = data if isinstance(data, list) else [data]
            for result_set in results_list:
                failed = result_set.get("results", {}).get("failed_checks", [])
                for check in failed:
                    severity = check.get("severity", "MEDIUM")
                    severity = severity.upper() if severity else "MEDIUM"
                    if severity in findings:
                        findings[severity] += 1
                    else:
                        findings["MEDIUM"] += 1
            print(f"  [+] Parsed Checkov: {path}")
        except Exception as e:
            print(f"  [!] Could not parse {path}: {e}")
    return findings


if __name__ == "__main__":
    reports_dir = sys.argv[1] if len(sys.argv) > 1 else "all-reports"
    passed = evaluate_gate(reports_dir)
    sys.exit(0 if passed else 1)
