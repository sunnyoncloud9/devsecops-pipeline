"""
DevSecOps Pipeline — Security Gate
Aggregates results from all scan stages and enforces policy.
Author: Sunny Bhardwaj
GitHub: https://github.com/sunnyoncloud9/devsecops-pipeline
"""

import json
import sys
from pathlib import Path


# Gate thresholds
THRESHOLDS = {
    "CRITICAL": 0,
    "HIGH": 5,
}


def load_json(path: Path):
    """Safely load a JSON file — returns empty dict if missing or invalid."""
    if not path.exists():
        print(f"  [!] Report not found, skipping: {path.name}")
        return {}
    try:
        with open(path) as f:
            return json.load(f)
    except (json.JSONDecodeError, Exception) as e:
        print(f"  [!] Could not parse {path.name}: {e}")
        return {}


def parse_bandit(data: dict) -> tuple[int, int]:
    """Parse Bandit SAST results."""
    critical, high = 0, 0
    for issue in data.get("results", []):
        severity = issue.get("issue_severity", "").upper()
        if severity == "CRITICAL":
            critical += 1
        elif severity == "HIGH":
            high += 1
    return critical, high


def parse_pip_audit(data: dict) -> tuple[int, int]:
    """Parse pip-audit SCA results."""
    critical, high = 0, 0
    deps = data.get("dependencies", data if isinstance(data, list) else [])
    for dep in deps:
        for vuln in dep.get("vulns", []):
            severity = vuln.get("severity", "").upper()
            if severity == "CRITICAL":
                critical += 1
            elif severity == "HIGH":
                high += 1
    return critical, high


def parse_trivy(data: dict) -> tuple[int, int]:
    """Parse Trivy container scan results (SARIF format)."""
    critical, high = 0, 0
    for run in data.get("runs", []):
        for result in run.get("results", []):
            level = result.get("level", "")
            if level == "error":
                high += 1
    return critical, high


def parse_checkov(data: dict) -> tuple[int, int]:
    """Parse Checkov IaC scan results."""
    critical, high = 0, 0
    results_list = data if isinstance(data, list) else [data]
    for result_set in results_list:
        failed = result_set.get("results", {}).get("failed_checks", [])
        for check in failed:
            severity = check.get("severity", "MEDIUM")
            if isinstance(severity, str):
                severity = severity.upper()
                if severity == "CRITICAL":
                    critical += 1
                elif severity == "HIGH":
                    high += 1
    return critical, high


def main(reports_dir: str):
    reports = Path(reports_dir)

    print("=" * 60)
    print("🚦 SECURITY GATE EVALUATION")
    print("=" * 60)

    # Parse all reports
    parsers = [
        ("Bandit (SAST)",      parse_bandit,    reports / "bandit.json"),
        ("pip-audit (SCA)",    parse_pip_audit, reports / "pip-audit.json"),
        ("Trivy (Container)",  parse_trivy,     reports / "trivy-results.sarif"),
        ("Checkov (IaC)",      parse_checkov,   reports / "checkov.json"),
    ]

    total_critical, total_high = 0, 0
    for name, parser, path in parsers:
        data = load_json(path)
        if data:
            c, h = parser(data)
            total_critical += c
            total_high += h
            print(f"  [+] {name}: CRITICAL={c}, HIGH={h}")
        else:
            print(f"  [-] {name}: no data")

    # Summary
    print()
    print("📊 Aggregated Findings:")
    print(f"  CRITICAL : {total_critical}")
    print(f"  HIGH     : {total_high}")
    print()

    # Gate evaluation
    passed = True
    if total_critical > THRESHOLDS["CRITICAL"]:
        print(f"❌ FAIL: {total_critical} critical findings — threshold is {THRESHOLDS['CRITICAL']}")
        passed = False

    if total_high > THRESHOLDS["HIGH"]:
        print(f"❌ FAIL: {total_high} high findings — threshold is {THRESHOLDS['HIGH']}")
        passed = False

    print("=" * 60)
    if passed:
        print("✅ SECURITY GATE PASSED")
    else:
        print("🛑 SECURITY GATE FAILED — review findings before merging")
    print("=" * 60)

    sys.exit(0 if passed else 1)


if __name__ == "__main__":
    reports_dir = sys.argv[1] if len(sys.argv) > 1 else "reports"
    main(reports_dir)
