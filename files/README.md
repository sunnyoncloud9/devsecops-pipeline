# 🛡️ DevSecOps Pipeline

> **A complete security-integrated CI/CD pipeline — shift-left security across the full SDLC**

[![DevSecOps Pipeline](https://github.com/sunnyoncloud9/devsecops-pipeline/actions/workflows/devsecops.yml/badge.svg)](https://github.com/sunnyoncloud9/devsecops-pipeline/actions/workflows/devsecops.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## 📌 Overview

This project implements a production-grade **DevSecOps pipeline** that embeds security at every stage of the software delivery lifecycle. Every commit is automatically scanned for vulnerable code, vulnerable dependencies, leaked secrets, insecure container images, and misconfigured infrastructure — and the build is **blocked** if critical issues are found.

The goal is to demonstrate **shift-left security**: catching problems in CI before they ever reach production.

---

## 📸 Pipeline in Action

### All Scanning Stages Passing
![Security Gate Logs](images/gate-logs.png)

### Pipeline Run Overview
![Pipeline Failure](images/failure.png)

---

## 🔧 Pipeline Stages

| Stage | Tool | What it catches |
|-------|------|-----------------|
| **SAST** | Bandit, Semgrep | Insecure code patterns, injection flaws |
| **SCA** | pip-audit, Safety | Vulnerable dependencies (CVEs) |
| **Secret Scanning** | Gitleaks, detect-secrets | Hardcoded API keys, tokens, passwords |
| **Container Scanning** | Trivy | Vulnerable OS packages in images |
| **IaC Scanning** | Checkov | Misconfigured Terraform resources |
| **Security Gate** | Custom Python | Aggregates results, enforces policy |

---

## 🏗️ Architecture

```
Developer pushes code
        │
        ▼
┌─────────────────────────────────────────────┐
│           GitHub Actions Pipeline            │
│                                              │
│  SAST ──┐                                   │
│  SCA ───┤                                   │
│  Secrets┤──→ Security Gate ──→ Pass / Fail  │
│  Docker ┤                                   │
│  IaC ───┘                                   │
└─────────────────────────────────────────────┘
```

---

## 🚦 Security Gate Policy

The gate (`scripts/security_gate.py`) enforces:

- **CRITICAL findings:** `0` allowed — any critical finding fails the build
- **HIGH findings:** up to `5` tolerated — exceeding this fails the build

```python
if critical > 0:
    print("❌ Critical vulnerabilities found")
    sys.exit(1)

if high > 5:
    print("❌ Too many high vulnerabilities")
    sys.exit(1)

print("✅ Security gate passed")
```

---

## 💥 Example Failure Scenario

A developer introduces a vulnerable dependency:

1. Code passes SAST ✅
2. Dependency scan detects CVE ✅
3. Security Gate evaluates all findings
4. Build **fails** — insecure code blocked before deployment ❌

---

## 🔐 Security Practices in the Sample App

- Secrets loaded from environment variables — never hardcoded
- Non-root container user — principle of least privilege
- Pinned base image — `python:3.11-slim`, not `latest`
- Production WSGI server — gunicorn, not Flask dev server
- Input validation on all endpoints
- S3 encryption, versioning, and public-access blocks in Terraform
- Least-privilege security groups — HTTPS only

---

## 📁 Project Structure

```
devsecops-pipeline/
├── .github/workflows/
│   └── devsecops.yml          # Full pipeline definition
├── sample-app/
│   ├── app.py                 # Hardened Flask app
│   ├── requirements.txt
│   └── Dockerfile             # Non-root hardened container
├── iac/
│   └── main.tf                # Secure-by-default Terraform
├── scripts/
│   ├── security_gate.py       # Aggregates results, enforces policy
│   └── report.py              # Generates PDF security report
├── tests/
│   └── test_security_gate.py  # Unit tests
├── images/
│   ├── failure.png
│   └── gate-logs.png
└── README.md
```

---

## 🚀 Running Locally

```bash
# Run the security gate
python scripts/security_gate.py ./reports

# Generate PDF report
python scripts/report.py ./reports

# Run unit tests
python -m unittest discover tests/

# Build and run the sample app
docker build -t sample-app ./sample-app
docker run -p 5000:5000 sample-app
```

---

## 🗺️ Roadmap

- [ ] DAST stage (dynamic scanning of the running app)
- [ ] SBOM generation (CycloneDX)
- [ ] Sign container images (cosign)
- [ ] Deploy gate to AWS with OIDC
- [ ] Slack notification on gate failure

---

## 👤 Author

**Sunny Bhardwaj**
- GitHub: [@sunnyoncloud9](https://github.com/sunnyoncloud9)
- LinkedIn: [linkedin.com/in/bhardwajsunny](https://www.linkedin.com/in/bhardwajsunny/)

---

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.
