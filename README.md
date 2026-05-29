# 🛡️ DevSecOps Pipeline

> **A complete security-integrated CI/CD pipeline — shift-left security across the full SDLC**

[![DevSecOps Pipeline](https://github.com/sunnyoncloud9/devsecops-pipeline/actions/workflows/devsecops.yml/badge.svg)](https://github.com/sunnyoncloud9/devsecops-pipeline/actions/workflows/devsecops.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## 📌 Overview

This project implements a production-grade **DevSecOps pipeline** that embeds security at every stage of the software delivery lifecycle. Every commit is automatically scanned for vulnerable code, vulnerable dependencies, leaked secrets, insecure container images, and misconfigured infrastructure — and the build is **blocked** if critical issues are found.

The goal is to demonstrate **shift-left security**: catching problems in CI before they ever reach production, rather than detecting them after deployment.

---

## 🔧 Pipeline Stages

| Stage | Tool | What it catches |
|-------|------|-----------------|
| **SAST** | Bandit, Semgrep | Insecure code patterns, injection flaws |
| **SCA** | pip-audit, Safety | Vulnerable dependencies (known CVEs) |
| **Secret Scanning** | Gitleaks, detect-secrets | Hardcoded API keys, passwords, tokens |
| **Container Scanning** | Trivy | Vulnerable OS packages and libraries in images |
| **IaC Scanning** | Checkov | Misconfigured Terraform/cloud resources |
| **Security Gate** | Custom Python | Aggregates results, fails build on threshold breach |

---

## 🏗️ Architecture

```
Developer pushes code
        │
        ▼
┌──────────────────────────────────────────────┐
│            GitHub Actions Pipeline             │
│                                                │
│  ┌──────────┐  ┌──────────┐  ┌──────────────┐ │
│  │  SAST    │  │   SCA    │  │ Secret Scan  │ │  (run in parallel)
│  └────┬─────┘  └────┬─────┘  └──────┬───────┘ │
│       │             │               │         │
│  ┌────┴─────┐  ┌────┴─────┐         │         │
│  │Container │  │   IaC    │         │         │
│  │  Scan    │  │  Scan    │         │         │
│  └────┬─────┘  └────┬─────┘         │         │
│       └─────────────┴───────────────┘         │
│                     │                          │
│                     ▼                          │
│            ┌─────────────────┐                 │
│            │  Security Gate   │                 │
│            │  CRITICAL = 0    │                 │
│            │  HIGH ≤ 5        │                 │
│            └────────┬─────────┘                 │
└─────────────────────┼──────────────────────────┘
                      ▼
              ✅ Pass / 🛑 Fail
```

---

## 🚦 Security Gate Policy

The pipeline enforces a configurable security gate (`scripts/security_gate.py`):

- **CRITICAL findings:** `0` allowed — any critical finding fails the build
- **HIGH findings:** up to `5` tolerated — beyond that the build fails

Thresholds are defined in one place and easy to tighten as the codebase matures.

---

## 📁 Project Structure

```
devsecops-pipeline/
├── .github/workflows/
│   └── devsecops.yml          # The full pipeline definition
├── sample-app/                # Target application being scanned
│   ├── app.py                 # Hardened Flask app
│   ├── requirements.txt
│   └── Dockerfile             # Hardened, non-root container
├── iac/
│   └── main.tf                # Secure-by-default Terraform
├── scripts/
│   └── security_gate.py       # Aggregates results, enforces policy
├── tests/
│   └── test_security_gate.py  # Unit tests for gate logic
└── README.md
```

---

## 🔐 Security Practices Demonstrated

The sample app and infrastructure intentionally follow best practices so the pipeline passes cleanly:

- **Secrets via environment variables** — never hardcoded
- **Non-root container user** — principle of least privilege
- **Pinned base image** — `python:3.11-slim`, not `latest`
- **Production WSGI server** — gunicorn, not Flask dev server
- **Input validation** on all endpoints
- **S3 encryption, versioning, and public-access blocks** in Terraform
- **Least-privilege security groups** — HTTPS only

---

## 🚀 Running Locally

```bash
# Run the security gate against scan reports
python scripts/security_gate.py ./reports

# Run the unit tests
python -m unittest discover tests/

# Build the sample app container
docker build -t sample-app ./sample-app

# Run the sample app
docker run -p 5000:5000 sample-app
```

---

## ⚙️ How It Runs

The pipeline triggers automatically on:
- Every push to `main` or `develop`
- Every pull request to `main`
- A weekly scheduled scan (Mondays 9am UTC)
- Manual dispatch from the Actions tab

All scan reports are uploaded as workflow artifacts and retained for review.

---

## 🗺️ Roadmap

- [ ] DAST stage (dynamic scanning of the running app)
- [ ] SBOM generation (CycloneDX)
- [ ] Sign container images (cosign)
- [ ] Deploy gate to AWS with OIDC (no long-lived keys)
- [ ] Slack notification on gate failure

---

## 👤 Author

**Sunny Bhardwaj**
- GitHub: [@sunnyoncloud9](https://github.com/sunnyoncloud9)
- LinkedIn: [linkedin.com/in/bhardwajsunny](https://www.linkedin.com/in/bhardwajsunny/)

---

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.
