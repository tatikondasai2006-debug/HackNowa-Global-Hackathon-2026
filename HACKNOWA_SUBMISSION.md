# 🛡️ HackNowa Global Hackathon 2026 — Final Project Submission

## 📌 Submission Summary

| Field | Details |
|---|---|
| **Participant Name** | **TATIKONDA LEELADHARA SRI MANIKANTA SAI** |
| **GitHub Handle** | [`tatikondasai2006-debug`](https://github.com/tatikondasai2006-debug) |
| **Project Name** | **CyberSentinel** — Small Business Cybersecurity Scanner |
| **Track / Problem Statement** | Cyber Security & Defensive Posture Assessment for Small Businesses |
| **Target Audience** | Small & Medium Businesses (SMBs), non-technical site owners, IT admins |
| **Core Innovation** | Passive, non-invasive automated network & domain scanner with 100% deterministic 0–100 scoring, audit-ready evidence, optional Gemini AI remediation guidance, and RAG knowledge assistant |
| **Repository URL** | [`https://github.com/tatikondasai2006-debug/HackNowa-Global-Hackathon-2026`](https://github.com/tatikondasai2006-debug/HackNowa-Global-Hackathon-2026) |
| **Live Demo URL** | `http://localhost:5173` *(Local demo ready)* |
| **Demo Video URL** | *[Insert Loom / YouTube link to demo video]* |

---

## 🎯 Problem Statement & Solution

### The Problem
Small businesses rarely have dedicated security teams or budgets for enterprise vulnerability management solutions. Yet, they depend heavily on basic public-facing security hygiene: TLS configuration, HTTPS upgrade enforcement, HTTP security headers, DNS integrity, email anti-spoofing (SPF/DMARC/DKIM), and exposed service ports. Left unchecked, misconfigurations lead to phishing, domain spoofing, data interception, and ransomware attacks.

### The Solution: CyberSentinel
CyberSentinel automates passive security posture checks for any authorized domain without performing invasive penetration testing or brute forcing. It fetches only what is publicly visible to internet clients, scores the posture deterministically from 0 to 100 with zero hallucination, and offers optional AI-powered remediation advice grounded strictly in scan evidence.

---

## 🚀 Key Features & Highlights

1. **6-Module Passive Scanner**:
   - 🔒 **TLS/SSL**: Certificate validity, expiration warnings, cipher suite strength, protocol versions (TLS 1.2/1.3).
   - 🌐 **HTTPS**: Standard reachability, HTTP-to-HTTPS redirect enforcement.
   - 🛡️ **Security Headers**: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, server header leaks.
   - 🔍 **DNS & Domain**: DNSSEC validation, CAA records, nameserver redundancy.
   - 📧 **Email Security**: SPF, DMARC policies, DKIM selector probing.
   - 🔌 **Exposed Network Ports**: Safe TCP connect scan on standard service ports (21, 22, 25, 80, 443, 3306, 5432, 8080, 8443).

2. **Deterministic Weighted Scoring Engine (0–100)**:
   - Eliminates AI hallucinations for scoring.
   - Every point deducted is backed by empirical log evidence and specific risk severity levels (Critical, High, Medium, Low, Info).

3. **Security & Guardrails**:
   - **SSRF Guard**: Pre-flight validation blocks loopback, private RFC1918 IPs, link-local addresses, and cloud metadata endpoints.
   - **Attestation Enforcement**: Requires explicit owner authorization check before initiating scans.
   - **JWT Auth & Session Revocation**: Built-in user registration, login throttling, bcrypt hashing, and token revocation.
   - **Rate Limiting & Concurrency Control**: Per-user scan quotas and global concurrency caps.

4. **AI & RAG Knowledge Assistant**:
   - Downstream Gemini integration for plain-English remediation guidance.
   - Offline-capable: Gracefully falls back to deterministic rule-based guidance if AI key is absent.
   - Grounded RAG system querying curated cybersecurity documentation.

5. **Reporting & Dashboard**:
   - Interactive React dashboard with security trends, risk distributions, and scan comparisons.
   - One-click exportable HTML and PDF security audit reports.

---

## 🛠️ Architecture & Tech Stack

```
[ Domain Input ] ➔ [ SSRF & Attestation Guard ] ➔ [ 6-Module Passive Scanner Engine ]
                                                             │
                                                             ▼
[ HTML / PDF Reports ] ◄── [ React Dashboard ] ◄── [ Deterministic Scoring (0-100) ]
                                                             │
                                                             ▼
                                                    [ Gemini AI & RAG ]
```

- **Frontend**: React 18, Vite 5, React Router 6, Lucide Icons, Custom CSS Design System.
- **Backend**: Python 3.12, FastAPI, Pydantic v2, SQLAlchemy 2 (Async), Alembic, `dnspython`, `httpx`.
- **Database**: Async SQLite / PostgreSQL support.
- **Testing & Verification**: 335 backend unit/integration tests (`pytest`), verified Vite production build.

---

## 📽️ Unstop Submission Checklist

- [x] **Project Status**: 100% Completed & Verified (Tests & Build Passing)
- [x] **Documentation**: Full `README.md` and `docs/architecture.md` included
- [ ] **GitHub Repo**: Push code to your GitHub account and make repository public
- [ ] **Demo Video**: Record a 2-minute screen recording demonstrating:
  1. User Registration / Login
  2. Running a Passive Scan on a public domain
  3. Reviewing the 0–100 Score Breakdown & 6 Module Results
  4. Viewing AI Remediation & RAG Assistant
  5. Downloading PDF / HTML Reports
- [ ] **Submit on Unstop**: Paste project title, description, repo URL, video link, and live demo link.
