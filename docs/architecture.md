# CyberSentinel — System Architecture & Specification

## 1. System Overview
**CyberSentinel** is a production-style, defensive cybersecurity posture assessment platform specifically engineered for small businesses (SMBs). It provides automated non-invasive observation, deterministic risk classification, verifiable remediation instructions, and AI-grounded explanations.

---

## 2. End-to-End Pipeline
```
[User Input Domain]
       │
       ▼
[Sanitization & SSRF Guard] ── (Blocks localhost, RFC1918 private ranges)
       │
       ▼
[Scan Job Orchestrator] ── runs 6 independent modules
   ├── TLS/SSL Module (Cipher suites, Cert chain, TLS 1.2/1.3, Expiration)
   ├── HTTPS Module (Reachability, HTTP→HTTPS upgrade behaviour)
   ├── Security Headers Module (HSTS, CSP, X-Frame-Options, NoSniff, Info Leaks)
   ├── DNS & DNSSEC Module (DNSKEY, CAA records, Nameserver redundancy)
   ├── Email Spoofing Defense (SPF formatting, DMARC policy, DKIM selectors)
   └── Port & Service Exposure (Safe TCP scan of well-known exposed DB/remote ports)
       │
       ▼
[Deterministic Scoring Engine] ── (Weighted factors, traceable 0-100 score)
       │
       ▼
[Findings & Prioritized Remediation] ── (Risk level, evidence, fix steps)
       │
       ▼
[RAG & Gemini AI Layer] ── (Optional; grounds explanations strictly in verified
                            evidence and falls back to deterministic text when
                            GEMINI_API_KEY is unset)
       │
       ▼
[HTML (Jinja2) / PDF (fpdf2) Report Generator] & [React Dashboard]
```

---

## 3. Database Schema (SQLite)

SQLite is the supported database, accessed asynchronously through SQLAlchemy 2 and
`aiosqlite`. `DATABASE_URL` is configurable, but other engines are not covered by the
test suite.

- **`users`**: Authentication credentials, hashed password (bcrypt), profile metadata, timestamps.
- **`scan_jobs`**: Target domain, status (pending/running/completed/failed), scores, check counts, AI summary.
- **`scan_results`**: Individual check outcomes per module, evidence text, earned/max score impact.
- **`findings`**: Identified security misconfigurations, risk level, evidence snippet, remediation steps.
- **`reports`**: Generated report records, executive summaries, audit linkage.
- **`audit_logs`**: Security activity logs, user events, resource identifiers, including the
  per-scan authorization attestation.

Schema management has two modes, selected by `USE_ALEMBIC`: `create_all` on startup
(default, for local development) or `alembic upgrade head` (for deployments). See
`alembic/versions/` for the migration history.

---

## 4. API Endpoints Reference

Base prefix: `/api/v1`. All endpoints except `/health` and registration/login require a
valid bearer token, and all scan-scoped resources are ownership-checked.

### System
- `GET /health`: Unauthenticated liveness probe (served at the app root, not under `/api/v1`).

### Authentication (`/api/v1/auth`)
- `POST /register`: Create new account & issue JWT.
- `POST /login`: Authenticate and issue JWT (progressive backoff on repeated failures).
- `GET /me`: Get authenticated user profile.
- `PUT /me`: Update user profile details.
- `POST /change-password`: Update password.

### Scans (`/api/v1/scans`)
- `POST /validate`: Validate a target domain (normalization + SSRF screening).
- `POST /`: Initiate asynchronous scan job.
- `GET /`: Get paginated scan history (filters: `page`, `page_size`, `domain`).
- `GET /history/{domain}`: Chronological scan history for a single domain (`page_size`).
- `GET /compare/{scan_id_a}/{scan_id_b}`: Score and finding delta between two scans.
- `GET /{scan_id}`: Full scan details with module results & findings.
- `GET /{scan_id}/status`: Lightweight status polling endpoint.
- `GET /{scan_id}/recommendations`: Prioritized remediation plan for a scan.
- `DELETE /{scan_id}`: Delete scan record & associated findings.

### Reports (`/api/v1/reports`)
- `POST /generate/{scan_id}`: Generate persistent report (`format=html|pdf`).
- `GET /`: List the authenticated user's reports.
- `GET /{report_id}/view`: View rendered HTML report.
- `GET /{report_id}/pdf`: Download a generated report as PDF.
- `GET /scan/{scan_id}/view`: Live render HTML report for a scan.
- `GET /scan/{scan_id}/pdf`: Download a scan report as PDF.

Report responses are served with `X-Content-Type-Options: nosniff` and
`X-Frame-Options: DENY`.

### AI & RAG (`/api/v1/ai`)
- `POST /explain-scan/{scan_id}`: Generate AI executive brief for a scan.
- `POST /explain-finding/{finding_id}`: Plain-English explanation for one finding.
- `POST /rag/ask`: Knowledge base Q&A with source citations.

All three degrade gracefully to deterministic text when `GEMINI_API_KEY` is unset.

### Dashboard (`/api/v1/dashboard`)
- `GET /stats`: Aggregate posture metrics & score trends.
