# 🛡️ CyberSentinel — Small Business Cybersecurity Scanner

**A defensive cybersecurity posture assessment platform for small businesses.**

CyberSentinel scans a domain's **publicly reachable** security configuration, produces a
deterministic, explainable 0–100 security score, and generates actionable remediation
guidance — with optional AI-written explanations grounded in the scan's own evidence.

---

## 🧩 Problem Statement

Small businesses rarely employ a full security team, yet they depend on a small set of
public-facing controls: TLS configuration, HTTPS availability, HTTP security headers, DNS
integrity, email anti-spoofing, and exposed network ports. These are usually checked with
disconnected, expensive tooling, or not at all.

CyberSentinel automates that specific check. It is deliberately **passive**: it only reads
configuration that is already visible to any internet client. It does not exploit, brute
force, or modify anything.

---

## 🏗️ Architecture

Scan pipeline:

```
[Domain input]
     │
     ▼
[Validation & SSRF guard] ── blocks loopback, link-local, and private ranges
     │
     ▼
[Scan orchestrator] ── runs 6 independent modules
     ├── TLS/SSL          certificate chain, protocol versions, expiry, cipher suites
     ├── HTTPS             reachability and HTTP→HTTPS upgrade behaviour
     ├── Headers           HSTS, CSP, X-Frame-Options, X-Content-Type-Options, info leaks
     ├── DNS               DNSSEC (DNSKEY), CAA, nameserver redundancy
     ├── Email             SPF, DMARC, DKIM selector probing
     └── Ports             safe TCP connect scan of well-known exposed services
     │
     ▼
[Deterministic scoring engine] ── weighted 0–100, every point traceable to a check
     │
     ▼
[Findings + remediation] ── risk level, evidence snippet, remediation steps
     │
     ▼
[HTML / PDF reports]  ·  [React dashboard]  ·  [AI explanations]  ·  [RAG assistant]
```

The AI layer is **optional and strictly downstream**. If `GEMINI_API_KEY` is unset, the
application falls back to deterministic rule-based explanations and remains fully
functional.

Repository layout:

```
.
├── backend/                     # FastAPI (Python)
│   ├── alembic/
│   │   ├── env.py               # reads DATABASE_URL from app settings
│   │   └── versions/            # migration revisions
│   ├── app/
│   │   ├── ai/                  # Gemini client wrapper + RAG assistant
│   │   ├── api/                 # routers: auth, scans, reports, ai, dashboard
│   │   ├── core/                # config, security primitives, exceptions, logging
│   │   ├── db/                  # async engine/session + schema bootstrap
│   │   ├── models/              # SQLAlchemy models
│   │   ├── reports/             # Jinja2 HTML report template
│   │   ├── scanner/             # the 6 scanner modules, orchestrator, scoring
│   │   ├── schemas/             # Pydantic request/response schemas
│   │   ├── services/            # business logic (scans, reports, AI, limits, throttle)
│   │   └── main.py              # ASGI application entry point
│   ├── knowledge_base/          # markdown documents used by the RAG assistant
│   ├── tests/                   # pytest suite
│   ├── alembic.ini
│   ├── requirements.txt
│   └── .env.example
├── frontend/                    # React + Vite
│   ├── src/
│   │   ├── components/          # reusable UI components
│   │   ├── context/             # auth context provider
│   │   ├── pages/               # routed page components
│   │   ├── services/            # API client
│   │   ├── styles/              # global stylesheet and design tokens
│   │   ├── utils/               # formatters, domain helpers
│   │   ├── App.jsx              # router
│   │   └── main.jsx             # browser entry point
│   ├── index.html
│   ├── package.json
│   └── .env.example
├── docs/
│   └── architecture.md
└── README.md
```

## 🚀 Technology Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React 18, React Router 6, Vite 5, `lucide-react` icons, hand-written CSS |
| Backend | Python, FastAPI, Pydantic v2, `pydantic-settings` |
| Database | SQLite via SQLAlchemy 2 (async, `aiosqlite`) |
| Migrations | Alembic |
| Auth | JWT (`python-jose`, HS256) + bcrypt password hashing |
| AI / LLM | Google Gemini (`google-generativeai`), optional |
| RAG retrieval | Markdown knowledge base + keyword relevance scoring over Gemini |
| Scanner | Python stdlib `ssl` / `socket` / `asyncio`, `dnspython`, `httpx`, `python-whois` |
| Reports | HTML via Jinja2; PDF via `fpdf2` |
| Testing | `pytest` + `pytest-asyncio` (backend only) |

## 📋 Features

- ✅ User registration and JWT authentication
- ✅ Domain validation with an SSRF guard (loopback / private / link-local blocked)
- ✅ Authorization checkbox with a persisted scan attestation
- ✅ Six-module scanner: TLS, HTTPS, headers, DNS, email anti-spoofing, ports
- ✅ Deterministic, weighted 0–100 scoring with per-check evidence
- ✅ Risk classification with severity levels and remediation steps
- ✅ Optional AI explanations grounded in the scan's own findings
- ✅ RAG cybersecurity Q&A assistant with source citations
- ✅ HTML and PDF report generation
- ✅ Scan history and scan-to-scan comparison
- ✅ Interactive dashboard with posture trends
- ✅ Responsive UI (verified down to 320 px)

---

## ⚙️ Setup

### Prerequisites

- Python 3.11+
- Node.js 18+ and npm 9+

### 1. Backend

```bash
cd backend
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env              # Windows: copy .env.example .env
```

Edit `.env`. Every supported variable is documented inline in `backend/.env.example`.
At minimum set `JWT_SECRET_KEY` before any real deployment:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

`GEMINI_API_KEY` is optional. Leave it as the placeholder to run fully without AI.

### 2. Database schema

The backend supports two schema-management modes, selected by `USE_ALEMBIC`:

- `USE_ALEMBIC=false` *(default)* — the app creates/updates tables with
  `create_all` on startup. Convenient for local SQLite development.
- `USE_ALEMBIC=true` — the app runs `alembic upgrade head` on startup. Use this mode
  for any real deployment. Databases created before Alembic was introduced are
  stamped automatically.

You can also drive Alembic directly:

```bash
cd backend
alembic upgrade head
```

`alembic/env.py` reads `DATABASE_URL` from your `.env`, so there is a single source of
truth for the connection string.

### 3. Run the backend

```bash
cd backend
uvicorn app.main:app --reload --port 8000
```

- Health check: `GET http://127.0.0.1:8000/health`
- Interactive API docs: `http://127.0.0.1:8000/docs`
  (available when `ENVIRONMENT` is not `production`, unless `ENABLE_API_DOCS` overrides it)

### 4. Frontend

```bash
cd frontend
npm install
cp .env.example .env              # Windows: copy .env.example .env
npm run dev
```

The dev server proxies `/api` and `/health` to the backend, so the app is served
same-origin. `VITE_API_URL` is optional; it defaults to `/api/v1`.

### 5. Production build

```bash
cd frontend
npm run build        # emits dist/
npm run preview      # serves dist/ (does not proxy; use a real reverse proxy)
```

---

## 🧪 Testing

Backend only — the project has **no frontend test runner configured**.

```bash
cd backend
python -m pytest tests -q
```

The suite covers authentication, authorization and IDOR resistance, SSRF and domain
validation, scan rate limiting, login throttling and password timing, JWT handling,
session revocation, log redaction, configuration security, path-parameter bounds, and
Alembic migrations.

Frontend build verification:

```bash
cd frontend
npm run build
```

---

## 🔒 Security Considerations

Implemented controls:

- **Password storage** — bcrypt with per-password salt; inputs validated against
  bcrypt's 72-byte limit.
- **Tokens** — HS256 JWTs; `exp` is required and enforced; tokens are held in
  `sessionStorage`, never `localStorage`, and cleared on logout.
- **Authorization** — every scan, report, finding and AI endpoint is ownership-scoped;
  non-owned resources return `404` rather than revealing existence.
- **SSRF / domain validation** — loopback, private, link-local and reserved targets are
  rejected before any connection is made; outbound connects are IP-pinned to limit DNS
  rebinding.
- **Abuse controls** — per-user scan quota, global concurrent-scan cap, scan timeout, and
  progressive login backoff.
- **Secret hygiene** — `GEMINI_API_KEY` and `JWT_SECRET_KEY` are `SecretStr` fields, so
  they are excluded from `repr()`, logs and serialisation; log records and exception
  tracebacks are redacted.
- **Prompt discipline** — AI prompts instruct the model to use only supplied findings,
  never to invent issues or scores, and never to echo secrets; model output is sanitized
  and schema-validated before it reaches the API, and unavailable-AI states fall back to
  deterministic text and are labelled as such.
- **Report hardening** — `X-Content-Type-Options: nosniff` and `X-Frame-Options: DENY`.
- **Production startup gate** — the app refuses to start with `DEBUG=true`, wildcard
  CORS, or placeholder secrets when `ENVIRONMENT=production`.

Operational caveats:

- `TRUST_PROXY_HEADERS` must stay `false` unless you control the proxy in front of the
  app; otherwise clients can spoof their IP and weaken login throttling.
- The login throttle and scan-admission guard hold state **in the process**. They are
  correct for a single worker; a multi-worker deployment needs shared state.
- The application ships without a Content-Security-Policy header.

---

## ⚖️ Limitations

- Only publicly reachable configuration is assessed. Findings reflect the view from the
  internet at scan time, not internal posture.
- Scanner checks are point-in-time; results are not continuously monitored.
- The RAG assistant uses keyword relevance over a small bundled knowledge base — it is
  not a vector database, and answer quality is bounded by those documents.
- AI features are optional and untested against live Gemini quotas in CI; the suite mocks
  the model.
- SQLite is the supported development database. `DATABASE_URL` is configurable, but other
  engines are not covered by the test suite.
- There is no frontend automated test suite and no CI pipeline.

## 🔮 Future Work

- Frontend component and end-to-end test coverage.
- Continuous re-scanning with change alerting.
- A CI pipeline running migrations and the test suite on every change.
- Shared-state rate limiting so limits hold across multiple workers.

---

## 🧭 Responsible Use

- **Authorized scanning only.** Users are responsible for having permission to assess
  any target domain.
- **No exploitation.** The tool performs no brute forcing, credential attacks, or
  destructive testing.
- **No data exfiltration.** It fetches only what a normal client can already see.
- **Transparent scoring.** Every score is traceable to individual checks and evidence.

### ⚠️ Disclaimer

This tool performs passive, non-invasive assessment of publicly accessible
configuration. It is **not** a penetration test and performs no active attack. Use it only
against systems you own or are explicitly authorized to assess.

## 📝 License

**License: No open-source license has been selected yet.**

No `LICENSE` file is present in this repository. All rights are reserved by default, so
the project must not be redistributed or published until a license is chosen.

See [`docs/architecture.md`](docs/architecture.md) for the system design and endpoint
reference.
