# BhashaRakshak

> **AI-powered Scam X-Ray** — detects scam intent in multilingual, transliterated, misspelled, obfuscated, and code-mixed SMS messages.

[![Python](https://img.shields.io/badge/python-3.11-blue.svg)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111-green.svg)](https://fastapi.tiangolo.com)
[![Next.js](https://img.shields.io/badge/Next.js-14-black.svg)](https://nextjs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-blue.svg)](https://typescriptlang.org)
[![Docker](https://img.shields.io/badge/Docker-ready-blue.svg)](https://docker.com)

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Prerequisites](#prerequisites)
3. [Quick Start (Docker)](#quick-start-docker)
4. [Local Development (without Docker)](#local-development-without-docker)
5. [Environment Variables](#environment-variables)
6. [API Reference](#api-reference)
7. [Testing](#testing)
8. [Linting & Formatting](#linting--formatting)
9. [Project Structure](#project-structure)
10. [Security Notes](#security-notes)
11. [Development Phases](#development-phases)

---

## Architecture Overview

BhashaRakshak is a **modular monolith** — one repository, clear internal boundaries, independently runnable frontend and backend.

```
┌─────────────────────────────────────────────────────┐
│                    Browser / Client                  │
└───────────────────────┬─────────────────────────────┘
                        │ HTTPS
┌───────────────────────▼─────────────────────────────┐
│              Next.js Frontend (port 3000)            │
│  • TypeScript strict mode                            │
│  • Tailwind CSS                                      │
│  • Only NEXT_PUBLIC_ env vars exposed                │
└───────────────────────┬─────────────────────────────┘
                        │ HTTP (internal)
┌───────────────────────▼─────────────────────────────┐
│              FastAPI Backend (port 8000)             │
│  • /api/v1/...                                       │
│  • Request ID middleware                             │
│  • Rate limiting middleware                          │
│  • Security headers middleware                       │
│  • Structured JSON logging                           │
└───────────────────────┬─────────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────────┐
│         PostgreSQL 16 + pgvector (port 5432)         │
│  • pgvector ready for Phase 2 ML embeddings          │
└─────────────────────────────────────────────────────┘
```

---

## Prerequisites

| Tool | Minimum Version | Install |
|------|----------------|---------|
| Docker | 24.x | [docs.docker.com](https://docs.docker.com/get-docker/) |
| Docker Compose | v2.x | Included with Docker Desktop |
| Python | 3.11+ | [python.org](https://python.org) (for local dev) |
| Node.js | 20 LTS | [nodejs.org](https://nodejs.org) (for local dev) |
| Git | 2.x | [git-scm.com](https://git-scm.com) |

---

## Quick Start (Docker)

```bash
# 1. Clone the repository
git clone https://github.com/your-org/bhasharakshak.git
cd bhasharakshak

# 2. Create your environment file
cp .env.example .env
# Open .env and set:
#   POSTGRES_PASSWORD=<a strong password>
#   SECRET_KEY=$(openssl rand -hex 32)

# 3. Start all services
docker compose up --build

# 4. Verify everything is running
curl http://localhost:8000/api/v1/health
curl http://localhost:3000
```

---

## Local Development (without Docker)

### Backend

```bash
cd backend

# Create virtual environment
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt -r requirements-dev.txt

# Set up environment
cp .env.example .env
# Edit .env — set DATABASE_URL, SECRET_KEY

# Start the development server
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

# API docs available at:
# http://localhost:8000/docs        (Swagger UI — dev only)
# http://localhost:8000/redoc       (ReDoc — dev only)
```

### Frontend

```bash
cd frontend

# Install dependencies
npm install

# Set up environment
cp .env.example .env.local
# Edit .env.local — set NEXT_PUBLIC_API_BASE_URL=http://localhost:8000

# Start the development server
npm run dev

# App available at: http://localhost:3000
```

### Database (local PostgreSQL)

```bash
# Using Docker just for PostgreSQL (recommended for local dev):
docker run -d \
  --name bhasharakshak_postgres \
  -e POSTGRES_DB=bhasharakshak \
  -e POSTGRES_USER=bhasharakshak_user \
  -e POSTGRES_PASSWORD=localdevpassword \
  -p 5432:5432 \
  pgvector/pgvector:pg16
```

---

## Environment Variables

See [`.env.example`](.env.example) for the full reference.

### Backend Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DATABASE_URL` | ✅ | — | Full PostgreSQL async DSN |
| `SECRET_KEY` | ✅ | — | Min 32 char random secret |
| `ENVIRONMENT` | ✅ | `development` | `development\|staging\|production` |
| `CORS_ALLOWED_ORIGINS` | ✅ | — | Comma-separated allowed origins |
| `MAX_REQUEST_SIZE_BYTES` | ❌ | `1048576` | Max request body size (1 MB) |
| `RATE_LIMIT_REQUESTS` | ❌ | `60` | Requests per IP per window |
| `RATE_LIMIT_WINDOW_SECONDS` | ❌ | `60` | Rate limit window |
| `LOG_LEVEL` | ❌ | `INFO` | Logging level |

### Frontend Variables

Only `NEXT_PUBLIC_*` variables are safe to expose to the browser:

| Variable | Description |
|----------|-------------|
| `NEXT_PUBLIC_API_BASE_URL` | Backend API base URL |
| `NEXT_PUBLIC_APP_NAME` | Application display name |
| `NEXT_PUBLIC_APP_VERSION` | Application version |

> ⚠️ **Never** put secrets, database credentials, or API keys in `NEXT_PUBLIC_*` variables.

---

## API Reference

### Health Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/health` | GET | Full health check (service + DB) |
| `/api/v1/health/live` | GET | Liveness probe (always 200 if running) |
| `/api/v1/health/ready` | GET | Readiness probe (200 only if all deps up) |

### Error Response Format

All errors follow a consistent schema:

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Request validation failed",
    "request_id": "550e8400-e29b-41d4-a716-446655440000",
    "details": [
      {
        "field": "body.text",
        "message": "field required"
      }
    ]
  }
}
```

---

## Testing

```bash
cd backend

# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ -v --cov=app --cov-report=term-missing

# Run specific test file
pytest tests/test_health.py -v
```

---

## Linting & Formatting

### Backend (Python)

```bash
cd backend

# Lint (ruff)
ruff check app/ tests/

# Format (ruff)
ruff format app/ tests/

# Type check (mypy)
mypy app/

# All-in-one
ruff check app/ tests/ && ruff format --check app/ tests/ && mypy app/
```

### Frontend (TypeScript)

```bash
cd frontend

# Lint (ESLint)
npm run lint

# Type check (tsc)
npx tsc --noEmit

# Format (Prettier)
npx prettier --check .
```

---

## Project Structure

```
bhasharakshak/
├── backend/
│   ├── app/
│   │   ├── api/v1/          # Versioned API routes
│   │   ├── core/            # Shared schemas, error handlers
│   │   ├── db/              # SQLAlchemy session, base model
│   │   ├── middleware/      # Request ID, rate limit, security headers
│   │   ├── config.py        # Centralized settings (pydantic-settings)
│   │   ├── logging_config.py
│   │   └── main.py          # App factory
│   └── tests/
├── frontend/
│   └── src/
│       ├── app/             # Next.js App Router
│       ├── components/      # Reusable React components
│       ├── config/          # Public env config
│       ├── lib/             # API client, utilities
│       └── types/           # TypeScript type definitions
├── docker-compose.yml
├── .env.example
├── .gitignore
└── README.md
```

---

## Security Notes

- **No secrets in frontend**: Only `NEXT_PUBLIC_*` variables are exposed to the browser.
- **No wildcard CORS**: Production CORS must list explicit origins.
- **No stack traces**: Clients never receive internal error details.
- **Request size limits**: Default 1 MB, configurable via `MAX_REQUEST_SIZE_BYTES`.
- **Rate limiting**: Token-bucket per IP, configurable. Redis-ready for Phase 2.
- **Security headers**: `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, etc. on all responses.
- **Structured logging**: Passwords, tokens, and API keys are never logged.
- **Pinned dependencies**: `requirements.txt` and `package-lock.json` lock all versions.

---

## Development Phases

| Phase | Status | Description |
|-------|--------|-------------|
| **Phase 1** | ✅ Current | Repository scaffold, infrastructure, health checks, security hardening |
| Phase 2 | Planned | Authentication, user management, database migrations |
| Phase 3 | Planned | SMS text normalization, transliteration |
| Phase 4 | Planned | ML pipeline: embeddings, scam classification |
| Phase 5 | Planned | Analyst dashboard, campaign clustering |
| Phase 6 | Planned | Screenshot/OCR analysis |
| Phase 7 | Planned | Adversarial playground |

---

## Contributing

1. Create a feature branch from `main`
2. Follow linting and type-check requirements (`ruff`, `mypy`, `tsc`)
3. Add tests for new functionality
4. Open a pull request with a clear description

---

## License

Proprietary — BhashaRakshak. All rights reserved.
