# Auth-as-a-Service (AaaS) Enterprise Authentication Platform

[![Python Version](https://img.shields.io/badge/python-3.14%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/framework-FastAPI-green.svg)](https://fastapi.tiangolo.com/)
[![SQLAlchemy 2.0](https://img.shields.io/badge/orm-SQLAlchemy%202.0%20Async-orange.svg)](https://www.sqlalchemy.org/)
[![PostgreSQL](https://img.shields.io/badge/database-PostgreSQL%2016-336791.svg)](https://www.postgresql.org/)
[![Redis](https://img.shields.io/badge/cache-Redis%207-red.svg)](https://redis.io/)
[![Test Coverage](https://img.shields.io/badge/coverage-83%25-brightgreen.svg)](#testing--verification)
[![Passing Tests](https://img.shields.io/badge/tests-1212%20passed-success.svg)](#testing--verification)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Auth-as-a-Service (AaaS)** is a production-grade, multi-tenant authentication and authorization platform built from scratch with Python 3.14, FastAPI, SQLAlchemy 2.0 Async, PostgreSQL, and Redis. It provides enterprise security primitives: asymmetric JWT signing with JWKS, multi-tenant RBAC/ABAC enforcement, API key lifecycle management, OAuth2/OIDC social authentication (Google and GitHub), WebAuthn/TOTP MFA, GDPR compliance data export/erasure, automated audit trails, and distributed sliding-window rate limiting.

---

## 🏛️ System Architecture

The platform strictly adheres to a **5-Layer Decoupled Architecture**, ensuring clean separation of concerns and zero tight coupling across security primitives, business logic, storage, and transport layers.

```
+--------------------------------------------------------------------------+
|                       LAYER 5: PRESENTATION & API                        |
|   FastAPI REST Routers (53 Endpoints), Pydantic v2 Schemas, Middleware   |
|   (Tenant Middleware, Rate Limiter, CSRF, MTLS, OpenTelemetry Context)   |
+--------------------------------------------------------------------------+
                                     │
+--------------------------------------------------------------------------+
|                     LAYER 4: STORAGE & PERSISTENCE                       |
|   PostgreSQL Repositories (SQLAlchemy 2.0 Async), Redis Engine (Cache,    |
|   Token Blacklist, Sliding-Window Rate Limit, Distributed Lock)          |
+--------------------------------------------------------------------------+
                                     │
+--------------------------------------------------------------------------+
|                 LAYER 3: MULTI-TENANCY & ORCHESTRATION                   |
|   Tenant Isolation, Plan Quotas (Starter, Standard, Enterprise),         |
|   RBAC/ABAC Permission Enforcer, Tenant Provisioning Workflows           |
+--------------------------------------------------------------------------+
                                     │
+--------------------------------------------------------------------------+
|                    LAYER 2: AUTH DOMAIN & ADAPTERS                       |
|   OAuth2/OIDC (Google, GitHub, SAML), TOTP & WebAuthn MFA, Email,       |
|   Webhook HMAC Dispatcher, Device Sessions, Token Exchange & Introspect  |
+--------------------------------------------------------------------------+
                                     │
+--------------------------------------------------------------------------+
|                    LAYER 1: CORE SECURITY PRIMITIVES                     |
|   Bcrypt (OWASP Pre-Hash), Argon2id, PBKDF2, JWT/JWKS Asymmetric Signing |
|   (RS256, Ed25519), PKCE Verification, Constant-Time Comparison          |
+--------------------------------------------------------------------------+
```

For in-depth architectural details, see [ARCHITECTURE.md](ARCHITECTURE.md) and [PRD.md](PRD.md).

---

## ✨ Key Enterprise Capabilities

1. **Cryptographic Identity & Asymmetric Token Pairs**
   - Dual-token lifecycle: short-lived Access Tokens (15 min) and single-use Refresh Tokens with automatic reuse-detection revocation chains.
   - Symmetric (`HS256`, `HS384`, `HS512`) and Asymmetric (`RS256`, `Ed25519`) signing keys.
   - Public JSON Web Key Set (`/.well-known/jwks.json`) and OpenID Configuration (`/.well-known/openid-configuration`).
   - RFC 7662 Token Introspection (`/api/v1/auth/introspect`) and RFC 8693 Token Exchange (`/api/v1/oauth/token`).

2. **Hard Multi-Tenant Isolation**
   - Header-driven context (`X-Tenant-ID`) with validation at the database query level.
   - Cross-tenant boundary breach prevention with guaranteed zero data leakage.
   - Subscription tier quotas (`starter`, `standard`, `enterprise`) restricting users, API keys, and custom roles.

3. **Multi-Factor Authentication (MFA)**
   - RFC 6238 Time-Based One-Time Passwords (TOTP) with QR code URI generation.
   - FIDO2 / WebAuthn cryptographic challenge-response registration and assertion.
   - Single-use hashed backup recovery codes with constant-time verification.

4. **Hierarchical RBAC & Contextual ABAC**
   - Granular resources and actions (`user:create`, `tenant:delete`, `api_keys:manage`).
   - Role inheritance, system roles (`superadmin`, `tenant_admin`, `auditor`, `member`), and custom tenant roles.
   - Attribute-Based Access Control (ABAC) evaluating IP CIDR ranges, time of day, and tenant membership.

5. **API Key Infrastructure**
   - Dual environment prefixes (`aas_live_` and `aas_test_`).
   - High-entropy tokens with SHA-256 storage, prefix-based lookup, and expiration dates.
   - Per-key permission scopes and last-used timestamp auditing.

6. **Defense-in-Depth & Anti-Abuse**
   - Distributed sliding-window rate limiting in Redis with in-memory fallback.
   - Exponential account lockout on repeated failed credentials.
   - IP intelligence subnet classification (Loopback, RFC 1918 Private, Public, Banned honeypot CIDRs).
   - HaveIBeenPwned k-anonymity SHA-1 prefix checking for breached passwords.
   - Device fingerprinting and active concurrent session caps with remote session termination.

7. **GDPR / CCPA Privacy & Compliance**
   - Article 15 (Right to Access): Comprehensive user profile and activity JSON export.
   - Article 17 (Right to Erasure / "Be Forgotten"): Irreversible anonymization, PII redaction, and token revocation.
   - Append-only audit logs with streaming CSV export for external compliance monitors.

8. **Observability & Telemetry**
   - Prometheus metrics endpoint (`/metrics`) tracking auth attempts, JWT issuance, latency, and active sessions.
   - OpenTelemetry span instrumentation across authentication flows.
   - Structured JSON logging with trace context correlation.

---

## 🚀 Quickstart Guide

### Prerequisites
- Python 3.14+ (or 3.11+)
- Docker & Docker Compose (optional, for containerized services)
- PostgreSQL 16+ & Redis 7+ (or use automated SQLite/In-Memory fallback)

### Local Development Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/organization/auth-service.git
   cd auth-service
   ```

2. **Create and activate a virtual environment:**
   ```bash
   python -m venv venv
   # On Windows:
   .\venv\Scripts\Activate.ps1
   # On Linux/macOS:
   source venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment:**
   ```bash
   cp .env.example .env
   # Edit .env with your PostgreSQL, Redis, and secret keys
   ```

5. **Apply database migrations:**
   ```bash
   alembic upgrade head
   ```

6. **Start the API service:**
   ```bash
   uvicorn auth_service.main:app --host 0.0.0.0 --port 8000 --reload
   ```

7. **Access interactive documentation:**
   - Swagger UI: `http://localhost:8000/docs`
   - ReDoc: `http://localhost:8000/redoc`
   - OpenID Configuration: `http://localhost:8000/.well-known/openid-configuration`
   - JWKS Endpoint: `http://localhost:8000/.well-known/jwks.json`

---

## 🐳 Docker Compose Deployment

Launch the complete stack (AaaS API, PostgreSQL, Redis, Prometheus, and Nginx reverse proxy):

```bash
docker-compose up -d --build
```

Services exposed:
- **API Gateway (Nginx):** `http://localhost:80`
- **AaaS Direct Backend:** `http://localhost:8000`
- **Prometheus:** `http://localhost:9090`
- **PostgreSQL:** `localhost:5432`
- **Redis:** `localhost:6379`

---

## 🧪 Testing & Verification

AaaS includes an exhaustive, enterprise-grade test suite covering unit tests, property fuzzing, concurrency tests, and end-to-end integration workflows.

### Run All Tests
```bash
pytest
```

### Run Tests with Coverage Report
```bash
pytest --cov=auth_service --cov-report=term-missing
```

**Verification Results:**
- **Total Tests:** `1,212 passing` (0 failed, 0 errors)
- **Code Coverage:** `83%` across 5,546 statements
- **Execution Speed:** ~23 seconds

---

## 📦 Python SDK & CLI Tool

### Async Python Client SDK
```python
import asyncio
from auth_service.client.python_client_async import AsyncAuthServiceClient

async def main():
    async with AsyncAuthServiceClient(base_url="http://localhost:8000") as client:
        # Register user
        user = await client.register("newuser@example.com", "SecureP@ssw0rd2026!")
        print(f"Registered user: {user['id']}")

        # Login
        tokens = await client.login("newuser@example.com", "SecureP@ssw0rd2026!")
        print(f"Access token: {tokens['access_token'][:20]}...")

        # Introspect
        active = await client.introspect_token(tokens["access_token"])
        print(f"Token active: {active['active']}")

asyncio.run(main())
```

### CLI Utility (`auth-cli`)
```bash
# Register a user via CLI
python -m auth_service.client.cli register --email admin@example.com --password "P@ssword123456!"

# Login and receive JWT
python -m auth_service.client.cli login --email admin@example.com --password "P@ssword123456!"

# Check system health
python -m auth_service.client.cli health
```

---

## 📋 Comprehensive Endpoint Reference

A complete API inventory detailing all 53 endpoints across 12 resource groups is available in [API.md](API.md).

| Resource Group | Path Prefix | Primary Operations |
|---|---|---|
| **Authentication** | `/api/v1/auth` | Register, Login, Refresh, Logout, Forgot/Reset Password, Verify Email, Introspect |
| **OAuth2 / Social** | `/api/v1/oauth` | Google/GitHub Authorization & Callbacks, Token Exchange |
| **Multi-Factor Auth** | `/api/v1/mfa` | TOTP Setup & Verification, WebAuthn Registration & Login, Backup Codes |
| **Users** | `/api/v1/users` | Profile Management, Password Update, Avatar Upload |
| **Tenants** | `/api/v1/tenants` | Multi-Tenant Lifecycle, Plan Switching, Quota Checks |
| **RBAC Roles** | `/api/v1/roles` | Create Roles, Assign Permissions, Tenant Scoping |
| **Permissions** | `/api/v1/permissions` | System-Wide Permission Catalog |
| **API Keys** | `/api/v1/api-keys` | Key Provisioning, Scope Enforcement, Instant Revocation |
| **Sessions** | `/api/v1/sessions` | List Active Device Sessions, Remote Termination |
| **Webhooks** | `/api/v1/webhooks` | Subscriptions, Event Delivery, Secret Rotation |
| **Compliance & GDPR** | `/api/v1/compliance` | Article 15 Data Export, Article 17 Erasure Workflows |
| **Admin & Audit** | `/api/v1/admin` | Audit Log Search, CSV Export, User Status Toggles |
| **Well-Known & Metrics** | `/.well-known`, `/metrics` | JWKS, OIDC Discovery, Prometheus Metrics |

---

## 📄 License & Security

- **Security Disclosures:** Review [SECURITY.md](SECURITY.md) for vulnerability reporting guidelines and threat model details.
- **Contributing:** See [CONTRIBUTING.md](CONTRIBUTING.md) for code style and PR merge workflows.
- **License:** MIT License.

