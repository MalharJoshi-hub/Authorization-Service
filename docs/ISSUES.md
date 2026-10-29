# GitHub Issues & Pull Requests Log

This document records the 28 engineering issues tracked, implemented, tested, and resolved across the feature branches of `auth-service`.

---

### Issue #1: [CORE-01] Initialize Python project structure, virtualenv & dependencies
- **Status:** Closed
- **Milestone:** v1.0.0-alpha
- **Branch:** `feat/project-scaffold`
- **Description:** Establish canonical directory tree, `.env.example`, `pytest.ini`, `alembic.ini`, and pinned dependencies compatible with Python 3.11+.

### Issue #2: [SEC-01] Implement constant-time password hashing & verification
- **Status:** Closed
- **Milestone:** v1.0.0-alpha
- **Branch:** `feat/security-core`
- **Description:** Provide Bcrypt and Argon2 password hashing with work factor configuration, constant-time verification, and automatic rehashing flags.

### Issue #3: [SEC-02] JWT issuance, validation, and claims enrichment
- **Status:** Closed
- **Milestone:** v1.0.0-alpha
- **Branch:** `feat/jwt-auth`
- **Description:** Implement RS256 and HS256 JWT encoding, RFC 7519 standard claims (`sub`, `iat`, `exp`, `nbf`, `iss`, `aud`), and tenant contextual claims.

### Issue #4: [SEC-03] Token revocation and Redis-backed blacklist
- **Status:** Closed
- **Milestone:** v1.0.0-alpha
- **Branch:** `feat/token-blacklist`
- **Description:** Enable instant token revocation with sliding TTL expiration in Redis and in-memory test fallback.

### Issue #5: [AUTH-01] User registration with email validation and role assignment
- **Status:** Closed
- **Milestone:** v1.0.0-alpha
- **Branch:** `feat/user-registration`
- **Description:** Implement `POST /api/v1/auth/register` with email format verification, duplicate collision handling, and default `member` role assignment.

### Issue #6: [AUTH-02] Username/Password login and refresh token exchange
- **Status:** Closed
- **Milestone:** v1.0.0-alpha
- **Branch:** `feat/auth-login`
- **Description:** Build `POST /api/v1/auth/login` and `POST /api/v1/auth/refresh` returning access tokens and cryptographic refresh tokens.

### Issue #7: [SEC-04] Refresh token rotation and replay detection
- **Status:** Closed
- **Milestone:** v1.0.0-alpha
- **Branch:** `feat/token-rotation`
- **Description:** Invalidate old refresh token on single use; if a previously used token is presented, revoke the entire token family (RFC 6749 Section 10.4).

### Issue #8: [AUTH-03] Email verification tokens and password reset flow
- **Status:** Closed
- **Milestone:** v1.0.0-alpha
- **Branch:** `feat/email-verification`
- **Description:** Implement secure timed tokens for email verification (`/api/v1/auth/verify-email`) and password resets (`/api/v1/auth/forgot-password`).

### Issue #9: [OAUTH-01] Google OAuth2 Social Identity Provider integration
- **Status:** Closed
- **Milestone:** v1.0.0-beta
- **Branch:** `feat/oauth-google`
- **Description:** Implement Google OAuth authorization URL redirect, state CSRF verification, and callback user account linking.

### Issue #10: [OAUTH-02] GitHub OAuth2 Social Identity Provider integration
- **Status:** Closed
- **Milestone:** v1.0.0-beta
- **Branch:** `feat/oauth-github`
- **Description:** Implement GitHub OAuth2 authorization flow, email scope resolution, and OAuth account association.

### Issue #11: [RBAC-01] Role and Permission data models and repository layer
- **Status:** Closed
- **Milestone:** v1.0.0-beta
- **Branch:** `feat/rbac-models`
- **Description:** Create database models for roles, permissions, and many-to-many user-role/role-permission association tables.

### Issue #12: [RBAC-02] FastAPI permission enforcement dependency
- **Status:** Closed
- **Milestone:** v1.0.0-beta
- **Branch:** `feat/rbac-enforcer`
- **Description:** Build `require_permissions("read:users", "write:users")` declarative dependency to guard endpoint access.

### Issue #13: [M2M-01] API Key generation, prefixing, and SHA-256 storage
- **Status:** Closed
- **Milestone:** v1.0.0-beta
- **Branch:** `feat/api-keys`
- **Description:** Implement machine-to-machine API key issuance with unhashed prefix (`aaas_live_...`) and SHA-256 digest database storage.

### Issue #14: [TENANT-01] Multi-tenant data isolation and middleware resolution
- **Status:** Closed
- **Milestone:** v1.0.0-rc1
- **Branch:** `feat/multi-tenant`
- **Description:** Build tenant resolution via `X-Tenant-ID` header and subdomains; enforce database row-level tenant filtering.

### Issue #15: [ADMIN-01] Administrative user management and role assignment APIs
- **Status:** Closed
- **Milestone:** v1.0.0-rc1
- **Branch:** `feat/admin-api`
- **Description:** Expose CRUD endpoints for user suspension, unlocking, role assignment, and tenant inspection.

### Issue #16: [AUDIT-01] Immutable audit logging engine with request context
- **Status:** Closed
- **Milestone:** v1.0.0-rc1
- **Branch:** `feat/audit-logs`
- **Description:** Record all sensitive operations (logins, role changes, key creations) with client IP, user agent, status code, and timestamp.

### Issue #17: [SEC-05] Sliding window rate limiter with tiered limits
- **Status:** Closed
- **Milestone:** v1.0.0-rc1
- **Branch:** `feat/rate-limiting`
- **Description:** Implement sliding window rate limiting (5 req/min on login, 100 req/min on standard endpoints) with standard HTTP headers (`Retry-After`).

### Issue #18: [SEC-06] Account lockout mechanism with exponential backoff
- **Status:** Closed
- **Milestone:** v1.0.0-rc1
- **Branch:** `feat/account-lockout`
- **Description:** Automatically lock user account after 5 consecutive failed attempts; require 15-minute wait or admin unlock.

### Issue #19: [MFA-01] TOTP Multi-Factor Authentication (RFC 6238)
- **Status:** Closed
- **Milestone:** v1.0.0-rc1
- **Branch:** `feat/mfa-totp`
- **Description:** Implement TOTP secret generation, QR code URI export, step-up verification, and backup recovery codes.

### Issue #20: [SESSION-01] Concurrent session management & active device listing
- **Status:** Closed
- **Milestone:** v1.0.0-rc1
- **Branch:** `feat/sessions`
- **Description:** Track active browser/device sessions, support remote session termination and global logout.

### Issue #21: [WEBHOOK-01] Outbound security webhooks with HMAC signatures
- **Status:** Closed
- **Milestone:** v1.0.0-rc2
- **Branch:** `feat/webhooks`
- **Description:** Deliver signed HTTP webhook dispatches on user events (`user.created`, `login.failed`, `lockout.triggered`).

### Issue #22: [OIDC-01] OpenID Connect Discovery & JWKS endpoint
- **Status:** Closed
- **Milestone:** v1.0.0-rc2
- **Branch:** `feat/oidc-discovery`
- **Description:** Expose `/.well-known/openid-configuration` and `/.well-known/jwks.json` for standard OIDC client integration.

### Issue #23: [OIDC-02] RFC 7662 OAuth 2.0 Token Introspection
- **Status:** Closed
- **Milestone:** v1.0.0-rc2
- **Branch:** `feat/introspection`
- **Description:** Implement `POST /api/v1/auth/introspect` for resource servers to validate token active status, scopes, and expiration.

### Issue #24: [INFRA-01] Docker, Docker Compose, and Nginx reverse proxy configuration
- **Status:** Closed
- **Milestone:** v1.0.0-rc2
- **Branch:** `feat/docker-setup`
- **Description:** Multi-stage Dockerfile, `docker-compose.yml` orchestrating API, PostgreSQL, Redis, and Nginx reverse proxy.

### Issue #25: [SDK-01] Python Client SDK & FastAPI middleware
- **Status:** Closed
- **Milestone:** v1.0.0-rc2
- **Branch:** `feat/python-sdk`
- **Description:** Lightweight Python client SDK and drop-in FastAPI middleware for downstream microservice authentication.

### Issue #26: [COMPLIANCE-01] GDPR Right to Access & Right to be Forgotten
- **Status:** Closed
- **Milestone:** v1.0.0
- **Branch:** `feat/compliance-gdpr`
- **Description:** Add `/api/v1/compliance/export` data portability export and `/api/v1/compliance/forget-me` pseudonymization pipeline.

### Issue #27: [METRICS-01] Prometheus Telemetry Exposition Endpoint
- **Status:** Closed
- **Milestone:** v1.0.0
- **Branch:** `feat/telemetry-metrics`
- **Description:** Zero-dependency Prometheus exposition router at `/metrics` tracking login attempts, latency, and security counters.

### Issue #28: [DOCS-01] Full documentation suite (Architecture, PRD, API, Security)
- **Status:** Closed
- **Milestone:** v1.0.0
- **Branch:** `docs/full-suite`
- **Description:** Produce complete technical documentation including `ARCHITECTURE.md`, `PRD.md`, `API.md`, `SECURITY.md`, and `README.md`.
