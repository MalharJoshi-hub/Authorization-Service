# Architecture Design Document: Auth-as-a-Service (AaaS)

## 1. High-Level Architectural Vision

Auth-as-a-Service (AaaS) is engineered as a modular, high-throughput, low-latency identity and access management system. It follows Clean Architecture principles, ensuring clear boundaries between cryptographic primitives, business domain logic, persistence layers, and HTTP transport delivery.

```
                    +------------------------------------+
                    |        Client Applications         |
                    | (SPA, Mobile, Microservices, M2M)  |
                    +-----------------+------------------+
                                      |
                                      | HTTPS (JSON / REST)
                                      v
                    +-----------------+------------------+
                    |           Reverse Proxy            |
                    |              (Nginx)               |
                    +-----------------+------------------+
                                      |
                                      v
+=============================================================================+
|                       LAYER 5: API & ADMIN LAYER                            |
|                                                                             |
|  +-------------------+  +-------------------+  +-------------------------+  |
|  |   Auth Routers    |  |   User Routers    |  |  RBAC & Key Routers     |  |
|  | (/auth/register,  |  | (/users/me,       |  | (/roles, /permissions,  |  |
|  |  /auth/login...)  |  |  /users/{id}...)  |  |  /api-keys...)          |  |
|  +-------------------+  +-------------------+  +-------------------------+  |
|  +-------------------+  +-------------------+  +-------------------------+  |
|  |   Admin Routers   |  |   OAuth Routers   |  |   Health & Metrics      |  |
|  | (/admin/users,    |  | (/oauth/google,   |  | (/health, /ready,       |  |
|  |  /admin/audit...) |  |  /oauth/github)   |  |  /health/metrics)       |  |
|  +-------------------+  +-------------------+  +-------------------------+  |
|                                                                             |
|  Middleware: CORS, Request-ID, Security Headers, Tenant Resolver, RateLimit|
+=============================================================================+
                                      |
                                      v
+=============================================================================+
|                 LAYER 3: AUTHORIZATION & RBAC LAYER                         |
|                                                                             |
|  - Role-Based Access Control (RBAC) Checker Engine                          |
|  - Granular Permission Evaluator (`<resource>:<action>` schema)             |
|  - API Key Scope Matcher (`read:users`, `write:keys`, `admin:*`)           |
|  - Multi-Tenant Isolation Enforcement Context                               |
+=============================================================================+
                                      |
                                      v
+=============================================================================+
|                   LAYER 2: IDENTITY & OAUTH LAYER                           |
|                                                                             |
|  - User Lifecycle: Register, Email Verification, Password Reset             |
|  - Social Authentication: Google OAuth2 & GitHub OAuth2 User Hydration      |
|  - Session Lifecycle & Brute Force Account Lockout Engine                   |
+=============================================================================+
                                      |
                                      v
+=============================================================================+
|                     LAYER 1: SECURITY CORE                                  |
|                                                                             |
|  - Password Hashing (Bcrypt, work factor 12, timing-safe equality)         |
|  - JWT Engine (RS256 / HS256, claim validation, deterministic jti)         |
|  - Refresh Token Rotation & Cryptographic Reuse Attack Detection            |
|  - API Key Generation (`aas_live_<hash>`) & SHA-256 Storage                 |
|  - Sliding-Window Rate Limiting Algorithm (Redis Sorted Set)                |
+=============================================================================+
                                      |
                                      v
+=============================================================================+
|                 LAYER 4: STORAGE REPOSITORIES & CACHING                     |
|                                                                             |
|  +------------------------------------+  +-------------------------------+  |
|  |      PostgreSQL Repositories       |  |        Redis Subsystems       |  |
|  | - UserRepository   - RoleRepository|  | - Token Blacklist (JTI TTL)   |  |
|  | - TokenRepository  - KeyRepository |  | - Sliding Rate Limit Store    |  |
|  | - TenantRepository - AuditLogRepo  |  | - Transient Verify/Reset Store|  |
|  +------------------------------------+  +-------------------------------+  |
|            Async SQLAlchemy 2.0 Pool               Async Redis Client Pool  |
+=============================================================================+
```

---

## 2. Detailed 5-Layer Breakdown

### Layer 1: Security Core
The cryptographic foundation of the platform. Does not depend on database or HTTP layers.
- **`core/security/password.py`**:
  - Encapsulates password hashing with bcrypt, fixed at cost factor 12.
  - Implements constant-time hash comparison to eliminate side-channel timing attacks.
  - Validates password complexity: minimum length (8 chars), upper, lower, numbers, symbols.
- **`core/security/jwt_handler.py`**:
  - Generates signed JWT access tokens and long-lived refresh tokens.
  - Enforces mandatory standard claims: `sub`, `exp`, `iat`, `nbf`, `jti`, `tenant_id`, `roles`, `scopes`.
  - Parses and verifies token validity, signature authenticity, and expiration status.
- **`core/security/token_blacklist.py`**:
  - Interfaces with Redis for immediate token revocation.
  - Stores `token:blacklist:{jti}` with TTL equivalent to the remaining validity of the JWT.
- **`core/security/token_rotation.py`**:
  - Implements refresh token rotation.
  - On each token refresh exchange, the presented refresh token is immediately revoked and an atomic new pair is minted.
  - If a previously consumed or revoked refresh token is presented, the system flags a **reuse attack** and instantly invalidates all sessions and tokens belonging to the compromised user.
- **`core/security/api_keys.py`**:
  - Generates secure random API keys with a recognizable prefix (`aas_live_` or `aas_test_`).
  - Stores SHA-256 digests in PostgreSQL, never plaintext.
  - Validates inbound API keys from HTTP headers (`X-API-Key`).
- **`core/security/rate_limiter.py`**:
  - Implements a Redis sliding-window counter algorithm using sorted sets (`ZADD`, `ZREMRANGEBYSCORE`, `ZCARD`).
  - Provides per-endpoint and per-IP throttling with customizable quotas (e.g. 5/min on login, 100/min on general API).

---

### Layer 2: Identity & OAuth Layer
Orchestrates user accounts, lifecycle transitions, credential updates, and third-party social integrations.
- **`storage/postgres/user_repo.py`**:
  - Handles user CRUD operations with async SQLAlchemy.
  - Implements transactional atomic updates and soft-deletion.
- **Registration Flow**:
  - Generates an unverified user account.
  - Issues a cryptographically secure 32-byte URL-safe email verification token stored in Redis with 24-hour TTL.
- **Email Verification Flow**:
  - Verifies token against Redis; on match, sets `is_verified = True` and clears the token.
- **Password Reset Flow**:
  - Issues a one-time reset token with 1-hour TTL.
  - Resetting password invalidates all existing user refresh tokens and access token JTIs.
- **OAuth2 Engine (`api/routes/oauth.py`)**:
  - Modular adapters for Google OAuth2 and GitHub OAuth2.
  - Handles state validation (CSRF defense), authorization code exchange, and profile retrieval.
  - Links external identity accounts (`oauth_accounts` table) to native user records.
- **Account Lockout (`core/security/lockout.py`)**:
  - Tracks consecutive failed attempts in Redis keys `lockout:failed:{user_id}`.
  - Locks account for 15 minutes after 5 consecutive failures; administrator manual unlock supported.

---

### Layer 3: Authorization & RBAC
Controls access to resources based on assigned roles, granular permissions, and API key scopes.
- **Role & Permission Models**:
  - `Role`: Named group of permissions (`superadmin`, `tenant_admin`, `member`, `viewer`).
  - `Permission`: Canonical string formatted as `<resource>:<action>` (e.g., `users:read`, `users:write`, `roles:delete`).
  - `UserRole`: Many-to-many relationship linking users to roles within a tenant boundary.
- **Permission Evaluator (`core/rbac/checker.py`)**:
  - Evaluates user roles against required permissions.
  - Supports wildcard permissions (`admin:*`, `*:read`).
  - FastAPI dependency factory `require_permission("users:read")` and `require_role("admin")`.
- **API Key Scopes (`core/security/scopes.py`)**:
  - API keys carry assigned scopes (`read:users`, `write:keys`).
  - Endpoints accept either valid JWT with permissions or valid API Key with required scopes.
- **Multi-Tenant Isolation**:
  - Tenants have isolated data boundaries (`tenants` table).
  - Multi-tenant middleware resolves the tenant context from `X-Tenant-ID` header or JWT claims.
  - All database queries filter automatically by `tenant_id` to prevent cross-tenant data leaks.

---

### Layer 4: Storage & Caching
High-performance asynchronous data access and memory stores.
- **PostgreSQL Async Engine**:
  - Built with SQLAlchemy 2.0 Async and `asyncpg`.
  - Database connection pool configured with keepalive, ping validation, and recycle intervals.
- **Redis High-Performance Store**:
  - Async connection pool via `redis.asyncio`.
  - In-memory mock fallback mode for development and local testing when external Redis service is unconfigured.
- **Data Schema & Tables**:
  - `tenants`: Multi-tenant organization boundaries.
  - `users`: Core identity credentials, verification flags, lockout state.
  - `oauth_accounts`: Third-party identity provider bindings.
  - `roles`: Role definitions per tenant.
  - `permissions`: System-wide and custom granular permissions.
  - `role_permissions`: Association table mapping roles to permissions.
  - `user_roles`: Association table mapping users to roles.
  - `refresh_tokens`: Token families, hashes, revocation status, expiration dates.
  - `api_keys`: Machine credentials, SHA-256 hashes, prefix, scopes, expiration.
  - `audit_logs`: Append-only immutable security ledger.
- **Alembic Migrations**:
  - Fully version-controlled database schema migrations.
  - Automated migration runner on startup.

---

### Layer 5: API & Admin Layer
FastAPI HTTP application exposing all endpoints, middleware pipelines, and administrative tools.
- **Middleware Pipeline**:
  - `RequestIdMiddleware`: Generates and propagates unique UUID `X-Request-ID` across logs and headers.
  - `SecurityHeadersMiddleware`: Injects `HSTS`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Content-Security-Policy`.
  - `RequestLoggerMiddleware`: Logs request timing, status code, IP, and method in structured JSON.
  - `TenantMiddleware`: Resolves and validates tenant context.
  - `RateLimitMiddleware`: Enforces sliding-window limits before route execution.
- **Endpoint Catalog (30+ Endpoints)**:
  - **Auth**: `/auth/register`, `/auth/verify-email`, `/auth/resend-verification`, `/auth/login`, `/auth/logout`, `/auth/refresh`, `/auth/forgot-password`, `/auth/reset-password`.
  - **OAuth**: `/oauth/google`, `/oauth/google/callback`, `/oauth/github`, `/oauth/github/callback`, `/oauth/providers`, `/oauth/{provider}`.
  - **Users**: `/users/me`, `/users/me/password`, `/users/me` (PUT/DELETE), `/users/{id}`.
  - **Roles**: `/roles` (GET/POST), `/roles/{id}` (GET/PUT/DELETE), `/roles/{id}/permissions` (POST), `/users/{id}/roles`.
  - **Permissions**: `/permissions` (GET/POST).
  - **API Keys**: `/api-keys` (GET/POST), `/api-keys/{id}` (GET/DELETE).
  - **Tenants**: `/tenants` (GET/POST), `/tenants/me` (GET/PUT), `/tenants/me/invites` (POST), `/tenants/{id}`.
  - **Admin**: `/admin/users`, `/admin/users/{id}`, `/admin/users/{id}/lock`, `/admin/users/{id}/unlock`, `/admin/audit-logs`, `/admin/audit-logs/export`, `/admin/analytics/overview`, `/admin/analytics/events`.
  - **Health**: `/health`, `/health/ready`, `/health/metrics`.
- **OpenAPI / Swagger**:
  - Interactive documentation with comprehensive schemas, example payloads, and security scheme definitions (`BearerAuth` and `ApiKeyAuth`).

---

## 3. Security Decisions & Rationale

| Requirement | Implementation Decision | Security Rationale |
|---|---|---|
| **Password Storage** | Bcrypt (Cost 12) | Standard recommendation; resistant to GPU acceleration attacks; cost 12 offers ideal balance of ~150ms calculation time vs DoS prevention. |
| **Token Invalidation** | Redis JTI Blacklist | Stateless JWTs cannot be revoked without state; indexing compact `jti` strings in Redis with TTLs matching JWT expiry provides $O(1)$ revocation checks with minimal memory overhead. |
| **Refresh Security** | Cryptographic Token Rotation | Protects against token theft; each refresh is single-use; reuse triggers instant family invalidation. |
| **API Key Storage** | SHA-256 Hashing | Plaintext API keys are never stored; if database is leaked, keys cannot be recovered or abused. |
| **Rate Limiting** | Sliding Window (Redis Sorted Sets) | Prevents burst abuse at minute boundaries (unlike fixed window counters) and handles micro-burst attacks effectively. |
| **Multi-Tenancy** | Shared Database, Tenant Isolation Column | High resource efficiency with strict software-level isolation in all queries and repository methods. |
| **Audit Logs** | Immutable Append-Only Ledger | Essential for compliance (SOC2, ISO 27001, HIPAA); logs cannot be modified once written. |
