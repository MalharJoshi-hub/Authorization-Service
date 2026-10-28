# Auth-as-a-Service (AaaS) REST API Reference

Enterprise-grade self-hosted authentication, authorization, and multi-tenant security platform.

- **Base URL (Local):** `http://localhost:8000`
- **API Prefix:** `/api/v1`
- **Interactive OpenAPI Documentation:** `http://localhost:8000/docs`
- **ReDoc Interactive Reference:** `http://localhost:8000/redoc`
- **JWKS Endpoint:** `http://localhost:8000/.well-known/jwks.json`
- **OIDC Discovery:** `http://localhost:8000/.well-known/openid-configuration`
- **Prometheus Metrics:** `http://localhost:8000/metrics`

---

## Standard Headers

| Header | Type | Description |
|---|---|---|
| `Authorization` | String | `Bearer <access_token>` |
| `X-API-Key` | String | `aas_live_<entropy>` or `aas_test_<entropy>` |
| `X-Tenant-ID` | UUID | Target tenant UUID boundary (optional if domain is bound) |
| `X-Request-ID` | UUID | Trace correlation ID (auto-generated if omitted) |
| `Content-Type` | String | `application/json` |

---

## Error Response Format (RFC 7807 Problem Details)

All API errors return a standard JSON object with an HTTP error status code:

```json
{
  "error": "AUTHENTICATION_FAILED",
  "message": "Invalid email address or password provided.",
  "code": "INVALID_CREDENTIALS",
  "request_id": "c1f7b82e-9d2a-4f51-b01e-3f6a2e88a012",
  "timestamp": "2026-11-02T10:00:00Z"
}
```

---

## 1. Authentication Endpoints (`/api/v1/auth`)

### 1.1 Register User
- **Method:** `POST`
- **Path:** `/api/v1/auth/register`
- **Auth:** Public
- **Rate Limit:** 3 req / minute

#### Request Body
```json
{
  "email": "developer@example.com",
  "password": "Compl3xP@ssword2026!",
  "full_name": "Jane Developer",
  "tenant_id": "00000000-0000-0000-0000-000000000001"
}
```

#### Response (`201 Created`)
```json
{
  "id": "74f3faad-037c-4ce5-a3de-0a2fbf376eae",
  "email": "developer@example.com",
  "full_name": "Jane Developer",
  "tenant_id": "00000000-0000-0000-0000-000000000001",
  "is_verified": false,
  "message": "Registration successful. Please verify your email."
}
```

---

### 1.2 User Login
- **Method:** `POST`
- **Path:** `/api/v1/auth/login`
- **Auth:** Public
- **Rate Limit:** 5 req / minute
- **Account Lockout:** Triggers after 5 consecutive failures

#### Request Body
```json
{
  "email": "developer@example.com",
  "password": "Compl3xP@ssword2026!"
}
```

#### Response (`200 OK`)
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 1800,
  "user": {
    "id": "74f3faad-037c-4ce5-a3de-0a2fbf376eae",
    "email": "developer@example.com",
    "full_name": "Jane Developer",
    "tenant_id": "00000000-0000-0000-0000-000000000001",
    "roles": ["member"],
    "is_verified": true
  }
}
```

---

### 1.3 Refresh Token
- **Method:** `POST`
- **Path:** `/api/v1/auth/refresh`
- **Auth:** Public (requires refresh token)
- **Security:** Automatic token rotation with replay detection

#### Request Body
```json
{
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

#### Response (`200 OK`)
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 1800
}
```

---

### 1.4 Logout
- **Method:** `POST`
- **Path:** `/api/v1/auth/logout`
- **Auth:** Bearer Token
- **Action:** Adds token JTI to Redis blacklist and revokes active refresh token family.

#### Response (`200 OK`)
```json
{
  "message": "Successfully logged out. Tokens revoked."
}
```

---

### 1.5 Token Introspection (RFC 7662)
- **Method:** `POST`
- **Path:** `/api/v1/auth/introspect`
- **Auth:** Resource Server Token or API Key

#### Request Body
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

#### Response (`200 OK`)
```json
{
  "active": true,
  "scope": "read:users write:users",
  "client_id": "aaas_client",
  "sub": "74f3faad-037c-4ce5-a3de-0a2fbf376eae",
  "exp": 1798848000,
  "iat": 1798844400,
  "iss": "http://localhost:8000",
  "tenant_id": "00000000-0000-0000-0000-000000000001",
  "roles": ["member"]
}
```

---

## 2. OAuth & Social Sign-In (`/api/v1/oauth`)

### 2.1 Google OAuth Initiation
- **Method:** `GET`
- **Path:** `/api/v1/oauth/google`
- **Action:** Redirects browser to Google Accounts OAuth 2.0 authorization URL.

### 2.2 Google OAuth Callback
- **Method:** `GET`
- **Path:** `/api/v1/oauth/google/callback?code=4/P7q...&state=...`
- **Response:** Returns TokenResponse bundle or sets session cookie.

### 2.3 GitHub OAuth Initiation
- **Method:** `GET`
- **Path:** `/api/v1/oauth/github`
- **Action:** Redirects browser to GitHub OAuth authorization screen.

### 2.4 GitHub OAuth Callback
- **Method:** `GET`
- **Path:** `/api/v1/oauth/github/callback?code=gh_code...&state=...`
- **Response:** Returns TokenResponse bundle.

### 2.5 List Linked Social Accounts
- **Method:** `GET`
- **Path:** `/api/v1/oauth/accounts`
- **Auth:** Bearer Token

---

## 3. User Profiles (`/api/v1/users`)

### 3.1 Get Current Profile
- **Method:** `GET`
- **Path:** `/api/v1/users/me`
- **Auth:** Bearer Token

#### Response (`200 OK`)
```json
{
  "id": "74f3faad-037c-4ce5-a3de-0a2fbf376eae",
  "email": "developer@example.com",
  "full_name": "Jane Developer",
  "avatar_url": "https://avatars.example.com/jane.png",
  "is_active": true,
  "is_verified": true,
  "is_superuser": false,
  "tenant_id": "00000000-0000-0000-0000-000000000001",
  "roles": [
    {
      "id": "role-1",
      "name": "member",
      "description": "Standard organizational member"
    }
  ],
  "created_at": "2026-11-02T10:00:00Z"
}
```

### 3.2 Update Profile
- **Method:** `PATCH`
- **Path:** `/api/v1/users/me`
- **Auth:** Bearer Token

### 3.3 Change Password
- **Method:** `POST`
- **Path:** `/api/v1/users/me/change-password`
- **Auth:** Bearer Token

---

## 4. RBAC Roles & Permissions (`/api/v1/roles`, `/api/v1/permissions`)

### 4.1 List Roles
- **Method:** `GET`
- **Path:** `/api/v1/roles`
- **Auth:** Bearer Token (Permission: `read:roles`)

### 4.2 Create Role
- **Method:** `POST`
- **Path:** `/api/v1/roles`
- **Auth:** Bearer Token (Permission: `write:roles`)

```json
{
  "name": "security_auditor",
  "description": "Read-only access to audit logs and telemetry",
  "permission_names": ["audit:read", "audit:export", "analytics:read"]
}
```

### 4.3 List Granular Permissions
- **Method:** `GET`
- **Path:** `/api/v1/permissions`
- **Auth:** Bearer Token (Permission: `read:permissions`)

---

## 5. Machine-to-Machine API Keys (`/api/v1/api-keys`)

### 5.1 Issue API Key
- **Method:** `POST`
- **Path:** `/api/v1/api-keys`
- **Auth:** Bearer Token (Permission: `manage:api_keys`)

#### Request Body
```json
{
  "name": "GitHub CI/CD Service Worker",
  "scopes": ["users:read", "audit:read"]
}
```

#### Response (`201 Created`)
```json
{
  "id": "key-9921b0",
  "name": "GitHub CI/CD Service Worker",
  "prefix": "aas_live_9a8b1c",
  "raw_key": "aas_live_9a8b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c",
  "scopes": ["users:read", "audit:read"],
  "created_at": "2026-11-02T10:00:00Z",
  "warning": "Copy this secret key now. It will NEVER be visible again."
}
```

### 5.2 List Active API Keys
- **Method:** `GET`
- **Path:** `/api/v1/api-keys`
- **Auth:** Bearer Token (Permission: `manage:api_keys`)

### 5.3 Revoke API Key
- **Method:** `DELETE`
- **Path:** `/api/v1/api-keys/{id}`
- **Auth:** Bearer Token (Permission: `manage:api_keys`)

---

## 6. Multi-Tenant Organizations (`/api/v1/tenants`)

### 6.1 Get Current Tenant Configuration
- **Method:** `GET`
- **Path:** `/api/v1/tenants/current`
- **Auth:** Bearer Token

### 6.2 Update Tenant Settings
- **Method:** `PATCH`
- **Path:** `/api/v1/tenants/current`
- **Auth:** Bearer Token (Permission: `manage:tenants`)

---

## 7. Multi-Factor Authentication (MFA / TOTP) (`/api/v1/mfa`)

### 7.1 Setup TOTP
- **Method:** `POST`
- **Path:** `/api/v1/mfa/setup`
- **Auth:** Bearer Token
- **Returns:** Base32 secret string and QR code data URI.

### 7.2 Verify and Activate TOTP
- **Method:** `POST`
- **Path:** `/api/v1/mfa/verify`
- **Auth:** Bearer Token
- **Request Body:** `{"code": "123456"}`

### 7.3 Regenerate Backup Recovery Codes
- **Method:** `POST`
- **Path:** `/api/v1/mfa/recovery-codes/regenerate`
- **Auth:** Bearer Token (with step-up confirmation)

---

## 8. Session Management (`/api/v1/sessions`)

### 8.1 List Active Sessions & Devices
- **Method:** `GET`
- **Path:** `/api/v1/sessions`
- **Auth:** Bearer Token
- **Returns:** List of active browser/device sessions with IP, User-Agent, and last activity timestamp.

### 8.2 Terminate Session
- **Method:** `DELETE`
- **Path:** `/api/v1/sessions/{session_id}`
- **Auth:** Bearer Token

### 8.3 Terminate All Other Sessions
- **Method:** `DELETE`
- **Path:** `/api/v1/sessions`
- **Auth:** Bearer Token

---

## 9. Security Webhooks (`/api/v1/webhooks`)

### 9.1 Register Webhook Endpoint
- **Method:** `POST`
- **Path:** `/api/v1/webhooks`
- **Auth:** Bearer Token (Permission: `manage:webhooks`)

```json
{
  "url": "https://siem.internal.company.com/ingest/auth-events",
  "events": ["user.created", "login.failure", "account.locked", "token.revoked"],
  "description": "Splunk Ingestion Pipeline"
}
```

---

## 10. GDPR & Compliance (`/api/v1/compliance`)

### 10.1 Export Personal Data (Right to Access)
- **Method:** `GET`
- **Path:** `/api/v1/compliance/export`
- **Auth:** Bearer Token
- **Returns:** Structured JSON data portability archive with SHA-256 integrity digest.

### 10.2 Right to be Forgotten (Account Erasure)
- **Method:** `POST`
- **Path:** `/api/v1/compliance/forget-me`
- **Auth:** Bearer Token
- **Action:** Pseudonymizes PII, revokes all sessions/tokens, and marks account erased.

---

## 11. Administration & Observability (`/api/v1/admin`)

### 11.1 Administrative User Search
- **Method:** `GET`
- **Path:** `/api/v1/admin/users?skip=0&limit=50&search=alex`
- **Auth:** Bearer Token (Role: `admin`)

### 11.2 Unlock Account
- **Method:** `POST`
- **Path:** `/api/v1/admin/users/{user_id}/unlock`
- **Auth:** Bearer Token (Role: `admin`)

### 11.3 Query Audit Logs
- **Method:** `GET`
- **Path:** `/api/v1/admin/audit-logs?event_type=auth.login.failure`
- **Auth:** Bearer Token (Permission: `audit:read`)

### 11.4 Export Audit Logs (CSV)
- **Method:** `GET`
- **Path:** `/api/v1/admin/audit-logs/export`
- **Auth:** Bearer Token (Permission: `audit:export`)
- **Returns:** `text/csv` attachment.

### 11.5 Telemetry Overview
- **Method:** `GET`
- **Path:** `/api/v1/admin/analytics/overview`
- **Auth:** Bearer Token (Permission: `analytics:read`)

---

## 12. Public Probes & Discovery

- `GET /health`: Liveness & readiness probe (`{"status": "ok", "version": "1.0.0"}`)
- `GET /metrics`: Standard Prometheus metrics exposition
- `GET /.well-known/openid-configuration`: OpenID Connect discovery metadata
- `GET /.well-known/jwks.json`: Public RFC 7517 JSON Web Key Set
