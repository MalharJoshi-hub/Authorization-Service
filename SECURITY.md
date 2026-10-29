# Security Policy & Threat Model

At Auth-as-a-Service (AaaS), security is the foundational design constraint. This document outlines our vulnerability disclosure policy, cryptographic standards, enterprise threat models, and architectural defensive controls.

---

## 1. Vulnerability Reporting & Disclosure

We welcome responsible security disclosures from developers, researchers, and penetration testers. If you believe you have identified a vulnerability in this platform, please report it immediately:

- **Security Team Email:** `security@authservice.io`
- **PGP Fingerprint:** `4A7E 9B21 C3F8 0D5A E829 7B44 12D0 9A7F 3C8E 1F2B`
- **Response SLA:**
  - **Initial Triage:** Within 24 hours.
  - **Vulnerability Assessment & Fix Timeline:** Within 72 hours for Critical/High severity (CVSS >= 7.0).
  - **Public Disclosure:** Coordinated 30 days post-patch release.

> [!IMPORTANT]
> Please do not publicly disclose any potential security flaw until the engineering team has verified, addressed, and deployed a fix to the stable release branch.

---

## 2. Threat Model & Defensive Mitigations

The platform implements multi-layered defensive controls modeled after OWASP Top 10 API Security Risks and NIST SP 800-63B standards:

### 2.1 Credential Stuffing & Brute Force Attacks
- **Sliding-Window Rate Limiting:** Enforced via Redis across IP and username dimensions (defaults: 5 failed attempts per minute on `/login`, 10 requests per minute on `/register`).
- **Account Lockout:** Progressive lockout triggers after 5 consecutive failures, requiring a 15-minute cooldown or administrator unlock.
- **Pwned Password Verification:** Evaluates candidate passwords against 800M+ compromised passwords using HaveIBeenPwned k-anonymity (SHA-1 prefix hashing), preventing users from setting breached credentials.
- **Timing Uniformity:** Dummy cryptographic verification executes on nonexistent users to eliminate timing side-channels during username enumeration.

### 2.2 Token Theft, Replay, and Invalidation
- **Dual-Token Architecture:** Access tokens are short-lived (15 minutes). Refresh tokens are long-lived (7 days) and strictly single-use.
- **Token Rotation & Reuse Detection:** When an already-consumed refresh token is presented, the system flags a token theft event and revokes all issued tokens associated with that session lineage immediately.
- **JTI Blacklisting:** Instant revocation via Redis with TTL matching token expiration.
- **Asymmetric Signing & JWKS:** Supports RS256 and Ed25519 asymmetric keys, allowing external resource servers to verify token integrity without possessing the private signing key.

### 2.3 Cross-Tenant Data Leakage
- **Horizontal Multi-Tenant Isolation:** All database queries require tenant scoping (`X-Tenant-ID` header validated against authenticated JWT claims).
- **Tenant Boundary Enforcement:** `TenantIsolationService` verifies cross-tenant authorization at the domain layer before any model fetch or mutation occurs.
- **Plan Quotas:** Enforces subscription ceilings (`starter`, `standard`, `enterprise`) preventing resource exhaustion.

### 2.4 CSRF, Replay, and Webhook Tampering
- **Double Submit Cookie CSRF Defense:** Statistically random CSRF token issued via Secure, SameSite=Strict cookies; verified against request header on state-modifying endpoints.
- **Webhook HMAC-SHA256 Signatures:** Webhook payloads are signed using a tenant-specific 256-bit secret, formatted with timestamp headers (`t={timestamp},v1={hash}`) to thwart replay attacks.
- **Mutual TLS (mTLS):** Validates client certificate subject DN and thumbprint for high-assurance API gateway communication.

### 2.5 Cryptographic Standards
| Primitive | Standard / Algorithm | Rationale |
|---|---|---|
| **Primary Password Hashing** | Bcrypt (cost 12) + SHA-256 Pre-Hash | Mitigates bcrypt 72-byte truncation without entropy loss while resisting GPU cracking. |
| **Alternative Password Hasher** | Argon2id (m=64MB, t=3, p=4) | Memory-hard password hashing recommended by OWASP. |
| **Legacy / FIPS Fallback** | PBKDF2-HMAC-SHA256 (600,000 iterations) | FIPS 140-3 compliant key derivation. |
| **Symmetric Token Signing** | HMAC SHA-256 (`HS256`, `HS384`, `HS512`) | High-throughput microservice verification. |
| **Asymmetric Token Signing** | RSA-2048 (`RS256`), Ed25519 (`EdDSA`) | Standard enterprise JWKS federation. |
| **API Key Storage** | SHA-256 Hex Digest | Raw key is never stored; keys are verified using constant-time hash comparison. |
| **MFA TOTP** | RFC 6238 HMAC-SHA1 (30s window) | Universal authenticator app compatibility (Google Authenticator, Authy). |
| **WebAuthn / FIDO2** | W3C WebAuthn Level 2 / CTAP2 | Hardware-backed biometric and security key authentication. |

---

## 3. Password Complexity Policy

By default, passwords must satisfy all of the following requirements:
- Minimum length of 8 characters (12+ recommended, enterprise configurable).
- At least one uppercase letter (`A-Z`).
- At least one lowercase letter (`a-z`).
- At least one numeric digit (`0-9`).
- At least one special symbol (`!@#$%^&*()_+-=[]{}|;:,.<>?`).
- Cannot match any of the user's previous 5 historical password hashes.
- Cannot exist in the known breached dictionary list.

---

## 4. Compliance & Privacy (GDPR / CCPA)

- **Article 15 (Right to Access):** Automated `/api/v1/compliance/export` compiles all tenant data, session history, and security logs for a requested subject into an encrypted JSON dossier.
- **Article 17 (Right to Erasure):** `/api/v1/compliance/erase` irreversibly anonymizes email addresses, deletes password hashes, purges active sessions, and marks audit trails with pseudonymized placeholders (`DELETED_USER_<id>`).
- **Audit Logging Immutability:** Audit entries are append-only; update and delete operations on the `audit_logs` table are strictly forbidden.
