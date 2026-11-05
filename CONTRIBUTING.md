# Contributing to Auth-as-a-Service (AaaS)

Thank you for your interest in contributing to Auth-as-a-Service! We welcome contributions from developers of all skill levels. To ensure clean code quality, stability, and architectural consistency, please follow these guidelines.

---

## 1. Code of Conduct

We are committed to providing a welcoming, inclusive, and harassment-free experience for everyone. Treat all contributors, maintainers, and community members with respect, constructive feedback, and professional courtesy.

---

## 2. Development Setup

### 2.1 Prerequisites
- Python 3.14+ (or 3.11+)
- Git 2.30+
- PostgreSQL 16+ & Redis 7+ (or Docker Compose)

### 2.2 Local Environment Setup
```bash
# Fork & clone the repository
git clone https://github.com/organization/auth-service.git
cd auth-service

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Or .\venv\Scripts\Activate.ps1 on Windows

# Install all development and testing dependencies
pip install -r requirements.txt

# Copy development environment variables
cp .env.example .env
```

---

## 3. Branching Strategy & Git Workflow

We follow standard Trunk-Based Development with feature branches merged via Pull Requests (`--no-ff`):

### 3.1 Branch Naming Conventions
- `feat/<short-description>`: New functional features or endpoints (e.g. `feat/mfa-totp`).
- `fix/<short-description>`: Bug fixes or security patches (e.g. `fix/jwt-aud-validation`).
- `docs/<short-description>`: Documentation additions or updates (e.g. `docs/api-guide`).
- `test/<short-description>`: Test suite expansions or matrix fuzzing (e.g. `test/fuzzing-matrix`).
- `refactor/<short-description>`: Code cleanup without altering external behavior.

### 3.2 Commit Message Standard
We adhere strictly to [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <short imperative summary>

[optional body explaining context, rationale, and design choices]

[optional footer referencing issue tracker, e.g. Resolves #12]
```

**Permitted Types:**
- `feat`: New feature or capability.
- `fix`: Bug fix or patch.
- `docs`: Documentation updates.
- `test`: Adding or modifying tests.
- `refactor`: Code change that neither fixes a bug nor adds a feature.
- `chore`: Build scripts, CI configs, dependency updates.

**Examples:**
```
feat(mfa): implement RFC 6238 TOTP enrollment and challenge verification

Adds endpoint /api/v1/mfa/totp/setup and QR code generation.
Resolves #18.
```

---

## 4. Architectural Rules

Any code contributed to this repository must respect the **5-Layer Architecture**:

1. **Layer 1 (Core Security Primitives):** Cannot import from Layers 2, 3, 4, or 5. Pure cryptographic utilities and algorithmic validators.
2. **Layer 2 (Auth Domain & Adapters):** Domain models and third-party provider adapters.
3. **Layer 3 (Multi-Tenancy & Orchestration):** Tenant scoping, permissions enforcement, and business workflows.
4. **Layer 4 (Storage & Persistence):** PostgreSQL SQLAlchemy 2.0 repositories and Redis stores. No HTTP/FastAPI dependencies.
5. **Layer 5 (API & Presentation):** FastAPI routes, Pydantic schemas, dependency injection, and middleware.

---

## 5. Testing & Code Quality Expectations

Every pull request must maintain or improve the overall quality bar:

1. **Unit & Integration Tests:**
   Every new endpoint or service method must be covered by unit tests in `tests/unit/` and integration tests in `tests/integration/`.
2. **Test Coverage Threshold:**
   Project coverage must remain $\ge 65\%$ (current baseline is **83%**).
3. **Run Test Suite:**
   ```bash
   pytest
   # With coverage:
   pytest --cov=auth_service --cov-report=term-missing
   ```
4. **All 1,200+ tests must pass with zero failures or errors.**

---

## 6. Pull Request Submission Checklist

Before submitting a Pull Request, verify:
- [ ] Code follows PEP 8 conventions.
- [ ] Type annotations are provided for all public methods and endpoints.
- [ ] All 1,212+ pytest tests pass cleanly.
- [ ] Documentation updated in `API.md` if endpoints are modified or added.
- [ ] Git commit history is clean, rebased against `master`, with descriptive commit messages.
- [ ] Linked relevant GitHub issue in the PR description (e.g., `Resolves #14`).

