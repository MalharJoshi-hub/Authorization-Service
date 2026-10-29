"""Security fuzzing, payload mutation, and input boundary tests."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_fuzz_login_sql_injection_payloads(async_client: AsyncClient):
    sql_payloads = [
        "' OR 1=1 --",
        "admin' --",
        "' OR 'x'='x",
        "'; DROP TABLE users; --",
        "1' UNION SELECT null, null, null--",
    ]

    for payload in sql_payloads:
        resp = await async_client.post(
            "/api/v1/auth/login",
            json={"username": payload, "password": "AnyPassword123!"},
        )
        # Service must return 401 Unauthorized or 400 Bad Request, NEVER 500 or SQL syntax error
        assert resp.status_code in (400, 401, 422)
        assert "syntax error" not in resp.text.lower()
        assert "traceback" not in resp.text.lower()


@pytest.mark.asyncio
async def test_fuzz_register_xss_payloads(async_client: AsyncClient):
    xss_payloads = [
        "<script>alert('xss')</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
        "'\"><svg/onload=alert(1)>",
    ]

    for idx, payload in enumerate(xss_payloads):
        resp = await async_client.post(
            "/api/v1/auth/register",
            json={
                "email": f"xss_{idx}@example.com",
                "username": f"xss_user_{idx}",
                "password": "ValidPassword123!",
                "full_name": payload,
            },
        )
        # Should either successfully store as sanitized text or reject with 422
        assert resp.status_code in (200, 201, 422)


@pytest.mark.asyncio
async def test_fuzz_oversized_payloads(async_client: AsyncClient):
    huge_string = "A" * 100_000
    resp = await async_client.post(
        "/api/v1/auth/login",
        json={"username": huge_string, "password": "AnyPassword123!"},
    )
    assert resp.status_code in (400, 401, 413, 422)


@pytest.mark.asyncio
async def test_fuzz_null_byte_injection(async_client: AsyncClient):
    resp = await async_client.post(
        "/api/v1/auth/login",
        json={"username": "admin\x00user", "password": "Password123!"},
    )
    assert resp.status_code in (400, 401, 422)


@pytest.mark.asyncio
async def test_fuzz_malformed_auth_headers(async_client: AsyncClient):
    malformed_headers = [
        {"Authorization": "Bearer"},
        {"Authorization": "Bearer "},
        {"Authorization": "Bearer invalid.jwt.token"},
        {"Authorization": "Bearer " + "a" * 1000},
        {"Authorization": "Basic YWRtaW46cGFzc3dvcmQ="},
        {"Authorization": "Token 123456"},
    ]

    for h in malformed_headers:
        resp = await async_client.get("/api/v1/users/me", headers=h)
        assert resp.status_code == 401
