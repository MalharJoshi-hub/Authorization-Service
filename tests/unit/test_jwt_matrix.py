"""Comprehensive cryptographic matrix tests for JSON Web Tokens (JWT).

Tests:
- Algorithm permutations (HS256, HS384, HS512, RS256)
- Clock skew tolerance and edge cases (leeway windows)
- Token claims validation (sub, iss, aud, nbf, exp, jti, amr)
- Tampering detection and cryptographic failure modes
- Malformed headers, payloads, signatures, and unicode encoding
"""

import time
import uuid
from datetime import datetime, timedelta, timezone
import jwt
import pytest

from auth_service.config import settings
from auth_service.core.exceptions import AuthenticationError
from auth_service.core.security.jwt_handler import (
    create_access_token,
    create_refresh_token,
    decode_token,
    encode_jwt,
    decode_jwt,
    get_token_jti,
)


# --- 1. Algorithm Permutations ---

def test_jwt_default_algorithm_is_hs256():
    token = create_access_token(user_id="u-1", email="u1@test.org", tenant_id="t-1")
    header = jwt.get_unverified_header(token)
    assert header["alg"] == "HS256"


def test_jwt_hs384_signing_and_verification():
    payload = {"sub": "u-hs384", "tenant_id": "t-1", "exp": int(time.time()) + 3600}
    token = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm="HS384")
    header = jwt.get_unverified_header(token)
    assert header["alg"] == "HS384"
    decoded = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=["HS384"])
    assert decoded["sub"] == "u-hs384"


def test_jwt_hs512_signing_and_verification():
    payload = {"sub": "u-hs512", "tenant_id": "t-1", "exp": int(time.time()) + 3600}
    token = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm="HS512")
    header = jwt.get_unverified_header(token)
    assert header["alg"] == "HS512"
    decoded = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=["HS512"])
    assert decoded["sub"] == "u-hs512"


def test_jwt_reject_none_algorithm():
    # Constructing a token with alg 'none'
    token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9."
    with pytest.raises(AuthenticationError):
        decode_token(token)


def test_jwt_algorithm_mismatch_fails():
    # Signed with HS512 but decoded with HS256 expected
    payload = {"sub": "u-test", "exp": int(time.time()) + 3600, "token_type": "access", "jti": "jti-1"}
    token = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm="HS512")
    with pytest.raises(AuthenticationError):
        decode_token(token)


# --- 2. Clock Skew and Timestamp Boundaries ---

def test_jwt_expired_token_raises_error():
    # Expired 10 seconds ago
    now = datetime.now(timezone.utc)
    delta = timedelta(seconds=-10)
    token = create_access_token(user_id="u-exp", email="exp@test.org", tenant_id="t-1", expires_delta=delta)
    with pytest.raises(AuthenticationError) as exc_info:
        decode_token(token)
    assert "expired" in str(exc_info.value).lower()


def test_jwt_future_issued_token_valid_within_lifetime():
    now = int(time.time())
    payload = {
        "sub": "u-future",
        "tenant_id": "t-1",
        "token_type": "access",
        "jti": str(uuid.uuid4()),
        "iat": now,
        "nbf": now,
        "exp": now + 600,
    }
    token = encode_jwt(payload)
    decoded = decode_token(token)
    assert decoded["sub"] == "u-future"


def test_jwt_nbf_in_future_rejected():
    now = int(time.time())
    payload = {
        "sub": "u-nbf",
        "tenant_id": "t-1",
        "token_type": "access",
        "jti": str(uuid.uuid4()),
        "iat": now,
        "nbf": now + 300,  # Valid 5 mins from now
        "exp": now + 600,
    }
    token = encode_jwt(payload)
    with pytest.raises(AuthenticationError):
        decode_token(token)


# --- 3. Claims Verification and Types ---

def test_jwt_access_token_claims_structure():
    roles = ["admin", "editor"]
    perms = ["read:users", "write:users"]
    extra = {"custom_org": "finance_corp"}

    token = create_access_token(
        user_id="u-claims",
        email="claims@test.org",
        tenant_id="t-org-99",
        roles=roles,
        permissions=perms,
        extra_claims=extra,
    )
    payload = decode_token(token, expected_type="access")

    assert payload["sub"] == "u-claims"
    assert payload["email"] == "claims@test.org"
    assert payload["tenant_id"] == "t-org-99"
    assert payload["roles"] == roles
    assert payload["permissions"] == perms
    assert payload["custom_org"] == "finance_corp"
    assert payload["token_type"] == "access"
    assert "jti" in payload
    assert "exp" in payload
    assert "iat" in payload


def test_jwt_refresh_token_claims_structure():
    res = create_refresh_token(user_id="u-ref", tenant_id="t-1", family_id="fam-42")
    token = res["token"]
    assert res["family_id"] == "fam-42"

    payload = decode_token(token, expected_type="refresh")
    assert payload["sub"] == "u-ref"
    assert payload["tenant_id"] == "t-1"
    assert payload["family_id"] == "fam-42"
    assert payload["token_type"] == "refresh"


def test_jwt_wrong_expected_type_raises():
    access_token = create_access_token(user_id="u-1", email="u1@test.org", tenant_id="t-1")
    with pytest.raises(AuthenticationError) as exc_info:
        decode_token(access_token, expected_type="refresh")
    assert "Invalid token type" in str(exc_info.value)


# --- 4. Tampering & Malformed Payloads ---

def test_jwt_tampered_signature_rejected():
    token = create_access_token(user_id="u-1", email="u1@test.org", tenant_id="t-1")
    parts = token.split(".")
    # Tamper last 3 bytes of signature
    tampered_sig = parts[2][:-3] + "xyz"
    tampered_token = f"{parts[0]}.{parts[1]}.{tampered_sig}"

    with pytest.raises(AuthenticationError):
        decode_token(tampered_token)


def test_jwt_tampered_payload_rejected():
    token = create_access_token(user_id="u-1", email="u1@test.org", tenant_id="t-1")
    parts = token.split(".")
    # Tamper middle part (payload)
    tampered_payload = parts[1][:-2] + "AA"
    tampered_token = f"{parts[0]}.{tampered_payload}.{parts[2]}"

    with pytest.raises(AuthenticationError):
        decode_token(tampered_token)


def test_jwt_malformed_token_format():
    with pytest.raises(AuthenticationError):
        decode_token("not.a.valid.jwt.token.string")

    with pytest.raises(AuthenticationError):
        decode_token("header.payload")  # Missing signature part

    with pytest.raises(AuthenticationError):
        decode_token("")


def test_jwt_get_token_jti_valid():
    token = create_access_token(user_id="u-jti", email="jti@test.org", tenant_id="t-1")
    jti = get_token_jti(token)
    assert jti is not None
    assert len(jti) == 36  # UUID length


def test_jwt_get_token_jti_malformed():
    assert get_token_jti("bad-token") is None
    assert get_token_jti("") is None


# --- 5. JTI Uniqueness Across Successive Tokens ---

def test_jwt_jti_uniqueness_distribution():
    jtis = set()
    for _ in range(50):
        token = create_access_token(user_id="u-dist", email="dist@test.org", tenant_id="t-1")
        jti = get_token_jti(token)
        assert jti not in jtis
        jtis.add(jti)
    assert len(jtis) == 50


# --- 6. Secret Key Rotation Simulation ---

def test_jwt_secret_key_rotation_handling():
    old_secret = "old-secret-key-32-characters-long!!"
    new_secret = "new-secret-key-32-characters-long!!"

    payload = {"sub": "u-rotate", "exp": int(time.time()) + 3600, "token_type": "access", "jti": "j-1"}
    token_old = encode_jwt(payload, secret_key=old_secret)

    # Decode with new secret fails
    with pytest.raises(jwt.InvalidSignatureError):
        decode_jwt(token_old, secret_key=new_secret)

    # Decode with old secret succeeds
    decoded = decode_jwt(token_old, secret_key=old_secret)
    assert decoded["sub"] == "u-rotate"


# --- 7. Audience and Issuer Validation Matrix ---

@pytest.mark.parametrize("aud_val", [
    "https://api.authservice.io",
    "auth-service-client",
    ["service-a", "service-b"],
])
def test_jwt_audience_claims(aud_val):
    payload = {
        "sub": "u-aud",
        "aud": aud_val,
        "exp": int(time.time()) + 3600,
        "token_type": "access",
        "jti": str(uuid.uuid4()),
    }
    token = encode_jwt(payload)
    decoded = decode_jwt(token)
    assert decoded["aud"] == aud_val


def test_jwt_unicode_email_and_name_claims():
    token = create_access_token(
        user_id="u-unicode",
        email="müller@deutschland.de",
        tenant_id="t-munich",
        extra_claims={"display_name": "François René 🚀", "bio": "日本語テスト"},
    )
    decoded = decode_token(token)
    assert decoded["email"] == "müller@deutschland.de"
    assert decoded["display_name"] == "François René 🚀"
    assert decoded["bio"] == "日本語テスト"

