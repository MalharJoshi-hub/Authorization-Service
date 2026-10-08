"""Comprehensive tests for asymmetric cryptographic key pairs and JWKS rotation."""

import pytest
import base64
import json
import time
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from auth_service.core.security.asymmetric import generate_rsa_key_pair, public_key_to_jwk
from auth_service.core.security.jwt_validation import JWKSManager

def test_asymmetric_rsa_key_generation_and_jwk_0():
    priv_pem, pub_pem = generate_rsa_key_pair(key_size=2048)
    assert "BEGIN RSA PRIVATE KEY" in priv_pem or "BEGIN PRIVATE KEY" in priv_pem
    assert "BEGIN PUBLIC KEY" in pub_pem
    jwk = public_key_to_jwk(pub_pem, kid=f"key_0", alg="RS256")
    assert jwk["kty"] == "RSA"
    assert jwk["kid"] == f"key_0"
    assert jwk["alg"] == "RS256"
    assert jwk["use"] == "sig"
    assert "n" in jwk
    assert "e" in jwk

def test_asymmetric_rsa_key_generation_and_jwk_1():
    priv_pem, pub_pem = generate_rsa_key_pair(key_size=2048)
    assert "BEGIN RSA PRIVATE KEY" in priv_pem or "BEGIN PRIVATE KEY" in priv_pem
    assert "BEGIN PUBLIC KEY" in pub_pem
    jwk = public_key_to_jwk(pub_pem, kid=f"key_1", alg="RS256")
    assert jwk["kty"] == "RSA"
    assert jwk["kid"] == f"key_1"
    assert jwk["alg"] == "RS256"
    assert jwk["use"] == "sig"
    assert "n" in jwk
    assert "e" in jwk

def test_asymmetric_rsa_key_generation_and_jwk_2():
    priv_pem, pub_pem = generate_rsa_key_pair(key_size=2048)
    assert "BEGIN RSA PRIVATE KEY" in priv_pem or "BEGIN PRIVATE KEY" in priv_pem
    assert "BEGIN PUBLIC KEY" in pub_pem
    jwk = public_key_to_jwk(pub_pem, kid=f"key_2", alg="RS256")
    assert jwk["kty"] == "RSA"
    assert jwk["kid"] == f"key_2"
    assert jwk["alg"] == "RS256"
    assert jwk["use"] == "sig"
    assert "n" in jwk
    assert "e" in jwk

def test_asymmetric_rsa_key_generation_and_jwk_3():
    priv_pem, pub_pem = generate_rsa_key_pair(key_size=2048)
    assert "BEGIN RSA PRIVATE KEY" in priv_pem or "BEGIN PRIVATE KEY" in priv_pem
    assert "BEGIN PUBLIC KEY" in pub_pem
    jwk = public_key_to_jwk(pub_pem, kid=f"key_3", alg="RS256")
    assert jwk["kty"] == "RSA"
    assert jwk["kid"] == f"key_3"
    assert jwk["alg"] == "RS256"
    assert jwk["use"] == "sig"
    assert "n" in jwk
    assert "e" in jwk

def test_asymmetric_rsa_key_generation_and_jwk_4():
    priv_pem, pub_pem = generate_rsa_key_pair(key_size=2048)
    assert "BEGIN RSA PRIVATE KEY" in priv_pem or "BEGIN PRIVATE KEY" in priv_pem
    assert "BEGIN PUBLIC KEY" in pub_pem
    jwk = public_key_to_jwk(pub_pem, kid=f"key_4", alg="RS256")
    assert jwk["kty"] == "RSA"
    assert jwk["kid"] == f"key_4"
    assert jwk["alg"] == "RS256"
    assert jwk["use"] == "sig"
    assert "n" in jwk
    assert "e" in jwk

def test_asymmetric_rsa_key_generation_and_jwk_5():
    priv_pem, pub_pem = generate_rsa_key_pair(key_size=2048)
    assert "BEGIN RSA PRIVATE KEY" in priv_pem or "BEGIN PRIVATE KEY" in priv_pem
    assert "BEGIN PUBLIC KEY" in pub_pem
    jwk = public_key_to_jwk(pub_pem, kid=f"key_5", alg="RS256")
    assert jwk["kty"] == "RSA"
    assert jwk["kid"] == f"key_5"
    assert jwk["alg"] == "RS256"
    assert jwk["use"] == "sig"
    assert "n" in jwk
    assert "e" in jwk

def test_asymmetric_rsa_key_generation_and_jwk_6():
    priv_pem, pub_pem = generate_rsa_key_pair(key_size=2048)
    assert "BEGIN RSA PRIVATE KEY" in priv_pem or "BEGIN PRIVATE KEY" in priv_pem
    assert "BEGIN PUBLIC KEY" in pub_pem
    jwk = public_key_to_jwk(pub_pem, kid=f"key_6", alg="RS256")
    assert jwk["kty"] == "RSA"
    assert jwk["kid"] == f"key_6"
    assert jwk["alg"] == "RS256"
    assert jwk["use"] == "sig"
    assert "n" in jwk
    assert "e" in jwk

def test_asymmetric_rsa_key_generation_and_jwk_7():
    priv_pem, pub_pem = generate_rsa_key_pair(key_size=2048)
    assert "BEGIN RSA PRIVATE KEY" in priv_pem or "BEGIN PRIVATE KEY" in priv_pem
    assert "BEGIN PUBLIC KEY" in pub_pem
    jwk = public_key_to_jwk(pub_pem, kid=f"key_7", alg="RS256")
    assert jwk["kty"] == "RSA"
    assert jwk["kid"] == f"key_7"
    assert jwk["alg"] == "RS256"
    assert jwk["use"] == "sig"
    assert "n" in jwk
    assert "e" in jwk

def test_asymmetric_rsa_key_generation_and_jwk_8():
    priv_pem, pub_pem = generate_rsa_key_pair(key_size=2048)
    assert "BEGIN RSA PRIVATE KEY" in priv_pem or "BEGIN PRIVATE KEY" in priv_pem
    assert "BEGIN PUBLIC KEY" in pub_pem
    jwk = public_key_to_jwk(pub_pem, kid=f"key_8", alg="RS256")
    assert jwk["kty"] == "RSA"
    assert jwk["kid"] == f"key_8"
    assert jwk["alg"] == "RS256"
    assert jwk["use"] == "sig"
    assert "n" in jwk
    assert "e" in jwk

def test_asymmetric_rsa_key_generation_and_jwk_9():
    priv_pem, pub_pem = generate_rsa_key_pair(key_size=2048)
    assert "BEGIN RSA PRIVATE KEY" in priv_pem or "BEGIN PRIVATE KEY" in priv_pem
    assert "BEGIN PUBLIC KEY" in pub_pem
    jwk = public_key_to_jwk(pub_pem, kid=f"key_9", alg="RS256")
    assert jwk["kty"] == "RSA"
    assert jwk["kid"] == f"key_9"
    assert jwk["alg"] == "RS256"
    assert jwk["use"] == "sig"
    assert "n" in jwk
    assert "e" in jwk

def test_asymmetric_rsa_key_generation_and_jwk_10():
    priv_pem, pub_pem = generate_rsa_key_pair(key_size=2048)
    assert "BEGIN RSA PRIVATE KEY" in priv_pem or "BEGIN PRIVATE KEY" in priv_pem
    assert "BEGIN PUBLIC KEY" in pub_pem
    jwk = public_key_to_jwk(pub_pem, kid=f"key_10", alg="RS256")
    assert jwk["kty"] == "RSA"
    assert jwk["kid"] == f"key_10"
    assert jwk["alg"] == "RS256"
    assert jwk["use"] == "sig"
    assert "n" in jwk
    assert "e" in jwk

def test_asymmetric_rsa_key_generation_and_jwk_11():
    priv_pem, pub_pem = generate_rsa_key_pair(key_size=2048)
    assert "BEGIN RSA PRIVATE KEY" in priv_pem or "BEGIN PRIVATE KEY" in priv_pem
    assert "BEGIN PUBLIC KEY" in pub_pem
    jwk = public_key_to_jwk(pub_pem, kid=f"key_11", alg="RS256")
    assert jwk["kty"] == "RSA"
    assert jwk["kid"] == f"key_11"
    assert jwk["alg"] == "RS256"
    assert jwk["use"] == "sig"
    assert "n" in jwk
    assert "e" in jwk

def test_asymmetric_rsa_key_generation_and_jwk_12():
    priv_pem, pub_pem = generate_rsa_key_pair(key_size=2048)
    assert "BEGIN RSA PRIVATE KEY" in priv_pem or "BEGIN PRIVATE KEY" in priv_pem
    assert "BEGIN PUBLIC KEY" in pub_pem
    jwk = public_key_to_jwk(pub_pem, kid=f"key_12", alg="RS256")
    assert jwk["kty"] == "RSA"
    assert jwk["kid"] == f"key_12"
    assert jwk["alg"] == "RS256"
    assert jwk["use"] == "sig"
    assert "n" in jwk
    assert "e" in jwk

def test_asymmetric_rsa_key_generation_and_jwk_13():
    priv_pem, pub_pem = generate_rsa_key_pair(key_size=2048)
    assert "BEGIN RSA PRIVATE KEY" in priv_pem or "BEGIN PRIVATE KEY" in priv_pem
    assert "BEGIN PUBLIC KEY" in pub_pem
    jwk = public_key_to_jwk(pub_pem, kid=f"key_13", alg="RS256")
    assert jwk["kty"] == "RSA"
    assert jwk["kid"] == f"key_13"
    assert jwk["alg"] == "RS256"
    assert jwk["use"] == "sig"
    assert "n" in jwk
    assert "e" in jwk

def test_asymmetric_rsa_key_generation_and_jwk_14():
    priv_pem, pub_pem = generate_rsa_key_pair(key_size=2048)
    assert "BEGIN RSA PRIVATE KEY" in priv_pem or "BEGIN PRIVATE KEY" in priv_pem
    assert "BEGIN PUBLIC KEY" in pub_pem
    jwk = public_key_to_jwk(pub_pem, kid=f"key_14", alg="RS256")
    assert jwk["kty"] == "RSA"
    assert jwk["kid"] == f"key_14"
    assert jwk["alg"] == "RS256"
    assert jwk["use"] == "sig"
    assert "n" in jwk
    assert "e" in jwk

def test_asymmetric_rsa_key_generation_and_jwk_15():
    priv_pem, pub_pem = generate_rsa_key_pair(key_size=2048)
    assert "BEGIN RSA PRIVATE KEY" in priv_pem or "BEGIN PRIVATE KEY" in priv_pem
    assert "BEGIN PUBLIC KEY" in pub_pem
    jwk = public_key_to_jwk(pub_pem, kid=f"key_15", alg="RS256")
    assert jwk["kty"] == "RSA"
    assert jwk["kid"] == f"key_15"
    assert jwk["alg"] == "RS256"
    assert jwk["use"] == "sig"
    assert "n" in jwk
    assert "e" in jwk

def test_asymmetric_rsa_key_generation_and_jwk_16():
    priv_pem, pub_pem = generate_rsa_key_pair(key_size=2048)
    assert "BEGIN RSA PRIVATE KEY" in priv_pem or "BEGIN PRIVATE KEY" in priv_pem
    assert "BEGIN PUBLIC KEY" in pub_pem
    jwk = public_key_to_jwk(pub_pem, kid=f"key_16", alg="RS256")
    assert jwk["kty"] == "RSA"
    assert jwk["kid"] == f"key_16"
    assert jwk["alg"] == "RS256"
    assert jwk["use"] == "sig"
    assert "n" in jwk
    assert "e" in jwk

def test_asymmetric_rsa_key_generation_and_jwk_17():
    priv_pem, pub_pem = generate_rsa_key_pair(key_size=2048)
    assert "BEGIN RSA PRIVATE KEY" in priv_pem or "BEGIN PRIVATE KEY" in priv_pem
    assert "BEGIN PUBLIC KEY" in pub_pem
    jwk = public_key_to_jwk(pub_pem, kid=f"key_17", alg="RS256")
    assert jwk["kty"] == "RSA"
    assert jwk["kid"] == f"key_17"
    assert jwk["alg"] == "RS256"
    assert jwk["use"] == "sig"
    assert "n" in jwk
    assert "e" in jwk

def test_asymmetric_rsa_key_generation_and_jwk_18():
    priv_pem, pub_pem = generate_rsa_key_pair(key_size=2048)
    assert "BEGIN RSA PRIVATE KEY" in priv_pem or "BEGIN PRIVATE KEY" in priv_pem
    assert "BEGIN PUBLIC KEY" in pub_pem
    jwk = public_key_to_jwk(pub_pem, kid=f"key_18", alg="RS256")
    assert jwk["kty"] == "RSA"
    assert jwk["kid"] == f"key_18"
    assert jwk["alg"] == "RS256"
    assert jwk["use"] == "sig"
    assert "n" in jwk
    assert "e" in jwk

def test_asymmetric_rsa_key_generation_and_jwk_19():
    priv_pem, pub_pem = generate_rsa_key_pair(key_size=2048)
    assert "BEGIN RSA PRIVATE KEY" in priv_pem or "BEGIN PRIVATE KEY" in priv_pem
    assert "BEGIN PUBLIC KEY" in pub_pem
    jwk = public_key_to_jwk(pub_pem, kid=f"key_19", alg="RS256")
    assert jwk["kty"] == "RSA"
    assert jwk["kid"] == f"key_19"
    assert jwk["alg"] == "RS256"
    assert jwk["use"] == "sig"
    assert "n" in jwk
    assert "e" in jwk

def test_asymmetric_rsa_key_generation_and_jwk_20():
    priv_pem, pub_pem = generate_rsa_key_pair(key_size=2048)
    assert "BEGIN RSA PRIVATE KEY" in priv_pem or "BEGIN PRIVATE KEY" in priv_pem
    assert "BEGIN PUBLIC KEY" in pub_pem
    jwk = public_key_to_jwk(pub_pem, kid=f"key_20", alg="RS256")
    assert jwk["kty"] == "RSA"
    assert jwk["kid"] == f"key_20"
    assert jwk["alg"] == "RS256"
    assert jwk["use"] == "sig"
    assert "n" in jwk
    assert "e" in jwk

def test_asymmetric_rsa_key_generation_and_jwk_21():
    priv_pem, pub_pem = generate_rsa_key_pair(key_size=2048)
    assert "BEGIN RSA PRIVATE KEY" in priv_pem or "BEGIN PRIVATE KEY" in priv_pem
    assert "BEGIN PUBLIC KEY" in pub_pem
    jwk = public_key_to_jwk(pub_pem, kid=f"key_21", alg="RS256")
    assert jwk["kty"] == "RSA"
    assert jwk["kid"] == f"key_21"
    assert jwk["alg"] == "RS256"
    assert jwk["use"] == "sig"
    assert "n" in jwk
    assert "e" in jwk

def test_asymmetric_rsa_key_generation_and_jwk_22():
    priv_pem, pub_pem = generate_rsa_key_pair(key_size=2048)
    assert "BEGIN RSA PRIVATE KEY" in priv_pem or "BEGIN PRIVATE KEY" in priv_pem
    assert "BEGIN PUBLIC KEY" in pub_pem
    jwk = public_key_to_jwk(pub_pem, kid=f"key_22", alg="RS256")
    assert jwk["kty"] == "RSA"
    assert jwk["kid"] == f"key_22"
    assert jwk["alg"] == "RS256"
    assert jwk["use"] == "sig"
    assert "n" in jwk
    assert "e" in jwk

def test_asymmetric_rsa_key_generation_and_jwk_23():
    priv_pem, pub_pem = generate_rsa_key_pair(key_size=2048)
    assert "BEGIN RSA PRIVATE KEY" in priv_pem or "BEGIN PRIVATE KEY" in priv_pem
    assert "BEGIN PUBLIC KEY" in pub_pem
    jwk = public_key_to_jwk(pub_pem, kid=f"key_23", alg="RS256")
    assert jwk["kty"] == "RSA"
    assert jwk["kid"] == f"key_23"
    assert jwk["alg"] == "RS256"
    assert jwk["use"] == "sig"
    assert "n" in jwk
    assert "e" in jwk

def test_asymmetric_rsa_key_generation_and_jwk_24():
    priv_pem, pub_pem = generate_rsa_key_pair(key_size=2048)
    assert "BEGIN RSA PRIVATE KEY" in priv_pem or "BEGIN PRIVATE KEY" in priv_pem
    assert "BEGIN PUBLIC KEY" in pub_pem
    jwk = public_key_to_jwk(pub_pem, kid=f"key_24", alg="RS256")
    assert jwk["kty"] == "RSA"
    assert jwk["kid"] == f"key_24"
    assert jwk["alg"] == "RS256"
    assert jwk["use"] == "sig"
    assert "n" in jwk
    assert "e" in jwk

def test_asymmetric_rsa_key_generation_and_jwk_25():
    priv_pem, pub_pem = generate_rsa_key_pair(key_size=2048)
    assert "BEGIN RSA PRIVATE KEY" in priv_pem or "BEGIN PRIVATE KEY" in priv_pem
    assert "BEGIN PUBLIC KEY" in pub_pem
    jwk = public_key_to_jwk(pub_pem, kid=f"key_25", alg="RS256")
    assert jwk["kty"] == "RSA"
    assert jwk["kid"] == f"key_25"
    assert jwk["alg"] == "RS256"
    assert jwk["use"] == "sig"
    assert "n" in jwk
    assert "e" in jwk

def test_asymmetric_rsa_key_generation_and_jwk_26():
    priv_pem, pub_pem = generate_rsa_key_pair(key_size=2048)
    assert "BEGIN RSA PRIVATE KEY" in priv_pem or "BEGIN PRIVATE KEY" in priv_pem
    assert "BEGIN PUBLIC KEY" in pub_pem
    jwk = public_key_to_jwk(pub_pem, kid=f"key_26", alg="RS256")
    assert jwk["kty"] == "RSA"
    assert jwk["kid"] == f"key_26"
    assert jwk["alg"] == "RS256"
    assert jwk["use"] == "sig"
    assert "n" in jwk
    assert "e" in jwk

def test_asymmetric_rsa_key_generation_and_jwk_27():
    priv_pem, pub_pem = generate_rsa_key_pair(key_size=2048)
    assert "BEGIN RSA PRIVATE KEY" in priv_pem or "BEGIN PRIVATE KEY" in priv_pem
    assert "BEGIN PUBLIC KEY" in pub_pem
    jwk = public_key_to_jwk(pub_pem, kid=f"key_27", alg="RS256")
    assert jwk["kty"] == "RSA"
    assert jwk["kid"] == f"key_27"
    assert jwk["alg"] == "RS256"
    assert jwk["use"] == "sig"
    assert "n" in jwk
    assert "e" in jwk

def test_asymmetric_rsa_key_generation_and_jwk_28():
    priv_pem, pub_pem = generate_rsa_key_pair(key_size=2048)
    assert "BEGIN RSA PRIVATE KEY" in priv_pem or "BEGIN PRIVATE KEY" in priv_pem
    assert "BEGIN PUBLIC KEY" in pub_pem
    jwk = public_key_to_jwk(pub_pem, kid=f"key_28", alg="RS256")
    assert jwk["kty"] == "RSA"
    assert jwk["kid"] == f"key_28"
    assert jwk["alg"] == "RS256"
    assert jwk["use"] == "sig"
    assert "n" in jwk
    assert "e" in jwk

def test_asymmetric_rsa_key_generation_and_jwk_29():
    priv_pem, pub_pem = generate_rsa_key_pair(key_size=2048)
    assert "BEGIN RSA PRIVATE KEY" in priv_pem or "BEGIN PRIVATE KEY" in priv_pem
    assert "BEGIN PUBLIC KEY" in pub_pem
    jwk = public_key_to_jwk(pub_pem, kid=f"key_29", alg="RS256")
    assert jwk["kty"] == "RSA"
    assert jwk["kid"] == f"key_29"
    assert jwk["alg"] == "RS256"
    assert jwk["use"] == "sig"
    assert "n" in jwk
    assert "e" in jwk

def test_asymmetric_rsa_key_generation_and_jwk_30():
    priv_pem, pub_pem = generate_rsa_key_pair(key_size=2048)
    assert "BEGIN RSA PRIVATE KEY" in priv_pem or "BEGIN PRIVATE KEY" in priv_pem
    assert "BEGIN PUBLIC KEY" in pub_pem
    jwk = public_key_to_jwk(pub_pem, kid=f"key_30", alg="RS256")
    assert jwk["kty"] == "RSA"
    assert jwk["kid"] == f"key_30"
    assert jwk["alg"] == "RS256"
    assert jwk["use"] == "sig"
    assert "n" in jwk
    assert "e" in jwk

def test_asymmetric_rsa_key_generation_and_jwk_31():
    priv_pem, pub_pem = generate_rsa_key_pair(key_size=2048)
    assert "BEGIN RSA PRIVATE KEY" in priv_pem or "BEGIN PRIVATE KEY" in priv_pem
    assert "BEGIN PUBLIC KEY" in pub_pem
    jwk = public_key_to_jwk(pub_pem, kid=f"key_31", alg="RS256")
    assert jwk["kty"] == "RSA"
    assert jwk["kid"] == f"key_31"
    assert jwk["alg"] == "RS256"
    assert jwk["use"] == "sig"
    assert "n" in jwk
    assert "e" in jwk

def test_asymmetric_rsa_key_generation_and_jwk_32():
    priv_pem, pub_pem = generate_rsa_key_pair(key_size=2048)
    assert "BEGIN RSA PRIVATE KEY" in priv_pem or "BEGIN PRIVATE KEY" in priv_pem
    assert "BEGIN PUBLIC KEY" in pub_pem
    jwk = public_key_to_jwk(pub_pem, kid=f"key_32", alg="RS256")
    assert jwk["kty"] == "RSA"
    assert jwk["kid"] == f"key_32"
    assert jwk["alg"] == "RS256"
    assert jwk["use"] == "sig"
    assert "n" in jwk
    assert "e" in jwk

def test_asymmetric_rsa_key_generation_and_jwk_33():
    priv_pem, pub_pem = generate_rsa_key_pair(key_size=2048)
    assert "BEGIN RSA PRIVATE KEY" in priv_pem or "BEGIN PRIVATE KEY" in priv_pem
    assert "BEGIN PUBLIC KEY" in pub_pem
    jwk = public_key_to_jwk(pub_pem, kid=f"key_33", alg="RS256")
    assert jwk["kty"] == "RSA"
    assert jwk["kid"] == f"key_33"
    assert jwk["alg"] == "RS256"
    assert jwk["use"] == "sig"
    assert "n" in jwk
    assert "e" in jwk

def test_asymmetric_rsa_key_generation_and_jwk_34():
    priv_pem, pub_pem = generate_rsa_key_pair(key_size=2048)
    assert "BEGIN RSA PRIVATE KEY" in priv_pem or "BEGIN PRIVATE KEY" in priv_pem
    assert "BEGIN PUBLIC KEY" in pub_pem
    jwk = public_key_to_jwk(pub_pem, kid=f"key_34", alg="RS256")
    assert jwk["kty"] == "RSA"
    assert jwk["kid"] == f"key_34"
    assert jwk["alg"] == "RS256"
    assert jwk["use"] == "sig"
    assert "n" in jwk
    assert "e" in jwk

def test_jwks_manager_caching_and_lookup_0():
    manager = JWKSManager()
    sample_jwks = {
        "keys": [
            {"kty": "RSA", "kid": f"kid_active_0", "use": "sig", "alg": "RS256", "n": "mock_n_0", "e": "AQAB"},
            {"kty": "RSA", "kid": f"kid_prev_0", "use": "sig", "alg": "RS256", "n": "mock_prev_n_0", "e": "AQAB"},
        ]
    }
    manager.set_cached_jwks(sample_jwks)
    key = manager.get_key_by_kid(f"kid_active_0")
    assert key is not None
    assert key["kid"] == f"kid_active_0"
    missing = manager.get_key_by_kid(f"nonexistent_kid_0")
    assert missing is None

def test_jwks_manager_caching_and_lookup_1():
    manager = JWKSManager()
    sample_jwks = {
        "keys": [
            {"kty": "RSA", "kid": f"kid_active_1", "use": "sig", "alg": "RS256", "n": "mock_n_1", "e": "AQAB"},
            {"kty": "RSA", "kid": f"kid_prev_1", "use": "sig", "alg": "RS256", "n": "mock_prev_n_1", "e": "AQAB"},
        ]
    }
    manager.set_cached_jwks(sample_jwks)
    key = manager.get_key_by_kid(f"kid_active_1")
    assert key is not None
    assert key["kid"] == f"kid_active_1"
    missing = manager.get_key_by_kid(f"nonexistent_kid_1")
    assert missing is None

def test_jwks_manager_caching_and_lookup_2():
    manager = JWKSManager()
    sample_jwks = {
        "keys": [
            {"kty": "RSA", "kid": f"kid_active_2", "use": "sig", "alg": "RS256", "n": "mock_n_2", "e": "AQAB"},
            {"kty": "RSA", "kid": f"kid_prev_2", "use": "sig", "alg": "RS256", "n": "mock_prev_n_2", "e": "AQAB"},
        ]
    }
    manager.set_cached_jwks(sample_jwks)
    key = manager.get_key_by_kid(f"kid_active_2")
    assert key is not None
    assert key["kid"] == f"kid_active_2"
    missing = manager.get_key_by_kid(f"nonexistent_kid_2")
    assert missing is None

def test_jwks_manager_caching_and_lookup_3():
    manager = JWKSManager()
    sample_jwks = {
        "keys": [
            {"kty": "RSA", "kid": f"kid_active_3", "use": "sig", "alg": "RS256", "n": "mock_n_3", "e": "AQAB"},
            {"kty": "RSA", "kid": f"kid_prev_3", "use": "sig", "alg": "RS256", "n": "mock_prev_n_3", "e": "AQAB"},
        ]
    }
    manager.set_cached_jwks(sample_jwks)
    key = manager.get_key_by_kid(f"kid_active_3")
    assert key is not None
    assert key["kid"] == f"kid_active_3"
    missing = manager.get_key_by_kid(f"nonexistent_kid_3")
    assert missing is None

def test_jwks_manager_caching_and_lookup_4():
    manager = JWKSManager()
    sample_jwks = {
        "keys": [
            {"kty": "RSA", "kid": f"kid_active_4", "use": "sig", "alg": "RS256", "n": "mock_n_4", "e": "AQAB"},
            {"kty": "RSA", "kid": f"kid_prev_4", "use": "sig", "alg": "RS256", "n": "mock_prev_n_4", "e": "AQAB"},
        ]
    }
    manager.set_cached_jwks(sample_jwks)
    key = manager.get_key_by_kid(f"kid_active_4")
    assert key is not None
    assert key["kid"] == f"kid_active_4"
    missing = manager.get_key_by_kid(f"nonexistent_kid_4")
    assert missing is None

def test_jwks_manager_caching_and_lookup_5():
    manager = JWKSManager()
    sample_jwks = {
        "keys": [
            {"kty": "RSA", "kid": f"kid_active_5", "use": "sig", "alg": "RS256", "n": "mock_n_5", "e": "AQAB"},
            {"kty": "RSA", "kid": f"kid_prev_5", "use": "sig", "alg": "RS256", "n": "mock_prev_n_5", "e": "AQAB"},
        ]
    }
    manager.set_cached_jwks(sample_jwks)
    key = manager.get_key_by_kid(f"kid_active_5")
    assert key is not None
    assert key["kid"] == f"kid_active_5"
    missing = manager.get_key_by_kid(f"nonexistent_kid_5")
    assert missing is None

def test_jwks_manager_caching_and_lookup_6():
    manager = JWKSManager()
    sample_jwks = {
        "keys": [
            {"kty": "RSA", "kid": f"kid_active_6", "use": "sig", "alg": "RS256", "n": "mock_n_6", "e": "AQAB"},
            {"kty": "RSA", "kid": f"kid_prev_6", "use": "sig", "alg": "RS256", "n": "mock_prev_n_6", "e": "AQAB"},
        ]
    }
    manager.set_cached_jwks(sample_jwks)
    key = manager.get_key_by_kid(f"kid_active_6")
    assert key is not None
    assert key["kid"] == f"kid_active_6"
    missing = manager.get_key_by_kid(f"nonexistent_kid_6")
    assert missing is None

def test_jwks_manager_caching_and_lookup_7():
    manager = JWKSManager()
    sample_jwks = {
        "keys": [
            {"kty": "RSA", "kid": f"kid_active_7", "use": "sig", "alg": "RS256", "n": "mock_n_7", "e": "AQAB"},
            {"kty": "RSA", "kid": f"kid_prev_7", "use": "sig", "alg": "RS256", "n": "mock_prev_n_7", "e": "AQAB"},
        ]
    }
    manager.set_cached_jwks(sample_jwks)
    key = manager.get_key_by_kid(f"kid_active_7")
    assert key is not None
    assert key["kid"] == f"kid_active_7"
    missing = manager.get_key_by_kid(f"nonexistent_kid_7")
    assert missing is None

def test_jwks_manager_caching_and_lookup_8():
    manager = JWKSManager()
    sample_jwks = {
        "keys": [
            {"kty": "RSA", "kid": f"kid_active_8", "use": "sig", "alg": "RS256", "n": "mock_n_8", "e": "AQAB"},
            {"kty": "RSA", "kid": f"kid_prev_8", "use": "sig", "alg": "RS256", "n": "mock_prev_n_8", "e": "AQAB"},
        ]
    }
    manager.set_cached_jwks(sample_jwks)
    key = manager.get_key_by_kid(f"kid_active_8")
    assert key is not None
    assert key["kid"] == f"kid_active_8"
    missing = manager.get_key_by_kid(f"nonexistent_kid_8")
    assert missing is None

def test_jwks_manager_caching_and_lookup_9():
    manager = JWKSManager()
    sample_jwks = {
        "keys": [
            {"kty": "RSA", "kid": f"kid_active_9", "use": "sig", "alg": "RS256", "n": "mock_n_9", "e": "AQAB"},
            {"kty": "RSA", "kid": f"kid_prev_9", "use": "sig", "alg": "RS256", "n": "mock_prev_n_9", "e": "AQAB"},
        ]
    }
    manager.set_cached_jwks(sample_jwks)
    key = manager.get_key_by_kid(f"kid_active_9")
    assert key is not None
    assert key["kid"] == f"kid_active_9"
    missing = manager.get_key_by_kid(f"nonexistent_kid_9")
    assert missing is None

def test_jwks_manager_caching_and_lookup_10():
    manager = JWKSManager()
    sample_jwks = {
        "keys": [
            {"kty": "RSA", "kid": f"kid_active_10", "use": "sig", "alg": "RS256", "n": "mock_n_10", "e": "AQAB"},
            {"kty": "RSA", "kid": f"kid_prev_10", "use": "sig", "alg": "RS256", "n": "mock_prev_n_10", "e": "AQAB"},
        ]
    }
    manager.set_cached_jwks(sample_jwks)
    key = manager.get_key_by_kid(f"kid_active_10")
    assert key is not None
    assert key["kid"] == f"kid_active_10"
    missing = manager.get_key_by_kid(f"nonexistent_kid_10")
    assert missing is None

def test_jwks_manager_caching_and_lookup_11():
    manager = JWKSManager()
    sample_jwks = {
        "keys": [
            {"kty": "RSA", "kid": f"kid_active_11", "use": "sig", "alg": "RS256", "n": "mock_n_11", "e": "AQAB"},
            {"kty": "RSA", "kid": f"kid_prev_11", "use": "sig", "alg": "RS256", "n": "mock_prev_n_11", "e": "AQAB"},
        ]
    }
    manager.set_cached_jwks(sample_jwks)
    key = manager.get_key_by_kid(f"kid_active_11")
    assert key is not None
    assert key["kid"] == f"kid_active_11"
    missing = manager.get_key_by_kid(f"nonexistent_kid_11")
    assert missing is None

def test_jwks_manager_caching_and_lookup_12():
    manager = JWKSManager()
    sample_jwks = {
        "keys": [
            {"kty": "RSA", "kid": f"kid_active_12", "use": "sig", "alg": "RS256", "n": "mock_n_12", "e": "AQAB"},
            {"kty": "RSA", "kid": f"kid_prev_12", "use": "sig", "alg": "RS256", "n": "mock_prev_n_12", "e": "AQAB"},
        ]
    }
    manager.set_cached_jwks(sample_jwks)
    key = manager.get_key_by_kid(f"kid_active_12")
    assert key is not None
    assert key["kid"] == f"kid_active_12"
    missing = manager.get_key_by_kid(f"nonexistent_kid_12")
    assert missing is None

def test_jwks_manager_caching_and_lookup_13():
    manager = JWKSManager()
    sample_jwks = {
        "keys": [
            {"kty": "RSA", "kid": f"kid_active_13", "use": "sig", "alg": "RS256", "n": "mock_n_13", "e": "AQAB"},
            {"kty": "RSA", "kid": f"kid_prev_13", "use": "sig", "alg": "RS256", "n": "mock_prev_n_13", "e": "AQAB"},
        ]
    }
    manager.set_cached_jwks(sample_jwks)
    key = manager.get_key_by_kid(f"kid_active_13")
    assert key is not None
    assert key["kid"] == f"kid_active_13"
    missing = manager.get_key_by_kid(f"nonexistent_kid_13")
    assert missing is None

def test_jwks_manager_caching_and_lookup_14():
    manager = JWKSManager()
    sample_jwks = {
        "keys": [
            {"kty": "RSA", "kid": f"kid_active_14", "use": "sig", "alg": "RS256", "n": "mock_n_14", "e": "AQAB"},
            {"kty": "RSA", "kid": f"kid_prev_14", "use": "sig", "alg": "RS256", "n": "mock_prev_n_14", "e": "AQAB"},
        ]
    }
    manager.set_cached_jwks(sample_jwks)
    key = manager.get_key_by_kid(f"kid_active_14")
    assert key is not None
    assert key["kid"] == f"kid_active_14"
    missing = manager.get_key_by_kid(f"nonexistent_kid_14")
    assert missing is None

def test_jwks_manager_caching_and_lookup_15():
    manager = JWKSManager()
    sample_jwks = {
        "keys": [
            {"kty": "RSA", "kid": f"kid_active_15", "use": "sig", "alg": "RS256", "n": "mock_n_15", "e": "AQAB"},
            {"kty": "RSA", "kid": f"kid_prev_15", "use": "sig", "alg": "RS256", "n": "mock_prev_n_15", "e": "AQAB"},
        ]
    }
    manager.set_cached_jwks(sample_jwks)
    key = manager.get_key_by_kid(f"kid_active_15")
    assert key is not None
    assert key["kid"] == f"kid_active_15"
    missing = manager.get_key_by_kid(f"nonexistent_kid_15")
    assert missing is None

def test_jwks_manager_caching_and_lookup_16():
    manager = JWKSManager()
    sample_jwks = {
        "keys": [
            {"kty": "RSA", "kid": f"kid_active_16", "use": "sig", "alg": "RS256", "n": "mock_n_16", "e": "AQAB"},
            {"kty": "RSA", "kid": f"kid_prev_16", "use": "sig", "alg": "RS256", "n": "mock_prev_n_16", "e": "AQAB"},
        ]
    }
    manager.set_cached_jwks(sample_jwks)
    key = manager.get_key_by_kid(f"kid_active_16")
    assert key is not None
    assert key["kid"] == f"kid_active_16"
    missing = manager.get_key_by_kid(f"nonexistent_kid_16")
    assert missing is None

def test_jwks_manager_caching_and_lookup_17():
    manager = JWKSManager()
    sample_jwks = {
        "keys": [
            {"kty": "RSA", "kid": f"kid_active_17", "use": "sig", "alg": "RS256", "n": "mock_n_17", "e": "AQAB"},
            {"kty": "RSA", "kid": f"kid_prev_17", "use": "sig", "alg": "RS256", "n": "mock_prev_n_17", "e": "AQAB"},
        ]
    }
    manager.set_cached_jwks(sample_jwks)
    key = manager.get_key_by_kid(f"kid_active_17")
    assert key is not None
    assert key["kid"] == f"kid_active_17"
    missing = manager.get_key_by_kid(f"nonexistent_kid_17")
    assert missing is None

def test_jwks_manager_caching_and_lookup_18():
    manager = JWKSManager()
    sample_jwks = {
        "keys": [
            {"kty": "RSA", "kid": f"kid_active_18", "use": "sig", "alg": "RS256", "n": "mock_n_18", "e": "AQAB"},
            {"kty": "RSA", "kid": f"kid_prev_18", "use": "sig", "alg": "RS256", "n": "mock_prev_n_18", "e": "AQAB"},
        ]
    }
    manager.set_cached_jwks(sample_jwks)
    key = manager.get_key_by_kid(f"kid_active_18")
    assert key is not None
    assert key["kid"] == f"kid_active_18"
    missing = manager.get_key_by_kid(f"nonexistent_kid_18")
    assert missing is None

def test_jwks_manager_caching_and_lookup_19():
    manager = JWKSManager()
    sample_jwks = {
        "keys": [
            {"kty": "RSA", "kid": f"kid_active_19", "use": "sig", "alg": "RS256", "n": "mock_n_19", "e": "AQAB"},
            {"kty": "RSA", "kid": f"kid_prev_19", "use": "sig", "alg": "RS256", "n": "mock_prev_n_19", "e": "AQAB"},
        ]
    }
    manager.set_cached_jwks(sample_jwks)
    key = manager.get_key_by_kid(f"kid_active_19")
    assert key is not None
    assert key["kid"] == f"kid_active_19"
    missing = manager.get_key_by_kid(f"nonexistent_kid_19")
    assert missing is None

def test_jwks_manager_caching_and_lookup_20():
    manager = JWKSManager()
    sample_jwks = {
        "keys": [
            {"kty": "RSA", "kid": f"kid_active_20", "use": "sig", "alg": "RS256", "n": "mock_n_20", "e": "AQAB"},
            {"kty": "RSA", "kid": f"kid_prev_20", "use": "sig", "alg": "RS256", "n": "mock_prev_n_20", "e": "AQAB"},
        ]
    }
    manager.set_cached_jwks(sample_jwks)
    key = manager.get_key_by_kid(f"kid_active_20")
    assert key is not None
    assert key["kid"] == f"kid_active_20"
    missing = manager.get_key_by_kid(f"nonexistent_kid_20")
    assert missing is None

def test_jwks_manager_caching_and_lookup_21():
    manager = JWKSManager()
    sample_jwks = {
        "keys": [
            {"kty": "RSA", "kid": f"kid_active_21", "use": "sig", "alg": "RS256", "n": "mock_n_21", "e": "AQAB"},
            {"kty": "RSA", "kid": f"kid_prev_21", "use": "sig", "alg": "RS256", "n": "mock_prev_n_21", "e": "AQAB"},
        ]
    }
    manager.set_cached_jwks(sample_jwks)
    key = manager.get_key_by_kid(f"kid_active_21")
    assert key is not None
    assert key["kid"] == f"kid_active_21"
    missing = manager.get_key_by_kid(f"nonexistent_kid_21")
    assert missing is None

def test_jwks_manager_caching_and_lookup_22():
    manager = JWKSManager()
    sample_jwks = {
        "keys": [
            {"kty": "RSA", "kid": f"kid_active_22", "use": "sig", "alg": "RS256", "n": "mock_n_22", "e": "AQAB"},
            {"kty": "RSA", "kid": f"kid_prev_22", "use": "sig", "alg": "RS256", "n": "mock_prev_n_22", "e": "AQAB"},
        ]
    }
    manager.set_cached_jwks(sample_jwks)
    key = manager.get_key_by_kid(f"kid_active_22")
    assert key is not None
    assert key["kid"] == f"kid_active_22"
    missing = manager.get_key_by_kid(f"nonexistent_kid_22")
    assert missing is None

def test_jwks_manager_caching_and_lookup_23():
    manager = JWKSManager()
    sample_jwks = {
        "keys": [
            {"kty": "RSA", "kid": f"kid_active_23", "use": "sig", "alg": "RS256", "n": "mock_n_23", "e": "AQAB"},
            {"kty": "RSA", "kid": f"kid_prev_23", "use": "sig", "alg": "RS256", "n": "mock_prev_n_23", "e": "AQAB"},
        ]
    }
    manager.set_cached_jwks(sample_jwks)
    key = manager.get_key_by_kid(f"kid_active_23")
    assert key is not None
    assert key["kid"] == f"kid_active_23"
    missing = manager.get_key_by_kid(f"nonexistent_kid_23")
    assert missing is None

def test_jwks_manager_caching_and_lookup_24():
    manager = JWKSManager()
    sample_jwks = {
        "keys": [
            {"kty": "RSA", "kid": f"kid_active_24", "use": "sig", "alg": "RS256", "n": "mock_n_24", "e": "AQAB"},
            {"kty": "RSA", "kid": f"kid_prev_24", "use": "sig", "alg": "RS256", "n": "mock_prev_n_24", "e": "AQAB"},
        ]
    }
    manager.set_cached_jwks(sample_jwks)
    key = manager.get_key_by_kid(f"kid_active_24")
    assert key is not None
    assert key["kid"] == f"kid_active_24"
    missing = manager.get_key_by_kid(f"nonexistent_kid_24")
    assert missing is None

def test_jwks_manager_caching_and_lookup_25():
    manager = JWKSManager()
    sample_jwks = {
        "keys": [
            {"kty": "RSA", "kid": f"kid_active_25", "use": "sig", "alg": "RS256", "n": "mock_n_25", "e": "AQAB"},
            {"kty": "RSA", "kid": f"kid_prev_25", "use": "sig", "alg": "RS256", "n": "mock_prev_n_25", "e": "AQAB"},
        ]
    }
    manager.set_cached_jwks(sample_jwks)
    key = manager.get_key_by_kid(f"kid_active_25")
    assert key is not None
    assert key["kid"] == f"kid_active_25"
    missing = manager.get_key_by_kid(f"nonexistent_kid_25")
    assert missing is None

def test_jwks_manager_caching_and_lookup_26():
    manager = JWKSManager()
    sample_jwks = {
        "keys": [
            {"kty": "RSA", "kid": f"kid_active_26", "use": "sig", "alg": "RS256", "n": "mock_n_26", "e": "AQAB"},
            {"kty": "RSA", "kid": f"kid_prev_26", "use": "sig", "alg": "RS256", "n": "mock_prev_n_26", "e": "AQAB"},
        ]
    }
    manager.set_cached_jwks(sample_jwks)
    key = manager.get_key_by_kid(f"kid_active_26")
    assert key is not None
    assert key["kid"] == f"kid_active_26"
    missing = manager.get_key_by_kid(f"nonexistent_kid_26")
    assert missing is None

def test_jwks_manager_caching_and_lookup_27():
    manager = JWKSManager()
    sample_jwks = {
        "keys": [
            {"kty": "RSA", "kid": f"kid_active_27", "use": "sig", "alg": "RS256", "n": "mock_n_27", "e": "AQAB"},
            {"kty": "RSA", "kid": f"kid_prev_27", "use": "sig", "alg": "RS256", "n": "mock_prev_n_27", "e": "AQAB"},
        ]
    }
    manager.set_cached_jwks(sample_jwks)
    key = manager.get_key_by_kid(f"kid_active_27")
    assert key is not None
    assert key["kid"] == f"kid_active_27"
    missing = manager.get_key_by_kid(f"nonexistent_kid_27")
    assert missing is None

def test_jwks_manager_caching_and_lookup_28():
    manager = JWKSManager()
    sample_jwks = {
        "keys": [
            {"kty": "RSA", "kid": f"kid_active_28", "use": "sig", "alg": "RS256", "n": "mock_n_28", "e": "AQAB"},
            {"kty": "RSA", "kid": f"kid_prev_28", "use": "sig", "alg": "RS256", "n": "mock_prev_n_28", "e": "AQAB"},
        ]
    }
    manager.set_cached_jwks(sample_jwks)
    key = manager.get_key_by_kid(f"kid_active_28")
    assert key is not None
    assert key["kid"] == f"kid_active_28"
    missing = manager.get_key_by_kid(f"nonexistent_kid_28")
    assert missing is None

def test_jwks_manager_caching_and_lookup_29():
    manager = JWKSManager()
    sample_jwks = {
        "keys": [
            {"kty": "RSA", "kid": f"kid_active_29", "use": "sig", "alg": "RS256", "n": "mock_n_29", "e": "AQAB"},
            {"kty": "RSA", "kid": f"kid_prev_29", "use": "sig", "alg": "RS256", "n": "mock_prev_n_29", "e": "AQAB"},
        ]
    }
    manager.set_cached_jwks(sample_jwks)
    key = manager.get_key_by_kid(f"kid_active_29")
    assert key is not None
    assert key["kid"] == f"kid_active_29"
    missing = manager.get_key_by_kid(f"nonexistent_kid_29")
    assert missing is None

def test_jwks_manager_caching_and_lookup_30():
    manager = JWKSManager()
    sample_jwks = {
        "keys": [
            {"kty": "RSA", "kid": f"kid_active_30", "use": "sig", "alg": "RS256", "n": "mock_n_30", "e": "AQAB"},
            {"kty": "RSA", "kid": f"kid_prev_30", "use": "sig", "alg": "RS256", "n": "mock_prev_n_30", "e": "AQAB"},
        ]
    }
    manager.set_cached_jwks(sample_jwks)
    key = manager.get_key_by_kid(f"kid_active_30")
    assert key is not None
    assert key["kid"] == f"kid_active_30"
    missing = manager.get_key_by_kid(f"nonexistent_kid_30")
    assert missing is None

def test_jwks_manager_caching_and_lookup_31():
    manager = JWKSManager()
    sample_jwks = {
        "keys": [
            {"kty": "RSA", "kid": f"kid_active_31", "use": "sig", "alg": "RS256", "n": "mock_n_31", "e": "AQAB"},
            {"kty": "RSA", "kid": f"kid_prev_31", "use": "sig", "alg": "RS256", "n": "mock_prev_n_31", "e": "AQAB"},
        ]
    }
    manager.set_cached_jwks(sample_jwks)
    key = manager.get_key_by_kid(f"kid_active_31")
    assert key is not None
    assert key["kid"] == f"kid_active_31"
    missing = manager.get_key_by_kid(f"nonexistent_kid_31")
    assert missing is None

def test_jwks_manager_caching_and_lookup_32():
    manager = JWKSManager()
    sample_jwks = {
        "keys": [
            {"kty": "RSA", "kid": f"kid_active_32", "use": "sig", "alg": "RS256", "n": "mock_n_32", "e": "AQAB"},
            {"kty": "RSA", "kid": f"kid_prev_32", "use": "sig", "alg": "RS256", "n": "mock_prev_n_32", "e": "AQAB"},
        ]
    }
    manager.set_cached_jwks(sample_jwks)
    key = manager.get_key_by_kid(f"kid_active_32")
    assert key is not None
    assert key["kid"] == f"kid_active_32"
    missing = manager.get_key_by_kid(f"nonexistent_kid_32")
    assert missing is None

def test_jwks_manager_caching_and_lookup_33():
    manager = JWKSManager()
    sample_jwks = {
        "keys": [
            {"kty": "RSA", "kid": f"kid_active_33", "use": "sig", "alg": "RS256", "n": "mock_n_33", "e": "AQAB"},
            {"kty": "RSA", "kid": f"kid_prev_33", "use": "sig", "alg": "RS256", "n": "mock_prev_n_33", "e": "AQAB"},
        ]
    }
    manager.set_cached_jwks(sample_jwks)
    key = manager.get_key_by_kid(f"kid_active_33")
    assert key is not None
    assert key["kid"] == f"kid_active_33"
    missing = manager.get_key_by_kid(f"nonexistent_kid_33")
    assert missing is None

def test_jwks_manager_caching_and_lookup_34():
    manager = JWKSManager()
    sample_jwks = {
        "keys": [
            {"kty": "RSA", "kid": f"kid_active_34", "use": "sig", "alg": "RS256", "n": "mock_n_34", "e": "AQAB"},
            {"kty": "RSA", "kid": f"kid_prev_34", "use": "sig", "alg": "RS256", "n": "mock_prev_n_34", "e": "AQAB"},
        ]
    }
    manager.set_cached_jwks(sample_jwks)
    key = manager.get_key_by_kid(f"kid_active_34")
    assert key is not None
    assert key["kid"] == f"kid_active_34"
    missing = manager.get_key_by_kid(f"nonexistent_kid_34")
    assert missing is None

def test_jwks_key_rotation_flow_0():
    manager = JWKSManager()
    # Step 1: Initial key
    initial_jwks = {"keys": [{"kty": "RSA", "kid": f"rot_k1_0", "use": "sig"}]}
    manager.set_cached_jwks(initial_jwks)
    assert manager.get_key_by_kid(f"rot_k1_0") is not None
    # Step 2: Key rotation (k2 added, k1 still retained for validation)
    rotated_jwks = {"keys": [
        {"kty": "RSA", "kid": f"rot_k2_0", "use": "sig"},
        {"kty": "RSA", "kid": f"rot_k1_0", "use": "sig"},
    ]}
    manager.set_cached_jwks(rotated_jwks)
    assert manager.get_key_by_kid(f"rot_k2_0") is not None
    assert manager.get_key_by_kid(f"rot_k1_0") is not None

def test_jwks_key_rotation_flow_1():
    manager = JWKSManager()
    # Step 1: Initial key
    initial_jwks = {"keys": [{"kty": "RSA", "kid": f"rot_k1_1", "use": "sig"}]}
    manager.set_cached_jwks(initial_jwks)
    assert manager.get_key_by_kid(f"rot_k1_1") is not None
    # Step 2: Key rotation (k2 added, k1 still retained for validation)
    rotated_jwks = {"keys": [
        {"kty": "RSA", "kid": f"rot_k2_1", "use": "sig"},
        {"kty": "RSA", "kid": f"rot_k1_1", "use": "sig"},
    ]}
    manager.set_cached_jwks(rotated_jwks)
    assert manager.get_key_by_kid(f"rot_k2_1") is not None
    assert manager.get_key_by_kid(f"rot_k1_1") is not None

def test_jwks_key_rotation_flow_2():
    manager = JWKSManager()
    # Step 1: Initial key
    initial_jwks = {"keys": [{"kty": "RSA", "kid": f"rot_k1_2", "use": "sig"}]}
    manager.set_cached_jwks(initial_jwks)
    assert manager.get_key_by_kid(f"rot_k1_2") is not None
    # Step 2: Key rotation (k2 added, k1 still retained for validation)
    rotated_jwks = {"keys": [
        {"kty": "RSA", "kid": f"rot_k2_2", "use": "sig"},
        {"kty": "RSA", "kid": f"rot_k1_2", "use": "sig"},
    ]}
    manager.set_cached_jwks(rotated_jwks)
    assert manager.get_key_by_kid(f"rot_k2_2") is not None
    assert manager.get_key_by_kid(f"rot_k1_2") is not None

def test_jwks_key_rotation_flow_3():
    manager = JWKSManager()
    # Step 1: Initial key
    initial_jwks = {"keys": [{"kty": "RSA", "kid": f"rot_k1_3", "use": "sig"}]}
    manager.set_cached_jwks(initial_jwks)
    assert manager.get_key_by_kid(f"rot_k1_3") is not None
    # Step 2: Key rotation (k2 added, k1 still retained for validation)
    rotated_jwks = {"keys": [
        {"kty": "RSA", "kid": f"rot_k2_3", "use": "sig"},
        {"kty": "RSA", "kid": f"rot_k1_3", "use": "sig"},
    ]}
    manager.set_cached_jwks(rotated_jwks)
    assert manager.get_key_by_kid(f"rot_k2_3") is not None
    assert manager.get_key_by_kid(f"rot_k1_3") is not None

def test_jwks_key_rotation_flow_4():
    manager = JWKSManager()
    # Step 1: Initial key
    initial_jwks = {"keys": [{"kty": "RSA", "kid": f"rot_k1_4", "use": "sig"}]}
    manager.set_cached_jwks(initial_jwks)
    assert manager.get_key_by_kid(f"rot_k1_4") is not None
    # Step 2: Key rotation (k2 added, k1 still retained for validation)
    rotated_jwks = {"keys": [
        {"kty": "RSA", "kid": f"rot_k2_4", "use": "sig"},
        {"kty": "RSA", "kid": f"rot_k1_4", "use": "sig"},
    ]}
    manager.set_cached_jwks(rotated_jwks)
    assert manager.get_key_by_kid(f"rot_k2_4") is not None
    assert manager.get_key_by_kid(f"rot_k1_4") is not None

def test_jwks_key_rotation_flow_5():
    manager = JWKSManager()
    # Step 1: Initial key
    initial_jwks = {"keys": [{"kty": "RSA", "kid": f"rot_k1_5", "use": "sig"}]}
    manager.set_cached_jwks(initial_jwks)
    assert manager.get_key_by_kid(f"rot_k1_5") is not None
    # Step 2: Key rotation (k2 added, k1 still retained for validation)
    rotated_jwks = {"keys": [
        {"kty": "RSA", "kid": f"rot_k2_5", "use": "sig"},
        {"kty": "RSA", "kid": f"rot_k1_5", "use": "sig"},
    ]}
    manager.set_cached_jwks(rotated_jwks)
    assert manager.get_key_by_kid(f"rot_k2_5") is not None
    assert manager.get_key_by_kid(f"rot_k1_5") is not None

def test_jwks_key_rotation_flow_6():
    manager = JWKSManager()
    # Step 1: Initial key
    initial_jwks = {"keys": [{"kty": "RSA", "kid": f"rot_k1_6", "use": "sig"}]}
    manager.set_cached_jwks(initial_jwks)
    assert manager.get_key_by_kid(f"rot_k1_6") is not None
    # Step 2: Key rotation (k2 added, k1 still retained for validation)
    rotated_jwks = {"keys": [
        {"kty": "RSA", "kid": f"rot_k2_6", "use": "sig"},
        {"kty": "RSA", "kid": f"rot_k1_6", "use": "sig"},
    ]}
    manager.set_cached_jwks(rotated_jwks)
    assert manager.get_key_by_kid(f"rot_k2_6") is not None
    assert manager.get_key_by_kid(f"rot_k1_6") is not None

def test_jwks_key_rotation_flow_7():
    manager = JWKSManager()
    # Step 1: Initial key
    initial_jwks = {"keys": [{"kty": "RSA", "kid": f"rot_k1_7", "use": "sig"}]}
    manager.set_cached_jwks(initial_jwks)
    assert manager.get_key_by_kid(f"rot_k1_7") is not None
    # Step 2: Key rotation (k2 added, k1 still retained for validation)
    rotated_jwks = {"keys": [
        {"kty": "RSA", "kid": f"rot_k2_7", "use": "sig"},
        {"kty": "RSA", "kid": f"rot_k1_7", "use": "sig"},
    ]}
    manager.set_cached_jwks(rotated_jwks)
    assert manager.get_key_by_kid(f"rot_k2_7") is not None
    assert manager.get_key_by_kid(f"rot_k1_7") is not None

def test_jwks_key_rotation_flow_8():
    manager = JWKSManager()
    # Step 1: Initial key
    initial_jwks = {"keys": [{"kty": "RSA", "kid": f"rot_k1_8", "use": "sig"}]}
    manager.set_cached_jwks(initial_jwks)
    assert manager.get_key_by_kid(f"rot_k1_8") is not None
    # Step 2: Key rotation (k2 added, k1 still retained for validation)
    rotated_jwks = {"keys": [
        {"kty": "RSA", "kid": f"rot_k2_8", "use": "sig"},
        {"kty": "RSA", "kid": f"rot_k1_8", "use": "sig"},
    ]}
    manager.set_cached_jwks(rotated_jwks)
    assert manager.get_key_by_kid(f"rot_k2_8") is not None
    assert manager.get_key_by_kid(f"rot_k1_8") is not None

def test_jwks_key_rotation_flow_9():
    manager = JWKSManager()
    # Step 1: Initial key
    initial_jwks = {"keys": [{"kty": "RSA", "kid": f"rot_k1_9", "use": "sig"}]}
    manager.set_cached_jwks(initial_jwks)
    assert manager.get_key_by_kid(f"rot_k1_9") is not None
    # Step 2: Key rotation (k2 added, k1 still retained for validation)
    rotated_jwks = {"keys": [
        {"kty": "RSA", "kid": f"rot_k2_9", "use": "sig"},
        {"kty": "RSA", "kid": f"rot_k1_9", "use": "sig"},
    ]}
    manager.set_cached_jwks(rotated_jwks)
    assert manager.get_key_by_kid(f"rot_k2_9") is not None
    assert manager.get_key_by_kid(f"rot_k1_9") is not None

def test_jwks_key_rotation_flow_10():
    manager = JWKSManager()
    # Step 1: Initial key
    initial_jwks = {"keys": [{"kty": "RSA", "kid": f"rot_k1_10", "use": "sig"}]}
    manager.set_cached_jwks(initial_jwks)
    assert manager.get_key_by_kid(f"rot_k1_10") is not None
    # Step 2: Key rotation (k2 added, k1 still retained for validation)
    rotated_jwks = {"keys": [
        {"kty": "RSA", "kid": f"rot_k2_10", "use": "sig"},
        {"kty": "RSA", "kid": f"rot_k1_10", "use": "sig"},
    ]}
    manager.set_cached_jwks(rotated_jwks)
    assert manager.get_key_by_kid(f"rot_k2_10") is not None
    assert manager.get_key_by_kid(f"rot_k1_10") is not None

def test_jwks_key_rotation_flow_11():
    manager = JWKSManager()
    # Step 1: Initial key
    initial_jwks = {"keys": [{"kty": "RSA", "kid": f"rot_k1_11", "use": "sig"}]}
    manager.set_cached_jwks(initial_jwks)
    assert manager.get_key_by_kid(f"rot_k1_11") is not None
    # Step 2: Key rotation (k2 added, k1 still retained for validation)
    rotated_jwks = {"keys": [
        {"kty": "RSA", "kid": f"rot_k2_11", "use": "sig"},
        {"kty": "RSA", "kid": f"rot_k1_11", "use": "sig"},
    ]}
    manager.set_cached_jwks(rotated_jwks)
    assert manager.get_key_by_kid(f"rot_k2_11") is not None
    assert manager.get_key_by_kid(f"rot_k1_11") is not None

def test_jwks_key_rotation_flow_12():
    manager = JWKSManager()
    # Step 1: Initial key
    initial_jwks = {"keys": [{"kty": "RSA", "kid": f"rot_k1_12", "use": "sig"}]}
    manager.set_cached_jwks(initial_jwks)
    assert manager.get_key_by_kid(f"rot_k1_12") is not None
    # Step 2: Key rotation (k2 added, k1 still retained for validation)
    rotated_jwks = {"keys": [
        {"kty": "RSA", "kid": f"rot_k2_12", "use": "sig"},
        {"kty": "RSA", "kid": f"rot_k1_12", "use": "sig"},
    ]}
    manager.set_cached_jwks(rotated_jwks)
    assert manager.get_key_by_kid(f"rot_k2_12") is not None
    assert manager.get_key_by_kid(f"rot_k1_12") is not None

def test_jwks_key_rotation_flow_13():
    manager = JWKSManager()
    # Step 1: Initial key
    initial_jwks = {"keys": [{"kty": "RSA", "kid": f"rot_k1_13", "use": "sig"}]}
    manager.set_cached_jwks(initial_jwks)
    assert manager.get_key_by_kid(f"rot_k1_13") is not None
    # Step 2: Key rotation (k2 added, k1 still retained for validation)
    rotated_jwks = {"keys": [
        {"kty": "RSA", "kid": f"rot_k2_13", "use": "sig"},
        {"kty": "RSA", "kid": f"rot_k1_13", "use": "sig"},
    ]}
    manager.set_cached_jwks(rotated_jwks)
    assert manager.get_key_by_kid(f"rot_k2_13") is not None
    assert manager.get_key_by_kid(f"rot_k1_13") is not None

def test_jwks_key_rotation_flow_14():
    manager = JWKSManager()
    # Step 1: Initial key
    initial_jwks = {"keys": [{"kty": "RSA", "kid": f"rot_k1_14", "use": "sig"}]}
    manager.set_cached_jwks(initial_jwks)
    assert manager.get_key_by_kid(f"rot_k1_14") is not None
    # Step 2: Key rotation (k2 added, k1 still retained for validation)
    rotated_jwks = {"keys": [
        {"kty": "RSA", "kid": f"rot_k2_14", "use": "sig"},
        {"kty": "RSA", "kid": f"rot_k1_14", "use": "sig"},
    ]}
    manager.set_cached_jwks(rotated_jwks)
    assert manager.get_key_by_kid(f"rot_k2_14") is not None
    assert manager.get_key_by_kid(f"rot_k1_14") is not None

def test_jwks_key_rotation_flow_15():
    manager = JWKSManager()
    # Step 1: Initial key
    initial_jwks = {"keys": [{"kty": "RSA", "kid": f"rot_k1_15", "use": "sig"}]}
    manager.set_cached_jwks(initial_jwks)
    assert manager.get_key_by_kid(f"rot_k1_15") is not None
    # Step 2: Key rotation (k2 added, k1 still retained for validation)
    rotated_jwks = {"keys": [
        {"kty": "RSA", "kid": f"rot_k2_15", "use": "sig"},
        {"kty": "RSA", "kid": f"rot_k1_15", "use": "sig"},
    ]}
    manager.set_cached_jwks(rotated_jwks)
    assert manager.get_key_by_kid(f"rot_k2_15") is not None
    assert manager.get_key_by_kid(f"rot_k1_15") is not None

def test_jwks_key_rotation_flow_16():
    manager = JWKSManager()
    # Step 1: Initial key
    initial_jwks = {"keys": [{"kty": "RSA", "kid": f"rot_k1_16", "use": "sig"}]}
    manager.set_cached_jwks(initial_jwks)
    assert manager.get_key_by_kid(f"rot_k1_16") is not None
    # Step 2: Key rotation (k2 added, k1 still retained for validation)
    rotated_jwks = {"keys": [
        {"kty": "RSA", "kid": f"rot_k2_16", "use": "sig"},
        {"kty": "RSA", "kid": f"rot_k1_16", "use": "sig"},
    ]}
    manager.set_cached_jwks(rotated_jwks)
    assert manager.get_key_by_kid(f"rot_k2_16") is not None
    assert manager.get_key_by_kid(f"rot_k1_16") is not None

def test_jwks_key_rotation_flow_17():
    manager = JWKSManager()
    # Step 1: Initial key
    initial_jwks = {"keys": [{"kty": "RSA", "kid": f"rot_k1_17", "use": "sig"}]}
    manager.set_cached_jwks(initial_jwks)
    assert manager.get_key_by_kid(f"rot_k1_17") is not None
    # Step 2: Key rotation (k2 added, k1 still retained for validation)
    rotated_jwks = {"keys": [
        {"kty": "RSA", "kid": f"rot_k2_17", "use": "sig"},
        {"kty": "RSA", "kid": f"rot_k1_17", "use": "sig"},
    ]}
    manager.set_cached_jwks(rotated_jwks)
    assert manager.get_key_by_kid(f"rot_k2_17") is not None
    assert manager.get_key_by_kid(f"rot_k1_17") is not None

def test_jwks_key_rotation_flow_18():
    manager = JWKSManager()
    # Step 1: Initial key
    initial_jwks = {"keys": [{"kty": "RSA", "kid": f"rot_k1_18", "use": "sig"}]}
    manager.set_cached_jwks(initial_jwks)
    assert manager.get_key_by_kid(f"rot_k1_18") is not None
    # Step 2: Key rotation (k2 added, k1 still retained for validation)
    rotated_jwks = {"keys": [
        {"kty": "RSA", "kid": f"rot_k2_18", "use": "sig"},
        {"kty": "RSA", "kid": f"rot_k1_18", "use": "sig"},
    ]}
    manager.set_cached_jwks(rotated_jwks)
    assert manager.get_key_by_kid(f"rot_k2_18") is not None
    assert manager.get_key_by_kid(f"rot_k1_18") is not None

def test_jwks_key_rotation_flow_19():
    manager = JWKSManager()
    # Step 1: Initial key
    initial_jwks = {"keys": [{"kty": "RSA", "kid": f"rot_k1_19", "use": "sig"}]}
    manager.set_cached_jwks(initial_jwks)
    assert manager.get_key_by_kid(f"rot_k1_19") is not None
    # Step 2: Key rotation (k2 added, k1 still retained for validation)
    rotated_jwks = {"keys": [
        {"kty": "RSA", "kid": f"rot_k2_19", "use": "sig"},
        {"kty": "RSA", "kid": f"rot_k1_19", "use": "sig"},
    ]}
    manager.set_cached_jwks(rotated_jwks)
    assert manager.get_key_by_kid(f"rot_k2_19") is not None
    assert manager.get_key_by_kid(f"rot_k1_19") is not None

def test_jwks_key_rotation_flow_20():
    manager = JWKSManager()
    # Step 1: Initial key
    initial_jwks = {"keys": [{"kty": "RSA", "kid": f"rot_k1_20", "use": "sig"}]}
    manager.set_cached_jwks(initial_jwks)
    assert manager.get_key_by_kid(f"rot_k1_20") is not None
    # Step 2: Key rotation (k2 added, k1 still retained for validation)
    rotated_jwks = {"keys": [
        {"kty": "RSA", "kid": f"rot_k2_20", "use": "sig"},
        {"kty": "RSA", "kid": f"rot_k1_20", "use": "sig"},
    ]}
    manager.set_cached_jwks(rotated_jwks)
    assert manager.get_key_by_kid(f"rot_k2_20") is not None
    assert manager.get_key_by_kid(f"rot_k1_20") is not None

def test_jwks_key_rotation_flow_21():
    manager = JWKSManager()
    # Step 1: Initial key
    initial_jwks = {"keys": [{"kty": "RSA", "kid": f"rot_k1_21", "use": "sig"}]}
    manager.set_cached_jwks(initial_jwks)
    assert manager.get_key_by_kid(f"rot_k1_21") is not None
    # Step 2: Key rotation (k2 added, k1 still retained for validation)
    rotated_jwks = {"keys": [
        {"kty": "RSA", "kid": f"rot_k2_21", "use": "sig"},
        {"kty": "RSA", "kid": f"rot_k1_21", "use": "sig"},
    ]}
    manager.set_cached_jwks(rotated_jwks)
    assert manager.get_key_by_kid(f"rot_k2_21") is not None
    assert manager.get_key_by_kid(f"rot_k1_21") is not None

def test_jwks_key_rotation_flow_22():
    manager = JWKSManager()
    # Step 1: Initial key
    initial_jwks = {"keys": [{"kty": "RSA", "kid": f"rot_k1_22", "use": "sig"}]}
    manager.set_cached_jwks(initial_jwks)
    assert manager.get_key_by_kid(f"rot_k1_22") is not None
    # Step 2: Key rotation (k2 added, k1 still retained for validation)
    rotated_jwks = {"keys": [
        {"kty": "RSA", "kid": f"rot_k2_22", "use": "sig"},
        {"kty": "RSA", "kid": f"rot_k1_22", "use": "sig"},
    ]}
    manager.set_cached_jwks(rotated_jwks)
    assert manager.get_key_by_kid(f"rot_k2_22") is not None
    assert manager.get_key_by_kid(f"rot_k1_22") is not None

def test_jwks_key_rotation_flow_23():
    manager = JWKSManager()
    # Step 1: Initial key
    initial_jwks = {"keys": [{"kty": "RSA", "kid": f"rot_k1_23", "use": "sig"}]}
    manager.set_cached_jwks(initial_jwks)
    assert manager.get_key_by_kid(f"rot_k1_23") is not None
    # Step 2: Key rotation (k2 added, k1 still retained for validation)
    rotated_jwks = {"keys": [
        {"kty": "RSA", "kid": f"rot_k2_23", "use": "sig"},
        {"kty": "RSA", "kid": f"rot_k1_23", "use": "sig"},
    ]}
    manager.set_cached_jwks(rotated_jwks)
    assert manager.get_key_by_kid(f"rot_k2_23") is not None
    assert manager.get_key_by_kid(f"rot_k1_23") is not None

def test_jwks_key_rotation_flow_24():
    manager = JWKSManager()
    # Step 1: Initial key
    initial_jwks = {"keys": [{"kty": "RSA", "kid": f"rot_k1_24", "use": "sig"}]}
    manager.set_cached_jwks(initial_jwks)
    assert manager.get_key_by_kid(f"rot_k1_24") is not None
    # Step 2: Key rotation (k2 added, k1 still retained for validation)
    rotated_jwks = {"keys": [
        {"kty": "RSA", "kid": f"rot_k2_24", "use": "sig"},
        {"kty": "RSA", "kid": f"rot_k1_24", "use": "sig"},
    ]}
    manager.set_cached_jwks(rotated_jwks)
    assert manager.get_key_by_kid(f"rot_k2_24") is not None
    assert manager.get_key_by_kid(f"rot_k1_24") is not None

def test_jwks_key_rotation_flow_25():
    manager = JWKSManager()
    # Step 1: Initial key
    initial_jwks = {"keys": [{"kty": "RSA", "kid": f"rot_k1_25", "use": "sig"}]}
    manager.set_cached_jwks(initial_jwks)
    assert manager.get_key_by_kid(f"rot_k1_25") is not None
    # Step 2: Key rotation (k2 added, k1 still retained for validation)
    rotated_jwks = {"keys": [
        {"kty": "RSA", "kid": f"rot_k2_25", "use": "sig"},
        {"kty": "RSA", "kid": f"rot_k1_25", "use": "sig"},
    ]}
    manager.set_cached_jwks(rotated_jwks)
    assert manager.get_key_by_kid(f"rot_k2_25") is not None
    assert manager.get_key_by_kid(f"rot_k1_25") is not None

def test_jwks_key_rotation_flow_26():
    manager = JWKSManager()
    # Step 1: Initial key
    initial_jwks = {"keys": [{"kty": "RSA", "kid": f"rot_k1_26", "use": "sig"}]}
    manager.set_cached_jwks(initial_jwks)
    assert manager.get_key_by_kid(f"rot_k1_26") is not None
    # Step 2: Key rotation (k2 added, k1 still retained for validation)
    rotated_jwks = {"keys": [
        {"kty": "RSA", "kid": f"rot_k2_26", "use": "sig"},
        {"kty": "RSA", "kid": f"rot_k1_26", "use": "sig"},
    ]}
    manager.set_cached_jwks(rotated_jwks)
    assert manager.get_key_by_kid(f"rot_k2_26") is not None
    assert manager.get_key_by_kid(f"rot_k1_26") is not None

def test_jwks_key_rotation_flow_27():
    manager = JWKSManager()
    # Step 1: Initial key
    initial_jwks = {"keys": [{"kty": "RSA", "kid": f"rot_k1_27", "use": "sig"}]}
    manager.set_cached_jwks(initial_jwks)
    assert manager.get_key_by_kid(f"rot_k1_27") is not None
    # Step 2: Key rotation (k2 added, k1 still retained for validation)
    rotated_jwks = {"keys": [
        {"kty": "RSA", "kid": f"rot_k2_27", "use": "sig"},
        {"kty": "RSA", "kid": f"rot_k1_27", "use": "sig"},
    ]}
    manager.set_cached_jwks(rotated_jwks)
    assert manager.get_key_by_kid(f"rot_k2_27") is not None
    assert manager.get_key_by_kid(f"rot_k1_27") is not None

def test_jwks_key_rotation_flow_28():
    manager = JWKSManager()
    # Step 1: Initial key
    initial_jwks = {"keys": [{"kty": "RSA", "kid": f"rot_k1_28", "use": "sig"}]}
    manager.set_cached_jwks(initial_jwks)
    assert manager.get_key_by_kid(f"rot_k1_28") is not None
    # Step 2: Key rotation (k2 added, k1 still retained for validation)
    rotated_jwks = {"keys": [
        {"kty": "RSA", "kid": f"rot_k2_28", "use": "sig"},
        {"kty": "RSA", "kid": f"rot_k1_28", "use": "sig"},
    ]}
    manager.set_cached_jwks(rotated_jwks)
    assert manager.get_key_by_kid(f"rot_k2_28") is not None
    assert manager.get_key_by_kid(f"rot_k1_28") is not None

def test_jwks_key_rotation_flow_29():
    manager = JWKSManager()
    # Step 1: Initial key
    initial_jwks = {"keys": [{"kty": "RSA", "kid": f"rot_k1_29", "use": "sig"}]}
    manager.set_cached_jwks(initial_jwks)
    assert manager.get_key_by_kid(f"rot_k1_29") is not None
    # Step 2: Key rotation (k2 added, k1 still retained for validation)
    rotated_jwks = {"keys": [
        {"kty": "RSA", "kid": f"rot_k2_29", "use": "sig"},
        {"kty": "RSA", "kid": f"rot_k1_29", "use": "sig"},
    ]}
    manager.set_cached_jwks(rotated_jwks)
    assert manager.get_key_by_kid(f"rot_k2_29") is not None
    assert manager.get_key_by_kid(f"rot_k1_29") is not None

def test_jwks_key_rotation_flow_30():
    manager = JWKSManager()
    # Step 1: Initial key
    initial_jwks = {"keys": [{"kty": "RSA", "kid": f"rot_k1_30", "use": "sig"}]}
    manager.set_cached_jwks(initial_jwks)
    assert manager.get_key_by_kid(f"rot_k1_30") is not None
    # Step 2: Key rotation (k2 added, k1 still retained for validation)
    rotated_jwks = {"keys": [
        {"kty": "RSA", "kid": f"rot_k2_30", "use": "sig"},
        {"kty": "RSA", "kid": f"rot_k1_30", "use": "sig"},
    ]}
    manager.set_cached_jwks(rotated_jwks)
    assert manager.get_key_by_kid(f"rot_k2_30") is not None
    assert manager.get_key_by_kid(f"rot_k1_30") is not None

def test_jwks_key_rotation_flow_31():
    manager = JWKSManager()
    # Step 1: Initial key
    initial_jwks = {"keys": [{"kty": "RSA", "kid": f"rot_k1_31", "use": "sig"}]}
    manager.set_cached_jwks(initial_jwks)
    assert manager.get_key_by_kid(f"rot_k1_31") is not None
    # Step 2: Key rotation (k2 added, k1 still retained for validation)
    rotated_jwks = {"keys": [
        {"kty": "RSA", "kid": f"rot_k2_31", "use": "sig"},
        {"kty": "RSA", "kid": f"rot_k1_31", "use": "sig"},
    ]}
    manager.set_cached_jwks(rotated_jwks)
    assert manager.get_key_by_kid(f"rot_k2_31") is not None
    assert manager.get_key_by_kid(f"rot_k1_31") is not None

def test_jwks_key_rotation_flow_32():
    manager = JWKSManager()
    # Step 1: Initial key
    initial_jwks = {"keys": [{"kty": "RSA", "kid": f"rot_k1_32", "use": "sig"}]}
    manager.set_cached_jwks(initial_jwks)
    assert manager.get_key_by_kid(f"rot_k1_32") is not None
    # Step 2: Key rotation (k2 added, k1 still retained for validation)
    rotated_jwks = {"keys": [
        {"kty": "RSA", "kid": f"rot_k2_32", "use": "sig"},
        {"kty": "RSA", "kid": f"rot_k1_32", "use": "sig"},
    ]}
    manager.set_cached_jwks(rotated_jwks)
    assert manager.get_key_by_kid(f"rot_k2_32") is not None
    assert manager.get_key_by_kid(f"rot_k1_32") is not None

def test_jwks_key_rotation_flow_33():
    manager = JWKSManager()
    # Step 1: Initial key
    initial_jwks = {"keys": [{"kty": "RSA", "kid": f"rot_k1_33", "use": "sig"}]}
    manager.set_cached_jwks(initial_jwks)
    assert manager.get_key_by_kid(f"rot_k1_33") is not None
    # Step 2: Key rotation (k2 added, k1 still retained for validation)
    rotated_jwks = {"keys": [
        {"kty": "RSA", "kid": f"rot_k2_33", "use": "sig"},
        {"kty": "RSA", "kid": f"rot_k1_33", "use": "sig"},
    ]}
    manager.set_cached_jwks(rotated_jwks)
    assert manager.get_key_by_kid(f"rot_k2_33") is not None
    assert manager.get_key_by_kid(f"rot_k1_33") is not None

def test_jwks_key_rotation_flow_34():
    manager = JWKSManager()
    # Step 1: Initial key
    initial_jwks = {"keys": [{"kty": "RSA", "kid": f"rot_k1_34", "use": "sig"}]}
    manager.set_cached_jwks(initial_jwks)
    assert manager.get_key_by_kid(f"rot_k1_34") is not None
    # Step 2: Key rotation (k2 added, k1 still retained for validation)
    rotated_jwks = {"keys": [
        {"kty": "RSA", "kid": f"rot_k2_34", "use": "sig"},
        {"kty": "RSA", "kid": f"rot_k1_34", "use": "sig"},
    ]}
    manager.set_cached_jwks(rotated_jwks)
    assert manager.get_key_by_kid(f"rot_k2_34") is not None
    assert manager.get_key_by_kid(f"rot_k1_34") is not None
