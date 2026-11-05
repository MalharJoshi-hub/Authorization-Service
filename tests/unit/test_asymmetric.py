"""Unit Tests for Asymmetric Digital Signatures & Key Generation (Phase 8: Layer 1)."""

from auth_service.core.security.asymmetric import asymmetric_crypto


def test_generate_and_sign_rsa():
    priv_pem, pub_pem = asymmetric_crypto.generate_rsa_keypair(key_size=2048)
    assert "-----BEGIN PRIVATE KEY-----" in priv_pem
    assert "-----BEGIN PUBLIC KEY-----" in pub_pem

    data = b"confidential payload for digital signature verification"
    signature = asymmetric_crypto.sign_rsa_sha256(priv_pem, data)
    assert len(signature) > 0

    # Verification with correct public key succeeds
    assert asymmetric_crypto.verify_rsa_sha256(pub_pem, data, signature) is True

    # Verification with altered data fails
    assert asymmetric_crypto.verify_rsa_sha256(pub_pem, b"tampered payload", signature) is False


def test_generate_ecdsa_and_ed25519():
    ec_priv, ec_pub = asymmetric_crypto.generate_ecdsa_keypair()
    assert "-----BEGIN PRIVATE KEY-----" in ec_priv
    assert "-----BEGIN PUBLIC KEY-----" in ec_pub

    ed_priv, ed_pub = asymmetric_crypto.generate_ed25519_keypair()
    assert "-----BEGIN PRIVATE KEY-----" in ed_priv
    assert "-----BEGIN PUBLIC KEY-----" in ed_pub

