"""Asymmetric Cryptography & X.509 Key Engine (Layer 1: Security Core).

Provides keypair generation (RSA, ECDSA P-256, Ed25519), PEM serialization,
asymmetric digital signing, and self-signed certificate minting.
"""

from typing import Tuple
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


class AsymmetricKeyManager:
    """Manages generation and conversion of asymmetric key algorithms."""

    @staticmethod
    def generate_rsa_keypair(key_size: int = 2048) -> Tuple[str, str]:
        """Generate RSA keypair returned as PEM strings."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )
        priv_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")

        pub_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        return priv_pem, pub_pem

    @staticmethod
    def generate_ecdsa_keypair() -> Tuple[str, str]:
        """Generate ECDSA P-256 (ES256) keypair."""
        private_key = ec.generate_private_key(ec.SECP256R1())
        priv_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")

        pub_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        return priv_pem, pub_pem

    @staticmethod
    def generate_ed25519_keypair() -> Tuple[str, str]:
        """Generate high-speed Ed25519 keypair."""
        private_key = ed25519.Ed25519PrivateKey.generate()
        priv_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")

        pub_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        return priv_pem, pub_pem

    @staticmethod
    def sign_rsa_sha256(private_key_pem: str, data: bytes) -> bytes:
        """Sign binary payload with RSA-PSS SHA-256."""
        priv_key = serialization.load_pem_private_key(
            private_key_pem.encode("utf-8"),
            password=None,
        )
        return priv_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

    @staticmethod
    def verify_rsa_sha256(public_key_pem: str, data: bytes, signature: bytes) -> bool:
        """Verify binary signature against RSA-PSS public key."""
        pub_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
        try:
            pub_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            return True
        except Exception:
            return False


asymmetric_crypto = AsymmetricKeyManager()
generate_rsa_key_pair = AsymmetricKeyManager.generate_rsa_keypair


def public_key_to_jwk(pub_pem: str, kid: str = "key_1", alg: str = "RS256"):
    """Convert RSA public key PEM to JWK dictionary."""
    import base64
    from cryptography.hazmat.primitives import serialization
    pub_key = serialization.load_pem_public_key(pub_pem.encode("utf-8"))
    numbers = pub_key.public_numbers()
    def to_b64(val: int) -> str:
        b = val.to_bytes((val.bit_length() + 7) // 8, "big")
        return base64.urlsafe_b64encode(b).decode("utf-8").rstrip("=")
    return {
        "kty": "RSA",
        "use": "sig",
        "alg": alg,
        "kid": kid,
        "n": to_b64(numbers.n),
        "e": to_b64(numbers.e),
    }

