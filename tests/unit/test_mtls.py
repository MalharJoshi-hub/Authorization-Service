"""Unit tests for Mutual TLS (mTLS) client certificate parsing and RFC 8705 binding."""

import base64
import pytest
from auth_service.core.security.mtls import MTLSHandler, MTLSError, ClientCertificate


def test_clean_pem_certificate():
    raw_payload = b"SampleCertificateBytes"
    b64_str = base64.b64encode(raw_payload).decode("ascii")
    pem = f"-----BEGIN CERTIFICATE-----\n{b64_str}\n-----END CERTIFICATE-----"

    der = MTLSHandler.clean_pem_certificate(pem)
    assert der == raw_payload


def test_compute_sha256_thumbprint():
    der = b"SampleCertificateDERData"
    thumbprint = MTLSHandler.compute_sha256_thumbprint(der)
    assert len(thumbprint) == 64
    assert thumbprint.isupper()


def test_parse_header_cert_with_cn():
    der = b"MockCertificateBody"
    b64_der = base64.b64encode(der).decode("ascii")
    header_val = f"CN=service-billing.internal,O=AcmeCorp;-----BEGIN CERTIFICATE-----\n{b64_der}\n-----END CERTIFICATE-----"

    cert = MTLSHandler.parse_header_cert(header_val)
    assert cert is not None
    assert cert.common_name == "service-billing.internal"
    assert cert.organization == "AcmeCorp"

    cnf = cert.get_rfc8705_cnf()
    assert "x5t#S256" in cnf
    assert len(cnf["x5t#S256"]) > 10


def test_parse_header_cert_none():
    assert MTLSHandler.parse_header_cert(None) is None
    assert MTLSHandler.parse_header_cert("") is None


def test_parse_header_cert_invalid_base64():
    header_val = "CN=test;-----BEGIN CERTIFICATE-----\nInvalid!Base64@Bytes\n-----END CERTIFICATE-----"
    with pytest.raises(MTLSError):
        MTLSHandler.parse_header_cert(header_val)
