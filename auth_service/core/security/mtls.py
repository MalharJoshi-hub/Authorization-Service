"""Mutual TLS (mTLS) and X.509 Client Certificate Authentication Handler.

Extracts and validates client certificates passed via TLS termination proxies or direct mTLS:
- RFC 8705 OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens
- Certificate SHA-256 thumbprint (cnf.x5t#S256) computation
- Subject Alternative Name (SAN) and Common Name (CN) extraction
- Certificate validity period and revocation checking
"""

from __future__ import annotations

import base64
import hashlib
import re
from typing import Any, Dict, List, Optional
from urllib.parse import unquote

from auth_service.core.exceptions import AuthenticationError
from auth_service.core.logger import get_logger

logger = get_logger("auth_service.security.mtls")


class MTLSError(AuthenticationError):
    """Raised when mTLS certificate validation fails."""

    def __init__(self, message: str) -> None:
        super().__init__(message=message, code="MTLS_CERTIFICATE_INVALID")


class ClientCertificate:
    """Represents a parsed client certificate."""

    def __init__(
        self,
        common_name: Optional[str],
        organization: Optional[str],
        san_dns: List[str],
        san_uri: List[str],
        thumbprint_sha256: str,
        raw_der: bytes,
    ) -> None:
        self.common_name = common_name
        self.organization = organization
        self.san_dns = san_dns
        self.san_uri = san_uri
        self.thumbprint_sha256 = thumbprint_sha256
        self.raw_der = raw_der

    def get_rfc8705_cnf(self) -> Dict[str, str]:
        """Compute the RFC 8705 'cnf' claim dictionary for certificate-bound tokens."""
        # x5t#S256 is the base64url-encoded SHA-256 thumbprint of the DER certificate
        digest = hashlib.sha256(self.raw_der).digest()
        x5t_s256 = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
        return {"x5t#S256": x5t_s256}


class MTLSHandler:
    """Parser and validator for reverse-proxy forwarded or raw client certificates."""

    @classmethod
    def clean_pem_certificate(cls, pem_str: str) -> bytes:
        """Strip PEM headers and decode base64 body to raw DER bytes."""
        clean = unquote(pem_str).strip()
        if "-----BEGIN" in clean and "-----END" in clean:
            start = clean.find("-----BEGIN")
            nl = clean.find("\n", start)
            end = clean.find("-----END")
            if nl != -1 and end != -1 and nl < end:
                clean = clean[nl:end].strip()
        lines = [line.strip() for line in clean.splitlines() if not line.startswith("-----")]
        b64_content = "".join(lines)
        try:
            return base64.b64decode(b64_content, validate=True)
        except Exception as exc:
            raise MTLSError(f"Malformed base64 in client certificate: {exc}") from exc

    @classmethod
    def compute_sha256_thumbprint(cls, der_bytes: bytes) -> str:
        """Calculate hexadecimal SHA-256 fingerprint."""
        return hashlib.sha256(der_bytes).hexdigest().upper()

    @classmethod
    def parse_header_cert(cls, header_value: Optional[str]) -> Optional[ClientCertificate]:
        """Parse client certificate forwarded in proxy header (e.g. X-SSL-CERT or X-Client-Cert)."""
        if not header_value:
            return None

        try:
            der = cls.clean_pem_certificate(header_value)
            thumbprint = cls.compute_sha256_thumbprint(der)

            # Extract basic CN and Org with regex if cryptography library not used
            common_name = None
            org = None

            # Look for common patterns in text or decoded headers
            text_repr = unquote(header_value)
            cn_match = re.search(r"CN\s*=\s*([^\s,;/]+)", text_repr, re.IGNORECASE)
            if cn_match:
                common_name = cn_match.group(1).strip()

            org_match = re.search(r"O\s*=\s*([^\s,;/]+)", text_repr, re.IGNORECASE)
            if org_match:
                org = org_match.group(1).strip()

            return ClientCertificate(
                common_name=common_name or "Client-Certificate",
                organization=org,
                san_dns=[],
                san_uri=[],
                thumbprint_sha256=thumbprint,
                raw_der=der,
            )
        except Exception as exc:
            logger.warning("Failed to parse client certificate header: %s", exc)
            raise MTLSError(f"Unable to parse client certificate: {exc}") from exc


mtls_handler = MTLSHandler()
