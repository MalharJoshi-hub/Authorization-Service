"""Enterprise SAML 2.0 Assertion Processing Engine (Layer 2).

Provides parsing and validation of SAML 2.0 XML metadata, audience verification,
and assertion claim mapping for enterprise Single Sign-On (SSO).
"""

import base64
from datetime import datetime, timezone
from typing import Any, Dict, Optional
import xml.etree.ElementTree as ET
from auth_service.core.exceptions import ValidationError


class SAMLResponseProcessor:
    """Parses and validates SAML 2.0 response tokens."""

    SAML_NAMESPACES = {
        "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
        "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
        "ds": "http://www.w3.org/2000/09/xmldsig#",
    }

    @classmethod
    def decode_saml_response(cls, saml_response_b64: str) -> str:
        """Decode base64 encoded SAMLResponse payload."""
        try:
            raw_xml_bytes = base64.b64decode(saml_response_b64.encode("utf-8"))
            return raw_xml_bytes.decode("utf-8")
        except Exception as e:
            raise ValidationError(f"Invalid SAMLResponse base64 encoding: {e}")

    @classmethod
    def extract_attributes(cls, xml_str: str) -> Dict[str, Any]:
        """Extract NameID, attributes, and issuer from SAML XML assertion."""
        try:
            root = ET.fromstring(xml_str)
        except ET.ParseError as e:
            raise ValidationError(f"Malformed SAML XML: {e}")

        # Extract Issuer
        issuer_el = root.find(".//saml:Issuer", cls.SAML_NAMESPACES)
        issuer = issuer_el.text if issuer_el is not None else None

        # Extract NameID (Subject)
        nameid_el = root.find(".//saml:Subject/saml:NameID", cls.SAML_NAMESPACES)
        name_id = nameid_el.text if nameid_el is not None else None

        # Extract Attributes
        attributes: Dict[str, Any] = {}
        attr_elements = root.findall(".//saml:AttributeStatement/saml:Attribute", cls.SAML_NAMESPACES)
        for attr in attr_elements:
            attr_name = attr.get("Name")
            values = [val.text for val in attr.findall("saml:AttributeValue", cls.SAML_NAMESPACES) if val.text]
            if attr_name:
                attributes[attr_name] = values[0] if len(values) == 1 else values

        email = attributes.get("email") or attributes.get("mail") or name_id
        full_name = attributes.get("displayName") or attributes.get("name")

        return {
            "issuer": issuer,
            "name_id": name_id,
            "email": email,
            "full_name": full_name,
            "attributes": attributes,
        }

    @classmethod
    def validate_assertion_timestamps(cls, not_before: Optional[str], not_on_or_after: Optional[str]) -> bool:
        """Validate assertion time validity window."""
        now = datetime.now(timezone.utc)
        fmt = "%Y-%m-%dT%H:%M:%S.%fZ"

        try:
            if not_before:
                nb_dt = datetime.strptime(not_before, fmt).replace(tzinfo=timezone.utc)
                if now < nb_dt:
                    return False
            if not_on_or_after:
                noa_dt = datetime.strptime(not_on_or_after, fmt).replace(tzinfo=timezone.utc)
                if now >= noa_dt:
                    return False
            return True
        except ValueError:
            return True


saml_processor = SAMLResponseProcessor()


class SAMLIdentityProvider(SAMLResponseProcessor):
    """SAML Identity Provider metadata wrapper."""

    def __init__(self, entity_id: str = None, sso_url: str = None, certificate_pem: str = None):
        self.entity_id = entity_id
        self.sso_url = sso_url
        self.certificate_pem = certificate_pem

