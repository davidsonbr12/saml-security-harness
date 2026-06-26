import pytest
import base64
from copy import deepcopy
from datetime import datetime, timezone, timedelta
from lxml import etree

from harness.client import get_sp_flow, ACS_URL
from harness.parser import strip_signature, to_base64

_SAML_NS   = "urn:oasis:names:tc:SAML:2.0:assertion"
_SAMLP_NS  = "urn:oasis:names:tc:SAML:2.0:protocol"
_DS_NS     = "http://www.w3.org/2000/09/xmldsig#"


def _post_to_sp(session, xml_bytes):
    """Re-encode xml_bytes as base64 and POST to the SP ACS. Returns the response."""
    b64 = base64.b64encode(xml_bytes).decode()
    return session.post(ACS_URL, data={"SAMLResponse": b64, "RelayState": "test"})


def _sp_rejected(response):
    """True if the SP returned an error rather than redirecting to the ReturnTo URL."""
    return response.status_code >= 400 or "error" in response.text.lower()


# ── Tests ─────────────────────────────────────────────────────────────────────

@pytest.mark.attack
def test_missing_signature(idp_container):
    xml_bytes, session = get_sp_flow("user1", "password1")
    response = _post_to_sp(session, etree.tostring(strip_signature(etree.fromstring(xml_bytes))))
    assert _sp_rejected(response), "SP Accepted unsigned SAML Response"
                                     
@pytest.mark.attack
def test_expired_conditions(idp_container):
    pass


@pytest.mark.attack
def test_audience_restriction_bypass(idp_container):
    pass


@pytest.mark.attack
def test_name_id_injection(idp_container):
    pass


@pytest.mark.attack
def test_replay_attack(idp_container):
    pass


@pytest.mark.attack
def test_xml_signature_wrapping(idp_container):
    pass
