import pytest
import base64
from copy import deepcopy
from datetime import datetime, timezone, timedelta
from lxml import etree

from harness.client import get_sp_flow, ACS_URL
from harness.parser import strip_signature

_SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion"
_DS_NS   = "http://www.w3.org/2000/09/xmldsig#"


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
    root = etree.fromstring(xml_bytes)
    strip_signature(root)
    response = _post_to_sp(session, etree.tostring(root))
    assert _sp_rejected(response), "SP accepted a SAMLResponse with no signature"


@pytest.mark.attack
def test_expired_conditions(idp_container):
    # Set NotOnOrAfter to one hour in the past — assertion window has closed
    xml_bytes, session = get_sp_flow("user1", "password1")
    root = etree.fromstring(xml_bytes)

    conditions = root.find(f".//{{{_SAML_NS}}}Conditions")
    assert conditions is not None, "SAMLResponse has no Conditions element"
    expired = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    conditions.set("NotOnOrAfter", expired)

    response = _post_to_sp(session, etree.tostring(root))
    assert _sp_rejected(response), "SP accepted an assertion with an expired Conditions window"


@pytest.mark.attack
def test_audience_restriction_bypass(idp_container):
    # Change the Audience to an attacker-controlled SP entity ID.
    # The SP should detect it is not the intended recipient and reject.
    xml_bytes, session = get_sp_flow("user1", "password1")
    root = etree.fromstring(xml_bytes)

    audience = root.find(f".//{{{_SAML_NS}}}Audience")
    assert audience is not None, "SAMLResponse has no Audience element"
    audience.text = "http://evil-sp.attacker.com"

    response = _post_to_sp(session, etree.tostring(root))
    assert _sp_rejected(response), "SP accepted an assertion intended for a different audience"


@pytest.mark.attack
def test_name_id_injection(idp_container):
    # Inject a SQL payload into NameID. Modifying signed content breaks the
    # signature, so the SP should reject it at the signature verification step.
    xml_bytes, session = get_sp_flow("user1", "password1")
    root = etree.fromstring(xml_bytes)

    name_id = root.find(f".//{{{_SAML_NS}}}NameID")
    assert name_id is not None, "SAMLResponse has no NameID element"
    name_id.text = "' OR '1'='1"

    response = _post_to_sp(session, etree.tostring(root))
    assert _sp_rejected(response), "SP accepted an assertion with a tampered NameID"


@pytest.mark.attack
@pytest.mark.xfail(
    strict=True,
    reason=(
        "FINDING [HIGH]: SSP in default configuration does not enforce assertion ID "
        "replay protection. A captured SAMLResponse can be resubmitted and accepted. "
        "Fix: enable a persistent datastore in SSP config so processed assertion IDs "
        "are tracked across requests."
    ),
)
def test_replay_attack(idp_container):
    # Submit the same valid assertion twice. A correctly configured SP should
    # track assertion IDs it has already processed and reject the second submission.
    xml_bytes, session = get_sp_flow("user1", "password1")
    b64 = base64.b64encode(xml_bytes).decode()

    # First submission — should be accepted
    first = session.post(ACS_URL, data={"SAMLResponse": b64, "RelayState": "test"})
    assert not _sp_rejected(first), "First (valid) submission was unexpectedly rejected"

    # Second submission of the identical assertion — should be rejected
    second = session.post(ACS_URL, data={"SAMLResponse": b64, "RelayState": "test"})
    assert _sp_rejected(second), "SP accepted a replayed assertion (same ID submitted twice)"


@pytest.mark.attack
def test_xml_signature_wrapping(idp_container):
    # XSW: inject an unsigned malicious assertion alongside the legitimate signed one.
    # The signed original is kept intact (so signature verification passes), but
    # an evil copy with a modified NameID is inserted before it in the Response.
    # A correctly implemented SP should only process the assertion covered by
    # the signature and reject this manipulation.
    xml_bytes, session = get_sp_flow("user1", "password1")
    root = etree.fromstring(xml_bytes)

    # Find the legitimate signed assertion
    original = root.find(f"{{{_SAML_NS}}}Assertion")

    # Deep copy it and modify the NameID to an attacker value
    evil = deepcopy(original)
    evil_name_id = evil.find(f".//{{{_SAML_NS}}}NameID")
    evil_name_id.text = "admin"

    # Give the evil copy a different ID so it doesn't collide with the signed one
    evil.set("ID", "_evil_unsigned_assertion")

    # Remove the signature from the evil copy — it was never signed
    strip_signature(evil)

    # Inject the evil assertion before the legitimate one in the Response
    root.insert(list(root).index(original), evil)

    response = _post_to_sp(session, etree.tostring(root))
    assert _sp_rejected(response), "SP accepted an XSW attack with an injected unsigned assertion"
