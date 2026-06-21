from datetime import datetime, timezone
from lxml import etree
from harness.client import saml_login, get_saml_response_xml, get_saml_response_xml_unknown_sp
from harness.parser import decode_saml_response, extract_assertion, extract_name_id

IDP_BASE = "http://localhost:8080/simplesaml"
TEST_URL = f"{IDP_BASE}/module.php/admin/test/example-userpass"
SP_ENTITY_ID = "http://localhost:8080/sp"

_SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion"
_SAMLP_NS = "urn:oasis:names:tc:SAML:2.0:protocol"


# ── Existing baseline login tests ─────────────────────────────────────────────

def test_valid_login_returns_200(idp_container):
    response = saml_login(TEST_URL, "user1", "password1")
    assert response.status_code == 200

def test_uid_in_response(idp_container):
    response = saml_login(TEST_URL, "user1", "password1")
    assert "user1" in response.text

def test_email_in_response(idp_container):
    response = saml_login(TEST_URL, "user1", "password1")
    assert "user1@example.com" in response.text

def test_affiliation_in_response(idp_container):
    response = saml_login(TEST_URL, "user1", "password1")
    assert "member" in response.text

def test_wrong_password_rejected(idp_container):
    response = saml_login(TEST_URL, "bad_user", "bad_password")
    assert "user1@example.com" not in response.text

def test_wrong_username_rejected(idp_container):
    response = saml_login(TEST_URL, "bad_user1", "bad_password")
    assert "user1@example.com" not in response.text

def test_user2_login_returns_200(idp_container):
    response = saml_login(TEST_URL, "user2", "password2")
    assert response.status_code == 200


# ── SAML assertion structure tests (SP-initiated flow) ────────────────────────

def _get_assertion(idp_container):
    xml_bytes = get_saml_response_xml(IDP_BASE, "user1", "password1")
    root = etree.fromstring(xml_bytes)
    assertion = root.find(f"{{{_SAML_NS}}}Assertion")
    assert assertion is not None, "No Assertion element in SAMLResponse"
    return root, assertion


def test_name_id_present(idp_container):
    _, assertion = _get_assertion(idp_container)
    name_id = assertion.find(f".//{{{_SAML_NS}}}NameID")
    assert name_id is not None and name_id.text, "NameID is missing or empty"


def test_audience_matches_sp_entity_id(idp_container):
    _, assertion = _get_assertion(idp_container)
    audiences = assertion.findall(f".//{{{_SAML_NS}}}Audience")
    assert any(a.text == SP_ENTITY_ID for a in audiences), (
        f"Expected Audience '{SP_ENTITY_ID}' not found in {[a.text for a in audiences]}"
    )


def test_conditions_window_is_valid(idp_container):
    _, assertion = _get_assertion(idp_container)
    conditions = assertion.find(f"{{{_SAML_NS}}}Conditions")
    assert conditions is not None, "Conditions element missing"

    now = datetime.now(timezone.utc)
    not_before = datetime.fromisoformat(conditions.get("NotBefore").replace("Z", "+00:00"))
    not_on_or_after = datetime.fromisoformat(conditions.get("NotOnOrAfter").replace("Z", "+00:00"))

    assert not_before <= now < not_on_or_after, (
        f"Current time {now} is outside Conditions window [{not_before}, {not_on_or_after})"
    )


def test_authn_statement_present(idp_container):
    _, assertion = _get_assertion(idp_container)
    authn_stmt = assertion.find(f"{{{_SAML_NS}}}AuthnStatement")
    assert authn_stmt is not None, "AuthnStatement element missing"
    assert authn_stmt.get("AuthnInstant"), "AuthnStatement has no AuthnInstant attribute"


# ── Negative: unknown SP entity ID ────────────────────────────────────────────

def test_unknown_sp_entity_id_rejected(idp_container):
    response = get_saml_response_xml_unknown_sp(IDP_BASE)
    # SSP should return an error page, not a SAMLResponse form
    assert response.status_code in (400, 403, 500) or "SAMLResponse" not in response.text, (
        "IdP should reject an AuthnRequest from an unregistered SP entity ID"
    )
