import base64, zlib, uuid
import requests
from lxml import html
from urllib.parse import urljoin
from datetime import datetime, timezone

ADMIN_PASSWORD = "testpassword"
SP_ENTITY_ID = "http://localhost:8080/sp"
ACS_URL = "http://localhost:8080/sp/acs"

def _parse_form(response):
    tree = html.fromstring(response.text)
    form = tree.find('.//form')
    action = urljoin(response.url, form.get('action') or '')
    hidden = {i.get('name'): i.get('value') for i in form.findall('.//input[@type="hidden"]')}
    return action, hidden

def saml_login(idp_url, username, password):
    session = requests.Session()

    response = session.get(idp_url)
    print(f"Step 1: {response.status_code} {response.url}")
    print(response.text[:1000])

    action, hidden = _parse_form(response)
    hidden['password'] = ADMIN_PASSWORD
    response = session.post(action, data=hidden)
    print(f"Step 2: {response.status_code} {response.url}")

    action, hidden = _parse_form(response)
    hidden['username'] = username
    hidden['password'] = password
    response = session.post(action, data=hidden)
    print(f"Step 3: {response.status_code} {response.url}")

    return response

def get_saml_response_xml(idp_base_url, username, password, sp_entity_id=SP_ENTITY_ID, acs_url=ACS_URL):
    """Drive a real SP-initiated SAML flow and return the decoded SAMLResponse as bytes."""
    session = requests.Session()

    authn_request = _build_authn_request(sp_entity_id, acs_url)
    sso_url = f"{idp_base_url}/module.php/saml/idp/singleSignOnService"

    response = session.get(sso_url, params={"SAMLRequest": authn_request, "RelayState": "test"})

    # SSP shows the authsource login form
    action, hidden = _parse_form(response)
    hidden["username"] = username
    hidden["password"] = password
    response = session.post(action, data=hidden)

    # SSP returns a self-posting form with the SAMLResponse
    tree = html.fromstring(response.text)
    saml_b64 = tree.xpath('//input[@name="SAMLResponse"]/@value')
    if not saml_b64:
        raise RuntimeError(
            f"No SAMLResponse in IdP response (status {response.status_code}). "
            f"Response snippet: {response.text[:500]}"
        )
    return base64.b64decode(saml_b64[0])

def get_saml_response_xml_unknown_sp(idp_base_url):
    """Initiate a SAML flow from an SP entity ID not in the IdP's remote metadata."""
    session = requests.Session()
    authn_request = _build_authn_request("http://unknown-sp.attacker.com", "http://unknown-sp.attacker.com/acs")
    sso_url = f"{idp_base_url}/module.php/saml/idp/singleSignOnService"
    return session.get(sso_url, params={"SAMLRequest": authn_request, "RelayState": "test"})

def _build_authn_request(sp_entity_id, acs_url):
    """Return a base64+deflate encoded SAML AuthnRequest for the redirect binding."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    xml = (
        f'<?xml version="1.0"?>'
        f'<samlp:AuthnRequest'
        f' xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"'
        f' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"'
        f' ID="_{uuid.uuid4().hex}"'
        f' Version="2.0"'
        f' IssueInstant="{now}"'
        f' AssertionConsumerServiceURL="{acs_url}">'
        f'<saml:Issuer>{sp_entity_id}</saml:Issuer>'
        f'</samlp:AuthnRequest>'
    )
    compressed = zlib.compress(xml.encode())[2:-4]  # raw deflate (strip zlib header/trailer)
    return base64.b64encode(compressed).decode()
