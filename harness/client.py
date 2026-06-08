import requests
from lxml import html
from urllib.parse import urljoin

ADMIN_PASSWORD = "testpassword"

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
