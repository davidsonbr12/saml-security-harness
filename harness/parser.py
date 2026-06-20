import base64
from lxml import etree

_SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion"
_SAMLP_NS = "urn:oasis:names:tc:SAML:2.0:protocol"
_DS_NS = "http://www.w3.org/2000/09/xmldsig#"

def decode_saml_response(b64_response: str) -> etree._Element:
    return etree.fromstring(base64.b64decode(b64_response))

def extract_assertion(root: etree._Element) -> etree._Element | None:
    assertions = root.findall(f"{{{_SAML_NS}}}Assertion")
    return assertions[0] if assertions else None

def extract_name_id(root: etree._Element) -> str | None:
    el = root.find(f".//{{{_SAML_NS}}}NameID")
    return el.text if el is not None else None

def extract_attributes(root: etree._Element) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for attr in root.findall(f".//{{{_SAML_NS}}}Attribute"):
        name = attr.get("Name")
        values = [v.text for v in attr.findall(f"{{{_SAML_NS}}}AttributeValue")]
        result[name] = values
    return result

def has_signature(root: etree._Element) -> bool:
    return root.find(f".//{{{_DS_NS}}}Signature") is not None

def strip_signature(root: etree._Element) -> etree._Element:
    for sig in root.findall(f".//{{{_DS_NS}}}Signature"):
        sig.getparent().remove(sig)
    return root

def to_base64(root: etree._Element) -> str:
    return base64.b64encode(etree.tostring(root)).decode()
