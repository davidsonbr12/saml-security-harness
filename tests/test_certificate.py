import ipaddress
import pytest
import responses as mock_http
from datetime import datetime, timezone, timedelta
from cryptography import x509
from cryptography.x509 import ocsp
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from harness.cert_validator import validate_cert_chain


# ── Helpers ──────────────────────────────────────────────────────────────────

def _new_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _make_ca():
    key = _new_key()
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "Test CA")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert, key


def _make_cert(cn, ca_cert, ca_key, not_before=None, not_after=None, san=None, ocsp_url=None):
    key = _new_key()
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, cn)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before or datetime.now(timezone.utc))
        .not_valid_after(not_after or (datetime.now(timezone.utc) + timedelta(days=365)))
    )
    if san:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(san)]), critical=False
        )
    if ocsp_url:
        builder = builder.add_extension(
            x509.AuthorityInformationAccess([
                x509.AccessDescription(
                    x509.oid.AuthorityInformationAccessOID.OCSP,
                    x509.UniformResourceIdentifier(ocsp_url),
                )
            ]),
            critical=False,
        )
    return builder.sign(ca_key, hashes.SHA256()), key


def _pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM)


def _build_ocsp_response(cert, ca_cert, ca_key, status):
    builder = (
        ocsp.OCSPResponseBuilder()
        .add_response(
            cert=cert,
            issuer=ca_cert,
            algorithm=hashes.SHA256(),
            cert_status=status,
            this_update=datetime.now(timezone.utc),
            next_update=datetime.now(timezone.utc) + timedelta(hours=1),
            revocation_time=datetime.now(timezone.utc) - timedelta(days=1) if status == ocsp.OCSPCertStatus.REVOKED else None,
            revocation_reason=None,
        )
        .responder_id(ocsp.OCSPResponderEncoding.HASH, ca_cert)
    )
    return builder.sign(ca_key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def ca():
    return _make_ca()


# ── Tests ─────────────────────────────────────────────────────────────────────

def test_valid_cert_passes(ca):
    ca_cert, ca_key = ca
    cert, _ = _make_cert("localhost", ca_cert, ca_key)
    findings = validate_cert_chain(_pem(cert), _pem(ca_cert))
    assert findings == []


def test_self_signed_raises_low():
    key = _new_key()
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "self-signed.example.com")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    findings = validate_cert_chain(_pem(cert), _pem(cert))
    assert any(f.check_name == "self_signed_cert" and f.severity == "LOW" for f in findings)


def test_expired_cert_raises_critical(ca):
    ca_cert, ca_key = ca
    cert, _ = _make_cert(
        "localhost", ca_cert, ca_key,
        not_before=datetime.now(timezone.utc) - timedelta(days=365),
        not_after=datetime.now(timezone.utc) - timedelta(seconds=1),
    )
    findings = validate_cert_chain(_pem(cert), _pem(ca_cert))
    assert any(f.check_name == "expired_cert" and f.severity == "CRITICAL" for f in findings)


def test_hostname_mismatch_raises_high(ca):
    ca_cert, ca_key = ca
    cert, _ = _make_cert("wrong.example.com", ca_cert, ca_key)
    findings = validate_cert_chain(_pem(cert), _pem(ca_cert), hostname="localhost")
    assert any(f.check_name == "hostname_mismatch" and f.severity == "HIGH" for f in findings)


def test_expiring_soon_raises_medium(ca):
    ca_cert, ca_key = ca
    cert, _ = _make_cert(
        "localhost", ca_cert, ca_key,
        not_after=datetime.now(timezone.utc) + timedelta(days=15),
    )
    findings = validate_cert_chain(_pem(cert), _pem(ca_cert))
    assert any(f.check_name == "cert_expiring_soon" and f.severity == "MEDIUM" for f in findings)


@mock_http.activate
def test_ocsp_revoked_raises_critical(ca):
    ca_cert, ca_key = ca
    ocsp_url = "http://ocsp.test.local"
    cert, _ = _make_cert("localhost", ca_cert, ca_key, ocsp_url=ocsp_url)

    response_der = _build_ocsp_response(cert, ca_cert, ca_key, ocsp.OCSPCertStatus.REVOKED)
    mock_http.add(
        mock_http.POST, ocsp_url,
        body=response_der, status=200,
        content_type="application/ocsp-response",
    )

    findings = validate_cert_chain(_pem(cert), _pem(ca_cert), check_ocsp=True)
    assert any(f.check_name == "cert_revoked" and f.severity == "CRITICAL" for f in findings)


# ── Coverage: SAN hostname paths ──────────────────────────────────────────────

def test_hostname_match_via_san_passes(ca):
    ca_cert, ca_key = ca
    cert, _ = _make_cert("localhost", ca_cert, ca_key, san="localhost")
    findings = validate_cert_chain(_pem(cert), _pem(ca_cert), hostname="localhost")
    assert not any(f.check_name == "hostname_mismatch" for f in findings)


def test_hostname_mismatch_via_san_raises_high(ca):
    ca_cert, ca_key = ca
    cert, _ = _make_cert("localhost", ca_cert, ca_key, san="other.example.com")
    findings = validate_cert_chain(_pem(cert), _pem(ca_cert), hostname="localhost")
    assert any(f.check_name == "hostname_mismatch" and f.severity == "HIGH" for f in findings)


def test_wildcard_hostname_match_passes(ca):
    ca_cert, ca_key = ca
    cert, _ = _make_cert("*.example.com", ca_cert, ca_key, san="*.example.com")
    findings = validate_cert_chain(_pem(cert), _pem(ca_cert), hostname="foo.example.com")
    assert not any(f.check_name == "hostname_mismatch" for f in findings)


def test_hostname_no_cn_raises_high(ca):
    ca_cert, ca_key = ca
    key = _new_key()
    # Cert with no CN attribute and no SAN
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "Acme")]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .sign(ca_key, hashes.SHA256())
    )
    findings = validate_cert_chain(_pem(cert), _pem(ca_cert), hostname="localhost")
    assert any(f.check_name == "hostname_mismatch" and f.severity == "HIGH" for f in findings)


# ── Coverage: OCSP edge paths ─────────────────────────────────────────────────

def test_ocsp_no_aia_raises_info(ca):
    ca_cert, ca_key = ca
    cert, _ = _make_cert("localhost", ca_cert, ca_key)  # no ocsp_url
    findings = validate_cert_chain(_pem(cert), _pem(ca_cert), check_ocsp=True)
    assert any(f.check_name == "ocsp_not_configured" and f.severity == "INFO" for f in findings)


def test_ocsp_aia_no_ocsp_url_raises_info(ca):
    ca_cert, ca_key = ca
    key = _new_key()
    # AIA with only CA_ISSUERS, no OCSP entry
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "localhost")]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(
            x509.AuthorityInformationAccess([
                x509.AccessDescription(
                    x509.oid.AuthorityInformationAccessOID.CA_ISSUERS,
                    x509.UniformResourceIdentifier("http://ca.example.com/ca.crt"),
                )
            ]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    findings = validate_cert_chain(_pem(cert), _pem(ca_cert), check_ocsp=True)
    assert any(f.check_name == "ocsp_not_configured" and f.severity == "INFO" for f in findings)


@mock_http.activate
def test_ocsp_network_failure_raises_low(ca):
    ca_cert, ca_key = ca
    ocsp_url = "http://ocsp.test.local"
    cert, _ = _make_cert("localhost", ca_cert, ca_key, ocsp_url=ocsp_url)

    mock_http.add(mock_http.POST, ocsp_url, body=ConnectionError("unreachable"))

    findings = validate_cert_chain(_pem(cert), _pem(ca_cert), check_ocsp=True)
    assert any(f.check_name == "ocsp_unavailable" and f.severity == "LOW" for f in findings)


@mock_http.activate
def test_ocsp_bad_response_status_raises_medium(ca):
    ca_cert, ca_key = ca
    ocsp_url = "http://ocsp.test.local"
    cert, _ = _make_cert("localhost", ca_cert, ca_key, ocsp_url=ocsp_url)

    bad_response = ocsp.OCSPResponseBuilder.build_unsuccessful(
        ocsp.OCSPResponseStatus.INTERNAL_ERROR
    )
    mock_http.add(
        mock_http.POST, ocsp_url,
        body=bad_response.public_bytes(serialization.Encoding.DER),
        status=200,
        content_type="application/ocsp-response",
    )

    findings = validate_cert_chain(_pem(cert), _pem(ca_cert), check_ocsp=True)
    assert any(f.check_name == "ocsp_error" and f.severity == "MEDIUM" for f in findings)


def test_hostname_san_with_no_dns_entries_raises_high(ca):
    # SAN extension present but contains only an IP address (no DNSName entries).
    # RFC 6125 §6.4.4: CN must not be used as fallback — hostname cannot be matched.
    ca_cert, ca_key = ca
    key = _new_key()
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "localhost")]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    findings = validate_cert_chain(_pem(cert), _pem(ca_cert), hostname="localhost")
    assert any(f.check_name == "hostname_mismatch" and f.severity == "HIGH" for f in findings)


@mock_http.activate
def test_ocsp_http_error_raises_low(ca):
    # OCSP responder is reachable but returns a non-2xx HTTP status.
    ca_cert, ca_key = ca
    ocsp_url = "http://ocsp.test.local"
    cert, _ = _make_cert("localhost", ca_cert, ca_key, ocsp_url=ocsp_url)

    mock_http.add(mock_http.POST, ocsp_url, status=503)

    findings = validate_cert_chain(_pem(cert), _pem(ca_cert), check_ocsp=True)
    assert any(f.check_name == "ocsp_unavailable" and f.severity == "LOW" for f in findings)


@mock_http.activate
def test_ocsp_unknown_status_raises_high(ca):
    ca_cert, ca_key = ca
    ocsp_url = "http://ocsp.test.local"
    cert, _ = _make_cert("localhost", ca_cert, ca_key, ocsp_url=ocsp_url)

    response_der = _build_ocsp_response(cert, ca_cert, ca_key, ocsp.OCSPCertStatus.UNKNOWN)
    mock_http.add(
        mock_http.POST, ocsp_url,
        body=response_der, status=200,
        content_type="application/ocsp-response",
    )

    findings = validate_cert_chain(_pem(cert), _pem(ca_cert), check_ocsp=True)
    assert any(f.check_name == "ocsp_unknown" and f.severity == "HIGH" for f in findings)
