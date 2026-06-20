from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Literal
from cryptography import x509
from cryptography.x509 import ocsp
from cryptography.hazmat.primitives import hashes, serialization
import requests as http

@dataclass
class Finding:
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    check_name: str
    detail: str
    remediation: str

def validate_cert_chain(
    pem_cert: bytes,
    trusted_ca_pem: bytes,
    hostname: str | None = None,
    expiry_warn_days: int = 30,
    check_ocsp: bool = False,
) -> list[Finding]:
    findings: list[Finding] = []
    cert = x509.load_pem_x509_certificate(pem_cert)
    ca = x509.load_pem_x509_certificate(trusted_ca_pem)

    _check_self_signed(cert, findings)
    _check_expiry(cert, expiry_warn_days, findings)
    if hostname:
        _check_hostname(cert, hostname, findings)
    if check_ocsp:
        _check_ocsp(cert, ca, findings)

    return findings

def _check_expiry(cert: x509.Certificate, warn_days: int, findings: list[Finding]) -> None:
    now = datetime.now(timezone.utc)
    not_after = cert.not_valid_after_utc

    if now > not_after:
        findings.append(Finding(
            severity="CRITICAL",
            check_name="expired_cert",
            detail=f"Certificate expired on {not_after.isoformat()}",
            remediation="Renew the certificate immediately.",
        ))
    elif not_after - now <= timedelta(days=warn_days):
        days_left = (not_after - now).days
        findings.append(Finding(
            severity="MEDIUM",
            check_name="cert_expiring_soon",
            detail=f"Certificate expires in {days_left} day(s) (threshold: {warn_days})",
            remediation=f"Renew the certificate before {not_after.date()}.",
        ))

def _check_self_signed(cert: x509.Certificate, findings: list[Finding]) -> None:
    if cert.issuer == cert.subject:
        findings.append(Finding(
            severity="LOW",
            check_name="self_signed_cert",
            detail=f"Certificate is self-signed (subject: {cert.subject.rfc4514_string()})",
            remediation="Replace with a certificate signed by a trusted CA.",
        ))

def _check_hostname(cert: x509.Certificate, hostname: str, findings: list[Finding]) -> None:
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        dns_names = san.value.get_values_for_type(x509.DNSName)
        if dns_names:
            if not any(_hostname_matches(hostname, name) for name in dns_names):
                findings.append(Finding(
                    severity="HIGH",
                    check_name="hostname_mismatch",
                    detail=f"Hostname '{hostname}' does not match SANs: {dns_names}",
                    remediation="Reissue the certificate with the correct hostname in the SAN extension.",
                ))
            return
    except x509.ExtensionNotFound:
        pass

    cn_attrs = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    if not cn_attrs:
        findings.append(Finding(
            severity="HIGH",
            check_name="hostname_mismatch",
            detail=f"Certificate has no CN or SAN to match against '{hostname}'",
            remediation="Reissue the certificate with the correct hostname in the SAN extension.",
        ))
        return

    cn = cn_attrs[0].value
    if not _hostname_matches(hostname, cn):
        findings.append(Finding(
            severity="HIGH",
            check_name="hostname_mismatch",
            detail=f"Hostname '{hostname}' does not match CN '{cn}'",
            remediation="Reissue the certificate with the correct hostname in the CN or SAN extension.",
        ))

def _hostname_matches(hostname: str, pattern: str) -> bool:
    if pattern.startswith("*."):
        suffix = pattern[2:]
        parts = hostname.split(".")
        return len(parts) > 1 and ".".join(parts[1:]) == suffix
    return hostname == pattern

def _check_ocsp(cert: x509.Certificate, ca: x509.Certificate, findings: list[Finding]) -> None:
    try:
        aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess)
        ocsp_urls = [
            access.access_location.value
            for access in aia.value
            if access.access_method == x509.oid.AuthorityInformationAccessOID.OCSP
        ]
    except x509.ExtensionNotFound:
        findings.append(Finding(
            severity="INFO",
            check_name="ocsp_not_configured",
            detail="Certificate has no AIA extension with an OCSP URL.",
            remediation="Include an OCSP URL in the Authority Information Access extension.",
        ))
        return

    if not ocsp_urls:
        findings.append(Finding(
            severity="INFO",
            check_name="ocsp_not_configured",
            detail="Certificate AIA extension has no OCSP entry.",
            remediation="Include an OCSP URL in the Authority Information Access extension.",
        ))
        return

    ocsp_url = ocsp_urls[0]

    builder = ocsp.OCSPRequestBuilder().add_certificate(cert, ca, hashes.SHA256())
    request_der = builder.build().public_bytes(serialization.Encoding.DER)

    try:
        resp = http.post(
            ocsp_url,
            data=request_der,
            headers={"Content-Type": "application/ocsp-request"},
            timeout=5,
        )
        response_der = resp.content
    except Exception as e:
        findings.append(Finding(
            severity="LOW",
            check_name="ocsp_unavailable",
            detail=f"OCSP check failed: {e}",
            remediation="Verify the OCSP responder is reachable and the URL is correct.",
        ))
        return

    ocsp_response = ocsp.load_der_ocsp_response(response_der)

    if ocsp_response.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
        findings.append(Finding(
            severity="MEDIUM",
            check_name="ocsp_error",
            detail=f"OCSP responder returned: {ocsp_response.response_status.name}",
            remediation="Verify the OCSP responder configuration.",
        ))
        return

    status = ocsp_response.certificate_status
    if status == ocsp.OCSPCertStatus.REVOKED:
        findings.append(Finding(
            severity="CRITICAL",
            check_name="cert_revoked",
            detail=f"Certificate is REVOKED. Revocation time: {ocsp_response.revocation_time_utc}",
            remediation="Replace the certificate immediately — it has been revoked.",
        ))
    elif status == ocsp.OCSPCertStatus.UNKNOWN:
        findings.append(Finding(
            severity="HIGH",
            check_name="ocsp_unknown",
            detail="OCSP responder returned UNKNOWN status for this certificate.",
            remediation="Contact your CA — the certificate status cannot be verified.",
        ))
