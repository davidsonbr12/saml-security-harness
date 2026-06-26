import pytest
import requests
import time
import subprocess

from harness.report import ReportFinding, generate_html_report, generate_json_report

_findings: list[ReportFinding] = []


# ── Docker fixture ────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def idp_container():
    subprocess.run(["docker-compose", "up", "-d"], check=True)
    while True:
        try:
            requests.get("http://localhost:8080/simplesaml")
            break
        except:
            time.sleep(2)

    yield

    subprocess.run(["docker-compose", "down"], check=True)


# ── Reporting hooks ───────────────────────────────────────────────────────────

def pytest_runtest_logreport(report: pytest.TestReport) -> None:
    """Collect a ReportFinding for each test after it runs."""
    if report.when != "call":
        return

    test_name = report.nodeid
    is_attack = "test_attacks" in test_name

    if hasattr(report, "wasxfail"):
        # Expected failure — a documented security finding
        status   = "WARN"
        severity = "HIGH"
        detail   = report.wasxfail
        remediation = "See finding description for remediation guidance."

    elif report.passed:
        status   = "PASS"
        severity = "INFO"
        detail   = "Defense held — SP correctly rejected the attack." if is_attack else "Test passed."
        remediation = "No action required."

    else:
        # Unexpected failure
        status   = "FAIL"
        severity = "HIGH" if is_attack else "MEDIUM"
        detail   = str(report.longrepr) if report.longrepr else "Test failed."
        remediation = (
            "Investigate — SP may be vulnerable to this attack vector."
            if is_attack else
            "Fix the failing test before merging."
        )

    _findings.append(ReportFinding(
        test_name=test_name,
        severity=severity,
        status=status,
        detail=detail,
        remediation=remediation,
    ))


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    """Write HTML and JSON reports after all tests complete."""
    if not _findings:
        return

    generate_html_report(_findings, "reports/report.html")
    generate_json_report(_findings, "reports/report.json")
    print(f"\nReports written to reports/report.html and reports/report.json")
