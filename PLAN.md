**SAML / SSO SECURITY**

**TEST HARNESS**

*Claude Code Project Handoff Document*

Security QA Engineering · Authentication Systems · v1.0

Prepared by Senior QA Engineer

May 28, 2026

# **1. Executive Summary**

This document is a complete handoff specification for the SAML/SSO Security Test Harness — a purpose-built automated testing framework targeting authentication security at the protocol level. The project converts ad-hoc vendor triage work into a systematic, repeatable, and auditable process.

**The framework will:**

* Automatically validate SAML assertions, certificate chains, and SSO flows
* Simulate known authentication attack vectors (XSW, replay, signature bypass)
* Generate structured severity-classified reports for both technical and non-technical audiences
* Run continuously in CI/CD on a schedule or triggered by vendor changes

|  |  |  |  |
| --- | --- | --- | --- |
| **Timeline** | **Tech Stack** | **Test Coverage** | **Output** |
| **8 weeks** | **Python / pytest** | **6 attack categories** | **HTML + JSON reports** |

# **2. Project Goals**

## **2.1 Primary Objectives**

* Replace manual SAML payload inspection with deterministic automated checks
* Build a reusable test library that can be pointed at any SP/IdP integration
* Surface authentication vulnerabilities before they reach production
* Create audit-ready evidence of security testing for compliance review

## **2.2 Non-Goals**

* This is NOT a penetration testing tool — it validates configuration, not exploits systems
* Does not cover OAuth 2.0 / OIDC flows (future phase)
* Does not auto-remediate findings — reporting only

# **3. Architecture Overview**

The harness is structured in four distinct layers, each independently testable and replaceable.

|  |  |  |
| --- | --- | --- |
| **Layer** | **Component** | **Responsibility** |
| **Transport** | HTTP Client (requests) | Initiates SP/IdP flows, captures redirects and POST bindings |
| **Parsing** | SAML Parser (lxml + pysaml2) | Decodes base64, parses XML, extracts assertions and signatures |
| **Validation** | Test Modules (pytest) | Runs assertions against parsed SAML objects and cert chains |
| **Reporting** | Reporter (pytest-html + JSON) | Produces severity-tagged HTML and machine-readable JSON output |
| **CI Layer** | GitHub Actions | Schedules runs, gates PRs, archives report artifacts |

## **3.1 Repository Structure**

Instruct Claude Code to scaffold this exact directory layout:

saml-security-harness/

├── docker/

│ └── idp/ # SimpleSAMLphp IdP container

├── harness/

│ ├── \_\_init\_\_.py

│ ├── client.py # HTTP session + redirect following

│ ├── parser.py # SAML base64 decode + XML parse

│ ├── cert\_validator.py # Certificate chain validation

│ └── report.py # Severity tagging + JSON export

├── tests/

│ ├── conftest.py # Fixtures, IdP startup, shared config

│ ├── test\_certificate.py # Phase 1: cert chain tests

│ ├── test\_assertion.py # Phase 2: payload structure tests

│ ├── test\_attacks.py # Phase 3: XSW, replay, bypass tests

│ └── test\_flows.py # Phase 4: SP/IdP-initiated flows

├── reports/ # Output directory (gitignored)

├── .github/workflows/

│ └── saml\_security.yml # CI pipeline

├── requirements.txt

├── pytest.ini

└── README.md

# **4. Development Milestones**

Each phase has a clear entry condition, deliverable, and definition of done. Provide this milestone table to Claude Code when starting each phase.

|  |  |
| --- | --- |
| **Phase 1**  Weeks 1–2 | **Environment & Baseline** |
| ☐ Scaffold repo structure per Section 3.1 |
| ☐ Create docker-compose.yml with SimpleSAMLphp IdP on port 8080 |
| ☐ Write conftest.py with pytest fixtures that start/stop the container |
| ☐ Implement client.py: SP-initiated login flow, capture final SAML POST |
| ☐ Write 5 baseline positive tests: valid login returns 200, NameID present, Audience matches SP entity ID, Conditions window is valid, AuthnStatement present |
| ☐ Write 3 baseline negative tests: wrong password returns error, expired session rejected, unknown SP entity ID rejected |
| **✓ Done when:** All 8 baseline tests pass against local IdP. pytest summary shows green. |

|  |  |
| --- | --- |
| **Phase 2**  Weeks 3–4 | **Certificate Validation Module** |
| ☐ Implement cert\_validator.py using Python cryptography library |
| ☐ Test: valid cert signed by trusted CA passes |
| ☐ Test: self-signed cert raises WARNING severity finding |
| ☐ Test: expired cert (mock via OpenSSL date offset) raises CRITICAL finding |
| ☐ Test: cert CN/SAN mismatch with IdP hostname raises HIGH finding |
| ☐ Test: cert expiring within 30 days raises WARNING (configurable threshold) |
| ☐ Test: cert revocation check via OCSP stub (mock server) |
| ☐ All findings include: severity, cert field, expected vs actual, remediation hint |
| **✓ Done when:** cert\_validator.py has 100% line coverage. All 6 cert tests pass. Findings JSON schema validated. |

|  |  |
| --- | --- |
| **Phase 3**  Week 5 | **Attack Simulation Suite** |
| ☐ XML Signature Wrapping (XSW): inject unsigned assertion alongside signed one; verify SP rejects it |
| ☐ Replay Attack: re-submit captured assertion with same ID; verify SP rejects duplicate |
| ☐ Missing Signature: strip ds:Signature from assertion; verify SP rejects unsigned |
| ☐ Conditions Bypass: modify NotBefore/NotOnOrAfter to expired window; verify SP rejects |
| ☐ Audience Restriction Bypass: change Audience to attacker SP; verify original SP rejects |
| ☐ NameID Injection: inject SQL/XSS payload in NameID value; verify SP sanitizes or rejects |
| **✓ Done when:** All 6 attack tests pass (SP correctly rejects each). Tests are tagged @pytest.mark.attack for selective runs. |

|  |  |
| --- | --- |
| **Phase 4**  Week 6 | **Reporting Layer** |
| ☐ Implement report.py: accepts list of Finding objects, outputs HTML and JSON |
| ☐ Finding schema: { id, test\_name, severity: CRITICAL|HIGH|MEDIUM|LOW|INFO, status: PASS|FAIL|WARN, detail, remediation } |
| ☐ HTML report: severity-colored rows, summary counts at top, sortable by severity |
| ☐ JSON report: machine-readable, suitable for SIEM ingestion or ticketing API |
| ☐ pytest plugin hook: auto-generate report on test run completion |
| ☐ Configure pytest-html for human-readable secondary report |
| **✓ Done when:** Running pytest generates both reports/report.html and reports/report.json. HTML renders correctly in browser. |

|  |  |
| --- | --- |
| **Phase 5**  Week 7 | **CI/CD Pipeline** |
| ☐ Write .github/workflows/saml\_security.yml |
| ☐ Trigger: push to main, pull\_request, and schedule: cron '0 6 \* \* 1' (weekly Monday) |
| ☐ Steps: checkout, setup-python 3.11, pip install -r requirements.txt, docker-compose up -d, pytest, upload-artifact reports/ |
| ☐ Badge: add passing/failing badge to README |
| ☐ Failure notification: on failure, print summary of CRITICAL and HIGH findings to GitHub Actions summary |
| **✓ Done when:** Pipeline passes on GitHub. Report artifact downloadable from Actions run. Badge shows in README. |

|  |  |
| --- | --- |
| **Phase 6**  Week 8 | **Polish & Documentation** |
| ☐ Write README.md: purpose, quickstart (docker-compose up + pytest), report interpretation guide |
| ☐ Add CONTRIBUTING.md: how to add a new test, finding schema reference |
| ☐ Add architecture diagram (Mermaid in README) |
| ☐ Write a plain-English findings summary template (for sharing with non-technical managers) |
| ☐ Record a 5-minute demo: run the full suite, open the HTML report, walk through one CRITICAL finding |
| **✓ Done when:** Project is portfolio-ready. README explains the project to a non-QA engineer in under 5 minutes. |

# **5. Dependencies & Tech Stack**

Include this as your requirements.txt. All packages are pip-installable.

|  |  |  |
| --- | --- | --- |
| **Package** | **Version** | **Purpose** |
| **pytest** | >=7.4 | Test runner and fixture engine |
| **pytest-html** | >=3.2 | Human-readable HTML test reports |
| **requests** | >=2.31 | HTTP client for SP/IdP flow simulation |
| **lxml** | >=4.9 | XML parsing and XPath for SAML documents |
| **pysaml2** | >=7.4 | SAML 2.0 protocol library for assertion handling |
| **cryptography** | >=41.0 | X.509 certificate parsing and chain validation |
| **docker** | >=6.1 | Python SDK for starting/stopping IdP container in tests |
| **responses** | >=0.23 | HTTP mock library for OCSP stub and offline tests |
| **pytest-cov** | >=4.1 | Code coverage enforcement |

*Docker requirement: Docker Desktop (Mac/Windows) or Docker Engine (Linux). SimpleSAMLphp IdP image: simpleSAMLphp/simplesamlphp:latest.*

# **6. Claude Code Prompt Guide**

Use these starter prompts verbatim when beginning each phase. They include the critical context Claude Code needs to avoid rework.

## **Phase 1 Prompt**

|  |
| --- |
| You are building a SAML security test harness in Python. Scaffold the repository structure exactly as specified: saml-security-harness/ with subdirectories docker/idp/, harness/, tests/, reports/, and .github/workflows/. Create a docker-compose.yml that runs SimpleSAMLphp on port 8080 with a test SP configured. Write tests/conftest.py with pytest fixtures that start the container before the session and stop it after. Write harness/client.py that uses requests to follow an SP-initiated login redirect, POST credentials, and capture the final SAML assertion from the POST binding. Write 8 baseline tests in tests/test\_assertion.py — 5 positive (valid login, NameID present, Audience match, valid Conditions window, AuthnStatement present) and 3 negative (wrong credentials, expired session, unknown SP entity). All tests must pass. |

## **Phase 2 Prompt**

|  |
| --- |
| In the existing saml-security-harness project, implement harness/cert\_validator.py. Use the Python cryptography library. It must expose a validate\_cert\_chain(pem\_cert, trusted\_ca\_pem) function that returns a list of Finding objects with fields: severity (CRITICAL/HIGH/MEDIUM/LOW), check\_name, detail, and remediation. Write tests in tests/test\_certificate.py covering: valid cert passes, self-signed raises WARNING, expired cert raises CRITICAL, CN/SAN mismatch raises HIGH, cert expiring within 30 days raises WARNING, and OCSP check using the responses library to mock the OCSP endpoint. Achieve 100% line coverage on cert\_validator.py (enforce with pytest-cov). |

## **Phase 3 Prompt**

|  |
| --- |
| In the existing saml-security-harness project, implement tests/test\_attacks.py. Each test must craft a malformed or malicious SAML assertion using lxml and attempt to submit it to the local SimpleSAMLphp SP via the POST binding endpoint. Tests must cover: (1) XML Signature Wrapping — duplicate the signed assertion, modify the copy, inject it alongside the original; (2) Replay Attack — submit the same valid assertion twice with the same InResponseTo and AssertionID; (3) Missing Signature — strip the ds:Signature element entirely; (4) Expired Conditions — set NotOnOrAfter to one hour in the past; (5) Audience Mismatch — change the Audience element to a different SP entity ID; (6) NameID Injection — set NameID value to a SQL injection payload. Each test asserts that the SP returns a 4xx or an error page. Tag all tests with @pytest.mark.attack. |

## **Phase 4 Prompt**

|  |
| --- |
| In the existing saml-security-harness project, implement harness/report.py. Define a Finding dataclass with fields: id (uuid), test\_name (str), severity (Literal['CRITICAL','HIGH','MEDIUM','LOW','INFO']), status (Literal['PASS','FAIL','WARN']), detail (str), remediation (str). Implement generate\_html\_report(findings: list[Finding], output\_path: str) that produces a self-contained HTML file with severity-colored rows, a summary bar at the top showing counts per severity, and a sortable table. Implement generate\_json\_report(findings: list[Finding], output\_path: str) that writes valid JSON with an ISO timestamp, total counts, and the full findings array. Add a pytest conftest.py hook using pytest\_sessionfinish to auto-call both functions after every test run, writing to reports/report.html and reports/report.json. |

## **Phase 5 Prompt**

|  |
| --- |
| In the existing saml-security-harness project, create .github/workflows/saml\_security.yml. The workflow must: (1) trigger on push to main, any pull\_request, and a weekly cron schedule every Monday at 06:00 UTC; (2) run on ubuntu-latest; (3) steps: checkout, setup Python 3.11, pip install -r requirements.txt, docker-compose up -d, sleep 15 to wait for IdP readiness, pytest --html=reports/report.html --json-report --json-report-file=reports/report.json, upload-artifact with the reports/ directory; (4) on failure, use the GitHub Actions step summary to print any CRITICAL or HIGH findings parsed from reports/report.json. Add the GitHub Actions badge to README.md. |

# **7. Severity Classification Reference**

All test findings must be tagged with one of these severity levels. This taxonomy aligns with CVSS scoring and is understood by security-minded hiring managers.

|  |  |  |  |
| --- | --- | --- | --- |
| **Level** | **Condition** | **SLA** | **Example** |
| **CRITICAL** | Authentication bypass possible | Fix before next deploy | XSW attack accepted by SP |
| **HIGH** | Security control missing or broken | Fix within 48 hours | Unsigned assertion accepted |
| **MEDIUM** | Security degraded but not bypassed | Fix within 2 weeks | Cert expiring in < 30 days |
| **LOW** | Non-blocking configuration issue | Fix in next sprint | Self-signed cert in use |
| **INFO** | Observation, no action required | Track only | Assertion uses SHA-256 |

# **8. Portfolio & Interview Notes**

## **What this project demonstrates**

* Security-aware QA engineering — not just test automation, but threat modeling and attack simulation
* Protocol-level knowledge — SAML, XML signatures, X.509 certificates, SSO flows
* Full-stack test ownership — from local environment setup to CI/CD pipeline
* Documentation discipline — the kind of handoff doc that reflects senior engineering practice

## **How to talk about it in interviews**

* "I built a tool that systematically validates SAML integrations against both spec conformance and known attack vectors — the same class of vulnerabilities that caused real breaches at major companies."
* "It replaced a manual, reactive process with an automated, proactive one. The report output is designed to be readable by a CISO, not just a developer."
* "I designed it to be vendor-agnostic — it can be pointed at any IdP/SP integration, not just ours."

## **Internal pitch to your manager**

* Reduces time spent on vendor cert/SAML triage tickets by providing immediate diagnostic output
* Creates an audit trail of security verification — valuable for SOC 2 or ISO 27001 reviews
* Zero additional tooling cost — runs on any machine with Python and Docker
