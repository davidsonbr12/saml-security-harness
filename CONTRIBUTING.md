# Contributing

## Adding a New Attack Test

Attack tests live in `tests/test_attacks.py`. Each test:

1. Calls `get_sp_flow(username, password)` to obtain a valid signed SAMLResponse and an authenticated session.
2. Parses the XML with `etree.fromstring(xml_bytes)`.
3. Mutates the XML to introduce the attack payload.
4. Re-encodes and POSTs to the SP ACS via `_post_to_sp(session, etree.tostring(root))`.
5. Asserts that `_sp_rejected(response)` is `True`.

Tag every attack test with `@pytest.mark.attack`.

```python
@pytest.mark.attack
def test_your_attack(idp_container):
    xml_bytes, session = get_sp_flow("user1", "password1")
    root = etree.fromstring(xml_bytes)

    # --- mutate root here ---

    response = _post_to_sp(session, etree.tostring(root))
    assert _sp_rejected(response), "SP accepted <describe the attack>"
```

If the SP is **expected to fail** (i.e., you are documenting a known vulnerability rather than a passing defense), mark the test as `xfail`:

```python
@pytest.mark.attack
@pytest.mark.xfail(
    strict=True,
    reason="FINDING [HIGH]: <describe the vulnerability and remediation>",
)
def test_known_vulnerability(idp_container):
    ...
```

`strict=True` means the suite will fail if the SP unexpectedly starts rejecting the attack — which is the signal to remove the `xfail` marker and close the finding.

---

## Adding a New Certificate Test

Certificate tests live in `tests/test_certificate.py`. Use the `_make_cert` helper to build test certificates signed by the shared `ca` fixture, then call `validate_cert_chain(pem_cert, pem_ca)` and assert on the returned `Finding` list.

```python
def test_your_cert_check(ca):
    ca_cert, ca_key = ca
    cert, _ = _make_cert("localhost", ca_cert, ca_key, <options>)
    findings = validate_cert_chain(_pem(cert), _pem(ca_cert), <options>)
    assert any(f.check_name == "your_check_name" and f.severity == "HIGH" for f in findings)
```

`_make_cert` accepts:
- `cn` — Common Name string
- `ca_cert`, `ca_key` — issuing CA (use the `ca` fixture)
- `not_before`, `not_after` — `datetime` objects (default: now, now+365d)
- `san` — DNS name string to add as a SAN extension
- `ocsp_url` — URL string to embed in the AIA extension

After adding tests, verify coverage stays at 100%:

```bash
pytest --cov=harness.cert_validator --cov-report=term-missing tests/test_certificate.py
```

---

## Finding Schema Reference

`harness/report.py` defines `ReportFinding`:

| Field | Type | Values |
|-------|------|--------|
| `id` | `str` | UUID, auto-generated |
| `test_name` | `str` | pytest node ID (e.g. `tests/test_attacks.py::test_missing_signature`) |
| `severity` | `str` | `CRITICAL` \| `HIGH` \| `MEDIUM` \| `LOW` \| `INFO` |
| `status` | `str` | `PASS` \| `FAIL` \| `WARN` |
| `detail` | `str` | Human-readable description of what was observed |
| `remediation` | `str` | Recommended fix or next action |

Findings are collected automatically by the `pytest_runtest_logreport` hook in `tests/conftest.py` — you do not need to instantiate them manually in tests. The hook maps pytest outcomes to severity/status as follows:

| Pytest outcome | Status | Severity |
|----------------|--------|----------|
| Passed | PASS | INFO |
| Passed (attack test) | PASS | INFO |
| xfail (expected failure) | WARN | HIGH |
| xpass (unexpected pass on xfail test) | PASS | INFO |
| Failed (attack test) | FAIL | HIGH |
| Failed (other) | FAIL | MEDIUM |
