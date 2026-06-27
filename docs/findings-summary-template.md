# SAML Security Test — Findings Summary

**Prepared by:** [Your name]
**Date:** [YYYY-MM-DD]
**System tested:** [IdP name / vendor / version]
**Test suite version:** [git SHA or tag]

---

## What Was Tested

We ran an automated security test suite against the SAML single sign-on integration. The suite checks three areas:

1. **Baseline correctness** — Does a valid login produce a well-formed, properly signed assertion?
2. **Certificate health** — Is the IdP certificate valid, trusted, unexpired, and bound to the correct hostname?
3. **Attack resistance** — Does the system correctly reject known SAML attack techniques?

The tests ran against a live IdP endpoint. Results are objective — each test either passes or fails based on the system's actual response.

---

## Summary

| Area | Tests Run | Passed | Issues Found |
|------|-----------|--------|--------------|
| Baseline login flow | [N] | [N] | [N] |
| Certificate validation | [N] | [N] | [N] |
| Attack simulation | [N] | [N] | [N] |
| **Total** | **[N]** | **[N]** | **[N]** |

> The full machine-readable report is in `reports/report.json`. The HTML version is in `reports/report.html`.

---

## Issues Requiring Action

List each FAIL or WARN finding here. Delete this section if there are none.

### [CRITICAL / HIGH / MEDIUM] — [Short title]

**What it means in plain English:**
[One or two sentences a non-technical manager can understand. Example: "An attacker who intercepts a valid login session can reuse it to log in again as that user, even after the session should have expired."]

**How we found it:**
[Brief description of the test. Example: "We submitted the same login token twice. The second submission was accepted rather than rejected."]

**Recommended fix:**
[One sentence. Example: "Enable assertion ID tracking in the IdP configuration so that each login token can only be used once."]

**Owner / ticket:** [Name or link]
**Target fix date:** [Date]

---

## What Passed

The following protections are confirmed working:

- [ ] Login requires a valid signed assertion — unsigned submissions are rejected
- [ ] Expired assertions are rejected — time-window enforcement is active
- [ ] Assertions intended for other systems are rejected — audience restriction works
- [ ] Tampered assertions are rejected — signature covers the NameID field
- [ ] XML Signature Wrapping is blocked — only the signed assertion is processed
- [ ] IdP certificate is valid and trusted
- [ ] Certificate hostname matches the IdP endpoint
- [ ] Certificate is not expiring within 30 days

---

## Next Steps

- [ ] Assign each issue above to an owner with a target date
- [ ] Re-run the test suite after fixes are deployed to verify closure
- [ ] Schedule next routine test run: [date or cadence]

---

*This summary was generated from the SAML Security Test Harness. For technical details, see `reports/report.html` or contact the Security QA team.*
