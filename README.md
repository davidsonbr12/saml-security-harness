# SAML/SSO Security Test Harness

A security testing harness for SAML 2.0 Identity Providers. Simulates real attack vectors — XML Signature Wrapping, assertion replay, signature bypass, and more — against a local SimpleSAMLphp IdP running in Docker.

Built as a portfolio project for Security QA Engineering.

## Project Phases

| Phase | Focus | Status |
|-------|-------|--------|
| 1 | Environment setup, Docker IdP, baseline login tests | Complete |
| 2 | SAML assertion validation (NameID, Audience, Conditions) | In Progress |
| 3 | Attack simulations (XSW, replay, signature bypass) | Planned |
| 4 | Certificate and cryptography tests | Planned |
| 5 | Edge cases and error handling | Planned |
| 6 | Reporting and CI integration | Planned |

## Prerequisites

- Python 3.11+
- Docker Desktop
- `docker-compose` (installed via Homebrew: `brew install docker-compose`)

## Setup

```bash
# Clone the repo
git clone https://github.com/davidsonbr12/saml-security-harness.git
cd saml-security-harness

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Build the Docker IdP image (required before first test run)
docker-compose build
```

## Running Tests

```bash
# Run all tests (starts and stops the IdP container automatically)
pytest -v

# Run with stdout output visible
pytest -v -s

# Run only attack simulation tests
pytest -v -m attack
```

The test fixture in `tests/conftest.py` manages the Docker container lifecycle — it starts the IdP before the session and tears it down after.

## Project Structure

```
saml-security-harness/
├── docker/
│   └── idp/
│       ├── Dockerfile          # Native ARM64 SimpleSAMLphp 2.5 image
│       ├── config/
│       │   ├── config.php      # SSP core configuration
│       │   └── authsources.php # Test user credentials
│       └── metadata/
│           ├── saml20-idp-hosted.php  # IdP metadata
│           └── saml20-sp-remote.php   # Registered SP
├── harness/
│   ├── client.py       # HTTP session driver for SAML login flows
│   ├── parser.py       # SAML assertion parsing utilities
│   └── cert_validator.py  # Certificate inspection helpers
├── tests/
│   ├── conftest.py         # Docker fixture (session-scoped)
│   ├── test_assertion.py   # Baseline login and assertion tests
│   ├── test_attacks.py     # Attack simulation tests
│   ├── test_certificate.py # Certificate and crypto tests
│   └── test_flows.py       # Edge case flow tests
├── reports/            # HTML test reports (gitignored)
├── docker-compose.yml
├── pytest.ini
└── requirements.txt
```

## IdP Test Credentials

| Username | Password |
|----------|----------|
| user1 | password1 |
| user2 | password2 |

Admin password: `testpassword`

The IdP runs at `http://localhost:8080/simplesaml` when the container is up.

## Architecture Notes

The Docker image uses `php:8.3-apache` as a native ARM64 base (required on Apple Silicon — pre-built SimpleSAMLphp images run under QEMU and fail with connection resets). SimpleSAMLphp 2.5 is installed via Composer at build time.

`session.cookie.secure` is disabled in the SSP config so that Python's `requests` library can send session cookies over HTTP during testing. In a production environment this would always be `true`.
