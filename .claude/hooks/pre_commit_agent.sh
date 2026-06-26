#!/usr/bin/env bash
# Pre-commit verification agent for saml-security-harness.
# Fires on every Bash tool call. Exits 0 (allow) for anything that isn't
# a git commit. For commits, gathers project context and asks a Claude
# agent to approve or block.

set -euo pipefail

PROJECT_ROOT="/Users/briandavidson/workspaces/saml-security-harness"

# ── 1. Read the tool input and check if this is a git commit ─────────────────

INPUT=$(cat)
COMMAND=$(echo "$INPUT" | python3 -c "import sys, json; print(json.load(sys.stdin).get('command', ''))" 2>/dev/null || echo "")

if ! echo "$COMMAND" | grep -qE "git\s+commit"; then
    exit 0
fi

echo "🔍 Pre-commit agent running..." >&2

# ── 2. Gather context ─────────────────────────────────────────────────────────

cd "$PROJECT_ROOT"

GIT_DIFF=$(git diff --staged 2>/dev/null | head -200)
GIT_STATUS=$(git status --short 2>/dev/null)

# Run fast tests only (cert tests don't need Docker)
FAST_TEST_OUTPUT=$(
    source .venv/bin/activate 2>/dev/null
    python -m pytest tests/test_certificate.py -q --tb=short 2>&1 | tail -20
)

# Count total tests collected across all files
TOTAL_TESTS=$(
    source .venv/bin/activate 2>/dev/null
    python -m pytest --collect-only -q 2>&1 | tail -3
)

# Phase status from README
PHASE_TABLE=$(grep -A8 "## Project Phases" README.md 2>/dev/null || echo "not found")

# ── 3. Call the Claude agent ──────────────────────────────────────────────────

PROMPT="You are a pre-commit verification agent for a SAML security test harness project.
Your job is to review what is about to be committed and decide whether it is safe to proceed.

## Project context
This is a Python/pytest security testing project that validates SAML 2.0 implementations.
It has 6 development phases. The team commits frequently as phases are completed.

## Current phase status
$PHASE_TABLE

## What is being committed (git diff --staged, truncated to 200 lines)
$GIT_DIFF

## Git status
$GIT_STATUS

## Fast test results (test_certificate.py — no Docker required)
$FAST_TEST_OUTPUT

## Test collection summary (all test files)
$TOTAL_TESTS

## Your task
Review the above and output ONE of the following verdicts on the first line:
  APPROVED
  BLOCKED

Then on the next lines give a 2-4 sentence explanation covering:
- Whether the staged changes look coherent and intentional
- Whether the fast tests passed
- Any concerns about missing tests, broken imports, or phase mismatches
- One specific thing done well

Be direct. This output is shown to the developer before the commit proceeds."

AGENT_OUTPUT=$(claude -p "$PROMPT" --output-format text 2>/dev/null)

# ── 4. Parse verdict and exit ─────────────────────────────────────────────────

echo "" >&2
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >&2
echo "  Pre-commit agent verdict" >&2
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >&2
echo "$AGENT_OUTPUT" >&2
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >&2
echo "" >&2

if echo "$AGENT_OUTPUT" | head -1 | grep -qi "^APPROVED"; then
    exit 0
else
    exit 1
fi
