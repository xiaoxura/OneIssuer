#!/usr/bin/env python3
"""Validate the reviewable, secret-free Phase 3 and Phase 4 records."""

from __future__ import annotations

import hashlib
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
BASE = ROOT / "conformance" / "phase-3"
MATRIX = BASE / "matrix.json"
RESULT = BASE / "results" / "2026-08-01.json"
EXPECTED_RELEASE = "release-v5.2.1"
EXPECTED_COMMIT = "932b46f1e507871eb0b34621aaef65ff04442e6f"
EXPECTED_MODULES = [
    ("oidcc-discovery-endpoint-verification", "none"),
    ("oidcc-ensure-request-with-valid-pkce-succeeds", "none"),
    ("oidcc-ensure-request-with-valid-pkce-succeeds", "client_secret_basic"),
]
OPAQUE_CREDENTIAL = re.compile(
    r"(?<![A-Za-z0-9_-])"
    r"(?:ois_sec_v1_|s1_|p1_|c1_|t1_|r1_|lt1_|lc1_)"
    r"[A-Za-z0-9_-]{43}"
    r"(?![A-Za-z0-9_-])"
)


def load(path: pathlib.Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SystemExit(f"invalid conformance JSON {path.relative_to(ROOT)}: {error}")
    if not isinstance(value, dict):
        raise SystemExit(f"conformance record is not an object: {path.relative_to(ROOT)}")
    return value


matrix = load(MATRIX)
result = load(RESULT)
for document, name in ((matrix, "matrix"), (result, "result")):
    suite = document.get("suite")
    if not isinstance(suite, dict) or suite.get("release") != EXPECTED_RELEASE or suite.get("source_commit") != EXPECTED_COMMIT:
        raise SystemExit(f"{name} does not pin the reviewed suite release and source commit")
    if suite.get("plan") != "oidcc-test-plan":
        raise SystemExit(f"{name} must use the non-certification oidcc-test-plan")

selected = [
    (entry.get("test_module"), entry.get("client_auth_type"))
    for entry in matrix.get("applicable_modules", [])
]
if selected != EXPECTED_MODULES:
    raise SystemExit(f"applicable module matrix drifted: {selected!r}")

records = result.get("results")
if not isinstance(records, list) or len(records) != len(EXPECTED_MODULES):
    raise SystemExit("result record must contain exactly three applicable module runs")
for entry, expected in zip(records, EXPECTED_MODULES, strict=True):
    actual = (entry.get("test_module"), entry.get("variants", {}).get("client_auth_type"))
    if actual != expected or entry.get("result") != "PASSED":
        raise SystemExit(f"applicable conformance module is not recorded as passed: {actual!r}")
    if not re.fullmatch(r"[A-Za-z0-9]{15}", str(entry.get("module_id", ""))):
        raise SystemExit("conformance module id is malformed")
    digest = str(entry.get("raw_export_sha256", ""))
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise SystemExit("raw conformance export digest is malformed")
    artifact = str(entry.get("raw_export", ""))
    if not artifact.startswith(".artifacts/conformance/") or not artifact.endswith(".zip"):
        raise SystemExit("raw conformance export must remain in the ignored artifact area")

if result.get("certification_claim") is not False or matrix.get("certification_plan", {}).get("applicable") is not False:
    raise SystemExit("phase three must not claim or imply OpenID certification")

for relative in result.get("configuration_templates", []):
    path = ROOT / relative
    template = path.read_text(encoding="utf-8")
    if "<runtime-" not in template and "<unique-" not in template:
        raise SystemExit(f"configuration template lacks runtime placeholders: {relative}")
    if OPAQUE_CREDENTIAL.search(template):
        raise SystemExit(f"configuration template contains a secret-shaped value: {relative}")

# Make accidental replacement of the reviewed files visible in CI diagnostics.
for path in (MATRIX, RESULT):
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    print(f"conformance record valid: {path.relative_to(ROOT)} sha256:{digest}")


# Phase four intentionally starts with a secret-free, NOT_RUN evidence record.
# Keeping the matrix in the same contract gate prevents a later external-suite
# update from silently changing the applicable client-auth or certification
# boundary.
PHASE4_BASE = ROOT / "conformance" / "phase-4"
PHASE4_MATRIX = PHASE4_BASE / "matrix.json"
PHASE4_RESULT = PHASE4_BASE / "results" / "2026-08-03.json"
PHASE4_MODULES = [
    ("oidcc-refresh-token-rotation", "none"),
    ("oidcc-refresh-token-rotation", "client_secret_basic"),
    ("oidcc-rp-initiated-logout", "none"),
]
phase4_matrix = load(PHASE4_MATRIX)
phase4_result = load(PHASE4_RESULT)
for document, name in ((phase4_matrix, "phase-four matrix"), (phase4_result, "phase-four result")):
    suite = document.get("suite")
    if not isinstance(suite, dict) or suite.get("release") != EXPECTED_RELEASE or suite.get("source_commit") != "working-tree-phase4" or suite.get("plan") != "oidcc-test-plan":
        raise SystemExit(f"{name} does not pin the reviewed phase-four suite boundary")
selected4 = [(entry.get("test_module"), entry.get("client_auth_type")) for entry in phase4_matrix.get("applicable_modules", [])]
if selected4 != PHASE4_MODULES:
    raise SystemExit(f"phase-four applicable module matrix drifted: {selected4!r}")
records4 = phase4_result.get("results")
if not isinstance(records4, list) or [(entry.get("test_module"), entry.get("variants", {}).get("client_auth_type")) for entry in records4] != PHASE4_MODULES:
    raise SystemExit("phase-four result modules do not match the applicable matrix")
if any(entry.get("result") != "NOT_RUN" for entry in records4) or phase4_result.get("certification_claim") is not False:
    raise SystemExit("phase-four scaffold must remain explicitly pending and non-certifying")
for relative in phase4_result.get("configuration_templates", []):
    path = ROOT / relative
    template = path.read_text(encoding="utf-8")
    if "<runtime-" not in template and "<unique-" not in template:
        raise SystemExit(f"phase-four configuration template lacks runtime placeholders: {relative}")
    if OPAQUE_CREDENTIAL.search(template):
        raise SystemExit(f"phase-four configuration template contains a secret-shaped value: {relative}")
for path in (PHASE4_MATRIX, PHASE4_RESULT):
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    print(f"conformance record valid: {path.relative_to(ROOT)} sha256:{digest}")
