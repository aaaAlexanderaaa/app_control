#!/usr/bin/env python3
"""Validate all app YAML files against the frozen schema rules."""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

from app_control.catalog import (
    APPS_DIR,
    REQUIRED_TOP_FIELDS,
    VALID_CATEGORIES,
    VALID_HOST_MATCH,
    VALID_IOC_STATUSES,
    VALID_KW_MATCH,
    VALID_NET_ROLES,
    VALID_SEVERITIES,
    VALID_SHAPES,
    iter_app_paths,
    load_app,
)


def validate_provenance(prov: dict, path: str, status: str) -> list[str]:
    errors = []
    if not isinstance(prov, dict):
        return [f"{path}: provenance must be a dict"]
    if status in ("reviewed", "validated") and not prov.get("url"):
        errors.append(f"{path}: status is '{status}' but provenance.url is empty")
    if not prov.get("evidence"):
        errors.append(f"{path}: provenance.evidence is empty or missing")
    if not prov.get("checked_at"):
        errors.append(f"{path}: provenance.checked_at is missing")
    return errors


def validate_network(net: dict, filepath: str) -> list[str]:
    errors = []
    ctx = f"{filepath} iocs.network"

    status = net.get("status")
    if status not in VALID_IOC_STATUSES:
        errors.append(f"{ctx}: invalid status '{status}'")

    if "provenance" in net:
        errors.extend(validate_provenance(net["provenance"], ctx, status or ""))
    else:
        errors.append(f"{ctx}: missing provenance")

    for index, hp in enumerate(net.get("hostname_patterns", [])):
        if not hp.get("pattern"):
            errors.append(f"{ctx}.hostname_patterns[{index}]: empty pattern")
        if hp.get("match") not in VALID_HOST_MATCH:
            errors.append(f"{ctx}.hostname_patterns[{index}]: invalid match '{hp.get('match')}'")
        if hp.get("role") not in VALID_NET_ROLES:
            errors.append(f"{ctx}.hostname_patterns[{index}]: invalid role '{hp.get('role')}'")

    for index, kp in enumerate(net.get("keyword_patterns", [])):
        if not kp.get("pattern"):
            errors.append(f"{ctx}.keyword_patterns[{index}]: empty pattern")
        if kp.get("match") not in VALID_KW_MATCH:
            errors.append(f"{ctx}.keyword_patterns[{index}]: invalid match '{kp.get('match')}'")

    return errors


def validate_host(host: dict, filepath: str) -> list[str]:
    errors = []
    ctx = f"{filepath} iocs.host"

    status = host.get("status")
    if status not in VALID_IOC_STATUSES:
        errors.append(f"{ctx}: invalid status '{status}'")

    if "provenance" in host:
        errors.extend(validate_provenance(host["provenance"], ctx, status or ""))
    else:
        errors.append(f"{ctx}: missing provenance")

    for field in (
        "paths",
        "bundle_ids",
        "process_names",
        "team_ids",
        "chrome_extension_ids",
        "safari_extension_bundle_ids",
    ):
        value = host.get(field)
        if value is not None and not isinstance(value, list):
            errors.append(f"{ctx}.{field}: must be a list")

    return errors


def validate_app(filepath: Path) -> list[str]:
    errors = []
    filename = filepath.name

    try:
        data = load_app(filepath)
    except yaml.YAMLError as exc:
        return [f"{filename}: YAML parse error: {exc}"]

    if not isinstance(data, dict):
        return [f"{filename}: root must be a mapping"]

    missing = REQUIRED_TOP_FIELDS - set(data.keys())
    if missing:
        errors.append(f"{filename}: missing required fields: {', '.join(sorted(missing))}")

    expected_id = filepath.stem
    if data.get("id") != expected_id:
        errors.append(f"{filename}: id '{data.get('id')}' does not match filename '{expected_id}'")

    if data.get("category") not in VALID_CATEGORIES:
        errors.append(f"{filename}: invalid category '{data.get('category')}'")

    shapes = data.get("product_shape", [])
    if not isinstance(shapes, list) or not shapes:
        errors.append(f"{filename}: product_shape must be a non-empty list")
    else:
        for shape in shapes:
            if shape not in VALID_SHAPES:
                errors.append(f"{filename}: invalid product_shape '{shape}'")

    if data.get("severity") not in VALID_SEVERITIES:
        errors.append(f"{filename}: invalid severity '{data.get('severity')}'")

    priority_score = data.get("priority_score")
    if not isinstance(priority_score, (int, float)) or priority_score < 0 or priority_score > 100:
        errors.append(f"{filename}: priority_score must be 0-100, got '{priority_score}'")

    iocs = data.get("iocs")
    if not isinstance(iocs, dict):
        errors.append(f"{filename}: iocs must be a mapping")
        return errors

    if "network" in iocs:
        errors.extend(validate_network(iocs["network"], filename))

    if "host" in iocs:
        errors.extend(validate_host(iocs["host"], filename))

    if "network" not in iocs and "host" not in iocs:
        errors.append(f"{filename}: iocs has neither network nor host group")

    return errors


def main() -> int:
    if not APPS_DIR.is_dir():
        print(f"ERROR: {APPS_DIR} does not exist")
        return 1

    files = iter_app_paths()
    if not files:
        print(f"ERROR: no YAML files in {APPS_DIR}")
        return 1

    total_errors = 0
    for filepath in files:
        errors = validate_app(filepath)
        for error in errors:
            print(f"  ERROR: {error}")
        total_errors += len(errors)

    print(f"\nValidated {len(files)} files, {total_errors} error(s)")
    return 1 if total_errors > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
