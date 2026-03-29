"""Reusable cohort-selection helpers for targeted alert generation."""

from __future__ import annotations

from typing import Any

from app_control.catalog import HOST_VALUE_FIELDS, get_ioc_group, load_apps, meets_min_status

HIGH_RISK_SEVERITIES = {"high", "critical"}


def host_group_has_values(host: dict[str, Any]) -> bool:
    return any(host.get(field) for field in HOST_VALUE_FIELDS)


def network_group_has_values(network: dict[str, Any]) -> bool:
    return bool(network.get("hostname_patterns") or network.get("keyword_patterns"))


def has_explicit_macos_install_signal(host: dict[str, Any]) -> bool:
    if any(
        host.get(field)
        for field in (
            "bundle_ids",
            "process_names",
            "team_ids",
            "chrome_extension_ids",
            "safari_extension_bundle_ids",
        )
    ):
        return True

    for path in host.get("paths", []):
        if path.startswith(("/", "~/", "$HOME/", "${HOME}/")):
            return True

    return False


def classify_claw_macos_installable_skip_reason(app: dict[str, Any], min_status: str) -> str | None:
    if app.get("category") != "CLAW_FAMILY_APP":
        return "outside CLAW_FAMILY_APP"

    if "macos" not in (app.get("product_shape") or []):
        return "hosted-only, mobile-only, or non-macOS surface"

    host = get_ioc_group(app, "host") or {}
    if not meets_min_status(host.get("status"), min_status):
        return f"host IOC below {min_status} threshold"

    if not host_group_has_values(host):
        return "no host IOC values"

    if not has_explicit_macos_install_signal(host):
        return "no clear macOS installation surface"

    return None


def load_claw_macos_installable_apps(min_status: str) -> tuple[list[dict[str, Any]], list[tuple[str, str]]]:
    included: list[dict[str, Any]] = []
    skipped: list[tuple[str, str]] = []

    for app in load_apps("CLAW_FAMILY_APP"):
        reason = classify_claw_macos_installable_skip_reason(app, min_status)
        if reason is None:
            included.append(app)
        else:
            skipped.append((app["id"], reason))

    return included, skipped


def load_high_risk_apps_excluding(exclude_ids: set[str] | None = None) -> list[dict[str, Any]]:
    excluded = exclude_ids or set()
    return [
        app
        for app in load_apps()
        if app.get("severity") in HIGH_RISK_SEVERITIES and app.get("id") not in excluded
    ]


def filter_apps_with_ready_group(apps: list[dict[str, Any]], group: str, min_status: str) -> list[dict[str, Any]]:
    filtered: list[dict[str, Any]] = []
    for app in apps:
        group_data = get_ioc_group(app, group)
        if not group_data or not meets_min_status(group_data.get("status"), min_status):
            continue
        if group == "network" and not network_group_has_values(group_data):
            continue
        if group == "host" and not host_group_has_values(group_data):
            continue
        filtered.append(app)
    return filtered
