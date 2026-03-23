#!/usr/bin/env python3
"""Export app IOC lists from YAML catalog entries."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from app_control.catalog import APPS_DIR, EXPORTABLE_IOC_FIELDS, load_apps, meets_min_status


def clean_group(group: dict[str, Any] | None) -> dict[str, Any] | None:
    if not group:
        return None

    cleaned: dict[str, Any] = {}
    for key in EXPORTABLE_IOC_FIELDS:
        value = group.get(key)
        if value:
            cleaned[key] = value
    return cleaned


def matches_review_state(app: dict[str, Any], review_state: str | None) -> bool:
    if review_state is None:
        return True

    iocs = app.get("iocs", {})
    network_status = (iocs.get("network") or {}).get("status")
    host_status = (iocs.get("host") or {}).get("status")
    network_reviewed = meets_min_status(network_status, "reviewed")
    host_reviewed = meets_min_status(host_status, "reviewed")

    if review_state == "any-reviewed":
        return network_reviewed or host_reviewed
    if review_state == "both-reviewed":
        return network_reviewed and host_reviewed
    if review_state == "none-reviewed":
        return not network_reviewed and not host_reviewed

    raise ValueError(f"Unsupported review_state: {review_state}")


def build_export(apps: list[dict[str, Any]], review_state: str | None = None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for app in apps:
        if not matches_review_state(app, review_state):
            continue
        iocs = app.get("iocs", {})
        rows.append(
            {
                "id": app["id"],
                "name": app["name"],
                "category": app["category"],
                "severity": app["severity"],
                "priority_score": app["priority_score"],
                "network": clean_group(iocs.get("network")),
                "host": clean_group(iocs.get("host")),
            }
        )
    return rows


def render_markdown(
    apps: list[dict[str, Any]],
    category: str | None = None,
    review_state: str | None = None,
) -> str:
    title = f"{category} IOC List" if category else "App IOC List"
    lines: list[str] = []
    lines.append(f"# {title}")
    lines.append("")
    lines.append(f"Generated from `{APPS_DIR}`.")
    lines.append("")
    if review_state:
        lines.append(f"Review state filter: `{review_state}`")
        lines.append("")
    lines.append(f"Apps included: {len(apps)}")
    lines.append("")

    for app in apps:
        lines.append(f"## {app['name']} (`{app['id']}`)")
        lines.append("")
        lines.append(
            f"- Category: `{app['category']}` | Severity: `{app['severity']}` | Priority: `{app['priority_score']}`"
        )

        network = app.get("network") or {}
        if network:
            provenance = network.get("provenance", {})
            lines.append(f"- Network status: `{network.get('status', 'draft')}`")
            if provenance:
                lines.append(f"- Network provenance: `{provenance.get('url', '')}`")
            hostnames = network.get("hostname_patterns") or []
            keywords = network.get("keyword_patterns") or []
            if hostnames:
                lines.append("- Network hostname patterns:")
                for item in hostnames:
                    lines.append(f"  - `{item['pattern']}` ({item['match']}, {item['role']})")
            if keywords:
                lines.append("- Network keyword patterns:")
                for item in keywords:
                    lines.append(f"  - `{item['pattern']}` ({item['match']})")

        host = app.get("host") or {}
        if host:
            provenance = host.get("provenance", {})
            lines.append(f"- Host status: `{host.get('status', 'draft')}`")
            if provenance:
                lines.append(f"- Host provenance: `{provenance.get('url', '')}`")

            for key, label in (
                ("paths", "Host paths"),
                ("bundle_ids", "Bundle IDs"),
                ("process_names", "Process names"),
                ("team_ids", "Team IDs"),
                ("chrome_extension_ids", "Chrome extension IDs"),
                ("safari_extension_bundle_ids", "Safari extension bundle IDs"),
            ):
                values = host.get(key) or []
                if not values:
                    continue
                lines.append(f"- {label}:")
                for value in values:
                    lines.append(f"  - `{value}`")

        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def render_json(apps: list[dict[str, Any]]) -> str:
    return json.dumps(apps, ensure_ascii=False, indent=2) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="Export IOC list from app YAML files")
    parser.add_argument(
        "--category",
        default=None,
        help="Only include apps in the given category (for example CLAW_FAMILY_APP)",
    )
    parser.add_argument(
        "--format",
        default="markdown",
        choices=("markdown", "json"),
        help="Output format",
    )
    parser.add_argument(
        "--review-state",
        default=None,
        choices=("any-reviewed", "both-reviewed", "none-reviewed"),
        help="Filter apps by reviewed IOC coverage across network/host groups",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Write output to this file path",
    )
    args = parser.parse_args()

    apps = build_export(load_apps(args.category), args.review_state)
    output = (
        render_markdown(apps, args.category, args.review_state)
        if args.format == "markdown"
        else render_json(apps)
    )

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(output, encoding="utf-8")


if __name__ == "__main__":
    main()
