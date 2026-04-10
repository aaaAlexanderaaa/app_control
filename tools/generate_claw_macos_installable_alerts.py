#!/usr/bin/env python3
"""Generate ES|QL and host scan artifacts for macOS-installable CLAW apps."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
from typing import Any

from app_control.catalog import HOST_VALUE_FIELDS, get_ioc_group, load_apps, meets_min_status
from generators.esql_rules import NetworkIOCConflictError, generate_esql
from generators.jamf_scan import generate_scan_script

OUTPUT_PREFIX = "claw_macos_installable"
FILTER_LABEL = "CLAW_FAMILY_APP_MACOS_INSTALLABLE"


def status_suffix(min_status: str) -> str:
    if min_status == "validated":
        return ""
    if min_status == "reviewed":
        return "_canary"
    return "_draft"


def write_text(path: Path, content: str, executable: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    if executable:
        os.chmod(path, 0o755)


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


def classify_skip_reason(app: dict[str, Any], min_status: str) -> str | None:
    if app.get("category") != "CLAW_FAMILY_APP":
        return "outside CLAW_FAMILY_APP"

    if "macos" not in (app.get("product_shape") or []):
        return "hosted-only, mobile-only, or non-macOS surface"

    host = get_ioc_group(app, "host")
    if not host or not meets_min_status(host.get("status"), min_status):
        return f"host IOC below {min_status} threshold"

    if not host_group_has_values(host):
        return "no host IOC values"

    if not has_explicit_macos_install_signal(host):
        return "no clear macOS installation surface"

    return None


def load_installable_claw_apps(min_status: str) -> tuple[list[dict[str, Any]], list[tuple[str, str]]]:
    included: list[dict[str, Any]] = []
    skipped: list[tuple[str, str]] = []

    for app in load_apps("CLAW_FAMILY_APP"):
        reason = classify_skip_reason(app, min_status)
        if reason is None:
            included.append(app)
        else:
            skipped.append((app["id"], reason))

    return included, skipped


def filter_group_apps(apps: list[dict[str, Any]], group: str, min_status: str) -> list[dict[str, Any]]:
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


def render_manifest(
    included: list[dict[str, Any]],
    skipped: list[tuple[str, str]],
    min_status: str,
) -> str:
    lines = [
        f"Included CLAW_FAMILY_APP entries with explicit macOS installation evidence at IOC status >= {min_status}",
        "(desktop app, App Store bundle, Homebrew/CLI install path, launchd artifact, or source-backed local runtime on macOS):",
    ]
    for app in included:
        lines.append(f"- {app['id']}")

    lines.append("")
    lines.append("Skipped CLAW_FAMILY_APP entries:")
    for app_id, reason in skipped:
        lines.append(f"- {app_id}: {reason}")

    return "\n".join(lines) + "\n"


def generate_artifacts(min_status: str, output_dir: Path) -> dict[str, Any]:
    included, skipped = load_installable_claw_apps(min_status)
    network_apps = filter_group_apps(included, "network", min_status)
    host_apps = filter_group_apps(included, "host", min_status)
    suffix = status_suffix(min_status)

    network_path = output_dir / f"{OUTPUT_PREFIX}_network_rules{suffix}.esql"
    host_path = output_dir / f"{OUTPUT_PREFIX}_host_scan{suffix}.sh"
    manifest_path = output_dir / f"{OUTPUT_PREFIX}_manifest.txt"

    write_text(network_path, generate_esql(network_apps, min_status, FILTER_LABEL))
    write_text(
        host_path,
        generate_scan_script(
            host_apps,
            min_status,
            FILTER_LABEL,
            output_mode="jamf_ea",
            include_inventory=False,
        ),
        executable=True,
    )
    write_text(manifest_path, render_manifest(included, skipped, min_status))

    return {
        "included": included,
        "skipped": skipped,
        "network_apps": network_apps,
        "host_apps": host_apps,
        "network_path": network_path,
        "host_path": host_path,
        "manifest_path": manifest_path,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate ES|QL and host scan artifacts for macOS-installable CLAW apps"
    )
    parser.add_argument(
        "--min-status",
        default="reviewed",
        choices=["draft", "reviewed", "validated"],
        help="Minimum IOC status to include (default: reviewed)",
    )
    parser.add_argument(
        "--output-dir",
        default="output",
        help="Directory to write generated artifacts into (default: output)",
    )
    args = parser.parse_args()

    try:
        result = generate_artifacts(args.min_status, Path(args.output_dir))
    except NetworkIOCConflictError as exc:
        raise SystemExit(f"ERROR: {exc}")
    print(
        " | ".join(
            [
                FILTER_LABEL,
                f"included={len(result['included'])}",
                f"network={len(result['network_apps'])} -> {result['network_path']}",
                f"host={len(result['host_apps'])} -> {result['host_path']}",
                f"manifest={result['manifest_path']}",
            ]
        )
    )


if __name__ == "__main__":
    main()
