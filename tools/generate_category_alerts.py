#!/usr/bin/env python3
"""Generate per-category ES|QL and host alert artifacts."""

from __future__ import annotations

import argparse
import os
from collections import defaultdict
from pathlib import Path

from app_control.catalog import VALID_CATEGORIES, category_slug, filter_apps_with_ioc_group
from generators.esql_rules import generate_esql
from generators.jamf_scan import generate_scan_script


def status_suffix(min_status: str) -> str:
    if min_status == "validated":
        return ""
    if min_status == "reviewed":
        return "_canary"
    return "_draft"


def iter_categories(category: str | None = None) -> list[str]:
    if category is None:
        return sorted(VALID_CATEGORIES)
    if category not in VALID_CATEGORIES:
        valid = ", ".join(sorted(VALID_CATEGORIES))
        raise SystemExit(f"Unknown category '{category}'. Valid categories: {valid}")
    return [category]


def write_text(path: Path, content: str, executable: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    if executable:
        os.chmod(path, 0o755)


def generate_category_artifacts(
    min_status: str,
    output_dir: Path,
    category: str | None = None,
) -> list[dict[str, object]]:
    generated: list[dict[str, object]] = []
    suffix = status_suffix(min_status)
    network_by_category: dict[str, list[dict]] = defaultdict(list)
    host_by_category: dict[str, list[dict]] = defaultdict(list)

    for app in filter_apps_with_ioc_group("network", min_status=min_status):
        network_by_category[app["category"]].append(app)

    for app in filter_apps_with_ioc_group("host", min_status=min_status):
        host_by_category[app["category"]].append(app)

    for current_category in iter_categories(category):
        network_apps = network_by_category.get(current_category, [])
        host_apps = host_by_category.get(current_category, [])
        if not network_apps and not host_apps:
            continue

        slug = category_slug(current_category)
        network_path = output_dir / f"{slug}_network_rules{suffix}.esql"
        host_path = output_dir / f"{slug}_host_scan{suffix}.sh"

        if network_apps:
            write_text(
                network_path,
                generate_esql(network_apps, min_status, current_category),
            )

        if host_apps:
            write_text(
                host_path,
                generate_scan_script(host_apps, min_status, current_category, include_inventory=False),
                executable=True,
            )

        generated.append(
            {
                "category": current_category,
                "network_apps": len(network_apps),
                "host_apps": len(host_apps),
                "network_path": str(network_path) if network_apps else None,
                "host_path": str(host_path) if host_apps else None,
            }
        )

    return generated


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate per-category ES|QL and host alert artifacts")
    parser.add_argument(
        "--min-status",
        default="validated",
        choices=["draft", "reviewed", "validated"],
        help="Minimum IOC status to include (default: validated)",
    )
    parser.add_argument(
        "--category",
        default=None,
        help="Only generate artifacts for the given category",
    )
    parser.add_argument(
        "--output-dir",
        default="output",
        help="Directory to write generated artifacts into (default: output)",
    )
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    generated = generate_category_artifacts(args.min_status, output_dir, args.category)
    if not generated:
        scope = f" in category '{args.category}'" if args.category else ""
        print(f"No category artifacts generated for min-status '{args.min_status}'{scope}.")
        return

    for item in generated:
        parts: list[str] = [item["category"]]
        if item["network_path"]:
            parts.append(f"network={item['network_apps']} -> {item['network_path']}")
        if item["host_path"]:
            parts.append(f"host={item['host_apps']} -> {item['host_path']}")
        print(" | ".join(parts))


if __name__ == "__main__":
    main()
