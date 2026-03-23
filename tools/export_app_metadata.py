#!/usr/bin/env python3
"""Export app classification metadata from YAML catalog entries."""

from __future__ import annotations

import argparse
import csv
import io
import json
from pathlib import Path

from app_control.catalog import APPS_DIR, load_apps


def build_rows(apps: list[dict]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for app in apps:
        iocs = app.get("iocs", {})
        rows.append(
            {
                "id": app["id"],
                "name": app["name"],
                "category": app["category"],
                "severity": app["severity"],
                "priority_score": app["priority_score"],
                "product_shape": ", ".join(app.get("product_shape", [])),
                "product_type": ", ".join(app.get("product_type", [])),
                "network_status": (iocs.get("network") or {}).get("status", ""),
                "host_status": (iocs.get("host") or {}).get("status", ""),
            }
        )

    rows.sort(key=lambda row: (-int(row["priority_score"]), str(row["category"]), str(row["id"])))
    return rows


def render_markdown(rows: list[dict[str, object]], category: str | None = None) -> str:
    title = f"{category} App Classification" if category else "App Classification"
    lines = [
        f"# {title}",
        "",
        f"Generated from `{APPS_DIR}`.",
        "",
        f"Apps included: {len(rows)}",
        "",
        "| ID | Name | Category | Severity | Priority | Shape | Type | Network | Host |",
        "| --- | --- | --- | --- | ---: | --- | --- | --- | --- |",
    ]
    for row in rows:
        lines.append(
            "| {id} | {name} | {category} | {severity} | {priority_score} | {product_shape} | {product_type} | {network_status} | {host_status} |".format(
                **row
            )
        )
    lines.append("")
    return "\n".join(lines)


def render_json(rows: list[dict[str, object]]) -> str:
    return json.dumps(rows, ensure_ascii=False, indent=2) + "\n"


def render_csv(rows: list[dict[str, object]]) -> str:
    fieldnames = [
        "id",
        "name",
        "category",
        "severity",
        "priority_score",
        "product_shape",
        "product_type",
        "network_status",
        "host_status",
    ]
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue()


def main() -> None:
    parser = argparse.ArgumentParser(description="Export per-app category and priority metadata")
    parser.add_argument(
        "--category",
        default=None,
        help="Only include apps in the given category (for example CLAW_FAMILY_APP)",
    )
    parser.add_argument(
        "--format",
        default="markdown",
        choices=("markdown", "json", "csv"),
        help="Output format",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Write output to this file path",
    )
    args = parser.parse_args()

    rows = build_rows(load_apps(args.category))
    if args.format == "json":
        output = render_json(rows)
    elif args.format == "csv":
        output = render_csv(rows)
    else:
        output = render_markdown(rows, args.category)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(output, encoding="utf-8")


if __name__ == "__main__":
    main()
