#!/usr/bin/env python3
"""Audit IOC quality across the catalog."""

from __future__ import annotations

import argparse
import json

from app_control.catalog import load_apps
from app_control.quality import (
    GROUP_GRADES,
    OVERALL_GRADES,
    coverage_percent,
    format_review_candidate,
    summarize_catalog_quality,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Audit IOC quality across the catalog")
    parser.add_argument("--category", help="Limit audit to a single category")
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=20,
        help="How many review candidates to print in text output (default: 20)",
    )
    return parser


def render_text(summary: dict[str, object], limit: int) -> str:
    total = int(summary["total_apps"])
    overall = summary["overall_grades"]
    network = summary["network_grades"]
    host = summary["host_grades"]
    metrics = summary["metrics"]
    review_candidates = summary["review_candidates"]

    lines = ["=== IOC Quality Audit ===", ""]
    lines.append(f"Total apps: {total}")
    lines.append("")

    lines.append("Overall grades:")
    for grade in OVERALL_GRADES:
        count = overall.get(grade, 0)
        lines.append(f"  {grade:11s}  {count:4d}  ({coverage_percent(count, total):3d}%)")

    lines.append("")
    lines.append("Network grades:")
    for grade in GROUP_GRADES:
        count = network.get(grade, 0)
        if count:
            lines.append(f"  {grade:11s}  {count:4d}  ({coverage_percent(count, total):3d}%)")

    lines.append("")
    lines.append("Host grades:")
    for grade in GROUP_GRADES:
        count = host.get(grade, 0)
        if count:
            lines.append(f"  {grade:11s}  {count:4d}  ({coverage_percent(count, total):3d}%)")

    lines.append("")
    lines.append("Quality metrics:")
    for label, key in (
        ("defense in depth", "defense_in_depth"),
        ("notes with omission rationale", "omission_rationale"),
        ("exact app-brand network", "exact_app_brand_network"),
        ("strong host artifacts", "strong_host_artifact"),
        ("placeholder entries", "placeholder"),
        ("legacy network provenance", "legacy_network_provenance"),
        ("legacy host provenance", "legacy_host_provenance"),
        ("inferred host provenance", "inferred_host_provenance"),
        ("keyword-only network", "keyword_only_network"),
        ("shared-only network", "shared_only_network"),
        ("single suffix app-brand network", "single_suffix_brand_network"),
        ("missing host group", "missing_host_group"),
        ("repo-local-only host", "repo_local_only_host"),
    ):
        count = int(metrics.get(key, 0))
        lines.append(f"  {label:28s}  {count:4d}  ({coverage_percent(count, total):3d}%)")

    lines.append("")
    lines.append(f"Apps needing review (top {min(limit, len(review_candidates))}):")
    if not review_candidates:
        lines.append("  none")
    else:
        for item in review_candidates[:limit]:
            lines.append(f"  {format_review_candidate(item)}")

    return "\n".join(lines)


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    apps = load_apps(category=args.category)
    summary = summarize_catalog_quality(apps)

    if args.format == "json":
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print(render_text(summary, args.limit))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
