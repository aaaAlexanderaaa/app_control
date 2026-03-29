#!/usr/bin/env python3
"""Generate targeted ES|QL, Jamf, and inventory outputs for requested cohorts."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
from typing import Any

from app_control.catalog import get_ioc_group, meets_min_status
from app_control.cohorts import (
    filter_apps_with_ready_group,
    host_group_has_values,
    load_claw_macos_installable_apps,
    load_high_risk_apps_excluding,
    network_group_has_values,
)
from generators.esql_rules import generate_optimized_esql
from generators.jamf_scan import generate_scan_script

CLAW_COHORT = "claw_macos_installable"
HIGH_RISK_COHORT = "high_risk_plus_excluding_claw_macos_installable"


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


def sort_apps(apps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(apps, key=lambda app: (-int(app.get("priority_score", 0)), app["category"], app["id"]))


def truncate(values: list[str], limit: int) -> str:
    if not values:
        return ""
    if len(values) <= limit:
        return ", ".join(values)
    remaining = len(values) - limit
    return f"{', '.join(values[:limit])} (+{remaining} more)"


def compact_text(value: str | None) -> str:
    return " ".join((value or "").split())


def escape_cell(value: str) -> str:
    return value.replace("|", "\\|")


def preferred_network_site(app: dict[str, Any]) -> str | None:
    network = get_ioc_group(app, "network") or {}
    hosts: list[str] = []
    for pattern in network.get("hostname_patterns", []):
        if pattern.get("role") != "app_brand" or pattern.get("match") != "exact":
            continue
        hosts.append(pattern["pattern"])

    app_tokens = {
        app["id"].replace("_", "").replace("-", ""),
        app["name"].lower().replace(" ", "").replace("-", ""),
    }
    machine_prefixes = {
        "api",
        "auth",
        "cdn",
        "config",
        "configdl",
        "download",
        "downloads",
        "files",
        "img",
        "login",
        "relay",
        "service",
        "static",
        "telemetry",
        "update",
        "updates",
        "webapi",
    }
    human_labels = {"www", "docs", "help", "support"}

    def prefix_kind(label: str) -> str:
        normalized = label.lower()
        if normalized in human_labels:
            return "human"
        for prefix in machine_prefixes:
            if normalized == prefix or normalized.startswith(prefix):
                return "machine"
        return "other"

    def is_human_facing_host(host: str) -> bool:
        labels = host.split(".")
        first = labels[0].lower()
        if len(labels) == 2:
            return True
        return prefix_kind(first) != "machine"

    def host_rank(host: str) -> tuple[int, int, int, str]:
        normalized = host.replace(".", "")
        labels = host.split(".")
        first = labels[0].lower()
        kind = prefix_kind(first)
        matches_app = any(token and token in normalized for token in app_tokens)
        if len(labels) == 2:
            surface_rank = 0
        elif kind == "human" and first == "www":
            surface_rank = 1
        elif kind == "human":
            surface_rank = 2
        elif kind == "other":
            surface_rank = 3
        else:
            surface_rank = 9
        return (0 if matches_app else 1, surface_rank, len(labels), host)

    preferred_hosts = [host for host in sorted(set(hosts), key=host_rank) if is_human_facing_host(host)]
    for host in preferred_hosts:
        return f"https://{host}/"
    return None




def normalize_site_url(url: str) -> str:
    raw_prefix = "https://raw.githubusercontent.com/"
    if url.startswith(raw_prefix):
        parts = url[len(raw_prefix):].split("/")
        if len(parts) >= 2:
            owner, repo = parts[0], parts[1]
            return f"https://github.com/{owner}/{repo}"
    return url

def official_site(app: dict[str, Any]) -> str:
    refs = app.get("references") or []
    preferred_site_kinds = ("official_site", "official_homepage")
    repo_kinds = ("official_repo",)
    secondary_kinds = (
        "official_marketplace",
        "official_docs",
        "official_support",
        "official_blog",
        "official_console",
        "official_onboarding",
        "official_tool",
        "official_source",
        "official_page",
    )

    def first_by_kind(kinds: tuple[str, ...]) -> str | None:
        for expected_kind in kinds:
            for ref in refs:
                kind = (ref.get("kind") or "").lower()
                if kind == expected_kind and ref.get("url"):
                    return ref["url"]
        return None

    selected = (
        first_by_kind(preferred_site_kinds)
        or first_by_kind(repo_kinds)
        or preferred_network_site(app)
        or first_by_kind(secondary_kinds)
        or next((ref.get("url") for ref in refs if ref.get("url")), None)
        or ((get_ioc_group(app, "network") or {}).get("provenance") or {}).get("url")
        or ((get_ioc_group(app, "host") or {}).get("provenance") or {}).get("url")
        or "UNKNOWN"
    )
    return normalize_site_url(selected)


def missing_network_reason(app: dict[str, Any], min_status: str) -> str:
    network = get_ioc_group(app, "network") or {}
    status = network.get("status") or "missing"
    text = f"{compact_text(app.get('notes'))} {compact_text((network.get('provenance') or {}).get('evidence'))}".lower()
    if "parked" in text or "404" in text or "unavailable" in text or "no trustworthy first-party" in text:
        return f"无；官方仓库/域名当前失效或停放，缺少可信一方网络面（状态: {status}）"
    if "withdrawn" in text or "failed revalidation" in text or "noise" in text:
        return f"无；旧网络 IOC 已撤回，剩余关键词噪声过高（状态: {status}）"
    return f"无；当前未保留达到 `{min_status}` 阈值的网络 IOC（状态: {status}）"


def missing_host_reason(app: dict[str, Any], min_status: str) -> str:
    host = get_ioc_group(app, "host") or {}
    status = host.get("status") or "missing"
    text = f"{compact_text(app.get('notes'))} {compact_text((host.get('provenance') or {}).get('evidence'))}".lower()
    if app.get("product_shape") == ["web"] or "browser" in text or "hosted" in text or "web-based" in text:
        return "无；官方资料仅显示托管/网页形态，未公开稳定本地路径、Bundle ID 或进程名"
    if "private server" in text or "no app to install" in text or "local runtime path" in text:
        return "无；官方资料未给出可稳定落地到终端的本地安装痕迹"
    return f"无；当前未保留达到 `{min_status}` 阈值的主机 IOC（状态: {status}）"


def summarize_network_ioc(app: dict[str, Any], min_status: str) -> str:
    network = get_ioc_group(app, "network") or {}
    if not meets_min_status(network.get("status"), min_status) or not network_group_has_values(network):
        return missing_network_reason(app, min_status)

    hosts = [item["pattern"] for item in network.get("hostname_patterns", [])]
    keywords = [item["pattern"] for item in network.get("keyword_patterns", [])]
    summary_parts: list[str] = []
    if hosts:
        summary_parts.append(f"Hosts: {truncate(hosts, 4)}")
    if keywords:
        summary_parts.append(f"KW: {truncate(keywords, 3)}")
    return "; ".join(summary_parts)


def summarize_host_ioc(app: dict[str, Any], min_status: str) -> str:
    host = get_ioc_group(app, "host") or {}
    if not meets_min_status(host.get("status"), min_status) or not host_group_has_values(host):
        return missing_host_reason(app, min_status)

    parts: list[str] = []
    paths = host.get("paths") or []
    bundle_ids = host.get("bundle_ids") or []
    process_names = host.get("process_names") or []
    if paths:
        parts.append(f"Paths: {truncate(paths, 4)}")
    if bundle_ids:
        parts.append(f"Bundle: {truncate(bundle_ids, 2)}")
    if process_names:
        parts.append(f"Process: {truncate(process_names, 2)}")
    return "; ".join(parts)


def render_inventory(
    title: str,
    description: str,
    apps: list[dict[str, Any]],
    min_status: str,
    network_path: Path,
    host_path: Path,
    network_apps: list[dict[str, Any]],
    host_apps: list[dict[str, Any]],
) -> str:
    lines = [
        f"# {title}",
        "",
        description,
        "",
        f"- IOC threshold: `{min_status}`",
        f"- Inventory rows: `{len(apps)}`",
        f"- Network-ready apps: `{len(network_apps)}` -> `{network_path}`",
        f"- Host-ready apps: `{len(host_apps)}` -> `{host_path}`",
        "",
        "| 名称 | 类别 | 网络 IOC | 主机 IOC | 官方站点 |",
        "| --- | --- | --- | --- | --- |",
    ]

    for app in apps:
        lines.append(
            "| {name} | {category} | {network} | {host} | {site} |".format(
                name=escape_cell(app["name"]),
                category=escape_cell(app["category"]),
                network=escape_cell(summarize_network_ioc(app, min_status)),
                host=escape_cell(summarize_host_ioc(app, min_status)),
                site=escape_cell(official_site(app)),
            )
        )

    lines.append("")
    return "\n".join(lines)


def generate_one_cohort(
    cohort_name: str,
    apps: list[dict[str, Any]],
    min_status: str,
    output_dir: Path,
    description: str,
    from_pattern: str,
    aggregate_minutes: int,
) -> dict[str, Any]:
    suffix = status_suffix(min_status)
    network_apps = sort_apps(filter_apps_with_ready_group(apps, "network", min_status))
    host_apps = sort_apps(filter_apps_with_ready_group(apps, "host", min_status))
    inventory_apps = sort_apps(apps)

    network_path = output_dir / f"{cohort_name}_network_rules{suffix}.esql"
    host_path = output_dir / f"{cohort_name}_host_scan{suffix}.sh"
    inventory_path = output_dir / f"{cohort_name}_inventory{suffix}.md"

    write_text(
        network_path,
        generate_optimized_esql(
            network_apps,
            min_status,
            cohort_name.upper(),
            from_pattern=from_pattern,
            aggregate_minutes=aggregate_minutes,
        ),
    )
    write_text(
        host_path,
        generate_scan_script(
            host_apps,
            min_status,
            cohort_name.upper(),
            output_mode="jamf_ea",
        ),
        executable=True,
    )
    write_text(
        inventory_path,
        render_inventory(
            title=cohort_name,
            description=description,
            apps=inventory_apps,
            min_status=min_status,
            network_path=network_path,
            host_path=host_path,
            network_apps=network_apps,
            host_apps=host_apps,
        ),
    )

    return {
        "cohort": cohort_name,
        "app_count": len(inventory_apps),
        "network_count": len(network_apps),
        "host_count": len(host_apps),
        "network_path": network_path,
        "host_path": host_path,
        "inventory_path": inventory_path,
    }


def render_manifest(results: list[dict[str, Any]], min_status: str, from_pattern: str) -> str:
    lines = [
        "# Targeted Alert Cohorts",
        "",
        f"- IOC threshold: `{min_status}`",
        f"- ES|QL source pattern: `{from_pattern}`",
        "",
        "| Cohort | Apps | Network | Host | Inventory |",
        "| --- | ---: | --- | --- | --- |",
    ]
    for item in results:
        lines.append(
            f"| `{item['cohort']}` | {item['app_count']} | `{item['network_path']}` ({item['network_count']}) | `{item['host_path']}` ({item['host_count']}) | `{item['inventory_path']}` |"
        )
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate targeted alert outputs for requested cohorts")
    parser.add_argument(
        "--min-status",
        default="reviewed",
        choices=["draft", "reviewed", "validated"],
        help="Minimum IOC status to include in generated artifacts (default: reviewed)",
    )
    parser.add_argument(
        "--from-pattern",
        default="*",
        help="ES|QL FROM pattern for generated queries (default: *)",
    )
    parser.add_argument(
        "--aggregate-minutes",
        type=int,
        default=1,
        help="ES|QL aggregation bucket size in minutes (default: 1)",
    )
    parser.add_argument(
        "--output-dir",
        default="output",
        help="Directory to write generated artifacts into (default: output)",
    )
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    claw_apps, _ = load_claw_macos_installable_apps(args.min_status)
    claw_ids = {app["id"] for app in claw_apps}
    high_risk_apps = load_high_risk_apps_excluding(claw_ids)

    results = [
        generate_one_cohort(
            CLAW_COHORT,
            claw_apps,
            args.min_status,
            output_dir,
            "CLAW 系中具备明确 macOS 可运行/可安装证据的应用（含 CLI）。",
            args.from_pattern,
            args.aggregate_minutes,
        ),
        generate_one_cohort(
            HIGH_RISK_COHORT,
            high_risk_apps,
            args.min_status,
            output_dir,
            "所有 high risk 及以上应用，排除集合 1；若缺少 reviewed 级网络或主机 IOC，则在清单中声明原因。",
            args.from_pattern,
            args.aggregate_minutes,
        ),
    ]

    manifest_path = output_dir / f"targeted_alert_cohorts{status_suffix(args.min_status)}.md"
    write_text(manifest_path, render_manifest(results, args.min_status, args.from_pattern))

    for item in results:
        print(
            " | ".join(
                [
                    item["cohort"],
                    f"apps={item['app_count']}",
                    f"network={item['network_count']} -> {item['network_path']}",
                    f"host={item['host_count']} -> {item['host_path']}",
                    f"inventory={item['inventory_path']}",
                ]
            )
        )
    print(f"manifest -> {manifest_path}")


if __name__ == "__main__":
    main()
