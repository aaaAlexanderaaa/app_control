#!/usr/bin/env python3
"""One-time migration: archived catalog JSON -> per-app YAML files in apps/."""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path

import yaml

from app_control.catalog import APPS_DIR, ARCHIVE_DIR

DEFAULT_CATALOG_PATH = ARCHIVE_DIR / "app_data_leak_risk_catalog.json"
SOURCES: dict[str, dict] = {}


def load_catalog(catalog_path: Path) -> dict:
    return json.loads(catalog_path.read_text(encoding="utf-8"))


def build_source_index(catalog: dict) -> None:
    for section in ("public_catalogs", "supporting"):
        for src in catalog["sources"].get(section, []):
            SOURCES[src["id"]] = src


def map_status(old_status: str) -> str:
    if old_status == "verified":
        return "reviewed"
    return "draft"


def build_provenance(source_ids: list[str], last_verified_at: str | None) -> dict:
    urls = []
    for source_id in source_ids:
        src = SOURCES.get(source_id)
        if src and src.get("url"):
            urls.append(src["url"])
    url = urls[0] if urls else ""
    evidence = f"Migrated from catalog. Original source_ids: {', '.join(source_ids)}"
    checked_at = last_verified_at or "2026-01-01"
    return {"url": url, "evidence": evidence, "checked_at": checked_at}


def collapse_paths(paths: list[dict]) -> list[str]:
    raw = []
    for path in paths:
        value = path["value"].replace("$HOME/", "~/").replace("${HOME}/", "~/")
        raw.append(value)

    raw.sort(key=len)
    collapsed: list[str] = []
    for path in raw:
        is_child = False
        for kept in collapsed:
            parent = kept.rstrip("/")
            if path == parent or path.startswith(parent + "/"):
                is_child = True
                break
        if not is_child:
            collapsed.append(path)

    collapsed.sort()
    return collapsed


def extract_host_artifacts(host_data: dict, field: str) -> list[str]:
    return [item["value"] for item in host_data.get(field, []) if item.get("value")]


def best_source_ids_from_network(patterns: list[dict]) -> list[str]:
    brand_patterns = [pattern for pattern in patterns if pattern.get("role") == "app_brand"]
    if brand_patterns:
        best = max(brand_patterns, key=lambda item: item.get("weight", 0))
        return best.get("source_ids", [])
    if patterns:
        best = max(patterns, key=lambda item: item.get("weight", 0))
        return best.get("source_ids", [])
    return []


def best_verified_at_from_network(patterns: list[dict]) -> str | None:
    dates = [pattern["last_verified_at"] for pattern in patterns if pattern.get("last_verified_at")]
    return max(dates) if dates else None


def best_status_from_network(patterns: list[dict]) -> str:
    statuses = {pattern.get("verification_status", "unverified") for pattern in patterns}
    if "verified" in statuses:
        return "reviewed"
    return "draft"


def best_status_from_host(host_data: dict) -> str:
    status = host_data.get("host_signal_status", "missing")
    if status == "verified":
        return "reviewed"
    return "draft"


def best_source_ids_from_host(host_data: dict) -> list[str]:
    all_ids: list[str] = []
    for field in (
        "bundle_ids",
        "process_names",
        "team_ids",
        "directory_paths",
        "chrome_extension_ids",
        "safari_extension_bundle_ids",
    ):
        for item in host_data.get(field, []):
            all_ids.extend(item.get("source_ids", []))
    seen: set[str] = set()
    deduped: list[str] = []
    for source_id in all_ids:
        if source_id not in seen:
            seen.add(source_id)
            deduped.append(source_id)
    return deduped


def best_verified_at_from_host(host_data: dict) -> str | None:
    dates: list[str] = []
    for field in (
        "bundle_ids",
        "process_names",
        "team_ids",
        "directory_paths",
        "chrome_extension_ids",
        "safari_extension_bundle_ids",
    ):
        for item in host_data.get(field, []):
            verified_at = item.get("last_verified_at")
            if verified_at:
                dates.append(verified_at)
    return max(dates) if dates else None


def has_host_data(host_data: dict) -> bool:
    for field in (
        "bundle_ids",
        "process_names",
        "team_ids",
        "directory_paths",
        "chrome_extension_ids",
        "safari_extension_bundle_ids",
    ):
        if host_data.get(field):
            return True
    return False


def migrate_app(app: dict) -> dict:
    network_patterns = app["fingerprints"]["network"]["hostname_patterns"]
    keyword_patterns = app["fingerprints"]["network"]["keyword_patterns"]
    host_macos = app["fingerprints"]["host"]["macos"]

    migrated: dict = {
        "id": app["id"],
        "name": app["name"],
        "category": app["category"],
        "product_shape": app["product_shape"],
        "product_type": app["product_type"],
        "severity": app["risk_profile"]["severity"],
        "priority_score": app["risk_profile"]["priority_score"],
    }

    if app.get("notes"):
        migrated["notes"] = app["notes"]

    iocs: dict = {}

    if network_patterns or keyword_patterns:
        net_source_ids = best_source_ids_from_network(network_patterns)
        net_verified_at = best_verified_at_from_network(network_patterns)
        net_status = best_status_from_network(network_patterns)

        hostname_list = [{"pattern": pattern["pattern"], "match": pattern["match"], "role": pattern["role"]} for pattern in network_patterns]
        keyword_list = [{"pattern": keyword["pattern"], "match": keyword["match"]} for keyword in keyword_patterns]

        iocs["network"] = {
            "status": net_status,
            "provenance": build_provenance(net_source_ids, net_verified_at),
            "hostname_patterns": hostname_list,
        }
        if keyword_list:
            iocs["network"]["keyword_patterns"] = keyword_list

    if has_host_data(host_macos):
        host_source_ids = best_source_ids_from_host(host_macos)
        host_verified_at = best_verified_at_from_host(host_macos)
        host_status = best_status_from_host(host_macos)

        host_ioc: dict = {
            "status": host_status,
            "provenance": build_provenance(host_source_ids, host_verified_at),
        }

        paths = collapse_paths(host_macos.get("directory_paths", []))
        if paths:
            host_ioc["paths"] = paths

        for field in (
            "bundle_ids",
            "process_names",
            "team_ids",
            "chrome_extension_ids",
            "safari_extension_bundle_ids",
        ):
            values = extract_host_artifacts(host_macos, field)
            if values:
                host_ioc[field] = values

        iocs["host"] = host_ioc

    migrated["iocs"] = iocs
    return migrated


class LiteralStr(str):
    pass


def literal_str_representer(dumper: yaml.Dumper, data: LiteralStr) -> yaml.Node:
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")


yaml.add_representer(LiteralStr, literal_str_representer)


def write_app_yaml(app_data: dict, out_dir: Path) -> None:
    filepath = out_dir / f"{app_data['id']}.yaml"
    with filepath.open("w", encoding="utf-8") as handle:
        yaml.dump(app_data, handle, default_flow_style=False, allow_unicode=True, sort_keys=False, width=120)


def main() -> None:
    parser = argparse.ArgumentParser(description="Migrate archived JSON catalog into per-app YAML files")
    parser.add_argument(
        "--catalog",
        default=str(DEFAULT_CATALOG_PATH),
        help=f"Path to legacy JSON catalog (default: {DEFAULT_CATALOG_PATH})",
    )
    parser.add_argument(
        "--output-dir",
        default=str(APPS_DIR),
        help=f"Directory to write migrated YAML files (default: {APPS_DIR})",
    )
    args = parser.parse_args()

    catalog_path = Path(args.catalog)
    output_dir = Path(args.output_dir)
    if not catalog_path.is_file():
        raise SystemExit(f"Catalog file not found: {catalog_path}")

    catalog = load_catalog(catalog_path)
    build_source_index(catalog)

    output_dir.mkdir(parents=True, exist_ok=True)

    count = 0
    for app in catalog["apps"]:
        write_app_yaml(migrate_app(app), output_dir)
        count += 1

    print(f"Migrated {count} apps to {output_dir}/")

    statuses: dict[str, int] = defaultdict(int)
    for app in catalog["apps"]:
        migrated = migrate_app(app)
        for group in ("network", "host"):
            if group in migrated.get("iocs", {}):
                status = migrated["iocs"][group]["status"]
                statuses[f"{group}:{status}"] += 1

    print("IOC group status breakdown:")
    for key, value in sorted(statuses.items()):
        print(f"  {key}: {value}")


if __name__ == "__main__":
    main()
