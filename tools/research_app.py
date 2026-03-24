#!/usr/bin/env python3
"""Unified app research orchestrator.

Runs the full analysis pipeline for an application:
1. Homebrew cask/formula research (host + network IoCs)
2. crt.sh subdomain enumeration for discovered domains
3. Quality assessment against the catalog quality standards
4. Consolidated report with suggested YAML skeleton

Usage:
    app-control research-app --app cursor
    app-control research-app --app cursor --format json
    app-control research-app --app cursor --write-skeleton
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

from app_control.catalog import APPS_DIR, VALID_CATEGORIES, load_app

TODAY = date.today().isoformat()


def _import_homebrew():
    from tools.research_homebrew import (
        KNOWN_MAP,
        BREW_API_CASK,
        BREW_API_FORMULA,
        _fetch_json,
        _fetch_text,
        _ruby_source_url,
        extract_cask_host_iocs,
        extract_cask_network_iocs,
        extract_formula_host_iocs,
        extract_formula_network_iocs,
    )
    return {
        "KNOWN_MAP": KNOWN_MAP,
        "BREW_API_CASK": BREW_API_CASK,
        "BREW_API_FORMULA": BREW_API_FORMULA,
        "fetch_json": _fetch_json,
        "fetch_text": _fetch_text,
        "ruby_source_url": _ruby_source_url,
        "extract_cask_host_iocs": extract_cask_host_iocs,
        "extract_cask_network_iocs": extract_cask_network_iocs,
        "extract_formula_host_iocs": extract_formula_host_iocs,
        "extract_formula_network_iocs": extract_formula_network_iocs,
    }


def _import_crtsh():
    from tools.research_crtsh import (
        query_crtsh,
        analyze_subdomains,
        suggest_hostname_patterns,
    )
    return {
        "query_crtsh": query_crtsh,
        "analyze_subdomains": analyze_subdomains,
        "suggest_hostname_patterns": suggest_hostname_patterns,
    }


# ── Quality assessment ──────────────────────────────────────────────────

def assess_quality(
    host_iocs: dict[str, Any] | None,
    network_iocs: dict[str, Any] | None,
    crtsh_results: dict[str, Any] | None,
) -> dict[str, Any]:
    """Assess IoC candidates against quality standards."""
    findings: list[str] = []
    score_components: dict[str, int] = {}

    has_host = bool(host_iocs and (host_iocs.get("paths") or host_iocs.get("bundle_ids")))
    has_network = bool(network_iocs and network_iocs.get("hostname_patterns"))

    if has_host and has_network:
        score_components["defense_in_depth"] = 2
        findings.append("✓ Defense in depth: both host and network IoCs available")
    elif has_host or has_network:
        score_components["defense_in_depth"] = 1
        channel = "host" if has_host else "network"
        findings.append(f"△ Single channel only: {channel} IoCs available")
    else:
        score_components["defense_in_depth"] = 0
        findings.append("✗ No IoCs extracted from automated research")

    if host_iocs:
        paths = host_iocs.get("paths", [])
        bundle_ids = host_iocs.get("bundle_ids", [])
        app_paths = [p for p in paths if p.startswith("/Applications/")]
        config_paths = [p for p in paths if "~/" in p or "/Library/" in p]

        if app_paths and config_paths:
            score_components["host_diversity"] = 2
            findings.append("✓ Host diversity: app bundle + config/library paths")
        elif app_paths or config_paths or paths:
            score_components["host_diversity"] = 1
            findings.append("△ Host coverage: single path type")
        if bundle_ids:
            findings.append(f"✓ Bundle IDs available: {len(bundle_ids)}")

    if network_iocs:
        patterns = network_iocs.get("hostname_patterns", [])
        branded = [p for p in patterns if p.get("role") == "app_brand"]
        non_branded = [p for p in patterns if p.get("role") != "app_brand"]

        if branded:
            score_components["network_uniqueness"] = 2
            findings.append(f"✓ App-branded domains: {len(branded)}")
        if non_branded:
            findings.append(f"  Supporting domains ({len(non_branded)}): " +
                          ", ".join(p["role"] for p in non_branded))

    if crtsh_results:
        hv = crtsh_results.get("high_value", [])
        if hv:
            score_components["ct_coverage"] = min(len(hv), 3)
            findings.append(f"✓ crt.sh found {len(hv)} high-value subdomains")
        excluded = crtsh_results.get("excluded_shared_infra", [])
        if excluded:
            findings.append(f"  Filtered out {len(excluded)} shared-infra domains")

    provenance_sources = 0
    if host_iocs and host_iocs.get("provenance_url"):
        provenance_sources += 1
    if network_iocs and network_iocs.get("provenance_url"):
        provenance_sources += 1
    if crtsh_results and crtsh_results.get("total_certs", 0) > 0:
        provenance_sources += 1
    score_components["provenance_depth"] = min(provenance_sources, 3)
    if provenance_sources >= 2:
        findings.append(f"✓ Multi-source provenance: {provenance_sources} sources")

    total = sum(score_components.values())
    max_possible = 12
    grade = "excellent" if total >= 9 else "good" if total >= 6 else "acceptable" if total >= 3 else "needs_work"

    return {
        "grade": grade,
        "score": total,
        "max_score": max_possible,
        "components": score_components,
        "findings": findings,
    }


# ── YAML skeleton generation ───────────────────────────────────────────

def generate_skeleton(
    app_id: str,
    host_iocs: dict[str, Any] | None,
    network_iocs: dict[str, Any] | None,
    crtsh_suggested: list[dict[str, str]] | None,
) -> str:
    """Generate a draft YAML skeleton from research results."""
    net_patterns = []
    if network_iocs and network_iocs.get("hostname_patterns"):
        for hp in network_iocs["hostname_patterns"]:
            net_patterns.append({
                "pattern": hp["pattern"],
                "match": hp["match"],
                "role": hp["role"],
            })

    if crtsh_suggested:
        existing = {p["pattern"] for p in net_patterns}
        for sp in crtsh_suggested:
            if sp["pattern"] not in existing:
                net_patterns.append({
                    "pattern": sp["pattern"],
                    "match": sp["match"],
                    "role": sp["role"],
                })

    skeleton: dict[str, Any] = {
        "id": app_id,
        "name": app_id.replace("_", " ").title(),
        "category": "GENAI_CODING",
        "product_shape": ["macos"],
        "product_type": ["coding"],
        "severity": "medium",
        "priority_score": 50,
        "notes": "Auto-generated skeleton from research-app. Review and update all fields.",
        "iocs": {},
    }

    if net_patterns:
        net_provenance_url = (network_iocs or {}).get("provenance_url", "")
        net_evidence = (network_iocs or {}).get("evidence", "Automated Homebrew + crt.sh research")
        skeleton["iocs"]["network"] = {
            "status": "draft",
            "provenance": {
                "url": net_provenance_url,
                "evidence": net_evidence,
                "checked_at": TODAY,
            },
            "hostname_patterns": net_patterns,
        }

    if host_iocs and (host_iocs.get("paths") or host_iocs.get("bundle_ids")):
        host_section: dict[str, Any] = {
            "status": "draft",
            "provenance": {
                "url": host_iocs.get("provenance_url", ""),
                "evidence": host_iocs.get("evidence", "Automated Homebrew research"),
                "checked_at": TODAY,
            },
        }
        if host_iocs.get("paths"):
            host_section["paths"] = host_iocs["paths"]
        if host_iocs.get("bundle_ids"):
            host_section["bundle_ids"] = host_iocs["bundle_ids"]
        skeleton["iocs"]["host"] = host_section

    return yaml.dump(skeleton, default_flow_style=False, sort_keys=False, allow_unicode=True)


# ── Report formatting ──────────────────────────────────────────────────

def format_report(
    app_id: str,
    host_iocs: dict[str, Any] | None,
    network_iocs: dict[str, Any] | None,
    crtsh_analysis: dict[str, Any] | None,
    crtsh_suggested: list[dict[str, str]] | None,
    quality: dict[str, Any],
    output_format: str = "text",
) -> str:
    if output_format == "json":
        return json.dumps({
            "app_id": app_id,
            "researched_at": TODAY,
            "host_iocs": host_iocs,
            "network_iocs": network_iocs,
            "crtsh_analysis": crtsh_analysis,
            "crtsh_suggested_patterns": crtsh_suggested,
            "quality_assessment": quality,
        }, indent=2, default=str)

    lines = [
        f"{'═' * 60}",
        f"  App Research Report: {app_id}",
        f"  Date: {TODAY}",
        f"{'═' * 60}",
        "",
    ]

    lines.append(f"── Quality Assessment: {quality['grade'].upper()} ({quality['score']}/{quality['max_score']}) ──")
    for finding in quality["findings"]:
        lines.append(f"  {finding}")
    lines.append("")

    if host_iocs:
        lines.append("── Host IoC Candidates ──")
        lines.append(f"  Source: {host_iocs.get('provenance_url', 'N/A')}")
        if host_iocs.get("paths"):
            lines.append(f"  Paths ({len(host_iocs['paths'])}):")
            for p in host_iocs["paths"]:
                lines.append(f"    {p}")
        if host_iocs.get("bundle_ids"):
            lines.append(f"  Bundle IDs ({len(host_iocs['bundle_ids'])}):")
            for b in host_iocs["bundle_ids"]:
                lines.append(f"    {b}")
        lines.append("")

    if network_iocs and network_iocs.get("hostname_patterns"):
        lines.append("── Network IoC Candidates (Homebrew) ──")
        lines.append(f"  Source: {network_iocs.get('provenance_url', 'N/A')}")
        for hp in network_iocs["hostname_patterns"]:
            lines.append(f"    {hp['pattern']:40s}  {hp['match']:6s}  {hp['role']}")
        lines.append("")

    if crtsh_analysis:
        hv = crtsh_analysis.get("high_value", [])
        if hv:
            lines.append(f"── crt.sh High-Value Subdomains ({len(hv)}) ──")
            for entry in hv:
                lines.append(f"  ★ {entry['subdomain']}")
            lines.append("")

    if crtsh_suggested:
        lines.append(f"── Suggested Hostname Patterns (merged, {len(crtsh_suggested)}) ──")
        for sp in crtsh_suggested:
            lines.append(f"    {sp['pattern']:40s}  {sp['match']:6s}  {sp['role']}")
        lines.append("")

    return "\n".join(lines)


# ── Main pipeline ──────────────────────────────────────────────────────

def run_research(
    app_id: str,
    output_format: str = "text",
    write_skeleton: bool = False,
) -> int:
    host_iocs: dict[str, Any] | None = None
    network_iocs: dict[str, Any] | None = None
    crtsh_analysis: dict[str, Any] | None = None
    crtsh_suggested: list[dict[str, str]] | None = None

    brew = _import_homebrew()
    crtsh = _import_crtsh()

    # Phase 1: Homebrew research
    if app_id in brew["KNOWN_MAP"]:
        brew_type, token = brew["KNOWN_MAP"][app_id]
        print(f"[homebrew] Researching {app_id} ({brew_type}:{token})...", file=sys.stderr)

        if brew_type == "cask":
            data = brew["fetch_json"](brew["BREW_API_CASK"].format(token=token))
            if data:
                host_iocs = brew["extract_cask_host_iocs"](data, token)
                network_iocs = brew["extract_cask_network_iocs"](data, token)
        else:
            data = brew["fetch_json"](brew["BREW_API_FORMULA"].format(token=token))
            if data:
                ruby_url = brew["ruby_source_url"]("formula", token)
                ruby_source = brew["fetch_text"](ruby_url)
                host_iocs = brew["extract_formula_host_iocs"](ruby_source, token)
                network_iocs = brew["extract_formula_network_iocs"](data, ruby_source, token)
    else:
        print(f"[homebrew] {app_id} not in known Homebrew map, skipping", file=sys.stderr)

    # Phase 2: crt.sh subdomain enumeration
    domains_to_check: set[str] = set()
    if network_iocs:
        for hp in network_iocs.get("hostname_patterns", []):
            domain = hp["pattern"]
            parts = domain.split(".")
            if len(parts) >= 2:
                base = ".".join(parts[-2:])
                domains_to_check.add(base)

    existing_yaml = APPS_DIR / f"{app_id}.yaml"
    if existing_yaml.exists():
        app_data = load_app(existing_yaml)
        iocs = app_data.get("iocs", {})
        net = iocs.get("network", {})
        for hp in net.get("hostname_patterns", []):
            domain = hp.get("pattern", "")
            parts = domain.split(".")
            if len(parts) >= 2:
                base = ".".join(parts[-2:])
                domains_to_check.add(base)

    for domain in sorted(domains_to_check):
        print(f"[crt.sh] Querying *.{domain}...", file=sys.stderr)
        subdomains = crtsh["query_crtsh"](domain)
        if subdomains:
            analysis = crtsh["analyze_subdomains"](subdomains, domain)
            suggested = crtsh["suggest_hostname_patterns"](analysis, domain)
            if crtsh_analysis is None:
                crtsh_analysis = analysis
                crtsh_suggested = suggested
            else:
                crtsh_analysis["high_value"].extend(analysis.get("high_value", []))
                crtsh_analysis["standard"].extend(analysis.get("standard", []))
                crtsh_analysis["excluded_shared_infra"].extend(analysis.get("excluded_shared_infra", []))
                crtsh_analysis["total_certs"] += analysis.get("total_certs", 0)
                if crtsh_suggested is not None and suggested:
                    existing_patterns = {s["pattern"] for s in crtsh_suggested}
                    for s in suggested:
                        if s["pattern"] not in existing_patterns:
                            crtsh_suggested.append(s)

    # Phase 3: Quality assessment
    quality = assess_quality(host_iocs, network_iocs, crtsh_analysis)

    # Phase 4: Report
    report = format_report(
        app_id, host_iocs, network_iocs,
        crtsh_analysis, crtsh_suggested, quality, output_format,
    )
    print(report)

    # Optional: write YAML skeleton
    if write_skeleton:
        skeleton = generate_skeleton(app_id, host_iocs, network_iocs, crtsh_suggested)
        skeleton_path = APPS_DIR / f"{app_id}.yaml"
        if skeleton_path.exists():
            print(f"\n[skeleton] {skeleton_path} already exists — writing to scratch/{app_id}_research.yaml", file=sys.stderr)
            scratch_dir = APPS_DIR.parent / "scratch"
            scratch_dir.mkdir(exist_ok=True)
            skeleton_path = scratch_dir / f"{app_id}_research.yaml"
        skeleton_path.write_text(skeleton)
        print(f"[skeleton] Written to {skeleton_path}", file=sys.stderr)

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the full app research pipeline (Homebrew + crt.sh + quality assessment).",
    )
    parser.add_argument("--app", type=str, required=True, help="App ID to research")
    parser.add_argument("--format", type=str, choices=("text", "json"), default="text")
    parser.add_argument("--write-skeleton", action="store_true",
                        help="Write a draft YAML skeleton to apps/ or scratch/")
    args = parser.parse_args()

    return run_research(args.app, args.format, args.write_skeleton)


if __name__ == "__main__":
    raise SystemExit(main())
