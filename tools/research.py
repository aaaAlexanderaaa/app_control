#!/usr/bin/env python3
"""Research IoC candidates for catalog applications.

Combines Homebrew metadata extraction, crt.sh Certificate Transparency
subdomain enumeration, and quality assessment into a single tool.

Usage:
    app-control research --app cursor                       # full pipeline
    app-control research --app cursor --source homebrew     # Homebrew only
    app-control research --domain cursor.sh --source crtsh  # crt.sh only
    app-control research --list-known                       # known Homebrew mappings
    app-control research --app cursor --format json
    app-control research --app cursor --write-skeleton
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from datetime import date
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

from app_control.catalog import APPS_DIR, load_app

TODAY = date.today().isoformat()

# ════════════════════════════════════════════════════════════════════════
#  Shared infrastructure filters
# ════════════════════════════════════════════════════════════════════════

SHARED_CDN_SUFFIXES = frozenset({
    "cloudfront.net", "akamai.net", "akamaized.net", "edgekey.net",
    "fastly.net", "fastlylb.net", "cloudflare.com", "cdn.cloudflare.net",
    "azureedge.net", "azurefd.net", "trafficmanager.net",
    "googleapis.com", "gstatic.com", "googlesyndication.com",
    "amazonaws.com", "s3.amazonaws.com", "elasticbeanstalk.com",
    "heroku.com", "herokuapp.com", "vercel.app", "netlify.app",
    "github.io", "githubusercontent.com",
    "sentry.io", "bugsnag.com", "launchdarkly.com",
    "segment.io", "segment.com", "mixpanel.com",
    "intercom.io", "zendesk.com", "crisp.chat",
    "stripe.com", "braintree-api.com", "paypal.com",
})

SHARED_HOSTING_EXACT = frozenset({
    "github.com", "raw.githubusercontent.com", "objects.githubusercontent.com",
    "codeload.github.com", "ghcr.io",
    "pypi.org", "files.pythonhosted.org",
    "registry.npmjs.org", "npmjs.com",
    "crates.io", "static.crates.io",
    "proxy.golang.org", "sum.golang.org",
    "rubygems.org", "api.rubygems.org",
    "dl.google.com", "storage.googleapis.com",
    "download.docker.com", "registry.hub.docker.com",
})


def _is_shared_infra(domain: str) -> bool:
    if domain in SHARED_HOSTING_EXACT:
        return True
    for suffix in SHARED_CDN_SUFFIXES:
        if domain == suffix or domain.endswith("." + suffix):
            return True
    return False


# ════════════════════════════════════════════════════════════════════════
#  HTTP helpers
# ════════════════════════════════════════════════════════════════════════

def _fetch_json(url: str) -> dict | None:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "app-control/0.1"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read())
    except Exception as exc:
        print(f"  WARN: fetch failed {url}: {exc}", file=sys.stderr)
        return None


def _fetch_text(url: str) -> str | None:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "app-control/0.1"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception as exc:
        print(f"  WARN: fetch failed {url}: {exc}", file=sys.stderr)
        return None


# ════════════════════════════════════════════════════════════════════════
#  Homebrew research
# ════════════════════════════════════════════════════════════════════════

BREW_API_CASK = "https://formulae.brew.sh/api/cask/{token}.json"
BREW_API_FORMULA = "https://formulae.brew.sh/api/formula/{token}.json"
BREW_FORMULA_RAW = "https://raw.githubusercontent.com/Homebrew/homebrew-core/master/Formula/{prefix}/{token}.rb"

KNOWN_HOMEBREW_MAP: dict[str, tuple[str, str]] = {
    "ironclaw":             ("formula", "ironclaw"),
    "nullclaw":             ("formula", "nullclaw"),
    "nanobot":              ("formula", "nanobot"),
    "cursor":               ("cask", "cursor"),
    "windsurf":             ("cask", "windsurf"),
    "trae":                 ("cask", "trae"),
    "kiro":                 ("cask", "kiro"),
    "codex_app":            ("cask", "codex"),
    "replit":               ("cask", "replit"),
    "superset_ide":         ("cask", "superset"),
    "aider":                ("formula", "aider"),
    "goose":                ("cask", "block-goose"),
    "dropbox":              ("cask", "dropbox"),
    "google_drive":         ("cask", "google-drive"),
    "onedrive":             ("cask", "onedrive"),
    "anydesk":              ("cask", "anydesk"),
    "teamviewer":           ("cask", "teamviewer"),
    "splashtop":            ("cask", "splashtop-business"),
    "qbittorrent":          ("cask", "qbittorrent"),
    "transmission":         ("cask", "transmission"),
    "resilio_sync":         ("cask", "resilio-sync"),
    "syncthing":            ("formula", "syncthing"),
    "warp":                 ("cask", "warp"),
    "rewind":               ("cask", "rewind"),
    "jetbrains_ai_assistant": ("cask", "jetbrains-toolbox"),
    "chatgpt":              ("cask", "chatgpt"),
    "discord":              ("cask", "discord"),
    "notion":               ("cask", "notion"),
    "signal":               ("cask", "signal"),
    "telegram":             ("cask", "telegram"),
    "whatsapp":             ("cask", "whatsapp"),
    "lm_studio":            ("cask", "lm-studio"),
    "anythingllm":          ("cask", "anythingllm"),
    "cherry_studio":        ("cask", "cherry-studio"),
    "jan":                  ("cask", "jan"),
    "chatbox":              ("cask", "chatbox"),
    "raycast":              ("cask", "raycast"),
    "pieces":               ("cask", "pieces"),
    "zed":                  ("cask", "zed"),
    "messenger":            ("cask", "messenger"),
    "viber":                ("cask", "viber"),
    "ollama":               ("cask", "ollama-app"),
    "obsidian_sync":        ("cask", "obsidian"),
    "slack_personal_unmanaged_workspace": ("cask", "slack"),
    "grammarly":            ("cask", "grammarly-desktop"),
    "taskade_desktop":      ("cask", "taskade"),
}


def _path_sort_key(p: str) -> tuple:
    if p.startswith("/Applications"):
        return (0, p)
    if p.startswith("/Library"):
        return (1, p)
    if p.startswith("/opt"):
        return (2, p)
    if p.startswith("/usr"):
        return (3, p)
    if p.startswith("~"):
        return (4, p)
    return (5, p)


def _extract_cask_host_iocs(data: dict, token: str) -> dict[str, Any]:
    paths: list[str] = []
    bundle_ids: set[str] = set()

    for artifact in data.get("artifacts", []):
        if not isinstance(artifact, dict):
            continue

        if "app" in artifact:
            for entry in artifact["app"]:
                if isinstance(entry, str) and entry.endswith(".app"):
                    paths.append(f"/Applications/{entry}")
                elif isinstance(entry, dict) and "target" in entry:
                    paths.append(f"/Applications/{entry['target']}")

        if "binary" in artifact:
            for entry in artifact["binary"]:
                if isinstance(entry, dict) and "target" in entry:
                    name = entry["target"]
                elif isinstance(entry, str):
                    name = Path(entry).name
                else:
                    continue
                paths.append(f"/opt/homebrew/bin/{name}")
                paths.append(f"/usr/local/bin/{name}")

        for key in ("uninstall", "zap"):
            items = artifact.get(key, [])
            if not isinstance(items, list):
                items = [items]
            for item in items:
                if not isinstance(item, dict):
                    continue
                for bid_key in ("quit", "launchctl"):
                    bids = item.get(bid_key, [])
                    if isinstance(bids, str):
                        bids = [bids]
                    for bid in bids:
                        bundle_ids.add(bid)
                for path_key in ("delete", "trash", "rmdir"):
                    raw_paths = item.get(path_key, [])
                    if isinstance(raw_paths, str):
                        raw_paths = [raw_paths]
                    for p in raw_paths:
                        paths.append(p)

    seen: set[str] = set()
    deduped: list[str] = []
    for p in paths:
        norm = p.rstrip("/")
        if norm not in seen:
            seen.add(norm)
            deduped.append(p)

    return {
        "paths": sorted(deduped, key=_path_sort_key),
        "bundle_ids": sorted(bundle_ids),
        "provenance_url": BREW_API_CASK.format(token=token),
        "evidence": "Homebrew cask artifact declarations (app, binary, uninstall, zap stanzas)",
    }


def _extract_formula_host_iocs(ruby_source: str | None, token: str) -> dict[str, Any]:
    paths = [f"/opt/homebrew/bin/{token}", f"/usr/local/bin/{token}"]
    extra: list[str] = []

    if ruby_source:
        in_install = False
        for line in ruby_source.splitlines():
            stripped = line.strip()
            if stripped.startswith("def install"):
                in_install = True
                continue
            if in_install and stripped == "end":
                break
            if not in_install:
                continue

            if "bin.install" in stripped:
                m = re.search(r'bin\.install\s+"([^"]+)"', stripped)
                if m and m.group(1) != token:
                    extra.append(f"/opt/homebrew/bin/{m.group(1)}")
                    extra.append(f"/usr/local/bin/{m.group(1)}")
                m2 = re.search(r'"([^"]+)"\s*=>\s*"([^"]+)"', stripped)
                if m2 and m2.group(2) != token:
                    extra.append(f"/opt/homebrew/bin/{m2.group(2)}")
                    extra.append(f"/usr/local/bin/{m2.group(2)}")

            if "etc.install" in stripped or "prefix.install" in stripped:
                m = re.search(r'(?:etc|prefix)\.install\s+"([^"]+)"', stripped)
                if m:
                    extra.append(f"/opt/homebrew/etc/{m.group(1)}")

    paths.extend(extra)
    return {
        "paths": paths,
        "bundle_ids": [],
        "provenance_url": BREW_API_FORMULA.format(token=token),
        "evidence": "Homebrew formula binary installation paths and def install block",
    }


def _extract_cask_network_iocs(data: dict, token: str) -> dict[str, Any]:
    domains: dict[str, str] = {}

    homepage = data.get("homepage", "")
    if homepage:
        parsed = urlparse(homepage)
        if parsed.hostname:
            domains[parsed.hostname] = "app_brand"

    url_field = data.get("url", "")
    if url_field:
        parsed = urlparse(url_field)
        if parsed.hostname and not _is_shared_infra(parsed.hostname):
            domains[parsed.hostname] = "file_download"

    for field_name in ("appcast",):
        val = data.get(field_name, "")
        if val:
            parsed = urlparse(val)
            if parsed.hostname and not _is_shared_infra(parsed.hostname):
                domains[parsed.hostname] = "app_brand"

    livecheck = data.get("livecheck", {})
    if isinstance(livecheck, dict) and livecheck.get("url"):
        parsed = urlparse(livecheck["url"])
        if parsed.hostname and not _is_shared_infra(parsed.hostname):
            domains[parsed.hostname] = "app_brand"

    return {
        "hostname_patterns": [
            {"pattern": d, "match": "exact", "role": r}
            for d, r in sorted(domains.items())
        ],
        "provenance_url": BREW_API_CASK.format(token=token),
        "evidence": f"Homebrew cask homepage, download URL, and appcast/livecheck for {token}",
    }


def _extract_formula_network_iocs(data: dict, ruby_source: str | None, token: str) -> dict[str, Any]:
    domains: dict[str, str] = {}

    homepage = data.get("homepage", "")
    if homepage:
        parsed = urlparse(homepage)
        if parsed.hostname:
            domains[parsed.hostname] = "app_brand"

    stable = data.get("urls", {}).get("stable", {})
    if isinstance(stable, dict) and stable.get("url"):
        parsed = urlparse(stable["url"])
        if parsed.hostname and not _is_shared_infra(parsed.hostname):
            domains[parsed.hostname] = "file_download"

    if ruby_source:
        for m in re.finditer(r'https?://([a-zA-Z0-9._-]+\.[a-zA-Z]{2,})', ruby_source):
            host = m.group(1).lower()
            if not _is_shared_infra(host) and host not in domains:
                domains[host] = "app_brand"

    return {
        "hostname_patterns": [
            {"pattern": d, "match": "exact", "role": r}
            for d, r in sorted(domains.items())
        ],
        "provenance_url": BREW_API_FORMULA.format(token=token),
        "evidence": f"Homebrew formula homepage, source URL, and Ruby source URLs for {token}",
    }


def run_homebrew(app_id: str | None, brew_type: str | None, token: str | None) -> tuple[dict | None, dict | None]:
    """Run Homebrew research, returning (host_iocs, network_iocs)."""
    if app_id and app_id in KNOWN_HOMEBREW_MAP and not token:
        brew_type, token = KNOWN_HOMEBREW_MAP[app_id]
    if not brew_type or not token:
        return None, None

    if brew_type == "cask":
        data = _fetch_json(BREW_API_CASK.format(token=token))
        if not data:
            return None, None
        return _extract_cask_host_iocs(data, token), _extract_cask_network_iocs(data, token)

    data = _fetch_json(BREW_API_FORMULA.format(token=token))
    if not data:
        return None, None
    ruby_url = BREW_FORMULA_RAW.format(prefix=token[0], token=token)
    ruby_source = _fetch_text(ruby_url)
    return _extract_formula_host_iocs(ruby_source, token), _extract_formula_network_iocs(data, ruby_source, token)


# ════════════════════════════════════════════════════════════════════════
#  crt.sh research
# ════════════════════════════════════════════════════════════════════════

CRTSH_API = "https://crt.sh/?q=%.{domain}&output=json"

IOC_RELEVANT_PREFIXES = frozenset({
    "api", "telemetry", "metrics", "analytics", "tracking",
    "update", "updates", "appcast", "autoupdate", "sparkle",
    "auth", "login", "sso", "oauth", "authenticate",
    "license", "activation", "register",
    "cdn", "static", "assets", "download", "downloads",
    "ws", "wss", "realtime", "socket", "push",
    "app", "portal", "dashboard", "console",
})


def _extract_prefix(subdomain: str, base_domain: str) -> str | None:
    if subdomain == base_domain:
        return None
    suffix = "." + base_domain
    if subdomain.endswith(suffix):
        prefix = subdomain[: -len(suffix)]
        return prefix.split(".")[-1]
    return None


def _classify_subdomain(subdomain: str, base_domain: str) -> str:
    prefix = _extract_prefix(subdomain, base_domain)
    if prefix and prefix.lower() in IOC_RELEVANT_PREFIXES:
        return "high_value"
    if prefix and any(kw in prefix.lower() for kw in ("api", "telemetry", "auth", "update", "license")):
        return "high_value"
    return "standard"


def query_crtsh(domain: str) -> list[str]:
    url = CRTSH_API.format(domain=domain)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "app-control/0.1"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
    except Exception as exc:
        print(f"  WARN: crt.sh query failed for {domain}: {exc}", file=sys.stderr)
        return []

    subdomains: set[str] = set()
    for entry in data:
        name_value = entry.get("name_value", "")
        for name in name_value.split("\n"):
            name = name.strip().lower().lstrip("*.")
            if name and not name.startswith("."):
                subdomains.add(name)

    return sorted(subdomains)


def analyze_subdomains(subdomains: list[str], base_domain: str) -> dict[str, Any]:
    high_value: list[dict[str, str]] = []
    standard: list[dict[str, str]] = []
    excluded: list[str] = []

    for sub in subdomains:
        if _is_shared_infra(sub):
            excluded.append(sub)
            continue
        cls = _classify_subdomain(sub, base_domain)
        entry = {"subdomain": sub, "classification": cls}
        (high_value if cls == "high_value" else standard).append(entry)

    return {
        "base_domain": base_domain,
        "total_certs": len(subdomains),
        "high_value": high_value,
        "standard": standard,
        "excluded_shared_infra": excluded,
    }


def suggest_hostname_patterns(analysis: dict[str, Any], base_domain: str) -> list[dict[str, str]]:
    patterns: list[dict[str, str]] = [
        {"pattern": base_domain, "match": "suffix", "role": "app_brand", "source": "base_domain"},
    ]
    for entry in analysis["high_value"]:
        sub = entry["subdomain"]
        if sub == base_domain:
            continue
        prefix = _extract_prefix(sub, base_domain)
        role = "app_brand"
        if prefix:
            pl = prefix.lower()
            if pl in ("cdn", "static", "assets"):
                role = "cdn_static"
            elif pl in ("download", "downloads"):
                role = "file_download"
            elif pl in ("upload", "uploads"):
                role = "file_upload"
        patterns.append({"pattern": sub, "match": "exact", "role": role, "source": "crt.sh"})

    return patterns


def run_crtsh(domain: str) -> tuple[dict[str, Any], list[dict[str, str]]]:
    """Run crt.sh research, returning (analysis, suggested_patterns)."""
    subdomains = query_crtsh(domain)
    if not subdomains:
        return {"base_domain": domain, "total_certs": 0, "high_value": [], "standard": [], "excluded_shared_infra": []}, []
    analysis = analyze_subdomains(subdomains, domain)
    suggested = suggest_hostname_patterns(analysis, domain)
    return analysis, suggested


# ════════════════════════════════════════════════════════════════════════
#  Quality assessment
# ════════════════════════════════════════════════════════════════════════

def assess_quality(
    host_iocs: dict[str, Any] | None,
    network_iocs: dict[str, Any] | None,
    crtsh_results: dict[str, Any] | None,
) -> dict[str, Any]:
    findings: list[str] = []
    scores: dict[str, int] = {}

    has_host = bool(host_iocs and (host_iocs.get("paths") or host_iocs.get("bundle_ids")))
    has_network = bool(network_iocs and network_iocs.get("hostname_patterns"))

    if has_host and has_network:
        scores["defense_in_depth"] = 2
        findings.append("✓ Defense in depth: both host and network IoCs available")
    elif has_host or has_network:
        scores["defense_in_depth"] = 1
        findings.append(f"△ Single channel only: {'host' if has_host else 'network'} IoCs available")
    else:
        scores["defense_in_depth"] = 0
        findings.append("✗ No IoCs extracted from automated research")

    if host_iocs:
        paths = host_iocs.get("paths", [])
        app_paths = [p for p in paths if p.startswith("/Applications/")]
        config_paths = [p for p in paths if "~/" in p or "/Library/" in p]
        if app_paths and config_paths:
            scores["host_diversity"] = 2
            findings.append("✓ Host diversity: app bundle + config/library paths")
        elif app_paths or config_paths or paths:
            scores["host_diversity"] = 1
            findings.append("△ Host coverage: single path type")
        if host_iocs.get("bundle_ids"):
            findings.append(f"✓ Bundle IDs available: {len(host_iocs['bundle_ids'])}")

    if network_iocs:
        patterns = network_iocs.get("hostname_patterns", [])
        branded = [p for p in patterns if p.get("role") == "app_brand"]
        if branded:
            scores["network_uniqueness"] = 2
            findings.append(f"✓ App-branded domains: {len(branded)}")

    if crtsh_results:
        hv = crtsh_results.get("high_value", [])
        if hv:
            scores["ct_coverage"] = min(len(hv), 3)
            findings.append(f"✓ crt.sh found {len(hv)} high-value subdomains")

    provenance_sources = sum([
        bool(host_iocs and host_iocs.get("provenance_url")),
        bool(network_iocs and network_iocs.get("provenance_url")),
        bool(crtsh_results and crtsh_results.get("total_certs", 0) > 0),
    ])
    scores["provenance_depth"] = min(provenance_sources, 3)
    if provenance_sources >= 2:
        findings.append(f"✓ Multi-source provenance: {provenance_sources} sources")

    total = sum(scores.values())
    grade = "excellent" if total >= 9 else "good" if total >= 6 else "acceptable" if total >= 3 else "needs_work"

    return {"grade": grade, "score": total, "max_score": 12, "components": scores, "findings": findings}


# ════════════════════════════════════════════════════════════════════════
#  YAML skeleton
# ════════════════════════════════════════════════════════════════════════

def generate_skeleton(
    app_id: str,
    host_iocs: dict[str, Any] | None,
    network_iocs: dict[str, Any] | None,
    crtsh_suggested: list[dict[str, str]] | None,
) -> str:
    net_patterns = []
    if network_iocs and network_iocs.get("hostname_patterns"):
        for hp in network_iocs["hostname_patterns"]:
            net_patterns.append({"pattern": hp["pattern"], "match": hp["match"], "role": hp["role"]})
    if crtsh_suggested:
        existing = {p["pattern"] for p in net_patterns}
        for sp in crtsh_suggested:
            if sp["pattern"] not in existing:
                net_patterns.append({"pattern": sp["pattern"], "match": sp["match"], "role": sp["role"]})

    skeleton: dict[str, Any] = {
        "id": app_id,
        "name": app_id.replace("_", " ").title(),
        "category": "GENAI_CODING",
        "product_shape": ["macos"],
        "product_type": ["coding"],
        "severity": "medium",
        "priority_score": 50,
        "notes": "Auto-generated skeleton. Review and update all fields.",
        "iocs": {},
    }

    if net_patterns:
        skeleton["iocs"]["network"] = {
            "status": "draft",
            "provenance": {
                "url": (network_iocs or {}).get("provenance_url", ""),
                "evidence": (network_iocs or {}).get("evidence", "Automated research"),
                "checked_at": TODAY,
            },
            "hostname_patterns": net_patterns,
        }

    if host_iocs and (host_iocs.get("paths") or host_iocs.get("bundle_ids")):
        host_section: dict[str, Any] = {
            "status": "draft",
            "provenance": {
                "url": host_iocs.get("provenance_url", ""),
                "evidence": host_iocs.get("evidence", "Automated research"),
                "checked_at": TODAY,
            },
        }
        if host_iocs.get("paths"):
            host_section["paths"] = host_iocs["paths"]
        if host_iocs.get("bundle_ids"):
            host_section["bundle_ids"] = host_iocs["bundle_ids"]
        skeleton["iocs"]["host"] = host_section

    return yaml.dump(skeleton, default_flow_style=False, sort_keys=False, allow_unicode=True)


# ════════════════════════════════════════════════════════════════════════
#  Report formatting
# ════════════════════════════════════════════════════════════════════════

def format_full_report(
    app_id: str,
    host_iocs: dict | None,
    network_iocs: dict | None,
    crtsh_analysis: dict | None,
    crtsh_suggested: list | None,
    quality: dict,
    fmt: str = "text",
) -> str:
    if fmt == "json":
        return json.dumps({
            "app_id": app_id, "researched_at": TODAY,
            "host_iocs": host_iocs, "network_iocs": network_iocs,
            "crtsh_analysis": crtsh_analysis,
            "crtsh_suggested_patterns": crtsh_suggested,
            "quality_assessment": quality,
        }, indent=2, default=str)

    lines = [
        f"{'═' * 60}",
        f"  App Research Report: {app_id}",
        f"  Date: {TODAY}",
        f"{'═' * 60}", "",
        f"── Quality: {quality['grade'].upper()} ({quality['score']}/{quality['max_score']}) ──",
    ]
    for f in quality["findings"]:
        lines.append(f"  {f}")
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
        lines.append(f"── Suggested Hostname Patterns ({len(crtsh_suggested)}) ──")
        for sp in crtsh_suggested:
            lines.append(f"    {sp['pattern']:40s}  {sp['match']:6s}  {sp['role']}")
        lines.append("")

    return "\n".join(lines)


def format_homebrew_report(app_id: str, host_iocs: dict, network_iocs: dict, fmt: str = "text") -> str:
    if fmt == "json":
        return json.dumps({"app_id": app_id, "researched_at": TODAY, "host": host_iocs, "network": network_iocs}, indent=2)

    lines = [f"═══ Homebrew Research: {app_id} ═══", f"Date: {TODAY}", "", "── Host IoC Candidates ──"]
    if host_iocs.get("paths"):
        lines.append("  Paths:")
        for p in host_iocs["paths"]:
            lines.append(f"    - {p}")
    if host_iocs.get("bundle_ids"):
        lines.append("  Bundle IDs:")
        for b in host_iocs["bundle_ids"]:
            lines.append(f"    - {b}")
    if not host_iocs.get("paths") and not host_iocs.get("bundle_ids"):
        lines.append("  (none)")
    lines += ["", "── Network IoC Candidates ──"]
    if network_iocs.get("hostname_patterns"):
        for hp in network_iocs["hostname_patterns"]:
            lines.append(f"    {hp['pattern']:40s}  {hp['match']:6s}  {hp['role']}")
    else:
        lines.append("  (none)")
    lines.append("")
    return "\n".join(lines)


def format_crtsh_report(domain: str, analysis: dict, suggested: list, fmt: str = "text") -> str:
    if fmt == "json":
        return json.dumps({"base_domain": domain, "researched_at": TODAY, "analysis": analysis, "suggested": suggested}, indent=2)

    lines = [
        f"═══ crt.sh Research: {domain} ═══",
        f"Date: {TODAY}",
        f"Unique subdomains: {analysis['total_certs']}", "",
    ]
    if analysis["high_value"]:
        lines.append(f"── High-Value ({len(analysis['high_value'])}) ──")
        for e in analysis["high_value"]:
            lines.append(f"  ★ {e['subdomain']}")
        lines.append("")
    if analysis["standard"]:
        lines.append(f"── Standard ({len(analysis['standard'])}) ──")
        for e in analysis["standard"]:
            lines.append(f"    {e['subdomain']}")
        lines.append("")
    if analysis["excluded_shared_infra"]:
        lines.append(f"── Excluded ({len(analysis['excluded_shared_infra'])}) ──")
        for d in analysis["excluded_shared_infra"]:
            lines.append(f"  ✗ {d}")
        lines.append("")
    if suggested:
        lines.append("── Suggested Patterns ──")
        for sp in suggested:
            lines.append(f"    {sp['pattern']:40s}  {sp['match']:6s}  {sp['role']}")
        lines.append("")
    return "\n".join(lines)


# ════════════════════════════════════════════════════════════════════════
#  Main
# ════════════════════════════════════════════════════════════════════════

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Research IoC candidates for catalog applications.",
        epilog="Examples:\n"
               "  app-control research --app cursor\n"
               "  app-control research --app cursor --source homebrew\n"
               "  app-control research --domain cursor.sh --source crtsh\n"
               "  app-control research --list-known\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--app", type=str, help="App ID to research")
    parser.add_argument("--domain", type=str, help="Base domain for crt.sh query")
    parser.add_argument("--source", type=str, choices=("homebrew", "crtsh", "all"), default="all",
                        help="Research source (default: all)")
    parser.add_argument("--token", type=str, help="Homebrew cask/formula token (overrides app lookup)")
    parser.add_argument("--type", type=str, choices=("cask", "formula"), help="Homebrew package type")
    parser.add_argument("--format", type=str, choices=("text", "json"), default="text")
    parser.add_argument("--write-skeleton", action="store_true", help="Write draft YAML skeleton")
    parser.add_argument("--list-known", action="store_true", help="List known Homebrew mappings")
    args = parser.parse_args()

    if args.list_known:
        print(f"{'App ID':40s}  {'Type':8s}  Token")
        print("-" * 72)
        for aid, (bt, tok) in sorted(KNOWN_HOMEBREW_MAP.items()):
            print(f"{aid:40s}  {bt:8s}  {tok}")
        return 0

    # ── Source: homebrew only ──
    if args.source == "homebrew":
        if not args.app and not args.token:
            parser.error("--source homebrew requires --app or --token")
        host, net = run_homebrew(args.app, args.type, args.token)
        if not host and not net:
            print(f"No Homebrew data found for {args.app or args.token}", file=sys.stderr)
            return 1
        app_id = args.app or (args.token or "").replace("-", "_")
        print(format_homebrew_report(app_id, host or {}, net or {}, args.format))
        return 0

    # ── Source: crtsh only ──
    if args.source == "crtsh":
        domain = args.domain
        if not domain:
            parser.error("--source crtsh requires --domain")
        print(f"Querying crt.sh for *.{domain}...", file=sys.stderr)
        analysis, suggested = run_crtsh(domain.lower().strip())
        print(format_crtsh_report(domain, analysis, suggested, args.format))
        return 0

    # ── Source: all (full pipeline) ──
    if not args.app:
        parser.error("--app is required for full research (or use --source homebrew/crtsh)")

    app_id = args.app
    host_iocs: dict | None = None
    network_iocs: dict | None = None
    crtsh_analysis: dict | None = None
    crtsh_suggested: list | None = None

    if app_id in KNOWN_HOMEBREW_MAP:
        brew_type, token = KNOWN_HOMEBREW_MAP[app_id]
        print(f"[homebrew] Researching {app_id} ({brew_type}:{token})...", file=sys.stderr)
        host_iocs, network_iocs = run_homebrew(app_id, None, None)
    else:
        print(f"[homebrew] {app_id} not in known map, skipping", file=sys.stderr)

    # Collect base domains for crt.sh
    domains: set[str] = set()
    if args.domain:
        domains.add(args.domain.lower().strip())
    if network_iocs:
        for hp in network_iocs.get("hostname_patterns", []):
            parts = hp["pattern"].split(".")
            if len(parts) >= 2:
                domains.add(".".join(parts[-2:]))
    existing = APPS_DIR / f"{app_id}.yaml"
    if existing.exists():
        app_data = load_app(existing)
        for hp in app_data.get("iocs", {}).get("network", {}).get("hostname_patterns", []):
            parts = hp.get("pattern", "").split(".")
            if len(parts) >= 2:
                domains.add(".".join(parts[-2:]))

    for domain in sorted(domains):
        print(f"[crt.sh] Querying *.{domain}...", file=sys.stderr)
        analysis, suggested = run_crtsh(domain)
        if crtsh_analysis is None:
            crtsh_analysis = analysis
            crtsh_suggested = suggested
        else:
            crtsh_analysis["high_value"].extend(analysis.get("high_value", []))
            crtsh_analysis["standard"].extend(analysis.get("standard", []))
            crtsh_analysis["excluded_shared_infra"].extend(analysis.get("excluded_shared_infra", []))
            crtsh_analysis["total_certs"] += analysis.get("total_certs", 0)
            if crtsh_suggested is not None:
                existing_p = {s["pattern"] for s in crtsh_suggested}
                for s in suggested:
                    if s["pattern"] not in existing_p:
                        crtsh_suggested.append(s)

    quality = assess_quality(host_iocs, network_iocs, crtsh_analysis)
    print(format_full_report(app_id, host_iocs, network_iocs, crtsh_analysis, crtsh_suggested, quality, args.format))

    if args.write_skeleton:
        skeleton = generate_skeleton(app_id, host_iocs, network_iocs, crtsh_suggested)
        path = APPS_DIR / f"{app_id}.yaml"
        if path.exists():
            scratch = APPS_DIR.parent / "scratch"
            scratch.mkdir(exist_ok=True)
            path = scratch / f"{app_id}_research.yaml"
            print(f"[skeleton] App exists — writing to {path}", file=sys.stderr)
        path.write_text(skeleton)
        print(f"[skeleton] Written to {path}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
