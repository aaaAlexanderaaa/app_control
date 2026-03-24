#!/usr/bin/env python3
"""Research host and network IoCs from Homebrew cask/formula metadata.

This tool fetches structured data from the Homebrew Formulae JSON API and
(for formulas) the Ruby source on GitHub, then extracts IoC candidates with
full provenance.  It is designed to be called early in the app analysis
pipeline so that the mechanical extraction is done once and the results can
be reviewed by a human or downstream tool.

Usage:
    app-control research-homebrew --app cursor
    app-control research-homebrew --token cursor --type cask
    app-control research-homebrew --token aider --type formula
    app-control research-homebrew --list-known
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

APPS_DIR = Path(__file__).resolve().parent.parent / "apps"
TODAY = date.today().isoformat()

BREW_API_CASK = "https://formulae.brew.sh/api/cask/{token}.json"
BREW_API_FORMULA = "https://formulae.brew.sh/api/formula/{token}.json"
BREW_CASK_RAW = "https://raw.githubusercontent.com/Homebrew/homebrew-cask/master/Casks/{prefix}/{token}.rb"
BREW_FORMULA_RAW = "https://raw.githubusercontent.com/Homebrew/homebrew-core/master/Formula/{prefix}/{token}.rb"

KNOWN_MAP: dict[str, tuple[str, str]] = {
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


def _ruby_source_url(brew_type: str, token: str) -> str:
    prefix = token[0]
    if brew_type == "cask":
        return BREW_CASK_RAW.format(prefix=prefix, token=token)
    return BREW_FORMULA_RAW.format(prefix=prefix, token=token)


# ── Host IoC extraction ────────────────────────────────────────────────

def extract_cask_host_iocs(data: dict, token: str) -> dict[str, Any]:
    """Extract host IoC candidates from cask JSON artifacts."""
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


def extract_formula_host_iocs(ruby_source: str | None, token: str) -> dict[str, Any]:
    """Extract host IoC candidates from formula Ruby source.

    Parses the ``def install`` block for ``bin.install``, ``prefix.install``,
    ``etc.install``, ``mkdir``, and ``ln_s`` targets.
    """
    paths = [
        f"/opt/homebrew/bin/{token}",
        f"/usr/local/bin/{token}",
    ]
    extra_paths: list[str] = []

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
                if m:
                    name = m.group(1)
                    if name != token:
                        extra_paths.append(f"/opt/homebrew/bin/{name}")
                        extra_paths.append(f"/usr/local/bin/{name}")
                m2 = re.search(r'"([^"]+)"\s*=>\s*"([^"]+)"', stripped)
                if m2:
                    target = m2.group(2)
                    if target != token:
                        extra_paths.append(f"/opt/homebrew/bin/{target}")
                        extra_paths.append(f"/usr/local/bin/{target}")

            if "etc.install" in stripped or "prefix.install" in stripped:
                m = re.search(r'(?:etc|prefix)\.install\s+"([^"]+)"', stripped)
                if m:
                    extra_paths.append(f"/opt/homebrew/etc/{m.group(1)}")

    paths.extend(extra_paths)

    return {
        "paths": paths,
        "bundle_ids": [],
        "provenance_url": BREW_API_FORMULA.format(token=token),
        "evidence": "Homebrew formula binary installation paths and def install block",
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


# ── Network IoC extraction ─────────────────────────────────────────────

SHARED_CDN_SUFFIXES = {
    "cloudfront.net", "akamai.net", "akamaized.net", "edgekey.net",
    "fastly.net", "cloudflare.com", "cdn.cloudflare.net",
    "azureedge.net", "googleapis.com", "gstatic.com",
    "amazonaws.com", "s3.amazonaws.com",
}

SHARED_HOSTING_EXACT = {
    "github.com", "raw.githubusercontent.com", "objects.githubusercontent.com",
    "codeload.github.com", "ghcr.io",
    "pypi.org", "files.pythonhosted.org",
    "registry.npmjs.org", "npmjs.com",
    "crates.io", "static.crates.io",
    "proxy.golang.org", "sum.golang.org",
    "rubygems.org", "api.rubygems.org",
    "dl.google.com", "storage.googleapis.com",
    "download.docker.com", "registry.hub.docker.com",
}


def _is_shared_cdn(domain: str) -> bool:
    if domain in SHARED_HOSTING_EXACT:
        return True
    for suffix in SHARED_CDN_SUFFIXES:
        if domain == suffix or domain.endswith("." + suffix):
            return True
    return False


def extract_cask_network_iocs(data: dict, token: str) -> dict[str, Any]:
    """Extract network IoC candidates from cask metadata.

    Sources: ``url`` (download), ``appcast`` (update check), ``homepage``.
    """
    domains: dict[str, str] = {}

    homepage = data.get("homepage", "")
    if homepage:
        parsed = urlparse(homepage)
        if parsed.hostname:
            domains[parsed.hostname] = "app_brand"

    url_field = data.get("url", "")
    if url_field:
        parsed = urlparse(url_field)
        if parsed.hostname and not _is_shared_cdn(parsed.hostname):
            domains[parsed.hostname] = "file_download"

    appcast = data.get("appcast", "")
    if appcast:
        parsed = urlparse(appcast)
        if parsed.hostname and not _is_shared_cdn(parsed.hostname):
            domains[parsed.hostname] = "app_brand"

    auto_updates = data.get("auto_updates")
    livecheck = data.get("livecheck", {})
    if isinstance(livecheck, dict) and livecheck.get("url"):
        parsed = urlparse(livecheck["url"])
        if parsed.hostname and not _is_shared_cdn(parsed.hostname):
            domains[parsed.hostname] = "app_brand"

    hostname_patterns = []
    for domain, role in sorted(domains.items()):
        hostname_patterns.append({
            "pattern": domain,
            "match": "exact",
            "role": role,
        })

    return {
        "hostname_patterns": hostname_patterns,
        "provenance_url": BREW_API_CASK.format(token=token),
        "evidence": f"Homebrew cask homepage, download URL, and appcast/livecheck fields for {token}",
    }


def extract_formula_network_iocs(data: dict, ruby_source: str | None, token: str) -> dict[str, Any]:
    """Extract network IoC candidates from formula metadata + Ruby source."""
    domains: dict[str, str] = {}

    homepage = data.get("homepage", "")
    if homepage:
        parsed = urlparse(homepage)
        if parsed.hostname:
            domains[parsed.hostname] = "app_brand"

    for stable in (data.get("urls", {}).get("stable", {}),):
        url = stable.get("url", "") if isinstance(stable, dict) else ""
        if url:
            parsed = urlparse(url)
            if parsed.hostname and not _is_shared_cdn(parsed.hostname):
                domains[parsed.hostname] = "file_download"

    if ruby_source:
        for m in re.finditer(r'https?://([a-zA-Z0-9._-]+\.[a-zA-Z]{2,})', ruby_source):
            host = m.group(1).lower()
            if not _is_shared_cdn(host) and host not in domains:
                domains[host] = "app_brand"

    hostname_patterns = []
    for domain, role in sorted(domains.items()):
        hostname_patterns.append({
            "pattern": domain,
            "match": "exact",
            "role": role,
        })

    return {
        "hostname_patterns": hostname_patterns,
        "provenance_url": BREW_API_FORMULA.format(token=token),
        "evidence": f"Homebrew formula homepage, source URL, and Ruby source URLs for {token}",
    }


# ── Output formatting ──────────────────────────────────────────────────

def format_report(
    app_id: str,
    brew_type: str,
    token: str,
    host_iocs: dict[str, Any],
    network_iocs: dict[str, Any],
    output_format: str = "text",
) -> str:
    if output_format == "json":
        return json.dumps({
            "app_id": app_id,
            "brew_type": brew_type,
            "brew_token": token,
            "researched_at": TODAY,
            "host": host_iocs,
            "network": network_iocs,
        }, indent=2)

    lines = [
        f"═══ Homebrew Research: {app_id} ({brew_type}:{token}) ═══",
        f"Date: {TODAY}",
        "",
        "── Host IoC Candidates ──",
        f"  Provenance: {host_iocs['provenance_url']}",
        f"  Evidence:   {host_iocs['evidence']}",
    ]
    if host_iocs.get("paths"):
        lines.append("  Paths:")
        for p in host_iocs["paths"]:
            lines.append(f"    - {p}")
    if host_iocs.get("bundle_ids"):
        lines.append("  Bundle IDs:")
        for b in host_iocs["bundle_ids"]:
            lines.append(f"    - {b}")
    if not host_iocs.get("paths") and not host_iocs.get("bundle_ids"):
        lines.append("  (no host IoCs extracted)")

    lines.append("")
    lines.append("── Network IoC Candidates ──")
    lines.append(f"  Provenance: {network_iocs['provenance_url']}")
    lines.append(f"  Evidence:   {network_iocs['evidence']}")
    if network_iocs.get("hostname_patterns"):
        lines.append("  Hostname patterns:")
        for hp in network_iocs["hostname_patterns"]:
            lines.append(f"    - {hp['pattern']:40s}  match={hp['match']:6s}  role={hp['role']}")
    else:
        lines.append("  (no network IoCs extracted)")

    lines.append("")
    return "\n".join(lines)


# ── Main ────────────────────────────────────────────────────────────────

def research_app(app_id: str | None, brew_type: str | None, token: str | None, output_format: str = "text") -> str:
    """Run the full Homebrew research pipeline for one app."""
    if app_id and app_id in KNOWN_MAP and not token:
        brew_type, token = KNOWN_MAP[app_id]
    elif not brew_type or not token:
        return f"ERROR: app '{app_id}' not in known map; provide --type and --token explicitly"

    if not app_id:
        app_id = token.replace("-", "_")

    if brew_type == "cask":
        data = _fetch_json(BREW_API_CASK.format(token=token))
        if not data:
            return f"ERROR: could not fetch cask data for {token}"
        host_iocs = extract_cask_host_iocs(data, token)
        network_iocs = extract_cask_network_iocs(data, token)
    else:
        data = _fetch_json(BREW_API_FORMULA.format(token=token))
        if not data:
            return f"ERROR: could not fetch formula data for {token}"
        ruby_url = _ruby_source_url("formula", token)
        ruby_source = _fetch_text(ruby_url)
        host_iocs = extract_formula_host_iocs(ruby_source, token)
        network_iocs = extract_formula_network_iocs(data, ruby_source, token)

    return format_report(app_id, brew_type, token, host_iocs, network_iocs, output_format)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Research host and network IoCs from Homebrew cask/formula metadata.",
    )
    parser.add_argument("--app", type=str, help="App ID from the catalog (looks up in known map)")
    parser.add_argument("--token", type=str, help="Homebrew cask or formula token")
    parser.add_argument("--type", type=str, choices=("cask", "formula"), help="Homebrew package type")
    parser.add_argument("--format", type=str, choices=("text", "json"), default="text", help="Output format")
    parser.add_argument("--list-known", action="store_true", help="List all known app→Homebrew mappings")
    args = parser.parse_args()

    if args.list_known:
        print(f"{'App ID':40s}  {'Type':8s}  Token")
        print("-" * 72)
        for app_id, (btype, btok) in sorted(KNOWN_MAP.items()):
            print(f"{app_id:40s}  {btype:8s}  {btok}")
        return 0

    if not args.app and not args.token:
        parser.error("provide --app or --token (or --list-known)")

    result = research_app(args.app, args.type, args.token, args.format)
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
