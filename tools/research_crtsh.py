#!/usr/bin/env python3
"""Discover subdomains via Certificate Transparency logs (crt.sh).

Queries crt.sh for certificates issued to a given domain, extracts
subdomains, and filters for IoC-relevant patterns while excluding
shared CDN infrastructure.

Usage:
    app-control research-crtsh --domain cursor.sh
    app-control research-crtsh --domain cursor.sh --format json
    app-control research-crtsh --domain cursor.sh --app cursor
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from datetime import date
from typing import Any

TODAY = date.today().isoformat()

CRTSH_API = "https://crt.sh/?q=%.{domain}&output=json"

# Subdomains matching these patterns are high-value IoC candidates
IOC_RELEVANT_PREFIXES = {
    "api", "telemetry", "metrics", "analytics", "tracking",
    "update", "updates", "appcast", "autoupdate", "sparkle",
    "auth", "login", "sso", "oauth", "authenticate",
    "license", "activation", "register",
    "cdn", "static", "assets", "download", "downloads",
    "ws", "wss", "realtime", "socket", "push",
    "app", "portal", "dashboard", "console",
}

# Domains belonging to shared infrastructure providers — not app-exclusive
SHARED_INFRA_SUFFIXES = frozenset({
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


def _is_shared_infra(domain: str) -> bool:
    for suffix in SHARED_INFRA_SUFFIXES:
        if domain == suffix or domain.endswith("." + suffix):
            return True
    return False


def _extract_prefix(subdomain: str, base_domain: str) -> str | None:
    """Return the leftmost label before the base domain."""
    if subdomain == base_domain:
        return None
    suffix = "." + base_domain
    if subdomain.endswith(suffix):
        prefix = subdomain[: -len(suffix)]
        return prefix.split(".")[-1]
    return None


def _classify_subdomain(subdomain: str, base_domain: str) -> str:
    """Classify a subdomain by its IoC relevance."""
    prefix = _extract_prefix(subdomain, base_domain)
    if prefix and prefix.lower() in IOC_RELEVANT_PREFIXES:
        return "high_value"
    if prefix and any(kw in prefix.lower() for kw in ("api", "telemetry", "auth", "update", "license")):
        return "high_value"
    return "standard"


def query_crtsh(domain: str) -> list[str]:
    """Query crt.sh and return deduplicated subdomain list."""
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
            name = name.strip().lower()
            name = name.lstrip("*.")
            if name and not name.startswith("."):
                subdomains.add(name)

    return sorted(subdomains)


def analyze_subdomains(
    subdomains: list[str],
    base_domain: str,
) -> dict[str, Any]:
    """Classify subdomains into IoC candidates."""
    high_value: list[dict[str, str]] = []
    standard: list[dict[str, str]] = []
    excluded_shared: list[str] = []

    for sub in subdomains:
        if _is_shared_infra(sub):
            excluded_shared.append(sub)
            continue

        classification = _classify_subdomain(sub, base_domain)
        entry = {"subdomain": sub, "classification": classification}

        if classification == "high_value":
            high_value.append(entry)
        else:
            standard.append(entry)

    return {
        "base_domain": base_domain,
        "total_certs": len(subdomains),
        "high_value": high_value,
        "standard": standard,
        "excluded_shared_infra": excluded_shared,
    }


def suggest_hostname_patterns(
    analysis: dict[str, Any],
    base_domain: str,
) -> list[dict[str, str]]:
    """Generate suggested hostname_patterns entries from crt.sh results."""
    patterns: list[dict[str, str]] = []

    patterns.append({
        "pattern": base_domain,
        "match": "suffix",
        "role": "app_brand",
        "source": "base_domain",
    })

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
        patterns.append({
            "pattern": sub,
            "match": "exact",
            "role": role,
            "source": "crt.sh_high_value",
        })

    return patterns


def format_report(
    base_domain: str,
    analysis: dict[str, Any],
    suggested: list[dict[str, str]],
    app_id: str | None,
    output_format: str = "text",
) -> str:
    if output_format == "json":
        return json.dumps({
            "app_id": app_id,
            "base_domain": base_domain,
            "researched_at": TODAY,
            "analysis": analysis,
            "suggested_patterns": suggested,
        }, indent=2)

    lines = [
        f"═══ crt.sh Research: {base_domain} ═══",
        f"Date: {TODAY}",
        f"Total unique subdomains found: {analysis['total_certs']}",
        "",
    ]

    if analysis["high_value"]:
        lines.append(f"── High-Value Subdomains ({len(analysis['high_value'])}) ──")
        for entry in analysis["high_value"]:
            lines.append(f"  ★ {entry['subdomain']}")
        lines.append("")

    if analysis["standard"]:
        lines.append(f"── Standard Subdomains ({len(analysis['standard'])}) ──")
        for entry in analysis["standard"]:
            lines.append(f"    {entry['subdomain']}")
        lines.append("")

    if analysis["excluded_shared_infra"]:
        lines.append(f"── Excluded (shared infra) ({len(analysis['excluded_shared_infra'])}) ──")
        for d in analysis["excluded_shared_infra"]:
            lines.append(f"  ✗ {d}")
        lines.append("")

    if suggested:
        lines.append("── Suggested hostname_patterns ──")
        for sp in suggested:
            lines.append(f"  - pattern: {sp['pattern']:40s}  match: {sp['match']:6s}  role: {sp['role']:16s}  (from {sp['source']})")
        lines.append("")

    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Discover subdomains via crt.sh Certificate Transparency logs.",
    )
    parser.add_argument("--domain", type=str, required=True, help="Base domain to query (e.g., cursor.sh)")
    parser.add_argument("--app", type=str, help="App ID for context labeling")
    parser.add_argument("--format", type=str, choices=("text", "json"), default="text")
    args = parser.parse_args()

    domain = args.domain.lower().strip()

    print(f"Querying crt.sh for *.{domain}...", file=sys.stderr)
    subdomains = query_crtsh(domain)

    if not subdomains:
        print(f"No certificates found for {domain}", file=sys.stderr)
        return 0

    analysis = analyze_subdomains(subdomains, domain)
    suggested = suggest_hostname_patterns(analysis, domain)
    report = format_report(domain, analysis, suggested, args.app, args.format)
    print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
