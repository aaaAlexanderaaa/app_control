#!/usr/bin/env python3
"""Generate ES|QL network detection rules from app YAML files.

Only includes apps whose network IOC group meets the --min-status threshold.
Optionally filters to a specific app category.
"""

from __future__ import annotations

import argparse
import re
import sys
from datetime import date

from app_control.catalog import filter_apps_with_ioc_group

GENERIC_HOST_LABELS = {
    "api",
    "app",
    "apps",
    "assets",
    "auth",
    "beta",
    "cdn",
    "cloud",
    "console",
    "desktop",
    "dev",
    "docs",
    "download",
    "downloads",
    "files",
    "github",
    "help",
    "hub",
    "img",
    "m",
    "platform",
    "portal",
    "prod",
    "production",
    "service",
    "static",
    "support",
    "update",
    "updates",
    "www",
}

GENERIC_PREFILTER_TOKENS = {
    "agent",
    "agents",
    "ai",
    "app",
    "apps",
    "bot",
    "chat",
    "claw",
    "cli",
    "cloud",
    "code",
    "desktop",
    "dev",
    "file",
    "files",
    "home",
    "internal",
    "labs",
    "local",
    "mac",
    "office",
    "service",
    "studio",
    "space",
    "tool",
    "tools",
    "web",
    "www",
}


class NetworkIOCConflictError(ValueError):
    """Raised when multiple apps claim the same network IOC."""


def load_apps(min_status: str, category: str | None = None) -> list[dict]:
    return filter_apps_with_ioc_group("network", min_status=min_status, category=category)


def escape_esql(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def escape_regex(value: str) -> str:
    return re.escape(value)


def build_case_conditions(net: dict) -> list[str]:
    patterns = net.get("hostname_patterns", [])
    keywords = net.get("keyword_patterns", [])
    conditions: list[str] = []

    exact = [pattern["pattern"] for pattern in patterns if pattern["match"] == "exact"]
    for exact_match in exact:
        conditions.append(f'observed_domain == "{escape_esql(exact_match)}"')

    suffix = [pattern["pattern"] for pattern in patterns if pattern["match"] == "suffix"]
    for suffix_match in suffix:
        conditions.append(
            f'(observed_domain == "{escape_esql(suffix_match)}" '
            f'OR observed_domain LIKE "*.{escape_esql(suffix_match)}")'
        )

    for keyword_pattern in keywords:
        pattern = keyword_pattern["pattern"]
        if keyword_pattern["match"] == "substring":
            escaped = escape_esql(pattern)
            if not any(char.isspace() for char in pattern):
                conditions.append(f'observed_domain LIKE "*{escaped}*"')
            conditions.append(f'apps_lower LIKE "*{escaped}*"')
        elif keyword_pattern["match"] == "regex":
            escaped = escape_esql(pattern)
            conditions.append(f'observed_domain RLIKE "{escaped}"')
            conditions.append(f'apps_lower RLIKE "{escaped}"')

    return conditions


def tokenize_hostname_pattern(pattern: str) -> list[str]:
    tokens: list[str] = []
    for label in re.split(r"[^a-z0-9]+", pattern.lower()):
        if len(label) < 4:
            continue
        if label in GENERIC_HOST_LABELS or label in GENERIC_PREFILTER_TOKENS:
            continue
        tokens.append(label)
    return tokens


def collect_app_prefilter_terms(app: dict) -> set[str]:
    terms: set[str] = set()
    net = app["iocs"]["network"]
    for item in net.get("hostname_patterns", []):
        if item.get("role") in {"file_download", "file_upload", "platform_service", "cdn_static"}:
            continue
        terms.update(tokenize_hostname_pattern(item["pattern"]))
    for item in net.get("keyword_patterns", []):
        if item["match"] != "substring":
            continue
        for token in re.split(r"[^a-z0-9]+", item["pattern"].lower()):
            if len(token) < 4:
                continue
            if token in GENERIC_PREFILTER_TOKENS:
                continue
            terms.add(token)
    return terms


def build_prefilter_terms(apps: list[dict]) -> list[str]:
    terms_by_app: dict[str, set[str]] = {}
    term_owners: dict[str, set[str]] = {}

    for app in apps:
        app_terms = collect_app_prefilter_terms(app)
        terms_by_app[app["id"]] = app_terms
        for term in app_terms:
            term_owners.setdefault(term, set()).add(app["id"])

    selected: set[str] = set()
    for term, owners in term_owners.items():
        if len(owners) <= 4 or len(term) >= 9:
            selected.add(term)

    for app in apps:
        app_terms = sorted(terms_by_app.get(app["id"], set()), key=lambda value: (-len(value), value))
        if any(term in selected for term in app_terms):
            continue
        selected.update(app_terms[:2])

    return sorted(selected, key=lambda value: (len(value), value))


def build_prefilter_regex(terms: list[str]) -> str | None:
    if not terms:
        return None
    return "|".join(escape_regex(term) for term in terms)


def find_shared_network_iocs(apps: list[dict]) -> list[str]:
    claims: dict[tuple[str, str, str], set[str]] = {}

    for app in apps:
        net = app["iocs"]["network"]
        for item in net.get("hostname_patterns", []):
            key = ("hostname", item["match"], item["pattern"])
            claims.setdefault(key, set()).add(app["id"])
        for item in net.get("keyword_patterns", []):
            key = ("keyword", item["match"], item["pattern"])
            claims.setdefault(key, set()).add(app["id"])

    conflicts: list[str] = []
    for (kind, match, pattern), owners in sorted(claims.items()):
        if len(owners) <= 1:
            continue
        owners_text = ", ".join(sorted(owners))
        conflicts.append(f"{kind}:{match}:{pattern} claimed by {owners_text}")
    return conflicts


def ensure_no_shared_network_iocs(apps: list[dict]) -> None:
    conflicts = find_shared_network_iocs(apps)
    if not conflicts:
        return

    details = "\n".join(f"- {conflict}" for conflict in conflicts)
    raise NetworkIOCConflictError(
        "Shared network IOCs must be resolved before ES|QL generation:\n"
        f"{details}"
    )


def build_prefilter_clause(apps: list[dict]) -> str | None:
    terms_by_app: dict[str, set[str]] = {}
    for app in apps:
        terms_by_app[app["id"]] = collect_app_prefilter_terms(app)

    selected_terms = build_prefilter_terms(apps)
    regex = build_prefilter_regex(selected_terms)
    clauses: list[str] = []

    if regex:
        escaped_regex = escape_esql(regex)
        clauses.append(
            f'(observed_domain RLIKE ".*({escaped_regex}).*" OR apps_lower RLIKE ".*({escaped_regex}).*")'
        )

    selected_term_set = set(selected_terms)
    for app in apps:
        app_terms = terms_by_app[app["id"]]
        if app_terms and app_terms & selected_term_set:
            continue

        conditions = build_case_conditions(app["iocs"]["network"])
        if not conditions:
            continue
        clauses.append("(" + " OR ".join(conditions) + ")")

    if not clauses:
        return None
    return " OR ".join(clauses)


def generate_esql(apps: list[dict], min_status: str, category: str | None = None) -> str:
    ensure_no_shared_network_iocs(apps)

    lines: list[str] = []
    lines.append(f"// Auto-generated by esql_rules.py on {date.today().isoformat()}")
    lines.append(f"// Minimum IOC status: {min_status}")
    if category:
        lines.append(f"// Category filter: {category}")
    lines.append(f"// Apps included: {len(apps)}")
    lines.append("")
    lines.append("// --- Network detection: hostname + keyword matching ---")
    lines.append("")
    lines.append('| EVAL domain_lower = TO_LOWER(COALESCE(dns.question.name, tls.client.server_name, url.domain, ""))')
    lines.append("")

    case_clauses: list[str] = []
    for app in apps:
        app_id = app["id"]
        app_name = app["name"]
        net = app["iocs"]["network"]
        conditions = [condition.replace("observed_domain", "domain_lower") for condition in build_case_conditions(net)]

        if conditions:
            joined = "\n    OR ".join(conditions)
            case_clauses.append(f'  // {app_name} ({app_id})\n  {joined}, "{escape_esql(app_id)}"')

    lines.append("| EVAL ai_tool = CASE(")
    lines.append(",\n".join(case_clauses))
    lines.append(")")
    lines.append("")
    lines.append("| WHERE ai_tool IS NOT NULL")

    return "\n".join(lines) + "\n"


def generate_optimized_esql(
    apps: list[dict],
    min_status: str,
    category: str | None = None,
    *,
    from_pattern: str = "*",
    aggregate_minutes: int = 1,
    limit: int = 1000,
) -> str:
    ensure_no_shared_network_iocs(apps)

    lines: list[str] = []
    lines.append(f"// Auto-generated by esql_rules.py on {date.today().isoformat()}")
    lines.append(f"// Minimum IOC status: {min_status}")
    if category:
        lines.append(f"// Cohort filter: {category}")
    lines.append(f"// Apps included: {len(apps)}")
    lines.append(f"// Optimized source pattern: {from_pattern}")
    lines.append("")
    lines.append(f"FROM {from_pattern}")
    lines.append('| WHERE network.direction IS NULL OR network.direction != "internal"')
    lines.append("| WHERE network.bytes IS NOT NULL")
    lines.append(
        "| KEEP @timestamp, dns.question.name, tls.client.server_name, url.domain, "
        "network.application, network.bytes, source.bytes, destination.bytes, source.ip, destination.ip"
    )
    lines.append("")
    lines.append(
        '| EVAL observed_domain = TO_LOWER(COALESCE(url.domain, tls.client.server_name, dns.question.name, ""))'
    )
    lines.append('| EVAL apps_lower = TO_LOWER(TO_STRING(COALESCE(network.application, "")))')

    prefilter_clause = build_prefilter_clause(apps)
    if prefilter_clause:
        lines.append("")
        lines.append(f"| WHERE {prefilter_clause}")

    lines.append("")
    case_clauses: list[str] = []
    for app in apps:
        app_id = app["id"]
        app_name = app["name"]
        conditions = build_case_conditions(app["iocs"]["network"])
        if not conditions:
            continue
        joined = "\n    OR ".join(conditions)
        case_clauses.append(f'  // {app_name} ({app_id})\n  {joined}, "{escape_esql(app_id)}"')

    lines.append("| EVAL monitored_app = CASE(")
    lines.append(",\n".join(case_clauses))
    lines.append(")")
    lines.append("")
    lines.append("| WHERE monitored_app IS NOT NULL")
    lines.append("| STATS")
    lines.append("    traffic_bytes = SUM(network.bytes),")
    lines.append("    upload_traffic = SUM(COALESCE(source.bytes, 0)),")
    lines.append("    download_traffic = SUM(COALESCE(destination.bytes, 0)) * -1,")
    lines.append("    request_count = COUNT(*),")
    lines.append("    domains = VALUES(observed_domain),")
    lines.append("    raw_apps = VALUES(network.application)")
    lines.append(
        f"  BY time = BUCKET(@timestamp, {aggregate_minutes} minute), monitored_app, source.ip"
    )
    lines.append("| SORT traffic_bytes DESC")
    lines.append(f"| LIMIT {limit}")
    lines.append(
        "| KEEP time, monitored_app, source.ip, upload_traffic, download_traffic, "
        "traffic_bytes, request_count, raw_apps, domains"
    )

    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate ES|QL network detection rules")
    parser.add_argument(
        "--min-status",
        default="validated",
        choices=["draft", "reviewed", "validated"],
        help="Minimum IOC status to include (default: validated)",
    )
    parser.add_argument("--category", default=None, help="Only include apps in the given category")
    args = parser.parse_args()

    apps = load_apps(args.min_status, args.category)
    if not apps:
        suffix = f" in category '{args.category}'" if args.category else ""
        print(f"// No apps meet min-status '{args.min_status}'{suffix}. No rules generated.", file=sys.stderr)
        sys.exit(0)

    try:
        output = generate_esql(apps, args.min_status, args.category)
    except NetworkIOCConflictError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
    sys.stdout.write(output)


if __name__ == "__main__":
    main()
