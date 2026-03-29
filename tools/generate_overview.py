#!/usr/bin/env python3
"""Generate a self-contained one-page catalog overview."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import datetime
from html import escape
from pathlib import Path
from typing import Any

from app_control.catalog import APPS_DIR, get_ioc_group, load_apps, meets_min_status

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
STATUS_ORDER = {"validated": 0, "reviewed": 1, "draft": 2, "stale": 3, "missing": 4}
SITE_PRIMARY_KINDS = ("official_site", "official_homepage")
SITE_SECONDARY_KINDS = (
    "official_repo",
    "official_marketplace",
    "official_docs",
    "official_support",
    "official_console",
    "official_onboarding",
    "official_tool",
    "official_source",
    "official_page",
    "official_blog",
)
MACHINE_PREFIXES = {
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
HUMAN_LABELS = {"www", "docs", "help", "support"}


def compact_text(value: str | None) -> str:
    return " ".join((value or "").split())


def normalize_site_url(url: str) -> str:
    raw_prefix = "https://raw.githubusercontent.com/"
    if url.startswith(raw_prefix):
        parts = url[len(raw_prefix):].split("/")
        if len(parts) >= 2:
            owner, repo = parts[0], parts[1]
            return f"https://github.com/{owner}/{repo}"
    return url


def prefix_kind(label: str) -> str:
    normalized = label.lower()
    if normalized in HUMAN_LABELS:
        return "human"
    for prefix in MACHINE_PREFIXES:
        if normalized == prefix or normalized.startswith(prefix):
            return "machine"
    return "other"


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

    def is_human_facing_host(host: str) -> bool:
        labels = host.split(".")
        if len(labels) == 2:
            return True
        return prefix_kind(labels[0]) != "machine"

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

    for host in [item for item in sorted(set(hosts), key=host_rank) if is_human_facing_host(item)]:
        return f"https://{host}/"
    return None


def official_site(app: dict[str, Any]) -> str:
    refs = app.get("references") or []

    def first_by_kind(kinds: tuple[str, ...]) -> str | None:
        for expected_kind in kinds:
            for ref in refs:
                kind = (ref.get("kind") or "").lower()
                if kind == expected_kind and ref.get("url"):
                    return ref["url"]
        return None

    selected = (
        first_by_kind(SITE_PRIMARY_KINDS)
        or first_by_kind(("official_repo",))
        or preferred_network_site(app)
        or first_by_kind(SITE_SECONDARY_KINDS)
        or next((ref.get("url") for ref in refs if ref.get("url")), None)
        or ((get_ioc_group(app, "network") or {}).get("provenance") or {}).get("url")
        or ((get_ioc_group(app, "host") or {}).get("provenance") or {}).get("url")
        or ""
    )
    return normalize_site_url(selected)


def count_network_iocs(app: dict[str, Any]) -> int:
    network = get_ioc_group(app, "network") or {}
    return len(network.get("hostname_patterns") or []) + len(network.get("keyword_patterns") or [])


def count_host_iocs(app: dict[str, Any]) -> int:
    host = get_ioc_group(app, "host") or {}
    total = 0
    for field in (
        "paths",
        "bundle_ids",
        "process_names",
        "team_ids",
        "chrome_extension_ids",
        "safari_extension_bundle_ids",
    ):
        total += len(host.get(field) or [])
    return total


def reviewed_coverage(app: dict[str, Any]) -> str:
    network_status = ((get_ioc_group(app, "network") or {}).get("status")) or "missing"
    host_status = ((get_ioc_group(app, "host") or {}).get("status")) or "missing"
    network_ready = meets_min_status(network_status, "reviewed")
    host_ready = meets_min_status(host_status, "reviewed")
    if network_ready and host_ready:
        return "both"
    if network_ready:
        return "network"
    if host_ready:
        return "host"
    return "neither"


def build_rows(apps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for app in apps:
        network = get_ioc_group(app, "network") or {}
        host = get_ioc_group(app, "host") or {}
        rows.append(
            {
                "id": app["id"],
                "name": app["name"],
                "category": app["category"],
                "severity": app["severity"],
                "priority_score": int(app.get("priority_score", 0)),
                "product_shape": list(app.get("product_shape") or []),
                "product_shape_label": ", ".join(app.get("product_shape") or []),
                "product_type_label": ", ".join(app.get("product_type") or []),
                "network_status": network.get("status", "missing"),
                "host_status": host.get("status", "missing"),
                "network_ioc_count": count_network_iocs(app),
                "host_ioc_count": count_host_iocs(app),
                "coverage": reviewed_coverage(app),
                "official_site": official_site(app),
                "notes": compact_text(app.get("notes")),
            }
        )
    rows.sort(
        key=lambda row: (
            -int(row["priority_score"]),
            SEVERITY_ORDER.get(str(row["severity"]), 9),
            str(row["category"]),
            str(row["id"]),
        )
    )
    return rows


def build_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    severity_counts = Counter(str(row["severity"]) for row in rows)
    category_counts = Counter(str(row["category"]) for row in rows)
    network_status_counts = Counter(str(row["network_status"]) for row in rows)
    host_status_counts = Counter(str(row["host_status"]) for row in rows)
    coverage_counts = Counter(str(row["coverage"]) for row in rows)

    macos_count = sum(1 for row in rows if "macos" in row["product_shape"])
    web_count = sum(1 for row in rows if "web" in row["product_shape"])
    high_risk_count = sum(1 for row in rows if row["severity"] in {"high", "critical"})
    claw_count = sum(1 for row in rows if row["category"] == "CLAW_FAMILY_APP")
    validated_both = sum(
        1
        for row in rows
        if meets_min_status(str(row["network_status"]), "validated")
        and meets_min_status(str(row["host_status"]), "validated")
    )
    reviewed_both = sum(
        1
        for row in rows
        if meets_min_status(str(row["network_status"]), "reviewed")
        and meets_min_status(str(row["host_status"]), "reviewed")
    )

    top_priority = rows[:15]
    return {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "source": str(APPS_DIR),
        "total_apps": len(rows),
        "macos_count": macos_count,
        "web_count": web_count,
        "high_risk_count": high_risk_count,
        "claw_count": claw_count,
        "reviewed_both": reviewed_both,
        "validated_both": validated_both,
        "severity_counts": dict(sorted(severity_counts.items(), key=lambda item: SEVERITY_ORDER.get(item[0], 9))),
        "category_counts": dict(sorted(category_counts.items(), key=lambda item: (-item[1], item[0]))),
        "network_status_counts": dict(sorted(network_status_counts.items(), key=lambda item: STATUS_ORDER.get(item[0], 9))),
        "host_status_counts": dict(sorted(host_status_counts.items(), key=lambda item: STATUS_ORDER.get(item[0], 9))),
        "coverage_counts": dict(sorted(coverage_counts.items())),
        "top_priority": top_priority,
    }


def card(title: str, value: str | int, subtitle: str) -> str:
    return (
        '<div class="card">'
        f'<div class="card-title">{escape(title)}</div>'
        f'<div class="card-value">{escape(str(value))}</div>'
        f'<div class="card-subtitle">{escape(subtitle)}</div>'
        '</div>'
    )


def render_simple_table(title: str, columns: tuple[str, str], rows: list[tuple[str, int]]) -> str:
    body = "".join(
        f"<tr><td>{escape(label)}</td><td class=\"num\">{count}</td></tr>" for label, count in rows
    )
    return (
        '<section class="panel">'
        f'<h2>{escape(title)}</h2>'
        '<table class="summary-table">'
        '<thead>'
        f'<tr><th>{escape(columns[0])}</th><th>{escape(columns[1])}</th></tr>'
        '</thead>'
        f'<tbody>{body}</tbody>'
        '</table>'
        '</section>'
    )


def render_top_priority(rows: list[dict[str, Any]]) -> str:
    body = []
    for row in rows:
        site = str(row["official_site"])
        site_cell = f'<a href="{escape(site)}" target="_blank" rel="noreferrer">link</a>' if site else ""
        body.append(
            "<tr>"
            f"<td>{escape(str(row['name']))}</td>"
            f"<td>{escape(str(row['category']))}</td>"
            f"<td><span class=\"sev sev-{escape(str(row['severity']))}\">{escape(str(row['severity']))}</span></td>"
            f"<td class=\"num\">{int(row['priority_score'])}</td>"
            f"<td>{escape(str(row['network_status']))} / {escape(str(row['host_status']))}</td>"
            f"<td>{site_cell}</td>"
            "</tr>"
        )
    return (
        '<section class="panel wide">'
        '<h2>Priority Hotspots</h2>'
        '<table class="summary-table">'
        '<thead><tr><th>Name</th><th>Category</th><th>Severity</th><th>Priority</th><th>IOC Status</th><th>Site</th></tr></thead>'
        f'<tbody>{"".join(body)}</tbody>'
        '</table>'
        '</section>'
    )


def render_html(rows: list[dict[str, Any]], summary: dict[str, Any], title: str) -> str:
    severity_rows = [(key, int(value)) for key, value in summary["severity_counts"].items()]
    category_rows = [(key, int(value)) for key, value in summary["category_counts"].items()]
    network_rows = [(key, int(value)) for key, value in summary["network_status_counts"].items()]
    host_rows = [(key, int(value)) for key, value in summary["host_status_counts"].items()]
    data_json = json.dumps(rows, ensure_ascii=False)
    categories_json = json.dumps(sorted({str(row["category"]) for row in rows}), ensure_ascii=False)
    severities_json = json.dumps(["critical", "high", "medium", "low"], ensure_ascii=False)
    shapes_json = json.dumps(["macos", "web"], ensure_ascii=False)
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{escape(title)}</title>
  <style>
    :root {{
      color-scheme: light dark;
      --bg: #0b1020;
      --panel: #121933;
      --panel-2: #182242;
      --text: #e8ecf8;
      --muted: #9eabd0;
      --border: #2a355d;
      --accent: #6ea8fe;
      --critical: #ff6b6b;
      --high: #ffb86b;
      --medium: #ffd86b;
      --low: #7ee787;
    }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: linear-gradient(180deg, #0b1020, #111831 35%, #0f1730); color: var(--text); }}
    a {{ color: var(--accent); text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
    .container {{ max-width: 1440px; margin: 0 auto; padding: 24px; }}
    .hero {{ display: flex; gap: 20px; justify-content: space-between; align-items: flex-end; flex-wrap: wrap; margin-bottom: 20px; }}
    .hero h1 {{ margin: 0 0 8px; font-size: 34px; }}
    .hero p {{ margin: 4px 0; color: var(--muted); }}
    .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 12px; margin-bottom: 20px; }}
    .card, .panel {{ background: rgba(18,25,51,.92); border: 1px solid var(--border); border-radius: 14px; box-shadow: 0 8px 24px rgba(0,0,0,.22); }}
    .card {{ padding: 16px; }}
    .card-title {{ color: var(--muted); font-size: 13px; text-transform: uppercase; letter-spacing: .05em; }}
    .card-value {{ font-size: 30px; font-weight: 700; margin: 10px 0 6px; }}
    .card-subtitle {{ color: var(--muted); font-size: 13px; }}
    .grid {{ display: grid; grid-template-columns: repeat(12, 1fr); gap: 16px; margin-bottom: 20px; }}
    .panel {{ padding: 16px; overflow: hidden; }}
    .panel h2 {{ margin: 0 0 12px; font-size: 18px; }}
    .panel.wide {{ grid-column: span 12; }}
    .panel.third {{ grid-column: span 4; }}
    .panel.half {{ grid-column: span 6; }}
    .summary-table, .apps-table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ text-align: left; padding: 10px 12px; border-bottom: 1px solid rgba(255,255,255,.08); vertical-align: top; }}
    th {{ color: var(--muted); font-weight: 600; font-size: 13px; }}
    td {{ font-size: 14px; }}
    .num {{ text-align: right; font-variant-numeric: tabular-nums; }}
    .sev {{ display: inline-flex; padding: 3px 8px; border-radius: 999px; font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: .04em; }}
    .sev-critical {{ background: rgba(255,107,107,.15); color: var(--critical); }}
    .sev-high {{ background: rgba(255,184,107,.15); color: var(--high); }}
    .sev-medium {{ background: rgba(255,216,107,.15); color: var(--medium); }}
    .sev-low {{ background: rgba(126,231,135,.15); color: var(--low); }}
    .toolbar {{ display: grid; grid-template-columns: 2fr 1fr 1fr 1fr 1fr; gap: 12px; margin: 14px 0 14px; }}
    input, select {{ width: 100%; background: rgba(255,255,255,.04); color: var(--text); border: 1px solid var(--border); border-radius: 10px; padding: 10px 12px; font: inherit; }}
    .table-wrap {{ overflow: auto; border: 1px solid rgba(255,255,255,.06); border-radius: 12px; }}
    .muted {{ color: var(--muted); }}
    .badge {{ display: inline-flex; align-items: center; gap: 6px; padding: 3px 8px; border: 1px solid var(--border); border-radius: 999px; background: rgba(255,255,255,.03); color: var(--muted); font-size: 12px; }}
    .footer {{ margin-top: 16px; color: var(--muted); font-size: 12px; }}
    @media (max-width: 1100px) {{
      .panel.third, .panel.half {{ grid-column: span 12; }}
      .toolbar {{ grid-template-columns: 1fr 1fr; }}
    }}
    @media (max-width: 720px) {{
      .container {{ padding: 16px; }}
      .toolbar {{ grid-template-columns: 1fr; }}
      th:nth-child(6), td:nth-child(6), th:nth-child(8), td:nth-child(8), th:nth-child(9), td:nth-child(9) {{ display: none; }}
    }}
  </style>
</head>
<body>
  <div class="container">
    <section class="hero">
      <div>
        <h1>{escape(title)}</h1>
        <p>Source: <code>{escape(summary['source'])}</code></p>
        <p>Generated at: {escape(summary['generated_at'])}</p>
      </div>
      <div class="badge">{summary['total_apps']}-row scale friendly · local static HTML · no backend required</div>
    </section>

    <section class="cards">
      {card('Total Apps', summary['total_apps'], 'Catalog rows in apps/')} 
      {card('High Risk+', summary['high_risk_count'], 'critical + high apps')} 
      {card('CLAW Family', summary['claw_count'], 'category = CLAW_FAMILY_APP')} 
      {card('macOS Surface', summary['macos_count'], 'apps with macos in product_shape')} 
      {card('Web Surface', summary['web_count'], 'apps with web in product_shape')} 
      {card('Reviewed Both', summary['reviewed_both'], 'network + host at reviewed or validated')} 
      {card('Validated Both', summary['validated_both'], 'network + host both validated')} 
    </section>

    <section class="grid">
      <div class="panel third">
        <h2>Severity Mix</h2>
        <table class="summary-table"><thead><tr><th>Severity</th><th class="num">Apps</th></tr></thead><tbody>
          {''.join(f'<tr><td><span class="sev sev-{escape(name)}">{escape(name)}</span></td><td class="num">{count}</td></tr>' for name, count in severity_rows)}
        </tbody></table>
      </div>
      <div class="panel third">
        <h2>IOC Readiness</h2>
        <table class="summary-table"><thead><tr><th>Coverage</th><th class="num">Apps</th></tr></thead><tbody>
          {''.join(f'<tr><td>{escape(name)}</td><td class="num">{count}</td></tr>' for name, count in summary['coverage_counts'].items())}
        </tbody></table>
      </div>
      <div class="panel third">
        <h2>Top Categories</h2>
        <table class="summary-table"><thead><tr><th>Category</th><th class="num">Apps</th></tr></thead><tbody>
          {''.join(f'<tr><td>{escape(name)}</td><td class="num">{count}</td></tr>' for name, count in category_rows[:10])}
        </tbody></table>
      </div>
      <div class="panel half">
        <h2>Network IOC Status</h2>
        <table class="summary-table"><thead><tr><th>Status</th><th class="num">Apps</th></tr></thead><tbody>
          {''.join(f'<tr><td>{escape(name)}</td><td class="num">{count}</td></tr>' for name, count in network_rows)}
        </tbody></table>
      </div>
      <div class="panel half">
        <h2>Host IOC Status</h2>
        <table class="summary-table"><thead><tr><th>Status</th><th class="num">Apps</th></tr></thead><tbody>
          {''.join(f'<tr><td>{escape(name)}</td><td class="num">{count}</td></tr>' for name, count in host_rows)}
        </tbody></table>
      </div>
      {render_top_priority(summary['top_priority'])}
    </section>

    <section class="panel wide">
      <h2>All Apps</h2>
      <p class="muted">Search by name/id/category/type/notes. Filter by severity, category, shape, and reviewed coverage.</p>
      <div class="toolbar">
        <input id="search" type="search" placeholder="Search apps, categories, notes, site...">
        <select id="severity"><option value="">All severities</option></select>
        <select id="category"><option value="">All categories</option></select>
        <select id="shape"><option value="">All shapes</option></select>
        <select id="coverage"><option value="">All reviewed coverage</option><option value="both">both</option><option value="network">network</option><option value="host">host</option><option value="neither">neither</option></select>
      </div>
      <div class="muted" id="result-count"></div>
      <div class="table-wrap">
        <table class="apps-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>ID</th>
              <th>Category</th>
              <th>Severity</th>
              <th class="num">Priority</th>
              <th>Shape</th>
              <th>Network / Host</th>
              <th class="num">Net IOC</th>
              <th class="num">Host IOC</th>
              <th>Site</th>
            </tr>
          </thead>
          <tbody id="apps-body"></tbody>
        </table>
      </div>
      <div class="footer">Tip: open this file directly in a browser, or regenerate it after catalog updates.</div>
    </section>
  </div>

  <script>
    const APPS = {data_json};
    const CATEGORIES = {categories_json};
    const SEVERITIES = {severities_json};
    const SHAPES = {shapes_json};

    const searchInput = document.getElementById('search');
    const severitySelect = document.getElementById('severity');
    const categorySelect = document.getElementById('category');
    const shapeSelect = document.getElementById('shape');
    const coverageSelect = document.getElementById('coverage');
    const body = document.getElementById('apps-body');
    const resultCount = document.getElementById('result-count');

    function fillOptions(select, values) {{
      values.forEach(value => {{
        const option = document.createElement('option');
        option.value = value;
        option.textContent = value;
        select.appendChild(option);
      }});
    }}

    fillOptions(severitySelect, SEVERITIES);
    fillOptions(categorySelect, CATEGORIES);
    fillOptions(shapeSelect, SHAPES);

    function severityChip(value) {{
      return `<span class="sev sev-${{value}}">${{value}}</span>`;
    }}

    function matches(row) {{
      const query = searchInput.value.trim().toLowerCase();
      const severity = severitySelect.value;
      const category = categorySelect.value;
      const shape = shapeSelect.value;
      const coverage = coverageSelect.value;
      const haystack = [
        row.name,
        row.id,
        row.category,
        row.product_type_label,
        row.product_shape_label,
        row.notes,
        row.official_site,
      ].join(' ').toLowerCase();
      if (query && !haystack.includes(query)) return false;
      if (severity && row.severity !== severity) return false;
      if (category && row.category !== category) return false;
      if (shape && !row.product_shape.includes(shape)) return false;
      if (coverage && row.coverage !== coverage) return false;
      return true;
    }}

    function render() {{
      const filtered = APPS.filter(matches);
      resultCount.textContent = `${{filtered.length}} / ${{APPS.length}} apps shown`;
      body.innerHTML = filtered.map(row => {{
        const site = row.official_site ? `<a href="${{row.official_site}}" target="_blank" rel="noreferrer">open</a>` : '';
        return `<tr>
          <td>${{row.name}}</td>
          <td><code>${{row.id}}</code></td>
          <td>${{row.category}}</td>
          <td>${{severityChip(row.severity)}}</td>
          <td class="num">${{row.priority_score}}</td>
          <td>${{row.product_shape_label}}</td>
          <td>${{row.network_status}} / ${{row.host_status}}</td>
          <td class="num">${{row.network_ioc_count}}</td>
          <td class="num">${{row.host_ioc_count}}</td>
          <td>${{site}}</td>
        </tr>`;
      }}).join('');
    }}

    [searchInput, severitySelect, categorySelect, shapeSelect, coverageSelect].forEach(node => {{
      node.addEventListener('input', render);
      node.addEventListener('change', render);
    }});

    render();
  </script>
</body>
</html>
"""


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a one-page catalog overview as static HTML")
    parser.add_argument(
        "--output",
        default="output/apps_overview.html",
        help="Write output to this file path (default: output/apps_overview.html)",
    )
    parser.add_argument(
        "--title",
        default="Enterprise App Control Catalog Overview",
        help="Page title (default: Enterprise App Control Catalog Overview)",
    )
    args = parser.parse_args()

    rows = build_rows(load_apps())
    summary = build_summary(rows)
    output = render_html(rows, summary, args.title)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(output, encoding="utf-8")
    print(f"overview -> {output_path} | apps={len(rows)}")


if __name__ == "__main__":
    main()
