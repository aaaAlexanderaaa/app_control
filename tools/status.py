#!/usr/bin/env python3
"""Report coverage and status breakdown across all app YAML files."""

from __future__ import annotations

from collections import Counter

from app_control.catalog import load_apps


def main() -> int:
    apps = load_apps()
    if not apps:
        print("No app files found.")
        return 1

    total = len(apps)
    severity_counts: Counter[str] = Counter()
    category_counts: Counter[str] = Counter()
    net_status: Counter[str] = Counter()
    host_status: Counter[str] = Counter()
    has_network = 0
    has_host = 0
    has_neither = 0

    for app in apps:
        severity_counts[app.get("severity", "unknown")] += 1
        category_counts[app.get("category", "unknown")] += 1

        iocs = app.get("iocs", {})
        net = iocs.get("network")
        host = iocs.get("host")

        if net:
            has_network += 1
            net_status[net.get("status", "unknown")] += 1
        if host:
            has_host += 1
            host_status[host.get("status", "unknown")] += 1
        if not net and not host:
            has_neither += 1

    print("=== App Control Catalog Status ===\n")
    print(f"Total apps: {total}\n")

    print("Severity:")
    for severity in ("critical", "high", "medium", "low"):
        count = severity_counts.get(severity, 0)
        if count:
            print(f"  {severity:10s}  {count:4d}  ({100 * count / total:.0f}%)")

    print("\nIOC coverage:")
    print(f"  network IOCs:  {has_network:4d}  ({100 * has_network / total:.0f}%)")
    print(f"  host IOCs:     {has_host:4d}  ({100 * has_host / total:.0f}%)")
    print(f"  neither:       {has_neither:4d}  ({100 * has_neither / total:.0f}%)")

    print("\nNetwork IOC status:")
    for status in ("draft", "reviewed", "validated", "stale"):
        count = net_status.get(status, 0)
        if count:
            print(f"  {status:12s}  {count:4d}")

    print("\nHost IOC status:")
    for status in ("draft", "reviewed", "validated", "stale"):
        count = host_status.get(status, 0)
        if count:
            print(f"  {status:12s}  {count:4d}")

    net_ready = net_status.get("validated", 0)
    host_ready = host_status.get("validated", 0)
    net_canary = net_ready + net_status.get("reviewed", 0)
    host_canary = host_ready + host_status.get("reviewed", 0)
    print("\nRule generation readiness:")
    print(f"  Network (validated):  {net_ready:4d} apps ready for production ES|QL")
    print(f"  Network (reviewed+):  {net_canary:4d} apps available for canary ES|QL")
    print(f"  Host (validated):     {host_ready:4d} apps ready for production Jamf scan")
    print(f"  Host (reviewed+):     {host_canary:4d} apps available for canary Jamf scan")

    print("\nCategory breakdown:")
    for category, count in sorted(category_counts.items(), key=lambda item: -item[1]):
        print(f"  {category:30s}  {count:4d}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
