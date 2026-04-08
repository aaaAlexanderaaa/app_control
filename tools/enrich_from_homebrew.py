#!/usr/bin/env python3
"""Enrich app YAML files with host IOCs from Homebrew Formulae JSON API.

For each app mapped to a Homebrew cask or formula, fetches artifacts data
and generates/updates host IOC sections using only explicit Homebrew API
evidence. The script intentionally avoids heuristic inference such as
deriving process names from app bundle names or bundle IDs from plist paths.

Usage:
    python3 tools/enrich_from_homebrew.py [--dry-run] [--app APP_ID]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from datetime import date
from pathlib import Path
from typing import Optional

APPS_DIR = Path(__file__).resolve().parent.parent / "apps"
TODAY = date.today().isoformat()

# Map app_id -> (type, cask_or_formula_token)
# type: "cask" or "formula"
HOMEBREW_MAP = {
    # Critical
    # Claw-family formulas
    "ironclaw":             ("formula", "ironclaw"),
    "nullclaw":             ("formula", "nullclaw"),
    "nanobot":              ("formula", "nanobot"),

    # High - GENAI_CODING
    "cursor":               ("cask", "cursor"),
    "windsurf":             ("cask", "windsurf"),
    "trae":                 ("cask", "trae"),
    "kiro":                 ("cask", "kiro"),
    "codex_app":            ("cask", "codex"),
    "replit":               ("cask", "replit"),
    "superset_ide":         ("cask", "superset"),
    "aider":                ("formula", "aider"),
    "goose":                ("cask", "block-goose"),

    # High - Cloud storage
    "dropbox":              ("cask", "dropbox"),
    "google_drive":         ("cask", "google-drive"),
    "onedrive":             ("cask", "onedrive"),

    # High - Remote access
    "anydesk":              ("cask", "anydesk"),
    "teamviewer":           ("cask", "teamviewer"),
    "splashtop":            ("cask", "splashtop-business"),

    # High - P2P / file sync
    "qbittorrent":          ("cask", "qbittorrent"),
    "transmission":         ("cask", "transmission"),
    "resilio_sync":         ("cask", "resilio-sync"),
    "syncthing":            ("formula", "syncthing"),

    # High - Other
    "warp":                 ("cask", "warp"),
    "rewind":               ("cask", "rewind"),

    # High - JetBrains (Toolbox is the entry point)
    "jetbrains_ai_assistant": ("cask", "jetbrains-toolbox"),

    # Medium severity apps with Homebrew casks (commonly installed)
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

    # Auto-matched 2026-04-08: bulk Homebrew cask index scan
    "aionui":               ("cask", "aionui"),
    "baidu_netdisk":        ("cask", "baidunetdisk"),
    "boltai":               ("cask", "boltai"),
    "chrome_remote_desktop": ("cask", "chrome-remote-desktop-host"),
    "claude":               ("cask", "claude"),
    "claude_code":          ("cask", "claude-code"),
    "codebuddy":            ("cask", "codebuddy"),
    "comet":                ("cask", "comet"),
    "craft":                ("cask", "craft"),
    "deepl":                ("cask", "deepl"),
    "dia":                  ("cask", "thebrowsercompany-dia"),
    "doubao":               ("cask", "doubao"),
    "dyad":                 ("cask", "dyad"),
    "elephas":              ("cask", "elephas"),
    "evernote":             ("cask", "evernote"),
    "fathom":               ("cask", "fathom"),
    "gpt4all":              ("cask", "gpt4all"),
    "jump_desktop":         ("cask", "jump-desktop"),
    "kimi":                 ("cask", "kimi"),
    "langflow":             ("cask", "langflow"),
    "loom":                 ("cask", "loom"),
    "mega":                 ("cask", "megasync"),
    "openclaw":             ("cask", "openclaw"),
    "opencode":             ("cask", "opencode-desktop"),
    "osaurus":              ("cask", "osaurus"),
    "parsec":               ("cask", "parsec"),
    "poe":                  ("cask", "poe"),
    "proton_drive":         ("cask", "proton-drive"),
    "roam_research":        ("cask", "roam-research"),
    "runway":               ("cask", "runway"),
    "rustdesk":             ("cask", "rustdesk"),
    "seafile":              ("cask", "seafile-client"),
    "send_anywhere":        ("cask", "send-anywhere"),
    "skype":                ("cask", "skype"),
    "slite":                ("cask", "slite"),
    "tencent_docs":         ("cask", "tencent-docs"),
    "tresorit":             ("cask", "tresorit"),
    "void":                 ("cask", "void"),
    "yandex_disk":          ("cask", "yandex-disk"),
    "yuque":                ("cask", "yuque"),
}


def fetch_cask(token: str) -> dict | None:
    """Fetch cask JSON from Homebrew API."""
    url = f"https://formulae.brew.sh/api/cask/{token}.json"
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            return json.loads(resp.read())
    except Exception as e:
        print(f"  WARN: Failed to fetch cask {token}: {e}", file=sys.stderr)
        return None


def fetch_formula(token: str) -> dict | None:
    """Fetch formula JSON from Homebrew API."""
    url = f"https://formulae.brew.sh/api/formula/{token}.json"
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            return json.loads(resp.read())
    except Exception as e:
        print(f"  WARN: Failed to fetch formula {token}: {e}", file=sys.stderr)
        return None


def extract_cask_iocs(data: dict, token: str) -> dict:
    """Extract host IOC fields from explicit cask artifacts only."""
    paths = []
    bundle_ids = set()
    process_names = set()

    artifacts = data.get("artifacts", [])

    for artifact in artifacts:
        if not isinstance(artifact, dict):
            continue

        # App bundles -> /Applications/X.app
        if "app" in artifact:
            for app_entry in artifact["app"]:
                if isinstance(app_entry, str) and app_entry.endswith(".app"):
                    # Handle target renames
                    paths.append(f"/Applications/{app_entry}")
                elif isinstance(app_entry, dict) and "target" in app_entry:
                    paths.append(f"/Applications/{app_entry['target']}")

        # Binary symlinks. The cask explicitly names the target filename.
        if "binary" in artifact:
            for bin_entry in artifact["binary"]:
                if isinstance(bin_entry, dict) and "target" in bin_entry:
                    target = bin_entry["target"]
                    paths.append(f"/opt/homebrew/bin/{target}")
                    paths.append(f"/usr/local/bin/{target}")
                elif isinstance(bin_entry, str):
                    target = Path(bin_entry).name
                    paths.append(f"/opt/homebrew/bin/{target}")
                    paths.append(f"/usr/local/bin/{target}")

        # Pkg installs
        if "pkg" in artifact:
            for pkg_entry in artifact["pkg"]:
                if isinstance(pkg_entry, str):
                    pass  # pkg names aren't directly useful as paths

        # Uninstall stanzas -> bundle IDs, launchctl labels, paths
        for key in ("uninstall", "uninstall_preflight", "uninstall_postflight"):
            if key in artifact:
                items = artifact[key]
                if not isinstance(items, list):
                    items = [items]
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    # quit -> bundle IDs
                    if "quit" in item:
                        quits = item["quit"]
                        if isinstance(quits, str):
                            quits = [quits]
                        for q in quits:
                            bundle_ids.add(q)
                    # launchctl -> launchd labels (also useful as bundle IDs)
                    if "launchctl" in item:
                        lcs = item["launchctl"]
                        if isinstance(lcs, str):
                            lcs = [lcs]
                        for lc in lcs:
                            bundle_ids.add(lc)
                    # delete -> system paths
                    if "delete" in item:
                        dels = item["delete"]
                        if isinstance(dels, str):
                            dels = [dels]
                        for d in dels:
                            if d.startswith("/") and not d.startswith("~"):
                                paths.append(d)

        # Zap stanzas -> user-level paths explicitly declared by the cask
        if "zap" in artifact:
            items = artifact["zap"]
            if not isinstance(items, list):
                items = [items]
            for item in items:
                if not isinstance(item, dict):
                    continue
                for zap_key in ("trash", "rmdir"):
                    if zap_key in item:
                        zap_paths = item[zap_key]
                        if isinstance(zap_paths, str):
                            zap_paths = [zap_paths]
                        for p in zap_paths:
                            paths.append(p)

    # De-duplicate and sort
    # For paths, keep unique important ones
    seen_paths = []
    seen_set = set()
    for p in paths:
        normalized = p.rstrip("/")
        if normalized not in seen_set:
            seen_set.add(normalized)
            seen_paths.append(p)

    provenance_url = f"https://formulae.brew.sh/api/cask/{token}.json"

    return {
        "paths": sorted(seen_paths, key=_path_sort_key),
        "bundle_ids": sorted(bundle_ids),
        "process_names": sorted(process_names),
        "provenance_url": provenance_url,
    }


def extract_formula_iocs(data: dict, token: str) -> dict:
    """Extract host IOC fields from formula data."""
    paths = [
        f"/opt/homebrew/bin/{token}",
        f"/usr/local/bin/{token}",
    ]

    provenance_url = f"https://formulae.brew.sh/api/formula/{token}.json"

    return {
        "paths": paths,
        "bundle_ids": [],
        "process_names": [],
        "provenance_url": provenance_url,
    }


def _path_sort_key(p: str) -> tuple:
    """Sort: /Applications first, /Library second, ~ third."""
    if p.startswith("/Applications"):
        return (0, p)
    if p.startswith("/Library"):
        return (1, p)
    if p.startswith("/opt"):
        return (2, p)
    if p.startswith("~"):
        return (3, p)
    return (4, p)


def build_host_yaml_block(iocs: dict, evidence_detail: str) -> str:
    """Build the YAML text for a host IOC section."""
    lines = []
    lines.append("  host:")
    lines.append("    status: draft")
    lines.append("    provenance:")
    lines.append(f"      url: {iocs['provenance_url']}")
    lines.append(f"      evidence: {evidence_detail}")
    lines.append(f"      checked_at: '{TODAY}'")

    if iocs["paths"]:
        lines.append("    paths:")
        for p in iocs["paths"]:
            lines.append(f"    - {p}")

    if iocs["bundle_ids"]:
        lines.append("    bundle_ids:")
        for b in iocs["bundle_ids"]:
            lines.append(f"    - {b}")

    if iocs["process_names"]:
        lines.append("    process_names:")
        for p in iocs["process_names"]:
            lines.append(f"    - {p}")

    return "\n".join(lines)


def _get_host_status(content: str) -> str | None:
    """Extract the current host IOC status from file content."""
    for line in content.split("\n"):
        stripped = line.strip()
        if stripped.startswith("status:") and "  host:" in content[:content.index(stripped)].split("  host:")[-1]:
            # Crude: find status under host section
            pass
    # More reliable: parse host section
    in_host = False
    for line in content.split("\n"):
        if line.strip() == "" :
            continue
        if re.match(r"  host:", line):
            in_host = True
            continue
        if in_host and line.strip().startswith("status:"):
            return line.strip().split(":")[1].strip()
        if in_host and not line.startswith("    "):
            break
    return None


def update_app_file(app_id: str, brew_type: str, brew_token: str, dry_run: bool = False) -> bool:
    """Fetch Homebrew data and update the app YAML file."""
    yaml_path = APPS_DIR / f"{app_id}.yaml"
    if not yaml_path.exists():
        print(f"  SKIP: {yaml_path} does not exist")
        return False

    content = yaml_path.read_text()

    # Check if already has Homebrew provenance
    if "formulae.brew.sh" in content:
        print(f"  SKIP: {app_id} already has Homebrew provenance")
        return False

    # Don't downgrade reviewed/validated host IOCs
    host_status = _get_host_status(content)
    if host_status in ("reviewed", "validated"):
        print(f"  SKIP: {app_id} host IOCs already {host_status} - not overwriting")
        return False

    # Fetch data
    if brew_type == "cask":
        data = fetch_cask(brew_token)
        if not data:
            return False
        iocs = extract_cask_iocs(data, brew_token)
        evidence = "Homebrew cask explicitly defines app, binary, uninstall, or zap artifact paths"
    else:
        data = fetch_formula(brew_token)
        if not data:
            return False
        iocs = extract_formula_iocs(data, brew_token)
        evidence = "Homebrew formula defines binary installation paths"

    # Skip if we got nothing useful
    if not iocs["paths"] and not iocs["bundle_ids"] and not iocs["process_names"]:
        print(f"  SKIP: {app_id} - no useful IOCs extracted from Homebrew")
        return False

    host_block = build_host_yaml_block(iocs, evidence)

    # Determine how to insert/replace
    if "  host:" in content:
        # Replace existing host section
        # Find the host: line and everything until the next top-level key or EOF
        lines = content.split("\n")
        host_start = None
        host_end = None
        for i, line in enumerate(lines):
            if line.strip().startswith("host:") and (line.startswith("  host:") or line.startswith("    host:")):
                # Find indent level
                indent = len(line) - len(line.lstrip())
                if indent <= 4:  # This is the top-level host under iocs
                    host_start = i
                    # Find end: next line with same or less indent (that isn't blank)
                    for j in range(i + 1, len(lines)):
                        stripped = lines[j].strip()
                        if stripped == "":
                            continue
                        line_indent = len(lines[j]) - len(lines[j].lstrip())
                        if line_indent <= indent:
                            host_end = j
                            break
                    if host_end is None:
                        host_end = len(lines)
                    break

        if host_start is not None:
            new_lines = lines[:host_start] + [host_block] + lines[host_end:]
            new_content = "\n".join(new_lines)
        else:
            print(f"  WARN: {app_id} - could not locate host section for replacement")
            return False
    else:
        # No host section exists - append after network section
        # Append at end of file
        new_content = content.rstrip("\n") + "\n" + host_block + "\n"

    # Ensure file ends with newline
    if not new_content.endswith("\n"):
        new_content += "\n"

    if dry_run:
        print(f"  DRY-RUN: Would update {app_id}")
        print(f"    paths: {len(iocs['paths'])}")
        print(f"    bundle_ids: {len(iocs['bundle_ids'])}")
        print(f"    process_names: {len(iocs['process_names'])}")
        return True

    yaml_path.write_text(new_content)
    print(f"  UPDATED: {app_id} ({len(iocs['paths'])} paths, {len(iocs['bundle_ids'])} bundle_ids, {len(iocs['process_names'])} process_names)")
    return True


def main():
    parser = argparse.ArgumentParser(description="Enrich app YAML with Homebrew IOCs")
    parser.add_argument("--dry-run", action="store_true", help="Print what would change without writing")
    parser.add_argument("--app", type=str, help="Only process a single app ID")
    args = parser.parse_args()

    if args.app:
        if args.app not in HOMEBREW_MAP:
            print(f"ERROR: {args.app} not in Homebrew map")
            sys.exit(1)
        apps_to_process = {args.app: HOMEBREW_MAP[args.app]}
    else:
        apps_to_process = HOMEBREW_MAP

    updated = 0
    skipped = 0
    failed = 0

    for app_id, (brew_type, brew_token) in sorted(apps_to_process.items()):
        print(f"Processing {app_id} ({brew_type}:{brew_token})...")
        try:
            if update_app_file(app_id, brew_type, brew_token, dry_run=args.dry_run):
                updated += 1
            else:
                skipped += 1
        except Exception as e:
            print(f"  ERROR: {app_id}: {e}", file=sys.stderr)
            failed += 1

    print(f"\nDone: {updated} updated, {skipped} skipped, {failed} failed")


if __name__ == "__main__":
    main()
