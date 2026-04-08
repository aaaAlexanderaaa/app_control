#!/usr/bin/env python3
"""Generate Jamf/MDM host scanning scripts from app YAML files.

The generated script has two sections:
1. Targeted detection: per-app checks for known IOCs (paths, bundle IDs,
   process names, Chrome extension IDs, repo/project searches).
2. Inventory discovery: enumerates uncataloged apps and CLI tools via
   system_profiler, mdfind, and package manager filesystem scans.

system_profiler SPApplicationsDataType -json provides _name, path, version,
obtained_from, and signed_by. It does NOT provide bundle IDs or team IDs —
those are looked up from Info.plist (defaults read) and codesign output.
"""

from __future__ import annotations

import argparse
import sys
from datetime import date

from app_control.catalog import filter_apps_with_ioc_group

GENERIC_DIR_NAMES = {
    "app",
    "api",
    "bin",
    "build",
    "client",
    "config",
    "configs",
    "data",
    "developer",
    "dist",
    "docs",
    "frontend",
    "lib",
    "log",
    "logs",
    "output",
    "server",
    "src",
    "web",
}

_USER_BIN_PREFIXES = (".local/bin/", ".cargo/bin/", "go/bin/", ".go/bin/")
_SYSTEM_BIN_DIRS = ("/opt/homebrew/bin", "/usr/local/bin")
_NPM_GLOBAL_DIRS = ("/opt/homebrew/lib/node_modules", "/usr/local/lib/node_modules")
DEFAULT_SEARCH_IOC_MODE = "first_hit"
DEFAULT_SEARCH_IOC_STALE_DAYS = 30


def _normalize_ioc_path(path: str) -> str:
    """Normalize an IOC path for sharing comparison (strip trailing slash)."""
    return path.rstrip("/")


def _path_owner_score(path: str, app_id: str) -> int:
    """Score how well an app_id matches a path for ownership.

    Returns 0 if no match, higher for better matches.
    """
    app_token = app_id.lower().replace("-", "_").replace(".", "_")
    clean = path.replace("~/", "").replace("$HOME/", "").replace("${HOME}/", "")
    if clean.startswith("/"):
        parts = clean.strip("/").split("/")
    else:
        parts = clean.split("/")

    for part in parts:
        token = part.lstrip(".").rstrip("/").lower().replace("-", "_").replace(".", "_")
        if not token:
            continue
        if token == app_token:
            return 2
        if app_token in token or token in app_token:
            return 1
    return 0


def resolve_shared_ioc_ownership(apps: list[dict]) -> dict[str, set[str]]:
    """When multiple apps claim the same IOC path, assign ownership to the
    app whose id best matches the path.  Non-owners get the path excluded.
    """
    path_claims: dict[str, list[tuple[str, str]]] = {}
    for app in apps:
        host = app.get("iocs", {}).get("host", {})
        for path in host.get("paths", []):
            normalized = _normalize_ioc_path(path)
            path_claims.setdefault(normalized, []).append((app["id"], path))

    excluded: dict[str, set[str]] = {}
    for normalized, claims in path_claims.items():
        if len(claims) <= 1:
            continue

        scored = [(app_id, _path_owner_score(normalized, app_id)) for app_id, _ in claims]
        scored.sort(key=lambda x: -x[1])

        owner = scored[0][0] if scored[0][1] > 0 else claims[0][0]

        for app_id, original in claims:
            if app_id != owner:
                excluded.setdefault(app_id, set()).add(_normalize_ioc_path(original))

    return excluded


def load_apps(min_status: str, category: str | None = None) -> list[dict]:
    return filter_apps_with_ioc_group("host", min_status=min_status, category=category)


def shell_escape(value: str) -> str:
    return value.replace("'", "'\\''")


def classify_path(path: str) -> tuple[str, str]:
    """Classify an IOC path into a scan strategy."""
    if (
        path.startswith("~/")
        or path.startswith("$HOME/")
        or path.startswith("${HOME}/")
    ):
        normalized = (
            path.replace("~/", "").replace("$HOME/", "").replace("${HOME}/", "")
        )
        return "user", normalized

    if path.startswith("/"):
        return "system", path

    if path.startswith("*/"):
        inner = path[2:]
        first_component = inner.split("/")[0]
        if (
            first_component
            and first_component.lower() not in GENERIC_DIR_NAMES
            and not first_component.startswith(".")
        ):
            return "repo", inner
        return "project", inner

    if path.startswith("./"):
        return "project", path[2:]

    if path.startswith("*"):
        return "project", path

    return "project", path


def emit_shell_array(
    lines: list[str], var_name: str, values: list[str], indent: str = ""
) -> None:
    lines.append(f"{indent}{var_name}=(")
    for value in values:
        lines.append(f'{indent}    "{shell_escape(value)}"')
    lines.append(f"{indent})")


def generate_scan_script(
    apps: list[dict],
    min_status: str,
    category: str | None = None,
    *,
    output_mode: str = "report",
    include_inventory: bool = True,
    watchlist_keywords: list[str] | None = None,
) -> str:
    lines: list[str] = []

    lines.append("#!/bin/bash")
    lines.append(f"# Auto-generated by jamf_scan.py on {date.today().isoformat()}")
    lines.append(f"# Minimum IOC status: {min_status}")
    if category:
        lines.append(f"# Category filter: {category}")
    lines.append(f"# Apps scanned: {len(apps)}")
    lines.append(f"# Output mode: {output_mode}")
    lines.append(f"# Inventory discovery: {'enabled' if include_inventory else 'disabled'}")
    lines.append(
        f"# Directory-traversal IOC mode: ${'{'}SEARCH_IOC_MODE:-{DEFAULT_SEARCH_IOC_MODE}{'}'} "
        "(first_hit|all_hits)"
    )
    lines.append(
        f"# Weak-path stale filter: ${'{'}SEARCH_IOC_STALE_DAYS:-{DEFAULT_SEARCH_IOC_STALE_DAYS}{'}'} "
        "days for non-.app / non-executable path hits"
    )
    lines.append("")
    lines.append("set -eo pipefail")
    lines.append("")
    lines.append(f'SEARCH_IOC_MODE="${{SEARCH_IOC_MODE:-{DEFAULT_SEARCH_IOC_MODE}}}"')
    lines.append(f'SEARCH_IOC_STALE_DAYS="${{SEARCH_IOC_STALE_DAYS:-{DEFAULT_SEARCH_IOC_STALE_DAYS}}}"')
    lines.append('case "$SEARCH_IOC_MODE" in')
    lines.append("    first_hit|all_hits) ;;")
    lines.append(f'    *) SEARCH_IOC_MODE="{DEFAULT_SEARCH_IOC_MODE}" ;;')
    lines.append("esac")
    lines.append('case "$SEARCH_IOC_STALE_DAYS" in')
    lines.append(f'    ""|*[!0-9]*) SEARCH_IOC_STALE_DAYS={DEFAULT_SEARCH_IOC_STALE_DAYS} ;;')
    lines.append("esac")
    lines.append('NOW_EPOCH=$(/bin/date "+%s" 2>/dev/null || echo 0)')
    lines.append("")
    lines.append('PROFILER_TIMEOUT="${PROFILER_TIMEOUT:-30}"')
    lines.append('FIND_TIMEOUT="${FIND_TIMEOUT:-30}"')
    lines.append('WITH_NICE="${WITH_NICE:-0}"')
    lines.append('if [ "$WITH_NICE" = "1" ]; then /usr/bin/renice 10 $$ >/dev/null 2>&1 || true; fi')
    lines.append("")
    lines.append("RESULTS=()")
    lines.append('FOUND_IDS="|"')
    lines.append("")

    lines.extend(
        [
            "# --- Shared data collection (collected once, used by detection + inventory + watchlist) ---",
            "",
            "USER_HOMES=()",
            "for h in /Users/*; do",
            '    [ -d "$h" ] || continue',
            '    [ "$h" = "/Users/Shared" ] && continue',
            '    USER_HOMES+=("$h")',
            "done",
            "",
            "SEARCH_DIRS=()",
            'SEARCH_DIR_MARKERS="|"',
            "add_search_dir() {",
            '    local dir="$1"',
            '    [ -d "$dir" ] || return 0',
            '    case "$SEARCH_DIR_MARKERS" in',
            '        *"|$dir|"*) return 0 ;;',
            "    esac",
            '    SEARCH_DIRS+=("$dir")',
            '    SEARCH_DIR_MARKERS="${SEARCH_DIR_MARKERS}${dir}|"',
            "}",
            "",
            'for h in "${USER_HOMES[@]}"; do',
            "    for sub in Documents Desktop Downloads code Code repos projects src git workspace dev Development; do",
            '        add_search_dir "$h/$sub"',
            "    done",
            '    add_search_dir "$h"',
            "done",
            "",
            "# Pre-collect system_profiler JSON (one call, ~3-15s on Intel)",
            '_CACHED_SP_JSON=$(/usr/bin/timeout "$PROFILER_TIMEOUT" /usr/sbin/system_profiler SPApplicationsDataType -json 2>/dev/null || true)',
            "",
            "# Pre-collect mdfind .app bundles (one call, ~1s)",
            '_CACHED_MDFIND_APPS=$(/usr/bin/timeout "$PROFILER_TIMEOUT" mdfind "kMDItemContentTypeTree == \'com.apple.application-bundle\'" 2>/dev/null || true)',
            "",
            "# Pre-build bundle_id <-> path map from mdfind results (bash 3.2 compatible)",
            "# Stored as newline-separated 'bundle_id<TAB>path' pairs",
            '_BUNDLE_MAP_DATA=""',
            '_build_bundle_map() {',
            '    [ -n "$_CACHED_MDFIND_APPS" ] || return 0',
            '    while IFS= read -r _bm_path; do',
            '        [ -n "$_bm_path" ] || continue',
            '        [ -d "$_bm_path/Contents" ] || continue',
            '        local _bm_plist="$_bm_path/Contents/Info.plist"',
            '        local _bm_bid=""',
            '        if [ -f "$_bm_plist" ]; then',
            '            _bm_bid=$(/usr/bin/defaults read "$_bm_plist" CFBundleIdentifier 2>/dev/null || true)',
            "        fi",
            '        if [ -z "$_bm_bid" ]; then',
            '            _bm_bid=$(mdls -name kMDItemCFBundleIdentifier -raw "$_bm_path" 2>/dev/null || true)',
            '            [ "$_bm_bid" = "(null)" ] && _bm_bid=""',
            "        fi",
            '        [ -n "$_bm_bid" ] || continue',
            "        # Deduplicate: skip if bid already in map",
            '        case "$_BUNDLE_MAP_DATA" in',
            "            *\"${_bm_bid}	\"*) ;;",
            '            *) _BUNDLE_MAP_DATA="${_BUNDLE_MAP_DATA}${_bm_bid}	${_bm_path}"$\'\\n\' ;;',
            "        esac",
            '    done <<< "$_CACHED_MDFIND_APPS"',
            "}",
            "_build_bundle_map",
            "",
            "# Pre-collect running process names (one ps call, avoids per-app pgrep)",
            '_CACHED_PROCS=$(/bin/ps -axco comm= 2>/dev/null || true)',
            "",
            "# Pre-build filesystem index for search_name (one find pass per SEARCH_DIR)",
            '_CACHED_FS_INDEX=""',
            'for _fs_d in "${SEARCH_DIRS[@]}"; do',
            '    _CACHED_FS_INDEX="${_CACHED_FS_INDEX}$(/usr/bin/timeout "$FIND_TIMEOUT" /usr/bin/find "$_fs_d" -maxdepth 3 -print 2>/dev/null || true)"',
            '    _CACHED_FS_INDEX="${_CACHED_FS_INDEX}"$\'\\n\'',
            "done",
            "",
            "# Pre-collect Homebrew package list (one call)",
            '_CACHED_BREW_CMD=""',
            'if [ -x /opt/homebrew/bin/brew ]; then _CACHED_BREW_CMD=/opt/homebrew/bin/brew',
            'elif [ -x /usr/local/bin/brew ]; then _CACHED_BREW_CMD=/usr/local/bin/brew; fi',
            '_CACHED_BREW_LIST=""',
            'if [ -n "$_CACHED_BREW_CMD" ]; then',
            '    _CACHED_BREW_LIST=$("$_CACHED_BREW_CMD" list -1 2>/dev/null || true)',
            "fi",
            "",
            "# --- Helper functions ---",
            "",
            "app_found() {",
            '    local app_id="$1"',
            '    case "$FOUND_IDS" in',
            '        *"|$app_id|"*) return 0 ;;',
            "        *) return 1 ;;",
            "    esac",
            "}",
            "",
            "mark_found() {",
            '    local app_id="$1"',
            '    FOUND_IDS="${FOUND_IDS}${app_id}|"',
            "}",
            "",
            "time_to_epoch() {",
            '    local timestamp="$1"',
            '    if [ -z "$timestamp" ] || [ "$timestamp" = "UNKNOWN" ]; then',
            "        return 1",
            "    fi",
            '    /bin/date -j -f "%Y-%m-%d %H:%M:%S" "$timestamp" "+%s" 2>/dev/null || return 1',
            "}",
            "",
            "get_times() {",
            '    local path="$1"',
            "    local birth_time last_used",
            "    # Birth time (install approximation) via stat",
            '    birth_time=$(/usr/bin/stat -f "%SB" -t "%Y-%m-%d %H:%M:%S" "$path" 2>/dev/null || true)',
            '    [ -n "$birth_time" ] || birth_time="UNKNOWN"',
            "    # Last-used via kMDItemLastUsedDate (reliable on APFS; atime is not)",
            '    last_used=$(/usr/bin/mdls -name kMDItemLastUsedDate -raw "$path" 2>/dev/null || true)',
            '    case "$last_used" in',
            '        "(null)"|""|*"could not find"*)',
            "            # Fallback to mtime when mdls has no data",
            '            last_used=$(/usr/bin/stat -f "%Sm" -t "%Y-%m-%d %H:%M:%S" "$path" 2>/dev/null || true)',
            '            [ -n "$last_used" ] || last_used="UNKNOWN"',
            "            ;;",
            "        *)",
            '            # mdls returns "2024-01-15 10:30:00 +0000"; strip timezone suffix',
            '            last_used="${last_used% +0000}"',
            "            ;;",
            "    esac",
            '    echo "${birth_time}|${last_used}"',
            "}",
            "",
            "record_path_match() {",
            '    local app_id="$1"',
            '    local path="$2"',
            "    local times install_time last_access",
            '    if [ -n "$path" ] && [ "$path" != "UNKNOWN" ] && [ -e "$path" ]; then',
            '        times=$(get_times "$path")',
            "    else",
            '        times="UNKNOWN|UNKNOWN"',
            "    fi",
            "    install_time=${times%%|*}",
            "    last_access=${times#*|}",
            '    RESULTS+=("$app_id|PATH=$path|INSTALL_APPROX=$install_time|LAST_ACCESS=$last_access")',
            '    mark_found "$app_id"',
            "}",
            "",
            "record_bundle_match() {",
            '    local app_id="$1"',
            '    local bundle_id="$2"',
            '    local path="$3"',
            "    local times install_time last_access",
            '    if [ -n "$path" ] && [ "$path" != "UNKNOWN" ] && [ -e "$path" ]; then',
            '        times=$(get_times "$path")',
            "    else",
            '        times="UNKNOWN|UNKNOWN"',
            "    fi",
            "    install_time=${times%%|*}",
            "    last_access=${times#*|}",
            '    RESULTS+=("$app_id|BUNDLE_ID=$bundle_id|PATH=$path|INSTALL_APPROX=$install_time|LAST_ACCESS=$last_access")',
            '    mark_found "$app_id"',
            "}",
            "",
            "record_process_match() {",
            '    local app_id="$1"',
            '    local process_name="$2"',
            '    RESULTS+=("$app_id|PROCESS=$process_name")',
            '    mark_found "$app_id"',
            "}",
            "",
            "record_extension_match() {",
            '    local app_id="$1"',
            '    local ext_id="$2"',
            '    local ext_path="$3"',
            '    RESULTS+=("$app_id|CHROME_EXT=$ext_id|PATH=$ext_path")',
            '    mark_found "$app_id"',
            "}",
            "",
            "path_match_is_strong_signal() {",
            '    local path="$1"',
            '    case "$path" in',
            "        *.app)",
            '            [ -d "$path/Contents" ] && return 0',
            "            ;;",
            "        *.app/*)",
            '            local app_root="${path%.app/*}.app"',
            '            [ -d "$app_root/Contents" ] && return 0',
            "            ;;",
            "    esac",
            '    if [ -f "$path" ] && [ -x "$path" ]; then',
            "        return 0",
            "    fi",
            "    return 1",
            "}",
            "",
            "path_match_is_stale() {",
            '    local path="$1"',
            "    local times install_time last_access install_epoch access_epoch cutoff_seconds",
            '    [ "$SEARCH_IOC_STALE_DAYS" -gt 0 ] || return 1',
            '    path_match_is_strong_signal "$path" && return 1',
            '    [ -e "$path" ] || return 1',
            '    [ "$NOW_EPOCH" -gt 0 ] || return 1',
            '    times=$(get_times "$path")',
            "    install_time=${times%%|*}",
            "    last_access=${times#*|}",
            '    install_epoch=$(time_to_epoch "$install_time") || return 1',
            '    access_epoch=$(time_to_epoch "$last_access") || return 1',
            '    cutoff_seconds=$((SEARCH_IOC_STALE_DAYS * 86400))',
            '    if [ $((NOW_EPOCH - install_epoch)) -gt "$cutoff_seconds" ] && [ $((NOW_EPOCH - access_epoch)) -gt "$cutoff_seconds" ]; then',
            "        return 0",
            "    fi",
            "    return 1",
            "}",
            "",
            "record_search_path_match() {",
            '    local app_id="$1"',
            '    local search_ioc="$2"',
            '    local path="$3"',
            "    local times install_time last_access",
            '    if [ -n "$path" ] && [ "$path" != "UNKNOWN" ] && [ -e "$path" ]; then',
            '        times=$(get_times "$path")',
            "    else",
            '        times="UNKNOWN|UNKNOWN"',
            "    fi",
            "    install_time=${times%%|*}",
            "    last_access=${times#*|}",
            '    RESULTS+=("$app_id|SEARCH_IOC=$search_ioc|PATH=$path|INSTALL_APPROX=$install_time|LAST_ACCESS=$last_access")',
            '    mark_found "$app_id"',
            "}",
            "",
            "check_chrome_extension() {",
            '    local app_id="$1"',
            '    local ext_id="$2"',
            "    local h ext_path",
            '    for h in "${USER_HOMES[@]}"; do',
            '        for profile_dir in "$h/Library/Application Support/Google/Chrome"/*; do',
            '            [ -d "$profile_dir/Extensions/$ext_id" ] || continue',
            '            record_extension_match "$app_id" "$ext_id" "$profile_dir/Extensions/$ext_id"',
            "            return 0",
            "        done",
            "    done",
            "    return 1",
            "}",
            "",
            "check_candidate_pattern() {",
            '    local app_id="$1"',
            '    local candidate="$2"',
            '    local match=""',
            '    if [[ "$candidate" == *"*"* || "$candidate" == *"?"* || "$candidate" == *"["* ]]; then',
            '        while IFS= read -r match; do',
            '            [ -n "$match" ] || continue',
            '            path_match_is_stale "$match" && continue',
            '            record_path_match "$app_id" "$match"',
            "            return 0",
            '        done < <(compgen -G "$candidate" 2>/dev/null || true)',
            '    elif [ -e "$candidate" ]; then',
            '        path_match_is_stale "$candidate" && return 1',
            '        record_path_match "$app_id" "$candidate"',
            "        return 0",
            "    fi",
            "    return 1",
            "}",
            "",
            "check_app_paths() {",
            '    local app_id="$1"',
            "    shift",
            "    local candidate",
            '    for candidate in "$@"; do',
            '        check_candidate_pattern "$app_id" "$candidate" && return 0',
            "    done",
            "    return 1",
            "}",
            "",
            "# P2: Uses pre-built _BUNDLE_MAP_DATA instead of per-call mdfind",
            "check_bundle_id() {",
            '    local app_id="$1"',
            '    local bundle_id="$2"',
            "    local _cb_bid _cb_path",
            "    while IFS=$'\\t' read -r _cb_bid _cb_path; do",
            '        if [ "$_cb_bid" = "$bundle_id" ]; then',
            '            record_bundle_match "$app_id" "$bundle_id" "$_cb_path"',
            "            return 0",
            "        fi",
            '    done <<< "$_BUNDLE_MAP_DATA"',
            "    return 1",
            "}",
            "",
            "# P3: Uses pre-collected _CACHED_PROCS instead of per-call pgrep",
            "check_process_name() {",
            '    local app_id="$1"',
            '    local process_name="$2"',
            "    local proc",
            '    while IFS= read -r proc; do',
            '        [ "$proc" = "$process_name" ] && { record_process_match "$app_id" "$process_name"; return 0; }',
            '    done <<< "$_CACHED_PROCS"',
            "    return 1",
            "}",
            "",
            "# search_dirs: unchanged (stat-based, no forks)",
            "search_dirs() {",
            '    local app_id="$1"',
            '    local rel_path="$2"',
            "    local d candidate",
            '    for d in "${SEARCH_DIRS[@]}"; do',
            '        candidate="$d/$rel_path"',
            '        if [ -e "$candidate" ]; then',
            '            path_match_is_stale "$candidate" && continue',
            '            record_search_path_match "$app_id" "$rel_path" "$candidate"',
            "            return 0",
            "        fi",
            "    done",
            "    return 1",
            "}",
            "",
            "# P1: Uses pre-built _CACHED_FS_INDEX instead of per-call find",
            "search_name() {",
            '    local app_id="$1"',
            '    local pattern="$2"',
            '    local type_flag="${3:--d}"',
            "    local match",
            '    while IFS= read -r match; do',
            '        [ -n "$match" ] || continue',
            '        case "$type_flag" in',
            '            -d) [ -d "$match" ] || continue ;;',
            '            -f) [ -f "$match" ] || continue ;;',
            "        esac",
            '        local base="${match##*/}"',
            '        [ "$base" = "$pattern" ] || continue',
            '        path_match_is_stale "$match" && continue',
            '        record_search_path_match "$app_id" "$pattern" "$match"',
            "        return 0",
            '    done <<< "$_CACHED_FS_INDEX"',
            "    return 1",
            "}",
            "",
        ]
    )

    ioc_excluded = resolve_shared_ioc_ownership(apps)

    for app in apps:
        app_id = app["id"]
        app_name = app["name"]
        host = app["iocs"]["host"]
        var_name = app_id.upper().replace("-", "_").replace(".", "_")
        if var_name[0].isdigit():
            var_name = "APP_" + var_name

        app_excluded_paths = ioc_excluded.get(app_id, set())

        system_paths: list[str] = []
        user_paths: list[str] = []
        repo_paths: list[str] = []
        project_paths: list[str] = []

        for path in host.get("paths", []):
            if _normalize_ioc_path(path) in app_excluded_paths:
                continue
            category_name, value = classify_path(path)
            if category_name == "system":
                system_paths.append(value)
            elif category_name == "user":
                user_paths.append(value)
            elif category_name == "repo":
                repo_paths.append(value)
            else:
                project_paths.append(value)

        system_set = set(system_paths)
        for user_path in user_paths:
            for prefix in _USER_BIN_PREFIXES:
                if user_path.startswith(prefix):
                    binary = user_path[len(prefix) :]
                    for system_dir in _SYSTEM_BIN_DIRS:
                        candidate = f"{system_dir}/{binary}"
                        if candidate not in system_set:
                            system_paths.append(candidate)
                            system_set.add(candidate)
                    break

        lines.append(f"# {'─' * 30}")
        lines.append(f"# {app_name} ({app_id})")
        lines.append(f"# {'─' * 30}")

        if system_paths or user_paths:
            emit_shell_array(lines, f"{var_name}_CANDIDATES", system_paths)
            if user_paths:
                lines.append('for h in "${USER_HOMES[@]}"; do')
                lines.append(f"    {var_name}_CANDIDATES+=(")
                for path in user_paths:
                    lines.append(f'        "$h/{shell_escape(path)}"')
                lines.append("    )")
                lines.append("done")
            lines.append("")

        strong_branches: list[str] = []
        if system_paths or user_paths:
            strong_branches.append(
                f'check_app_paths "{app_id}" "${{{var_name}_CANDIDATES[@]}}"'
            )
        for bundle_id in host.get("bundle_ids", []):
            strong_branches.append(f'check_bundle_id "{app_id}" "{shell_escape(bundle_id)}"')
        for process_name in host.get("process_names", []):
            strong_branches.append(
                f'check_process_name "{app_id}" "{shell_escape(process_name)}"'
            )
        for ext_id in host.get("chrome_extension_ids", []):
            strong_branches.append(
                f'check_chrome_extension "{app_id}" "{shell_escape(ext_id)}"'
            )
        search_branches: list[str] = []
        for repo_path in repo_paths:
            search_branches.append(f'search_dirs "{app_id}" "{shell_escape(repo_path)}"')
        for project_path in project_paths:
            first_segment = project_path.rstrip("/").split("/")[0]
            if first_segment.startswith("*"):
                type_flag = "-d" if project_path.endswith("/") else "-f"
                search_branches.append(
                    f'search_name "{app_id}" "{shell_escape(first_segment)}" {type_flag}'
                )
            elif "/" not in project_path.rstrip("/"):
                type_flag = "-d" if project_path.endswith("/") else "-f"
                search_branches.append(
                    f'search_name "{app_id}" "{shell_escape(first_segment)}" {type_flag}'
                )
            else:
                parts = project_path.rstrip("/").split("/")
                distinctive = next(
                    (
                        part
                        for part in parts
                        if part.lower() not in GENERIC_DIR_NAMES and part != "."
                    ),
                    parts[-1],
                )
                type_flag = "-d"
                if distinctive == parts[-1] and not project_path.endswith("/"):
                    type_flag = "-f"
                search_branches.append(
                    f'search_name "{app_id}" "{shell_escape(distinctive)}" {type_flag}'
                )

        if strong_branches or search_branches:
            lines.append(f'if ! app_found "{app_id}"; then')
            if strong_branches:
                for index, branch in enumerate(strong_branches):
                    prefix = "if" if index == 0 else "elif"
                    lines.append(f"    {prefix} {branch}; then")
                    lines.append("        :")
                if search_branches:
                    lines.append("    else")
                    lines.append('        if [ "$SEARCH_IOC_MODE" = "all_hits" ]; then')
                    for branch in search_branches:
                        lines.append(f"            {branch} || true")
                    lines.append("        else")
                    for index, branch in enumerate(search_branches):
                        prefix = "if" if index == 0 else "elif"
                        lines.append(f"            {prefix} {branch}; then")
                        lines.append("                :")
                    lines.append("            fi")
                    lines.append("        fi")
                lines.append("    fi")
            else:
                lines.append('    if [ "$SEARCH_IOC_MODE" = "all_hits" ]; then')
                for branch in search_branches:
                    lines.append(f"        {branch} || true")
                lines.append("    else")
                for index, branch in enumerate(search_branches):
                    prefix = "if" if index == 0 else "elif"
                    lines.append(f"        {prefix} {branch}; then")
                    lines.append("            :")
                lines.append("        fi")
                lines.append("    fi")
            lines.append("fi")
        lines.append("")

    if include_inventory:
        # --- Inventory Discovery Section ---
        # Build lookups of all known catalog identifiers for cross-referencing
        # against system_profiler, mdfind, and package manager output.
        all_bundle_ids: set[str] = set()
        all_app_names: set[str] = set()
        all_cli_names: set[str] = set()
        all_extension_ids: set[str] = set()
        _bin_prefixes = (
            "~/.local/bin/",
            "~/.cargo/bin/",
            "~/go/bin/",
            "~/.go/bin/",
            "/opt/homebrew/bin/",
            "/usr/local/bin/",
        )
        for app in apps:
            host = app.get("iocs", {}).get("host") or {}
            for bid in host.get("bundle_ids", []):
                all_bundle_ids.add(bid)
            for ext_id in host.get("chrome_extension_ids", []):
                all_extension_ids.add(ext_id)
            # Extract CLI binary names from known bin directories
            for path in host.get("paths", []):
                for prefix in _bin_prefixes:
                    if path.startswith(prefix):
                        binary = path[len(prefix) :].rstrip("/")
                        if binary and "*" not in binary:
                            all_cli_names.add(binary)
                        break
                # Extract .app display names from paths for fuzzy matching
                if ".app" in path:
                    for segment in path.split("/"):
                        if segment.endswith(".app") or ".app" in segment:
                            clean = (
                                segment.replace("*.app", "")
                                .replace(".app", "")
                                .replace("*", "")
                                .strip()
                            )
                            if clean:
                                all_app_names.add(clean)
            # Also add the app id and name as known identifiers
            all_cli_names.add(app["id"])
            all_cli_names.add(app["id"].replace("_", "-"))
            app_name_lower = app.get("name", "").lower().replace(" ", "-")
            if app_name_lower:
                all_cli_names.add(app_name_lower)

        lines.append("# --- Inventory Discovery ---")
        lines.append("# Use system_profiler, mdfind, and package managers to discover")
        lines.append("# apps and CLI tools not in the catalog")
        lines.append("UNKNOWN_APPS=()")
        lines.append("")

        # Emit the known bundle IDs as a lookup string
        lines.append("# Known catalog bundle IDs for cross-reference")
        known_ids_str = "|".join(sorted(all_bundle_ids))
        lines.append(f'KNOWN_BUNDLE_IDS="|{shell_escape(known_ids_str)}|"')
        lines.append("")

        # Emit known app names as a lookup string
        known_names_str = "|".join(sorted(all_app_names))
        lines.append(f'KNOWN_APP_NAMES="|{shell_escape(known_names_str)}|"')
        lines.append("")

        # Emit known CLI binary/package names as a lookup string
        known_cli_str = "|".join(sorted(all_cli_names))
        lines.append("# Known catalog CLI tool names for package manager cross-reference")
        lines.append(f'KNOWN_CLI_NAMES="|{shell_escape(known_cli_str)}|"')
        lines.append("")

        # Emit known Chrome extension IDs as a lookup string
        known_ext_str = "|".join(sorted(all_extension_ids))
        lines.append("# Known catalog Chrome extension IDs for cross-reference")
        lines.append(f'KNOWN_EXTENSION_IDS="|{shell_escape(known_ext_str)}|"')
        lines.append("")

        lines.extend(
            [
                "# Helper: get bundle ID from an .app path (uses _BUNDLE_MAP_DATA cache when possible)",
                "get_bundle_id_from_path() {",
                '    local app_path="$1"',
                "    local _gbid _gpath",
                "    while IFS=$'\\t' read -r _gbid _gpath; do",
                '        if [ "$_gpath" = "$app_path" ]; then echo "$_gbid"; return; fi',
                '    done <<< "$_BUNDLE_MAP_DATA"',
                '    local plist="$app_path/Contents/Info.plist"',
                "    local bid",
                '    if [ -f "$plist" ]; then',
                '        bid=$(/usr/bin/defaults read "$plist" CFBundleIdentifier 2>/dev/null || true)',
                '        if [ -n "$bid" ]; then echo "$bid"; return; fi',
                "    fi",
                '    bid=$(mdls -name kMDItemCFBundleIdentifier -raw "$app_path" 2>/dev/null || true)',
                '    if [ -n "$bid" ] && [ "$bid" != "(null)" ]; then echo "$bid"; return; fi',
                "}",
                "",
                "# Helper: extract team ID from codesign output",
                "get_team_id_from_path() {",
                '    local app_path="$1"',
                "    local line",
                '    line=$(/usr/bin/codesign -dvv "$app_path" 2>&1 | grep "^TeamIdentifier=" || true)',
                '    if [ -n "$line" ]; then',
                '        echo "${line#TeamIdentifier=}"',
                "    fi",
                "}",
                "",
                "# Discover installed apps via cached system_profiler JSON",
                "discover_via_system_profiler() {",
                '    [ -n "$_CACHED_SP_JSON" ] || return 0',
                "    local parsed",
                '    parsed=$(/usr/bin/python3 -c "',
                "import sys, json, re",
                "data = json.load(sys.stdin)",
                "apps = data.get('SPApplicationsDataType', [])",
                "for app in apps:",
                "    name = app.get('_name', '')",
                "    path = app.get('path', '')",
                "    version = app.get('version', 'UNKNOWN')",
                "    obtained = app.get('obtained_from', 'unknown')",
                "    team_id = ''",
                "    signed_by = app.get('signed_by', [])",
                "    if signed_by and isinstance(signed_by, list):",
                "        m = re.search(r'\\(([A-Z0-9]{10})\\)', signed_by[0])",
                "        if m:",
                "            team_id = m.group(1)",
                "    if not team_id:",
                "        team_id = 'UNKNOWN'",
                "    print(f'{name}\\t{path}\\t{version}\\t{obtained}\\t{team_id}')",
                '" <<< "$_CACHED_SP_JSON" 2>/dev/null || true)',
                '    [ -n "$parsed" ] || return 0',
                "",
                "    while IFS=$'\\t' read -r sp_name sp_path sp_version sp_obtained sp_team; do",
                '        [ -n "$sp_name" ] || continue',
                '        case "$sp_obtained" in apple) continue ;; esac',
                '        case "$sp_path" in /System/*|/Library/Apple/*) continue ;; esac',
                "        local sp_bundle",
                '        sp_bundle=$(get_bundle_id_from_path "$sp_path" 2>/dev/null || true)',
                '        [ -n "$sp_bundle" ] || sp_bundle="UNKNOWN"',
                "        local known=0",
                '        if [ "$sp_bundle" != "UNKNOWN" ]; then',
                '            case "$KNOWN_BUNDLE_IDS" in *"|$sp_bundle|"*) known=1 ;; esac',
                "        fi",
                '        if [ "$known" -eq 0 ] && [ -n "$sp_name" ]; then',
                '            case "$KNOWN_APP_NAMES" in *"|$sp_name|"*) known=1 ;; esac',
                "        fi",
                '        [ "$known" -eq 0 ] && UNKNOWN_APPS+=("UNKNOWN_APP|NAME=$sp_name|BUNDLE_ID=$sp_bundle|PATH=$sp_path|VERSION=$sp_version|TEAM_ID=$sp_team|SOURCE=$sp_obtained")',
                '    done <<< "$parsed"',
                "}",
                "",
                "# Discover .app bundles via cached mdfind results",
                "discover_via_mdfind() {",
                '    [ -n "$_CACHED_MDFIND_APPS" ] || return 0',
                '    while IFS= read -r app_path; do',
                '        [ -n "$app_path" ] || continue',
                '        case "$app_path" in /System/*|/Library/Apple/*|/usr/*) continue ;; esac',
                "        local app_name",
                '        app_name="${app_path##*/}" && app_name="${app_name%.app}"',
                '        [ -n "$app_name" ] || continue',
                "        local already_found=0",
                "        local entry",
                '        for entry in "${UNKNOWN_APPS[@]}" "${RESULTS[@]}"; do',
                '            case "$entry" in *"$app_path"*) already_found=1; break ;; esac',
                "        done",
                '        [ "$already_found" -eq 1 ] && continue',
                '        case "$KNOWN_APP_NAMES" in *"|$app_name|"*) continue ;; esac',
                "        local bundle_id",
                '        bundle_id=$(get_bundle_id_from_path "$app_path" 2>/dev/null || true)',
                '        [ -n "$bundle_id" ] || bundle_id="UNKNOWN"',
                '        if [ "$bundle_id" != "UNKNOWN" ]; then',
                '            case "$KNOWN_BUNDLE_IDS" in *"|$bundle_id|"*) continue ;; esac',
                "        fi",
                '        UNKNOWN_APPS+=("UNKNOWN_APP|NAME=$app_name|BUNDLE_ID=$bundle_id|PATH=$app_path|SOURCE=mdfind")',
                '    done <<< "$_CACHED_MDFIND_APPS"',
                "}",
                "",
                "# Discover Homebrew packages via cached brew list",
                "discover_via_brew() {",
                '    [ -n "$_CACHED_BREW_LIST" ] || return 0',
                "    while IFS= read -r formula; do",
                '        [ -n "$formula" ] || continue',
                '        case "$KNOWN_CLI_NAMES" in *"|$formula|"*) continue ;; esac',
                '        case "$KNOWN_APP_NAMES" in *"|$formula|"*) continue ;; esac',
                '        UNKNOWN_APPS+=("UNKNOWN_CLI|NAME=$formula|SOURCE=homebrew")',
                '    done <<< "$_CACHED_BREW_LIST"',
                "}",
                "",
                "# Discover Cargo-installed crates (reads JSON manifest, no cargo binary needed)",
                "discover_via_cargo() {",
                "    local h",
                '    for h in "${USER_HOMES[@]}"; do',
                '        local cargo_file="$h/.cargo/.crates2.json"',
                '        [ -f "$cargo_file" ] || continue',
                "        local crates",
                '        crates=$(/usr/bin/python3 -c "',
                "import sys, json",
                "data = json.load(open(sys.argv[1]))",
                "for key in data.get('installs', {}):",
                "    print(key.split(' ')[0])",
                '" "$cargo_file" 2>/dev/null || true)',
                '        [ -n "$crates" ] || continue',
                "        while IFS= read -r crate; do",
                '            [ -n "$crate" ] || continue',
                '            case "$KNOWN_CLI_NAMES" in *"|$crate|"*) continue ;; esac',
                '            UNKNOWN_APPS+=("UNKNOWN_CLI|NAME=$crate|SOURCE=cargo|USER=$h")',
                '        done <<< "$crates"',
                "    done",
                "}",
                "",
                "# Discover Go-installed binaries (scans filesystem, no go binary needed)",
                "discover_via_go() {",
                "    local h",
                '    for h in "${USER_HOMES[@]}"; do',
                '        for gobin in "$h/go/bin" "$h/.go/bin"; do',
                '            [ -d "$gobin" ] || continue',
                "            local binary",
                '            for binary in "$gobin"/*; do',
                '                [ -x "$binary" ] || continue',
                "                local bin_name",
                '                bin_name="${binary##*/}"',
                '                case "$KNOWN_CLI_NAMES" in *"|$bin_name|"*) continue ;; esac',
                '                UNKNOWN_APPS+=("UNKNOWN_CLI|NAME=$bin_name|SOURCE=go|PATH=$binary|USER=$h")',
                "            done",
                "        done",
                "    done",
                "}",
                "",
                "# Discover globally installed npm packages (checks known paths, no npm binary needed)",
                "discover_via_npm() {",
                "    local npm_dir",
                "    for npm_dir in /opt/homebrew/lib/node_modules /usr/local/lib/node_modules; do",
                '        [ -d "$npm_dir" ] || continue',
                "        local pkg_dir",
                '        for pkg_dir in "$npm_dir"/*/; do',
                '            [ -d "$pkg_dir" ] || continue',
                "            local pkg_name",
                '            pkg_name="${pkg_dir%/}" && pkg_name="${pkg_name##*/}"',
                '            [ -n "$pkg_name" ] || continue',
                '            case "$KNOWN_CLI_NAMES" in *"|$pkg_name|"*) continue ;; esac',
                '            UNKNOWN_APPS+=("UNKNOWN_CLI|NAME=$pkg_name|SOURCE=npm|PATH=$pkg_dir")',
                "        done",
                "    done",
                "    local h",
                '    for h in "${USER_HOMES[@]}"; do',
                '        local user_npm_dir="$h/.npm-global/lib/node_modules"',
                '        [ -d "$user_npm_dir" ] || continue',
                '        for pkg_dir in "$user_npm_dir"/*/; do',
                '            [ -d "$pkg_dir" ] || continue',
                "            local pkg_name",
                '            pkg_name="${pkg_dir%/}" && pkg_name="${pkg_name##*/}"',
                '            case "$KNOWN_CLI_NAMES" in *"|$pkg_name|"*) continue ;; esac',
                '            UNKNOWN_APPS+=("UNKNOWN_CLI|NAME=$pkg_name|SOURCE=npm|PATH=$pkg_dir|USER=$h")',
                "        done",
                "    done",
                "}",
                "",
                "# Discover pip/pipx-installed tools (checks filesystem, no pip binary needed)",
                "discover_via_pip() {",
                "    local h",
                '    for h in "${USER_HOMES[@]}"; do',
                '        local pipx_dir="$h/.local/pipx/venvs"',
                '        if [ -d "$pipx_dir" ]; then',
                '            for venv in "$pipx_dir"/*/; do',
                '                [ -d "$venv" ] || continue',
                "                local pkg_name",
                '                pkg_name="${venv%/}" && pkg_name="${pkg_name##*/}"',
                '                case "$KNOWN_CLI_NAMES" in *"|$pkg_name|"*) continue ;; esac',
                '                UNKNOWN_APPS+=("UNKNOWN_CLI|NAME=$pkg_name|SOURCE=pipx|USER=$h")',
                "            done",
                "        fi",
                '        local local_bin="$h/.local/bin"',
                '        if [ -d "$local_bin" ]; then',
                '            for binary in "$local_bin"/*; do',
                '                [ -x "$binary" ] || continue',
                "                local bin_name",
                '                bin_name="${binary##*/}"',
                '                case "$KNOWN_CLI_NAMES" in *"|$bin_name|"*) continue ;; esac',
                '                UNKNOWN_APPS+=("UNKNOWN_CLI|NAME=$bin_name|SOURCE=pip_local|PATH=$binary|USER=$h")',
                "            done",
                "        fi",
                "    done",
                "}",
                "",
                "# Discover Chrome/Chromium-based browser extensions (enumerates all profiles)",
                "discover_via_chrome_extensions() {",
                "    local h",
                '    for h in "${USER_HOMES[@]}"; do',
                "        local _ce_entry browser_name browser_dir",
                '        while IFS=$\'\\t\' read -r browser_name browser_dir; do',
                '            [ -d "$browser_dir" ] || continue',
                "            local profile_dir",
                '            for profile_dir in "$browser_dir"/*/; do',
                '                [ -d "$profile_dir/Extensions" ] || continue',
                "                local ext_dir",
                '                for ext_dir in "$profile_dir/Extensions"/*/; do',
                '                    [ -d "$ext_dir" ] || continue',
                "                    local ext_id",
                '                    ext_id="${ext_dir%/}" && ext_id="${ext_id##*/}"',
                '                    [ -n "$ext_id" ] || continue',
                "                    # Skip extensions already in the catalog",
                '                    case "$KNOWN_EXTENSION_IDS" in *"|$ext_id|"*) continue ;; esac',
                "                    # Find the latest version directory containing manifest.json",
                '                    local manifest_file=""',
                "                    local ver_dir",
                '                    for ver_dir in "$ext_dir"/*/; do',
                '                        [ -f "$ver_dir/manifest.json" ] && manifest_file="$ver_dir/manifest.json"',
                "                    done",
                '                    [ -n "$manifest_file" ] || continue',
                "                    local ext_version",
                '                    ext_version="${manifest_file%/manifest.json}" && ext_version="${ext_version##*/}"',
                "                    # Extract extension name from manifest.json using python3",
                "                    local ext_name",
                "                    ext_name=$(/usr/bin/python3 -c \"",
                "import json, sys, os",
                "try:",
                "    manifest_path = sys.argv[1]",
                "    with open(manifest_path) as f:",
                "        manifest = json.load(f)",
                "    name = manifest.get('name', '')",
                "    if name.startswith('__MSG_') and name.endswith('__'):",
                "        msg_key = name[6:-2]",
                "        locale_dir = os.path.join(os.path.dirname(manifest_path), '_locales')",
                "        for lang in ['en', 'en_US', 'en_GB']:",
                "            msg_file = os.path.join(locale_dir, lang, 'messages.json')",
                "            if os.path.isfile(msg_file):",
                "                with open(msg_file) as mf:",
                "                    msgs = json.load(mf)",
                "                for k, v in msgs.items():",
                "                    if k.lower() == msg_key.lower():",
                "                        name = v.get('message', name)",
                "                        break",
                "                break",
                "    print(name)",
                "except Exception:",
                "    pass",
                '\" "$manifest_file" 2>/dev/null || true)',
                '                    [ -n "$ext_name" ] || ext_name="UNKNOWN"',
                "                    local profile_name",
                '                    profile_name="${profile_dir%/}" && profile_name="${profile_name##*/}"',
                '                    UNKNOWN_APPS+=("UNKNOWN_EXT|NAME=$ext_name|EXT_ID=$ext_id|VERSION=$ext_version|BROWSER=$browser_name|PROFILE=$profile_name|PATH=$ext_dir|USER=$h")',
                "                done",
                "            done",
                "        done <<EOF",
                "Chrome\t$h/Library/Application Support/Google/Chrome",
                "Edge\t$h/Library/Application Support/Microsoft Edge",
                "Brave\t$h/Library/Application Support/BraveSoftware/Brave-Browser",
                "Chromium\t$h/Library/Application Support/Chromium",
                "Vivaldi\t$h/Library/Application Support/Vivaldi",
                "Arc\t$h/Library/Application Support/Arc/User Data",
                "Opera\t$h/Library/Application Support/com.operasoftware.Opera",
                "EOF",
                "    done",
                "}",
                "",
                "# Run discovery using cached data (no duplicate external calls)",
                "discover_via_system_profiler",
                "discover_via_mdfind",
                "discover_via_cargo",
                "discover_via_go",
                "discover_via_npm",
                "discover_via_pip",
                "discover_via_chrome_extensions",
                "",
            ]
        )

        if output_mode == "report":
            lines.extend(
                [
                    "# Homebrew discovery (report mode -- uses cached brew list)",
                    "discover_via_brew",
                    "",
                ]
            )

    if watchlist_keywords:
        kw_pipe = "|".join(shell_escape(kw) for kw in watchlist_keywords)
        lines.append("# --- Watchlist Keyword Scan ---")
        lines.append("# Single-pass awk matching against cached data sources.")
        lines.append("# All case-insensitive matching and dedup handled inside awk (zero fork inner loops).")
        lines.append("WATCHLIST_HITS=()")
        lines.append("")
        lines.extend(
            [
                "scan_watchlist() {",
                "    # Parse system_profiler JSON once into tab-separated lines",
                '    local sp_parsed=""',
                '    if [ -n "$_CACHED_SP_JSON" ]; then',
                "        sp_parsed=$(/usr/bin/python3 -c \"",
                "import sys, json",
                "data = json.load(sys.stdin)",
                "for a in data.get('SPApplicationsDataType', []):",
                "    n = a.get('_name', '')",
                "    p = a.get('path', '')",
                "    v = a.get('version', 'UNKNOWN')",
                "    o = a.get('obtained_from', 'unknown')",
                "    if n and o != 'apple' and not p.startswith('/System/') and not p.startswith('/Library/Apple/'):",
                "        print(f'{n}\\t{p}\\t{v}')",
                '" <<< "$_CACHED_SP_JSON" 2>/dev/null || true)',
                "    fi",
                "",
                "    # Collect bin directory listings into a flat list (path per line)",
                '    local bin_listing=""',
                "    for _bd in /opt/homebrew/bin /usr/local/bin; do",
                '        [ -d "$_bd" ] || continue',
                '        for _bp in "$_bd"/*; do',
                '            [ -x "$_bp" ] && bin_listing="${bin_listing}${_bp}"$\'\\n\'',
                "        done",
                "    done",
                '    for _uh in "${USER_HOMES[@]}"; do',
                '        for _ubd in "$_uh/.local/bin" "$_uh/.cargo/bin" "$_uh/go/bin"; do',
                '            [ -d "$_ubd" ] || continue',
                '            for _bp in "$_ubd"/*; do',
                '                [ -x "$_bp" ] && bin_listing="${bin_listing}${_bp}"$\'\\n\'',
                "            done",
                "        done",
                "    done",
                "",
                "    # Single awk pass: match all keywords against all data sources",
                "    # Input is 5 sections separated by marker lines.",
                "    # Output: one hit per line (path\\ttag) for bash to stat timestamps.",
                "    local awk_hits",
                "    awk_hits=$({",
                '        echo "---SP---"',
                '        [ -n "$sp_parsed" ] && printf \'%s\\n\' "$sp_parsed"',
                '        echo "---MDFIND---"',
                '        [ -n "$_CACHED_MDFIND_APPS" ] && printf \'%s\\n\' "$_CACHED_MDFIND_APPS"',
                '        echo "---BREW---"',
                '        [ -n "$_CACHED_BREW_LIST" ] && printf \'%s\\n\' "$_CACHED_BREW_LIST"',
                '        echo "---BIN---"',
                '        [ -n "$bin_listing" ] && printf \'%s\\n\' "$bin_listing"',
                "    } | /usr/bin/awk '",
                "    BEGIN {",
                f'        n = split("{kw_pipe}", kw_arr, "|")',
                "        for (i = 1; i <= n; i++) kw_lower[i] = tolower(kw_arr[i])",
                '        section = ""',
                "    }",
                '    /^---SP---$/    { section = "sp"; next }',
                '    /^---MDFIND---$/ { section = "mdfind"; next }',
                '    /^---BREW---$/  { section = "brew"; next }',
                '    /^---BIN---$/   { section = "bin"; next }',
                "",
                '    section == "sp" {',
                "        split($0, f, \"\\t\")",
                "        name = f[1]; path = f[2]; ver = f[3]",
                "        low = tolower(name)",
                "        for (i = 1; i <= n; i++) {",
                "            if (index(low, kw_lower[i]) > 0 && !(path SUBSEP kw_arr[i] in seen)) {",
                "                seen[path SUBSEP kw_arr[i]] = 1",
                '                print path "\\tWATCHLIST|KEYWORD=" kw_arr[i] "|SOURCE=system_profiler|NAME=" name "|PATH=" path "|VERSION=" ver',
                "            }",
                "        }",
                "        next",
                "    }",
                "",
                '    section == "mdfind" {',
                "        path = $0",
                '        if (path ~ /^\\/System\\/|^\\/Library\\/Apple\\//) next',
                "        # Extract .app name: strip directory prefix and .app suffix",
                "        aname = path",
                "        sub(/.*\\//, \"\", aname)",
                '        sub(/\\.app$/, "", aname)',
                "        low = tolower(aname)",
                "        for (i = 1; i <= n; i++) {",
                "            if (index(low, kw_lower[i]) > 0 && !(path SUBSEP kw_arr[i] in seen)) {",
                "                seen[path SUBSEP kw_arr[i]] = 1",
                '                print path "\\tWATCHLIST|KEYWORD=" kw_arr[i] "|SOURCE=mdfind|NAME=" aname "|PATH=" path',
                "            }",
                "        }",
                "        next",
                "    }",
                "",
                '    section == "brew" {',
                "        formula = $0",
                "        low = tolower(formula)",
                "        for (i = 1; i <= n; i++) {",
                '            if (index(low, kw_lower[i]) > 0 && !("brew" SUBSEP formula SUBSEP kw_arr[i] in seen)) {',
                '                seen["brew" SUBSEP formula SUBSEP kw_arr[i]] = 1',
                '                print "\\tWATCHLIST|KEYWORD=" kw_arr[i] "|SOURCE=homebrew|NAME=" formula',
                "            }",
                "        }",
                "        next",
                "    }",
                "",
                '    section == "bin" {',
                "        path = $0",
                "        bname = path",
                "        sub(/.*\\//, \"\", bname)",
                "        low = tolower(bname)",
                "        for (i = 1; i <= n; i++) {",
                "            if (index(low, kw_lower[i]) > 0 && !(path SUBSEP kw_arr[i] in seen)) {",
                "                seen[path SUBSEP kw_arr[i]] = 1",
                '                print path "\\tWATCHLIST|KEYWORD=" kw_arr[i] "|SOURCE=bin|NAME=" bname "|PATH=" path',
                "            }",
                "        }",
                "        next",
                "    }",
                "    ' 2>/dev/null || true)",
                "",
                "    # Read awk output and add timestamps for hits that have paths",
                '    [ -n "$awk_hits" ] || return 0',
                "    while IFS=$'\\t' read -r hit_path hit_tag; do",
                '        [ -n "$hit_tag" ] || continue',
                "        local times install_time last_access",
                '        if [ -n "$hit_path" ] && [ -e "$hit_path" ]; then',
                '            times=$(get_times "$hit_path")',
                "        else",
                '            times="UNKNOWN|UNKNOWN"',
                "        fi",
                "        install_time=${times%%|*}",
                "        last_access=${times#*|}",
                '        WATCHLIST_HITS+=("${hit_tag}|INSTALL_APPROX=$install_time|LAST_ACCESS=$last_access")',
                '    done <<< "$awk_hits"',
                "}",
                "",
                "scan_watchlist",
                "",
            ]
        )

    lines.append("# --- Report ---")
    if output_mode == "jamf_ea":
        use_combined = include_inventory or watchlist_keywords
        if use_combined:
            combined_lines = [
                "COMBINED=()",
                'for item in "${RESULTS[@]}"; do',
                '    COMBINED+=("$item")',
                "done",
            ]
            if include_inventory:
                combined_lines.extend(
                    [
                        'for item in "${UNKNOWN_APPS[@]}"; do',
                        '    COMBINED+=("$item")',
                        "done",
                    ]
                )
            if watchlist_keywords:
                combined_lines.extend(
                    [
                        'for item in "${WATCHLIST_HITS[@]}"; do',
                        '    COMBINED+=("$item")',
                        "done",
                    ]
                )
            combined_lines.extend(
                [
                    'if [ "${#COMBINED[@]}" -eq 0 ]; then',
                    '    echo "<result>NOT_FOUND</result>"',
                    "else",
                    "    OUT=$(printf \"%s\\n\" \"${COMBINED[@]}\" | /usr/bin/awk 'NF' | /usr/bin/paste -sd ';' -)",
                    '    echo "<result>$OUT</result>"',
                    "fi",
                ]
            )
            lines.extend(combined_lines)
        else:
            lines.extend(
                [
                    'if [ "${#RESULTS[@]}" -eq 0 ]; then',
                    '    echo "<result>NOT_FOUND</result>"',
                    "else",
                    "    OUT=$(printf \"%s\\n\" \"${RESULTS[@]}\" | /usr/bin/awk 'NF' | /usr/bin/paste -sd ';' -)",
                    '    echo "<result>$OUT</result>"',
                    "fi",
                ]
            )
    else:
        lines.extend(
            [
                "EXIT_CODE=0",
                "",
                'if [ "${#RESULTS[@]}" -gt 0 ]; then',
                '    echo "ALERT: ${#RESULTS[@]} cataloged indicator(s) found:"',
                '    for item in "${RESULTS[@]}"; do',
                '        echo "  - $item"',
                "    done",
                "    EXIT_CODE=1",
                "fi",
                "",
            ]
        )
        if watchlist_keywords:
            lines.extend(
                [
                    'if [ "${#WATCHLIST_HITS[@]}" -gt 0 ]; then',
                    '    echo ""',
                    '    echo "WATCHLIST: ${#WATCHLIST_HITS[@]} keyword match(es) found:"',
                    '    for item in "${WATCHLIST_HITS[@]}"; do',
                    '        echo "  - $item"',
                    "    done",
                    "    EXIT_CODE=1",
                    "fi",
                    "",
                ]
            )
        if include_inventory:
            lines.extend(
                [
                    'if [ "${#UNKNOWN_APPS[@]}" -gt 0 ]; then',
                    '    echo ""',
                    '    echo "INVENTORY: ${#UNKNOWN_APPS[@]} uncataloged application(s) discovered:"',
                    '    for item in "${UNKNOWN_APPS[@]}"; do',
                    '        echo "  - $item"',
                    "    done",
                    "fi",
                    "",
                ]
            )
        clean_parts = ['[ "${#RESULTS[@]}" -eq 0 ]']
        if include_inventory:
            clean_parts.append('[ "${#UNKNOWN_APPS[@]}" -eq 0 ]')
        if watchlist_keywords:
            clean_parts.append('[ "${#WATCHLIST_HITS[@]}" -eq 0 ]')
        clean_check = " && ".join(clean_parts)
        lines.extend(
            [
                f"if {clean_check}; then",
                '    echo "CLEAN: No monitored apps detected."',
                "fi",
                "",
                "exit $EXIT_CODE",
            ]
        )

    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate Jamf/MDM host scan script")
    parser.add_argument(
        "--min-status",
        default="validated",
        choices=["draft", "reviewed", "validated"],
        help="Minimum IOC status to include (default: validated)",
    )
    parser.add_argument(
        "--category", default=None, help="Only include apps in the given category"
    )
    parser.add_argument(
        "--output-mode",
        default="report",
        choices=["report", "jamf_ea"],
        help="Rendered script output mode (default: report)",
    )
    args = parser.parse_args()

    apps = load_apps(args.min_status, args.category)
    if not apps:
        suffix = f" in category '{args.category}'" if args.category else ""
        print(
            f"# No apps meet min-status '{args.min_status}'{suffix}. No scan generated.",
            file=sys.stderr,
        )
        sys.exit(0)

    output = generate_scan_script(
        apps,
        args.min_status,
        args.category,
        output_mode=args.output_mode,
    )
    sys.stdout.write(output)


if __name__ == "__main__":
    main()
