"""Shared catalog paths, constants, and loaders."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent
APPS_DIR = ROOT / "apps"
ARCHIVE_DIR = ROOT / "archive"
OUTPUT_DIR = ROOT / "output"
SCHEMAS_DIR = ROOT / "schemas"

AppRecord = dict[str, Any]

STATUS_ORDER = {"draft": 0, "reviewed": 1, "validated": 2, "stale": 0}

VALID_CATEGORIES = {
    "AI_AGENT_FRAMEWORK", "AI_BROWSER_AGENT", "AI_DESKTOP_ASSISTANT",
    "AI_OBSERVABILITY", "CLAW_FAMILY_APP", "CLOUD_STORAGE", "COLLAB_KNOWLEDGE",
    "DOC_CONVERSION_UPLOAD", "FILE_TRANSFER", "GENAI_CHAT", "GENAI_CODING",
    "GENAI_MEDIA", "MEETING_TRANSCRIPTION", "NON_WORK_IM", "P2P_FILE_SHARING",
    "PASTE_SHARING", "REMOTE_ACCESS", "SCREEN_RECORDING_SHARE", "TRANSLATION",
}
VALID_SHAPES = {"web", "macos"}
VALID_SEVERITIES = {"critical", "high", "medium", "low"}
VALID_IOC_STATUSES = {"draft", "reviewed", "validated", "stale"}
VALID_HOST_MATCH = {"exact", "suffix"}
VALID_NET_ROLES = {
    "app_brand", "ai_service_provider", "platform_service", "cdn_static",
    "file_upload", "file_download", "file_share", "file_sync", "file_transfer",
}
VALID_KW_MATCH = {"substring", "regex"}
REQUIRED_TOP_FIELDS = {
    "id", "name", "category", "product_shape", "product_type",
    "severity", "priority_score", "iocs",
}
HOST_VALUE_FIELDS = (
    "paths",
    "bundle_ids",
    "process_names",
    "team_ids",
    "chrome_extension_ids",
    "safari_extension_bundle_ids",
)
EXPORTABLE_IOC_FIELDS = (
    "status",
    "provenance",
    "hostname_patterns",
    "keyword_patterns",
    "paths",
    "bundle_ids",
    "process_names",
    "team_ids",
    "chrome_extension_ids",
    "safari_extension_bundle_ids",
)


def iter_app_paths() -> list[Path]:
    return sorted(APPS_DIR.glob("*.yaml"))


def category_slug(category: str) -> str:
    slug = category.lower()
    if slug.endswith("_app"):
        slug = slug[:-4]
    return slug


def load_app(path: Path) -> AppRecord:
    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    if data is None:
        return {}
    return data


def load_apps(category: str | None = None) -> list[AppRecord]:
    apps: list[AppRecord] = []
    for path in iter_app_paths():
        app = load_app(path)
        if category and app.get("category") != category:
            continue
        apps.append(app)
    return apps


def get_ioc_group(app: AppRecord, group: str) -> dict[str, Any] | None:
    iocs = app.get("iocs")
    if not isinstance(iocs, dict):
        return None
    group_data = iocs.get(group)
    if not isinstance(group_data, dict):
        return None
    return group_data


def meets_min_status(status: str | None, min_status: str) -> bool:
    actual_rank = STATUS_ORDER.get(status or "draft", 0)
    threshold_rank = STATUS_ORDER.get(min_status, 0)
    return actual_rank >= threshold_rank


def filter_apps_with_ioc_group(
    group: str,
    min_status: str = "draft",
    category: str | None = None,
) -> list[AppRecord]:
    apps: list[AppRecord] = []
    for app in load_apps(category):
        group_data = get_ioc_group(app, group)
        if not group_data:
            continue
        if not meets_min_status(group_data.get("status"), min_status):
            continue

        if group == "network":
            has_values = bool(group_data.get("hostname_patterns") or group_data.get("keyword_patterns"))
        elif group == "host":
            has_values = any(group_data.get(field) for field in HOST_VALUE_FIELDS)
        else:
            has_values = True

        if not has_values:
            continue
        apps.append(app)
    return apps
