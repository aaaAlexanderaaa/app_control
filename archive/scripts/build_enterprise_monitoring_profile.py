#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import date
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
CATALOG_PATH = ROOT / "app_data_leak_risk_catalog.json"
OUTPUT_PATH = ROOT / "enterprise_app_monitoring_profile.json"

MONITORING_FIELDS = ["dns.query", "tls.sni", "http.hostname"]

ROLE_PRIORITY = {
    "app_brand": 0,
    "file_upload": 1,
    "file_transfer": 2,
    "file_share": 3,
    "file_sync": 4,
    "file_download": 5,
    "cdn_static": 6,
    "ai_service_provider": 7,
    "platform_service": 8,
}

PRECISION_PRIORITY = {
    "high": 0,
    "medium": 1,
    "low": 2,
    "unknown": 3,
}

POLICY_TIERS = {
    "block_preferred": {
        "name": "Block Preferred",
        "description": (
            "Default-deny posture for high-confidence exfiltration channels or "
            "non-work apps. Use Jamf to remove/restrict native apps and network "
            "telemetry to alert or block web access."
        ),
        "default_jamf_action": "restrict_or_remove_when_possible",
        "default_network_action": "alert_and_block_when_policy_allows",
    },
    "managed_only": {
        "name": "Managed Tenant Only",
        "description": (
            "Allow only sanctioned corporate tenants or managed instances. Alert "
            "on personal, guest, or unmanaged usage patterns."
        ),
        "default_jamf_action": "allow_only_managed_instance",
        "default_network_action": "alert_on_unmanaged_or_unsanctioned_use",
    },
    "monitor_high_risk": {
        "name": "Monitor High Risk",
        "description": (
            "High-risk tools that may be approved for limited use. Inventory with "
            "Jamf where possible and correlate host presence with network signals."
        ),
        "default_jamf_action": "inventory_and_review",
        "default_network_action": "alert_and_review",
    },
}

CATEGORY_DEFAULTS = {
    "AI_AGENT_FRAMEWORK": {
        "policy_tier": "monitor_high_risk",
        "reason": "Agent frameworks can automate browsing, tool use, and file actions against external services.",
    },
    "AI_BROWSER_AGENT": {
        "policy_tier": "monitor_high_risk",
        "reason": "Browser agents can access sensitive SaaS content and operate inside authenticated sessions.",
    },
    "AI_DESKTOP_ASSISTANT": {
        "policy_tier": "block_preferred",
        "reason": "Native assistants can bypass browser controls and are better governed through endpoint management.",
    },
    "CLAW_FAMILY_APP": {
        "policy_tier": "block_preferred",
        "reason": "Claw-family agents combine local execution, messaging control, and plugin or skill ecosystems that make unmanaged deployment especially risky.",
    },
    "AI_OBSERVABILITY": {
        "policy_tier": "monitor_high_risk",
        "reason": "Prompt and response tracing tools can retain sensitive model traffic and tool outputs.",
    },
    "CLOUD_STORAGE": {
        "policy_tier": "managed_only",
        "reason": "Cloud drives should be limited to sanctioned tenants because persistent sync and share links are common leak paths.",
    },
    "COLLAB_KNOWLEDGE": {
        "policy_tier": "managed_only",
        "reason": "Docs and knowledge bases may be legitimate, but unmanaged tenants create durable external exposure.",
    },
    "DOC_CONVERSION_UPLOAD": {
        "policy_tier": "managed_only",
        "reason": "File conversion sites require document upload and should be limited to approved workflows only.",
    },
    "FILE_TRANSFER": {
        "policy_tier": "block_preferred",
        "reason": "Ad-hoc transfer services provide direct external file movement with limited governance.",
    },
    "GENAI_CHAT": {
        "policy_tier": "monitor_high_risk",
        "reason": "General LLM chat tools are common prompt and text exfiltration channels.",
    },
    "GENAI_CODING": {
        "policy_tier": "monitor_high_risk",
        "reason": "Coding assistants can upload repository context, diffs, and credentials to external providers.",
    },
    "GENAI_MEDIA": {
        "policy_tier": "monitor_high_risk",
        "reason": "Media generation tools can receive sensitive images, audio, or identity-related media.",
    },
    "MEETING_TRANSCRIPTION": {
        "policy_tier": "managed_only",
        "reason": "Meeting bots and transcript services capture audio, summaries, and meeting artifacts externally.",
    },
    "NON_WORK_IM": {
        "policy_tier": "block_preferred",
        "reason": "Personal or unmanaged messaging channels move text, files, and screenshots outside enterprise retention controls.",
    },
    "P2P_FILE_SHARING": {
        "policy_tier": "block_preferred",
        "reason": "P2P sync and torrent tools create uncontrolled transfer paths that evade tenant-based governance.",
    },
    "PASTE_SHARING": {
        "policy_tier": "block_preferred",
        "reason": "Paste sites are a direct code and secret publication path with low friction and high blast radius.",
    },
    "REMOTE_ACCESS": {
        "policy_tier": "block_preferred",
        "reason": "Remote control software can bypass endpoint controls and usually includes clipboard or file transfer features.",
    },
    "SCREEN_RECORDING_SHARE": {
        "policy_tier": "managed_only",
        "reason": "Screen recording tools create externally shared videos that frequently contain internal product and customer data.",
    },
    "TRANSLATION": {
        "policy_tier": "managed_only",
        "reason": "Translation services often require full text or document submission and should remain approval-based.",
    },
}

APP_OVERRIDES = {
    "dingtalk_personal_tenant": {
        "policy_tier": "managed_only",
        "reason": "Differentiate approved corporate DingTalk tenants from personal or unmanaged tenants.",
    },
    "feishu_personal_tenant": {
        "policy_tier": "managed_only",
        "reason": "Differentiate approved corporate Feishu tenants from personal or unmanaged tenants.",
    },
    "lark_personal_tenant": {
        "policy_tier": "managed_only",
        "reason": "Differentiate approved corporate Lark tenants from personal or unmanaged tenants.",
    },
    "slack_personal_unmanaged_workspace": {
        "policy_tier": "managed_only",
        "reason": "Slack may be sanctioned internally, but personal or unmanaged workspaces should alert immediately.",
    },
    "teams_personal_unmanaged_tenant": {
        "policy_tier": "managed_only",
        "reason": "Microsoft Teams may be corporate-approved, but personal or unmanaged tenants should be treated separately.",
    },
}

TIER_ORDER = {
    "block_preferred": 0,
    "managed_only": 1,
    "monitor_high_risk": 2,
}


def load_catalog() -> dict:
    return json.loads(CATALOG_PATH.read_text())


def sha256_hex(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def simplify_host_artifacts(entries: list[dict]) -> list[dict]:
    simplified = []
    for entry in entries:
        item = {
            "value": entry["value"],
            "match": entry["match"],
            "precision": entry["precision"],
            "verification_status": entry["verification_status"],
        }
        if "path_type" in entry:
            item["path_type"] = entry["path_type"]
        simplified.append(item)
    return simplified


def role_sort_key(entry: dict) -> tuple:
    return (
        ROLE_PRIORITY.get(entry.get("role", ""), 99),
        PRECISION_PRIORITY.get(entry.get("precision", "unknown"), 99),
        -entry.get("weight", 0),
        entry.get("pattern", ""),
    )


def keyword_sort_key(entry: dict) -> tuple:
    return (
        PRECISION_PRIORITY.get(entry.get("precision", "unknown"), 99),
        -entry.get("weight", 0),
        entry.get("pattern", ""),
    )


def simplify_hostname_patterns(entries: list[dict], limit: int = 6) -> list[dict]:
    preferred = sorted(entries, key=role_sort_key)[:limit]
    simplified = []
    for entry in preferred:
        item = {
            "pattern": entry["pattern"],
            "match": entry["match"],
            "match_on": entry["match_on"],
            "role": entry["role"],
            "precision": entry["precision"],
            "weight": entry["weight"],
            "verification_status": entry["verification_status"],
        }
        if "file_semantics" in entry:
            item["file_semantics"] = entry["file_semantics"]
        simplified.append(item)
    return simplified


def simplify_keyword_patterns(entries: list[dict], limit: int = 3) -> list[dict]:
    return [
        {
            "pattern": entry["pattern"],
            "match": entry["match"],
            "precision": entry["precision"],
            "weight": entry["weight"],
        }
        for entry in sorted(entries, key=keyword_sort_key)[:limit]
    ]


def derive_policy(app: dict) -> tuple[str, str]:
    override = APP_OVERRIDES.get(app["id"])
    if override:
        return override["policy_tier"], override["reason"]

    default = CATEGORY_DEFAULTS[app["category"]]
    return default["policy_tier"], default["reason"]


def jamf_scope(product_shape: list[str]) -> str:
    shapes = set(product_shape)
    if shapes == {"macos"}:
        return "macos_native_only"
    if shapes == {"web"}:
        return "web_only"
    if shapes == {"macos", "web"}:
        return "macos_and_web"
    return "unknown"


def jamf_primary_action(policy_tier: str, product_shape: list[str], host_artifact_count: int) -> str:
    has_macos = "macos" in product_shape
    if policy_tier == "block_preferred":
        if has_macos:
            return "restrict_or_remove_native_app"
        return "network_block_or_alert"
    if policy_tier == "managed_only":
        if has_macos:
            return "allow_only_managed_app_or_tenant"
        return "network_alert_on_unmanaged_use"
    if has_macos and host_artifact_count > 0:
        return "inventory_app_and_alert_on_network_use"
    if has_macos:
        return "inventory_app_with_custom_detection"
    return "network_monitor_only"


def jamf_coverage(product_shape: list[str], host_artifact_count: int) -> str:
    has_macos = "macos" in product_shape
    if not has_macos:
        return "network_only_visibility"
    if host_artifact_count > 0:
        return "direct_host_artifacts_available"
    return "custom_inventory_or_process_detection_needed"


def monitoring_notes(app: dict, policy_tier: str, host_artifact_count: int, high_precision_network_signal_count: int) -> str:
    notes = []
    if policy_tier == "block_preferred":
        notes.append("Treat observed use as a strong policy event.")
    elif policy_tier == "managed_only":
        notes.append("Correlate traffic with tenant context before escalation where feasible.")
    else:
        notes.append("Review with user role, exception status, and data-handling policy.")

    if high_precision_network_signal_count == 0:
        notes.append("Network precision is limited; rely more on Jamf inventory and process context.")
    if "macos" in app["product_shape"] and host_artifact_count == 0:
        notes.append("No verified Jamf-friendly host artifacts are present in the source catalog yet.")
    return " ".join(notes)


def build_profile(catalog: dict) -> dict:
    risk_title_by_id = {
        item["id"]: item["title"] for item in catalog["taxonomy"]["risks"]["items"]
    }

    apps = []
    counts_by_policy_tier: Counter[str] = Counter()
    counts_by_primary_action: Counter[str] = Counter()
    counts_by_category: Counter[str] = Counter()

    for app in catalog["apps"]:
        policy_tier, policy_reason = derive_policy(app)

        host = app["fingerprints"]["host"]["macos"]
        host_indicators = {
            "bundle_ids": simplify_host_artifacts(host["bundle_ids"]),
            "process_names": simplify_host_artifacts(host["process_names"]),
            "team_ids": simplify_host_artifacts(host["team_ids"]),
            "directory_paths": simplify_host_artifacts(host.get("directory_paths", [])),
            "chrome_extension_ids": simplify_host_artifacts(host["chrome_extension_ids"]),
            "safari_extension_bundle_ids": simplify_host_artifacts(host["safari_extension_bundle_ids"]),
            "notes": host.get("notes", ""),
            "host_signal_status": host["host_signal_status"],
        }
        host_artifact_count = sum(
            len(host_indicators[key])
            for key in (
                "bundle_ids",
                "process_names",
                "team_ids",
                "directory_paths",
                "chrome_extension_ids",
                "safari_extension_bundle_ids",
            )
        )

        hostname_patterns = app["fingerprints"]["network"]["hostname_patterns"]
        keyword_patterns = app["fingerprints"]["network"]["keyword_patterns"]
        high_precision_network_signal_count = sum(
            1 for entry in hostname_patterns if entry.get("precision") == "high"
        )

        jamf_action = jamf_primary_action(
            policy_tier, app["product_shape"], host_artifact_count
        )
        coverage = jamf_coverage(app["product_shape"], host_artifact_count)

        derived = {
            "catalog_app_id": app["id"],
            "name": app["name"],
            "category": app["category"],
            "product_shape": app["product_shape"],
            "product_type": app["product_type"],
            "severity": app["risk_profile"]["severity"],
            "priority_score": app["risk_profile"]["priority_score"],
            "policy_tier": policy_tier,
            "policy_reason": policy_reason,
            "jamf_posture": {
                "scope": jamf_scope(app["product_shape"]),
                "primary_action": jamf_action,
                "coverage": coverage,
                "host_indicators": host_indicators,
            },
            "monitoring_strategy": {
                "fields": MONITORING_FIELDS,
                "priority_hostname_patterns": simplify_hostname_patterns(hostname_patterns),
                "keyword_patterns": simplify_keyword_patterns(keyword_patterns),
                "signal_coverage": {
                    "hostname_patterns": len(hostname_patterns),
                    "keyword_patterns": len(keyword_patterns),
                    "high_precision_hostname_patterns": high_precision_network_signal_count,
                    "host_artifacts": host_artifact_count,
                },
                "notes": monitoring_notes(
                    app,
                    policy_tier,
                    host_artifact_count,
                    high_precision_network_signal_count,
                ),
            },
            "risks": app["risk_profile"]["risks"],
            "risk_titles": [
                risk_title_by_id[risk_id]
                for risk_id in app["risk_profile"]["risks"]
                if risk_id in risk_title_by_id
            ],
            "evidence_status": app["evidence"]["verification_status"],
            "notes": app.get("notes", ""),
        }

        apps.append(derived)
        counts_by_policy_tier[policy_tier] += 1
        counts_by_primary_action[jamf_action] += 1
        counts_by_category[app["category"]] += 1

    apps.sort(
        key=lambda item: (
            TIER_ORDER[item["policy_tier"]],
            -item["priority_score"],
            item["name"].lower(),
        )
    )

    total_apps = len(apps)
    apps_with_host_artifacts = sum(
        1
        for app in apps
        if app["monitoring_strategy"]["signal_coverage"]["host_artifacts"] > 0
    )
    apps_with_high_precision_network_signals = sum(
        1
        for app in apps
        if app["monitoring_strategy"]["signal_coverage"]["high_precision_hostname_patterns"] > 0
    )

    category_defaults = [
        {
            "category": category,
            "policy_tier": details["policy_tier"],
            "reason": details["reason"],
        }
        for category, details in sorted(CATEGORY_DEFAULTS.items())
    ]

    return {
        "$schema": "./enterprise_app_monitoring_profile.schema.json",
        "profile_version": "1.0.0",
        "generated_at": date.today().isoformat(),
        "goal": (
            "Enterprise-oriented app monitoring list for Jamf-managed macOS devices "
            "and network telemetry keyed on dns.query, tls.sni, and http.hostname."
        ),
        "source_catalog": {
            "path": CATALOG_PATH.name,
            "schema_version": catalog["schema_version"],
            "generated_at": catalog["generated_at"],
            "app_count": len(catalog["apps"]),
            "sha256": sha256_hex(CATALOG_PATH),
        },
        "monitoring_fields": MONITORING_FIELDS,
        "policy_tiers": [
            {
                "id": policy_id,
                **details,
            }
            for policy_id, details in POLICY_TIERS.items()
        ],
        "category_defaults": category_defaults,
        "summary": {
            "total_apps": total_apps,
            "counts_by_policy_tier": dict(sorted(counts_by_policy_tier.items())),
            "counts_by_primary_action": dict(sorted(counts_by_primary_action.items())),
            "counts_by_category": dict(sorted(counts_by_category.items())),
            "apps_with_host_artifacts": apps_with_host_artifacts,
            "apps_with_high_precision_network_signals": apps_with_high_precision_network_signals,
            "apps_requiring_network_only_or_custom_inventory": total_apps - apps_with_host_artifacts,
        },
        "apps": apps,
    }


def main() -> None:
    catalog = load_catalog()
    profile = build_profile(catalog)
    OUTPUT_PATH.write_text(json.dumps(profile, indent=2, ensure_ascii=True) + "\n")


if __name__ == "__main__":
    main()
