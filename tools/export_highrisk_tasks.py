#!/usr/bin/env python3
"""Export the high-risk task matrix with current quality and priority review data."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path
from typing import Any

from app_control.catalog import load_apps
from app_control.quality import SEVERITY_RANK, assess_app_quality

HEADER = [
    "order",
    "phase",
    "task_id",
    "app_id",
    "app_name",
    "category",
    "product_shape",
    "product_type",
    "current_severity",
    "current_priority_score",
    "current_quality_grade",
    "current_network_grade",
    "current_host_grade",
    "current_network_status",
    "current_host_status",
    "review_track",
    "gate_condition",
    "depends_on",
    "status",
    "manual_decision",
    "notes",
    "priority_standard_case",
    "recommended_severity",
    "severity_alignment",
    "ownership_review_required",
    "quality_issue_count",
    "quality_issue_summary",
]

EXPLICIT_PRIORITY_CASES: dict[str, dict[str, str]] = {
    "openclaw": {
        "recommended_severity": "critical",
        "case": "openclaw_zeroclaw_local_autonomous_agent",
        "notes": "Installed on host; high-autonomy local operation; can directly and continuously operate the computer.",
    },
    "zeroclaw": {
        "recommended_severity": "critical",
        "case": "openclaw_zeroclaw_local_autonomous_agent",
        "notes": "Installed on host; high-autonomy local operation; can directly and continuously operate the computer.",
    },
    "opencode": {
        "recommended_severity": "high",
        "case": "opencode_claude_code_user_invoked_local_exec",
        "notes": "Installed on host; user-invoked; can automatically execute commands and read files after user intent is given.",
    },
    "claude_code": {
        "recommended_severity": "high",
        "case": "opencode_claude_code_user_invoked_local_exec",
        "notes": "Installed on host; user-invoked; can automatically execute commands and read files after user intent is given.",
    },
    "lovable": {
        "recommended_severity": "medium",
        "case": "lovable_bolt_replit_active_upload_surface",
        "notes": "Treat as an active-upload surface for enterprise priority review; do not auto-escalate merely because it is an AI coding product.",
    },
    "bolt": {
        "recommended_severity": "medium",
        "case": "lovable_bolt_replit_active_upload_surface",
        "notes": "Treat as an active-upload surface for enterprise priority review; do not auto-escalate merely because it is an AI coding product.",
    },
    "replit": {
        "recommended_severity": "medium",
        "case": "lovable_bolt_replit_active_upload_surface",
        "notes": "Treat as an active-upload surface for enterprise priority review; do not auto-escalate solely because desktop packaging exists.",
    },
}


def select_apps(apps: list[dict[str, Any]], min_severity: str) -> list[dict[str, Any]]:
    threshold = SEVERITY_RANK[min_severity]
    return [app for app in apps if SEVERITY_RANK.get(app.get("severity", "low"), 99) <= threshold]


def sort_apps(apps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        apps,
        key=lambda app: (
            SEVERITY_RANK.get(app.get("severity", "low"), 99),
            -int(app.get("priority_score", 0) or 0),
            app.get("category", ""),
            app.get("id", ""),
        ),
    )


def join_list(values: list[str]) -> str:
    return "|".join(values)


def current_status(app: dict[str, Any], group: str) -> str:
    return str((((app.get("iocs") or {}).get(group)) or {}).get("status", ""))


def summarize_issues(issues: list[str], limit: int = 4) -> str:
    if not issues:
        return ""
    if len(issues) <= limit:
        return "; ".join(issues)
    return "; ".join(issues[:limit]) + f" (+{len(issues) - limit} more)"


def priority_case(app: dict[str, Any]) -> dict[str, str]:
    return EXPLICIT_PRIORITY_CASES.get(app["id"], {})


def ownership_review_required(app: dict[str, Any], quality: dict[str, Any]) -> bool:
    network_flags = quality["network"]["flags"]
    host_flags = quality["host"]["flags"]
    shapes = set(app.get("product_shape", []))

    if app.get("category") == "CLAW_FAMILY_APP":
        if "macos" not in shapes or host_flags.get("missing"):
            return True

    if network_flags.get("shared_only") and (host_flags.get("missing") or not quality["flags"]["defense_in_depth"]):
        return True
    if network_flags.get("keyword_only") and (host_flags.get("missing") or host_flags.get("repo_local_only")):
        return True
    return False


def severity_review_fields(app: dict[str, Any], quality: dict[str, Any]) -> tuple[str, str, str, str, str]:
    case = priority_case(app)
    current = app["severity"]
    recommended = case.get("recommended_severity", current)
    alignment = "aligned" if recommended == current else "conflict"
    if not case:
        alignment = "no_explicit_case"

    ownership_flag = ownership_review_required(app, quality)
    if ownership_flag:
        status = "todo"
        decision = "ownership_review_required"
    elif alignment == "conflict":
        status = "todo"
        decision = f"severity_conflict_with_{case['case']}"
    else:
        status = "done"
        decision = "retain_current_severity"

    note_parts: list[str] = []
    if case:
        note_parts.append(case["notes"])
    if ownership_flag:
        note_parts.append(
            "Independent review required: standalone-app boundary or host-manageability is not sufficiently clear under the Kimi-Claw standard."
        )
    return recommended, alignment, status, decision, " ".join(note_parts)


def ioc_review_fields(quality: dict[str, Any]) -> tuple[str, str]:
    grade = quality["overall"]["grade"]
    if grade in {"excellent", "good"}:
        return "done", f"retain_{grade}"
    return "todo", f"review_{grade}"


def gap_closure_fields(app: dict[str, Any], quality: dict[str, Any]) -> tuple[str, str, str]:
    blockers: list[str] = []
    if not quality["flags"]["defense_in_depth"]:
        blockers.append("missing defense in depth")
    if not quality["flags"]["omission_rationale"]:
        blockers.append("notes missing omission rationale")
    if ownership_review_required(app, quality):
        blockers.append("ownership/shared-surface review required")
    if quality["overall"]["grade"] in {"acceptable", "needs_work"}:
        blockers.append(f"overall quality is {quality['overall']['grade']}")

    if blockers:
        return "todo", "close_quality_and_scope_gaps", "; ".join(blockers)
    return "done", "no_gap_closure_needed", ""


def fresh_review_row(row: dict[str, str], all_todo: bool) -> dict[str, str]:
    if not all_todo:
        return row
    fresh = dict(row)
    fresh["status"] = "todo"
    fresh["manual_decision"] = ""
    return fresh


def build_rows(apps: list[dict[str, Any]], all_todo: bool = False) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    order = 1
    for app in sort_apps(apps):
        quality = assess_app_quality(app)
        issues = quality["overall"]["issues"]
        case = priority_case(app)
        recommended, alignment, severity_status, severity_decision, severity_notes = severity_review_fields(app, quality)
        ownership_flag = "yes" if ownership_review_required(app, quality) else "no"
        issue_summary = summarize_issues(issues)

        common = {
            "app_id": app["id"],
            "app_name": app["name"],
            "category": app["category"],
            "product_shape": join_list(app.get("product_shape", [])),
            "product_type": join_list(app.get("product_type", [])),
            "current_severity": app["severity"],
            "current_priority_score": str(app["priority_score"]),
            "current_quality_grade": quality["overall"]["grade"],
            "current_network_grade": quality["network"]["grade"],
            "current_host_grade": quality["host"]["grade"],
            "current_network_status": current_status(app, "network"),
            "current_host_status": current_status(app, "host"),
            "priority_standard_case": case.get("case", ""),
            "recommended_severity": recommended,
            "severity_alignment": alignment,
            "ownership_review_required": ownership_flag,
            "quality_issue_count": str(len(issues)),
            "quality_issue_summary": issue_summary,
        }

        severity_task_id = f"severity_review__{app['id']}"
        rows.append(
            fresh_review_row(
                {
                    "order": str(order),
                    "phase": "severity_review",
                    "task_id": severity_task_id,
                    "review_track": "independent_priority_review",
                    "gate_condition": "Independent review must answer ownership/shared-surface, quality-standard fit, and enterprise-management viewpoint questions before severity is trusted.",
                    "depends_on": "",
                    "status": severity_status,
                    "manual_decision": severity_decision,
                    "notes": severity_notes,
                    **common,
                },
                all_todo,
            )
        )
        order += 1

        ioc_status, ioc_decision = ioc_review_fields(quality)
        ioc_task_id = f"ioc_quality_review__{app['id']}"
        rows.append(
            fresh_review_row(
                {
                    "order": str(order),
                    "phase": "ioc_quality_review",
                    "task_id": ioc_task_id,
                    "review_track": "quality_standard_review",
                    "gate_condition": "Assess this app against docs/QUALITY_STANDARDS.md and verify ownership boundaries, alert independence, and actionable detections.",
                    "depends_on": severity_task_id,
                    "status": ioc_status,
                    "manual_decision": ioc_decision,
                    "notes": issue_summary or "Quality grades already satisfy current review threshold.",
                    **common,
                },
                all_todo,
            )
        )
        order += 1

        gap_status, gap_decision, gap_notes = gap_closure_fields(app, quality)
        rows.append(
            fresh_review_row(
                {
                    "order": str(order),
                    "phase": "gap_closure",
                    "task_id": f"gap_closure__{app['id']}",
                    "review_track": "gap_closure_review",
                    "gate_condition": "Close quality, ownership, and documentation gaps before treating the record as stable enterprise guidance.",
                    "depends_on": ioc_task_id,
                    "status": gap_status,
                    "manual_decision": gap_decision,
                    "notes": gap_notes or "No additional quality or ownership gap is open.",
                    **common,
                },
                all_todo,
            )
        )
        order += 1

    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description="Export highrisk task CSV with quality-standard evaluation")
    parser.add_argument(
        "--output",
        default="scratch/highrisk_tasks.csv",
        help="Write CSV to this path (default: scratch/highrisk_tasks.csv)",
    )
    parser.add_argument(
        "--min-severity",
        choices=("critical", "high", "medium", "low"),
        default="high",
        help="Include apps at or above this severity (default: high)",
    )
    parser.add_argument(
        "--all-todo",
        action="store_true",
        help="Force every exported task to status=todo and clear manual_decision for a fresh review pass.",
    )
    args = parser.parse_args()

    selected_apps = select_apps(load_apps(), args.min_severity)
    rows = build_rows(selected_apps, all_todo=args.all_todo)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=HEADER)
        writer.writeheader()
        writer.writerows(rows)

    print(
        f"wrote {len(rows)} rows for {len(selected_apps)} apps "
        f"(min_severity={args.min_severity}, all_todo={args.all_todo}) -> {output_path}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
