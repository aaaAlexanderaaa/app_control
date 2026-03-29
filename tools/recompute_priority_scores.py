#!/usr/bin/env python3
"""Normalize priority_score across app YAML files using governance risk bands.

This helper is not authoritative for app ownership or severity. Before relying on
its output, perform an independent review pass using the highest-priority bad-case
checks in `docs/QUALITY_STANDARDS.md`.

Priority is defined for enterprise data security and app control, with emphasis on
high-profile and high-risk AI apps. Explicit named cases in `docs/QUALITY_STANDARDS.md`
override these generic bands:

1. fully automated hosting / always-on autonomous agents
2. automated command execution
3. interaction-required execution
4. active file or prompt uploads leading to leakage
5. local-first or lower-priority point tools
"""

from __future__ import annotations

import argparse
import re
from collections import Counter
from pathlib import Path

from app_control.catalog import iter_app_paths, load_app

BANDS: dict[str, tuple[int, int]] = {
    "A": (90, 96),
    "B": (82, 89),
    "C": (74, 81),
    "D": (60, 73),
    "E": (35, 59),
}

LOCAL_TYPES = {"local_llm_runtime", "local_llm_client", "llm_runtime", "model_download"}
A_TYPES = {
    "personal_agent",
    "hosted_agent",
    "24_7_agent",
    "agent_runtime",
    "autonomous_agent",
    "persistent_agent",
    "daemon",
    "agent_os",
    "computer_use_agent",
    "containerized_agent",
    "messaging_gateway",
    "remote_control",
}
LOWER_INTERACTION_TYPES = {"ide", "llm_client", "desktop_client", "chatbot"}
C_DESKTOP_TYPES = {"desktop_agent", "assistant", "knowledge_assistant", "contextual_assistant", "launcher", "cli_agent"}
D_CATEGORIES = {
    "GENAI_CHAT",
    "CLOUD_STORAGE",
    "COLLAB_KNOWLEDGE",
    "DOC_CONVERSION_UPLOAD",
    "FILE_TRANSFER",
    "MEETING_TRANSCRIPTION",
    "NON_WORK_IM",
    "PASTE_SHARING",
    "SCREEN_RECORDING_SHARE",
    "AI_OBSERVABILITY",
}
E_CATEGORIES = {"TRANSLATION", "GENAI_MEDIA"}

EXPLICIT_BAND_OVERRIDES = {
    # Mandatory examples from docs/QUALITY_STANDARDS.md
    "openclaw": "A",
    "zeroclaw": "A",
    "opencode": "B",
    "claude_code": "B",
    "lovable": "D",
    "bolt": "D",
    "replit": "D",
}


def band_for(app: dict) -> str:
    app_id = app["id"]
    if app_id in EXPLICIT_BAND_OVERRIDES:
        return EXPLICIT_BAND_OVERRIDES[app_id]

    category = app["category"]
    types = set(app.get("product_type", []))

    if types & LOCAL_TYPES:
        return "E"
    if category in E_CATEGORIES:
        return "E"
    if category == "CLAW_FAMILY_APP" or types & A_TYPES:
        return "A"
    if category == "AI_BROWSER_AGENT":
        return "A" if "persistent_agent" in types else "B"
    if category == "AI_AGENT_FRAMEWORK":
        high_autonomy = {"autonomous_agent", "computer_use_agent", "daemon", "agent_os", "hosted_agent", "24_7_agent"}
        return "A" if types & high_autonomy else "B"
    if category == "GENAI_CODING":
        automated_execution = {"cli_agent", "agentic_coding", "terminal", "coding_assistant"}
        return "B" if types & automated_execution else "C"
    if category in {"REMOTE_ACCESS", "P2P_FILE_SHARING"}:
        return "C"
    if category == "AI_DESKTOP_ASSISTANT":
        return "C" if types & C_DESKTOP_TYPES else "D"
    if category in D_CATEGORIES:
        return "D"
    return "D"


def compute_priority_score(app: dict) -> tuple[int, str]:
    types = set(app.get("product_type", []))
    old_score = int(app["priority_score"])
    band = band_for(app)
    low, high = BANDS[band]
    score = min(max(old_score, low), high)

    if app["severity"] == "critical" and score < high:
        score += 1
    if app["severity"] == "low" and band in {"D", "E"} and score > low:
        score -= 1
    if types & {"hosted_agent", "24_7_agent", "daemon", "persistent_agent", "autonomous_agent", "computer_use_agent", "messaging_gateway", "agent_os"} and score < high:
        score += 1
    if types & {"cli_agent", "agentic_coding", "browser_automation", "terminal", "coding_assistant"} and band == "B" and score < high:
        score += 1
    if types & LOWER_INTERACTION_TYPES and band in {"C", "D"} and score > low:
        score -= 1

    return max(low, min(high, score)), band


def update_priority_line(path: Path, new_score: int) -> bool:
    content = path.read_text(encoding="utf-8")
    updated, count = re.subn(
        r"(?m)^(priority_score:\s*)\d+(\s*)$",
        lambda match: f"{match.group(1)}{new_score}{match.group(2)}",
        content,
        count=1,
    )
    if count != 1:
        raise ValueError(f"Could not update priority_score in {path}")
    if updated == content:
        return False
    path.write_text(updated, encoding="utf-8")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description="Recompute priority_score using governance risk bands")
    parser.add_argument("--write", action="store_true", help="Write updated priority_score values back to apps/*.yaml")
    args = parser.parse_args()

    changes: list[tuple[str, int, int, str]] = []
    band_counts: Counter[str] = Counter()
    for path in iter_app_paths():
        app = load_app(path)
        new_score, band = compute_priority_score(app)
        band_counts[band] += 1
        old_score = int(app["priority_score"])
        if old_score != new_score:
            changes.append((path.name, old_score, new_score, band))
            if args.write:
                update_priority_line(path, new_score)

    print("WARNING: priority/severity decisions require independent review; see docs/QUALITY_STANDARDS.md")
    print("Priority bands:")
    for band in ("A", "B", "C", "D", "E"):
        print(f"  {band}: {band_counts.get(band, 0)} apps")

    print(f"\nChanged scores: {len(changes)}")
    for filename, old_score, new_score, band in changes[:80]:
        print(f"  {filename}: {old_score} -> {new_score} [{band}]")
    if len(changes) > 80:
        print(f"  ... {len(changes) - 80} more")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
