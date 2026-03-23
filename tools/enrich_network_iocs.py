#!/usr/bin/env python3
"""Apply researched network IOC updates to app YAML files.

Replaces draft/legacy network IOC sections with research-backed data.
Only updates apps with verified provenance from official documentation.

Usage:
    python3 tools/enrich_network_iocs.py [--dry-run] [--app APP_ID]
"""

from __future__ import annotations

import argparse
import sys
from datetime import date
from pathlib import Path

APPS_DIR = Path(__file__).resolve().parent.parent / "apps"
TODAY = date.today().isoformat()


# Each entry: app_id -> dict with:
#   status: draft or reviewed (based on provenance quality)
#   provenance: { url, evidence }
#   hostname_patterns: list of { pattern, match, role }
#   keyword_patterns: list of { pattern, match }
NETWORK_IOC_UPDATES: dict[str, dict] = {

    # ===== CURSOR =====
    "cursor": {
        "status": "reviewed",
        "provenance": {
            "url": "https://cursor.com/security",
            "evidence": "Official security page lists exact subdomains for proxy whitelisting",
        },
        "hostname_patterns": [
            {"pattern": "cursor.sh", "match": "suffix", "role": "app_brand"},
            {"pattern": "cursor.com", "match": "suffix", "role": "app_brand"},
            {"pattern": "cursorapi.com", "match": "suffix", "role": "app_brand"},
            {"pattern": "cursor-cdn.com", "match": "suffix", "role": "cdn_static"},
            {"pattern": "api2.cursor.sh", "match": "exact", "role": "app_brand"},
            {"pattern": "api3.cursor.sh", "match": "exact", "role": "app_brand"},
            {"pattern": "api4.cursor.sh", "match": "exact", "role": "app_brand"},
            {"pattern": "api5.cursor.sh", "match": "exact", "role": "app_brand"},
            {"pattern": "repo42.cursor.sh", "match": "exact", "role": "app_brand"},
            {"pattern": "authenticate.cursor.sh", "match": "exact", "role": "app_brand"},
            {"pattern": "authenticator.cursor.sh", "match": "exact", "role": "app_brand"},
            {"pattern": "downloads.cursor.com", "match": "exact", "role": "app_brand"},
        ],
        "keyword_patterns": [
            {"pattern": "cursor", "match": "substring"},
        ],
    },

    # ===== WINDSURF =====
    "windsurf": {
        "status": "reviewed",
        "provenance": {
            "url": "https://windsurf.com/security",
            "evidence": "Official security page lists specific subdomains for whitelisting",
        },
        "hostname_patterns": [
            {"pattern": "codeium.com", "match": "suffix", "role": "app_brand"},
            {"pattern": "windsurf.com", "match": "suffix", "role": "app_brand"},
            {"pattern": "codeiumdata.com", "match": "suffix", "role": "cdn_static"},
            {"pattern": "server.codeium.com", "match": "exact", "role": "app_brand"},
            {"pattern": "web-backend.codeium.com", "match": "exact", "role": "app_brand"},
            {"pattern": "unleash.codeium.com", "match": "exact", "role": "app_brand"},
            {"pattern": "inference.codeium.com", "match": "exact", "role": "app_brand"},
        ],
        "keyword_patterns": [
            {"pattern": "windsurf", "match": "substring"},
            {"pattern": "codeium", "match": "substring"},
        ],
    },

    # ===== WARP =====
    "warp": {
        "status": "reviewed",
        "provenance": {
            "url": "https://www.warp.dev/legal/security",
            "evidence": "Security page confirms GCP+Sentry+Rudderstack; GitHub issue #5640 shows exact telemetry domains",
        },
        "hostname_patterns": [
            {"pattern": "warp.dev", "match": "suffix", "role": "app_brand"},
            {"pattern": "app.warp.dev", "match": "exact", "role": "app_brand"},
            {"pattern": "releases.warp.dev", "match": "exact", "role": "app_brand"},
        ],
        "keyword_patterns": [
            {"pattern": "warp.dev", "match": "substring"},
        ],
    },

    # ===== TRAE =====
    "trae": {
        "status": "reviewed",
        "provenance": {
            "url": "https://blog.unit221b.com/dont-read-this-blog/unveiling-trae-bytedances-ai-ide-and-its-extensive-data-collection-system",
            "evidence": "Unit 221B professional network traffic analysis of Trae IDE confirmed specific ByteDance telemetry domains",
        },
        "hostname_patterns": [
            {"pattern": "trae.ai", "match": "suffix", "role": "app_brand"},
            {"pattern": "trae.cn", "match": "suffix", "role": "app_brand"},
            {"pattern": "api.trae.ai", "match": "exact", "role": "app_brand"},
            {"pattern": "api-sg-central.trae.ai", "match": "exact", "role": "app_brand"},
            {"pattern": "mon-va.byteoversea.com", "match": "exact", "role": "app_brand"},
            {"pattern": "maliva-mcs.byteoversea.com", "match": "exact", "role": "app_brand"},
            {"pattern": "bytegate-sg.byteintlapi.com", "match": "exact", "role": "app_brand"},
            {"pattern": "byteoversea.com", "match": "suffix", "role": "platform_service"},
            {"pattern": "byteintlapi.com", "match": "suffix", "role": "platform_service"},
        ],
        "keyword_patterns": [
            {"pattern": "trae", "match": "substring"},
        ],
    },

    # ===== CLAUDE CODE =====
    "claude_code": {
        "status": "reviewed",
        "provenance": {
            "url": "https://docs.anthropic.com/en/docs/claude-code/enterprise-admin/network-configuration",
            "evidence": "Official enterprise network configuration docs list required URLs for firewall allowlisting",
        },
        "hostname_patterns": [
            {"pattern": "api.anthropic.com", "match": "exact", "role": "ai_service_provider"},
            {"pattern": "claude.ai", "match": "suffix", "role": "app_brand"},
            {"pattern": "platform.claude.com", "match": "exact", "role": "app_brand"},
            {"pattern": "code.claude.com", "match": "exact", "role": "app_brand"},
            {"pattern": "downloads.claude.ai", "match": "exact", "role": "app_brand"},
            {"pattern": "claudeusercontent.com", "match": "suffix", "role": "app_brand"},
        ],
        "keyword_patterns": [
            {"pattern": "claude code", "match": "substring"},
            {"pattern": "claude.ai", "match": "substring"},
        ],
    },

    # ===== CLINE =====
    "cline": {
        "status": "reviewed",
        "provenance": {
            "url": "https://docs.cline.bot/api/overview",
            "evidence": "Cline API docs show api.cline.bot as unified API endpoint; auth via app.cline.bot",
        },
        "hostname_patterns": [
            {"pattern": "cline.bot", "match": "suffix", "role": "app_brand"},
            {"pattern": "api.cline.bot", "match": "exact", "role": "app_brand"},
            {"pattern": "app.cline.bot", "match": "exact", "role": "app_brand"},
            {"pattern": "docs.cline.bot", "match": "exact", "role": "app_brand"},
            {"pattern": "api.anthropic.com", "match": "exact", "role": "ai_service_provider"},
            {"pattern": "api.openai.com", "match": "exact", "role": "ai_service_provider"},
            {"pattern": "openrouter.ai", "match": "suffix", "role": "ai_service_provider"},
        ],
        "keyword_patterns": [
            {"pattern": "cline", "match": "substring"},
        ],
    },

    # ===== CODEX APP =====
    "codex_app": {
        "status": "reviewed",
        "provenance": {
            "url": "https://developers.openai.com/codex/auth/",
            "evidence": "Codex auth docs show ChatGPT OAuth and api.openai.com as the API endpoint",
        },
        "hostname_patterns": [
            {"pattern": "api.openai.com", "match": "exact", "role": "ai_service_provider"},
            {"pattern": "chatgpt.com", "match": "suffix", "role": "ai_service_provider"},
            {"pattern": "auth.openai.com", "match": "exact", "role": "ai_service_provider"},
            {"pattern": "openai.com", "match": "suffix", "role": "ai_service_provider"},
        ],
        "keyword_patterns": [
            {"pattern": "codex", "match": "substring"},
        ],
    },

    # ===== DEVIN =====
    "devin": {
        "status": "reviewed",
        "provenance": {
            "url": "https://docs.devin.ai/enterprise/vpc/requirements",
            "evidence": "Official VPC network requirements list frp-server-0.devin.ai, api.devin.ai as required egress destinations",
        },
        "hostname_patterns": [
            {"pattern": "devin.ai", "match": "suffix", "role": "app_brand"},
            {"pattern": "cognition.ai", "match": "suffix", "role": "app_brand"},
            {"pattern": "api.devin.ai", "match": "exact", "role": "app_brand"},
            {"pattern": "app.devin.ai", "match": "exact", "role": "app_brand"},
            {"pattern": "frp-server-0.devin.ai", "match": "exact", "role": "app_brand"},
            {"pattern": "static.devin.ai", "match": "exact", "role": "app_brand"},
        ],
        "keyword_patterns": [
            {"pattern": "devin", "match": "substring"},
            {"pattern": "cognition", "match": "substring"},
        ],
    },

    # ===== SPLASHTOP =====
    "splashtop": {
        "status": "reviewed",
        "provenance": {
            "url": "https://support-splashtopbusiness.splashtop.com/hc/en-us/articles/115001811966",
            "evidence": "Official firewall documentation lists specific API, relay, and update domains",
        },
        "hostname_patterns": [
            {"pattern": "splashtop.com", "match": "suffix", "role": "app_brand"},
            {"pattern": "splashtop.eu", "match": "suffix", "role": "app_brand"},
            {"pattern": "api.splashtop.com", "match": "suffix", "role": "app_brand"},
            {"pattern": "relay.splashtop.com", "match": "suffix", "role": "app_brand"},
            {"pattern": "update.splashtop.com", "match": "exact", "role": "app_brand"},
            {"pattern": "sn.splashtop.com", "match": "exact", "role": "app_brand"},
        ],
        "keyword_patterns": [
            {"pattern": "splashtop", "match": "substring"},
        ],
    },

    # ===== REWIND (now Limitless) =====
    "rewind": {
        "status": "reviewed",
        "provenance": {
            "url": "https://www.limitless.ai/developers",
            "evidence": "Developer API docs show api.limitless.ai as the API endpoint; rewind.ai redirects to limitless.ai",
        },
        "hostname_patterns": [
            {"pattern": "rewind.ai", "match": "suffix", "role": "app_brand"},
            {"pattern": "limitless.ai", "match": "suffix", "role": "app_brand"},
            {"pattern": "api.limitless.ai", "match": "exact", "role": "app_brand"},
            {"pattern": "app.limitless.ai", "match": "exact", "role": "app_brand"},
        ],
        "keyword_patterns": [
            {"pattern": "rewind", "match": "substring"},
            {"pattern": "limitless", "match": "substring"},
        ],
    },

    # ===== AMAZON Q DEVELOPER =====
    "amazon_q_developer": {
        "status": "reviewed",
        "provenance": {
            "url": "https://docs.aws.amazon.com/amazonq/latest/qdeveloper-ug/firewall.html",
            "evidence": "Official AWS firewall config doc for Amazon Q Developer lists specific service endpoints",
        },
        "hostname_patterns": [
            {"pattern": "codewhisperer.us-east-1.amazonaws.com", "match": "exact", "role": "app_brand"},
            {"pattern": "q.us-east-1.amazonaws.com", "match": "exact", "role": "app_brand"},
            {"pattern": "q.eu-central-1.amazonaws.com", "match": "exact", "role": "app_brand"},
            {"pattern": "q-developer-integration.us-east-1.api.aws", "match": "exact", "role": "app_brand"},
            {"pattern": "idetoolkits-hostedfiles.amazonaws.com", "match": "exact", "role": "app_brand"},
            {"pattern": "idetoolkits.amazonwebservices.com", "match": "exact", "role": "app_brand"},
            {"pattern": "aws-toolkit-language-servers.amazonaws.com", "match": "exact", "role": "app_brand"},
            {"pattern": "client-telemetry.us-east-1.amazonaws.com", "match": "exact", "role": "app_brand"},
        ],
        "keyword_patterns": [
            {"pattern": "amazon q", "match": "substring"},
            {"pattern": "codewhisperer", "match": "substring"},
        ],
    },

    # ===== JETBRAINS AI ASSISTANT =====
    "jetbrains_ai_assistant": {
        "status": "reviewed",
        "provenance": {
            "url": "https://youtrack.jetbrains.com/articles/SUPPORT-A-297/",
            "evidence": "Official JetBrains support article lists specific AI Assistant firewall allowlist URLs",
        },
        "hostname_patterns": [
            {"pattern": "api.jetbrains.ai", "match": "exact", "role": "app_brand"},
            {"pattern": "api.ai.jetbrains.com.cn", "match": "exact", "role": "app_brand"},
            {"pattern": "api.app.prod.grazie.aws.intellij.net", "match": "exact", "role": "app_brand"},
        ],
        "keyword_patterns": [
            {"pattern": "jetbrains ai", "match": "substring"},
        ],
    },

    # ===== KIRO =====
    "kiro": {
        "status": "reviewed",
        "provenance": {
            "url": "https://kiro.dev/docs/privacy-and-security/firewalls/",
            "evidence": "Official firewall allowlist documentation lists every domain Kiro contacts",
        },
        "hostname_patterns": [
            {"pattern": "kiro.dev", "match": "suffix", "role": "app_brand"},
            {"pattern": "app.kiro.dev", "match": "exact", "role": "app_brand"},
            {"pattern": "cli.kiro.dev", "match": "exact", "role": "app_brand"},
            {"pattern": "prod.us-east-1.auth.desktop.kiro.dev", "match": "exact", "role": "app_brand"},
            {"pattern": "prod.us-east-1.telemetry.desktop.kiro.dev", "match": "exact", "role": "app_brand"},
            {"pattern": "prod.download.desktop.kiro.dev", "match": "exact", "role": "app_brand"},
            {"pattern": "q.us-east-1.amazonaws.com", "match": "exact", "role": "ai_service_provider"},
        ],
        "keyword_patterns": [
            {"pattern": "kiro", "match": "substring"},
        ],
    },

    # ===== AUGMENT =====
    "augment": {
        "status": "reviewed",
        "provenance": {
            "url": "https://docs.augmentcode.com/setup-augment/network-configuration",
            "evidence": "Official network configuration doc lists auth, API, telemetry, and CDN domains",
        },
        "hostname_patterns": [
            {"pattern": "augmentcode.com", "match": "suffix", "role": "app_brand"},
            {"pattern": "auth.augmentcode.com", "match": "exact", "role": "app_brand"},
            {"pattern": "login.augmentcode.com", "match": "exact", "role": "app_brand"},
            {"pattern": "api.augmentcode.com", "match": "suffix", "role": "app_brand"},
            {"pattern": "evs.grdt.augmentcode.com", "match": "exact", "role": "app_brand"},
            {"pattern": "cdn.augmentcode.com", "match": "exact", "role": "cdn_static"},
            {"pattern": "app.augmentcode.com", "match": "exact", "role": "app_brand"},
        ],
        "keyword_patterns": [
            {"pattern": "augment", "match": "substring"},
            {"pattern": "augmentcode", "match": "substring"},
        ],
    },

    # ===== CONTINUE =====
    "continue": {
        "status": "reviewed",
        "provenance": {
            "url": "https://docs.continue.dev/customize/telemetry",
            "evidence": "Telemetry docs confirm PostHog usage; continue.dev hosts Hub for configs and secrets",
        },
        "hostname_patterns": [
            {"pattern": "continue.dev", "match": "suffix", "role": "app_brand"},
        ],
        "keyword_patterns": [
            {"pattern": "continue.dev", "match": "substring"},
        ],
    },

    # ===== BOLT =====
    "bolt": {
        "status": "reviewed",
        "provenance": {
            "url": "https://support.bolt.new/building/intro-bolt",
            "evidence": "Bolt docs confirm StackBlitz parent, WebContainers runtime, bolt.host for project hosting",
        },
        "hostname_patterns": [
            {"pattern": "bolt.new", "match": "suffix", "role": "app_brand"},
            {"pattern": "bolt.host", "match": "suffix", "role": "app_brand"},
            {"pattern": "stackblitz.com", "match": "suffix", "role": "app_brand"},
            {"pattern": "webcontainers.io", "match": "suffix", "role": "platform_service"},
        ],
        "keyword_patterns": [
            {"pattern": "bolt.new", "match": "substring"},
            {"pattern": "stackblitz", "match": "substring"},
        ],
    },

    # ===== LOVABLE =====
    "lovable": {
        "status": "reviewed",
        "provenance": {
            "url": "https://docs.lovable.dev/features/custom-domain",
            "evidence": "Docs confirm lovable.app hosting domain and lovable.dev as the main platform",
        },
        "hostname_patterns": [
            {"pattern": "lovable.dev", "match": "suffix", "role": "app_brand"},
            {"pattern": "lovable.app", "match": "suffix", "role": "app_brand"},
        ],
        "keyword_patterns": [
            {"pattern": "lovable", "match": "substring"},
        ],
    },

    # ===== GEMINI CLI =====
    "gemini_cli": {
        "status": "reviewed",
        "provenance": {
            "url": "https://ai.google.dev/api",
            "evidence": "Official Gemini API docs show generativelanguage.googleapis.com as REST endpoint",
        },
        "hostname_patterns": [
            {"pattern": "generativelanguage.googleapis.com", "match": "exact", "role": "ai_service_provider"},
            {"pattern": "aiplatform.googleapis.com", "match": "exact", "role": "ai_service_provider"},
        ],
        "keyword_patterns": [
            {"pattern": "gemini-cli", "match": "substring"},
            {"pattern": "gemini cli", "match": "substring"},
        ],
    },

    # ===== ROO CODE =====
    "roo_code": {
        "status": "reviewed",
        "provenance": {
            "url": "https://github.com/RooCodeInc/Roo-Code/blob/main/PRIVACY.md",
            "evidence": "PRIVACY.md confirms PostHog telemetry; Cloud uses roocode.cloud; app.roocode.com for cloud portal",
        },
        "hostname_patterns": [
            {"pattern": "roocode.com", "match": "suffix", "role": "app_brand"},
            {"pattern": "roocode.cloud", "match": "suffix", "role": "app_brand"},
        ],
        "keyword_patterns": [
            {"pattern": "roocode", "match": "substring"},
            {"pattern": "roo code", "match": "substring"},
        ],
    },

    # ===== SOURCEGRAPH CODY =====
    "sourcegraph_cody": {
        "status": "reviewed",
        "provenance": {
            "url": "https://sourcegraph.com/docs/admin/model-provider",
            "evidence": "Official docs confirm cody-gateway.sourcegraph.com as the LLM proxy gateway",
        },
        "hostname_patterns": [
            {"pattern": "sourcegraph.com", "match": "suffix", "role": "app_brand"},
            {"pattern": "cody-gateway.sourcegraph.com", "match": "exact", "role": "app_brand"},
            {"pattern": "accounts.sourcegraph.com", "match": "exact", "role": "app_brand"},
        ],
        "keyword_patterns": [
            {"pattern": "cody", "match": "substring"},
            {"pattern": "sourcegraph", "match": "substring"},
        ],
    },

    # ===== REPLIT =====
    "replit": {
        "status": "reviewed",
        "provenance": {
            "url": "https://docs.replit.com/cloud-services/deployments/custom-domains",
            "evidence": "Docs confirm replit.app for deployed apps; all replit-specific domains verified",
        },
        "hostname_patterns": [
            {"pattern": "replit.com", "match": "suffix", "role": "app_brand"},
            {"pattern": "replit.dev", "match": "suffix", "role": "app_brand"},
            {"pattern": "replit.app", "match": "suffix", "role": "app_brand"},
            {"pattern": "replitusercontent.com", "match": "suffix", "role": "file_upload"},
            {"pattern": "repl.co", "match": "suffix", "role": "app_brand"},
        ],
        "keyword_patterns": [
            {"pattern": "replit", "match": "substring"},
        ],
    },

    # ===== UI-TARS DESKTOP =====
    "ui_tars_desktop": {
        "status": "draft",
        "provenance": {
            "url": "https://github.com/bytedance/UI-TARS-desktop",
            "evidence": "Agent TARS docs at agent-tars.com; model info at seed-tars.com; bytedance.com removed as too broad",
        },
        "hostname_patterns": [
            {"pattern": "agent-tars.com", "match": "suffix", "role": "app_brand"},
            {"pattern": "seed-tars.com", "match": "suffix", "role": "app_brand"},
        ],
        "keyword_patterns": [
            {"pattern": "ui-tars", "match": "substring"},
            {"pattern": "agent-tars", "match": "substring"},
        ],
    },

    # ===== ANTIGRAVITY =====
    "antigravity": {
        "status": "reviewed",
        "provenance": {
            "url": "https://antigravity.google/docs/home",
            "evidence": "Official Antigravity site is antigravity.google; google.com and googleapis.com removed as too broad",
        },
        "hostname_patterns": [
            {"pattern": "antigravity.google", "match": "suffix", "role": "app_brand"},
        ],
        "keyword_patterns": [
            {"pattern": "antigravity", "match": "substring"},
        ],
    },

    # ===== AUTOGPT =====
    "autogpt": {
        "status": "reviewed",
        "provenance": {
            "url": "https://github.com/Significant-Gravitas/AutoGPT",
            "evidence": "Official platform at agpt.co with subdomains platform/setup/docs; LLM provider domains removed as too broad",
        },
        "hostname_patterns": [
            {"pattern": "agpt.co", "match": "suffix", "role": "app_brand"},
        ],
        "keyword_patterns": [
            {"pattern": "autogpt", "match": "substring"},
            {"pattern": "agpt", "match": "substring"},
        ],
    },

    # ===== SWEEP =====
    "sweep": {
        "status": "reviewed",
        "provenance": {
            "url": "https://sweep.dev/",
            "evidence": "Official domain sweep.dev confirmed; github.com removed as too broad",
        },
        "hostname_patterns": [
            {"pattern": "sweep.dev", "match": "suffix", "role": "app_brand"},
        ],
        "keyword_patterns": [
            {"pattern": "sweep", "match": "substring"},
        ],
    },

    # ===== QODER =====
    "qoder": {
        "status": "reviewed",
        "provenance": {
            "url": "https://docs.qoder.com/troubleshooting/common-issue",
            "evidence": "Official FAQ lists api1/api2/api3.qoder.sh as API backends; aliyun.com removed as too broad",
        },
        "hostname_patterns": [
            {"pattern": "qoder.com", "match": "suffix", "role": "app_brand"},
            {"pattern": "qoder.sh", "match": "suffix", "role": "app_brand"},
        ],
        "keyword_patterns": [
            {"pattern": "qoder", "match": "substring"},
        ],
    },

    # ===== AIDER =====
    "aider": {
        "status": "reviewed",
        "provenance": {
            "url": "https://aider.chat/docs/config/dotenv.html",
            "evidence": "Aider docs confirm aider.chat as the official domain; CLI connects directly to user-configured LLM providers",
        },
        "hostname_patterns": [
            {"pattern": "aider.chat", "match": "suffix", "role": "app_brand"},
        ],
        "keyword_patterns": [
            {"pattern": "aider", "match": "substring"},
        ],
    },
}


def build_network_yaml(data: dict) -> str:
    """Build YAML text for a network IOC section."""
    lines = []
    lines.append("  network:")
    lines.append(f"    status: {data['status']}")
    lines.append("    provenance:")
    lines.append(f"      url: {data['provenance']['url']}")
    lines.append(f"      evidence: {data['provenance']['evidence']}")
    lines.append(f"      checked_at: '{TODAY}'")

    if data.get("hostname_patterns"):
        lines.append("    hostname_patterns:")
        for hp in data["hostname_patterns"]:
            lines.append(f"    - pattern: {hp['pattern']}")
            lines.append(f"      match: {hp['match']}")
            lines.append(f"      role: {hp['role']}")

    if data.get("keyword_patterns"):
        lines.append("    keyword_patterns:")
        for kp in data["keyword_patterns"]:
            lines.append(f"    - pattern: {kp['pattern']}")
            lines.append(f"      match: {kp['match']}")

    return "\n".join(lines)


def update_app_file(app_id: str, data: dict, dry_run: bool = False) -> bool:
    """Update network IOCs in an app YAML file."""
    yaml_path = APPS_DIR / f"{app_id}.yaml"
    if not yaml_path.exists():
        print(f"  SKIP: {yaml_path} does not exist")
        return False

    content = yaml_path.read_text()

    # Find and replace the network section
    lines = content.split("\n")
    net_start = None
    net_end = None

    for i, line in enumerate(lines):
        if line.strip().startswith("network:") and "  network:" in line:
            indent = len(line) - len(line.lstrip())
            if indent <= 4:
                net_start = i
                for j in range(i + 1, len(lines)):
                    stripped = lines[j].strip()
                    if stripped == "":
                        continue
                    line_indent = len(lines[j]) - len(lines[j].lstrip())
                    if line_indent <= indent:
                        net_end = j
                        break
                if net_end is None:
                    net_end = len(lines)
                break

    if net_start is None:
        print(f"  WARN: {app_id} - could not locate network section")
        return False

    new_block = build_network_yaml(data)

    if dry_run:
        print(f"  DRY-RUN: Would update {app_id}")
        print(f"    hostname_patterns: {len(data.get('hostname_patterns', []))}")
        print(f"    keyword_patterns: {len(data.get('keyword_patterns', []))}")
        print(f"    status: {data['status']}")
        return True

    new_lines = lines[:net_start] + [new_block] + lines[net_end:]
    new_content = "\n".join(new_lines)

    if not new_content.endswith("\n"):
        new_content += "\n"

    yaml_path.write_text(new_content)
    print(f"  UPDATED: {app_id} -> {data['status']} ({len(data.get('hostname_patterns', []))} hosts, {len(data.get('keyword_patterns', []))} keywords)")
    return True


def main():
    parser = argparse.ArgumentParser(description="Apply researched network IOC updates")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--app", type=str)
    args = parser.parse_args()

    if args.app:
        if args.app not in NETWORK_IOC_UPDATES:
            print(f"ERROR: {args.app} not in update map")
            sys.exit(1)
        apps = {args.app: NETWORK_IOC_UPDATES[args.app]}
    else:
        apps = NETWORK_IOC_UPDATES

    updated = 0
    for app_id, data in sorted(apps.items()):
        print(f"Processing {app_id}...")
        if update_app_file(app_id, data, dry_run=args.dry_run):
            updated += 1

    print(f"\nDone: {updated} apps updated out of {len(apps)}")


if __name__ == "__main__":
    main()
