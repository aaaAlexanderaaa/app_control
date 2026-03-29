# Manual IOC Review Plan - 2026-03-29

## Overview
Independent manual review of all 161 high/critical severity apps.
Focus: verify IOCs, discover new detection methods, fix hostname match types.

## Hostname Match Policy
- **Brand-owned apex domains** (low FP): `suffix` - catches api.*, docs.*, www.* subdomains
- **Shared infrastructure** (high FP): `exact` - e.g., *.qq.com, *.fly.dev, *.github.io
- **Brand subdomain on shared parent**: `exact` on full FQDN
- Decision informed by crt.sh subdomain counts during review

## Dead App Policy
- Verify truly dead (not network issue or domain migration)
- If confirmed dead: keep in apps/, add statement in notes, leave IOC as draft
- Do NOT delete from catalog

## Batch Assignments

### Phase 1: CLAW_FAMILY Apps (48 apps, 7 commits)

**Batch 1A - Reference Apps (2)**: openclaw, zeroclaw
**Batch 1B - Problem Apps (3)**: shrew, edict, flowly_ai
**Batch 1C - Web-Only (5)**: meowclaw, octoclaw, safeclaw, supaclaw, vivaclaw
**Batch 1D-i (10)**: angelclaw, atomic_bot, autobot, autoclaw, autoglm_claw, babyclaw, clawapp, clawlet, clawx, copaw
**Batch 1D-ii (10)**: countbot, easyclaw, hermes_agent, hermitclaw, ironclaw, katclaw, langbot, lettabot, lobsterai, microclaw
**Batch 1D-iii (10)**: mindclaw, molili, moltis, moxxy, nanobot, nanoclaw, nullclaw, oneclaw, openclaw_macos_companion, pickle_bot
**Batch 1D-iv (8)**: picobot, picoclaw, qclaw, qoderwork, tinyclaw, troublemaker, workbuddy, zeptoclaw

### Phase 2: Non-CLAW Critical (2 apps, 1 commit)

**Batch 2**: cline, openfang

### Phase 3: High-Severity Apps (111 apps, ~12 commits)

**Batch 3A - GENAI_CODING (47)**: agentless, aider, amazon_q_cli, amazon_q_developer, antigravity, augment, autocoderover, bolt, claude_code, claude_engineer, codex_app, codex_cli, continue, crush, cursor, devin, devon, forgecode, gemini_cli, github_copilot, goose, gptme, jetbrains_ai_assistant, kilo_code, kimi_cli, kiro, kode_cli, letta_code, lovable, mistral_vibe, neovate_code, opencode, plandex, qoder, qwen_code, ra_aid, replit, roo_code, smol_developer, sourcegraph_cody, superset_ide, swe_agent, sweep, trae, trae_agent, warp, windsurf

**Batch 3B - AI_AGENT_FRAMEWORK (44)**: activepieces, agent_zero, agenticseek, agno, aionui, astrbot, autogen, autogpt, camel, composio, copilotkit, coze_studio, cua, db_gpt, eliza, google_adk, gpt_researcher, graphiti, haystack, khoj, langchain, langgraph, letta, localai, mastra, mem0, n8n, open_autoglm, openai_agents_sdk, openhands, openmanus, osaurus, parlant, pentagi, perplexity_agent, pydantic_ai, ruflo, screenpipe, suna, superagi, taskade_desktop, ui_tars_desktop, upsonic, yao

**Batch 3C - REMOTE_ACCESS (3)**: anydesk, splashtop, teamviewer
**Batch 3D - CLOUD_STORAGE (4)**: dropbox, google_drive, mediafire, onedrive
**Batch 3E - P2P_FILE_SHARING (6)**: bittorrent, qbittorrent, resilio_sync, syncthing, transmission, utorrent
**Batch 3F - AI_BROWSER_AGENT (5)**: agentgpt, browser_use, browser_use_desktop, skyvern, stagehand
**Batch 3G - AI_DESKTOP_ASSISTANT (2)**: open_interpreter, rewind

## Per-App Review Checklist
1. Independence check: web-search, visit official site/repo
2. Verify network IOCs: DNS resolve hostnames, crt.sh for subdomain count, suffix/exact decision
3. Verify host IOCs: check paths against repo/docs/Homebrew
4. Discover new IOCs: extension IDs, team_ids, LaunchAgents, API endpoints, package paths
5. Severity validation: confirm rating matches actual capabilities
6. Update YAML with findings
7. Record in scratch/manual_review_tasks.csv

## Tracking
- Progress CSV: scratch/manual_review_tasks.csv
- Backup template: scratch/manual_review_tasks.csv.bak
- One standalone commit per batch, each passing `make validate`
