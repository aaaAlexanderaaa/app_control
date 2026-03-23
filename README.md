# Enterprise App Control Risk Catalog

## Background and Purpose

Enterprise environments face growing data leakage risk from AI-powered applications that can autonomously access, upload, or exfiltrate sensitive data. This project catalogs such applications and their fingerprints (network domains, host artifacts) to enable automated detection via:

- **Network IOCs** -- ES|QL alert rules matching DNS/TLS/HTTP traffic to known app domains
- **Host IOCs** -- MDM-deployed scripts (Jamf) scanning for app installations, config files, and binaries

Priority is given to high-risk AI apps ranked by autonomy and exfiltration surface:

Priority score bands follow this order:

- `90-96` fully automated hosting / always-on autonomous agents
- `82-89` automated command execution
- `74-81` interaction-required execution
- `60-73` active file or prompt uploads leading to leakage
- `35-59` local-first or lower-priority point tools

1. **Fully automated hosting** -- 24/7 daemons with skills/plugins and messaging integration (e.g., OpenClaw)
2. **Automated command execution** -- terminal-level AI with autonomous command generation (e.g., Warp.app)
3. **Interaction-required command execution** -- user-triggered but uploads code context (e.g., Codex CLI)
4. **Active file/text uploads** -- prompt and text exfiltration via chat interfaces (e.g., Perplexity App)

## What This Repository Does

Applications are cataloged as individual YAML files in `apps/`, each containing:

- **Identity**: category (19 MECE categories), severity, priority score
- **Network IOCs**: hostname patterns (exact/suffix match, role) and keyword patterns
- **Host IOCs**: filesystem paths, bundle IDs, process names, team IDs, browser extension IDs
- **Per-group status**: each IOC group (network, host) has its own lifecycle status and provenance

This repository is intended to be operated as an **internal governance workspace** for high-risk or unmanaged applications. That means the repository should be predictable, auditable, and safe for repeatable internal use rather than accumulating temporary exports and one-off scripts in operational paths.

## Enterprise Operating Model

- `apps/` is the only business source of truth; generated files are never hand-maintained.
- `app_control/` provides the shared library and unified CLI surface.
- `make`, `scripts/`, and `python3 -m app_control.cli` are the supported operator entrypoints for daily use.
- `tools/` and `generators/` are implementation directories, not scratch space.
- `output/` contains generated artifacts only and is kept out of version review.
- `archive/` holds historical material only; active governance work does not happen there.
- `scratch/` is the only acceptable place for one-off research or temporary scripts before promotion or deletion.

## Normalized Repository Layout

```
app_control/                 # shared loaders, constants, unified CLI
apps/                        # one YAML per app
pyproject.toml               # package metadata and console entrypoint
schemas/app.schema.yaml      # frozen schema definition

generators/
  esql_rules.py              # network IOCs -> ES|QL detection rules
  jamf_scan.py               # host IOCs -> Jamf/MDM scan scripts

tools/
  validate.py                # validate all app files against schema
  migrate.py                 # one-time migration from old catalog JSON
  status.py                  # coverage and status breakdown report

scripts/
  app-control                # single wrapper for the unified CLI
  catalog/                   # supported catalog operations
  generate/                  # supported artifact generation entrypoints
  enrich/                    # supported enrichment entrypoints

docs/
  PROJECT_STANDARD.md        # repository governance and layout rules

output/                      # generated detection artifacts (gitignored)
archive/                     # legacy monolithic catalog and research data
scratch/                     # temporary experiments only; promote or delete
```

For repository rules and what belongs in each path, see `docs/PROJECT_STANDARD.md`.

## Supported Commands

Prefer these stable entrypoints instead of calling ad-hoc paths directly:

```bash
make validate
make status
make build-prod
make build-canary

# Unified CLI without installation
python3 -m app_control.cli status
scripts/app-control status

# Optional category-scoped generation
make build-canary CATEGORY=GENAI_CODING

# Equivalent wrapper entrypoints
scripts/catalog/validate
scripts/catalog/status
scripts/catalog/export-iocs --category CLAW_FAMILY_APP --output output/claw_family_ioc_list.md
scripts/catalog/export-metadata --format csv --output scratch/app_category_priority.csv
scripts/catalog/recompute-priority --write
scripts/generate/network-rules --min-status reviewed
scripts/generate/host-scan --min-status validated
scripts/generate/category-alerts --min-status reviewed --output-dir output
```

## IOC Status Lifecycle

Each IOC group (network, host) per app tracks its own status:

```
draft -> reviewed -> validated -> stale (loops back for recheck)
```

- **draft**: AI-researched or migrated from old catalog. Not usable for production rules.
- **reviewed**: Human checked provenance URL and it supports the claims.
- **validated**: Confirmed against source code, installer, or analytics.
- **stale**: Was validated but app has updated; needs recheck.

## Authoring Policy

- Do not add IOC values from generic installation heuristics.
- If a source only proves that a macOS app exists, do not infer `/Applications/...`, `~/Library/...`, bundle IDs, or process names from the product name alone.
- For Homebrew-backed host IOCs, copy only artifact paths or identifiers that the Homebrew API explicitly exposes.
- For repo-distributed CLI or SDK tools, prefer official README/docs/package docs that explicitly name the executable and config files.
- If those docs create files relative to a cloned repo or project root, record them with a wildcard prefix (for example `*/ToolName/config.toml`) instead of assuming a fixed home-directory install path.
- If no direct evidence exists yet, leave the IOC group absent instead of filling it with speculative draft values.

## Temporary Work Discipline

- Put one-off utilities, CSV exports, and exploratory notes in `scratch/` first.
- Promote repeatable logic into `tools/`, `generators/`, or `docs/` only after it becomes part of the operating model.
- Do not keep generated deliverables outside `output/`.
- Do not mix archived research with active production-facing content.

Rule generators accept `--min-status` to control which IOCs are included:

```bash
# Validate all app files
make validate

# Check catalog status
make status

# Production rules (only validated IOCs)
make build-prod

# Canary rules for testing (includes reviewed IOCs)
make build-canary
```

### Example Generated Output

**ES|QL (network detection):**
```
| EVAL domain_lower = TO_LOWER(COALESCE(dns.question.name, tls.client.server_name, url.domain, ""))

| EVAL ai_tool = CASE(
  // OpenClaw (openclaw)
  (domain_lower == "openclaw.ai" OR domain_lower LIKE "*.openclaw.ai")
    OR (domain_lower == "clawhub.ai" OR domain_lower LIKE "*.clawhub.ai")
    OR domain_lower LIKE "*openclaw*", "openclaw",
  ...
)

| WHERE ai_tool IS NOT NULL
```

**Jamf scan (host detection):**
```bash
OPENCLAW_CANDIDATES=(
    "/Applications/OpenClaw.app"
    "/opt/homebrew/bin/openclaw"
    "/usr/local/bin/openclaw"
)
for h in "${USER_HOMES[@]}"; do
    OPENCLAW_CANDIDATES+=(
        "$h/.openclaw"
        "$h/Applications/OpenClaw.app"
    )
done
```

## Operational Gap

The pipeline from schema to rule generation now exists, and the repository structure is normalized around supported entrypoints and clear operational boundaries. The blocking gap remains **IOC validation**: migrated or draft data still needs human review against source code or other high-quality evidence before it can safely feed canary or production controls.

Use `make status` to compute live readiness instead of maintaining static counts in the README.

## Legacy Files

Previous monolithic catalog, schemas, viewer, and research data are archived in `archive/` for reference.
