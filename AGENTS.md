# Repository Guidelines

Follow the `docs/QUALITY_STANDARDS.md` and `docs/PROJECT_STANDARD.md`

## Priority Principles — Read This First

This project exists to **detect risk apps on enterprise endpoints with high F1 score**. Every change must serve this goal. Before starting work, ask: "Does this directly improve alert precision, recall, or IOC coverage?"

### Leverage hierarchy (20% effort → 80% value)

1. **IOC discovery mechanisms** — Automate via high-quality sources (Homebrew cask, App Store API, vendor docs). A good source eliminates manual analysis for dozens of apps at once. Never hand-research what can be batch-fetched.
2. **Host discovery methods** — Better discovery methods (`mdfind`, `system_profiler`, `bundleId`) reduce dependence on per-app IOC precision. One good method > 100 precise paths.
3. **Keyword collision audit** — Every keyword pattern must be reviewed for false-positive collision. A bare common word (`signal`, `notion`, `claude`) in a keyword match will fire on unrelated traffic and destroy alert credibility. Use domain fragments (`signal.org`, `notion.so`) instead.
4. **IOC provenance chain** — Who backs this IOC? Homebrew cask artifacts = peer-reviewed. Vendor security docs = authoritative. GitHub README = reasonable. Guesswork = unacceptable. The provenance source matters more than the review status label.

### What NOT to prioritize

- Code aesthetics, line count, deduplication — AI can maintain messy code; it cannot fix bad IOCs
- HTML viewers, dashboards, export formatters — nice-to-have, zero F1 impact
- Quality scoring engines — meaningless until IOC data itself is trustworthy
- Process documentation beyond what's needed for the next agent to continue work
- Shell script wrappers, directory reorganization, CI polish

## Project Structure & Module Organization
`apps/` is the source of truth: one YAML file per application. Keep active catalog work there, using snake_case filenames such as `apps/chatgpt.yaml`. Shared Python code lives in `app_control/`, operator-facing implementations live in `tools/` and `generators/`, and stable shell wrappers live in `scripts/`. Schema contracts are frozen in `schemas/`; governance and quality rules are in `docs/`. Treat `output/` as generated-only, `scratch/` as temporary workspace, and `archive/` as historical reference. The Jamf scan generator (`generators/jamf_scan.py`) produces both targeted detection for cataloged apps and inventory discovery of uncataloged apps via `system_profiler`, `mdfind`, and package manager filesystem scans.

## Generation Architecture Constraint
All `.sh` and `.esql` artifact generation **must** go through the two generator entry points in `generators/`:
- `generators/jamf_scan.py` — host scan script generation (`generate_scan_script`)
- `generators/esql_rules.py` — ES|QL rule generation (`generate_esql`, `generate_optimized_esql`)

Orchestration tools in `tools/` (e.g. `generate_targeted_alerts.py`, `generate_claw_macos_installable_alerts.py`, `generate_category_alerts.py`) **must** import and call these generator functions — never duplicate or re-implement generation logic. If a generator cannot support a required feature, fix the generator; do not create new generation entry points in `scripts/` or elsewhere. The `scripts/generate/` wrappers are thin shell shims that delegate to the CLI, which in turn routes to `tools/` orchestrators backed by `generators/`.

## Build, Test, and Development Commands
Use the supported entrypoints instead of ad hoc scripts:

- `make validate` checks all app YAML files against the catalog rules.
- `make status` reports coverage and IOC readiness across the catalog.
- `make build-prod` generates validated production artifacts in `output/`.
- `make build-canary` generates reviewed-plus canary artifacts.
- `make build-by-category-prod CATEGORY=GENAI_CODING` builds category-scoped outputs.
- `make research APP=cursor` runs the research pipeline for one app.
- `python3 -m app_control.cli <command>` or `scripts/app-control <command>` exposes the same CLI directly.

## Coding Style & Naming Conventions
Target Python 3.9+ and follow the existing style: 4-space indentation, type hints where practical, small functions, and concise module docstrings. No formatter or linter is configured in `pyproject.toml`, so match the surrounding code and keep imports tidy. For catalog records, keep `id` values and filenames aligned in snake_case, use uppercase category enums such as `GENAI_CHAT`, and avoid speculative IOCs or invented install paths.

## Testing Guidelines
There is no dedicated tracked `tests/` suite in this repository. Validation is the baseline gate: run `make validate` on every change and `make status` when altering catalog coverage. If you touch generators or export tooling, also run the relevant build target and confirm the generated output is deterministic. For app research changes, verify provenance URLs and keep notes focused on why signals were included or excluded.

## Commit & Pull Request Guidelines
Current history uses short, imperative commit subjects such as `Add quality standards and consolidated research tool`. Keep commits focused by workflow or data set, not by incidental file count. PRs should describe the operational reason for the change, list the commands run, link any issue or research source, and call out schema or generator impacts. Do not check in hand-edited files from `output/`.
