# Project Standard

## Positioning

This repository is the internal source of truth for high-risk or unmanaged application governance. Its ultimate deliverable is **detection rules (ES|QL + Jamf scan scripts) that achieve high F1 score** — every alert must be defensible evidence that a risk app is truly present.

Every file should support one of four enterprise workflows:

1. cataloging risky apps in a durable schema,
2. reviewing and validating IOC evidence,
3. generating deterministic detection artifacts,
4. retaining legacy research without mixing it into current operations.

## Work Prioritization

Before adding new code, tools, or documentation, evaluate against the **leverage hierarchy** in `AGENTS.md`. The default priority order is:

1. **Expand IOC coverage via automated high-quality sources** (Homebrew, App Store, vendor docs).
2. **Improve host/network detection precision** (fix keyword collisions, improve discovery methods).
3. **Validate existing IOCs** against real evidence (not just URL checks).
4. **Maintain and fix generators** — they are the production output pipeline.
5. Everything else (dashboards, exporters, code cleanup) is secondary.

## Canonical Repository Areas

- `apps/` — current catalog records, one YAML per application.
- `schemas/` — frozen schema contracts for current catalog data.
- `app_control/` — shared library and unified CLI entrypoint for supported operations.
- `tools/` — catalog maintenance, validation, enrichment, and research implementations.
- `generators/` — detection artifact generators (targeted app detection and uncataloged app inventory discovery).
- `scripts/` — shell wrappers for supported operator entrypoints.
- `pyproject.toml` — packaging and console-entry metadata for internal installation.
- `docs/` — governance, workflow, quality standards, and analysis playbooks.
- `output/` — generated artifacts only; never hand-edit and never treat as source data.
- `archive/` — historical or superseded material kept for traceability only.
- `scratch/` — the only acceptable location for one-off experiments or temporary utilities.

## Working Rules

- Treat `apps/` as the only authoritative business dataset.
- Treat `tools/` and `generators/` as implementation internals, not ad-hoc dumping grounds.
- Put temporary scripts, one-time exports, and research snippets in `scratch/`; promote them into `tools/`, `generators/`, or `docs/` only after they become repeatable workflow assets.
- Keep generated files inside `output/` so repository review stays focused on source changes.
- Keep legacy research in `archive/`; do not revive archived files into production paths without explicit review.

## Change Control Expectations

- New or updated app coverage changes `apps/` first, then regenerates artifacts.
- Schema changes are rare and should be accompanied by validator or generator updates.
- Production outputs should be generated from `validated` IOC groups only.
- Canary outputs may include `reviewed` IOC groups, but never bypass provenance requirements.
- Manual metrics in documentation should be avoided when the same information can be computed from `make status`.

## Supported Operations

- `python3 -m app_control.cli <command>` — unified no-install CLI surface.
- `make validate` — validate all app records.
- `make status` — report catalog coverage and readiness.
- `make build-prod` — generate validated production network and host artifacts.
- `make build-canary` — generate reviewed-plus canary artifacts.
- `make build-by-category-prod` — generate validated per-category ES|QL and host artifacts.
- `make build-by-category-canary` — generate reviewed-plus per-category artifacts.
- `make research APP=<id>` — run full app research pipeline (Homebrew + crt.sh + quality assessment).
- `scripts/catalog/*`, `scripts/generate/*`, `scripts/research` — stable human-friendly wrappers.

## Documentation

- `docs/PROJECT_STANDARD.md` — this file; repository governance and layout rules.
- `docs/QUALITY_STANDARDS.md` — quality bar (IoC, app, category, project) and standardized analysis process.

## Definition of "Repository-Ready" for Internal Use

The repository is structurally ready for enterprise self-use when:

- the source-of-truth data is isolated from generated output,
- supported entrypoints are consistent and documented,
- temporary work is quarantined from operational paths,
- IOC promotion rules are explicit,
- archived material is clearly separated from active controls.
