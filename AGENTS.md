# Repository Guidelines

Follow the `docs/QUALITY_STANDARDS.md` and `docs/PROJECT_STANDARD.md`

## Project Structure & Module Organization
`apps/` is the source of truth: one YAML file per application. Keep active catalog work there, using snake_case filenames such as `apps/chatgpt.yaml`. Shared Python code lives in `app_control/`, operator-facing implementations live in `tools/` and `generators/`, and stable shell wrappers live in `scripts/`. Schema contracts are frozen in `schemas/`; governance and quality rules are in `docs/`. Treat `output/` as generated-only, `scratch/` as temporary workspace, and `archive/` as historical reference.

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
