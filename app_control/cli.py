"""Unified CLI for supported App Control operations."""

from __future__ import annotations

import importlib
import sys
from typing import TextIO

COMMANDS: dict[str, tuple[str, str, str]] = {
    "validate": ("tools.validate", "main", "Validate catalog YAML files."),
    "status": ("tools.status", "main", "Report catalog coverage and readiness."),
    "migrate": ("tools.migrate", "main", "Migrate archived JSON catalog into YAML app records."),
    "generate-network": ("generators.esql_rules", "main", "Generate network ES|QL rules."),
    "generate-host": ("generators.jamf_scan", "main", "Generate host scan script."),
    "generate-category-alerts": (
        "tools.generate_category_alerts",
        "main",
        "Generate per-category ES|QL and host alert artifacts.",
    ),
    "enrich-homebrew": ("tools.enrich_from_homebrew", "main", "Enrich host IOCs from Homebrew metadata."),
    "enrich-network": ("tools.enrich_network_iocs", "main", "Apply researched network IOC updates."),
    "export-iocs": ("tools.export_ioc_list", "main", "Export IOC data in markdown or JSON."),
    "export-metadata": ("tools.export_app_metadata", "main", "Export app category and priority metadata."),
    "recompute-priority": ("tools.recompute_priority_scores", "main", "Recompute priority_score from governance risk bands."),
    "research-homebrew": ("tools.research_homebrew", "main", "Research IoCs from Homebrew cask/formula metadata."),
    "research-crtsh": ("tools.research_crtsh", "main", "Discover subdomains via crt.sh Certificate Transparency."),
    "research-app": ("tools.research_app", "main", "Run full app research pipeline."),
}


def print_help(stream: TextIO = sys.stdout) -> None:
    stream.write("Usage: app-control <command> [args]\n\n")
    stream.write("Supported commands:\n")
    for name, (_, _, description) in COMMANDS.items():
        stream.write(f"  {name:22s} {description}\n")


def run_command(command: str, argv: list[str]) -> int:
    module_name, attr_name, _ = COMMANDS[command]
    module = importlib.import_module(module_name)
    handler = getattr(module, attr_name)
    old_argv = sys.argv[:]
    try:
        sys.argv = [f"app-control {command}", *argv]
        try:
            result = handler()
        except SystemExit as exc:
            code = exc.code
            if code is None:
                return 0
            if isinstance(code, int):
                return code
            raise
    finally:
        sys.argv = old_argv

    if isinstance(result, int):
        return result
    return 0


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] in {"-h", "--help", "help", "list-commands"}:
        print_help()
        return 0

    command, *command_args = args
    if command not in COMMANDS:
        print(f"Unknown command: {command}\n", file=sys.stderr)
        print_help(sys.stderr)
        return 2

    return run_command(command, command_args)


if __name__ == "__main__":
    raise SystemExit(main())
