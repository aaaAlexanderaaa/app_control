# Targeted Alert Workflows

This workflow generates the two requested alert cohorts directly from `apps/` without hand-editing `output/`.

## Cohorts

1. `claw_macos_installable`
   - CLAW-family apps with explicit macOS runtime or install evidence, including CLI-capable entries.
2. `high_risk_plus_excluding_claw_macos_installable`
   - every `high` or `critical` app except cohort 1.
   - inventory rows still include apps that currently lack reviewed network or host IOCs; the table records why.

## Command

```bash
scripts/generate/targeted-alerts --min-status reviewed --from-pattern '*ftd*' --output-dir output
```

Equivalent CLI:

```bash
python3 -m app_control.cli generate-targeted-alerts --min-status reviewed --from-pattern '*ftd*'
```

## Output Files

For each cohort the command writes three artifacts:

- optimized network ES|QL
- Jamf extension-attribute style host scan script
- 5-column markdown inventory (`名称 / 类别 / 网络 IOC / 主机 IOC / 官方站点`)

It also writes a top-level manifest summarizing counts and file paths.

With the requested reviewed/canary threshold and `FROM *ftd*`, the current run writes:

- `output/claw_macos_installable_network_rules_canary.esql`
- `output/claw_macos_installable_host_scan_canary.sh`
- `output/claw_macos_installable_inventory_canary.md`
- `output/high_risk_plus_excluding_claw_macos_installable_network_rules_canary.esql`
- `output/high_risk_plus_excluding_claw_macos_installable_host_scan_canary.sh`
- `output/high_risk_plus_excluding_claw_macos_installable_inventory_canary.md`
- `output/targeted_alert_cohorts_canary.md`

## ES|QL Design Notes

The optimized ES|QL renderer is intentionally two-stage:

1. keep only network fields used by the rule,
2. normalize domain/application fields once,
3. apply a coarse prefilter regex first,
4. run exact/suffix/keyword `CASE` matching only on the reduced candidate set,
5. aggregate by minute and source host for shorter analyst-facing output.

Example shape:

```esql
FROM *ftd*
| WHERE network.direction IS NULL OR network.direction != "internal"
| WHERE network.bytes IS NOT NULL
| KEEP @timestamp, dns.question.name, tls.client.server_name, url.domain, network.application, network.bytes, source.bytes, destination.bytes, source.ip, destination.ip
| EVAL observed_domain = TO_LOWER(COALESCE(url.domain, tls.client.server_name, dns.question.name, ""))
| EVAL apps_lower = TO_LOWER(TO_STRING(COALESCE(network.application, "")))
| WHERE observed_domain RLIKE ".*(token_a|token_b).*" OR apps_lower RLIKE ".*(token_a|token_b).*"
| EVAL monitored_app = CASE(...)
| WHERE monitored_app IS NOT NULL
```

Concrete excerpt from the generated CLAW cohort rule:

```esql
FROM *ftd*
| WHERE network.direction IS NULL OR network.direction != "internal"
| WHERE network.bytes IS NOT NULL
| KEEP @timestamp, dns.question.name, tls.client.server_name, url.domain, network.application, network.bytes, source.bytes, destination.bytes, source.ip, destination.ip
| EVAL observed_domain = TO_LOWER(COALESCE(url.domain, tls.client.server_name, dns.question.name, ""))
| EVAL apps_lower = TO_LOWER(TO_STRING(COALESCE(network.application, "")))
| WHERE observed_domain RLIKE ".*(angel|clawx|copaw|letta|moxxy|qclaw|qoder|hermes|molili|moltcn|moltis|youdao|autobot|autoglm|clawapp|clawhub|clawlet|crystal|elephas|guanjia|katclaw|langbot|nanobot|oneclaw|zhipuai|autoclaw|babyclaw|easyclaw|ironclaw|lettabot|mindclaw|nanoclaw|nullclaw|openclaw|picoclaw|saharaai|zeroclaw|atomicbot|autoclaws|codebuddy|companion|lobsterai|microclaw|qoderwork|workbuddy|zeptoclaw|agentscope|nousresearch|troublemaker|zeroclawlabs).*" OR apps_lower RLIKE ".*(angel|clawx|copaw|letta|moxxy|qclaw|qoder|hermes|molili|moltcn|moltis|youdao|autobot|autoglm|clawapp|clawhub|clawlet|crystal|elephas|guanjia|katclaw|langbot|nanobot|oneclaw|zhipuai|autoclaw|babyclaw|easyclaw|ironclaw|lettabot|mindclaw|nanoclaw|nullclaw|openclaw|picoclaw|saharaai|zeroclaw|atomicbot|autoclaws|codebuddy|companion|lobsterai|microclaw|qoderwork|workbuddy|zeptoclaw|agentscope|nousresearch|troublemaker|zeroclawlabs).*"
| EVAL monitored_app = CASE(...)
| WHERE monitored_app IS NOT NULL
```

## Jamf Design Notes

The generated Jamf script has two operational sections: **targeted detection** of cataloged apps and **inventory discovery** of uncataloged software.

### Targeted Detection

Per-app checks are ordered for performance:

1. direct filesystem path checks first (system paths, then per-user paths)
2. wildcard-aware path matching (`compgen -G`), so globbed IOC paths do not silently fail
3. bundle ID checks via `mdfind kMDItemCFBundleIdentifier`
4. process name checks via `pgrep`
5. Chrome extension ID checks (scans `~/Library/Application Support/Google/Chrome/*/Extensions/<ext_id>`)
6. repo/project directory search only as a fallback
7. one finding per app to keep `<result>` compact

Example per-app shape:

```bash
if ! app_found "openclaw"; then
    if check_app_paths "openclaw" "${OPENCLAW_CANDIDATES[@]}"; then
        :
    elif check_bundle_id "openclaw" "ai.openclaw.mac"; then
        :
    elif check_process_name "openclaw" "openclaw"; then
        :
    elif check_chrome_extension "automa" "infppggnoaenmfagbfknfkancpbljcca"; then
        :
    fi
fi
```

### Inventory Discovery

After targeted detection, the script discovers uncataloged applications using
macOS-native tools and filesystem scans. All discovery functions use only native
macOS binaries (`/usr/sbin/system_profiler`, `/usr/bin/python3`, `/usr/bin/defaults`,
`/usr/bin/codesign`, `mdfind`, `mdls`).

1. **`system_profiler SPApplicationsDataType -json`** enumerates all installed `.app`
   bundles. The JSON output provides `_name`, `path`, `version`, `obtained_from`,
   and `signed_by` (certificate chain). It does **not** return bundle IDs or team
   IDs directly — these are looked up from the app's `Info.plist` (via `defaults read`)
   and the `signed_by` array (team ID extracted by regex from
   `"Developer ID Application: Name (TEAMID)"`).
2. **`mdfind`** with `kMDItemContentTypeTree == 'com.apple.application-bundle'`
   discovers `.app` bundles on any Spotlight-indexed volume, catching apps in
   non-standard locations that `system_profiler` may miss.
3. **Package manager filesystem scans** enumerate CLI tools installed via Cargo
   (`~/.cargo/.crates2.json`), Go (`~/go/bin/`), npm (`/opt/homebrew/lib/node_modules/`),
   and pip/pipx (`~/.local/pipx/venvs/`, `~/.local/bin/`). These scan the filesystem
   directly without invoking the package manager binaries.
4. **Homebrew enumeration** (`brew list --formula`, `brew list --cask`) is included
   in `report` mode only. It is excluded from `jamf_ea` mode because `brew` is a
   non-native binary and Jamf EA best practices require only native macOS commands.

Discovered applications are cross-referenced against the catalog's known bundle IDs,
app names, and CLI tool names. Anything not matched is reported as `UNKNOWN_APP` or
`UNKNOWN_CLI` with full metadata (name, bundle ID, path, version, team ID, source).

### Output Modes

- **`report` mode**: prints `ALERT` (cataloged matches) and `INVENTORY` (uncataloged
  discoveries) as separate sections. Exits 1 if cataloged apps are found, 0 otherwise.
- **`jamf_ea` mode**: combines both into a single `<result>` tag for Jamf Pro ingestion.

### Concrete Excerpt

```bash
OPENCLAW_CANDIDATES=(
    "/Applications/OpenClaw.app"
    "/opt/homebrew/bin/openclaw"
    "/usr/local/bin/openclaw"
)
for h in "${USER_HOMES[@]}"; do
    OPENCLAW_CANDIDATES+=(
        "$h/.cargo/bin/openclaw"
        "$h/.local/bin/openclaw"
        "$h/.openclaw"
        "$h/Applications/OpenClaw.app"
        "$h/Library/Logs/OpenClaw/diagnostics.jsonl"
    )
done

if ! app_found "openclaw"; then
    if check_app_paths "openclaw" "${OPENCLAW_CANDIDATES[@]}"; then
        :
    elif check_bundle_id "openclaw" "ai.openclaw.mac"; then
        :
    elif check_process_name "openclaw" "openclaw"; then
        :
    fi
fi
```
