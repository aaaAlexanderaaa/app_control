# Quality Standards

## STOP: Highest-Priority Bad Cases And Mandatory Re-Review Triggers

These bad cases already happened in this repository. Treat them as mandatory
stop-signs, not optional style guidance.

### Bad Case 1: Network IOC contains an obvious non-domain keyword

If a network IOC includes a keyword that is obviously not a domain-safe token
(for example it contains a space, like `kimi claw`), you must assume the
problem is bigger than that one IOC.

Required action:

- do **not** only delete the broken IOC and move on
- trigger a fresh, independent review of the entire YAML
- re-check whether the app should exist as an independent record at all
- re-check whether the app is sharing the parent app's domain, bundle ID, or
  other detection surface

Concrete repository example:

- `apps/kimi_claw.yaml` used the keyword `kimi claw`
- the same record also depended on the shared `www.kimi.com` host and the
  shared `com.moonshot.kimichat` bundle
- the right fix is not just "remove the bad keyword"; the right fix is to
  independently review whether `kimi_claw` should be merged into `kimi`

### Kimi-Claw Standard: When a record must be merged or removed

A record must be treated like `kimi_claw` and cannot remain a standalone active
app if the independent review finds all or nearly all of the following:

- it is only a feature, mode, activity page, beta rollout, or hosted surface
  inside a broader parent product or platform
- it has no independent host artifact such as an install path, bundle ID,
  process name, extension ID, or stable local state path
- its network evidence depends on a shared parent/product/platform host plus a
  keyword, instead of an independently governable app boundary
- from an enterprise application-management viewpoint, it is not a separately
  manageable installed app on the endpoint

Disposition rule:

- if a real parent app record exists in the catalog, merge the evidence into the
  parent app's notes/review context
- if no appropriate parent app record exists, remove the child record from the
  active catalog instead of keeping a misleading standalone app entry

### Bad Case 2: App priority/severity was decided without an independent review pass

App priority and severity must be reviewed by an **independent subagent** or an
explicitly separate review pass. Do not let the same drafting pass decide app
ownership, app independence, and enterprise severity in one shot.

That priority review must answer all of these questions explicitly:

- **a.** Is this app actually a standalone app, or is it only a feature / mode /
  product surface inside another app?
- **b.** Does it satisfy the quality standards in this document, especially
  ownership boundaries, alert independence, and actionable detections?
- **c.** Was it evaluated from the enterprise application-management viewpoint,
  instead of from product-marketing language?

The following examples are mandatory and must stay visible. Do not abstract
these away, do not remove the cases, and do not replace them with vague rules:

- `openclaw` / `zeroclaw`: `critical`
  - installed on the host
  - high-autonomy local operation
  - can directly and continuously operate the computer
  - from enterprise app management view this predictably leads to information leakage

- `opencode` / `claude code`: `high`
  - installed on the host
  - require the user to issue instructions
  - can automatically execute commands and read files after user intent is given
  - from enterprise app management view this very easily leads to information leakage

- `lovable` / `bolt` / `replit`: `medium`
  - treat these named repository examples as active-upload surfaces for enterprise priority review
  - the employee must still actively and intentionally upload or paste information
  - they should not be escalated to `high` or `critical` merely because they are AI coding products
  - do not overrule this named example merely because a product also offers desktop packaging or coding-related branding

Mandatory interpretation order for enterprise app management:

1. installed and locally operating on the host
2. installed and able to read files / run commands after user instruction
3. web-only usage that still requires the employee to actively upload data

If a record fails this review discipline, stop and re-review the YAML before it
is allowed to influence catalog severity, priority, or production-facing outputs.

This document defines the quality bar for every artifact in the catalog and the standardized process for producing them. "Acceptable" means the artifact passes validation; "excellent" means it actively makes the catalog more reliable and actionable.

## What Makes a Good IoC

**Acceptable** (passes validation): the pattern exists, has correct syntax, and matches the app.

**Excellent** (worth alerting on):

- **Uniqueness.** The pattern matches only this app across the entire internet — not just across this catalog. `api.cursor.sh` is excellent because no other product uses that domain. `chat.openai.com` is merely acceptable because it is shared surface.

- **Resilience.** The pattern survives app updates. First-party branded domains (`windsurf.com`) are resilient. Version-specific API paths (`/v3/beta/agent`) are fragile.

- **Independence.** Each IoC in an app provides an independent detection path. Two subdomains of the same parent domain are correlated signals, not independent ones. An excellent app entry has uncorrelated network + host indicators so one can confirm the other.

- **Signal-to-noise ratio.** If this pattern fired on 1,000 enterprise DNS logs, how many would be true positives? A pattern with >95% expected TP rate is excellent. A bare keyword like `poe` in HTTP traffic would drown in false hits.

- **Provenance depth.** Not just "URL checked" but multi-source corroboration — e.g., domain confirmed in app binary, DNS observed in sandbox traffic, AND listed in vendor docs. Each additional source increases confidence.

## What Makes a Good App YAML

**Acceptable**: has IoCs, passes schema validation.

**Excellent**:

- **Defense in depth.** At least two uncorrelated detection methods (e.g., a branded hostname AND a unique filesystem path). If the vendor changes their domain, the host IoC still catches it, and vice versa.

- **Intentional omissions documented.** Notes explain what was considered and rejected, not just what was included. "Excluded `api.openai.com` because it is shared with ChatGPT and 12 other tools" is more valuable than merely listing what is present.

- **Clear ownership boundaries.** Every pattern has a reason it belongs to this app and not a sibling. When two apps share infrastructure, the `shared_with` annotation makes the relationship explicit.

- **Provenance that tells a story.** The evidence field explains the verification method ("confirmed via mitmproxy interception of app launch traffic") not just the conclusion ("domain is used by app").

## What Makes a Good Category

**Acceptable**: apps are cataloged with some IoCs.

**Excellent**:

- **Alert independence.** No two apps in the category fire on the same network event. Duplicate hostnames are fully resolved via primary ownership.

- **Coverage without gaps.** Every known app in the threat landscape is represented — placeholders make gaps visible rather than hiding them.

- **Balanced detection surface.** Not purely network-only or host-only; the category has apps detectable through both channels.

- **Declining research debt.** Placeholder count decreases each review cycle. Stale entries are revalidated before new apps are added.

## What Makes a Good Project State

**Acceptable**: `make validate` passes.

**Excellent**:

- **Every alert is actionable.** An analyst receiving any alert from this catalog can immediately identify the app, assess the risk (severity is trustworthy), and decide on a response — without needing to research whether it is a false positive.

- **Zero redundant alerts.** No single network event triggers more than one app match. Cross-app deduplication is complete.

- **Measurable quality.** `make status` reports not just coverage counts but quality metrics — how many apps have independent multi-channel detection, how many placeholders remain, how many have fresh (non-stale) provenance.

- **Self-documenting.** A new agent or analyst can read the README, understand the quality bar, author a new app YAML, and know whether their work meets the standard — without asking anyone.

## Automated Quality Audit

Use `make quality` or `python3 -m app_control.cli quality` to run the catalog-wide
IOC quality audit. The audit is a structural review of the current YAML entries,
not a substitute for external research. It scores every app and both IOC groups
against the standards above and reports:

- overall app grades (`excellent`, `good`, `acceptable`, `needs_work`)
- per-group quality for network and host IOC coverage
- defense-in-depth coverage across network plus host
- placeholder, legacy-migration, inferred, keyword-only, and shared-infra-only
  weak spots that should be prioritized for review
- `missing_bundle_id`: apps with `.app` bundle paths but no `bundle_ids` field —
  these are retrievable via `system_profiler`, `defaults read`, or `mdls` and should
  be backfilled
- `cli_missing_pkg_path`: CLI-typed apps (`cli`, `cli_agent`, `terminal` in
  `product_type`) that lack any package manager install path (e.g.,
  `~/.local/bin/`, `/opt/homebrew/bin/`, `~/.cargo/bin/`, `~/go/bin/`)

`make status` includes the condensed quality summary so coverage, workflow state,
and IOC quality can be reviewed together.

---

## Analysis Process

The `app-control research` command automates the mechanical parts of app analysis. This section documents the decision logic so that results can be reviewed and manual steps filled in where automation cannot reach.

### Research Sources by Installation Method

| Installation method | Host IoC source | Network IoC source |
|--------------------|----------------|-------------------|
| Homebrew cask/formula | `research --source homebrew` | `research --source homebrew` + `--source crtsh` |
| GitHub / `curl \| sh` | Manual: parse install script for paths | Manual: extract URLs from source |
| DMG / PKG (closed-source) | Manual: BOM extraction (`lsbom`) | `research --source crtsh` on vendor domain |
| pip / pipx | Check `console_scripts` in `setup.py`/`pyproject.toml`; paths: `~/.local/bin/<tool>` | `research --source crtsh` on vendor domain |
| Cargo (Rust) | Check `[[bin]]` in `Cargo.toml`; paths: `~/.cargo/bin/<tool>` | `research --source crtsh` on vendor domain |
| npm (global) | Check `bin` in `package.json`; paths: `/opt/homebrew/lib/node_modules/<pkg>` | `research --source crtsh` on vendor domain |
| Go install | Check main packages; paths: `~/go/bin/<tool>` | `research --source crtsh` on vendor domain |
| Web-only | N/A | `research --source crtsh` on vendor domain |

### Host IoC Decision Tree

```
Homebrew cask/formula available?
├─ YES → app-control research --app <id> --source homebrew
│        Extracts: /Applications/*.app, /opt/homebrew/bin/*, bundle IDs,
│        uninstall paths, zap paths — all from explicit cask declarations.
├─ Open source (GitHub/cargo/go/pip/npm)?
│  └─ Search repo for: ~/.appname, LaunchAgents, launchctl, XDG paths
│     Check: install.sh, Makefile, setup.py post-install hooks
│     Check: Cargo.toml [[bin]], Go main packages, console_scripts
│     Check: package.json "bin" field for npm packages
│     Record install paths: ~/.local/bin/, ~/.cargo/bin/, ~/go/bin/
├─ Has a .app bundle but missing bundle_id?
│  └─ Retrieve via: defaults read /Applications/X.app/Contents/Info.plist CFBundleIdentifier
│     or: mdls -name kMDItemCFBundleIdentifier /Applications/X.app
│     The quality audit flags these as missing_bundle_id automatically.
├─ Has a .app bundle but missing team_id?
│  └─ Retrieve via: codesign -dvv /Applications/X.app 2>&1 | grep TeamIdentifier
│     or: parse signed_by array from system_profiler SPApplicationsDataType -json
└─ Closed-source DMG/PKG?
   ├─ Query Hybrid Analysis / OTX by hash (existing reports only)
   └─ For PKGs: static unpack BOM → lsbom for file manifest
```

### Network IoC Decision Tree

```
Official firewall/security docs exist?
├─ YES → highest-quality source; use directly
└─ NO
   ├─ Homebrew metadata → extracts homepage, download URL, appcast
   ├─ crt.sh CT logs → app-control research --domain <domain> --source crtsh
   │  Enumerates subdomains, classifies by relevance (api/telemetry/auth = high-value)
   ├─ Source code search → hardcoded URLs, SUFeedURL, telemetry endpoints
   └─ Confidence filter before recording:
      ├─ Shared CDN (Cloudflare/AWS/Akamai) → exclude or mark cdn_static
      ├─ Shared provider (api.openai.com) → mark ai_service_provider
      ├─ Generic infra (*.googleapis.com without app prefix) → exclude
      └─ App-exclusive (brand in domain, vendor-owned) → include ✓
```

### Checklist Before Commit

1. `make validate` passes.
2. Network IoCs: at least one `app_brand` hostname with `exact` or `suffix` match.
3. Host IoCs: at least one path or bundle ID from direct evidence (not heuristic).
4. Provenance URL is reachable and supports the claims.
5. `notes` field explains intentional omissions.
6. No duplicate hostnames with other apps in the same category.
7. Self-check against Uniqueness, Resilience, Independence, Signal-to-noise.
