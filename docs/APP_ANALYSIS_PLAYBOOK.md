# App Analysis Playbook

This document standardizes the process for researching a new application and producing a catalog-quality YAML file. It is designed to be followed by both human analysts and AI agents.

For quality criteria that determine whether the output is acceptable vs. excellent, see `docs/QUALITY_STANDARDS.md`.

## Overview

App analysis produces two classes of IoC:

| Channel | What we find | How it detects |
|---------|-------------|----------------|
| **Network** | Branded domains, API endpoints, telemetry hosts | DNS/TLS/HTTP alert rules (ES\|QL) |
| **Host** | Filesystem paths, bundle IDs, process names, team IDs | MDM scan scripts (Jamf) |

The playbook below provides a decision tree for each channel, ordered by information yield per token spent. Scriptable steps reference tools in `tools/` that handle the mechanical work.

---

## Phase 1: Triage

Before researching, determine the app's installation surface:

| Installation method | Host IoC path | Network IoC path |
|--------------------|--------------|-----------------|
| Homebrew cask/formula | `research-homebrew` → Phase 2A | `research-homebrew` (appcast/url) → Phase 3A |
| GitHub release / `curl \| sh` | Phase 2B | Phase 3B |
| DMG / PKG (closed source) | Phase 2C | Phase 3A |
| Web-only (no local install) | Skip host | Phase 3A |
| Browser extension only | Chrome Web Store / Safari metadata | Phase 3A |

Use `app-control research-app --app <id>` to run the automated triage and research pipeline.

---

## Phase 2: Host IoC Research

### 2A — Homebrew Cask/Formula (highest yield, fully scriptable)

```bash
app-control research-homebrew --app <app_id>
```

**What the tool does:**

1. Fetches the cask/formula JSON from `formulae.brew.sh`.
2. For casks: extracts `app` (→ `/Applications/*.app`), `binary` (→ `/opt/homebrew/bin/*`, `/usr/local/bin/*`), `uninstall` (→ bundle IDs, launchctl labels), `zap` (→ user-level paths).
3. For formulas: fetches the Ruby source from GitHub, parses the `def install` block to extract explicit installation targets.
4. Outputs structured IoC candidates with provenance.

**What requires human judgment:**

- Whether `zap` paths are specific enough (e.g., `~/Library/Caches/com.todesktop.*` may match multiple todesktop-wrapped apps).
- Whether extracted bundle IDs belong to this app or a shared framework.

### 2B — Open Source / Install Scripts

For apps distributed via GitHub, `cargo install`, `go install`, `pip install`, or `curl | sh`:

1. **Fetch the install script** (if `curl | sh` pattern):
   - Download the script content.
   - Extract `mkdir`, `cp`, `install`, `ln -s` target paths.
   - Look for `~/.appname`, `~/.config/appname`, LaunchAgent plists.

2. **Search the repository** for host artifacts:
   - Search for `~/.appname`, `LaunchAgents`, `launchctl`, `XDG_CONFIG`, `XDG_DATA`.
   - Check `install.sh`, `Makefile`, `setup.py`, `post-install` hooks.
   - Check `Cargo.toml` `[[bin]]` targets, Go `main` package names, Python `console_scripts`.

3. **Record** each path with the source file URL as provenance.

### 2C — Closed-Source DMG/PKG

1. **Check existing reports first** — query Hybrid Analysis or OTX AlienVault by known hash (no submission needed; query existing reports only).
2. **For PKGs**: static unpack of the BOM file → `lsbom` to extract the complete file manifest.
3. **For DMGs**: mount and list the `.app` bundle contents for bundle IDs, embedded frameworks, and helper tools.

---

## Phase 3: Network IoC Research

### 3A — Domain Discovery (primary path)

Execute in order of decreasing reliability:

1. **Official firewall/security docs** — many enterprise apps publish allowlists (e.g., Cursor's `/security`, Kiro's `/docs/privacy-and-security/firewalls/`). This is the highest-quality source.

2. **Homebrew metadata** (scriptable):
   ```bash
   app-control research-homebrew --app <app_id>
   ```
   Extracts `appcast` URL (update-check endpoint) and `url` (download domain) from cask data.

3. **crt.sh subdomain enumeration** (scriptable):
   ```bash
   app-control research-crtsh --domain <domain>
   ```
   Queries the Certificate Transparency log for subdomains, then filters for `telemetry`, `api`, `update`, `license`, `auth` patterns while excluding shared CDN infrastructure.

4. **Source code search** (for open-source apps):
   - Search the repository for hardcoded URLs, `SUFeedURL` (Sparkle update framework), `telemetry`, `api.`, `https://`.
   - Check configuration files for default server endpoints.

5. **Install script analysis** — extract all URLs from `curl | sh` scripts or installer packages.

### 3B — Confidence Filtering

Before recording a network IoC, apply these filters:

| Filter | Rule | Action if matched |
|--------|------|-------------------|
| **Shared CDN** | Domain resolves to Cloudflare, AWS CloudFront, Akamai, Fastly, or Google Cloud CDN | Mark as `cdn_static` role or exclude |
| **Shared provider** | Domain is `api.openai.com`, `api.anthropic.com`, or other multi-tenant AI provider | Mark as `ai_service_provider` role; note shared usage |
| **Generic infrastructure** | `*.googleapis.com`, `*.amazonaws.com`, `*.azure.com` without app-specific prefix | Exclude unless the prefix is app-branded |
| **App-exclusive** | Domain contains the app's brand name and resolves to vendor-owned infrastructure | **Include** — this is a high-confidence IoC |

Only domains that survive all filters as "app-exclusive" qualify as excellent network IoCs per the quality standards.

---

## Phase 4: Assembly

### YAML Structure

```yaml
id: <snake_case_id>
name: <Human Readable Name>
category: <VALID_CATEGORY>
product_shape:
- macos          # and/or: web
product_type:
- <free_form_tag>
severity: <critical|high|medium|low>
priority_score: <0-100>
notes: >
  <Intentional omissions and context. Explain what was excluded and why.>
iocs:
  network:
    status: draft
    provenance:
      url: <primary_evidence_url>
      evidence: <one sentence explaining what the URL proves>
      checked_at: 'YYYY-MM-DD'
    hostname_patterns:
    - pattern: <domain>
      match: <exact|suffix>
      role: <app_brand|ai_service_provider|platform_service|cdn_static|file_*>
    keyword_patterns:
    - pattern: <keyword>
      match: <substring|regex>
  host:
    status: draft
    provenance:
      url: <primary_evidence_url>
      evidence: <one sentence explaining what the URL proves>
      checked_at: 'YYYY-MM-DD'
    paths:
    - /Applications/AppName.app
    - ~/.appname
    bundle_ids:
    - com.vendor.appname
    process_names:
    - appname
```

### Checklist Before Commit

- [ ] `make validate` passes.
- [ ] Network IoCs: at least one `app_brand` hostname with `exact` or `suffix` match.
- [ ] Host IoCs: at least one path or bundle ID from direct evidence (not heuristic inference).
- [ ] Provenance URL is reachable and supports the claims.
- [ ] `notes` field explains any intentional omissions (shared domains excluded, host paths not yet available, etc.).
- [ ] No duplicate hostnames with other apps in the same category (check with `make status`).
- [ ] Quality standards self-check: Uniqueness, Resilience, Independence, Signal-to-noise (see `docs/QUALITY_STANDARDS.md`).

---

## Tool Reference

| Command | Purpose | Phase |
|---------|---------|-------|
| `app-control research-homebrew --app <id>` | Extract host + network IoCs from Homebrew cask/formula | 2A, 3A |
| `app-control research-homebrew --token <cask>` | Research by Homebrew token directly | 2A, 3A |
| `app-control research-crtsh --domain <domain>` | Enumerate subdomains via Certificate Transparency | 3A |
| `app-control research-app --app <id>` | Run full automated research pipeline | All |
| `app-control enrich-homebrew --app <id>` | Apply Homebrew research to existing YAML | Post-research |
| `app-control enrich-network --app <id>` | Apply network research to existing YAML | Post-research |
| `app-control validate` | Schema validation | 4 |
| `app-control status` | Coverage and quality metrics | 4 |
