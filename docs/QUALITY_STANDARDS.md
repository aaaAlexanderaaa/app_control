# Quality Standards

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

---

## Analysis Process

The `app-control research` command automates the mechanical parts of app analysis. This section documents the decision logic so that results can be reviewed and manual steps filled in where automation cannot reach.

### Research Sources by Installation Method

| Installation method | Host IoC source | Network IoC source |
|--------------------|----------------|-------------------|
| Homebrew cask/formula | `research --source homebrew` | `research --source homebrew` + `--source crtsh` |
| GitHub / `curl \| sh` | Manual: parse install script for paths | Manual: extract URLs from source |
| DMG / PKG (closed-source) | Manual: BOM extraction (`lsbom`) | `research --source crtsh` on vendor domain |
| Web-only | N/A | `research --source crtsh` on vendor domain |

### Host IoC Decision Tree

```
Homebrew cask/formula available?
├─ YES → app-control research --app <id> --source homebrew
│        Extracts: /Applications/*.app, /opt/homebrew/bin/*, bundle IDs,
│        uninstall paths, zap paths — all from explicit cask declarations.
├─ Open source (GitHub/cargo/go/pip)?
│  └─ Search repo for: ~/.appname, LaunchAgents, launchctl, XDG paths
│     Check: install.sh, Makefile, setup.py post-install hooks
│     Check: Cargo.toml [[bin]], Go main packages, console_scripts
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
