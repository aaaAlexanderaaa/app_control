# Quality Standards

This document defines the quality bar for every artifact in the catalog: individual IoCs, app YAML files, categories, and the project as a whole. "Acceptable" means the artifact passes validation; "excellent" means it actively makes the catalog more reliable and actionable.

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

## Applying These Standards

When authoring or reviewing an app YAML:

1. Run `make validate` — this is the minimum bar.
2. Check each IoC against Uniqueness, Resilience, Independence, and Signal-to-noise.
3. Verify provenance depth: prefer multi-source corroboration over single-URL evidence.
4. Document intentional omissions in the `notes` field.
5. Confirm the app does not duplicate patterns owned by another app in the category.
6. Use `make status` to verify your change does not regress project-level quality metrics.
