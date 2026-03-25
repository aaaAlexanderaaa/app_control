"""IOC quality assessment helpers for catalog records."""

from __future__ import annotations

from collections import Counter
from typing import Any

from app_control.catalog import get_ioc_group

OVERALL_GRADES = ("excellent", "good", "acceptable", "needs_work")
GROUP_GRADES = ("excellent", "good", "acceptable", "needs_work", "missing")
OVERALL_GRADE_POINTS = {
    "missing": 0,
    "needs_work": 1,
    "acceptable": 2,
    "good": 3,
    "excellent": 4,
}
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}
REVIEW_GRADE_RANK = {"needs_work": 0, "acceptable": 1, "good": 2, "excellent": 3, "missing": 4}
RATIONALE_TERMS = (
    "avoid",
    "drop",
    "exclude",
    "excluded",
    "keep only",
    "limit",
    "limited to",
    "omit",
    "remove",
)
SHARED_NETWORK_ROLES = {"ai_service_provider", "platform_service", "cdn_static"}
STRONG_HOST_FIELDS = (
    "bundle_ids",
    "team_ids",
    "chrome_extension_ids",
    "safari_extension_bundle_ids",
)


def _has_http_url(value: str) -> bool:
    return value.startswith("http://") or value.startswith("https://")


def _is_legacy_provenance(url: str) -> bool:
    return url.startswith("urn:internal:legacy-migration:")


def _is_inferred_evidence(evidence: str) -> bool:
    return evidence.lower().startswith("inference from")


def _contains_placeholder_text(value: str) -> bool:
    lowered = value.lower()
    return (
        "placeholder imported from archive/claw_ecosystem_full_report.csv" in lowered
        or "detailed ioc review pending" in lowered
    )


def has_omission_rationale(notes: str) -> bool:
    lowered = notes.lower()
    return any(term in lowered for term in RATIONALE_TERMS)


def _grade_from_score(score: int, excellent: int, good: int, acceptable: int) -> str:
    if score >= excellent:
        return "excellent"
    if score >= good:
        return "good"
    if score >= acceptable:
        return "acceptable"
    return "needs_work"


def _grade_index(grade: str, order: tuple[str, ...]) -> int:
    try:
        return order.index(grade)
    except ValueError:
        return len(order) - 1


def _cap_grade(grade: str, maximum: str, order: tuple[str, ...]) -> str:
    if _grade_index(grade, order) >= _grade_index(maximum, order):
        return grade
    return maximum


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        ordered.append(value)
    return ordered


def _path_family_flags(paths: list[str]) -> dict[str, bool]:
    app_bundle = False
    user_scope = False
    repo_local = False
    for path in paths:
        if not path:
            continue
        if "/Applications/" in path and ".app" in path:
            app_bundle = True
            continue
        if path.startswith("~/") or path.startswith("/Library/") or path.startswith("~/Library/"):
            user_scope = True
            continue
        if path.startswith("./") or path.startswith("*/") or not path.startswith(("/", "~")):
            repo_local = True
            continue
        if "/Library/" in path:
            user_scope = True
    return {
        "app_bundle_path": app_bundle,
        "user_scope_path": user_scope,
        "repo_local_path": repo_local,
    }


def assess_network_quality(app: dict[str, Any]) -> dict[str, Any]:
    network = get_ioc_group(app, "network")
    if not network:
        return {
            "grade": "missing",
            "score": 0,
            "max_score": 7,
            "strengths": [],
            "issues": ["network IOC group is missing"],
            "flags": {
                "missing": True,
                "placeholder": False,
                "legacy_provenance": False,
                "keyword_only": False,
                "shared_only": False,
                "single_suffix_brand": False,
                "exact_app_brand": False,
            },
        }

    notes = str(app.get("notes", ""))
    status = str(network.get("status", ""))
    provenance = network.get("provenance") or {}
    url = str(provenance.get("url", ""))
    evidence = str(provenance.get("evidence", ""))
    hosts = network.get("hostname_patterns") or []
    keywords = network.get("keyword_patterns") or []
    placeholder = _contains_placeholder_text(notes) or _contains_placeholder_text(evidence)
    legacy = _is_legacy_provenance(url)
    inferred = _is_inferred_evidence(evidence)

    branded_exact = [item for item in hosts if item.get("role") == "app_brand" and item.get("match") == "exact"]
    branded_suffix = [item for item in hosts if item.get("role") == "app_brand" and item.get("match") == "suffix"]
    exact_secondary = [item for item in hosts if item.get("match") == "exact" and item.get("role") != "app_brand"]
    keyword_only = not hosts and bool(keywords)
    shared_only = bool(hosts) and not (branded_exact or branded_suffix) and {
        item.get("role") for item in hosts
    } <= SHARED_NETWORK_ROLES
    single_suffix_brand = len(branded_suffix) == 1 and not branded_exact and not exact_secondary

    score = 0
    strengths: list[str] = []
    issues: list[str] = []

    if _has_http_url(url) and not legacy and not inferred:
        score += 2
        strengths.append("network provenance points to a direct source")
    elif url and not legacy:
        score += 1
        issues.append("network provenance is weaker than a direct product or source reference")
    else:
        issues.append("network provenance still relies on legacy migration metadata")

    if len(branded_exact) >= 2:
        score += 3
        strengths.append("network has multiple exact app-branded hosts")
    elif len(branded_exact) == 1:
        score += 2
        strengths.append("network has an exact app-branded host")
    elif branded_suffix:
        score += 1
        issues.append("network relies on suffix app-brand matching")
    elif keywords:
        issues.append("network relies on keyword matching without an app-branded host")
    else:
        issues.append("network lacks an app-branded hostname")

    if exact_secondary and (branded_exact or branded_suffix):
        score += 2
        strengths.append("network has corroborating exact secondary hosts")
    elif keywords and (branded_exact or branded_suffix):
        score += 1
        strengths.append("network has keyword corroboration")
    elif hosts:
        score += 1

    if status == "validated":
        strengths.append("network IOC status is validated")

    grade = _grade_from_score(score, excellent=6, good=4, acceptable=2)
    if placeholder or legacy:
        grade = _cap_grade(grade, "needs_work", GROUP_GRADES)
    elif keyword_only:
        grade = _cap_grade(grade, "needs_work", GROUP_GRADES)
    elif shared_only:
        grade = _cap_grade(grade, "acceptable", GROUP_GRADES)
    elif single_suffix_brand:
        grade = _cap_grade(grade, "acceptable", GROUP_GRADES)

    if placeholder:
        issues.append("network IOC is still a placeholder pending detailed review")
    if keyword_only:
        issues.append("network IOC is keyword-only")
    if shared_only:
        issues.append("network IOC only captures shared or infrastructure hosts")

    return {
        "grade": grade,
        "score": score,
        "max_score": 7,
        "strengths": _dedupe(strengths),
        "issues": _dedupe(issues),
        "flags": {
            "missing": False,
            "placeholder": placeholder,
            "legacy_provenance": legacy,
            "keyword_only": keyword_only,
            "shared_only": shared_only,
            "single_suffix_brand": single_suffix_brand,
            "exact_app_brand": bool(branded_exact),
        },
    }


def assess_host_quality(app: dict[str, Any]) -> dict[str, Any]:
    host = get_ioc_group(app, "host")
    if not host:
        return {
            "grade": "missing",
            "score": 0,
            "max_score": 7,
            "strengths": [],
            "issues": ["host IOC group is missing"],
            "flags": {
                "missing": True,
                "placeholder": False,
                "legacy_provenance": False,
                "inferred_provenance": False,
                "strong_artifact": False,
                "single_family": False,
                "repo_local_only": False,
            },
        }

    notes = str(app.get("notes", ""))
    status = str(host.get("status", ""))
    provenance = host.get("provenance") or {}
    url = str(provenance.get("url", ""))
    evidence = str(provenance.get("evidence", ""))
    placeholder = _contains_placeholder_text(notes) or _contains_placeholder_text(evidence)
    legacy = _is_legacy_provenance(url)
    inferred = _is_inferred_evidence(evidence)

    paths = host.get("paths") or []
    process_names = host.get("process_names") or []
    strong_identity = any(host.get(field) for field in STRONG_HOST_FIELDS)
    path_flags = _path_family_flags(paths)
    app_bundle_path = path_flags["app_bundle_path"]
    user_scope_path = path_flags["user_scope_path"]
    repo_local_path = path_flags["repo_local_path"]

    family_count = sum(
        1
        for present in (
            app_bundle_path,
            user_scope_path,
            repo_local_path,
            strong_identity,
            bool(process_names),
        )
        if present
    )
    strong_artifact = strong_identity or app_bundle_path or user_scope_path
    repo_local_only = repo_local_path and not strong_artifact
    single_family = family_count <= 1

    score = 0
    strengths: list[str] = []
    issues: list[str] = []

    if _has_http_url(url) and not legacy and not inferred:
        score += 2
        strengths.append("host provenance points to a direct source")
    elif url and not legacy:
        score += 1
        issues.append("host provenance is inferred rather than directly documented")
    else:
        issues.append("host provenance still relies on legacy migration metadata")

    if strong_identity:
        score += 3
        strengths.append("host IOC includes a strong identity artifact")
    elif app_bundle_path or user_scope_path:
        score += 2
        strengths.append("host IOC includes a concrete install or user-scope path")
    elif repo_local_path or process_names:
        score += 1
        issues.append("host IOC is limited to repo-local paths or process names")
    else:
        issues.append("host IOC lacks concrete artifacts")

    if family_count >= 3:
        score += 2
        strengths.append("host IOC spans multiple artifact families")
    elif family_count == 2:
        score += 1
        strengths.append("host IOC has two independent artifact families")
    else:
        issues.append("host IOC provides only one artifact family")

    if status == "validated":
        strengths.append("host IOC status is validated")

    grade = _grade_from_score(score, excellent=6, good=4, acceptable=2)
    if placeholder or legacy:
        grade = _cap_grade(grade, "needs_work", GROUP_GRADES)
    elif repo_local_only:
        grade = _cap_grade(grade, "acceptable", GROUP_GRADES)
    elif inferred and single_family:
        grade = _cap_grade(grade, "acceptable", GROUP_GRADES)
    elif not strong_artifact:
        grade = _cap_grade(grade, "acceptable", GROUP_GRADES)

    if placeholder:
        issues.append("host IOC is still a placeholder pending detailed review")
    if inferred:
        issues.append("host IOC depends on inferred installer or product naming")
    if not strong_artifact:
        issues.append("host IOC lacks a strong installation or identity artifact")

    return {
        "grade": grade,
        "score": score,
        "max_score": 7,
        "strengths": _dedupe(strengths),
        "issues": _dedupe(issues),
        "flags": {
            "missing": False,
            "placeholder": placeholder,
            "legacy_provenance": legacy,
            "inferred_provenance": inferred,
            "strong_artifact": strong_artifact,
            "single_family": single_family,
            "repo_local_only": repo_local_only,
        },
    }


def assess_app_quality(app: dict[str, Any]) -> dict[str, Any]:
    network = assess_network_quality(app)
    host = assess_host_quality(app)
    notes = str(app.get("notes", ""))
    omission_rationale = has_omission_rationale(notes)
    placeholder = network["flags"]["placeholder"] or host["flags"]["placeholder"]

    score = OVERALL_GRADE_POINTS[network["grade"]] + OVERALL_GRADE_POINTS[host["grade"]]
    strengths: list[str] = []
    issues: list[str] = []

    if network["grade"] in {"acceptable", "good", "excellent"} and host["grade"] in {"acceptable", "good", "excellent"}:
        score += 2
        strengths.append("app has both network and host coverage")
    elif network["grade"] in {"acceptable", "good", "excellent"} or host["grade"] in {"acceptable", "good", "excellent"}:
        score += 1
        issues.append("app relies on a single IOC channel")
    else:
        issues.append("app lacks reliable multi-channel IOC coverage")

    if omission_rationale:
        score += 1
        strengths.append("notes document intentional inclusions or exclusions")
    else:
        issues.append("notes do not document intentional omissions")

    grade = _grade_from_score(score, excellent=9, good=6, acceptable=3)
    if placeholder:
        grade = _cap_grade(grade, "needs_work", OVERALL_GRADES)

    issues.extend(network["issues"])
    issues.extend(host["issues"])
    if placeholder:
        issues.append("placeholder entry is still pending detailed IOC review")

    return {
        "app_id": str(app.get("id", "")),
        "name": str(app.get("name", "")),
        "category": str(app.get("category", "")),
        "severity": str(app.get("severity", "")),
        "priority_score": int(app.get("priority_score", 0) or 0),
        "overall": {
            "grade": grade,
            "score": score,
            "max_score": 11,
            "strengths": _dedupe(strengths),
            "issues": _dedupe(issues),
        },
        "network": network,
        "host": host,
        "flags": {
            "placeholder": placeholder,
            "omission_rationale": omission_rationale,
            "defense_in_depth": (
                network["grade"] in {"acceptable", "good", "excellent"}
                and host["grade"] in {"acceptable", "good", "excellent"}
            ),
        },
    }


def summarize_catalog_quality(apps: list[dict[str, Any]]) -> dict[str, Any]:
    assessments = [assess_app_quality(app) for app in apps]
    total = len(assessments)
    overall = Counter(item["overall"]["grade"] for item in assessments)
    network = Counter(item["network"]["grade"] for item in assessments)
    host = Counter(item["host"]["grade"] for item in assessments)
    metrics = Counter()

    for item in assessments:
        if item["flags"]["defense_in_depth"]:
            metrics["defense_in_depth"] += 1
        if item["flags"]["omission_rationale"]:
            metrics["omission_rationale"] += 1
        if item["flags"]["placeholder"]:
            metrics["placeholder"] += 1
        if item["network"]["flags"]["legacy_provenance"]:
            metrics["legacy_network_provenance"] += 1
        if item["host"]["flags"]["legacy_provenance"]:
            metrics["legacy_host_provenance"] += 1
        if item["host"]["flags"]["inferred_provenance"]:
            metrics["inferred_host_provenance"] += 1
        if item["network"]["flags"]["keyword_only"]:
            metrics["keyword_only_network"] += 1
        if item["network"]["flags"]["shared_only"]:
            metrics["shared_only_network"] += 1
        if item["network"]["flags"]["single_suffix_brand"]:
            metrics["single_suffix_brand_network"] += 1
        if item["network"]["flags"]["exact_app_brand"]:
            metrics["exact_app_brand_network"] += 1
        if item["host"]["flags"]["missing"]:
            metrics["missing_host_group"] += 1
        if item["host"]["flags"]["strong_artifact"]:
            metrics["strong_host_artifact"] += 1
        if item["host"]["flags"]["repo_local_only"]:
            metrics["repo_local_only_host"] += 1

    review_candidates = sorted(
        (
            item for item in assessments
            if item["overall"]["grade"] in {"needs_work", "acceptable"}
        ),
        key=lambda item: (
            REVIEW_GRADE_RANK.get(item["overall"]["grade"], 99),
            SEVERITY_RANK.get(item["severity"], 99),
            -item["priority_score"],
            item["app_id"],
        ),
    )

    return {
        "total_apps": total,
        "overall_grades": {grade: overall.get(grade, 0) for grade in OVERALL_GRADES},
        "network_grades": {grade: network.get(grade, 0) for grade in GROUP_GRADES},
        "host_grades": {grade: host.get(grade, 0) for grade in GROUP_GRADES},
        "metrics": dict(metrics),
        "apps": assessments,
        "review_candidates": review_candidates,
    }


def coverage_percent(count: int, total: int) -> int:
    if total <= 0:
        return 0
    return round(100 * count / total)


def format_review_candidate(item: dict[str, Any]) -> str:
    issues = item["overall"]["issues"][:3]
    issue_text = "; ".join(issues) if issues else "no issues recorded"
    return (
        f"{item['severity']:8s} {item['app_id']:28s} "
        f"{item['overall']['grade']:11s} "
        f"network={item['network']['grade']:<11s} host={item['host']['grade']:<11s} "
        f"priority={item['priority_score']:3d}  {issue_text}"
    )
