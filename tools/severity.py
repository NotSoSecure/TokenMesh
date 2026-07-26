"""
Severity scoring and CIS Azure Foundations Benchmark mapping.

Two capabilities:

1. `score_finding` returns an integer 0-100 severity + a confidence label,
   derived from the labelled risk + scope + principal type + attack shape.
   Defenders can sort a mixed pile of findings by severity number without
   having to interpret prose per-item.

2. `add_cis_mapping` annotates a finding with a CIS Azure Foundations
   Benchmark v2.1 control ID (or list, when a finding maps to multiple).
   Compliance teams use this to drive audit evidence and remediation
   ticket priority.

Both are pure functions with no live Azure calls — safe to run over any
finding shape.
"""

from typing import Any, Dict, List, Optional

from tools.attack_vectors import (
    SCOPE_MANAGEMENT_GROUP,
    SCOPE_RESOURCE,
    SCOPE_RESOURCE_GROUP,
    SCOPE_SUBSCRIPTION,
    _classify_scope,
)
from tools.principal_types import SERVICE_PRINCIPAL, UNKNOWN, USER


_BASE_RISK_SCORE = {
    "Critical": 90,
    "High": 70,
    "Medium": 50,
    "Low": 30,
    "Info": 10,
}

_SCOPE_BONUS = {
    SCOPE_MANAGEMENT_GROUP: 10,
    SCOPE_SUBSCRIPTION: 5,
    SCOPE_RESOURCE_GROUP: 0,
    SCOPE_RESOURCE: 0,
}


# ---------------------------------------------------------------------------
# CIS Azure Foundations Benchmark v2.1 mapping (subset relevant to detectors)
# ---------------------------------------------------------------------------
#
# The full CIS benchmark is 200+ controls; we map only the detectors we
# actually emit so this file stays maintainable. Missing controls are OK —
# add them as detectors expand.

CIS_MAPPING: Dict[str, List[str]] = {
    # Identity & access
    "service_principal_with_owner": ["CIS Azure 1.24"],
    "orphaned_role_assignment": ["CIS Azure 1.23"],
    "long_lived_application_secret": ["CIS Azure 1.19"],
    "long_lived_application_certificate": ["CIS Azure 1.19"],
    "federated_credential_wildcard_subject": ["CIS Azure 1.19"],
    "guest_user_with_azure_role": ["CIS Azure 1.4", "CIS Azure 1.5"],
    "cross_tenant_service_principal_with_azure_role": ["CIS Azure 1.15"],
    "dangerous_graph_app_role": ["CIS Azure 1.14"],
    "illicit_oauth_consent_grant": ["CIS Azure 1.14", "CIS Azure 1.16"],
    "third_party_admin_consent_grant": ["CIS Azure 1.14"],

    # Storage
    "storage_public_access": ["CIS Azure 3.1", "CIS Azure 3.7"],
    "storage_weak_tls": ["CIS Azure 3.15"],
    "public_boot_diagnostics_storage": ["CIS Azure 3.1"],

    # Key Vault
    "dangling_keyvault_access_policy": ["CIS Azure 8.1", "CIS Azure 8.2"],
    "overly_broad_keyvault_access_policy": ["CIS Azure 8.1"],
    "cross_tenant_keyvault_access_policy": ["CIS Azure 8.1"],
    "legacy_keyvault_contributor_escalation": ["CIS Azure 8.5"],
    "keyvault_object_no_expiry": ["CIS Azure 8.1", "CIS Azure 8.2"],
    "keyvault_object_long_lived": ["CIS Azure 8.2"],

    # Compute
    "managed_identity_escalation": ["CIS Azure 1.22", "CIS Azure 7.1"],
    "suspicious_vm_extension": ["CIS Azure 7.7"],

    # App Service
    "appservice_scm_basic_auth_enabled": ["CIS Azure 9.11"],
    "appservice_ftp_basic_auth_enabled": ["CIS Azure 9.10"],
    "appservice_managed_identity_escalation": ["CIS Azure 9.5", "CIS Azure 1.22"],
    "appservice_plaintext_secrets_in_appsettings": ["CIS Azure 9.13"],
}


# ---------------------------------------------------------------------------
# Severity scoring
# ---------------------------------------------------------------------------


def _principal_type_bonus(finding: Dict[str, Any]) -> int:
    ptype = finding.get("principal_type")
    evidence = finding.get("evidence") or {}
    bonus = 0
    if ptype == UNKNOWN:
        # Unresolvable principals are the classic backdoor shape; boost.
        bonus += 10
    if ptype == USER and evidence.get("user_type") == "Guest":
        bonus += 5
    if ptype == SERVICE_PRINCIPAL and evidence.get("app_owner_organization_id") and evidence.get("home_tenant_id"):
        if evidence["app_owner_organization_id"] != evidence["home_tenant_id"]:
            bonus += 8
    return bonus


def _attack_shape_bonus(finding: Dict[str, Any]) -> int:
    attack = str(finding.get("attack_name") or "").lower()
    detector = str(finding.get("detector") or "").lower()
    mitre = str(finding.get("mitre_technique_id") or "")
    bonus = 0
    if "takeover" in attack or "subscription takeover" in attack:
        bonus += 8
    if "managed identity" in attack or "managed_identity" in detector:
        bonus += 5
    if "persistence" in attack or "backdoor" in attack:
        bonus += 4
    if "T1098.003" in mitre or "T1078.004" in mitre:
        bonus += 3
    if "T1580" in mitre and "T1580" == mitre.strip():
        # Pure discovery — cap severity.
        bonus -= 5
    return bonus


def _confidence(finding: Dict[str, Any]) -> str:
    """
    High-confidence findings are those grounded in a specific role
    assignment or configuration read. Medium confidence is for pattern
    heuristics (generic names, suspicious keys). Low is reserved for
    circumstantial correlations.
    """
    detector = str(finding.get("detector") or "")
    high_confidence = {
        "orphaned_role_assignment",
        "service_principal_with_owner",
        "managed_identity_escalation",
        "appservice_managed_identity_escalation",
        "guest_user_with_azure_role",
        "cross_tenant_service_principal_with_azure_role",
        "legacy_keyvault_contributor_escalation",
        "dangling_keyvault_access_policy",
        "dangerous_graph_app_role",
        "third_party_admin_consent_grant",
        "federated_credential_wildcard_subject",
        "long_lived_application_secret",
        "long_lived_application_certificate",
        "appservice_scm_basic_auth_enabled",
        "appservice_ftp_basic_auth_enabled",
        "suspicious_vm_extension",
    }
    medium_confidence = {
        "illicit_oauth_consent_grant",
        "appservice_plaintext_secrets_in_appsettings",
        "public_boot_diagnostics_storage",
        "keyvault_object_no_expiry",
        "keyvault_object_long_lived",
    }
    if detector in high_confidence:
        return "high"
    if detector in medium_confidence:
        return "medium"
    return "low"


def score_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Return an annotated copy of `finding` with:
      - severity_score: int in [0, 100]
      - confidence:     'high' | 'medium' | 'low'
      - cis_controls:   list[str] of CIS control IDs (empty if unmapped)

    Does not mutate the input.
    """
    base = _BASE_RISK_SCORE.get(str(finding.get("risk", "")), 40)
    scope_tier = _classify_scope(finding.get("scope"))
    score = base + _SCOPE_BONUS.get(scope_tier, 0)
    score += _principal_type_bonus(finding)
    score += _attack_shape_bonus(finding)
    score = max(0, min(100, score))

    detector = str(finding.get("detector") or "")
    cis = CIS_MAPPING.get(detector, [])
    # Preserve any pre-set cis_control field if the detector emits one.
    if finding.get("cis_control") and finding["cis_control"] not in cis:
        cis = ([finding["cis_control"]] if isinstance(finding["cis_control"], str) else list(finding["cis_control"])) + cis

    annotated = dict(finding)
    annotated["severity_score"] = score
    annotated["confidence"] = _confidence(finding)
    annotated["cis_controls"] = cis
    annotated["scope_tier"] = scope_tier
    return annotated


def score_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Batch-annotate a list of findings and sort by severity_score descending."""
    scored = [score_finding(f) for f in findings]
    scored.sort(key=lambda f: (f["severity_score"], f["confidence"]), reverse=True)
    return scored


def top_findings(findings: List[Dict[str, Any]], n: int = 10) -> List[Dict[str, Any]]:
    """Return the top N findings by severity_score."""
    return score_findings(findings)[:n]
