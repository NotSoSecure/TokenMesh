from typing import Any, Dict, List, Optional

import requests

from tools.attack_vectors import map_role_to_attacks
from tools.entra_roles import get_entra_roles
from tools.principal_types import (
    SERVICE_PRINCIPAL,
    UNKNOWN,
    is_valid,
    matches,
    normalize,
    normalize_graph_endpoint,
    validate_filter,
)
from tools.rbac import summarize_high_privilege_assignments
from azure_auth import get_graph_token


GRAPH_URL = "https://graph.microsoft.com/v1.0"


def _headers():
    return {
        "Authorization": f"Bearer {get_graph_token()}",
        "Content-Type": "application/json",
    }


# Ordered so the ARM-declared type is tried first when it's provided.
_GRAPH_ENDPOINTS = [
    ("users", "User"),
    ("servicePrincipals", "ServicePrincipal"),
    ("groups", "Group"),
]


def _lookup_order(authoritative_type: Optional[str]) -> List[str]:
    """Prefer the ARM-authoritative type first, then fall back through the rest."""
    canonical = normalize(authoritative_type) if authoritative_type else None
    ordered = [ep for ep, t in _GRAPH_ENDPOINTS if t == canonical]
    ordered += [ep for ep, t in _GRAPH_ENDPOINTS if t != canonical]
    return ordered


def resolve_principal(
    principal_id: str,
    authoritative_type: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Resolve a principal ID via Microsoft Graph.

    The `authoritative_type` argument comes from the ARM role assignment's
    `properties.principalType` field, which is Microsoft's canonical source
    of truth for what kind of object owns the assignment. When present, it
    takes precedence over Graph endpoint URL inference — Graph is only used
    to enrich name/UPN. When Graph resolution fails entirely the returned
    type is the ARM value (if any) or 'Unknown'.
    """
    canonical_type = normalize(authoritative_type) if authoritative_type else None

    for endpoint in _lookup_order(authoritative_type):
        url = f"{GRAPH_URL}/{endpoint}/{principal_id}"
        try:
            response = requests.get(url, headers=_headers(), timeout=20)
        except requests.RequestException:
            continue

        if response.status_code == 200:
            data = response.json()
            resolved_type = canonical_type or normalize_graph_endpoint(endpoint)
            return {
                "id": principal_id,
                "name": data.get("displayName"),
                "userPrincipalName": data.get("userPrincipalName"),
                "principal_type": resolved_type,
            }

    # Graph didn't find it anywhere. Fall back to the ARM value if we had one.
    return {
        "id": principal_id,
        "name": "Unknown",
        "userPrincipalName": None,
        "principal_type": canonical_type or UNKNOWN,
    }


def generate_attack_paths(
    role: Optional[str],
    principal_type: Optional[str],
    scope: Optional[str] = None,
) -> List[str]:
    """
    Return a list of attack-path summary strings for a role. Backed by the
    data-driven attack-vector engine in `tools.attack_vectors`.

    Returned as strings so the PDF renderer and any legacy caller still work.
    For the full structured attack vectors (with MITRE IDs, KQL, remediation),
    call `map_role_to_attacks` or read `attack_vectors` on the enriched finding.
    """
    vectors = map_role_to_attacks(role, scope)
    paths = [f"[{v['technique_id']}] {v['attack_name']}: {v['primitive']}" for v in vectors]

    if normalize(principal_type) == SERVICE_PRINCIPAL:
        paths.append(
            "[T1098.001] Application Credential Persistence: "
            "Add a long-lived clientSecret or federated identity credential to the app registration."
        )

    return paths


def get_high_privileged_identities(
    subscription_id: str,
    principal_type: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Return every principal holding a high-privilege Azure RBAC role, enriched
    with Entra directory roles, risk level, evidence, and attack paths.

    Args:
        subscription_id: Azure subscription ID.
        principal_type: Optional filter using Microsoft's canonical ARM
            vocabulary — 'User', 'ServicePrincipal', or 'Group'. Omit for all
            types. Never pass lowercase-plural forms like 'servicePrincipals'.
    """
    filter_type = validate_filter(principal_type)

    data = summarize_high_privilege_assignments(subscription_id)
    entra_roles = get_entra_roles()["entra_roles"]

    enriched: List[Dict[str, Any]] = []

    for item in data["findings"]:
        # ARM's principalType is authoritative; Graph is only used to enrich.
        arm_type = item.get("principal_type")
        principal = resolve_principal(item["principal_id"], authoritative_type=arm_type)
        resolved_type = principal["principal_type"]

        # Apply the defender-supplied filter after resolution so that
        # findings which resolve to a different type than ARM claimed are
        # still filtered correctly (defense-in-depth against ARM/Graph drift).
        if not matches(resolved_type, filter_type):
            continue

        matched_entra_roles = [
            r["role"]
            for r in entra_roles
            if r["principal_id"] == item["principal_id"]
        ]

        role = item.get("role_name")

        scope = item.get("scope")
        structured_vectors = map_role_to_attacks(role, scope)
        if resolved_type == SERVICE_PRINCIPAL:
            structured_vectors = structured_vectors + [{
                "technique_id": "T1098.001",
                "attack_name": "Application Credential Persistence",
                "primitive": (
                    "Add a long-lived clientSecret or federated identity credential "
                    "to the app registration."
                ),
                "detection_signal": (
                    "AuditLogs | where OperationName == "
                    "'Update application - Certificates and secrets management' "
                    f"| where TargetResources has '{item['principal_id']}'"
                ),
                "remediation": (
                    "Rotate all credentials on high-priv service principals every 90 days. "
                    "Prefer federated identity credentials with strict subject scoping."
                ),
                "min_scope": "resource",
                "scope_tier": "resource",
                "tags": ["persistence", "entra", "service-principal"],
            }]

        enriched.append({
            "principal_id": item["principal_id"],
            "name": principal.get("name"),
            "upn": principal.get("userPrincipalName"),
            "principal_type": resolved_type,
            "azure_role": role,
            "entra_roles": matched_entra_roles,
            "scope": scope,
            "risk_level": "Critical" if role == "Owner" else "High",
            "evidence": {
                "role": role,
                "scope": scope,
                "principal_type": resolved_type,
                "arm_reported_principal_type": normalize(arm_type),
            },
            "attack_paths": generate_attack_paths(role, resolved_type, scope),
            "attack_vectors": structured_vectors,
        })

    return {
        "count": len(enriched),
        "principal_type_filter": filter_type,
        "identities": enriched,
    }


# ---------------------------------------------------------------------------
# Intent-mapped convenience helpers
# ---------------------------------------------------------------------------
#
# These wrap `get_high_privileged_identities` in specific defender intents so
# the LLM (and any human caller) can express the question directly, without
# having to remember filter arguments. They exist because the original bug
# was exactly this: a defender asked "service principals with Owner" and the
# tool returned users, because the LLM had no way to express "SP only" and
# the tool had no filter.


def list_high_privileged_service_principals(subscription_id: str) -> Dict[str, Any]:
    """
    Every service principal with Owner / Contributor / User Access Administrator
    at any scope in the subscription, enriched with SP-specific attributes:
    app_id, service_principal_type, credential summary, appOwnerOrganizationId.
    """
    base = get_high_privileged_identities(subscription_id, principal_type=SERVICE_PRINCIPAL)

    # Enrich each entry with SP-specific fields.
    enriched = []
    for identity in base["identities"]:
        sp_id = identity["principal_id"]
        try:
            r = requests.get(
                f"{GRAPH_URL}/servicePrincipals/{sp_id}"
                "?$select=appId,servicePrincipalType,appOwnerOrganizationId,accountEnabled,passwordCredentials,keyCredentials",
                headers=_headers(),
                timeout=20,
            )
            sp_data = r.json() if r.status_code == 200 else {}
        except requests.RequestException:
            sp_data = {}

        enriched.append({
            **identity,
            "app_id": sp_data.get("appId"),
            "service_principal_type": sp_data.get("servicePrincipalType"),
            "app_owner_organization_id": sp_data.get("appOwnerOrganizationId"),
            "account_enabled": sp_data.get("accountEnabled"),
            "password_credential_count": len(sp_data.get("passwordCredentials") or []),
            "key_credential_count": len(sp_data.get("keyCredentials") or []),
        })

    return {
        "count": len(enriched),
        "principal_type_filter": SERVICE_PRINCIPAL,
        "service_principals": enriched,
    }


def list_guest_users_with_azure_roles(subscription_id: str) -> Dict[str, Any]:
    """
    Entra guest users (`userType = Guest`) holding Owner / Contributor /
    User Access Administrator at any scope in the subscription. Documented
    partner-tenant lateral movement path.
    """
    base = get_high_privileged_identities(subscription_id, principal_type="User")

    # Fetch guest users only.
    try:
        r = requests.get(
            f"{GRAPH_URL}/users?$filter=userType eq 'Guest'"
            "&$select=id,displayName,userPrincipalName,mail,accountEnabled",
            headers=_headers(),
            timeout=30,
        )
        guests = {u["id"]: u for u in (r.json().get("value") if r.status_code == 200 else [])}
    except requests.RequestException:
        guests = {}

    findings: List[Dict[str, Any]] = []
    for identity in base["identities"]:
        guest = guests.get(identity["principal_id"])
        if not guest:
            continue
        findings.append({
            **identity,
            "mail": guest.get("mail"),
            "account_enabled": guest.get("accountEnabled"),
            "user_type": "Guest",
        })

    return {
        "count": len(findings),
        "guest_users_with_high_privilege": findings,
    }


def list_orphaned_role_assignments(subscription_id: str) -> Dict[str, Any]:
    """
    Every high-privilege role assignment whose principal_id no longer resolves
    in Microsoft Graph — the deleted-object persistence pattern. Any Contributor
    or Owner-role assignment whose principal has vanished from the directory
    is a candidate backdoor: an attacker can re-create the object (or restore
    from Recycle Bin within the retention window) to reinstate access.
    """
    base = get_high_privileged_identities(subscription_id)
    orphans = [i for i in base["identities"] if i["principal_type"] == UNKNOWN or i.get("name") == "Unknown"]
    return {
        "count": len(orphans),
        "orphaned_role_assignments": orphans,
    }
