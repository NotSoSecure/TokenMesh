"""
Microsoft Graph app-role assignments and OAuth2 delegated consent grants.

Two attack surfaces that TokenMesh previously did not cover:

  1. Application (app-only) permissions granted to service principals via
     `appRoleAssignments`. When an SP holds high-privilege Graph roles like
     `Application.ReadWrite.All`, `AppRoleAssignment.ReadWrite.All`, or
     `RoleManagement.ReadWrite.Directory`, it can escalate any way it wants —
     add itself as Global Administrator, mint new SPs with more roles, or
     grant itself any other application permission. BloodHound-Azure calls
     this the AZMGGrantAppRoles / AZAppRoleAssignmentReadWrite edge and
     tracks it as one of the shortest paths to tenant takeover.

  2. OAuth2 delegated (user-consented) permissions via
     `oauth2PermissionGrants`. When a user consents to a third-party app for
     high-risk scopes (`Mail.Read`, `Files.Read.All`, `Sites.Read.All`,
     `User.Read.All`), the app reads that user's mailbox/OneDrive/SharePoint
     as long as the grant survives. Illicit Consent Grant is Microsoft's
     canonical name for the phishing-to-cloud pivot.

Both are read entirely through Microsoft Graph — no ARM calls.
"""

from typing import Any, Dict, Iterable, List, Optional

import requests

from azure_auth import get_graph_token
from tools.principal_types import SERVICE_PRINCIPAL, USER, normalize_odata_type


GRAPH = "https://graph.microsoft.com/v1.0"


# ---------------------------------------------------------------------------
# Reference tables — dangerous Graph permissions
# ---------------------------------------------------------------------------
#
# Sourced from:
#   - BloodHound-Azure edge taxonomy (SpecterOps)
#   - Microsoft Learn "Application permissions" ranking
#   - Andy Robbins' "Azure AD App Role Abuse" writeups
#   - Dirk-jan Mollema's ROADtools consent-attack research

# App-only (application) permissions that provide direct escalation to
# global-admin-equivalent. When any of these is granted to a non-Microsoft
# SP, the SP can perform tenant-wide compromise via Graph.
DANGEROUS_APP_ROLES: Dict[str, Dict[str, Any]] = {
    # Value: (technique_id, risk, why)
    "RoleManagement.ReadWrite.Directory": {
        "technique_id": "T1098.003",
        "risk": "Critical",
        "why": "Grant any Entra directory role — including Global Administrator — to any principal.",
        "bloodhound_edge": "AZMGGrantRole",
    },
    "AppRoleAssignment.ReadWrite.All": {
        "technique_id": "T1098.003",
        "risk": "Critical",
        "why": "Assign any Graph app role (including this one) to any principal — self-escalating.",
        "bloodhound_edge": "AZMGGrantAppRoles",
    },
    "Application.ReadWrite.All": {
        "technique_id": "T1098.001",
        "risk": "Critical",
        "why": "Add credentials to any application, mint new SPs, and take over their permissions.",
        "bloodhound_edge": "AZMGAppAddSecret / AZAppRoleAssignmentReadWrite",
    },
    "Application.ReadWrite.OwnedBy": {
        "technique_id": "T1098.001",
        "risk": "High",
        "why": "Add credentials to any app the SP owns; chained with owner escalation this is takeover.",
        "bloodhound_edge": "AZMGAppAddSecret (scoped)",
    },
    "Directory.ReadWrite.All": {
        "technique_id": "T1098.003",
        "risk": "Critical",
        "why": "Read/write every directory object — bulk mutation without discrete role attribution.",
        "bloodhound_edge": "AZMGGrantRole (indirect)",
    },
    "User.ReadWrite.All": {
        "technique_id": "T1098.003",
        "risk": "High",
        "why": "Modify user records — remove MFA, reset passwords (non-admins).",
        "bloodhound_edge": "AZMGGrantAppRoles (user vector)",
    },
    "GroupMember.ReadWrite.All": {
        "technique_id": "T1098.003",
        "risk": "High",
        "why": "Add self to any group — chain via PIM-eligible group -> privileged role.",
        "bloodhound_edge": "AZAddMembers",
    },
    "Group.ReadWrite.All": {
        "technique_id": "T1098.003",
        "risk": "High",
        "why": "Full group control — same escalation vector as GroupMember.ReadWrite.All.",
        "bloodhound_edge": "AZAddMembers",
    },
    "PrivilegedAccess.ReadWrite.AzureAD": {
        "technique_id": "T1098.003",
        "risk": "Critical",
        "why": "Modify PIM eligibility — grant self activation on Global Administrator role.",
        "bloodhound_edge": "AZMGGrantRole (PIM)",
    },
    "PrivilegedAccess.ReadWrite.AzureADGroup": {
        "technique_id": "T1098.003",
        "risk": "High",
        "why": "Modify PIM eligibility on groups — same escalation via PIM-eligible groups.",
        "bloodhound_edge": "AZMGGrantRole (PIM)",
    },
    "Domain.ReadWrite.All": {
        "technique_id": "T1556.007",
        "risk": "Critical",
        "why": "Add a federated domain (Golden SAML precondition) — full identity impersonation.",
        "bloodhound_edge": "N/A",
    },
    "Policy.ReadWrite.ConditionalAccess": {
        "technique_id": "T1556.009",
        "risk": "Critical",
        "why": "Disable or exempt Conditional Access policies — defeat MFA enforcement.",
        "bloodhound_edge": "N/A",
    },
    "Policy.ReadWrite.AuthenticationMethod": {
        "technique_id": "T1556",
        "risk": "High",
        "why": "Modify authentication method policies — enable temporary access passes, disable MFA methods.",
        "bloodhound_edge": "N/A",
    },
    "RoleManagementPolicy.ReadWrite.Directory": {
        "technique_id": "T1098.003",
        "risk": "High",
        "why": "Modify PIM assignment / activation policies (approval, MFA, duration).",
        "bloodhound_edge": "N/A",
    },
    "Mail.ReadWrite": {
        "technique_id": "T1114.002",
        "risk": "High",
        "why": "Read + modify any mailbox as the app — mail-flow tampering, cred harvest via draft manipulation.",
        "bloodhound_edge": "N/A",
    },
    "Mail.Read": {
        "technique_id": "T1114.002",
        "risk": "High",
        "why": "Read any mailbox as the app — bulk exfil, business email fraud reconnaissance.",
        "bloodhound_edge": "N/A",
    },
    "Files.ReadWrite.All": {
        "technique_id": "T1213",
        "risk": "High",
        "why": "Read + modify OneDrive / SharePoint files across tenant.",
        "bloodhound_edge": "N/A",
    },
    "Sites.FullControl.All": {
        "technique_id": "T1213.002",
        "risk": "Critical",
        "why": "Full control over every SharePoint site — bulk exfil + planted persistence.",
        "bloodhound_edge": "N/A",
    },
}


# Delegated (user-consented) scopes that carry high blast radius when
# consented — especially at admin-consent / all-users level. Called out
# because MITRE T1528 ("Steal Application Access Token") explicitly names
# these as the illicit consent grant surface.
HIGH_RISK_DELEGATED_SCOPES: Dict[str, Dict[str, Any]] = {
    "Mail.Read": {"technique_id": "T1114", "risk": "High", "why": "Read the consenting user's mailbox — phishing → data theft."},
    "Mail.ReadWrite": {"technique_id": "T1114", "risk": "High", "why": "Read + modify the consenting user's mailbox — inbox rules, hidden folders."},
    "Files.Read.All": {"technique_id": "T1213", "risk": "High", "why": "Read every file the consenting user can access."},
    "Files.ReadWrite.All": {"technique_id": "T1213", "risk": "High", "why": "Read/write every file the user can access."},
    "Sites.Read.All": {"technique_id": "T1213.002", "risk": "High", "why": "Read every SharePoint site the user has access to."},
    "User.Read.All": {"technique_id": "T1580", "risk": "Medium", "why": "Enumerate the entire directory as the consenting user — reconnaissance."},
    "Directory.Read.All": {"technique_id": "T1580", "risk": "High", "why": "Full directory recon — users, groups, apps, service principals."},
    "offline_access": {"technique_id": "T1550.001", "risk": "Info", "why": "Refresh-token persistence — token stays valid past user session."},
}


# Microsoft Graph service principal appId — assignments in appRoleAssignments
# reference this as the resourceId, which we cross-check.
MICROSOFT_GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"


# ---------------------------------------------------------------------------
# Graph helpers
# ---------------------------------------------------------------------------


def _headers() -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {get_graph_token()}",
        "Accept": "application/json",
    }


def _paged_get(url: str) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    next_url: Optional[str] = url
    while next_url:
        try:
            r = requests.get(next_url, headers=_headers(), timeout=60)
            r.raise_for_status()
        except requests.RequestException:
            break
        data = r.json()
        page = data.get("value") or []
        if isinstance(page, list):
            items.extend(page)
        next_url = data.get("@odata.nextLink")
    return items


def _get_graph_service_principal_object_id() -> Optional[str]:
    """
    Resolve the objectId of the Microsoft Graph SP in the current tenant.
    Every appRoleAssignment for Graph permissions has resourceId equal to
    this objectId — needed to correlate the ID -> permission name mapping.
    """
    try:
        r = requests.get(
            f"{GRAPH}/servicePrincipals?$filter=appId eq '{MICROSOFT_GRAPH_APP_ID}'&$select=id,appRoles",
            headers=_headers(),
            timeout=30,
        )
        r.raise_for_status()
        val = r.json().get("value") or []
        return val[0].get("id") if val else None
    except requests.RequestException:
        return None


def _get_graph_app_role_map() -> Dict[str, str]:
    """
    Build appRoleId -> permission name (e.g. 'RoleManagement.ReadWrite.Directory').
    """
    try:
        r = requests.get(
            f"{GRAPH}/servicePrincipals?$filter=appId eq '{MICROSOFT_GRAPH_APP_ID}'&$select=appRoles",
            headers=_headers(),
            timeout=30,
        )
        r.raise_for_status()
        val = r.json().get("value") or []
        if not val:
            return {}
        roles = val[0].get("appRoles") or []
        return {r["id"]: r["value"] for r in roles if r.get("id") and r.get("value")}
    except requests.RequestException:
        return {}


def _resolve_service_principal_summary(principal_id: str) -> Dict[str, Any]:
    """
    One-shot SP lookup used by the optimized dangerous-Graph-role hunt.
    Only fetches the fields the finding actually renders. Returns {} on
    any failure so a single missing SP never breaks the whole scan.
    """
    try:
        r = requests.get(
            f"{GRAPH}/servicePrincipals/{principal_id}"
            "?$select=id,appId,displayName,servicePrincipalType,appOwnerOrganizationId",
            headers=_headers(),
            timeout=30,
        )
        if r.status_code == 200:
            return r.json()
    except requests.RequestException:
        pass
    return {}


# ---------------------------------------------------------------------------
# Public tools
# ---------------------------------------------------------------------------


def list_dangerous_graph_app_role_assignments(
    subscription_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Enumerate every service principal that holds a dangerous Microsoft Graph
    application permission (app-only).

    Performance note: the OBVIOUS implementation is to list every SP in the
    tenant and, for each one, query its /appRoleAssignments. That's N+1 API
    calls — 501 requests for a 500-SP tenant, which reliably times out on
    real environments.

    The correct query is `/servicePrincipals/{graph-sp-id}/appRoleAssignedTo`,
    which returns every grant WHERE Microsoft Graph is the resource — in one
    paginated call. Then we only need to resolve the ~dozen grantee SPs
    that actually appear in the results, not the whole tenant.
    """
    graph_sp_object_id = _get_graph_service_principal_object_id()
    role_map = _get_graph_app_role_map()
    if not graph_sp_object_id or not role_map:
        return {
            "total_findings": 0,
            "findings": [],
            "warning": "Could not resolve Microsoft Graph service principal.",
        }

    # ONE paginated call gets every grantee, regardless of tenant size.
    grants = _paged_get(
        f"{GRAPH}/servicePrincipals/{graph_sp_object_id}/appRoleAssignedTo"
    )

    # Bucket grants by principalId so we only look up each grantee once,
    # even if it holds multiple dangerous roles.
    grants_by_principal: Dict[str, List[Dict[str, Any]]] = {}
    for g in grants:
        pid = g.get("principalId")
        if not pid:
            continue
        role_name = role_map.get(g.get("appRoleId"))
        if not role_name or role_name not in DANGEROUS_APP_ROLES:
            continue
        grants_by_principal.setdefault(pid, []).append({
            "role_name": role_name,
            "assignment_id": g.get("id"),
            "created": g.get("createdDateTime"),
        })

    if not grants_by_principal:
        return {"total_findings": 0, "findings": []}

    # Resolve grantee SPs only for the (small) set that actually got flagged.
    findings: List[Dict[str, Any]] = []
    for principal_id, matched in grants_by_principal.items():
        sp = _resolve_service_principal_summary(principal_id)
        for entry in matched:
            role_name = entry["role_name"]
            danger = DANGEROUS_APP_ROLES[role_name]
            findings.append({
                "detector": "dangerous_graph_app_role",
                "principal_id": principal_id,
                "principal_type": SERVICE_PRINCIPAL,
                "display_name": sp.get("displayName"),
                "scope": "https://graph.microsoft.com",
                "risk": danger["risk"],
                "mitre_technique_id": danger["technique_id"],
                "attack_name": f"Dangerous Graph App Role: {role_name}",
                "detection_signal": (
                    "AuditLogs | where OperationName == 'Add app role assignment to service principal' "
                    f"| where TargetResources has '{role_name}'"
                ),
                "remediation": (
                    f"Revoke the {role_name} app role assignment from this service principal. "
                    "Only Microsoft-published apps should hold this permission; "
                    "for owned SPs, require a documented business justification and periodic review."
                ),
                "cis_control": None,
                "bloodhound_edge": danger["bloodhound_edge"],
                "evidence": {
                    "app_id": sp.get("appId"),
                    "sp_type": sp.get("servicePrincipalType"),
                    "app_owner_organization_id": sp.get("appOwnerOrganizationId"),
                    "graph_permission_name": role_name,
                    "assignment_id": entry["assignment_id"],
                    "granted_at": entry["created"],
                    "why": danger["why"],
                },
            })

    return {"total_findings": len(findings), "findings": findings}


def list_illicit_oauth_consent_grants(
    subscription_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Enumerate every OAuth2 delegated permission grant (oauth2PermissionGrants)
    and flag high-risk scopes.

    Two shapes matter:
      - consentType='AllPrincipals'  — admin-consented for every user. Highest blast radius.
      - consentType='Principal'      — user-consented; principalId identifies the user. Common phishing pivot.

    Both are flagged; admin-consent gets higher risk.
    """
    grants = _paged_get(f"{GRAPH}/oauth2PermissionGrants")
    findings: List[Dict[str, Any]] = []

    for grant in grants:
        scopes = str(grant.get("scope") or "").split()
        matched_scopes = [s for s in scopes if s in HIGH_RISK_DELEGATED_SCOPES]
        if not matched_scopes:
            continue

        # Escalate risk when admin-consented (AllPrincipals) — everyone in
        # the tenant hands out the scope to this app.
        base_risk = max(
            (HIGH_RISK_DELEGATED_SCOPES[s]["risk"] for s in matched_scopes),
            key=lambda r: {"Info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}.get(r, 0),
        )
        consent_type = grant.get("consentType")
        if consent_type == "AllPrincipals" and base_risk in {"Medium", "High"}:
            base_risk = "Critical" if base_risk == "High" else "High"

        techniques = sorted({HIGH_RISK_DELEGATED_SCOPES[s]["technique_id"] for s in matched_scopes})

        findings.append({
            "detector": "illicit_oauth_consent_grant",
            "principal_id": grant.get("clientId"),
            "principal_type": SERVICE_PRINCIPAL,
            "display_name": None,
            "scope": grant.get("resourceId"),
            "risk": base_risk,
            "mitre_technique_id": "T1528",
            "additional_technique_ids": techniques,
            "attack_name": (
                "Illicit Consent Grant (Admin-consent)" if consent_type == "AllPrincipals"
                else "Illicit Consent Grant (User-consent)"
            ),
            "detection_signal": (
                "AuditLogs | where OperationName == 'Consent to application' "
                "| where TargetResources has 'Mail.Read' or has 'Files.Read.All' or has 'Sites.Read.All'"
            ),
            "remediation": (
                "Review the app's publisher, review count, and scope necessity. If not a documented "
                "trusted integration, revoke via Graph DELETE oauth2PermissionGrants/{id}. Consider "
                "moving to admin-consent workflow so end users cannot grant these scopes."
            ),
            "cis_control": "CIS Azure 1.14",
            "evidence": {
                "client_id_sp": grant.get("clientId"),
                "resource_id_sp": grant.get("resourceId"),
                "consent_type": consent_type,
                "principal_id_of_user": grant.get("principalId"),
                "matched_scopes": matched_scopes,
                "all_scopes": scopes,
                "reasons": [HIGH_RISK_DELEGATED_SCOPES[s]["why"] for s in matched_scopes],
            },
        })

    return {"total_findings": len(findings), "findings": findings}


def list_third_party_apps_with_admin_consent(
    subscription_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Any third-party (non-Microsoft-published) service principal that has
    received an admin-consented delegated permission grant. Illicit consent
    grant + admin-consent = whole-tenant mailbox/OneDrive exfil, which is
    Microsoft's own definition of the highest-severity OAuth abuse pattern.
    """
    grants = _paged_get(f"{GRAPH}/oauth2PermissionGrants?$filter=consentType eq 'AllPrincipals'")
    if not grants:
        return {"total_findings": 0, "findings": []}

    # Resolve every clientId (SP objectId) to check publisherName / verified publisher.
    findings: List[Dict[str, Any]] = []
    seen_clients: Dict[str, Dict[str, Any]] = {}

    for grant in grants:
        client_sp_id = grant.get("clientId")
        if not client_sp_id or client_sp_id in seen_clients:
            continue
        try:
            r = requests.get(
                f"{GRAPH}/servicePrincipals/{client_sp_id}"
                "?$select=id,appId,displayName,servicePrincipalType,appOwnerOrganizationId,publisherName,verifiedPublisher",
                headers=_headers(),
                timeout=30,
            )
            sp = r.json() if r.status_code == 200 else {}
        except requests.RequestException:
            sp = {}
        seen_clients[client_sp_id] = sp

    for grant in grants:
        client_sp_id = grant.get("clientId")
        sp = seen_clients.get(client_sp_id, {})
        publisher = sp.get("publisherName") or ""
        verified = sp.get("verifiedPublisher") or {}
        is_verified = bool(verified.get("displayName"))
        if publisher.lower().startswith("microsoft"):
            continue

        findings.append({
            "detector": "third_party_admin_consent_grant",
            "principal_id": client_sp_id,
            "principal_type": SERVICE_PRINCIPAL,
            "display_name": sp.get("displayName"),
            "scope": grant.get("resourceId"),
            "risk": "High" if is_verified else "Critical",
            "mitre_technique_id": "T1528",
            "attack_name": "Third-Party App Holds Admin-Consented Delegated Permission",
            "detection_signal": (
                "AuditLogs | where OperationName == 'Consent to application' "
                "| where InitiatedBy.user has @'admin' or InitiatedBy.app has 'consent'"
            ),
            "remediation": (
                "Review the app in the Enterprise Applications blade. Confirm it is documented and "
                "still required. If not, revoke the admin-consented grant."
            ),
            "cis_control": "CIS Azure 1.14",
            "evidence": {
                "publisher_name": publisher,
                "verified_publisher_display_name": verified.get("displayName"),
                "app_id": sp.get("appId"),
                "app_owner_organization_id": sp.get("appOwnerOrganizationId"),
                "consented_scopes": grant.get("scope"),
            },
        })

    return {"total_findings": len(findings), "findings": findings}
