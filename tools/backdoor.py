"""
Backdoor and persistence detection — pluggable detectors.

Each `_detect_*` function is independent, returns a list of findings, and
can be run alone. `detect_backdoors` composes them; the caller can select
a subset by name via the `detectors` argument.

Every finding follows the same shape:
    {
      detector, principal_id, principal_type, display_name, scope,
      risk, mitre_technique_id, attack_name,
      detection_signal, remediation, evidence
    }

Reason for the uniform shape: the LLM, the PDF renderer, and downstream
Sentinel/Defender workflows all consume this data — one shape keeps them
simple.
"""

from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional

import requests

from azure_auth import get_graph_token
from tools.principal_types import (
    SERVICE_PRINCIPAL,
    UNKNOWN,
    USER,
    normalize,
    validate_filter,
)
from tools.severity import score_findings


GRAPH = "https://graph.microsoft.com/v1.0"
_HIGH_PRIV_ROLES = {"Owner", "Contributor", "User Access Administrator", "Role Based Access Control Administrator"}


def _graph_headers() -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {get_graph_token()}",
        "Accept": "application/json",
    }


def _graph_get_paged(url: str) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    next_url: Optional[str] = url
    while next_url:
        try:
            r = requests.get(next_url, headers=_graph_headers(), timeout=60)
            r.raise_for_status()
        except requests.RequestException:
            break
        data = r.json()
        page = data.get("value") or []
        if isinstance(page, list):
            items.extend(page)
        next_url = data.get("@odata.nextLink")
    return items


def _tenant_id() -> Optional[str]:
    try:
        r = requests.get(f"{GRAPH}/organization?$select=id", headers=_graph_headers(), timeout=30)
        r.raise_for_status()
        val = r.json().get("value") or []
        if val:
            return val[0].get("id")
    except requests.RequestException:
        return None
    return None


# ---------------------------------------------------------------------------
# Cache — populated once per detect_backdoors run to avoid re-fetching
# ---------------------------------------------------------------------------


class _RunCache:
    """
    Lazy per-run cache. Every detector calls `.identities()`, `.assignments()`,
    etc. and only the first call triggers the Azure API request.
    """

    def __init__(self, subscription_id: str, principal_type_filter: Optional[str]):
        self.subscription_id = subscription_id
        self.principal_type_filter = principal_type_filter
        self._identities: Optional[Dict[str, Any]] = None
        self._role_assignments: Optional[Dict[str, Any]] = None
        self._service_principals: Optional[List[Dict[str, Any]]] = None
        self._users: Optional[List[Dict[str, Any]]] = None
        self._tenant_id: Optional[str] = None
        self._tenant_lookup_done: bool = False

    def identities(self) -> Dict[str, Any]:
        if self._identities is None:
            from tools.intelligence import get_high_privileged_identities
            self._identities = get_high_privileged_identities(
                self.subscription_id,
                principal_type=self.principal_type_filter,
            )
        return self._identities

    def role_assignments(self) -> Dict[str, Any]:
        if self._role_assignments is None:
            from tools.rbac import list_role_assignments
            self._role_assignments = list_role_assignments(
                subscription_id=self.subscription_id,
                principal_type=self.principal_type_filter,
            )
        return self._role_assignments

    def service_principals(self) -> List[Dict[str, Any]]:
        if self._service_principals is None:
            self._service_principals = _graph_get_paged(
                f"{GRAPH}/servicePrincipals?"
                f"$select=id,appId,displayName,accountEnabled,servicePrincipalType,appOwnerOrganizationId"
            )
        return self._service_principals

    def users(self) -> List[Dict[str, Any]]:
        if self._users is None:
            self._users = _graph_get_paged(
                f"{GRAPH}/users?$select=id,displayName,userPrincipalName,userType,accountEnabled"
            )
        return self._users

    def tenant_id(self) -> Optional[str]:
        if not self._tenant_lookup_done:
            self._tenant_id = _tenant_id()
            self._tenant_lookup_done = True
        return self._tenant_id


# ---------------------------------------------------------------------------
# Detectors
# ---------------------------------------------------------------------------


def _detect_service_principal_with_owner(cache: _RunCache) -> List[Dict[str, Any]]:
    findings = []
    for identity in cache.identities()["identities"]:
        if identity["principal_type"] == SERVICE_PRINCIPAL and identity["azure_role"] == "Owner":
            findings.append({
                "detector": "service_principal_with_owner",
                "principal_id": identity["principal_id"],
                "principal_type": SERVICE_PRINCIPAL,
                "display_name": identity["name"],
                "scope": identity["scope"],
                "risk": "Critical",
                "mitre_technique_id": "T1078.004",
                "attack_name": "Service Principal Backdoor (Owner-holding SP)",
                "detection_signal": (
                    "AzureActivity | where OperationNameValue == "
                    "'MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE' "
                    f"| where Properties has '{identity['principal_id']}'"
                ),
                "remediation": (
                    "Review SP ownership, credentials (secrets, certificates, FICs), and consented app roles. "
                    "Reduce to least-privilege or migrate the workload to a managed identity."
                ),
                "evidence": {
                    "azure_role": identity["azure_role"],
                    "scope": identity["scope"],
                    "entra_roles": identity["entra_roles"],
                },
            })
    return findings


def _detect_orphaned_role_assignments(cache: _RunCache) -> List[Dict[str, Any]]:
    findings = []
    for identity in cache.identities()["identities"]:
        if identity["principal_type"] == UNKNOWN or identity.get("name") == "Unknown":
            findings.append({
                "detector": "orphaned_role_assignment",
                "principal_id": identity["principal_id"],
                "principal_type": identity["principal_type"],
                "display_name": identity.get("name"),
                "scope": identity["scope"],
                "risk": "High",
                "mitre_technique_id": "T1078.004",
                "attack_name": "Orphaned Role Assignment (Deleted-Principal Persistence)",
                "detection_signal": (
                    "AzureActivity | where OperationNameValue == "
                    "'MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE' "
                    f"| where Properties has '{identity['principal_id']}'"
                ),
                "remediation": (
                    "Principal ID does not resolve in Microsoft Graph. Remove the RBAC assignment. "
                    "If the app registration was deleted but the assignment remained, this is the "
                    "classic Azure backdoor pattern — the SP can be re-created from backup with the "
                    "same object ID to reinstate access."
                ),
                "evidence": {"azure_role": identity["azure_role"], "scope": identity["scope"]},
            })
    return findings


_LONG_LIVED_DAYS = 730


def _detect_long_lived_app_credentials(cache: _RunCache) -> List[Dict[str, Any]]:
    """
    Applications with client secrets or certificates that don't expire for
    more than 2 years. Common attacker persistence — pentester playbook
    (MicroBurst `Get-AzPasswords`) explicitly hunts for these.
    """
    findings: List[Dict[str, Any]] = []
    sp_ids_of_interest = {
        i["principal_id"] for i in cache.identities()["identities"]
        if i["principal_type"] == SERVICE_PRINCIPAL
    }
    if not sp_ids_of_interest:
        return findings

    # Cross to /applications via appId -- iterate SPs, look up owning app.
    sps = {sp["id"]: sp for sp in cache.service_principals()}
    now = datetime.now(timezone.utc)
    threshold = now + timedelta(days=_LONG_LIVED_DAYS)

    for sp_id in sp_ids_of_interest:
        sp = sps.get(sp_id)
        if not sp:
            continue
        app_id = sp.get("appId")
        if not app_id:
            continue
        apps = _graph_get_paged(f"{GRAPH}/applications?$filter=appId eq '{app_id}'&$select=id,displayName,passwordCredentials,keyCredentials")
        for app in apps:
            for cred in (app.get("passwordCredentials") or []):
                end = cred.get("endDateTime")
                if not end:
                    continue
                try:
                    end_dt = datetime.fromisoformat(end.replace("Z", "+00:00"))
                except ValueError:
                    continue
                if end_dt > threshold:
                    findings.append({
                        "detector": "long_lived_application_secret",
                        "principal_id": sp_id,
                        "principal_type": SERVICE_PRINCIPAL,
                        "display_name": sp.get("displayName"),
                        "scope": None,
                        "risk": "High",
                        "mitre_technique_id": "T1098.001",
                        "attack_name": "Long-Lived Application Secret",
                        "detection_signal": (
                            "AuditLogs | where OperationName == 'Update application - Certificates and secrets management' "
                            f"| where TargetResources has '{sp_id}'"
                        ),
                        "remediation": (
                            "Rotate to a credential with lifetime <= 90 days. Prefer federated identity credentials with "
                            "strict subject scoping over long-lived secrets."
                        ),
                        "evidence": {
                            "app_id": app_id,
                            "credential_id": cred.get("keyId"),
                            "end_date": end,
                            "start_date": cred.get("startDateTime"),
                            "hint": cred.get("hint"),
                        },
                    })
            for cred in (app.get("keyCredentials") or []):
                end = cred.get("endDateTime")
                if not end:
                    continue
                try:
                    end_dt = datetime.fromisoformat(end.replace("Z", "+00:00"))
                except ValueError:
                    continue
                if end_dt > threshold:
                    findings.append({
                        "detector": "long_lived_application_certificate",
                        "principal_id": sp_id,
                        "principal_type": SERVICE_PRINCIPAL,
                        "display_name": sp.get("displayName"),
                        "scope": None,
                        "risk": "Medium",
                        "mitre_technique_id": "T1098.001",
                        "attack_name": "Long-Lived Application Certificate",
                        "detection_signal": (
                            "AuditLogs | where OperationName == 'Update application - Certificates and secrets management' "
                            f"| where TargetResources has '{sp_id}'"
                        ),
                        "remediation": "Rotate certificate and set lifetime to <= 1 year.",
                        "evidence": {
                            "app_id": app_id,
                            "credential_id": cred.get("keyId"),
                            "end_date": end,
                        },
                    })
    return findings


def _detect_federated_credentials_with_wildcard_subject(cache: _RunCache) -> List[Dict[str, Any]]:
    """
    Federated identity credentials (workload identity federation) with an
    overly permissive `subject` claim. `subject: *`, missing subject scoping,
    or issuer/subject pairs that would accept tokens from arbitrary workloads
    are documented persistence primitives.
    """
    findings: List[Dict[str, Any]] = []
    sp_ids_of_interest = {
        i["principal_id"] for i in cache.identities()["identities"]
        if i["principal_type"] == SERVICE_PRINCIPAL
    }
    if not sp_ids_of_interest:
        return findings

    sps = {sp["id"]: sp for sp in cache.service_principals()}
    for sp_id in sp_ids_of_interest:
        sp = sps.get(sp_id)
        if not sp:
            continue
        app_id = sp.get("appId")
        if not app_id:
            continue
        apps = _graph_get_paged(f"{GRAPH}/applications?$filter=appId eq '{app_id}'&$select=id,displayName")
        for app in apps:
            fics = _graph_get_paged(f"{GRAPH}/applications/{app['id']}/federatedIdentityCredentials")
            for fic in fics:
                subject = str(fic.get("subject") or "")
                issuer = str(fic.get("issuer") or "")
                bad_subject = ("*" in subject) or subject == "" or subject.lower() == "sub"
                if bad_subject:
                    findings.append({
                        "detector": "federated_credential_wildcard_subject",
                        "principal_id": sp_id,
                        "principal_type": SERVICE_PRINCIPAL,
                        "display_name": sp.get("displayName"),
                        "scope": None,
                        "risk": "Critical",
                        "mitre_technique_id": "T1098.001",
                        "attack_name": "Federated Identity Credential with Wildcard Subject",
                        "detection_signal": (
                            "AuditLogs | where OperationName has 'federated identity credential' "
                            f"| where TargetResources has '{sp_id}'"
                        ),
                        "remediation": (
                            "Every FIC must scope subject to a specific workload identity "
                            "(e.g. `repo:my-org/my-repo:ref:refs/heads/main`). Delete any FIC with a "
                            "wildcard subject."
                        ),
                        "evidence": {
                            "fic_name": fic.get("name"),
                            "issuer": issuer,
                            "subject": subject,
                            "audiences": fic.get("audiences"),
                        },
                    })
    return findings


def _detect_guest_users_with_high_privilege(cache: _RunCache) -> List[Dict[str, Any]]:
    """
    Entra guests with high-privilege Azure RBAC roles. Partner-tenant breach
    = your subscription breach. MITRE T1078.004.
    """
    users_by_id = {u["id"]: u for u in cache.users() if u.get("userType", "").lower() == "guest"}
    findings: List[Dict[str, Any]] = []
    for identity in cache.identities()["identities"]:
        if identity["principal_type"] != USER:
            continue
        user = users_by_id.get(identity["principal_id"])
        if not user:
            continue
        findings.append({
            "detector": "guest_user_with_azure_role",
            "principal_id": identity["principal_id"],
            "principal_type": USER,
            "display_name": user.get("displayName") or identity.get("name"),
            "scope": identity["scope"],
            "risk": "Critical" if identity["azure_role"] == "Owner" else "High",
            "mitre_technique_id": "T1078.004",
            "attack_name": "Partner-Tenant Guest with Azure RBAC",
            "detection_signal": (
                "AzureActivity | where OperationNameValue == "
                "'MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE' "
                f"| where Properties has '{identity['principal_id']}'"
            ),
            "remediation": (
                "Guest users should not hold Contributor/Owner/UAA. Move to a native SP with PIM, "
                "or downgrade to Reader. Review cross-tenant access policy."
            ),
            "evidence": {
                "azure_role": identity["azure_role"],
                "scope": identity["scope"],
                "user_principal_name": user.get("userPrincipalName"),
                "user_type": user.get("userType"),
                "entra_roles": identity["entra_roles"],
            },
        })
    return findings


def _detect_cross_tenant_service_principals_with_high_privilege(cache: _RunCache) -> List[Dict[str, Any]]:
    """
    Service principals whose owning application lives in a different tenant.
    Third-party apps holding high-priv roles are documented persistence
    surfaces — an SP consented by a compromised app admin can retain access
    even after the vendor rotates their app secrets, and the vendor tenant
    itself is now a lateral-movement path.
    """
    tenant_id = cache.tenant_id()
    if not tenant_id:
        return []

    sps = {sp["id"]: sp for sp in cache.service_principals()}
    findings: List[Dict[str, Any]] = []
    for identity in cache.identities()["identities"]:
        if identity["principal_type"] != SERVICE_PRINCIPAL:
            continue
        sp = sps.get(identity["principal_id"])
        if not sp:
            continue
        owner_org = sp.get("appOwnerOrganizationId")
        if owner_org and owner_org != tenant_id:
            findings.append({
                "detector": "cross_tenant_service_principal_with_azure_role",
                "principal_id": identity["principal_id"],
                "principal_type": SERVICE_PRINCIPAL,
                "display_name": sp.get("displayName") or identity.get("name"),
                "scope": identity["scope"],
                "risk": "Critical" if identity["azure_role"] == "Owner" else "High",
                "mitre_technique_id": "T1199",
                "attack_name": "Cross-Tenant Service Principal with High-Privilege Azure Role",
                "detection_signal": (
                    "AzureActivity | where OperationNameValue == "
                    "'MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE' "
                    f"| where Properties has '{identity['principal_id']}'"
                ),
                "remediation": (
                    "Third-party service principals should not hold Contributor/Owner. "
                    "Review cross-tenant access policy and consent audit; scope down or replace with own SP."
                ),
                "evidence": {
                    "azure_role": identity["azure_role"],
                    "scope": identity["scope"],
                    "app_id": sp.get("appId"),
                    "sp_type": sp.get("servicePrincipalType"),
                    "app_owner_organization_id": owner_org,
                    "home_tenant_id": tenant_id,
                },
            })
    return findings


def _detect_dangling_keyvault_access_policies(cache: _RunCache) -> List[Dict[str, Any]]:
    """
    Delegate to check_keyvault_access_policies — that module emits the
    canonical shape already.
    """
    try:
        from tools.keyvault import check_keyvault_access_policies
        result = check_keyvault_access_policies(cache.subscription_id)
    except Exception:
        return []
    return [f for f in result.get("findings", []) if f.get("detector") == "dangling_keyvault_access_policy"]


def _detect_legacy_keyvault_contributor_escalation(cache: _RunCache) -> List[Dict[str, Any]]:
    """
    Any identity holding `Key Vault Contributor` on a vault where
    `enableRbacAuthorization=false` — that's a self-service escalation path
    into data-plane secret/key access via accessPolicies write.
    """
    try:
        from tools.keyvault import list_key_vaults
        vaults = list_key_vaults(cache.subscription_id)["items"]
    except Exception:
        return []

    legacy_vaults = {
        v["resource_id"].lower(): v
        for v in vaults
        if v.get("enable_rbac_authorization") is False and v.get("resource_id")
    }
    if not legacy_vaults:
        return []

    findings: List[Dict[str, Any]] = []
    for a in cache.role_assignments()["items"]:
        if a.get("role_name") != "Key Vault Contributor":
            continue
        scope = (a.get("scope") or "").lower()
        vault = None
        for vid, v in legacy_vaults.items():
            if scope == vid or scope in vid or vid in scope:
                vault = v
                break
        if not vault:
            continue
        findings.append({
            "detector": "legacy_keyvault_contributor_escalation",
            "principal_id": a["principal_id"],
            "principal_type": a["principal_type"],
            "display_name": None,
            "scope": a["scope"],
            "risk": "Critical",
            "mitre_technique_id": "T1098.003",
            "attack_name": "Legacy Key Vault Access-Policy Self-Grant",
            "detection_signal": (
                "AzureActivity | where OperationNameValue == "
                "'MICROSOFT.KEYVAULT/VAULTS/ACCESSPOLICIES/WRITE' "
                f"| where Resource has '{vault['name']}'"
            ),
            "remediation": (
                f"Set enableRbacAuthorization=true on vault '{vault['name']}' and migrate access policies "
                "to Key Vault Secrets User / Officer role assignments. This closes the KV Contributor -> "
                "data plane escalation."
            ),
            "evidence": {
                "vault": vault["name"],
                "vault_resource_id": vault["resource_id"],
                "role": a["role_name"],
            },
        })
    return findings


def _detect_suspicious_vm_extensions(cache: _RunCache) -> List[Dict[str, Any]]:
    try:
        from tools.compute import check_compute_extensions
        return check_compute_extensions(cache.subscription_id).get("findings", [])
    except Exception:
        return []


def _detect_managed_identity_owner_escalation(cache: _RunCache) -> List[Dict[str, Any]]:
    try:
        from tools.compute import check_compute_managed_identity_exposure
        return check_compute_managed_identity_exposure(cache.subscription_id).get("findings", [])
    except Exception:
        return []


def _detect_appservice_scm_basic_auth(cache: _RunCache) -> List[Dict[str, Any]]:
    try:
        from tools.appservice import check_appservice_scm_exposure
        return check_appservice_scm_exposure(cache.subscription_id).get("findings", [])
    except Exception:
        return []


def _detect_appservice_managed_identity_escalation(cache: _RunCache) -> List[Dict[str, Any]]:
    try:
        from tools.appservice import check_appservice_managed_identity_exposure
        return check_appservice_managed_identity_exposure(cache.subscription_id).get("findings", [])
    except Exception:
        return []


def _detect_appservice_plaintext_secrets(cache: _RunCache) -> List[Dict[str, Any]]:
    try:
        from tools.appservice import check_appservice_connection_strings
        return check_appservice_connection_strings(cache.subscription_id).get("findings", [])
    except Exception:
        return []


def _detect_dangerous_graph_app_roles(cache: _RunCache) -> List[Dict[str, Any]]:
    try:
        from tools.graph_permissions import list_dangerous_graph_app_role_assignments
        return list_dangerous_graph_app_role_assignments(cache.subscription_id).get("findings", [])
    except Exception:
        return []


def _detect_illicit_oauth_consent_grants(cache: _RunCache) -> List[Dict[str, Any]]:
    try:
        from tools.graph_permissions import list_illicit_oauth_consent_grants
        return list_illicit_oauth_consent_grants(cache.subscription_id).get("findings", [])
    except Exception:
        return []


def _detect_third_party_admin_consent(cache: _RunCache) -> List[Dict[str, Any]]:
    try:
        from tools.graph_permissions import list_third_party_apps_with_admin_consent
        return list_third_party_apps_with_admin_consent(cache.subscription_id).get("findings", [])
    except Exception:
        return []


def _detect_public_boot_diagnostics_storage(cache: _RunCache) -> List[Dict[str, Any]]:
    """
    VM boot diagnostics writes serial-console screenshots to a storage
    account. If that storage account is public, screenshots (which can
    contain login prompts, kernel panics, sensitive output) leak.
    """
    try:
        from tools.storage import check_storage_public_access
        from tools.compute import list_virtual_machines
    except Exception:
        return []

    public = check_storage_public_access(cache.subscription_id).get("findings", [])
    public_uris = set()
    for s in public:
        name = s.get("name")
        if name:
            public_uris.add(f"https://{name}.blob.core.windows.net/")

    findings: List[Dict[str, Any]] = []
    for vm in list_virtual_machines(cache.subscription_id)["items"]:
        bd = vm.get("boot_diagnostics") or {}
        uri = (bd.get("storage_uri") or "").lower()
        if not uri:
            continue
        if any(pub.lower() in uri for pub in public_uris):
            findings.append({
                "detector": "public_boot_diagnostics_storage",
                "principal_id": None,
                "principal_type": None,
                "display_name": vm["name"],
                "scope": vm["resource_id"],
                "risk": "High",
                "mitre_technique_id": "T1530",
                "attack_name": "VM Boot Diagnostics on Public Storage",
                "detection_signal": (
                    "AzureDiagnostics | where ResourceProvider == 'MICROSOFT.STORAGE' "
                    f"| where Resource has '{uri}'"
                ),
                "remediation": (
                    "Switch to managed boot diagnostics, or move to a storage account with "
                    "allowBlobPublicAccess=false and network ACLs."
                ),
                "evidence": {"vm": vm["name"], "boot_diagnostics_uri": bd.get("storage_uri")},
            })
    return findings


# ---------------------------------------------------------------------------
# Registry + entry point
# ---------------------------------------------------------------------------


_DETECTORS: Dict[str, Callable[[_RunCache], List[Dict[str, Any]]]] = {
    # Identity / RBAC
    "service_principal_with_owner": _detect_service_principal_with_owner,
    "orphaned_role_assignment": _detect_orphaned_role_assignments,
    "long_lived_application_credential": _detect_long_lived_app_credentials,
    "federated_credential_wildcard_subject": _detect_federated_credentials_with_wildcard_subject,
    "guest_user_with_azure_role": _detect_guest_users_with_high_privilege,
    "cross_tenant_service_principal_with_azure_role": _detect_cross_tenant_service_principals_with_high_privilege,
    # Key Vault
    "dangling_keyvault_access_policy": _detect_dangling_keyvault_access_policies,
    "legacy_keyvault_contributor_escalation": _detect_legacy_keyvault_contributor_escalation,
    # Compute
    "suspicious_vm_extension": _detect_suspicious_vm_extensions,
    "managed_identity_escalation": _detect_managed_identity_owner_escalation,
    "public_boot_diagnostics_storage": _detect_public_boot_diagnostics_storage,
    # App Service
    "appservice_scm_basic_auth_enabled": _detect_appservice_scm_basic_auth,
    "appservice_managed_identity_escalation": _detect_appservice_managed_identity_escalation,
    "appservice_plaintext_secrets_in_appsettings": _detect_appservice_plaintext_secrets,
    # Microsoft Graph
    "dangerous_graph_app_role": _detect_dangerous_graph_app_roles,
    "illicit_oauth_consent_grant": _detect_illicit_oauth_consent_grants,
    "third_party_admin_consent_grant": _detect_third_party_admin_consent,
}


AVAILABLE_DETECTORS = sorted(_DETECTORS.keys())


def detect_backdoors(
    subscription_id: str,
    principal_type: Optional[str] = None,
    detectors: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Run backdoor detectors. Returns a single flat list of findings plus
    per-detector counts.

    Args:
        subscription_id: Azure subscription ID.
        principal_type: Optional filter using Microsoft's canonical ARM
            vocabulary — 'User', 'ServicePrincipal', or 'Group'. Omit for all.
            Only detectors that operate on identities honor this filter;
            resource-based detectors (VM extensions, boot diagnostics) ignore it.
        detectors: Optional list of detector names to run. Omit to run all.
            Names come from AVAILABLE_DETECTORS.
    """
    filter_type = validate_filter(principal_type)
    cache = _RunCache(subscription_id, filter_type)

    selected: List[str]
    if detectors:
        selected = [d for d in detectors if d in _DETECTORS]
        unknown = [d for d in detectors if d not in _DETECTORS]
    else:
        selected = list(_DETECTORS.keys())
        unknown = []

    all_findings: List[Dict[str, Any]] = []
    by_detector: Dict[str, int] = {}
    detector_errors: Dict[str, str] = {}

    for name in selected:
        func = _DETECTORS[name]
        try:
            findings = func(cache)
        except Exception as exc:  # keep the run going if one detector fails
            detector_errors[name] = str(exc)
            findings = []
        by_detector[name] = len(findings)
        all_findings.extend(findings)

    # Annotate every finding with severity_score, confidence, and CIS mapping,
    # then sort by severity so defenders get the highest-impact items first.
    scored = score_findings(all_findings)

    return {
        "total_findings": len(scored),
        "principal_type_filter": filter_type,
        "detectors_run": selected,
        "unknown_detectors": unknown,
        "detector_errors": detector_errors,
        "by_detector": by_detector,
        "top_severity_score": scored[0]["severity_score"] if scored else 0,
        "findings": scored,
    }
