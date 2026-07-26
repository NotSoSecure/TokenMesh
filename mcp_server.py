"""
TokenMesh — Cloud Security MCP Agent

Exposes every Azure/Entra security analysis capability as an MCP tool
so Claude Desktop (or any MCP client) can call them directly.

Principal-type vocabulary — read this once, then never guess:
    Every tool that accepts a `principal_type` argument expects one of
    Microsoft's canonical ARM values: 'User', 'ServicePrincipal', or
    'Group' (PascalCase singular). These match `properties.principalType`
    on `Microsoft.Authorization/roleAssignments`, `az role assignment
    list --output table`, the Azure Portal, and Microsoft Sentinel KQL
    (`PrincipalType == "ServicePrincipal"`). Never use lowercase-plural
    forms like 'servicePrincipals' or 'users' — those are Graph URL
    shapes, not defender vocabulary.
"""

import json
from typing import List, Optional

from mcp.server.fastmcp import FastMCP

from azure_auth import get_subscription_id
from tools.appservice import (
    check_appservice_connection_strings,
    check_appservice_hardening,
    check_appservice_managed_identity_exposure,
    check_appservice_scm_exposure,
    list_web_apps,
)
from tools.attack_vectors import (
    analyze_attack_vectors,
    map_role_to_attacks,
)
from tools.backdoor import AVAILABLE_DETECTORS, detect_backdoors
from tools.compute import (
    check_compute_extensions,
    check_compute_hardening,
    check_compute_managed_identity_exposure,
    list_arc_machines,
    list_virtual_machines,
)
from tools.graph_permissions import (
    list_dangerous_graph_app_role_assignments,
    list_illicit_oauth_consent_grants,
    list_third_party_apps_with_admin_consent,
)
from tools.identity import list_groups, list_service_principals, list_users
from tools.intelligence import (
    get_high_privileged_identities,
    list_guest_users_with_azure_roles,
    list_high_privileged_service_principals,
    list_orphaned_role_assignments,
)
from tools.keyvault import (
    check_keyvault_access_policies,
    check_keyvault_hardening,
    check_keyvault_object_expiration,
    list_key_vaults,
)
from tools.rbac import (
    list_role_assignments,
    list_subscription_scoped_assignments,
    summarize_high_privilege_assignments,
)
from tools.formatters import render as _render_markdown
from tools.report import generate_pdf_report
from tools.severity import score_findings, top_findings
from tools.storage import (
    check_storage_hardening,
    check_storage_public_access,
    list_storage_accounts,
)

mcp = FastMCP("TokenMesh")


def _sub_id(subscription_id: Optional[str] = None) -> str:
    return get_subscription_id(subscription_id)


def _json_result(data) -> str:
    return json.dumps(data, indent=2, default=str)


_last_result: dict = {}


def _store(result, display_hint: Optional[str] = None) -> str:
    """
    Store the raw result for later use (PDF, top_findings) and return a
    JSON string that also carries a `_display` markdown field the LLM
    can render verbatim to the user.
    """
    global _last_result
    _last_result = result
    if isinstance(result, dict):
        display = _render_markdown(result, hint=display_hint)
        if display and "_display" not in result:
            result = {**result, "_display": display}
    return _json_result(result)


# ---------------------------------------------------------------------------
# Identity — Entra directory objects
# ---------------------------------------------------------------------------


@mcp.tool()
def mcp_list_users(subscription_id: Optional[str] = None, top: int = 100) -> str:
    """List Microsoft Entra ID users.

    Returns Entra directory user objects only — no service principals or groups.
    Use `mcp_list_service_principals` for SPs and `mcp_list_groups` for groups.
    """
    return _store(list_users(subscription_id=subscription_id, top=top))


@mcp.tool()
def mcp_list_groups(subscription_id: Optional[str] = None, top: int = 100) -> str:
    """List Microsoft Entra ID groups."""
    return _store(list_groups(subscription_id=subscription_id, top=top))


@mcp.tool()
def mcp_list_service_principals(subscription_id: Optional[str] = None, top: int = 100) -> str:
    """List Microsoft Entra ID service principals (application, managed identity, and legacy types)."""
    return _store(list_service_principals(subscription_id=subscription_id, top=top))


# ---------------------------------------------------------------------------
# RBAC — Azure Resource Manager role assignments
# ---------------------------------------------------------------------------


@mcp.tool()
def mcp_list_role_assignments(
    subscription_id: Optional[str] = None,
    scope: Optional[str] = None,
    principal_type: Optional[str] = None,
) -> str:
    """List Azure RBAC role assignments at subscription or custom scope.

    Args:
        subscription_id: Azure subscription ID.
        scope: Optional ARM scope path (e.g. /subscriptions/<id>/resourceGroups/<rg>).
        principal_type: Optional filter — 'User', 'ServicePrincipal', or 'Group'
            (Microsoft canonical ARM values, PascalCase singular). Omit to include all.
    """
    return _store(list_role_assignments(
        subscription_id=subscription_id, scope=scope, principal_type=principal_type,
    ))


@mcp.tool()
def mcp_summarize_high_privilege_assignments(
    subscription_id: Optional[str] = None,
    principal_type: Optional[str] = None,
) -> str:
    """Summarize high-privilege Azure RBAC roles (Owner, Contributor, User Access Administrator).

    Args:
        subscription_id: Azure subscription ID.
        principal_type: Optional filter — 'User', 'ServicePrincipal', or 'Group'.
            Use 'ServicePrincipal' when the defender question is about SPs specifically.
    """
    return _store(summarize_high_privilege_assignments(
        subscription_id=subscription_id, principal_type=principal_type,
    ))


@mcp.tool()
def mcp_list_subscription_scoped_assignments(
    subscription_id: Optional[str] = None,
    principal_type: Optional[str] = None,
) -> str:
    """List all RBAC role assignments scoped to the subscription.

    Args:
        subscription_id: Azure subscription ID.
        principal_type: Optional filter — 'User', 'ServicePrincipal', or 'Group'.
    """
    return _store(list_subscription_scoped_assignments(
        subscription_id=subscription_id, principal_type=principal_type,
    ))


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------


@mcp.tool()
def mcp_list_storage_accounts(subscription_id: Optional[str] = None) -> str:
    """List all Azure storage accounts in the subscription."""
    return _store(list_storage_accounts(subscription_id=subscription_id))


@mcp.tool()
def mcp_check_storage_public_access(subscription_id: Optional[str] = None) -> str:
    """Find storage accounts that allow public blob access."""
    return _store(check_storage_public_access(subscription_id=subscription_id))


@mcp.tool()
def mcp_check_storage_hardening(subscription_id: Optional[str] = None) -> str:
    """Check storage accounts for misconfigurations: public access, weak TLS, HTTP usage, permissive network rules."""
    return _store(check_storage_hardening(subscription_id=subscription_id), display_hint="storage_account_hardening")


# ---------------------------------------------------------------------------
# Key Vault
# ---------------------------------------------------------------------------


@mcp.tool()
def mcp_list_key_vaults(subscription_id: Optional[str] = None) -> str:
    """List every Azure Key Vault (`Microsoft.KeyVault/vaults`) in the subscription with hardening-relevant properties."""
    return _store(list_key_vaults(subscription_id=subscription_id))


@mcp.tool()
def mcp_check_keyvault_hardening(subscription_id: Optional[str] = None) -> str:
    """Detect Key Vault misconfigurations enabling attacker persistence or exfiltration.

    Flags: soft-delete disabled, purge protection missing, legacy access-policy mode
    (enableRbacAuthorization=false), publicNetworkAccess=Enabled, permissive network ACLs
    (defaultAction=Allow, bypass=AzureServices), no private endpoints. Each finding includes
    MITRE technique ID, KQL detection signal, and remediation.
    """
    return _store(check_keyvault_hardening(subscription_id=subscription_id), display_hint="key_vault_hardening")


@mcp.tool()
def mcp_check_keyvault_access_policies(subscription_id: Optional[str] = None) -> str:
    """Audit legacy Key Vault access policies for backdoor patterns.

    Detects: dangling access policies (objectId no longer resolves — deleted-principal
    persistence), overly broad permissions (all/purge/import), cross-tenant objectIds.
    """
    return _store(check_keyvault_access_policies(subscription_id=subscription_id))


@mcp.tool()
def mcp_check_keyvault_object_expiration(
    subscription_id: Optional[str] = None,
    max_lifetime_days: int = 730,
) -> str:
    """Flag Key Vault keys, secrets, and certificates without an expiry or with an expiry more than `max_lifetime_days` in the future.

    Requires the caller to hold Key Vault Reader / Officer permissions on each vault
    (data-plane access). Where access is denied, the vault is reported with an
    `enumeration_failed` info entry instead of a finding.
    """
    return _store(check_keyvault_object_expiration(
        subscription_id=subscription_id, max_lifetime_days=max_lifetime_days,
    ))


# ---------------------------------------------------------------------------
# Compute
# ---------------------------------------------------------------------------


@mcp.tool()
def mcp_list_virtual_machines(subscription_id: Optional[str] = None) -> str:
    """List every Azure VM (`Microsoft.Compute/virtualMachines`) with identity, security, and boot-diagnostics fields."""
    return _store(list_virtual_machines(subscription_id=subscription_id))


@mcp.tool()
def mcp_check_compute_managed_identity_exposure(subscription_id: Optional[str] = None) -> str:
    """Cross-reference every VM's managed identity against Azure RBAC and flag identities holding Owner/Contributor/UAA at subscription-or-higher scope.

    This is the "managed identity escalation" path: any code execution on the VM
    (runCommand, IMDS token theft, malicious extension) inherits the MI's permissions.
    MITRE T1552.005 -> T1098.003.
    """
    return _store(check_compute_managed_identity_exposure(subscription_id=subscription_id))


@mcp.tool()
def mcp_check_compute_extensions(subscription_id: Optional[str] = None) -> str:
    """Enumerate VM extensions and flag CustomScriptExtension, RunCommand, DSC, or any extension pulling from foreign (non-tenant) storage URIs.

    BloodHound-Azure edge: AZExecuteCommand. MicroBurst: Invoke-AzureRmVMRunCommand.
    MITRE T1651.
    """
    return _store(check_compute_extensions(subscription_id=subscription_id))


@mcp.tool()
def mcp_check_compute_hardening(subscription_id: Optional[str] = None) -> str:
    """Flag VM hardening gaps: encryption at host disabled, no TrustedLaunch, unmanaged OS disks, platform-managed keys, classic boot diagnostics."""
    return _store(check_compute_hardening(subscription_id=subscription_id), display_hint="virtual_machine_hardening")


@mcp.tool()
def mcp_list_arc_machines(
    subscription_id: Optional[str] = None,
    stale_after_days: int = 30,
) -> str:
    """List Azure Arc-connected machines (`Microsoft.HybridCompute/machines`) and flag stale registrations.

    Stale Arc registrations (no status change in `stale_after_days`) are a documented
    persistence artifact — attacker registers a machine, uses its managed identity,
    then abandons the agent while the RBAC assignment remains.
    """
    return _store(list_arc_machines(subscription_id=subscription_id, stale_after_days=stale_after_days))


# ---------------------------------------------------------------------------
# Intelligence — enriched high-priv view + intent-mapped defender tools
# ---------------------------------------------------------------------------


@mcp.tool()
def mcp_get_high_privileged_identities(
    subscription_id: Optional[str] = None,
    principal_type: Optional[str] = None,
) -> str:
    """Get high-privileged identities with Azure RBAC + Entra roles, risk levels, evidence, MITRE-tagged attack vectors.

    Args:
        subscription_id: Azure subscription ID.
        principal_type: Optional filter — 'User', 'ServicePrincipal', or 'Group'
            (Microsoft canonical ARM values). Omit for all. If the defender asks
            about a specific type (e.g. "service principals with Owner"), pass
            'ServicePrincipal' — never return mixed principal types when the
            question was about one type.
    """
    return _store(get_high_privileged_identities(
        subscription_id=_sub_id(subscription_id), principal_type=principal_type,
    ))


@mcp.tool()
def mcp_list_high_privileged_service_principals(subscription_id: Optional[str] = None) -> str:
    """Every service principal with Owner / Contributor / User Access Administrator, enriched with SP-specific fields.

    Use this when the defender question is specifically about service principals.
    Returns app_id, service_principal_type (Application vs ManagedIdentity),
    credential counts, and appOwnerOrganizationId (cross-tenant flag).
    """
    return _store(list_high_privileged_service_principals(subscription_id=_sub_id(subscription_id)))


@mcp.tool()
def mcp_list_guest_users_with_azure_roles(subscription_id: Optional[str] = None) -> str:
    """Entra guest users (`userType = Guest`) with high-privilege Azure RBAC.

    Partner-tenant breach = your subscription breach. This is the documented
    lateral movement path when a customer trusts an external tenant's identity.
    """
    return _store(list_guest_users_with_azure_roles(subscription_id=_sub_id(subscription_id)))


@mcp.tool()
def mcp_list_orphaned_role_assignments(subscription_id: Optional[str] = None) -> str:
    """Every high-privilege role assignment whose principal_id does not resolve in Microsoft Graph.

    Classic Azure backdoor: an SP or user was deleted, but the RBAC assignment stayed.
    The object can be re-created (or restored from Recycle Bin) with the same ID to
    reinstate access. MITRE T1078.004.
    """
    return _store(list_orphaned_role_assignments(subscription_id=_sub_id(subscription_id)))


# ---------------------------------------------------------------------------
# Attack vectors — data-driven role → attack mapping
# ---------------------------------------------------------------------------


@mcp.tool()
def mcp_analyze_attack_vectors(
    principal_id: str,
    subscription_id: Optional[str] = None,
) -> str:
    """Analyze one identity's blast radius by mapping every role it holds to concrete attack techniques.

    Returns: resolved principal, all its Azure RBAC assignments, and a list of
    attack vectors each with MITRE technique ID, KQL detection signal, remediation,
    and the granting role. Sources: MITRE ATT&CK for Cloud, BloodHound-Azure edge
    taxonomy, MicroBurst, Socchi's Entra privesc matrix.
    """
    return _store(analyze_attack_vectors(
        subscription_id=_sub_id(subscription_id), principal_id=principal_id,
    ))


@mcp.tool()
def mcp_map_role_to_attacks(role_name: str, scope: Optional[str] = None) -> str:
    """Look up attack vectors enabled by a single Azure/Entra built-in role at a given scope.

    Pure reference-data lookup — no live Azure calls. Useful when the defender
    asks "what could someone with `Storage Account Contributor` do?" or wants to
    understand the blast radius of a role before granting it.
    """
    return _store({
        "role_name": role_name,
        "scope": scope,
        "attack_vectors": map_role_to_attacks(role_name, scope),
    })


# ---------------------------------------------------------------------------
# App Service
# ---------------------------------------------------------------------------


@mcp.tool()
def mcp_list_web_apps(subscription_id: Optional[str] = None) -> str:
    """List every App Service site (web apps + function apps) with hardening-relevant fields."""
    return _store(list_web_apps(subscription_id=subscription_id))


@mcp.tool()
def mcp_check_appservice_hardening(subscription_id: Optional[str] = None) -> str:
    """Flag App Service hardening gaps: HTTPS-only off, min TLS < 1.2, FTP publishing allowed, publicNetworkAccess=Enabled, remote debugging on, wildcard CORS. Includes CIS Azure control IDs."""
    return _store(check_appservice_hardening(subscription_id=subscription_id), display_hint="app_service_hardening")


@mcp.tool()
def mcp_check_appservice_scm_exposure(subscription_id: Optional[str] = None) -> str:
    """Detect Kudu SCM / FTP basic auth enabled — the MicroBurst web-shell primitive. MITRE T1505.003."""
    return _store(check_appservice_scm_exposure(subscription_id=subscription_id))


@mcp.tool()
def mcp_check_appservice_managed_identity_exposure(subscription_id: Optional[str] = None) -> str:
    """Cross-reference App Service managed identities against Azure RBAC — flag MI holding Owner/Contributor/UAA. Kudu deployment access = subscription takeover primitive."""
    return _store(check_appservice_managed_identity_exposure(subscription_id=subscription_id))


@mcp.tool()
def mcp_check_appservice_connection_strings(subscription_id: Optional[str] = None) -> str:
    """Flag plaintext secrets stored in App Service app settings (rather than referenced via Key Vault). Only names and metadata are captured — never values."""
    return _store(check_appservice_connection_strings(subscription_id=subscription_id))


# ---------------------------------------------------------------------------
# Microsoft Graph app-role + OAuth consent
# ---------------------------------------------------------------------------


@mcp.tool()
def mcp_list_dangerous_graph_app_role_assignments(subscription_id: Optional[str] = None) -> str:
    """Enumerate service principals holding dangerous Microsoft Graph application permissions — RoleManagement.ReadWrite.Directory, AppRoleAssignment.ReadWrite.All, Application.ReadWrite.All, and similar tenant-takeover primitives. BloodHound-Azure AZMGGrantAppRoles / AZMGGrantRole edges."""
    return _store(list_dangerous_graph_app_role_assignments(subscription_id=subscription_id))


@mcp.tool()
def mcp_list_illicit_oauth_consent_grants(subscription_id: Optional[str] = None) -> str:
    """Enumerate OAuth2 delegated permission grants for high-risk scopes (Mail.Read, Files.Read.All, Sites.Read.All, Directory.Read.All). Detects Microsoft's canonical Illicit Consent Grant phishing pattern (MITRE T1528)."""
    return _store(list_illicit_oauth_consent_grants(subscription_id=subscription_id))


@mcp.tool()
def mcp_list_third_party_apps_with_admin_consent(subscription_id: Optional[str] = None) -> str:
    """Third-party (non-Microsoft) service principals that have received admin-consented delegated grants. Admin-consent to a third-party app = tenant-wide data-plane access."""
    return _store(list_third_party_apps_with_admin_consent(subscription_id=subscription_id))


# ---------------------------------------------------------------------------
# Severity + prioritization
# ---------------------------------------------------------------------------


@mcp.tool()
def mcp_top_findings(n: int = 10) -> str:
    """Return the top N findings from the last analysis, sorted by severity score (0-100) and confidence.

    Call after any analysis that produced a `findings` list (e.g. mcp_detect_backdoors,
    mcp_check_appservice_hardening). Each finding is annotated with severity_score,
    confidence (high/medium/low), and cis_controls.
    """
    findings = _last_result.get("findings") if _last_result else None
    if not findings:
        return json.dumps({"error": "No findings available. Run an analysis tool first."})
    return _json_result({"top_n": n, "findings": top_findings(findings, n=n)})


# ---------------------------------------------------------------------------
# Backdoor detection
# ---------------------------------------------------------------------------


@mcp.tool()
def mcp_detect_backdoors(
    subscription_id: Optional[str] = None,
    principal_type: Optional[str] = None,
    detectors: Optional[List[str]] = None,
) -> str:
    """Run backdoor and persistence detectors across identity, RBAC, Key Vault, and Compute layers.

    Args:
        subscription_id: Azure subscription ID.
        principal_type: Optional filter — 'User', 'ServicePrincipal', or 'Group'.
            Only detectors that operate on identities honor this filter; resource-based
            detectors (VM extensions, boot diagnostics, KV access policies) run regardless.
        detectors: Optional list of detector names to run. Omit for all. Available:
            service_principal_with_owner, orphaned_role_assignment,
            long_lived_application_credential, federated_credential_wildcard_subject,
            guest_user_with_azure_role, cross_tenant_service_principal_with_azure_role,
            dangling_keyvault_access_policy, legacy_keyvault_contributor_escalation,
            suspicious_vm_extension, managed_identity_escalation,
            public_boot_diagnostics_storage.

    Every finding includes principal_type (Microsoft canonical), MITRE technique ID,
    KQL detection signal for Sentinel/Defender, and remediation.
    """
    return _store(detect_backdoors(
        subscription_id=_sub_id(subscription_id),
        principal_type=principal_type,
        detectors=detectors,
    ))


@mcp.tool()
def mcp_list_available_backdoor_detectors() -> str:
    """List every backdoor detector name available for the `detectors` argument of mcp_detect_backdoors."""
    return _json_result({"available_detectors": AVAILABLE_DETECTORS})


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------


@mcp.tool()
def mcp_generate_pdf_report() -> str:
    """Generate a PDF security report from the most recent analysis result.

    Call one of the analysis tools first (e.g. mcp_get_high_privileged_identities,
    mcp_detect_backdoors, mcp_analyze_attack_vectors) so there is data to render.
    """
    if not _last_result:
        return json.dumps({"error": "No analysis data available yet. Run an analysis tool first."})
    return _json_result(generate_pdf_report(_last_result))


# ---------------------------------------------------------------------------


if __name__ == "__main__":
    mcp.run()
