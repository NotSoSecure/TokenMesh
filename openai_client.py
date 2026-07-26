import os
from typing import Optional

from openai import OpenAI

# =========================
# CONFIG
# =========================

MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

# Lazy client — the OpenAI SDK constructor requires OPENAI_API_KEY at
# construction time. Making it lazy lets `import openai_client` succeed in
# environments where the key isn't set (MCP server, tests, static analysis)
# and defers the failure to the first actual API call.
_client: Optional[OpenAI] = None


class _LazyClient:
    """Delegates attribute access to a real OpenAI client on first use."""

    def _get(self) -> OpenAI:
        global _client
        if _client is None:
            _client = OpenAI()
        return _client

    def __getattr__(self, name):
        return getattr(self._get(), name)


client = _LazyClient()

# =========================
# SHARED SCHEMA FRAGMENTS
# =========================

_PRINCIPAL_TYPE_SCHEMA = {
    "type": "string",
    "enum": ["User", "ServicePrincipal", "Group"],
    "description": (
        "Filter by Microsoft canonical ARM principal type (PascalCase singular). "
        "Never use lowercase-plural forms like 'servicePrincipals' — those are "
        "Graph URL shapes, not defender vocabulary."
    ),
}


def _sp(properties=None, required=None):
    return {
        "type": "object",
        "properties": properties or {},
        "required": required or [],
        "additionalProperties": False,
    }


def _fn(name, description, properties=None, required=None):
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": _sp(properties, required),
        },
    }


# =========================
# TOOL DEFINITIONS
# =========================

TOOLS = [
    # ---------- Storage ----------
    _fn("list_storage_accounts", "List all Azure storage accounts in the subscription."),
    _fn("check_storage_public_access", "Find storage accounts that allow public blob access."),
    _fn(
        "check_storage_hardening",
        "Check storage accounts for misconfigurations: public access, weak TLS, HTTP usage, permissive network rules.",
    ),

    # ---------- Key Vault ----------
    _fn("list_key_vaults", "List every Azure Key Vault with hardening-relevant properties."),
    _fn(
        "check_keyvault_hardening",
        "Detect Key Vault misconfigurations enabling attacker persistence or exfiltration: "
        "soft-delete off, purge protection off, legacy access-policy mode, public network access, "
        "permissive network ACLs, no private endpoints. Includes MITRE IDs.",
    ),
    _fn(
        "check_keyvault_access_policies",
        "Audit legacy Key Vault access policies for dangling (deleted-principal) entries, "
        "overly broad permissions (all/purge/import), and cross-tenant objectIds.",
    ),
    _fn(
        "check_keyvault_object_expiration",
        "Flag Key Vault keys, secrets, and certificates with no expiry or lifetime > max_lifetime_days.",
        properties={
            "max_lifetime_days": {
                "type": "integer",
                "description": "Threshold — expiries further out than this are flagged.",
                "minimum": 30,
                "maximum": 3650,
            }
        },
    ),

    # ---------- Compute ----------
    _fn(
        "list_virtual_machines",
        "List every Azure VM with identity (system+user-assigned managed identities), security profile, disk, and boot diagnostics.",
    ),
    _fn(
        "check_compute_managed_identity_exposure",
        "Cross-reference VM managed identities against Azure RBAC. Flag VMs whose MI holds "
        "Owner/Contributor/UAA — code exec on such a VM equals subscription takeover. "
        "MITRE T1552.005 -> T1098.003.",
    ),
    _fn(
        "check_compute_extensions",
        "Enumerate VM extensions; flag CustomScriptExtension, RunCommand, DSC, or any extension "
        "pulling from foreign storage URIs. BloodHound-Azure AZExecuteCommand. MITRE T1651.",
    ),
    _fn(
        "check_compute_hardening",
        "Flag VM hardening gaps: encryption at host disabled, no TrustedLaunch, unmanaged OS disks, "
        "platform-managed keys, classic boot diagnostics.",
    ),
    _fn(
        "list_arc_machines",
        "List Azure Arc-connected machines and flag stale registrations (no status change in `stale_after_days`).",
        properties={
            "stale_after_days": {
                "type": "integer",
                "description": "Machines whose last status change is older than this are flagged stale.",
                "minimum": 1,
                "maximum": 365,
            }
        },
    ),

    # ---------- Identity (Entra) ----------
    _fn(
        "list_users",
        "List Microsoft Entra ID users (Entra directory user objects only — no service principals or groups).",
        properties={
            "top": {"type": "integer", "description": "Number of users to fetch (max 999).",
                    "minimum": 1, "maximum": 999}
        },
    ),
    _fn(
        "list_groups",
        "List Microsoft Entra ID groups.",
        properties={
            "top": {"type": "integer", "description": "Number of groups to fetch (max 999).",
                    "minimum": 1, "maximum": 999}
        },
    ),
    _fn(
        "list_service_principals",
        "List Microsoft Entra ID service principals.",
        properties={
            "top": {"type": "integer", "description": "Number of service principals to fetch (max 999).",
                    "minimum": 1, "maximum": 999}
        },
    ),

    # ---------- RBAC ----------
    _fn(
        "list_role_assignments",
        "List Azure RBAC role assignments at subscription or custom scope.",
        properties={
            "scope": {
                "type": "string",
                "description": "Optional ARM scope path (e.g. /subscriptions/<id>/resourceGroups/<rg>).",
            },
            "principal_type": _PRINCIPAL_TYPE_SCHEMA,
        },
    ),
    _fn(
        "summarize_high_privilege_assignments",
        "Summarize high-privilege Azure RBAC roles (Owner, Contributor, User Access Administrator).",
        properties={"principal_type": _PRINCIPAL_TYPE_SCHEMA},
    ),
    _fn(
        "list_subscription_scoped_assignments",
        "List all RBAC role assignments scoped to the subscription.",
        properties={"principal_type": _PRINCIPAL_TYPE_SCHEMA},
    ),

    # ---------- Intelligence + intent-mapped defender tools ----------
    _fn(
        "get_high_privileged_identities",
        "Get high-privileged identities with Azure RBAC + Entra roles, risk levels, evidence, and MITRE-tagged "
        "attack vectors. When the defender question is about a specific principal type (e.g. 'service principals "
        "with Owner'), always pass principal_type='ServicePrincipal' — never return mixed types.",
        properties={"principal_type": _PRINCIPAL_TYPE_SCHEMA},
    ),
    _fn(
        "list_high_privileged_service_principals",
        "Every service principal holding Owner/Contributor/UAA. Enriched with app_id, service_principal_type "
        "(Application vs ManagedIdentity), credential counts, and appOwnerOrganizationId (cross-tenant flag). "
        "Use this when the defender specifically asks about service principals.",
    ),
    _fn(
        "list_guest_users_with_azure_roles",
        "Entra guest users (`userType = Guest`) with high-privilege Azure RBAC. Partner-tenant lateral movement path.",
    ),
    _fn(
        "list_orphaned_role_assignments",
        "High-privilege role assignments whose principal_id does not resolve in Microsoft Graph — the "
        "deleted-object persistence pattern. MITRE T1078.004.",
    ),

    # ---------- Attack vectors ----------
    _fn(
        "analyze_attack_vectors",
        "Analyze one identity's blast radius by mapping every role it holds to concrete attack techniques with MITRE IDs.",
        properties={
            "principal_id": {
                "type": "string",
                "description": "Object ID of the identity (user, service principal, or group) to analyze.",
            }
        },
        required=["principal_id"],
    ),
    _fn(
        "map_role_to_attacks",
        "Look up attack vectors enabled by a single Azure/Entra role at a given scope. Pure reference lookup.",
        properties={
            "role_name": {
                "type": "string",
                "description": "Built-in Azure or Entra role display name (e.g. 'Storage Account Contributor').",
            },
            "scope": {
                "type": "string",
                "description": "Optional ARM scope. Attacks whose min_scope tier is not met are filtered out.",
            },
        },
        required=["role_name"],
    ),

    # ---------- Backdoor detection ----------
    _fn(
        "detect_backdoors",
        "Run backdoor and persistence detectors across identity, RBAC, Key Vault, and Compute layers. "
        "Every finding includes principal_type (Microsoft canonical), MITRE ID, KQL detection signal, and remediation.",
        properties={
            "principal_type": _PRINCIPAL_TYPE_SCHEMA,
            "detectors": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Optional list of detector names. Omit to run all. "
                    "Names: service_principal_with_owner, orphaned_role_assignment, "
                    "long_lived_application_credential, federated_credential_wildcard_subject, "
                    "guest_user_with_azure_role, cross_tenant_service_principal_with_azure_role, "
                    "dangling_keyvault_access_policy, legacy_keyvault_contributor_escalation, "
                    "suspicious_vm_extension, managed_identity_escalation, "
                    "public_boot_diagnostics_storage."
                ),
            },
        },
    ),
    _fn(
        "list_available_backdoor_detectors",
        "List every backdoor detector name available for the `detectors` argument of detect_backdoors.",
    ),

    # ---------- App Service ----------
    _fn(
        "list_web_apps",
        "List every App Service site (web apps + function apps) with hardening-relevant fields.",
    ),
    _fn(
        "check_appservice_hardening",
        "Flag App Service hardening gaps: HTTPS-only off, min TLS < 1.2, FTP publishing allowed, "
        "publicNetworkAccess=Enabled, remote debugging on, wildcard CORS. Includes CIS Azure control IDs.",
    ),
    _fn(
        "check_appservice_scm_exposure",
        "Detect Kudu SCM / FTP basic auth enabled — the MicroBurst web-shell primitive. MITRE T1505.003.",
    ),
    _fn(
        "check_appservice_managed_identity_exposure",
        "Cross-reference App Service managed identities against Azure RBAC. Flag MI holding "
        "Owner/Contributor/UAA — Kudu deployment access equals subscription takeover.",
    ),
    _fn(
        "check_appservice_connection_strings",
        "Flag plaintext secrets stored in App Service app settings (not referenced via Key Vault). "
        "Only names and metadata are captured — never values.",
    ),

    # ---------- Microsoft Graph app-role + OAuth consent ----------
    _fn(
        "list_dangerous_graph_app_role_assignments",
        "SPs holding dangerous Microsoft Graph application permissions like "
        "RoleManagement.ReadWrite.Directory, AppRoleAssignment.ReadWrite.All, "
        "Application.ReadWrite.All. BloodHound-Azure AZMGGrantAppRoles / AZMGGrantRole.",
    ),
    _fn(
        "list_illicit_oauth_consent_grants",
        "OAuth2 delegated permission grants for high-risk scopes (Mail.Read, Files.Read.All, "
        "Sites.Read.All, Directory.Read.All). Microsoft Illicit Consent Grant. MITRE T1528.",
    ),
    _fn(
        "list_third_party_apps_with_admin_consent",
        "Third-party (non-Microsoft) service principals holding admin-consented delegated grants.",
    ),

    # ---------- Report ----------
    _fn(
        "generate_pdf_report",
        "Generate a PDF security report for the most recent analysis result "
        "(high-privileged identities, backdoors, attack vectors, KV/Compute/AppService findings).",
    ),
]
