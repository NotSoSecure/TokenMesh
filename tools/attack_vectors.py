"""
Data-driven mapping from Azure/Entra role names to concrete attack vectors.

Each entry ties a role to a named technique with a MITRE ATT&CK for Cloud
identifier, the primitive an attacker would use, a KQL-friendly detection
signal a defender can drop into Microsoft Sentinel or Defender for Cloud,
and a remediation.

Sources folded into the seed table:
  - MITRE ATT&CK for Cloud (Azure / Entra ID matrices)
  - BloodHound-Azure edge taxonomy (SpecterOps)
  - MicroBurst (NetSPI) documented abuse paths
  - Socchi's Entra AD role privilege-escalation matrix
  - Microsoft's own privileged-role documentation

This is the module that answers the question "what could an attacker do
with a given identity" — a purely reference-data lookup with no live
Azure calls.
"""

from typing import Any, Dict, Iterable, List, Optional

from tools.principal_types import SERVICE_PRINCIPAL, normalize


# ---------------------------------------------------------------------------
# Scope helpers
# ---------------------------------------------------------------------------
#
# Azure RBAC scopes form a strict hierarchy:
#   management_group > subscription > resource_group > resource
# Any assignment made at a higher level is inherited by everything below.
# Some attacks only make sense at or above a given scope tier — e.g. UAA on
# a single resource group cannot escalate a peer subscription — so each
# attack entry names its minimum required scope.

SCOPE_MANAGEMENT_GROUP = "management_group"
SCOPE_SUBSCRIPTION = "subscription"
SCOPE_RESOURCE_GROUP = "resource_group"
SCOPE_RESOURCE = "resource"

_SCOPE_ORDER = {
    SCOPE_MANAGEMENT_GROUP: 4,
    SCOPE_SUBSCRIPTION: 3,
    SCOPE_RESOURCE_GROUP: 2,
    SCOPE_RESOURCE: 1,
}


def _classify_scope(scope_path: Optional[str]) -> str:
    """Bucket a raw ARM scope string into one of the four tiers."""
    if not scope_path:
        return SCOPE_RESOURCE
    s = scope_path.lower()
    if s.startswith("/providers/microsoft.management/managementgroups"):
        return SCOPE_MANAGEMENT_GROUP
    if "/resourcegroups/" in s and "/providers/" in s and s.count("/providers/") >= 1:
        # /subscriptions/.../resourceGroups/.../providers/... => individual resource
        parts = s.split("/providers/")
        if len(parts) >= 2 and parts[1].count("/") >= 1:
            return SCOPE_RESOURCE
        return SCOPE_RESOURCE_GROUP
    if "/resourcegroups/" in s:
        return SCOPE_RESOURCE_GROUP
    if s.startswith("/subscriptions/") and s.count("/") == 2:
        return SCOPE_SUBSCRIPTION
    return SCOPE_RESOURCE


def _scope_meets_minimum(scope_tier: str, min_tier: str) -> bool:
    return _SCOPE_ORDER.get(scope_tier, 0) >= _SCOPE_ORDER.get(min_tier, 0)


# ---------------------------------------------------------------------------
# The role -> attack vector table
# ---------------------------------------------------------------------------


def _v(
    technique_id: str,
    attack_name: str,
    primitive: str,
    detection_signal: str,
    remediation: str,
    min_scope: str = SCOPE_RESOURCE,
    tags: Optional[List[str]] = None,
) -> Dict[str, Any]:
    return {
        "technique_id": technique_id,
        "attack_name": attack_name,
        "primitive": primitive,
        "detection_signal": detection_signal,
        "remediation": remediation,
        "min_scope": min_scope,
        "tags": tags or [],
    }


ROLE_ATTACK_MAP: Dict[str, List[Dict[str, Any]]] = {
    # -------------------- Control plane --------------------
    "Owner": [
        _v(
            "T1098.003", "Subscription Takeover",
            "Grant self or planted principal any role at any scope.",
            "AzureActivity | where OperationNameValue == 'MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE' | where Caller has_any (identityId)",
            "Restrict Owner to break-glass identities protected by PIM + MFA + Conditional Access.",
            min_scope=SCOPE_RESOURCE_GROUP,
            tags=["control-plane", "critical"],
        ),
        _v(
            "T1562.008", "Disable Cloud Security Controls",
            "Turn off Defender for Cloud, delete diagnostic settings, remove alerts.",
            "AzureActivity | where OperationNameValue in ('MICROSOFT.SECURITY/POLICIES/WRITE', 'MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/DELETE')",
            "Deny diagnostic-setting deletion via Azure Policy; alert on Defender plan tier changes.",
            min_scope=SCOPE_SUBSCRIPTION,
            tags=["defense-evasion"],
        ),
    ],
    "Contributor": [
        _v(
            "T1578.002", "Deploy Malicious Cloud Resources",
            "Create VMs, function apps, deployment scripts running attacker code.",
            "AzureActivity | where OperationNameValue == 'MICROSOFT.RESOURCES/DEPLOYMENTS/WRITE' | summarize count() by Caller | where count_ > 5",
            "Require deployments through approved templates only; block deploymentScripts via policy.",
            min_scope=SCOPE_RESOURCE_GROUP,
            tags=["execution"],
        ),
        _v(
            "T1651", "Command Execution via runCommand",
            "Invoke Microsoft.Compute/virtualMachines/runCommand for SYSTEM shell on any VM.",
            "AzureActivity | where OperationNameValue endswith '/RUNCOMMAND/ACTION'",
            "Restrict Virtual Machine Contributor and Contributor to break-glass; alert on all runCommand invocations.",
            min_scope=SCOPE_RESOURCE,
            tags=["execution", "T1651"],
        ),
        _v(
            "T1098.003", "Managed Identity Escalation",
            "Create a UAMI, assign it a high-priv role, attach it to an attacker VM.",
            "AzureActivity | where OperationNameValue == 'MICROSOFT.MANAGEDIDENTITY/USERASSIGNEDIDENTITIES/WRITE'",
            "Require just-in-time access for UAMI creation; audit UAMI role assignments monthly.",
            min_scope=SCOPE_RESOURCE_GROUP,
            tags=["persistence"],
        ),
    ],
    "User Access Administrator": [
        _v(
            "T1098.003", "Additional Cloud Role (RBAC)",
            "Assign self or planted principal any Azure RBAC role at or below the assigner's scope.",
            "AzureActivity | where OperationNameValue == 'MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE'",
            "Restrict UAA to PIM-only, MFA-required. Alert on any new role assignment by a principal with no prior write history.",
            min_scope=SCOPE_RESOURCE_GROUP,
            tags=["privilege-escalation", "control-plane"],
        ),
    ],
    "Role Based Access Control Administrator": [
        _v(
            "T1098.003", "Additional Cloud Role (RBAC)",
            "Scoped equivalent of UAA — same abuse pattern with less blast radius.",
            "AzureActivity | where OperationNameValue == 'MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE'",
            "Prefer this role over UAA where possible; still gate behind PIM.",
            min_scope=SCOPE_RESOURCE_GROUP,
            tags=["privilege-escalation"],
        ),
    ],
    "Managed Identity Operator": [
        _v(
            "T1098.003", "Attach UAMI to Attacker Resource",
            "Assign an existing user-assigned managed identity to a resource the attacker controls — inherit the UAMI's permissions.",
            "AzureActivity | where OperationNameValue endswith '/WRITE' | where Properties has 'userAssignedIdentities'",
            "Do not co-locate high-priv UAMIs and low-privilege operators; grant Managed Identity Operator only on the specific UAMI.",
            min_scope=SCOPE_RESOURCE,
            tags=["privilege-escalation", "AZManagedIdentity"],
        ),
    ],
    "Managed Identity Contributor": [
        _v(
            "T1136.003", "Create Cloud Managed Identity",
            "Create a new UAMI, then assign it elsewhere as persistence.",
            "AzureActivity | where OperationNameValue == 'MICROSOFT.MANAGEDIDENTITY/USERASSIGNEDIDENTITIES/WRITE'",
            "Alert on UAMI creation outside change windows.",
            min_scope=SCOPE_RESOURCE_GROUP,
            tags=["persistence"],
        ),
    ],

    # -------------------- Storage data plane --------------------
    "Storage Blob Data Owner": [
        _v(
            "T1530", "Cloud Storage Data Exfiltration",
            "Read/write any blob without needing storage account keys.",
            "StorageBlobLogs | where AuthenticationType == 'OAuth' | where OperationName in ('GetBlob', 'ListBlobs') | summarize count() by CallerIpAddress",
            "Prefer scoped Storage Blob Data Reader; enable network ACLs.",
            min_scope=SCOPE_RESOURCE,
            tags=["data-plane", "exfiltration"],
        ),
    ],
    "Storage Blob Data Contributor": [
        _v(
            "T1530", "Cloud Storage Data Exfiltration",
            "Read/write any blob without needing storage account keys.",
            "StorageBlobLogs | where AuthenticationType == 'OAuth' | where OperationName in ('GetBlob', 'ListBlobs')",
            "Enable storage firewall; require private endpoints; audit oauth data-plane access from unexpected IPs.",
            min_scope=SCOPE_RESOURCE,
            tags=["data-plane", "exfiltration"],
        ),
    ],
    "Storage Blob Data Reader": [
        _v(
            "T1530", "Silent Cloud Storage Exfil",
            "Read-only data-plane access — hardest to detect if the storage isn't audited.",
            "StorageBlobLogs | where OperationName == 'GetBlob' and AuthenticationType == 'OAuth' | summarize sum(RequestBodySize) by AccountName, CallerIpAddress",
            "Ensure diagnostic settings send data-plane logs to a workspace.",
            min_scope=SCOPE_RESOURCE,
            tags=["data-plane", "stealth"],
        ),
    ],
    "Storage Account Contributor": [
        _v(
            "T1552.001", "listKeys Bypass of Data-Plane RBAC",
            "Call listKeys to obtain the storage account key — bypasses Storage Blob Data role scoping entirely.",
            "AzureActivity | where OperationNameValue == 'MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS/ACTION'",
            "Set allowSharedKeyAccess=false on the storage account so shared-key auth is blocked even if listKeys succeeds.",
            min_scope=SCOPE_RESOURCE,
            tags=["credential-access", "MicroBurst"],
        ),
    ],
    "Storage Account Key Operator Service Role": [
        _v(
            "T1552.001", "Storage Key Rotation Abuse",
            "listKeys returns current keys; rotate to a state where attacker knows both, defender knows neither.",
            "AzureActivity | where OperationNameValue in ('MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS/ACTION', 'MICROSOFT.STORAGE/STORAGEACCOUNTS/REGENERATEKEY/ACTION')",
            "Prefer Storage Blob Data roles; disable shared-key auth.",
            min_scope=SCOPE_RESOURCE,
            tags=["credential-access"],
        ),
    ],
    "Storage Table Data Contributor": [
        _v(
            "T1530", "Table Storage Exfil / Poisoning",
            "Bulk read of table entities; can poison downstream jobs by writing crafted rows.",
            "StorageTableLogs | where OperationName in ('QueryEntities', 'InsertOrReplaceEntity')",
            "Restrict to per-table data roles where possible.",
            min_scope=SCOPE_RESOURCE,
            tags=["data-plane"],
        ),
    ],
    "Storage Queue Data Contributor": [
        _v(
            "T1530", "Queue Storage Message Tampering",
            "Read and enqueue messages — often carries connection strings, tokens, or triggers processed by function apps.",
            "StorageQueueLogs | where OperationName in ('GetMessages', 'PutMessage')",
            "Restrict producers/consumers to separate identities.",
            min_scope=SCOPE_RESOURCE,
            tags=["data-plane"],
        ),
    ],

    # -------------------- Key Vault --------------------
    "Key Vault Administrator": [
        _v(
            "T1555.006", "Vault Data-Plane Compromise",
            "Read every secret; sign with every key; export keys where allowed. Full compromise of anything the vault protected.",
            "KeyVaultData | where OperationName in ('SecretGet', 'KeySign', 'KeyGet') | summarize count() by CallerIPAddress, ResultSignature",
            "Grant Key Vault Administrator only via PIM; use per-secret roles (Secrets User) for workloads.",
            min_scope=SCOPE_RESOURCE,
            tags=["data-plane", "critical"],
        ),
    ],
    "Key Vault Secrets Officer": [
        _v(
            "T1555.006", "Secret Read + Rotation",
            "Read and rotate all secrets in the vault.",
            "KeyVaultData | where OperationName in ('SecretGet', 'SecretSet', 'SecretDelete')",
            "Scope to per-secret; prefer Secrets User for read-only workloads.",
            min_scope=SCOPE_RESOURCE,
            tags=["credential-access"],
        ),
    ],
    "Key Vault Secrets User": [
        _v(
            "T1555.006", "Secret Read",
            "Read every secret. Common workload role — high blast radius if the workload is compromised.",
            "KeyVaultData | where OperationName == 'SecretGet' | summarize count() by CallerIPAddress",
            "Scope to specific secrets. Alert on SecretGet from unexpected IPs.",
            min_scope=SCOPE_RESOURCE,
            tags=["credential-access"],
        ),
    ],
    "Key Vault Crypto Officer": [
        _v(
            "T1552.004", "Key Export or Signing",
            "Export software-protected keys (HSM-protected can still be used for sign/decrypt); sign as the tenant to forge assertions.",
            "KeyVaultData | where OperationName in ('KeySign', 'KeyExport', 'KeyBackup')",
            "Enforce HSM protection on production keys; alert on KeyBackup / KeyExport calls.",
            min_scope=SCOPE_RESOURCE,
            tags=["credential-access"],
        ),
    ],
    "Key Vault Crypto User": [
        _v(
            "T1552.004", "Sign / Decrypt with Vault Keys",
            "Use keys for sign, verify, decrypt without ability to export them.",
            "KeyVaultData | where OperationName in ('KeySign', 'KeyDecrypt')",
            "Verify signing use-cases align with key purpose; alert on unusual key ID + client pairs.",
            min_scope=SCOPE_RESOURCE,
            tags=["credential-access"],
        ),
    ],
    "Key Vault Contributor": [
        _v(
            "T1098.003", "Legacy Access-Policy Self-Grant",
            "On a vault where enableRbacAuthorization=false, KV Contributor can rewrite accessPolicies to grant themselves data-plane. Not possible on RBAC-mode vaults — but the majority of long-lived vaults still run legacy mode.",
            "AzureActivity | where OperationNameValue == 'MICROSOFT.KEYVAULT/VAULTS/ACCESSPOLICIES/WRITE'",
            "Set enableRbacAuthorization=true on every vault. Then Key Vault Contributor loses the escalation entirely.",
            min_scope=SCOPE_RESOURCE,
            tags=["privilege-escalation", "legacy", "critical"],
        ),
    ],

    # -------------------- Compute --------------------
    "Virtual Machine Contributor": [
        _v(
            "T1651", "SYSTEM Shell via runCommand",
            "Invoke runCommand for a SYSTEM-context shell on the VM. BloodHound-Azure edge: AZExecuteCommand. MicroBurst: Invoke-AzureRmVMRunCommand.",
            "AzureActivity | where OperationNameValue endswith '/RUNCOMMAND/ACTION' | project TimeGenerated, Caller, Resource, ResultType",
            "Do not grant VM Contributor to service principals. If required, alert on every runCommand invocation and require change-ticket correlation.",
            min_scope=SCOPE_RESOURCE,
            tags=["execution", "AZExecuteCommand"],
        ),
        _v(
            "T1078.004", "Managed Identity Token Theft (via VM access)",
            "With code execution on a VM that has a system-assigned or user-assigned MI, request tokens from IMDS (169.254.169.254) for any resource the MI can access.",
            "SigninLogs | where AppDisplayName == 'Azure VM' | where AuthenticationProtocol == 'ClientCredentials' | where IPAddress != <expected>",
            "Restrict MI scope to least privilege. Alert on MI tokens issued to unexpected audiences (aud claim).",
            min_scope=SCOPE_RESOURCE,
            tags=["credential-access", "T1552.005"],
        ),
    ],
    "Virtual Machine Administrator Login": [
        _v(
            "T1078.004", "AAD RDP/SSH as VM Administrator",
            "Sign into the VM interactively using Entra credentials.",
            "SigninLogs | where AppDisplayName == 'Azure Windows VM Sign-In' or AppDisplayName == 'Azure Linux VM Sign-In'",
            "Require MFA on VM sign-in via Conditional Access.",
            min_scope=SCOPE_RESOURCE,
            tags=["initial-access"],
        ),
    ],
    "Virtual Machine User Login": [
        _v(
            "T1078.004", "AAD RDP/SSH as VM User",
            "Sign into the VM interactively as a user account.",
            "SigninLogs | where AppDisplayName == 'Azure Windows VM Sign-In' or AppDisplayName == 'Azure Linux VM Sign-In'",
            "Same as above.",
            min_scope=SCOPE_RESOURCE,
            tags=["initial-access"],
        ),
    ],

    # -------------------- Adjacent services --------------------
    "Automation Contributor": [
        _v(
            "T1651", "Hybrid Runbook Worker RCE",
            "Create a runbook that executes on the on-prem hybrid worker — arbitrary code inside the customer network. MicroBurst: Get-AzureRunAsCertificate.",
            "AzureActivity | where OperationNameValue in ('MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/RUNBOOKS/WRITE', 'MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/JOBS/WRITE')",
            "Scope Automation Contributor tightly; do not co-locate runbook edit rights with hybrid worker groups.",
            min_scope=SCOPE_RESOURCE_GROUP,
            tags=["execution", "MicroBurst"],
        ),
    ],
    "Logic App Contributor": [
        _v(
            "T1136.003", "Workflow Persistence + Connection Abuse",
            "Add an HTTP trigger to a workflow, exfil connection strings, or repurpose managed connections.",
            "AzureActivity | where OperationNameValue == 'MICROSOFT.LOGIC/WORKFLOWS/WRITE'",
            "Track workflow definition hashes; alert on trigger-type additions.",
            min_scope=SCOPE_RESOURCE,
            tags=["persistence"],
        ),
    ],
    "Website Contributor": [
        _v(
            "T1505.003", "Kudu SCM Web Shell",
            "Enable SCM basic auth, deploy via /api/zipdeploy, get a container shell. App settings often carry connection strings, storage keys, DB creds.",
            "AzureActivity | where OperationNameValue in ('MICROSOFT.WEB/SITES/CONFIG/WRITE', 'MICROSOFT.WEB/SITES/PUBLISHXML/ACTION')",
            "Disable SCM basic auth; require Entra sign-in for Kudu; block publishxml.",
            min_scope=SCOPE_RESOURCE,
            tags=["initial-access", "web-shell"],
        ),
    ],
    "Azure Kubernetes Service RBAC Cluster Admin": [
        _v(
            "T1552.007", "AKS Cluster Admin -> Pod Root",
            "kubectl exec into privileged pods, mount host filesystem, read all secrets, escalate to node-level.",
            "AKSAuditLogs | where User has 'clusterAdmin' | where Verb in ('exec', 'attach')",
            "Prefer AKS RBAC Reader/Writer; require Entra-integrated RBAC.",
            min_scope=SCOPE_RESOURCE,
            tags=["execution", "container-escape"],
        ),
    ],
    "Container Registry Contributor": [
        _v(
            "T1554", "Supply-Chain via Malicious Image",
            "Push :latest tag with attacker-controlled image consumed by AKS/App Service on next deploy.",
            "ContainerRegistryLoginEvents | where OperationName == 'push' | where Repository == 'latest' or Repository endswith ':latest'",
            "Enforce image signing (cosign); pin tags to digests in production.",
            min_scope=SCOPE_RESOURCE,
            tags=["supply-chain"],
        ),
    ],
    "DNS Zone Contributor": [
        _v(
            "T1584.002", "DNS Record Hijack",
            "Repoint records for phishing or to acquire wildcard TLS certs.",
            "AzureActivity | where OperationNameValue == 'MICROSOFT.NETWORK/DNSZONES/A/WRITE' or OperationNameValue == 'MICROSOFT.NETWORK/DNSZONES/CNAME/WRITE'",
            "Alert on production zone record changes outside change windows.",
            min_scope=SCOPE_RESOURCE,
            tags=["impact"],
        ),
    ],

    # -------------------- Reader --------------------
    "Reader": [
        _v(
            "T1580", "Cloud Infrastructure Discovery",
            "ARM enumeration to map the environment. Prerequisite for most cloud attacks (AzureHound, ROADtools, MicroBurst recon).",
            "AzureActivity | where ActivityStatusValue == 'Success' | where OperationNameValue endswith '/READ' | summarize count() by Caller | where count_ > 1000",
            "Avoid subscription-scope Reader for service principals; use per-resource-group Reader where possible.",
            min_scope=SCOPE_SUBSCRIPTION,
            tags=["discovery"],
        ),
    ],

    # -------------------- Entra ID --------------------
    "Global Administrator": [
        _v(
            "T1098.003", "Full Tenant Compromise",
            "Every Entra role, every Azure subscription (via 'access management for Azure resources' toggle), every M365 workload.",
            "AuditLogs | where OperationName == 'Add member to role' and TargetResources has 'Global Administrator'",
            "Break-glass only. PIM eligible with MFA. Every activation must generate an alert.",
            min_scope=SCOPE_MANAGEMENT_GROUP,
            tags=["critical", "entra"],
        ),
    ],
    "Privileged Role Administrator": [
        _v(
            "T1098.003", "Grant Any Entra Role",
            "Assign Global Administrator to self or a planted principal.",
            "AuditLogs | where OperationName == 'Add member to role'",
            "PIM eligible with MFA + Conditional Access + approval workflow.",
            min_scope=SCOPE_MANAGEMENT_GROUP,
            tags=["privilege-escalation", "entra"],
        ),
    ],
    "Application Administrator": [
        _v(
            "T1098.001", "Add Credential to Existing App",
            "Add a client secret or certificate to any non-privileged app registration; impersonate that SP.",
            "AuditLogs | where OperationName in ('Update application - Certificates and secrets management', 'Add service principal credentials')",
            "Alert on credential additions to any app with Azure RBAC role assignments. Prefer Cloud Application Administrator (cannot manage app credentials of privileged apps).",
            min_scope=SCOPE_MANAGEMENT_GROUP,
            tags=["persistence", "entra", "AZAddSecret"],
        ),
    ],
    "Cloud Application Administrator": [
        _v(
            "T1098.001", "Add Credential to Non-Privileged App",
            "Scoped version of Application Administrator — can still manage credentials on non-privileged apps.",
            "AuditLogs | where OperationName == 'Update application - Certificates and secrets management'",
            "Same as Application Administrator; audit consented apps monthly.",
            min_scope=SCOPE_MANAGEMENT_GROUP,
            tags=["persistence", "entra"],
        ),
    ],
    "Directory Readers": [
        _v(
            "T1580", "Directory Recon (Users, Groups, Apps)",
            "Bulk read of users/groups/apps for target selection. AzureHound and ROADtools both use this baseline.",
            "MicrosoftGraphActivityLogs | where RequestUri contains '/users' or contains '/servicePrincipals' | summarize count() by AppId | where count_ > 1000",
            "Grant only to service accounts that provably need it; alert on bulk read.",
            min_scope=SCOPE_MANAGEMENT_GROUP,
            tags=["discovery", "entra"],
        ),
    ],
    "Hybrid Identity Administrator": [
        _v(
            "T1556.007", "Hybrid Trust Manipulation",
            "Configure Entra Connect / cloud sync / cross-tenant sync — Dirk-jan Mollema's documented lateral pivots.",
            "AuditLogs | where OperationName in ('Set federation settings on domain', 'Set domain authentication', 'Set Company Information') or OperationName has 'crossTenantAccessPolicy'",
            "Break-glass only. Monitor federation setting changes.",
            min_scope=SCOPE_MANAGEMENT_GROUP,
            tags=["persistence", "entra", "hybrid"],
        ),
    ],
    "Password Administrator": [
        _v(
            "T1098.003", "Reset Passwords of Lower-Tier Admins",
            "Socchi's Entra privesc matrix: Password Administrator can reset non-admin and Password Admin passwords — chain via helpdesk-style social eng.",
            "AuditLogs | where OperationName == 'Reset user password'",
            "Restrict to helpdesk teams; enforce MFA and just-in-time.",
            min_scope=SCOPE_MANAGEMENT_GROUP,
            tags=["credential-access", "entra", "socchi"],
        ),
    ],
    "Authentication Administrator": [
        _v(
            "T1556", "MFA Method Manipulation",
            "Register or remove MFA methods on non-admin users; open the door to password-only sign-in.",
            "AuditLogs | where OperationName in ('User registered security info', 'Admin registered security info', 'Delete authentication method')",
            "Prefer Privileged Authentication Administrator patterns for admin tiers; monitor MFA method changes.",
            min_scope=SCOPE_MANAGEMENT_GROUP,
            tags=["defense-evasion", "entra"],
        ),
    ],
    "Privileged Authentication Administrator": [
        _v(
            "T1556", "MFA Manipulation on Admins",
            "Includes ability to modify MFA methods for Global Administrators — Socchi escalation path when combined with password reset.",
            "AuditLogs | where OperationName has 'authentication method' | where TargetResources has 'Global Administrator'",
            "Break-glass only, PIM eligible.",
            min_scope=SCOPE_MANAGEMENT_GROUP,
            tags=["privilege-escalation", "entra", "socchi"],
        ),
    ],
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def map_role_to_attacks(
    role_name: Optional[str],
    scope: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Return the attack vectors enabled by a single role at a given scope.

    Args:
        role_name: Azure or Entra role display name (must match the ROLE_ATTACK_MAP key).
        scope: Optional ARM scope string. Attacks whose min_scope tier is not
            met by this scope are filtered out — e.g. UAA at resource scope
            cannot escalate the peer subscription.
    """
    if not role_name:
        return []

    attacks = ROLE_ATTACK_MAP.get(role_name, [])
    if not attacks:
        return []

    scope_tier = _classify_scope(scope)
    return [
        {**attack, "scope_tier": scope_tier}
        for attack in attacks
        if _scope_meets_minimum(scope_tier, attack["min_scope"])
    ]


def map_identity_to_attack_vectors(
    principal_id: str,
    role_assignments: Iterable[Dict[str, Any]],
    principal_type: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Aggregate every attack vector available to a single identity across every
    role it holds.

    Args:
        principal_id: The identity's object ID.
        role_assignments: iterable of dicts with at least `role_name` and `scope`.
        principal_type: Canonical form. Adds SP-specific persistence vector.
    """
    all_vectors: List[Dict[str, Any]] = []
    by_role: Dict[str, int] = {}
    seen_techniques: set = set()

    for ra in role_assignments:
        role_name = ra.get("role_name")
        scope = ra.get("scope")
        vectors = map_role_to_attacks(role_name, scope)
        for v in vectors:
            annotated = {**v, "granting_role": role_name, "granting_scope": scope}
            all_vectors.append(annotated)
            seen_techniques.add(v["technique_id"])
        if vectors:
            by_role[role_name] = by_role.get(role_name, 0) + len(vectors)

    if normalize(principal_type) == SERVICE_PRINCIPAL:
        all_vectors.append({
            "technique_id": "T1098.001",
            "attack_name": "Application Credential Persistence",
            "primitive": "Add a long-lived clientSecret or federated identity credential to the app registration.",
            "detection_signal": (
                "AuditLogs | where OperationName == 'Update application - Certificates and secrets management' "
                f"| where TargetResources has '{principal_id}'"
            ),
            "remediation": (
                "Rotate all credentials on high-priv service principals every 90 days. "
                "Prefer federated identity credentials with strict subject scoping."
            ),
            "min_scope": SCOPE_RESOURCE,
            "scope_tier": SCOPE_RESOURCE,
            "tags": ["persistence", "entra", "service-principal"],
            "granting_role": None,
            "granting_scope": None,
        })
        seen_techniques.add("T1098.001")

    highest_scope_tier = max(
        (_SCOPE_ORDER.get(v.get("scope_tier", SCOPE_RESOURCE), 1) for v in all_vectors),
        default=1,
    )

    return {
        "principal_id": principal_id,
        "principal_type": normalize(principal_type),
        "attack_vector_count": len(all_vectors),
        "unique_techniques": sorted(seen_techniques),
        "highest_scope_tier": _tier_name_for(highest_scope_tier),
        "by_granting_role": by_role,
        "attack_vectors": all_vectors,
    }


def _tier_name_for(order_value: int) -> str:
    for name, order in _SCOPE_ORDER.items():
        if order == order_value:
            return name
    return SCOPE_RESOURCE


def analyze_attack_vectors(
    subscription_id: str,
    principal_id: str,
) -> Dict[str, Any]:
    """
    Full pipeline: resolve a principal, gather all its Azure RBAC assignments,
    map to attack vectors.
    """
    from tools.intelligence import resolve_principal
    from tools.rbac import list_role_assignments

    principal = resolve_principal(principal_id)
    assignments = list_role_assignments(subscription_id=subscription_id)
    principal_assignments = [
        a for a in assignments["items"] if a.get("principal_id") == principal_id
    ]

    vectors = map_identity_to_attack_vectors(
        principal_id=principal_id,
        role_assignments=principal_assignments,
        principal_type=principal.get("principal_type"),
    )

    return {
        "principal": principal,
        "role_assignments": principal_assignments,
        "analysis": vectors,
    }
