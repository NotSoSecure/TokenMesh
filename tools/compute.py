"""
Compute (VM, VMSS, Azure Arc) security checks.

The MVP attack-vector detector here is `check_compute_managed_identity_exposure`:
for every VM, resolve the system-assigned and user-assigned managed identities
back to their Azure RBAC assignments. If a VM's MI holds Owner/Contributor/UAA
at subscription-or-higher scope, that VM is one code-execution primitive away
(runCommand, IMDS, extensions) from tenant-wide compromise. This is the
"managed identity escalation" attack path defenders keep asking about.
"""

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import requests
from azure.core.exceptions import HttpResponseError, ResourceNotFoundError
from azure.mgmt.compute import ComputeManagementClient

from azure_auth import (
    get_credential,
    get_management_token,
    get_subscription_id,
    resource_group_from_id,
    safe_str,
)


# ---------------------------------------------------------------------------
# Clients
# ---------------------------------------------------------------------------


def _compute_client(subscription_id: Optional[str] = None) -> ComputeManagementClient:
    sub_id = get_subscription_id(subscription_id)
    return ComputeManagementClient(get_credential(), sub_id)


def _mgmt_headers() -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {get_management_token()}",
        "Accept": "application/json",
    }


# ---------------------------------------------------------------------------
# VM details
# ---------------------------------------------------------------------------


def _identity_details(vm) -> Dict[str, Any]:
    identity = getattr(vm, "identity", None)
    if not identity:
        return {
            "type": None,
            "system_assigned_principal_id": None,
            "user_assigned_identities": [],
        }

    uais = getattr(identity, "user_assigned_identities", None) or {}
    user_assigned = [
        {
            "resource_id": resource_id,
            "principal_id": safe_str(getattr(uai, "principal_id", None)),
            "client_id": safe_str(getattr(uai, "client_id", None)),
        }
        for resource_id, uai in uais.items()
    ]

    return {
        "type": safe_str(getattr(identity, "type", None)),
        "system_assigned_principal_id": safe_str(getattr(identity, "principal_id", None)),
        "user_assigned_identities": user_assigned,
    }


def _security_details(vm) -> Dict[str, Any]:
    sp = getattr(vm, "security_profile", None)
    if not sp:
        return {"encryption_at_host": None, "security_type": None}
    return {
        "encryption_at_host": getattr(sp, "encryption_at_host", None),
        "security_type": safe_str(getattr(sp, "security_type", None)),
    }


def _os_disk_details(vm) -> Dict[str, Any]:
    profile = getattr(vm, "storage_profile", None)
    if not profile:
        return {"os_disk": None}
    os_disk = getattr(profile, "os_disk", None)
    if not os_disk:
        return {"os_disk": None}
    managed = getattr(os_disk, "managed_disk", None)
    unmanaged_vhd = getattr(os_disk, "vhd", None)
    return {
        "os_disk": {
            "name": safe_str(getattr(os_disk, "name", None)),
            "os_type": safe_str(getattr(os_disk, "os_type", None)),
            "is_managed": managed is not None,
            "managed_disk_id": safe_str(getattr(managed, "id", None)) if managed else None,
            "storage_account_type": safe_str(getattr(managed, "storage_account_type", None)) if managed else None,
            "unmanaged_vhd_uri": safe_str(getattr(unmanaged_vhd, "uri", None)) if unmanaged_vhd else None,
            "encryption_set_id": safe_str(getattr(getattr(managed, "disk_encryption_set", None), "id", None)) if managed else None,
        }
    }


def _boot_diagnostics(vm) -> Dict[str, Any]:
    dp = getattr(vm, "diagnostics_profile", None)
    if not dp:
        return {"enabled": None, "storage_uri": None}
    bd = getattr(dp, "boot_diagnostics", None)
    if not bd:
        return {"enabled": None, "storage_uri": None}
    return {
        "enabled": getattr(bd, "enabled", None),
        "storage_uri": safe_str(getattr(bd, "storage_uri", None)),
    }


def _vm_details(vm) -> Dict[str, Any]:
    resource_id = getattr(vm, "id", None)
    rg = resource_group_from_id(resource_id)

    return {
        "name": safe_str(getattr(vm, "name", None)),
        "resource_group": rg,
        "location": safe_str(getattr(vm, "location", None)),
        "vm_size": safe_str(getattr(getattr(vm, "hardware_profile", None), "vm_size", None)),
        "identity": _identity_details(vm),
        "security": _security_details(vm),
        **_os_disk_details(vm),
        "boot_diagnostics": _boot_diagnostics(vm),
        "resource_id": resource_id,
    }


# ---------------------------------------------------------------------------
# Public tools
# ---------------------------------------------------------------------------


def list_virtual_machines(subscription_id: Optional[str] = None) -> Dict[str, Any]:
    client = _compute_client(subscription_id)
    items: List[Dict[str, Any]] = []

    for vm in client.virtual_machines.list_all():
        items.append(_vm_details(vm))

    return {"count": len(items), "items": items}


_HIGH_PRIV_ROLES = {"Owner", "Contributor", "User Access Administrator", "Role Based Access Control Administrator"}


def check_compute_managed_identity_exposure(subscription_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Cross-reference every VM's managed identity against Azure RBAC.

    An identity attached to a VM is one code-execution away (runCommand,
    IMDS, extension abuse) from full use. When that identity holds
    Owner/Contributor/UAA at subscription-or-higher scope, any code
    execution on the VM is effectively subscription takeover.

    MITRE T1552.005 (Cloud IMDS) chained into T1098.003 (Additional Cloud Roles).
    """
    from tools.rbac import list_role_assignments  # local to avoid circular import at load

    client = _compute_client(subscription_id)
    role_data = list_role_assignments(subscription_id=subscription_id)
    assignments_by_principal: Dict[str, List[Dict[str, Any]]] = {}
    for a in role_data["items"]:
        assignments_by_principal.setdefault(a["principal_id"], []).append(a)

    findings: List[Dict[str, Any]] = []

    for vm in client.virtual_machines.list_all():
        details = _vm_details(vm)
        mi_principal_ids: List[Dict[str, Any]] = []
        sys_pid = details["identity"]["system_assigned_principal_id"]
        if sys_pid:
            mi_principal_ids.append({"principal_id": sys_pid, "identity_type": "SystemAssigned", "identity_name": None})
        for uai in details["identity"]["user_assigned_identities"]:
            if uai["principal_id"]:
                mi_principal_ids.append({
                    "principal_id": uai["principal_id"],
                    "identity_type": "UserAssigned",
                    "identity_name": uai["resource_id"],
                })

        for mi in mi_principal_ids:
            mi_assignments = assignments_by_principal.get(mi["principal_id"], [])
            high_priv = [a for a in mi_assignments if a.get("role_name") in _HIGH_PRIV_ROLES]
            if not high_priv:
                continue

            findings.append({
                "detector": "managed_identity_escalation",
                "principal_id": mi["principal_id"],
                "principal_type": "ServicePrincipal",
                "display_name": mi["identity_name"] or f"SystemAssigned on {details['name']}",
                "vm_name": details["name"],
                "vm_resource_id": details["resource_id"],
                "identity_type": mi["identity_type"],
                "scope": ",".join(sorted({a["scope"] for a in high_priv})),
                "risk": "Critical" if any(a["role_name"] == "Owner" for a in high_priv) else "High",
                "mitre_technique_id": "T1552.005 -> T1098.003",
                "attack_name": "Managed Identity Escalation (IMDS -> Subscription Takeover)",
                "detection_signal": (
                    "SigninLogs | where AppDisplayName == 'Azure VM' and ServicePrincipalId == "
                    f"'{mi['principal_id']}' | where IPAddress != <expected>"
                ),
                "remediation": (
                    "Reduce this managed identity's Azure RBAC scope to only the resources the VM's "
                    "workload needs. Owner/Contributor/UAA on a VM's MI means anyone with code exec on "
                    "the VM (runCommand, IMDS, malicious extension) inherits those permissions."
                ),
                "evidence": {
                    "vm": details["name"],
                    "vm_resource_id": details["resource_id"],
                    "identity_type": mi["identity_type"],
                    "roles": [{"role": a["role_name"], "scope": a["scope"]} for a in high_priv],
                },
            })

    return {"total_findings": len(findings), "findings": findings}


_SUSPICIOUS_EXTENSION_TYPES = {
    "CustomScriptExtension",
    "CustomScript",
    "CustomScriptForLinux",
    "RunCommandLinux",
    "RunCommandWindows",
    "DSC",
    "DSCForLinux",
}


def check_compute_extensions(subscription_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Enumerate VM extensions and flag:
      - CustomScript / RunCommand / DSC extensions (code-execution primitives).
      - fileUris pointing outside the tenant's own storage accounts.

    Attack pattern: attacker with VM Contributor drops CustomScriptExtension
    referencing an attacker blob to persist across reboots. BloodHound-Azure
    edge AZExecuteCommand; MicroBurst Invoke-AzureRmVMRunCommand.
    """
    client = _compute_client(subscription_id)
    findings: List[Dict[str, Any]] = []

    for vm in client.virtual_machines.list_all():
        details = _vm_details(vm)
        rg = details["resource_group"]
        name = details["name"]
        if not rg or not name:
            continue

        try:
            extensions = client.virtual_machine_extensions.list(rg, name)
        except (HttpResponseError, ResourceNotFoundError):
            continue

        ext_list = getattr(extensions, "value", None) or []

        for ext in ext_list:
            ext_type = safe_str(getattr(ext, "type_properties_type", None) or getattr(ext, "virtual_machine_extension_type", None))
            publisher = safe_str(getattr(ext, "publisher", None))
            settings = getattr(ext, "settings", None) or {}
            file_uris: List[str] = []
            if isinstance(settings, dict):
                raw_uris = settings.get("fileUris") or settings.get("fileURIs") or []
                if isinstance(raw_uris, list):
                    file_uris = [str(u) for u in raw_uris]

            is_suspicious_type = ext_type in _SUSPICIOUS_EXTENSION_TYPES
            foreign_uris = [
                u for u in file_uris
                if u and (".blob.core.windows.net" not in u.lower() and "storage.azure.com" not in u.lower())
            ]

            if not (is_suspicious_type or foreign_uris):
                continue

            findings.append({
                "detector": "suspicious_vm_extension",
                "vm_name": name,
                "vm_resource_id": details["resource_id"],
                "extension_name": safe_str(getattr(ext, "name", None)),
                "extension_type": ext_type,
                "publisher": publisher,
                "file_uris": file_uris,
                "foreign_uris": foreign_uris,
                "risk": "Critical" if foreign_uris else "High",
                "mitre_technique_id": "T1651",
                "attack_name": "VM Extension Code Execution / Persistence",
                "detection_signal": (
                    "AzureActivity | where OperationNameValue == "
                    "'MICROSOFT.COMPUTE/VIRTUALMACHINES/EXTENSIONS/WRITE' "
                    f"| where Resource has '{name}'"
                ),
                "remediation": (
                    "Review who created this extension. If fileUris point outside your tenant's storage "
                    "accounts, treat as a persistence artifact. Remove the extension after preserving evidence."
                ),
                "evidence": {
                    "vm_resource_id": details["resource_id"],
                    "settings_summary": {"fileUris": file_uris, "publisher": publisher, "type": ext_type},
                },
            })

    return {"total_findings": len(findings), "findings": findings}


def check_compute_hardening(subscription_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Flag common VM hardening gaps.
    """
    client = _compute_client(subscription_id)
    items: List[Dict[str, Any]] = []

    for vm in client.virtual_machines.list_all():
        details = _vm_details(vm)
        issues: List[Dict[str, Any]] = []

        if details["security"]["encryption_at_host"] is False:
            issues.append({
                "issue": "Encryption at host disabled — memory + temp disk not encrypted",
                "mitre_technique_id": "T1552.008",
                "remediation": "Enable encryptionAtHost on VM SKUs that support it; enforce via Azure Policy.",
            })
        if not details["security"]["security_type"]:
            issues.append({
                "issue": "securityType not set (not TrustedLaunch or ConfidentialVM)",
                "mitre_technique_id": "T1542",
                "remediation": "Re-provision with TrustedLaunch for boot integrity + vTPM measurements.",
            })
        os_disk = details["os_disk"] or {}
        if os_disk and os_disk.get("unmanaged_vhd_uri"):
            issues.append({
                "issue": "Unmanaged OS disk (legacy VHD in a storage account)",
                "mitre_technique_id": "T1552.001",
                "remediation": "Convert to managed disks — unmanaged disks share the storage account's key surface.",
            })
        if os_disk and not os_disk.get("encryption_set_id") and os_disk.get("is_managed"):
            issues.append({
                "issue": "Managed OS disk uses platform-managed key (no customer-managed key encryption set)",
                "mitre_technique_id": "T1552.001",
                "remediation": "Attach a customer-managed disk encryption set for defense in depth.",
            })
        bd = details["boot_diagnostics"]
        if bd.get("storage_uri"):
            # Boot-diag storage account is worth flagging separately if it turns out public — done in backdoor.py.
            issues.append({
                "issue": "Boot diagnostics using classic storage URI (not managed)",
                "mitre_technique_id": "T1580",
                "remediation": (
                    "Switch to managed boot diagnostics so screenshots and serial logs are not written "
                    "to a customer-owned storage account whose exposure needs to be reviewed."
                ),
            })

        details["issues"] = issues
        details["issue_count"] = len(issues)
        items.append(details)

    return {"count": len(items), "items": items}


ARC_API_VERSION = "2023-10-03-preview"


def list_arc_machines(
    subscription_id: Optional[str] = None,
    stale_after_days: int = 30,
) -> Dict[str, Any]:
    """
    List Azure Arc-connected machines (`Microsoft.HybridCompute/machines`) and
    flag machines whose last status change is older than `stale_after_days`
    — a signature of attacker-abandoned or stale Arc registrations.
    """
    sub_id = get_subscription_id(subscription_id)
    url = (
        f"https://management.azure.com/subscriptions/{sub_id}"
        f"/providers/Microsoft.HybridCompute/machines?api-version={ARC_API_VERSION}"
    )
    machines: List[Dict[str, Any]] = []
    next_url: Optional[str] = url

    now = datetime.now(timezone.utc)
    threshold = now - timedelta(days=stale_after_days)

    while next_url:
        try:
            response = requests.get(next_url, headers=_mgmt_headers(), timeout=60)
            response.raise_for_status()
        except requests.RequestException as exc:
            return {
                "count": 0,
                "items": [],
                "warning": f"Failed to list Arc machines: {exc}",
            }

        data = response.json()
        for m in data.get("value", []):
            props = m.get("properties") or {}
            last_status_change = props.get("lastStatusChange")
            is_stale = False
            if last_status_change:
                try:
                    lsc = datetime.fromisoformat(last_status_change.replace("Z", "+00:00"))
                    is_stale = lsc < threshold
                except ValueError:
                    is_stale = False

            machines.append({
                "name": m.get("name"),
                "location": m.get("location"),
                "resource_group": resource_group_from_id(m.get("id")),
                "resource_id": m.get("id"),
                "status": props.get("status"),
                "os_name": props.get("osName"),
                "os_version": props.get("osVersion"),
                "vm_id": props.get("vmId"),
                "last_status_change": last_status_change,
                "is_stale": is_stale,
                "agent_version": props.get("agentVersion"),
                "identity_principal_id": (m.get("identity") or {}).get("principalId"),
            })

        next_url = data.get("nextLink")

    stale = [x for x in machines if x["is_stale"]]
    return {
        "count": len(machines),
        "stale_count": len(stale),
        "items": machines,
    }
