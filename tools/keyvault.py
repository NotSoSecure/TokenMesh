"""
Key Vault security checks (control-plane).

Mirrors the pattern in `tools/storage.py`:
  1. list_key_vaults        — inventory
  2. check_keyvault_hardening         — soft-delete, purge protection, network, RBAC-mode
  3. check_keyvault_access_policies   — dangling / over-permissioned access policies
  4. check_keyvault_object_expiration — data-plane: keys/secrets/certs without expiry
"""

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from azure.core.exceptions import HttpResponseError, ResourceNotFoundError
from azure.mgmt.keyvault import KeyVaultManagementClient

from azure_auth import (
    get_credential,
    get_subscription_id,
    resource_group_from_id,
    safe_str,
)
from tools.principal_types import UNKNOWN


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


def _client(subscription_id: Optional[str] = None) -> KeyVaultManagementClient:
    sub_id = get_subscription_id(subscription_id)
    return KeyVaultManagementClient(get_credential(), sub_id)


# ---------------------------------------------------------------------------
# Details extraction
# ---------------------------------------------------------------------------


def _iter_attr(obj, name):
    """
    Safely retrieve an attribute expected to be an iterable list.

    Returns [] if:
      - obj is None
      - the attribute is missing / None
      - the attribute is a bound method (SDK model quirk: field names like
        `keys` on Permissions can collide with inherited dict-style methods,
        so `getattr(perms, "keys")` returns the METHOD reference — trying to
        iterate that raises `'method' object is not iterable` in prod)
      - the attribute isn't iterable for any other reason

    This is defensive: the SDK is *supposed* to return a list here, but real
    tenants occasionally return non-list shapes (paged proxies, None, etc.)
    and one crashed vault should never take down the whole hunt.
    """
    if obj is None:
        return []
    val = getattr(obj, name, None)
    if val is None or callable(val):
        return []
    try:
        return list(val)
    except TypeError:
        return []


def _access_policy_details(policy) -> Dict[str, Any]:
    perms = getattr(policy, "permissions", None)
    return {
        "tenant_id": safe_str(getattr(policy, "tenant_id", None)),
        "object_id": safe_str(getattr(policy, "object_id", None)),
        "application_id": safe_str(getattr(policy, "application_id", None)),
        "permissions_keys": _iter_attr(perms, "keys"),
        "permissions_secrets": _iter_attr(perms, "secrets"),
        "permissions_certificates": _iter_attr(perms, "certificates"),
        "permissions_storage": _iter_attr(perms, "storage"),
    }


def _network_acls(vault) -> Dict[str, Any]:
    acls = getattr(getattr(vault, "properties", None), "network_acls", None)
    if not acls:
        return {
            "default_action": None,
            "bypass": None,
            "ip_rule_count": 0,
            "vnet_rule_count": 0,
        }
    return {
        "default_action": safe_str(getattr(acls, "default_action", None)),
        "bypass": safe_str(getattr(acls, "bypass", None)),
        "ip_rule_count": len(_iter_attr(acls, "ip_rules")),
        "vnet_rule_count": len(_iter_attr(acls, "virtual_network_rules")),
    }


def _vault_details(vault) -> Dict[str, Any]:
    resource_id = getattr(vault, "id", None)
    rg = resource_group_from_id(resource_id)
    props = getattr(vault, "properties", None)

    access_policies = _iter_attr(props, "access_policies")
    pe_connections = _iter_attr(props, "private_endpoint_connections")

    return {
        "name": safe_str(getattr(vault, "name", None)),
        "resource_group": rg,
        "location": safe_str(getattr(vault, "location", None)),
        "tenant_id": safe_str(getattr(props, "tenant_id", None)),
        "sku": safe_str(getattr(getattr(props, "sku", None), "name", None)),
        "enable_soft_delete": getattr(props, "enable_soft_delete", None),
        "soft_delete_retention_in_days": getattr(props, "soft_delete_retention_in_days", None),
        "enable_purge_protection": getattr(props, "enable_purge_protection", None),
        "enable_rbac_authorization": getattr(props, "enable_rbac_authorization", None),
        "public_network_access": safe_str(getattr(props, "public_network_access", None)),
        "network_acls": _network_acls(vault),
        "private_endpoint_count": len(pe_connections),
        "access_policy_count": len(access_policies),
        "access_policies": [_access_policy_details(p) for p in access_policies],
        "resource_id": resource_id,
    }


# ---------------------------------------------------------------------------
# Public tools
# ---------------------------------------------------------------------------


def list_key_vaults(subscription_id: Optional[str] = None) -> Dict[str, Any]:
    """List every Key Vault in the subscription."""
    client = _client(subscription_id)
    items: List[Dict[str, Any]] = []

    for vault in client.vaults.list_by_subscription():
        # `list_by_subscription` returns the Vault resource; hydrate full properties.
        rg = resource_group_from_id(getattr(vault, "id", None))
        full = vault
        if rg:
            try:
                full = client.vaults.get(rg, vault.name)
            except (HttpResponseError, ResourceNotFoundError):
                full = vault
        items.append(_vault_details(full))

    return {"count": len(items), "items": items}


_SOFT_DELETE_ISSUE = "Soft delete is disabled — destructive `purge` covers attacker tracks"
_PURGE_PROTECTION_ISSUE = "Purge protection is not enabled — deleted vault content can be permanently wiped"
_LEGACY_ACCESS_POLICY_ISSUE = (
    "enableRbacAuthorization is false — this vault is in legacy access-policy mode. "
    "Any principal with Key Vault Contributor (or Contributor) can rewrite accessPolicies to grant itself data-plane access."
)
_PUBLIC_ACCESS_ISSUE = "publicNetworkAccess is Enabled"
_DEFAULT_ALLOW_ISSUE = "networkAcls.defaultAction is Allow — vault is reachable from any network"
_AZURE_SERVICES_BYPASS_ISSUE = (
    "networkAcls.bypass is AzureServices — trusted Azure services can bypass firewall rules; "
    "abused as a data-plane trust bypass"
)
_NO_PRIVATE_ENDPOINT_ISSUE = "No private endpoint connections and publicNetworkAccess is Enabled"


def check_keyvault_hardening(subscription_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Flag Key Vault misconfigurations that enable attacker persistence or exfiltration.
    """
    client = _client(subscription_id)
    items: List[Dict[str, Any]] = []

    for vault in client.vaults.list_by_subscription():
        rg = resource_group_from_id(getattr(vault, "id", None))
        try:
            full = client.vaults.get(rg, vault.name) if rg else vault
        except (HttpResponseError, ResourceNotFoundError):
            full = vault

        details = _vault_details(full)
        issues: List[Dict[str, Any]] = []

        if details["enable_soft_delete"] is False:
            issues.append({
                "issue": _SOFT_DELETE_ISSUE,
                "mitre_technique_id": "T1485",
                "detection_signal": (
                    "AzureActivity | where OperationNameValue == 'MICROSOFT.KEYVAULT/VAULTS/WRITE' "
                    "| where Properties has 'enableSoftDelete' and Properties has 'false'"
                ),
                "remediation": "Enable soft delete via Azure Policy — required by default for new vaults since 2020.",
            })
        if not details["enable_purge_protection"]:
            issues.append({
                "issue": _PURGE_PROTECTION_ISSUE,
                "mitre_technique_id": "T1485",
                "detection_signal": (
                    "AzureActivity | where OperationNameValue == 'MICROSOFT.KEYVAULT/VAULTS/PURGE/ACTION'"
                ),
                "remediation": "Enable purge protection on all production vaults; disallow via Azure Policy on subscriptions.",
            })
        if details["enable_rbac_authorization"] is False:
            issues.append({
                "issue": _LEGACY_ACCESS_POLICY_ISSUE,
                "mitre_technique_id": "T1098.003",
                "detection_signal": (
                    "AzureActivity | where OperationNameValue == 'MICROSOFT.KEYVAULT/VAULTS/ACCESSPOLICIES/WRITE'"
                ),
                "remediation": "Migrate to RBAC mode: set enableRbacAuthorization=true, port accessPolicies to Key Vault Secrets User / Officer role assignments, then delete legacy policies.",
            })
        if str(details["public_network_access"]).lower() == "enabled":
            issues.append({
                "issue": _PUBLIC_ACCESS_ISSUE,
                "mitre_technique_id": "T1530",
                "detection_signal": (
                    "AzureDiagnostics | where ResourceProvider == 'MICROSOFT.KEYVAULT' | where CallerIPAddress !in (allowlist)"
                ),
                "remediation": "Set publicNetworkAccess=Disabled and require private endpoint access.",
            })
        acls = details["network_acls"]
        if acls.get("default_action") and acls["default_action"].lower() == "allow":
            issues.append({
                "issue": _DEFAULT_ALLOW_ISSUE,
                "mitre_technique_id": "T1530",
                "detection_signal": "AzureActivity | where OperationNameValue endswith '/NETWORKACLS/WRITE'",
                "remediation": "Set networkAcls.defaultAction=Deny and add explicit IP/VNet rules.",
            })
        if acls.get("bypass") and "azureservices" in acls["bypass"].lower():
            issues.append({
                "issue": _AZURE_SERVICES_BYPASS_ISSUE,
                "mitre_technique_id": "T1530",
                "detection_signal": "KeyVaultData | where CallerIPAddress == 'AzureServices'",
                "remediation": "Set networkAcls.bypass=None unless a specific trusted Azure service integration requires it — document each exception.",
            })
        if details["private_endpoint_count"] == 0 and str(details["public_network_access"]).lower() == "enabled":
            issues.append({
                "issue": _NO_PRIVATE_ENDPOINT_ISSUE,
                "mitre_technique_id": "T1530",
                "detection_signal": "AzureDiagnostics | where ResourceProvider == 'MICROSOFT.KEYVAULT' and CallerIPAddress != <corp>",
                "remediation": "Attach a private endpoint via a landing-zone module.",
            })

        details["issues"] = issues
        details["issue_count"] = len(issues)
        items.append(details)

    high_risk = [v for v in items if v["issue_count"] > 0]
    return {
        "count": len(items),
        "high_risk_count": len(high_risk),
        "items": items,
    }


_BROAD_KEY_PERMS = {"all", "purge", "recover", "restore", "import"}
_BROAD_SECRET_PERMS = {"all", "purge", "recover", "restore"}
_BROAD_CERT_PERMS = {"all", "purge", "recover", "restore", "manageissuers", "setissuers"}


def _broad_perms(perms: List[str], broad: set) -> List[str]:
    return [p for p in perms if p.lower() in broad]


def check_keyvault_access_policies(subscription_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Iterate every Key Vault's legacy accessPolicies list. Flag:
      - Dangling objectIds that no longer resolve in Graph (deleted-principal persistence).
      - Overly broad permissions (all / purge / import).
      - Cross-tenant objectIds (tenantId != vault.tenant_id).
    """
    from tools.intelligence import resolve_principal  # avoid circular import at module load

    client = _client(subscription_id)
    findings: List[Dict[str, Any]] = []

    for vault in client.vaults.list_by_subscription():
        rg = resource_group_from_id(getattr(vault, "id", None))
        try:
            full = client.vaults.get(rg, vault.name) if rg else vault
        except (HttpResponseError, ResourceNotFoundError):
            full = vault

        details = _vault_details(full)
        vault_tenant = details["tenant_id"]

        for policy in details["access_policies"]:
            object_id = policy["object_id"]
            if not object_id:
                continue

            resolved = resolve_principal(object_id)
            resolved_type = resolved["principal_type"]
            resolved_name = resolved.get("name") or "Unknown"

            evidence = {
                "vault": details["name"],
                "resource_id": details["resource_id"],
                "object_id": object_id,
                "resolved_type": resolved_type,
                "resolved_name": resolved_name,
                "policy_tenant_id": policy["tenant_id"],
                "vault_tenant_id": vault_tenant,
                "permissions_keys": policy["permissions_keys"],
                "permissions_secrets": policy["permissions_secrets"],
                "permissions_certificates": policy["permissions_certificates"],
            }

            if resolved_type == UNKNOWN:
                findings.append({
                    "detector": "dangling_keyvault_access_policy",
                    "principal_id": object_id,
                    "principal_type": UNKNOWN,
                    "display_name": resolved_name,
                    "scope": details["resource_id"],
                    "risk": "High",
                    "mitre_technique_id": "T1078.004",
                    "attack_name": "Dangling Key Vault Access Policy (Deleted-Principal Replay)",
                    "detection_signal": (
                        "AzureActivity | where OperationNameValue == 'MICROSOFT.KEYVAULT/VAULTS/ACCESSPOLICIES/WRITE' "
                        f"| where Properties has '{object_id}'"
                    ),
                    "remediation": (
                        "Remove the access policy for objectId that no longer resolves in Microsoft Graph. "
                        "If provenance is unknown, treat as planted persistence."
                    ),
                    "evidence": evidence,
                })
                continue

            broad_keys = _broad_perms(policy["permissions_keys"], _BROAD_KEY_PERMS)
            broad_secrets = _broad_perms(policy["permissions_secrets"], _BROAD_SECRET_PERMS)
            broad_certs = _broad_perms(policy["permissions_certificates"], _BROAD_CERT_PERMS)

            if broad_keys or broad_secrets or broad_certs:
                findings.append({
                    "detector": "overly_broad_keyvault_access_policy",
                    "principal_id": object_id,
                    "principal_type": resolved_type,
                    "display_name": resolved_name,
                    "scope": details["resource_id"],
                    "risk": "High",
                    "mitre_technique_id": "T1555.006",
                    "attack_name": "Overly Broad Key Vault Access Policy",
                    "detection_signal": (
                        "KeyVaultData | where OperationName in ('KeyBackup','KeyExport','SecretPurge','KeyPurge')"
                    ),
                    "remediation": (
                        "Reduce policy permissions to least privilege. Prefer RBAC mode with Secrets User / Crypto User."
                    ),
                    "evidence": {
                        **evidence,
                        "broad_key_permissions": broad_keys,
                        "broad_secret_permissions": broad_secrets,
                        "broad_certificate_permissions": broad_certs,
                    },
                })

            if vault_tenant and policy["tenant_id"] and policy["tenant_id"] != vault_tenant:
                findings.append({
                    "detector": "cross_tenant_keyvault_access_policy",
                    "principal_id": object_id,
                    "principal_type": resolved_type,
                    "display_name": resolved_name,
                    "scope": details["resource_id"],
                    "risk": "High",
                    "mitre_technique_id": "T1078.004",
                    "attack_name": "Cross-Tenant Key Vault Access Policy",
                    "detection_signal": (
                        "KeyVaultData | where CallerIPAddress != <corp> and identity != <expected tenant>"
                    ),
                    "remediation": (
                        "Remove access policies for principals in foreign tenants unless a documented partner integration requires it."
                    ),
                    "evidence": evidence,
                })

    return {"total_findings": len(findings), "findings": findings}


def check_keyvault_object_expiration(
    subscription_id: Optional[str] = None,
    max_lifetime_days: int = 730,
) -> Dict[str, Any]:
    """
    Flag keys, secrets, and certificates with:
      - no expiry (attributes.expires is null)
      - expiry more than `max_lifetime_days` in the future (default 2 years)

    This uses the data-plane clients (azure-keyvault-*) which require
    Key Vault Secrets Officer / Reader role on the caller.
    """
    from azure.keyvault.certificates import CertificateClient
    from azure.keyvault.keys import KeyClient
    from azure.keyvault.secrets import SecretClient

    client = _client(subscription_id)
    credential = get_credential()

    now = datetime.now(timezone.utc)
    max_future = now + timedelta(days=max_lifetime_days)

    findings: List[Dict[str, Any]] = []

    for vault in client.vaults.list_by_subscription():
        vault_uri = f"https://{vault.name}.vault.azure.net"
        vault_id = getattr(vault, "id", None)

        for label, client_cls, iterator in (
            ("secret", SecretClient, "list_properties_of_secrets"),
            ("key", KeyClient, "list_properties_of_keys"),
            ("certificate", CertificateClient, "list_properties_of_certificates"),
        ):
            try:
                dc = client_cls(vault_url=vault_uri, credential=credential)
                for prop in getattr(dc, iterator)():
                    expires = getattr(prop, "expires_on", None)
                    name = getattr(prop, "name", None)

                    if expires is None:
                        findings.append({
                            "detector": "keyvault_object_no_expiry",
                            "vault": vault.name,
                            "vault_id": vault_id,
                            "object_type": label,
                            "object_name": name,
                            "expires_on": None,
                            "risk": "Medium",
                            "mitre_technique_id": "T1098.001",
                            "attack_name": f"{label.capitalize()} without expiry — long-lived persistence primitive",
                            "detection_signal": (
                                f"KeyVaultData | where OperationName == '{label.capitalize()}Get' "
                                f"and ResourceId has '{vault.name}'"
                            ),
                            "remediation": (
                                f"Set an expiry on this {label} (max 1 year) and rotate on schedule."
                            ),
                        })
                    elif expires > max_future:
                        findings.append({
                            "detector": "keyvault_object_long_lived",
                            "vault": vault.name,
                            "vault_id": vault_id,
                            "object_type": label,
                            "object_name": name,
                            "expires_on": expires.isoformat(),
                            "risk": "Low",
                            "mitre_technique_id": "T1098.001",
                            "attack_name": f"{label.capitalize()} with expiry > {max_lifetime_days} days",
                            "detection_signal": (
                                f"KeyVaultData | where OperationName == '{label.capitalize()}Get' "
                                f"and ResourceId has '{vault.name}'"
                            ),
                            "remediation": f"Rotate this {label} to a shorter lifetime.",
                        })
            except (HttpResponseError, ResourceNotFoundError, PermissionError) as exc:
                findings.append({
                    "detector": "keyvault_object_enumeration_failed",
                    "vault": vault.name,
                    "vault_id": vault_id,
                    "object_type": label,
                    "risk": "Info",
                    "reason": str(exc),
                })

    return {"total_findings": len(findings), "findings": findings}
