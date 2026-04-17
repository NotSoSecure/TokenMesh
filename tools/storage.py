from typing import Any, Dict, List, Optional

from azure.mgmt.storage import StorageManagementClient

from azure_auth import (
    get_credential,
    get_subscription_id,
    resource_group_from_id,
    safe_str,
)


def _client(subscription_id: Optional[str] = None) -> StorageManagementClient:
    sub_id = get_subscription_id(subscription_id)
    return StorageManagementClient(get_credential(), sub_id)


def _storage_account_details(client: StorageManagementClient, account) -> Dict[str, Any]:
    resource_id = getattr(account, "id", None)
    rg_name = resource_group_from_id(resource_id)

    properties = account
    if rg_name:
        try:
            properties = client.storage_accounts.get_properties(rg_name, account.name)
        except Exception:
            properties = account

    sku = getattr(getattr(account, "sku", None), "name", None)
    if sku is None:
        sku = getattr(getattr(properties, "sku", None), "name", None)

    return {
        "name": getattr(account, "name", None),
        "resource_group": rg_name,
        "location": getattr(account, "location", None),
        "kind": getattr(account, "kind", None),
        "sku": sku,
        "https_only": safe_str(getattr(properties, "supports_https_traffic_only", None)),
        "minimum_tls_version": safe_str(getattr(properties, "minimum_tls_version", None)),
        "allow_blob_public_access": safe_str(getattr(properties, "allow_blob_public_access", None)),
        "public_network_access": safe_str(getattr(properties, "public_network_access", None)),
        "default_action": safe_str(
            getattr(getattr(properties, "network_rule_set", None), "default_action", None)
        ),
        "bypass": safe_str(getattr(getattr(properties, "network_rule_set", None), "bypass", None)),
        "is_hns_enabled": safe_str(getattr(properties, "is_hns_enabled", None)),
        "resource_id": resource_id,
    }


def list_storage_accounts(subscription_id: Optional[str] = None) -> Dict[str, Any]:
    client = _client(subscription_id)
    items: List[Dict[str, Any]] = []

    for account in client.storage_accounts.list():
        items.append(_storage_account_details(client, account))

    return {
        "count": len(items),
        "items": items,
    }


def check_storage_public_access(subscription_id: Optional[str] = None) -> Dict[str, Any]:
    client = _client(subscription_id)
    findings: List[Dict[str, Any]] = []

    for account in client.storage_accounts.list():
        details = _storage_account_details(client, account)
        allow_public = details.get("allow_blob_public_access")

        is_risky = str(allow_public).lower() == "true"
        if is_risky:
            details["risk"] = "Blob public access is enabled"
            findings.append(details)

    return {
        "high_risk_count": len(findings),
        "findings": findings,
    }


def check_storage_hardening(subscription_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Read-only summary of common hardening signals.
    """
    client = _client(subscription_id)
    items: List[Dict[str, Any]] = []

    for account in client.storage_accounts.list():
        details = _storage_account_details(client, account)

        issues = []
        if str(details.get("allow_blob_public_access")).lower() == "true":
            issues.append("Blob public access enabled")
        if str(details.get("https_only")).lower() == "false":
            issues.append("HTTPS-only disabled")
        if str(details.get("minimum_tls_version")) in ("TLS1_0", "TLS1_1"):
            issues.append("Weak TLS version")

        details["issues"] = issues
        details["issue_count"] = len(issues)
        items.append(details)

    return {
        "count": len(items),
        "items": items,
    }
