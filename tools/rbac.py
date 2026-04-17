from typing import Any, Dict, List, Optional

import requests

from azure_auth import get_management_token, get_subscription_id, subscription_scope, safe_str


API_VERSION = "2022-04-01"


def _mgmt_headers() -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {get_management_token()}",
        "Accept": "application/json",
    }


def _paged_get(url: str) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    next_url: Optional[str] = url

    while next_url:
        response = requests.get(next_url, headers=_mgmt_headers(), timeout=60)
        response.raise_for_status()
        data = response.json()

        page = data.get("value", [])
        if isinstance(page, list):
            items.extend(page)

        next_url = data.get("nextLink") or data.get("@odata.nextLink")

    return items


def _role_definition_map(scope: str) -> Dict[str, str]:
    url = (
        f"https://management.azure.com{scope}"
        f"/providers/Microsoft.Authorization/roleDefinitions?api-version={API_VERSION}"
    )
    role_defs = _paged_get(url)
    mapping: Dict[str, str] = {}

    for rd in role_defs:
        rd_id = safe_str(rd.get("id"))
        role_name = safe_str((rd.get("properties") or {}).get("roleName"))
        if rd_id and role_name:
            mapping[rd_id.lower()] = role_name

    return mapping


def list_role_assignments(
    subscription_id: Optional[str] = None,
    scope: Optional[str] = None,
) -> Dict[str, Any]:
    sub_id = get_subscription_id(subscription_id)
    scope_path = scope or subscription_scope(sub_id)

    assignments_url = (
        f"https://management.azure.com{scope_path}"
        f"/providers/Microsoft.Authorization/roleAssignments?api-version={API_VERSION}"
    )

    assignments = _paged_get(assignments_url)
    role_map = _role_definition_map(scope_path)

    items: List[Dict[str, Any]] = []
    for ra in assignments:
        props = ra.get("properties") or {}
        role_def_id = safe_str(props.get("roleDefinitionId"))
        principal_id = safe_str(props.get("principalId"))
        principal_type = safe_str(props.get("principalType"))
        assignment_scope = safe_str(props.get("scope"))

        role_name = None
        if role_def_id:
            role_name = role_map.get(role_def_id.lower(), role_def_id.rsplit("/", 1)[-1])

        items.append(
            {
                "id": safe_str(ra.get("id")),
                "name": safe_str(ra.get("name")),
                "scope": assignment_scope,
                "principal_id": principal_id,
                "principal_type": principal_type,
                "role_definition_id": role_def_id,
                "role_name": role_name,
            }
        )

    return {
        "count": len(items),
        "items": items,
    }


def summarize_high_privilege_assignments(subscription_id: Optional[str] = None) -> Dict[str, Any]:
    data = list_role_assignments(subscription_id=subscription_id)
    high_priv_roles = {"Owner", "Contributor", "User Access Administrator"}

    findings = [item for item in data["items"] if item.get("role_name") in high_priv_roles]

    by_role: Dict[str, int] = {}
    for item in findings:
        role = item.get("role_name") or "Unknown"
        by_role[role] = by_role.get(role, 0) + 1

    return {
        "total_assignments": data["count"],
        "high_privilege_count": len(findings),
        "by_role": by_role,
        "findings": findings,
    }


def list_subscription_scoped_assignments(subscription_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Alias-style helper for a quick read-only snapshot.
    """
    return list_role_assignments(subscription_id=subscription_id)
