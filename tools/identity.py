from typing import Any, Dict, List, Optional

import requests

from azure_auth import get_graph_token, safe_str


GRAPH_BASE = "https://graph.microsoft.com/v1.0"


def _graph_headers() -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {get_graph_token()}",
        "Accept": "application/json",
    }


def _paged_get(url: str) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    next_url: Optional[str] = url

    while next_url:
        response = requests.get(next_url, headers=_graph_headers(), timeout=60)
        response.raise_for_status()
        data = response.json()

        page = data.get("value", [])
        if isinstance(page, list):
            items.extend(page)

        next_url = data.get("@odata.nextLink")

    return items


def list_users(subscription_id: Optional[str] = None, top: int = 100) -> Dict[str, Any]:
    url = (
        f"{GRAPH_BASE}/users?"
        f"$top={int(top)}&"
        f"$select=id,displayName,userPrincipalName,mail,accountEnabled,userType"
    )
    users = _paged_get(url)

    return {
        "count": len(users),
        "items": [
            {
                "id": safe_str(u.get("id")),
                "display_name": safe_str(u.get("displayName")),
                "user_principal_name": safe_str(u.get("userPrincipalName")),
                "mail": safe_str(u.get("mail")),
                "account_enabled": u.get("accountEnabled"),
                "user_type": safe_str(u.get("userType")),
            }
            for u in users
        ],
    }


def list_groups(subscription_id: Optional[str] = None, top: int = 100) -> Dict[str, Any]:
    url = f"{GRAPH_BASE}/groups?$top={int(top)}&$select=id,displayName,mailEnabled,securityEnabled,groupTypes"
    groups = _paged_get(url)

    return {
        "count": len(groups),
        "items": [
            {
                "id": safe_str(g.get("id")),
                "display_name": safe_str(g.get("displayName")),
                "mail_enabled": g.get("mailEnabled"),
                "security_enabled": g.get("securityEnabled"),
                "group_types": g.get("groupTypes", []),
            }
            for g in groups
        ],
    }


def list_service_principals(subscription_id: Optional[str] = None, top: int = 100) -> Dict[str, Any]:
    url = (
        f"{GRAPH_BASE}/servicePrincipals?"
        f"$top={int(top)}&"
        f"$select=id,appId,displayName,accountEnabled,servicePrincipalType"
    )
    sps = _paged_get(url)

    return {
        "count": len(sps),
        "items": [
            {
                "id": safe_str(sp.get("id")),
                "app_id": safe_str(sp.get("appId")),
                "display_name": safe_str(sp.get("displayName")),
                "account_enabled": sp.get("accountEnabled"),
                "service_principal_type": safe_str(sp.get("servicePrincipalType")),
            }
            for sp in sps
        ],
    }
