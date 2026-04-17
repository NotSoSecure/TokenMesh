from typing import Dict, Any, List
import requests

from tools.entra_roles import get_entra_roles
from azure_auth import get_graph_token
from tools.rbac import summarize_high_privilege_assignments


GRAPH_URL = "https://graph.microsoft.com/v1.0"


def _headers():
    return {
        "Authorization": f"Bearer {get_graph_token()}",
        "Content-Type": "application/json"
    }


def resolve_principal(principal_id: str) -> Dict[str, Any]:
    endpoints = [
        f"/users/{principal_id}",
        f"/servicePrincipals/{principal_id}",
        f"/groups/{principal_id}"
    ]

    for ep in endpoints:
        try:
            r = requests.get(GRAPH_URL + ep, headers=_headers(), timeout=20)
            if r.status_code == 200:
                data = r.json()
                return {
                    "id": principal_id,
                    "name": data.get("displayName"),
                    "userPrincipalName": data.get("userPrincipalName"),
                    "type": ep.split("/")[1]
                }
        except:
            continue

    return {"id": principal_id, "name": "Unknown", "type": "Unknown"}


def generate_attack_paths(role: str, principal_type: str) -> List[str]:
    paths = []

    if role == "Owner":
        paths.extend([
            "Full subscription takeover",
            "Create backdoor service principal",
            "Assign Global Admin via Graph abuse",
            "Disable security controls (Defender, logs)"
        ])

    if role == "Contributor":
        paths.extend([
            "Deploy malicious resources",
            "Privilege escalation via managed identity",
            "Lateral movement via resource access"
        ])

    if principal_type == "servicePrincipals":
        paths.append("Persistence via application credentials")

    return paths


def get_high_privileged_identities(subscription_id: str):
    data = summarize_high_privilege_assignments(subscription_id)
    entra_roles = get_entra_roles()["entra_roles"]

    enriched = []

    for item in data["findings"]:
        principal = resolve_principal(item["principal_id"])

        # Match Entra roles
        matched_roles = [
            r["role"] for r in entra_roles
            if r["principal_id"] == item["principal_id"]
        ]

        role = item.get("role_name")

        enriched.append({
            "name": principal.get("name"),
            "upn": principal.get("userPrincipalName"),
            "type": principal.get("type"),
            "azure_role": role,
            "entra_roles": matched_roles,
            "scope": item.get("scope"),
            "risk_level": "Critical" if role == "Owner" else "High",
            "evidence": {
                "role": role,
                "scope": item.get("scope"),
                "principal_type": principal.get("type")
            },
            "attack_paths": generate_attack_paths(role, principal.get("type"))
        })

    return {"identities": enriched}
