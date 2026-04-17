import requests
from azure_auth import get_graph_token

GRAPH = "https://graph.microsoft.com/v1.0"


def get_entra_roles():
    headers = {
        "Authorization": f"Bearer {get_graph_token()}"
    }

    roles = requests.get(
        f"{GRAPH}/directoryRoles",
        headers=headers
    ).json().get("value", [])

    role_data = []

    for role in roles:
        role_id = role["id"]
        members = requests.get(
            f"{GRAPH}/directoryRoles/{role_id}/members",
            headers=headers
        ).json().get("value", [])

        for m in members:
            role_data.append({
                "role": role.get("displayName"),
                "principal_id": m.get("id"),
                "principal_type": m.get("@odata.type"),
                "name": m.get("displayName")
            })

    return {"entra_roles": role_data}
