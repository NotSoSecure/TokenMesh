from tools.storage import check_storage_public_access
from tools.intelligence import get_high_privileged_identities


def detect_backdoors(subscription_id: str):
    from tools.intelligence import get_high_privileged_identities

    identities = get_high_privileged_identities(subscription_id)

    findings = []

    for i in identities["identities"]:
        if i["type"] == "servicePrincipals" and i["azure_role"] == "Owner":
            findings.append({
                "type": "Service Principal Backdoor",
                "name": i["name"],
                "risk": "Critical",
                "reason": "Service principal with Owner role can persist access"
            })

        if i["name"] == "Unknown":
            findings.append({
                "type": "Unknown Identity",
                "risk": "High",
                "reason": "Unresolved principal ID with privileges"
            })

    return {
        "total_findings": len(findings),
        "findings": findings
    }
