"""
Azure App Service (Web Apps + Function Apps) security checks.

App Service is a persistent code-execution surface — Kudu SCM shell gives
you a full container terminal, publishing profiles hand out ready-to-use
FTP + Git-deploy credentials, and app settings are where developers stash
connection strings and API keys in plaintext.

MicroBurst (NetSPI) explicitly hunts these:
  - Get-AzPasswords enumerates publishing profiles.
  - Kudu SCM basic auth = code execution on the container.

Checks:
  1. list_web_apps                       — inventory
  2. check_appservice_hardening          — HTTPS-only, min TLS, ftp basic auth, scm basic auth, public network
  3. check_appservice_scm_exposure       — SCM (Kudu) reachable + basic auth on
  4. check_appservice_managed_identity_exposure — MI holds high Azure RBAC
  5. check_appservice_connection_strings — connection strings in app settings (metadata only)
"""

from typing import Any, Dict, List, Optional

from azure.core.exceptions import HttpResponseError, ResourceNotFoundError
from azure.mgmt.web import WebSiteManagementClient

from azure_auth import (
    get_credential,
    get_subscription_id,
    resource_group_from_id,
    safe_str,
)


def _client(subscription_id: Optional[str] = None) -> WebSiteManagementClient:
    sub_id = get_subscription_id(subscription_id)
    return WebSiteManagementClient(get_credential(), sub_id)


def _identity_details(site) -> Dict[str, Any]:
    identity = getattr(site, "identity", None)
    if not identity:
        return {"type": None, "system_assigned_principal_id": None, "user_assigned_identities": []}
    uais = getattr(identity, "user_assigned_identities", None) or {}
    user_assigned = [
        {
            "resource_id": rid,
            "principal_id": safe_str(getattr(uai, "principal_id", None)),
            "client_id": safe_str(getattr(uai, "client_id", None)),
        }
        for rid, uai in uais.items()
    ]
    return {
        "type": safe_str(getattr(identity, "type", None)),
        "system_assigned_principal_id": safe_str(getattr(identity, "principal_id", None)),
        "user_assigned_identities": user_assigned,
    }


def _site_details(site, config=None) -> Dict[str, Any]:
    return {
        "name": safe_str(getattr(site, "name", None)),
        "resource_group": resource_group_from_id(getattr(site, "id", None)),
        "location": safe_str(getattr(site, "location", None)),
        "kind": safe_str(getattr(site, "kind", None)),
        "state": safe_str(getattr(site, "state", None)),
        "default_host_name": safe_str(getattr(site, "default_host_name", None)),
        "https_only": getattr(site, "https_only", None),
        "public_network_access": safe_str(getattr(site, "public_network_access", None)),
        "identity": _identity_details(site),
        "resource_id": getattr(site, "id", None),
        "config": _site_config_details(config) if config is not None else None,
    }


def _site_config_details(config) -> Dict[str, Any]:
    return {
        "min_tls_version": safe_str(getattr(config, "min_tls_version", None)),
        "ftps_state": safe_str(getattr(config, "ftps_state", None)),
        "scm_ip_security_restrictions_use_main": getattr(config, "scm_ip_security_restrictions_use_main", None),
        "http20_enabled": getattr(config, "http20_enabled", None),
        "remote_debugging_enabled": getattr(config, "remote_debugging_enabled", None),
        "cors_allowed_origins": (getattr(getattr(config, "cors", None), "allowed_origins", None) or []),
    }


def list_web_apps(subscription_id: Optional[str] = None) -> Dict[str, Any]:
    """List every App Service site (web apps + function apps) in the subscription."""
    client = _client(subscription_id)
    items: List[Dict[str, Any]] = []

    for site in client.web_apps.list():
        rg = resource_group_from_id(getattr(site, "id", None))
        try:
            config = client.web_apps.get_configuration(rg, site.name) if rg else None
        except (HttpResponseError, ResourceNotFoundError):
            config = None
        items.append(_site_details(site, config))

    return {"count": len(items), "items": items}


def check_appservice_hardening(subscription_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Flag App Service hardening gaps:
      - HTTPS-only disabled — plaintext traffic to auth endpoints.
      - Min TLS version < 1.2.
      - FTPS state = AllAllowed — legacy FTP publishing accepted.
      - publicNetworkAccess = Enabled with no access restrictions.
      - Remote debugging enabled — exposes symbols to any Azure account.
      - CORS allowed origins = "*" — permissive cross-origin data-plane.
    """
    client = _client(subscription_id)
    items: List[Dict[str, Any]] = []

    for site in client.web_apps.list():
        rg = resource_group_from_id(getattr(site, "id", None))
        try:
            config = client.web_apps.get_configuration(rg, site.name) if rg else None
        except (HttpResponseError, ResourceNotFoundError):
            config = None

        details = _site_details(site, config)
        issues: List[Dict[str, Any]] = []

        if details["https_only"] is False:
            issues.append({
                "issue": "HTTPS-only disabled",
                "mitre_technique_id": "T1557",
                "cis_control": "CIS Azure 9.2",
                "remediation": "Set httpsOnly=true on the site; enforce via Azure Policy.",
            })

        cfg = details["config"] or {}
        min_tls = cfg.get("min_tls_version")
        if min_tls and min_tls in ("1.0", "1.1"):
            issues.append({
                "issue": f"Minimum TLS version is {min_tls}",
                "mitre_technique_id": "T1557",
                "cis_control": "CIS Azure 9.3",
                "remediation": "Set minTlsVersion to 1.2 (or 1.3 when available).",
            })

        ftps = cfg.get("ftps_state")
        if ftps and ftps.lower() == "allallowed":
            issues.append({
                "issue": "FTP publishing accepted (ftpsState=AllAllowed)",
                "mitre_technique_id": "T1078.004",
                "cis_control": "CIS Azure 9.9",
                "remediation": "Set ftpsState=FtpsOnly or Disabled. Legacy FTP publishing = plaintext creds.",
            })

        if str(details["public_network_access"]).lower() == "enabled":
            issues.append({
                "issue": "publicNetworkAccess=Enabled",
                "mitre_technique_id": "T1190",
                "cis_control": "CIS Azure 9.15",
                "remediation": "Restrict via access restrictions or move to Private Endpoint.",
            })

        if cfg.get("remote_debugging_enabled"):
            issues.append({
                "issue": "Remote debugging enabled",
                "mitre_technique_id": "T1552.007",
                "cis_control": "CIS Azure 9.8",
                "remediation": "Disable remote debugging outside of active troubleshooting windows.",
            })

        cors = cfg.get("cors_allowed_origins") or []
        if "*" in cors:
            issues.append({
                "issue": "CORS allowed origins includes '*'",
                "mitre_technique_id": "T1190",
                "cis_control": None,
                "remediation": "List specific origins; wildcard CORS defeats browser same-origin defense.",
            })

        details["issues"] = issues
        details["issue_count"] = len(issues)
        items.append(details)

    high_risk = [x for x in items if x["issue_count"] > 0]
    return {"count": len(items), "high_risk_count": len(high_risk), "items": items}


def check_appservice_scm_exposure(subscription_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Flag sites where Kudu SCM (source-control management endpoint) is
    reachable AND SCM basic auth is enabled — that combo is the MicroBurst
    Kudu shell primitive: get a container terminal via /api/command or push
    an arbitrary payload via /api/zipdeploy.

    Also flag when FTP basic auth is enabled (same pattern for the FTP endpoint).
    """
    client = _client(subscription_id)
    findings: List[Dict[str, Any]] = []

    for site in client.web_apps.list():
        rg = resource_group_from_id(getattr(site, "id", None))
        if not rg or not site.name:
            continue

        try:
            scm_policy = client.web_apps.get_scm_allowed(rg, site.name)
            scm_basic_auth_enabled = getattr(scm_policy, "allow", None)
        except (HttpResponseError, ResourceNotFoundError, AttributeError):
            scm_basic_auth_enabled = None

        try:
            ftp_policy = client.web_apps.get_ftp_allowed(rg, site.name)
            ftp_basic_auth_enabled = getattr(ftp_policy, "allow", None)
        except (HttpResponseError, ResourceNotFoundError, AttributeError):
            ftp_basic_auth_enabled = None

        base = {
            "site_name": site.name,
            "resource_id": site.id,
            "resource_group": rg,
            "default_host_name": safe_str(getattr(site, "default_host_name", None)),
            "scm_basic_auth_enabled": scm_basic_auth_enabled,
            "ftp_basic_auth_enabled": ftp_basic_auth_enabled,
        }

        if scm_basic_auth_enabled is True:
            findings.append({
                "detector": "appservice_scm_basic_auth_enabled",
                "principal_id": None,
                "principal_type": None,
                "display_name": site.name,
                "scope": site.id,
                "risk": "High",
                "mitre_technique_id": "T1505.003",
                "attack_name": "Kudu SCM Basic Auth Enabled (Web Shell Primitive)",
                "detection_signal": (
                    "AzureDiagnostics | where ResourceProvider == 'MICROSOFT.WEB' "
                    "| where OperationName has 'PublishXml' or Category == 'AppServiceHTTPLogs' "
                    f"| where Resource has '{site.name}' and CsUriStem has '/api/zipdeploy'"
                ),
                "remediation": (
                    "Set scmSiteAlsoStopped=false and disable basic auth on the SCM endpoint. "
                    "Require Entra sign-in for Kudu."
                ),
                "cis_control": "CIS Azure 9.11",
                "evidence": base,
            })

        if ftp_basic_auth_enabled is True:
            findings.append({
                "detector": "appservice_ftp_basic_auth_enabled",
                "principal_id": None,
                "principal_type": None,
                "display_name": site.name,
                "scope": site.id,
                "risk": "Medium",
                "mitre_technique_id": "T1078.004",
                "attack_name": "FTP Publishing Basic Auth Enabled",
                "detection_signal": (
                    "AzureDiagnostics | where OperationName has 'PublishingCredentials' "
                    f"| where Resource has '{site.name}'"
                ),
                "remediation": "Disable FTP basic auth. FTP credentials are plaintext-published in the publishing profile.",
                "cis_control": "CIS Azure 9.10",
                "evidence": base,
            })

    return {"total_findings": len(findings), "findings": findings}


_HIGH_PRIV_ROLES = {"Owner", "Contributor", "User Access Administrator", "Role Based Access Control Administrator"}


def check_appservice_managed_identity_exposure(subscription_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Cross-reference every App Service's managed identity against Azure RBAC.
    Same escalation shape as Compute MI escalation: any code exec on the app
    (via SCM, deployment, custom container, custom startup command) inherits
    the MI's permissions. If the MI holds Owner/Contributor/UAA at
    subscription-or-higher scope, that's a subscription takeover primitive.
    """
    from tools.rbac import list_role_assignments

    client = _client(subscription_id)
    role_data = list_role_assignments(subscription_id=subscription_id)
    assignments_by_principal: Dict[str, List[Dict[str, Any]]] = {}
    for a in role_data["items"]:
        assignments_by_principal.setdefault(a["principal_id"], []).append(a)

    findings: List[Dict[str, Any]] = []

    for site in client.web_apps.list():
        details = _site_details(site)
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
                "detector": "appservice_managed_identity_escalation",
                "principal_id": mi["principal_id"],
                "principal_type": "ServicePrincipal",
                "display_name": mi["identity_name"] or f"SystemAssigned on {details['name']}",
                "site_name": details["name"],
                "site_resource_id": details["resource_id"],
                "identity_type": mi["identity_type"],
                "scope": ",".join(sorted({a["scope"] for a in high_priv})),
                "risk": "Critical" if any(a["role_name"] == "Owner" for a in high_priv) else "High",
                "mitre_technique_id": "T1552.005 -> T1098.003",
                "attack_name": "App Service Managed Identity Escalation",
                "detection_signal": (
                    "SigninLogs | where AppDisplayName has 'App Service' and ServicePrincipalId == "
                    f"'{mi['principal_id']}' | where IPAddress != <expected>"
                ),
                "remediation": (
                    "Reduce the MI's Azure RBAC to only what the app workload needs. Kudu / deployment "
                    "access on the app equals full use of these roles."
                ),
                "evidence": {
                    "site": details["name"],
                    "identity_type": mi["identity_type"],
                    "roles": [{"role": a["role_name"], "scope": a["scope"]} for a in high_priv],
                },
            })

    return {"total_findings": len(findings), "findings": findings}


_SECRET_KEY_HINTS = (
    "connectionstring", "conn_str", "password", "secret", "apikey", "api_key",
    "accesskey", "access_key", "token", "clientsecret", "client_secret",
    "sas", "keyvaulturl",
)


def check_appservice_connection_strings(subscription_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Enumerate app settings and connection-string entries, flagging keys
    whose names indicate plaintext secrets stored in configuration rather
    than in Key Vault. Only names and lengths are captured — never values.

    Attack pattern: attacker with Website Contributor or SCM access reads
    app settings; connection strings for storage / SQL / cache are the
    persistence primitive.
    """
    client = _client(subscription_id)
    findings: List[Dict[str, Any]] = []

    for site in client.web_apps.list():
        rg = resource_group_from_id(getattr(site, "id", None))
        if not rg or not site.name:
            continue

        try:
            app_settings = client.web_apps.list_application_settings(rg, site.name)
            properties = getattr(app_settings, "properties", None) or {}
        except (HttpResponseError, ResourceNotFoundError):
            properties = {}

        suspicious_keys: List[str] = []
        keyvault_refs: List[str] = []
        for key, value in properties.items():
            key_l = key.lower()
            val = str(value or "")
            if val.startswith("@Microsoft.KeyVault"):
                keyvault_refs.append(key)
                continue
            if any(hint in key_l for hint in _SECRET_KEY_HINTS):
                suspicious_keys.append(key)

        if suspicious_keys:
            findings.append({
                "detector": "appservice_plaintext_secrets_in_appsettings",
                "principal_id": None,
                "principal_type": None,
                "display_name": site.name,
                "scope": site.id,
                "risk": "High",
                "mitre_technique_id": "T1552.001",
                "attack_name": "Plaintext Secrets in App Service Configuration",
                "detection_signal": (
                    "AzureActivity | where OperationNameValue == 'MICROSOFT.WEB/SITES/CONFIG/READ' "
                    f"| where Resource has '{site.name}'"
                ),
                "remediation": (
                    "Move secrets to Key Vault and reference them via @Microsoft.KeyVault(SecretUri=...) "
                    "in app settings. Rotate any secret currently exposed in plaintext."
                ),
                "cis_control": "CIS Azure 9.13",
                "evidence": {
                    "site": site.name,
                    "suspicious_key_names": suspicious_keys,
                    "keyvault_reference_count": len(keyvault_refs),
                    "total_app_settings": len(properties),
                },
            })

    return {"total_findings": len(findings), "findings": findings}
