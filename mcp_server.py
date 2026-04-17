"""
TokenMesh — Cloud Security MCP Agent

Exposes all Azure security analysis tools as MCP (Model Context Protocol)
tools so Claude Desktop (or any MCP client) can call them directly.
"""

import json
from typing import Optional

from mcp.server.fastmcp import FastMCP

from azure_auth import get_subscription_id
from tools.identity import list_users, list_groups, list_service_principals
from tools.rbac import (
    list_role_assignments,
    summarize_high_privilege_assignments,
    list_subscription_scoped_assignments,
)
from tools.storage import (
    list_storage_accounts,
    check_storage_public_access,
    check_storage_hardening,
)
from tools.intelligence import get_high_privileged_identities
from tools.backdoor import detect_backdoors
from tools.report import generate_pdf_report

mcp = FastMCP("TokenMesh")

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _sub_id(subscription_id: Optional[str] = None) -> str:
    """Resolve subscription ID from parameter or environment."""
    return get_subscription_id(subscription_id)


def _json_result(data: dict) -> str:
    """Return a pretty-printed JSON string for MCP text responses."""
    return json.dumps(data, indent=2, default=str)


# Keep track of last result for PDF report generation
_last_result: dict = {}


def _store(result: dict) -> str:
    global _last_result
    _last_result = result
    return _json_result(result)


# ---------------------------------------------------------------------------
# Identity tools
# ---------------------------------------------------------------------------

@mcp.tool()
def mcp_list_users(
    subscription_id: Optional[str] = None,
    top: int = 100,
) -> str:
    """List Microsoft Entra ID users.

    Args:
        subscription_id: Azure subscription ID. Uses AZURE_SUBSCRIPTION_ID env var if omitted.
        top: Number of users to fetch (max 999).
    """
    result = list_users(subscription_id=subscription_id, top=top)
    return _store(result)


@mcp.tool()
def mcp_list_groups(
    subscription_id: Optional[str] = None,
    top: int = 100,
) -> str:
    """List Microsoft Entra ID groups.

    Args:
        subscription_id: Azure subscription ID. Uses AZURE_SUBSCRIPTION_ID env var if omitted.
        top: Number of groups to fetch (max 999).
    """
    result = list_groups(subscription_id=subscription_id, top=top)
    return _store(result)


@mcp.tool()
def mcp_list_service_principals(
    subscription_id: Optional[str] = None,
    top: int = 100,
) -> str:
    """List Microsoft Entra ID service principals (app registrations).

    Args:
        subscription_id: Azure subscription ID. Uses AZURE_SUBSCRIPTION_ID env var if omitted.
        top: Number of service principals to fetch (max 999).
    """
    result = list_service_principals(subscription_id=subscription_id, top=top)
    return _store(result)


# ---------------------------------------------------------------------------
# RBAC tools
# ---------------------------------------------------------------------------

@mcp.tool()
def mcp_list_role_assignments(
    subscription_id: Optional[str] = None,
    scope: Optional[str] = None,
) -> str:
    """List Azure RBAC role assignments at subscription or custom scope.

    Args:
        subscription_id: Azure subscription ID. Uses AZURE_SUBSCRIPTION_ID env var if omitted.
        scope: Optional Azure scope (e.g. /subscriptions/<id> or a resource group path).
    """
    result = list_role_assignments(subscription_id=subscription_id, scope=scope)
    return _store(result)


@mcp.tool()
def mcp_summarize_high_privilege_assignments(
    subscription_id: Optional[str] = None,
) -> str:
    """Summarize high-privilege Azure RBAC roles (Owner, Contributor, User Access Administrator).

    Args:
        subscription_id: Azure subscription ID. Uses AZURE_SUBSCRIPTION_ID env var if omitted.
    """
    result = summarize_high_privilege_assignments(subscription_id=subscription_id)
    return _store(result)


@mcp.tool()
def mcp_list_subscription_scoped_assignments(
    subscription_id: Optional[str] = None,
) -> str:
    """List all RBAC role assignments scoped to the subscription.

    Args:
        subscription_id: Azure subscription ID. Uses AZURE_SUBSCRIPTION_ID env var if omitted.
    """
    result = list_subscription_scoped_assignments(subscription_id=subscription_id)
    return _store(result)


# ---------------------------------------------------------------------------
# Storage tools
# ---------------------------------------------------------------------------

@mcp.tool()
def mcp_list_storage_accounts(
    subscription_id: Optional[str] = None,
) -> str:
    """List all Azure storage accounts in the subscription.

    Args:
        subscription_id: Azure subscription ID. Uses AZURE_SUBSCRIPTION_ID env var if omitted.
    """
    result = list_storage_accounts(subscription_id=subscription_id)
    return _store(result)


@mcp.tool()
def mcp_check_storage_public_access(
    subscription_id: Optional[str] = None,
) -> str:
    """Find storage accounts that allow public blob access (security risk).

    Args:
        subscription_id: Azure subscription ID. Uses AZURE_SUBSCRIPTION_ID env var if omitted.
    """
    result = check_storage_public_access(subscription_id=subscription_id)
    return _store(result)


@mcp.tool()
def mcp_check_storage_hardening(
    subscription_id: Optional[str] = None,
) -> str:
    """Check storage accounts for misconfigurations: public access, weak TLS, HTTP usage.

    Args:
        subscription_id: Azure subscription ID. Uses AZURE_SUBSCRIPTION_ID env var if omitted.
    """
    result = check_storage_hardening(subscription_id=subscription_id)
    return _store(result)


# ---------------------------------------------------------------------------
# Intelligence & Backdoor detection
# ---------------------------------------------------------------------------

@mcp.tool()
def mcp_get_high_privileged_identities(
    subscription_id: Optional[str] = None,
) -> str:
    """Get high-privileged identities with Azure RBAC + Entra roles, risk levels, evidence, and attack paths.

    This is the core intelligence tool that enriches RBAC data with Entra directory
    roles, resolves principal names, and generates attack path analysis.

    Args:
        subscription_id: Azure subscription ID. Uses AZURE_SUBSCRIPTION_ID env var if omitted.
    """
    sub_id = _sub_id(subscription_id)
    result = get_high_privileged_identities(subscription_id=sub_id)
    return _store(result)


@mcp.tool()
def mcp_detect_backdoors(
    subscription_id: Optional[str] = None,
) -> str:
    """Detect potential backdoors: high-privilege service principals, unresolved identities, public storage.

    Args:
        subscription_id: Azure subscription ID. Uses AZURE_SUBSCRIPTION_ID env var if omitted.
    """
    sub_id = _sub_id(subscription_id)
    result = detect_backdoors(subscription_id=sub_id)
    return _store(result)


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

@mcp.tool()
def mcp_generate_pdf_report() -> str:
    """Generate a PDF security report from the most recent analysis results.

    Call one of the analysis tools first (e.g. mcp_get_high_privileged_identities)
    before calling this tool, so there is data to include in the report.
    """
    if not _last_result:
        return json.dumps({"error": "No analysis data available yet. Run an analysis tool first."})

    result = generate_pdf_report(_last_result)
    return _json_result(result)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run()
