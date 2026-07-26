"""
Canonical Microsoft Azure principal-type vocabulary.

Microsoft uses several different string forms across their APIs to describe
what kind of directory object owns a role assignment. Defenders see all of
them in different places:

  ARM roleAssignments.properties.principalType  -> "User" / "ServicePrincipal" / "Group"
  Microsoft Graph URL path shape                -> "users" / "servicePrincipals" / "groups"
  Microsoft Graph @odata.type                   -> "#microsoft.graph.user" / "#microsoft.graph.servicePrincipal" / "#microsoft.graph.group"
  Azure Portal, `az role assignment list`,
  Microsoft Sentinel KQL                        -> "User" / "ServicePrincipal" / "Group"

The last form is what defenders read in logs and portals every day, so
TokenMesh normalizes everything to that vocabulary at the boundary. Every
finding that flows out of a tool uses these strings and nothing else.
"""

from typing import Optional, Set


USER = "User"
SERVICE_PRINCIPAL = "ServicePrincipal"
GROUP = "Group"
UNKNOWN = "Unknown"

ALL: Set[str] = {USER, SERVICE_PRINCIPAL, GROUP}
ALL_WITH_UNKNOWN: Set[str] = ALL | {UNKNOWN}


_GRAPH_ENDPOINT_MAP = {
    "users": USER,
    "serviceprincipals": SERVICE_PRINCIPAL,
    "groups": GROUP,
}

_ODATA_TYPE_MAP = {
    "#microsoft.graph.user": USER,
    "#microsoft.graph.serviceprincipal": SERVICE_PRINCIPAL,
    "#microsoft.graph.group": GROUP,
}


def normalize_graph_endpoint(value: Optional[str]) -> str:
    """Map a Graph URL endpoint segment (users / servicePrincipals / groups) to canonical form."""
    if not value:
        return UNKNOWN
    return _GRAPH_ENDPOINT_MAP.get(value.strip().lower(), UNKNOWN)


def normalize_odata_type(value: Optional[str]) -> str:
    """Map a Graph @odata.type (#microsoft.graph.servicePrincipal) to canonical form."""
    if not value:
        return UNKNOWN
    return _ODATA_TYPE_MAP.get(value.strip().lower(), UNKNOWN)


def normalize(value: Optional[str]) -> str:
    """Normalize any known dialect to canonical form. Idempotent on canonical input."""
    if not value:
        return UNKNOWN
    stripped = value.strip()
    if stripped in ALL_WITH_UNKNOWN:
        return stripped
    lowered = stripped.lower()
    if lowered in _ODATA_TYPE_MAP:
        return _ODATA_TYPE_MAP[lowered]
    if lowered in _GRAPH_ENDPOINT_MAP:
        return _GRAPH_ENDPOINT_MAP[lowered]
    # ARM sometimes reports "Foreign Group" or "Everyone" — surface as Unknown rather than pretend.
    return UNKNOWN


def is_valid(value: Optional[str]) -> bool:
    """Membership check against the canonical set (excluding Unknown)."""
    return value in ALL


def matches(finding_type: Optional[str], filter_type: Optional[str]) -> bool:
    """
    Filter comparison used by every identity-returning tool.

    filter_type is what the defender asked for. None means "no filter, return
    everything". Anything else is compared exactly against the canonical form
    (after normalization) of the finding.
    """
    if filter_type is None:
        return True
    return normalize(finding_type) == normalize(filter_type)


def validate_filter(filter_type: Optional[str]) -> Optional[str]:
    """
    Coerce a filter argument to canonical form or raise ValueError.

    Called at the tool-boundary to reject typos like "serviceprincipal" or
    "user " with a message that names the accepted values.
    """
    if filter_type is None:
        return None
    normalized = normalize(filter_type)
    if normalized not in ALL:
        raise ValueError(
            f"Unknown principal_type '{filter_type}'. "
            f"Use one of: {sorted(ALL)} (Microsoft canonical ARM values, PascalCase singular)."
        )
    return normalized
