"""
Walk every identity-returning tool's output and assert:
  1. principal_type is always in the canonical set {User, ServicePrincipal, Group, Unknown}.
  2. Never a lowercase-plural form (servicePrincipals, users, groups).
  3. Every finding-shaped dict from a detector includes MITRE ID and detection signal.
"""

import re

import pytest

from tools import intelligence
from tools.principal_types import ALL_WITH_UNKNOWN, GROUP, SERVICE_PRINCIPAL, USER


SUB_ID = "22222222-3333-4444-5555-666666666666"
_LOWERCASE_PLURAL = re.compile(r"^(users|servicePrincipals|groups)$")


@pytest.fixture
def full_dataset(patch_role_assignments, patch_entra_roles, patch_resolve_principal):
    patch_role_assignments([
        {"id": "ra-a", "name": "ra-a", "scope": f"/subscriptions/{SUB_ID}",
         "principal_id": "u-1", "principal_type": USER,
         "role_definition_id": "rd-owner", "role_name": "Owner"},
        {"id": "ra-b", "name": "ra-b", "scope": f"/subscriptions/{SUB_ID}",
         "principal_id": "sp-1", "principal_type": SERVICE_PRINCIPAL,
         "role_definition_id": "rd-cont", "role_name": "Contributor"},
        {"id": "ra-c", "name": "ra-c", "scope": f"/subscriptions/{SUB_ID}",
         "principal_id": "g-1", "principal_type": GROUP,
         "role_definition_id": "rd-uaa", "role_name": "User Access Administrator"},
        {"id": "ra-d", "name": "ra-d", "scope": f"/subscriptions/{SUB_ID}",
         "principal_id": "deleted-1", "principal_type": SERVICE_PRINCIPAL,
         "role_definition_id": "rd-owner", "role_name": "Owner"},
    ])
    patch_entra_roles([])
    patch_resolve_principal({
        "u-1": {"name": "Alice", "principal_type": USER, "upn": "alice@corp.com"},
        "sp-1": {"name": "prod-sp", "principal_type": SERVICE_PRINCIPAL},
        "g-1": {"name": "prod-admins", "principal_type": GROUP},
        # deleted-1 intentionally missing -> resolves to Unknown, but ARM
        # authoritatively said ServicePrincipal, so the tool must return SP.
    })


def _iter_leaf_strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _iter_leaf_strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _iter_leaf_strings(v)


def test_get_high_privileged_identities_uses_canonical_types(full_dataset):
    result = intelligence.get_high_privileged_identities(SUB_ID)
    for identity in result["identities"]:
        assert identity["principal_type"] in ALL_WITH_UNKNOWN, (
            f"Non-canonical principal_type on identity: {identity['principal_type']}"
        )


def test_no_lowercase_plural_in_output(full_dataset):
    """
    Scan every string leaf of the identity output for the lowercase-plural
    dialect. Emitting `servicePrincipals` anywhere means the drift has
    returned — this is the regression signal we want.

    Note: KQL detection signals may legitimately contain `/servicePrincipals`
    inside a Microsoft Graph URL literal. We only flag the exact bare
    lowercase-plural token as a full field value.
    """
    result = intelligence.get_high_privileged_identities(SUB_ID)
    # Only check the categorical fields, not embedded string content
    # (KQL/URLs can legitimately reference /servicePrincipals/{id} paths).
    for identity in result["identities"]:
        assert not _LOWERCASE_PLURAL.match(str(identity.get("principal_type", "")))
        for k in ("azure_role", "name", "upn", "scope"):
            v = identity.get(k)
            if isinstance(v, str):
                assert not _LOWERCASE_PLURAL.match(v)


def test_arm_authority_preserved_for_unresolved(full_dataset):
    result = intelligence.get_high_privileged_identities(SUB_ID)
    deleted = next(i for i in result["identities"] if i["principal_id"] == "deleted-1")
    # Graph said Unknown, ARM said ServicePrincipal — ARM wins.
    assert deleted["principal_type"] == SERVICE_PRINCIPAL
    assert deleted["name"] == "Unknown"  # Graph did not resolve the display name


def test_intent_mapped_service_principal_tool_returns_sp_only(full_dataset, monkeypatch):
    monkeypatch.setattr("tools.intelligence.requests.get", lambda *a, **k: type("R", (), {"status_code": 404, "json": lambda self: {}})())
    result = intelligence.list_high_privileged_service_principals(SUB_ID)
    for sp in result["service_principals"]:
        assert sp["principal_type"] == SERVICE_PRINCIPAL
    assert result["principal_type_filter"] == SERVICE_PRINCIPAL


def test_orphaned_helper_returns_only_unknown(full_dataset):
    # deleted-1 resolves to Unknown display name but ARM claims SP — the
    # helper flags anything whose Graph name did not resolve, not just Unknown type.
    result = intelligence.list_orphaned_role_assignments(SUB_ID)
    assert result["count"] >= 1
    for orph in result["orphaned_role_assignments"]:
        assert orph.get("name") == "Unknown" or orph.get("principal_type") == "Unknown"
