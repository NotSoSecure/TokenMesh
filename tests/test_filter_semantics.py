"""
Regression test for the original bug.

Original defender query — from prompts/backdoor-detection.md — was:
    "every service principal with Owner access"

Old behavior: the tool called `get_high_privileged_identities` with no
principal-type filter, then `resolve_principal` re-derived the type from
the Graph endpoint URL (plural lowercase, e.g. "servicePrincipals"),
which meant:
  1. Output mixed Users, ServicePrincipals, and Groups even though the
     defender asked about SPs specifically.
  2. Comparisons against "servicePrincipals" plural lowercase diverged
     from ARM's "ServicePrincipal" PascalCase.

New behavior: passing `principal_type="ServicePrincipal"` returns
exactly service principals, using Microsoft's canonical vocabulary. This
test locks that in.
"""

import pytest

from tools import intelligence
from tools.principal_types import GROUP, SERVICE_PRINCIPAL, USER


SUB_ID = "11111111-2222-3333-4444-555555555555"


@pytest.fixture
def mixed_high_priv_assignments(patch_role_assignments, patch_entra_roles):
    """Three assignments — one User, one ServicePrincipal, one Group — all Owner."""
    patch_role_assignments([
        {
            "id": "ra-1", "name": "ra-1", "scope": f"/subscriptions/{SUB_ID}",
            "principal_id": "user-1", "principal_type": USER,
            "role_definition_id": "rd-owner", "role_name": "Owner",
        },
        {
            "id": "ra-2", "name": "ra-2", "scope": f"/subscriptions/{SUB_ID}",
            "principal_id": "sp-1", "principal_type": SERVICE_PRINCIPAL,
            "role_definition_id": "rd-owner", "role_name": "Owner",
        },
        {
            "id": "ra-3", "name": "ra-3", "scope": f"/subscriptions/{SUB_ID}",
            "principal_id": "group-1", "principal_type": GROUP,
            "role_definition_id": "rd-contributor", "role_name": "Contributor",
        },
    ])
    patch_entra_roles([])


def test_no_filter_returns_all_types(mixed_high_priv_assignments, patch_resolve_principal):
    patch_resolve_principal({
        "user-1": {"name": "Alice", "principal_type": USER, "upn": "alice@corp.com"},
        "sp-1": {"name": "prod-sp", "principal_type": SERVICE_PRINCIPAL},
        "group-1": {"name": "prod-admins", "principal_type": GROUP},
    })

    result = intelligence.get_high_privileged_identities(SUB_ID)
    types = {i["principal_type"] for i in result["identities"]}

    assert result["count"] == 3
    assert types == {USER, SERVICE_PRINCIPAL, GROUP}
    assert result["principal_type_filter"] is None


def test_service_principal_filter_excludes_users_and_groups(
    mixed_high_priv_assignments, patch_resolve_principal,
):
    """
    THIS IS THE REGRESSION TEST FOR THE ORIGINAL BUG.

    Asking for service principals must return exactly service principals.
    Zero User entries. Zero Group entries.
    """
    patch_resolve_principal({
        "user-1": {"name": "Alice", "principal_type": USER, "upn": "alice@corp.com"},
        "sp-1": {"name": "prod-sp", "principal_type": SERVICE_PRINCIPAL},
        "group-1": {"name": "prod-admins", "principal_type": GROUP},
    })

    result = intelligence.get_high_privileged_identities(
        SUB_ID, principal_type="ServicePrincipal",
    )

    assert result["principal_type_filter"] == SERVICE_PRINCIPAL
    assert result["count"] == 1
    assert result["identities"][0]["principal_type"] == SERVICE_PRINCIPAL
    assert result["identities"][0]["name"] == "prod-sp"

    # Explicit anti-assertions — the bug behavior would fail here.
    for identity in result["identities"]:
        assert identity["principal_type"] != USER
        assert identity["principal_type"] != GROUP


def test_user_filter_excludes_service_principals(
    mixed_high_priv_assignments, patch_resolve_principal,
):
    patch_resolve_principal({
        "user-1": {"name": "Alice", "principal_type": USER, "upn": "alice@corp.com"},
        "sp-1": {"name": "prod-sp", "principal_type": SERVICE_PRINCIPAL},
        "group-1": {"name": "prod-admins", "principal_type": GROUP},
    })

    result = intelligence.get_high_privileged_identities(
        SUB_ID, principal_type="User",
    )

    assert result["count"] == 1
    assert result["identities"][0]["principal_type"] == USER


def test_lowercase_plural_filter_is_normalized(
    mixed_high_priv_assignments, patch_resolve_principal,
):
    """
    Defender or LLM passes 'servicePrincipals' by accident (Graph URL form).
    The tool should coerce it to canonical form, not return everything.
    """
    patch_resolve_principal({
        "user-1": {"name": "Alice", "principal_type": USER, "upn": "alice@corp.com"},
        "sp-1": {"name": "prod-sp", "principal_type": SERVICE_PRINCIPAL},
        "group-1": {"name": "prod-admins", "principal_type": GROUP},
    })

    result = intelligence.get_high_privileged_identities(
        SUB_ID, principal_type="servicePrincipals",
    )

    assert result["principal_type_filter"] == SERVICE_PRINCIPAL
    assert result["count"] == 1
    assert result["identities"][0]["principal_type"] == SERVICE_PRINCIPAL


def test_invalid_filter_raises(mixed_high_priv_assignments, patch_resolve_principal):
    patch_resolve_principal({})
    with pytest.raises(ValueError, match="Unknown principal_type"):
        intelligence.get_high_privileged_identities(SUB_ID, principal_type="Everyone")


def test_arm_authoritative_type_survives_graph_lookup(
    mixed_high_priv_assignments, patch_resolve_principal,
):
    """
    Belt-and-suspenders: if Graph resolves and-suspenders confirms nothing
    (returns Unknown), the ARM-declared principal_type from the assignment
    is preserved on the finding. Defender sees ServicePrincipal even for
    a deleted SP because ARM said so.
    """
    # No Graph resolution for sp-1 — but ARM claimed ServicePrincipal.
    patch_resolve_principal({})
    result = intelligence.get_high_privileged_identities(SUB_ID)
    sp_finding = next(i for i in result["identities"] if i["principal_id"] == "sp-1")
    assert sp_finding["principal_type"] == SERVICE_PRINCIPAL
    assert sp_finding["evidence"]["arm_reported_principal_type"] == SERVICE_PRINCIPAL
