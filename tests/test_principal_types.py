"""
Terminology normalizer tests.

Bug the whole refactor was seeded from: `type = ep.split("/")[1]` in the old
intelligence.py returned "servicePrincipals" / "users" / "groups" (Graph URL
plural), while ARM roleAssignments returned "ServicePrincipal" / "User" /
"Group" (PascalCase singular). Downstream code compared against the plural
form; ARM data disagreed; defenders saw wrong types in output.

These tests lock the canonical vocabulary down: PascalCase singular
everywhere, with normalizers at every boundary.
"""

import pytest

from tools.principal_types import (
    ALL,
    GROUP,
    SERVICE_PRINCIPAL,
    UNKNOWN,
    USER,
    is_valid,
    matches,
    normalize,
    normalize_graph_endpoint,
    normalize_odata_type,
    validate_filter,
)


class TestNormalizeGraphEndpoint:
    @pytest.mark.parametrize("value,expected", [
        ("users", USER),
        ("servicePrincipals", SERVICE_PRINCIPAL),
        ("groups", GROUP),
        # Case tolerance — the endpoint plural comes from URL parsing so
        # case can drift.
        ("Users", USER),
        ("SERVICEPRINCIPALS", SERVICE_PRINCIPAL),
        ("  groups  ", GROUP),
    ])
    def test_valid_endpoints(self, value, expected):
        assert normalize_graph_endpoint(value) == expected

    @pytest.mark.parametrize("value", [None, "", "user", "servicePrincipal", "grp", "foreignGroup"])
    def test_unknown_becomes_unknown(self, value):
        assert normalize_graph_endpoint(value) == UNKNOWN


class TestNormalizeODataType:
    @pytest.mark.parametrize("value,expected", [
        ("#microsoft.graph.user", USER),
        ("#microsoft.graph.servicePrincipal", SERVICE_PRINCIPAL),
        ("#microsoft.graph.group", GROUP),
        # Case tolerance
        ("#Microsoft.Graph.ServicePrincipal", SERVICE_PRINCIPAL),
    ])
    def test_valid_odata_types(self, value, expected):
        assert normalize_odata_type(value) == expected

    @pytest.mark.parametrize("value", [None, "", "user", "#microsoft.graph.device"])
    def test_unknown_becomes_unknown(self, value):
        assert normalize_odata_type(value) == UNKNOWN


class TestNormalize:
    """
    normalize() is the multi-dialect entry point. It has to accept every
    known form and return canonical.
    """

    @pytest.mark.parametrize("value", ["User", "ServicePrincipal", "Group"])
    def test_idempotent_on_canonical(self, value):
        assert normalize(value) == value

    def test_maps_graph_endpoint(self):
        assert normalize("servicePrincipals") == SERVICE_PRINCIPAL

    def test_maps_odata_type(self):
        assert normalize("#microsoft.graph.user") == USER

    @pytest.mark.parametrize("value", [None, "", "Everyone", "ForeignGroup"])
    def test_defaults_to_unknown(self, value):
        assert normalize(value) == UNKNOWN


class TestIsValid:
    def test_canonical_values(self):
        for v in ALL:
            assert is_valid(v)

    def test_unknown_is_not_valid(self):
        assert not is_valid(UNKNOWN)

    def test_lowercase_plural_is_not_valid(self):
        assert not is_valid("servicePrincipals")
        assert not is_valid("users")


class TestMatches:
    def test_none_filter_matches_everything(self):
        assert matches(USER, None)
        assert matches(SERVICE_PRINCIPAL, None)
        assert matches(UNKNOWN, None)

    def test_exact_match(self):
        assert matches(SERVICE_PRINCIPAL, SERVICE_PRINCIPAL)

    def test_non_match(self):
        assert not matches(USER, SERVICE_PRINCIPAL)
        assert not matches(SERVICE_PRINCIPAL, USER)

    def test_filter_dialect_normalized(self):
        # Defender might pass the Graph URL form by accident — matches()
        # should still filter correctly rather than silently returning
        # everything.
        assert matches(SERVICE_PRINCIPAL, "servicePrincipals")
        assert not matches(USER, "servicePrincipals")


class TestValidateFilter:
    def test_none_passes_through(self):
        assert validate_filter(None) is None

    def test_canonical_passes(self):
        assert validate_filter("ServicePrincipal") == SERVICE_PRINCIPAL

    def test_plural_normalized_and_accepted(self):
        # We coerce common variants rather than reject — friendlier UX for
        # LLMs that occasionally emit the wrong form.
        assert validate_filter("servicePrincipals") == SERVICE_PRINCIPAL

    def test_garbage_raises(self):
        with pytest.raises(ValueError):
            validate_filter("Everyone")
        with pytest.raises(ValueError):
            validate_filter("admin")
