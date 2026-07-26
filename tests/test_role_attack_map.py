"""
Table integrity tests for the role -> attack vector map.

The map is defender-facing reference data; if fields are missing or the
technique IDs are malformed, downstream code (KQL rendering, PDF report,
LLM output) breaks silently. These tests catch table corruption at commit
time.
"""

import re

import pytest

from tools.attack_vectors import ROLE_ATTACK_MAP


_MITRE_ID = re.compile(r"^T\d{4}(\.\d{3})?(\s*->\s*T\d{4}(\.\d{3})?)?$")

_REQUIRED_KEYS = {
    "technique_id",
    "attack_name",
    "primitive",
    "detection_signal",
    "remediation",
    "min_scope",
    "tags",
}

_VALID_SCOPES = {"management_group", "subscription", "resource_group", "resource"}


class TestRoleAttackMapShape:
    def test_map_is_not_empty(self):
        assert len(ROLE_ATTACK_MAP) >= 30, "Seed set should cover >=30 roles"

    def test_every_entry_is_a_list(self):
        for role, vectors in ROLE_ATTACK_MAP.items():
            assert isinstance(vectors, list), f"{role} must map to a list"
            assert vectors, f"{role} has empty attack list — remove or fill"

    def test_every_vector_has_required_keys(self):
        missing = []
        for role, vectors in ROLE_ATTACK_MAP.items():
            for i, v in enumerate(vectors):
                gap = _REQUIRED_KEYS - set(v.keys())
                if gap:
                    missing.append(f"{role}[{i}] missing: {sorted(gap)}")
        assert not missing, "Missing required keys:\n" + "\n".join(missing)

    def test_every_technique_id_is_mitre_shaped(self):
        bad = []
        for role, vectors in ROLE_ATTACK_MAP.items():
            for v in vectors:
                if not _MITRE_ID.match(v["technique_id"]):
                    bad.append(f"{role} -> {v['attack_name']}: {v['technique_id']}")
        assert not bad, "Bad MITRE IDs:\n" + "\n".join(bad)

    def test_every_min_scope_is_valid(self):
        bad = []
        for role, vectors in ROLE_ATTACK_MAP.items():
            for v in vectors:
                if v["min_scope"] not in _VALID_SCOPES:
                    bad.append(f"{role} -> {v['attack_name']}: {v['min_scope']}")
        assert not bad, "Bad scopes:\n" + "\n".join(bad)


class TestCoverageInvariants:
    """
    These are 'canary' tests — if we ever accidentally drop a role that a
    defender explicitly asked about, the test names in the failure output
    tell you exactly which capability regressed.
    """

    @pytest.mark.parametrize("role", [
        "Owner",
        "Contributor",
        "User Access Administrator",
        "Storage Blob Data Contributor",
        "Storage Account Contributor",
        "Key Vault Administrator",
        "Key Vault Contributor",
        "Virtual Machine Contributor",
        "Automation Contributor",
        "Website Contributor",
        "Reader",
        "Global Administrator",
        "Application Administrator",
        "Password Administrator",
    ])
    def test_role_is_covered(self, role):
        assert role in ROLE_ATTACK_MAP, f"Role dropped from ROLE_ATTACK_MAP: {role}"

    def test_key_vault_contributor_labeled_legacy(self):
        """KV Contributor is only exploitable in legacy access-policy mode."""
        vectors = ROLE_ATTACK_MAP["Key Vault Contributor"]
        assert any("legacy" in v["tags"] for v in vectors)

    def test_vm_contributor_maps_to_runcommand(self):
        """VM Contributor must map to the runCommand SYSTEM shell technique."""
        vectors = ROLE_ATTACK_MAP["Virtual Machine Contributor"]
        assert any(v["technique_id"] == "T1651" for v in vectors)

    def test_reader_maps_to_discovery(self):
        vectors = ROLE_ATTACK_MAP["Reader"]
        assert any(v["technique_id"] == "T1580" for v in vectors)
