"""
Backdoor detector tests, driven by the pentesting scenario fixtures.

Each fixture is a self-contained scenario:
  * describes the technique (with source and MITRE ID)
  * provides the mock data
  * declares the expected finding

The tests wire fixture data through the module's mocking points and assert
the right detector fires with the right MITRE ID and risk.
"""

import pytest

from tools import backdoor, intelligence
from tools.principal_types import SERVICE_PRINCIPAL, USER


SUB_ID = "11111111-2222-3333-4444-555555555555"


def _install_role_assignments(monkeypatch, items):
    def _list_role_assignments(subscription_id=None, scope=None, principal_type=None):
        filtered = items
        if principal_type:
            filtered = [i for i in items if i.get("principal_type") == principal_type]
        return {"count": len(filtered), "principal_type_filter": principal_type, "items": filtered}

    def _summarize(subscription_id=None, principal_type=None):
        high_priv = {"Owner", "Contributor", "User Access Administrator"}
        findings = [i for i in items if i.get("role_name") in high_priv and (
            not principal_type or i.get("principal_type") == principal_type
        )]
        return {
            "total_assignments": len(items),
            "high_privilege_count": len(findings),
            "principal_type_filter": principal_type,
            "by_role": {}, "by_principal_type": {},
            "findings": findings,
        }

    monkeypatch.setattr("tools.rbac.list_role_assignments", _list_role_assignments)
    monkeypatch.setattr("tools.intelligence.summarize_high_privilege_assignments", _summarize)
    # Also patch backdoor's cache's imports.
    monkeypatch.setattr("tools.intelligence.get_entra_roles", lambda: {"entra_roles": []})


class TestOrphanedRoleAssignmentDetector:
    def test_deleted_sp_is_flagged(
        self, monkeypatch, load_fixture, patch_resolve_principal,
    ):
        fx = load_fixture("orphaned_owner_sp.json")
        _install_role_assignments(monkeypatch, fx["role_assignments"])
        patch_resolve_principal(fx["graph_principals"])

        result = backdoor.detect_backdoors(
            SUB_ID, detectors=["orphaned_role_assignment"],
        )

        assert result["by_detector"]["orphaned_role_assignment"] >= 1
        expected = fx["expected_finding"]
        finding = next(
            f for f in result["findings"]
            if f["detector"] == expected["detector"] and f["principal_id"] == expected["principal_id"]
        )
        assert finding["mitre_technique_id"] == expected["mitre_technique_id"]
        assert finding["risk"] == expected["risk"]
        assert finding["principal_type"] == expected["principal_type"]


class TestServicePrincipalWithOwnerDetector:
    def test_sp_with_owner_fires(
        self, monkeypatch, patch_resolve_principal,
    ):
        _install_role_assignments(monkeypatch, [{
            "id": "ra-x", "name": "ra-x", "scope": f"/subscriptions/{SUB_ID}",
            "principal_id": "sp-x", "principal_type": SERVICE_PRINCIPAL,
            "role_definition_id": "rd-owner", "role_name": "Owner",
        }])
        patch_resolve_principal({
            "sp-x": {"name": "backdoor-sp", "principal_type": SERVICE_PRINCIPAL},
        })

        result = backdoor.detect_backdoors(
            SUB_ID, detectors=["service_principal_with_owner"],
        )

        sp_findings = [f for f in result["findings"] if f["detector"] == "service_principal_with_owner"]
        assert len(sp_findings) == 1
        finding = sp_findings[0]
        assert finding["principal_type"] == SERVICE_PRINCIPAL
        assert finding["mitre_technique_id"] == "T1078.004"
        assert finding["risk"] == "Critical"
        assert "MICROSOFT.AUTHORIZATION" in finding["detection_signal"]

    def test_user_with_owner_does_not_fire(self, monkeypatch, patch_resolve_principal):
        _install_role_assignments(monkeypatch, [{
            "id": "ra-y", "name": "ra-y", "scope": f"/subscriptions/{SUB_ID}",
            "principal_id": "user-y", "principal_type": USER,
            "role_definition_id": "rd-owner", "role_name": "Owner",
        }])
        patch_resolve_principal({
            "user-y": {"name": "Alice", "principal_type": USER, "upn": "alice@corp.com"},
        })

        result = backdoor.detect_backdoors(
            SUB_ID, detectors=["service_principal_with_owner"],
        )
        sp_findings = [f for f in result["findings"] if f["detector"] == "service_principal_with_owner"]
        assert sp_findings == []


class TestGuestUserWithAzureRoleDetector:
    def test_guest_with_contributor_fires(
        self, monkeypatch, load_fixture, patch_resolve_principal,
    ):
        fx = load_fixture("guest_user_with_contributor.json")
        _install_role_assignments(monkeypatch, fx["role_assignments"])
        patch_resolve_principal(fx["graph_principals"])

        # The guest_user detector fetches users via the run cache — patch that.
        monkeypatch.setattr(
            "tools.backdoor._RunCache.users",
            lambda self: fx["users"],
        )

        result = backdoor.detect_backdoors(
            SUB_ID, detectors=["guest_user_with_azure_role"],
        )

        expected = fx["expected_finding"]
        guest_findings = [f for f in result["findings"] if f["detector"] == expected["detector"]]
        assert len(guest_findings) == 1
        assert guest_findings[0]["principal_type"] == expected["principal_type"]
        assert guest_findings[0]["mitre_technique_id"] == expected["mitre_technique_id"]


class TestPrincipalTypeFilterPassthrough:
    """
    Filter passes through to backdoor detectors — asking about SPs must not
    return findings on Users.
    """

    def test_service_principal_filter_excludes_user_findings(
        self, monkeypatch, patch_resolve_principal,
    ):
        _install_role_assignments(monkeypatch, [
            {"id": "ra-u", "name": "ra-u", "scope": f"/subscriptions/{SUB_ID}",
             "principal_id": "u-1", "principal_type": USER,
             "role_definition_id": "rd-owner", "role_name": "Owner"},
            {"id": "ra-s", "name": "ra-s", "scope": f"/subscriptions/{SUB_ID}",
             "principal_id": "sp-1", "principal_type": SERVICE_PRINCIPAL,
             "role_definition_id": "rd-owner", "role_name": "Owner"},
        ])
        patch_resolve_principal({
            "u-1": {"name": "Alice", "principal_type": USER, "upn": "a@x.com"},
            "sp-1": {"name": "sp-1", "principal_type": SERVICE_PRINCIPAL},
        })

        result = backdoor.detect_backdoors(
            SUB_ID,
            principal_type="ServicePrincipal",
            detectors=["service_principal_with_owner", "orphaned_role_assignment"],
        )

        # The service_principal_with_owner detector reads from `identities`
        # which was filtered by the principal_type — so no User findings.
        for f in result["findings"]:
            if f.get("principal_type") == USER:
                pytest.fail(f"User finding leaked despite ServicePrincipal filter: {f}")


class TestAvailableDetectorsListed:
    def test_all_detectors_are_listed(self):
        assert "service_principal_with_owner" in backdoor.AVAILABLE_DETECTORS
        assert "orphaned_role_assignment" in backdoor.AVAILABLE_DETECTORS
        assert "long_lived_application_credential" in backdoor.AVAILABLE_DETECTORS
        assert "federated_credential_wildcard_subject" in backdoor.AVAILABLE_DETECTORS
        assert "guest_user_with_azure_role" in backdoor.AVAILABLE_DETECTORS
        assert "cross_tenant_service_principal_with_azure_role" in backdoor.AVAILABLE_DETECTORS
        assert "dangling_keyvault_access_policy" in backdoor.AVAILABLE_DETECTORS
        assert "legacy_keyvault_contributor_escalation" in backdoor.AVAILABLE_DETECTORS
        assert "suspicious_vm_extension" in backdoor.AVAILABLE_DETECTORS
        assert "managed_identity_escalation" in backdoor.AVAILABLE_DETECTORS
        assert "public_boot_diagnostics_storage" in backdoor.AVAILABLE_DETECTORS


class TestFindingShapeConsistency:
    """Every finding must include the defender-facing required fields."""

    _REQUIRED_KEYS = {"detector", "principal_type", "mitre_technique_id", "risk"}
    _DEFENDER_KEYS = {"detection_signal", "remediation"}

    def test_all_findings_have_required_keys(self, monkeypatch, patch_resolve_principal):
        _install_role_assignments(monkeypatch, [
            {"id": "ra-1", "name": "ra-1", "scope": f"/subscriptions/{SUB_ID}",
             "principal_id": "sp-owner", "principal_type": SERVICE_PRINCIPAL,
             "role_definition_id": "rd-owner", "role_name": "Owner"},
        ])
        patch_resolve_principal({"sp-owner": {"name": "backdoor", "principal_type": SERVICE_PRINCIPAL}})

        result = backdoor.detect_backdoors(SUB_ID, detectors=["service_principal_with_owner"])
        for f in result["findings"]:
            missing_required = self._REQUIRED_KEYS - set(f.keys())
            missing_defender = self._DEFENDER_KEYS - set(f.keys())
            assert not missing_required, f"Missing required keys on {f['detector']}: {missing_required}"
            assert not missing_defender, f"Missing defender keys on {f['detector']}: {missing_defender}"
