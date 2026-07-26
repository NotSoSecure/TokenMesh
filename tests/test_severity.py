"""
Severity scoring and CIS Benchmark mapping tests.
"""

import pytest

from tools.severity import (
    CIS_MAPPING,
    score_finding,
    score_findings,
    top_findings,
)


class TestScoreFinding:
    def test_critical_scores_higher_than_high(self):
        crit = score_finding({"detector": "d", "risk": "Critical", "scope": "/subscriptions/x"})
        high = score_finding({"detector": "d", "risk": "High", "scope": "/subscriptions/x"})
        assert crit["severity_score"] > high["severity_score"]

    def test_management_group_scope_bonus(self):
        rg = score_finding({
            "detector": "d", "risk": "High",
            "scope": "/subscriptions/x/resourceGroups/rg1",
        })
        mg = score_finding({
            "detector": "d", "risk": "High",
            "scope": "/providers/Microsoft.Management/managementGroups/root",
        })
        assert mg["severity_score"] > rg["severity_score"]

    def test_score_bounded_0_100(self):
        # Pile on every bonus we can — score must still cap at 100.
        f = {
            "detector": "managed_identity_escalation",
            "risk": "Critical",
            "scope": "/providers/Microsoft.Management/managementGroups/root",
            "principal_type": "Unknown",
            "attack_name": "Subscription Takeover via Managed Identity Persistence",
            "mitre_technique_id": "T1098.003",
        }
        result = score_finding(f)
        assert 0 <= result["severity_score"] <= 100

    def test_orphaned_principal_flagged_higher(self):
        base = {"detector": "d", "risk": "High", "scope": "/subscriptions/x"}
        with_unknown = score_finding({**base, "principal_type": "Unknown"})
        without = score_finding({**base, "principal_type": "ServicePrincipal"})
        assert with_unknown["severity_score"] > without["severity_score"]

    def test_confidence_labels(self):
        assert score_finding({"detector": "managed_identity_escalation", "risk": "High"})["confidence"] == "high"
        assert score_finding({"detector": "illicit_oauth_consent_grant", "risk": "High"})["confidence"] == "medium"
        assert score_finding({"detector": "novel-unknown-detector", "risk": "High"})["confidence"] == "low"

    def test_cis_controls_populated(self):
        result = score_finding({"detector": "managed_identity_escalation", "risk": "High"})
        assert result["cis_controls"]
        assert any(c.startswith("CIS Azure") for c in result["cis_controls"])

    def test_scoring_does_not_mutate_input(self):
        f = {"detector": "d", "risk": "High", "scope": "/subscriptions/x"}
        _ = score_finding(f)
        assert "severity_score" not in f
        assert "confidence" not in f
        assert "cis_controls" not in f

    def test_discovery_only_findings_capped(self):
        """Reader-only recon findings should not outscore actual privesc."""
        recon = score_finding({
            "detector": "d", "risk": "Medium", "scope": "/subscriptions/x",
            "mitre_technique_id": "T1580", "attack_name": "Discovery",
        })
        escalation = score_finding({
            "detector": "managed_identity_escalation", "risk": "High",
            "scope": "/subscriptions/x", "mitre_technique_id": "T1098.003",
            "attack_name": "Managed Identity Escalation",
        })
        assert escalation["severity_score"] > recon["severity_score"]


class TestScoreFindings:
    def test_sorted_by_severity_desc(self):
        findings = [
            {"detector": "d", "risk": "Low", "scope": "/subscriptions/x"},
            {"detector": "d", "risk": "Critical", "scope": "/subscriptions/x"},
            {"detector": "d", "risk": "Medium", "scope": "/subscriptions/x"},
        ]
        scored = score_findings(findings)
        assert scored[0]["risk"] == "Critical"
        assert scored[-1]["risk"] == "Low"
        assert all(
            scored[i]["severity_score"] >= scored[i + 1]["severity_score"]
            for i in range(len(scored) - 1)
        )


class TestTopFindings:
    def test_returns_at_most_n(self):
        findings = [{"detector": "d", "risk": "High", "scope": "/subscriptions/x"} for _ in range(20)]
        assert len(top_findings(findings, n=5)) == 5

    def test_returns_all_if_fewer_than_n(self):
        findings = [{"detector": "d", "risk": "High", "scope": "/subscriptions/x"} for _ in range(3)]
        assert len(top_findings(findings, n=10)) == 3


class TestCISMappingCoverage:
    """Every detector that fires should have a CIS mapping (or explicit no-mapping)."""

    _DETECTORS_WITH_EXPECTED_MAPPING = [
        "service_principal_with_owner",
        "orphaned_role_assignment",
        "long_lived_application_secret",
        "guest_user_with_azure_role",
        "managed_identity_escalation",
        "dangling_keyvault_access_policy",
        "legacy_keyvault_contributor_escalation",
        "dangerous_graph_app_role",
        "illicit_oauth_consent_grant",
        "appservice_scm_basic_auth_enabled",
    ]

    @pytest.mark.parametrize("detector", _DETECTORS_WITH_EXPECTED_MAPPING)
    def test_detector_has_cis_mapping(self, detector):
        assert detector in CIS_MAPPING, f"Missing CIS mapping for {detector}"
        assert CIS_MAPPING[detector], f"Empty CIS mapping for {detector}"
