"""
Markdown formatter tests.

These lock the visual vocabulary and dispatch rules — if any of these
break, the in-chat rendering silently regresses.
"""

import pytest

from tools.formatters import (
    attack_path_diagram,
    executive_summary,
    findings_table,
    findings_top_cards,
    format_attack_vector_analysis,
    format_backdoor_result,
    format_identity_result,
    format_top_findings,
    kill_chain_arrow,
    mitre_coverage_grid,
    render,
    severity_histogram,
)


def _finding(**overrides):
    base = {
        "detector": "d",
        "principal_id": "obj-1",
        "principal_type": "ServicePrincipal",
        "display_name": "test-sp",
        "scope": "/subscriptions/xxx",
        "risk": "High",
        "mitre_technique_id": "T1078.004",
        "attack_name": "Test attack",
        "detection_signal": "AzureActivity | where 1==1",
        "remediation": "Rotate credentials.",
        "severity_score": 70,
        "confidence": "high",
        "cis_controls": ["CIS Azure 1.24"],
        "evidence": {"role": "Owner"},
    }
    base.update(overrides)
    return base


class TestSeverityHistogram:
    def test_shows_all_risk_levels_present(self):
        findings = [_finding(risk="Critical"), _finding(risk="High"), _finding(risk="High"), _finding(risk="Low")]
        out = severity_histogram(findings)
        assert "🔴" in out
        assert "🟠" in out
        assert "🟢" in out
        assert "Critical" in out
        assert "**2**" in out  # High count

    def test_empty_findings(self):
        assert severity_histogram([]) == "_No findings_"


class TestMitreCoverageGrid:
    def test_hit_marker_on_covered_techniques(self):
        findings = [_finding(mitre_technique_id="T1078.004")]
        grid = mitre_coverage_grid(findings)
        assert "🎯 `T1078.004`" in grid
        # Uncovered techniques get the dot marker
        assert "· `T1580`" in grid

    def test_multi_step_technique_split(self):
        findings = [_finding(mitre_technique_id="T1552.005 -> T1098.003")]
        grid = mitre_coverage_grid(findings)
        assert "🎯 `T1552.005`" in grid
        assert "🎯 `T1098.003`" in grid


class TestAttackPathDiagram:
    def test_contains_three_boxes(self):
        diagram = attack_path_diagram(_finding(azure_role="Owner"))
        assert diagram.startswith("```")
        assert "IDENTITY" in diagram
        assert "ROLE @ SCOPE" in diagram
        assert "TECHNIQUE" in diagram
        assert "──▶" in diagram
        assert "🟠" in diagram  # risk emoji

    def test_handles_missing_fields(self):
        # Sparse finding — should still render without crashing.
        f = {"principal_id": "x", "risk": "Critical"}
        d = attack_path_diagram(f)
        assert "IDENTITY" in d


class TestKillChainArrow:
    def test_multi_step_chain(self):
        chain = kill_chain_arrow([
            {"technique_id": "T1552.005", "name": "IMDS"},
            {"technique_id": "T1098.003", "name": "RBAC Write"},
        ])
        assert "T1552.005" in chain
        assert "T1098.003" in chain
        assert "─▶" in chain
        assert chain.endswith("🎯")

    def test_empty_chain(self):
        assert "no chain" in kill_chain_arrow([])


class TestExecutiveSummary:
    def test_counts_findings_by_risk(self):
        result = {"findings": [_finding(risk="Critical"), _finding(risk="High")]}
        summary = executive_summary(result, title="🔎 Backdoors")
        assert "**Total findings:** 2" in summary
        assert "🔴 **Critical:** 1" in summary
        assert "🟠 **High:** 1" in summary
        # No double emoji when caller already provides one
        assert "📋 🔎" not in summary


class TestFindingsTable:
    def test_columns_present(self):
        table = findings_table([_finding()])
        assert "| Sev |" in table
        assert "| Score |" in table
        assert "| MITRE |" in table
        assert "🟠" in table
        assert "`T1078.004`" in table

    def test_respects_limit(self):
        findings = [_finding(display_name=f"sp-{i}") for i in range(30)]
        table = findings_table(findings, limit=10)
        assert "sp-0" in table
        assert "sp-9" in table
        assert "sp-10" not in table
        assert "20 more findings" in table


class TestFindingsTopCards:
    def test_renders_top_n_with_attack_path(self):
        findings = [_finding(display_name=f"sp-{i}") for i in range(10)]
        out = findings_top_cards(findings, n=5)
        assert "Top 5 Findings" in out
        assert "#1" in out
        assert "#5" in out
        assert "#6" not in out
        # First three findings get their attack path diagram
        assert out.count("──▶") >= 3


class TestFormatBackdoorResult:
    def test_sections_present(self):
        result = {
            "total_findings": 1,
            "by_detector": {"orphaned_role_assignment": 1},
            "top_severity_score": 82,
            "detector_errors": {},
            "principal_type_filter": None,
            "findings": [_finding(risk="High", detector="orphaned_role_assignment")],
        }
        md = format_backdoor_result(result)
        assert "Executive Summary" in md
        assert "Severity Distribution" in md
        assert "MITRE ATT&CK" in md
        assert "Top" in md and "Findings" in md
        assert "All Findings" in md

    def test_detector_errors_section_appears_when_present(self):
        result = {
            "total_findings": 0, "by_detector": {}, "detector_errors": {"foo": "boom"},
            "findings": [],
        }
        md = format_backdoor_result(result)
        assert "Detector Errors" in md
        assert "`foo`" in md


class TestFormatIdentityResult:
    def test_service_principal_only_output(self):
        result = {
            "count": 1,
            "principal_type_filter": "ServicePrincipal",
            "service_principals": [
                {"principal_id": "sp-1", "name": "prod-sp", "principal_type": "ServicePrincipal",
                 "azure_role": "Owner", "scope": "/subscriptions/xxx", "risk_level": "Critical",
                 "attack_vectors": [{"technique_id": "T1078.004", "attack_name": "backdoor"}]},
            ],
        }
        md = format_identity_result(result)
        assert "**1** ServicePrincipal" in md
        assert "prod-sp" in md
        assert "🔴" in md


class TestFormatAttackVectorAnalysis:
    def test_covers_key_fields(self):
        result = {
            "principal": {"id": "sp-x", "name": "kv-manager-sp"},
            "analysis": {
                "principal_type": "ServicePrincipal",
                "attack_vector_count": 2,
                "unique_techniques": ["T1555.006", "T1098.001"],
                "highest_scope_tier": "subscription",
                "attack_vectors": [
                    {"technique_id": "T1555.006", "attack_name": "Vault Compromise",
                     "granting_role": "Key Vault Administrator", "granting_scope": "/kv/xxx",
                     "primitive": "Read every secret."},
                ],
            },
        }
        md = format_attack_vector_analysis(result)
        assert "T1555.006" in md
        assert "T1098.001" in md
        assert "Key Vault Administrator" in md
        assert "Read every secret." in md


class TestRenderDispatch:
    def test_dispatches_backdoor_shape(self):
        result = {"by_detector": {"x": 1}, "findings": [_finding()], "total_findings": 1}
        md = render(result)
        assert "Executive Summary" in md

    def test_dispatches_identity_shape(self):
        result = {"identities": [{"name": "u1", "principal_type": "User",
                                  "azure_role": "Owner", "risk_level": "Critical"}]}
        md = render(result)
        assert md  # non-empty rendering

    def test_dispatches_attack_analysis(self):
        result = {"principal": {"id": "x"}, "analysis": {"attack_vectors": []}}
        md = render(result)
        assert "Attack Vector Analysis" in md

    def test_dispatches_role_lookup(self):
        result = {"role_name": "Owner", "attack_vectors": [
            {"technique_id": "T1098.003", "attack_name": "Takeover", "primitive": "p", "scope_tier": "sub"},
        ]}
        md = render(result)
        assert "Owner" in md
        assert "T1098.003" in md

    def test_empty_result_returns_empty_string(self):
        assert render({"unrelated_key": "value"}) == ""
