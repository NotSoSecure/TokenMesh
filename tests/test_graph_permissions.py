"""
Graph app-role + OAuth consent grant detector tests.
"""

import pytest

from tools import graph_permissions
from tools.graph_permissions import (
    DANGEROUS_APP_ROLES,
    HIGH_RISK_DELEGATED_SCOPES,
)


class TestDangerousAppRolesTable:
    def test_covers_bloodhound_edges(self):
        """The key BloodHound-Azure app-role edges must be in the table."""
        must_have = [
            "RoleManagement.ReadWrite.Directory",
            "AppRoleAssignment.ReadWrite.All",
            "Application.ReadWrite.All",
        ]
        for role in must_have:
            assert role in DANGEROUS_APP_ROLES

    def test_every_entry_has_required_fields(self):
        for role, meta in DANGEROUS_APP_ROLES.items():
            assert "technique_id" in meta
            assert "risk" in meta
            assert "why" in meta
            assert meta["risk"] in {"Critical", "High", "Medium", "Low"}


class TestHighRiskDelegatedScopesTable:
    def test_covers_illicit_consent_scopes(self):
        must_have = ["Mail.Read", "Files.Read.All", "Sites.Read.All", "Directory.Read.All"]
        for scope in must_have:
            assert scope in HIGH_RISK_DELEGATED_SCOPES

    def test_every_entry_has_required_fields(self):
        for scope, meta in HIGH_RISK_DELEGATED_SCOPES.items():
            assert "technique_id" in meta
            assert "risk" in meta
            assert "why" in meta


class TestDangerousGraphAppRoleDetection:
    def test_returns_empty_when_graph_unresolvable(self, monkeypatch):
        monkeypatch.setattr(
            graph_permissions,
            "_get_graph_service_principal_object_id",
            lambda: None,
        )
        monkeypatch.setattr(graph_permissions, "_get_graph_app_role_map", lambda: {})
        result = graph_permissions.list_dangerous_graph_app_role_assignments("sub")
        assert result["total_findings"] == 0
        assert "warning" in result

    def test_flags_service_principal_with_dangerous_role(self, monkeypatch):
        monkeypatch.setattr(
            graph_permissions,
            "_get_graph_service_principal_object_id",
            lambda: "graph-sp-obj",
        )
        monkeypatch.setattr(
            graph_permissions,
            "_get_graph_app_role_map",
            lambda: {"role-uuid-1": "RoleManagement.ReadWrite.Directory"},
        )

        # Optimized path: one paginated call to /appRoleAssignedTo returns
        # every grantee. Two grants: one dangerous, one benign role name.
        def _paged(url):
            if url == f"{graph_permissions.GRAPH}/servicePrincipals/graph-sp-obj/appRoleAssignedTo":
                return [
                    {"id": "assign-1", "principalId": "sp-danger",
                     "resourceId": "graph-sp-obj", "appRoleId": "role-uuid-1",
                     "createdDateTime": "2024-01-01T00:00:00Z"},
                    {"id": "assign-2", "principalId": "sp-benign",
                     "resourceId": "graph-sp-obj", "appRoleId": "role-benign",
                     "createdDateTime": "2024-01-01T00:00:00Z"},
                ]
            return []

        # SP resolution is a per-grantee lookup; the tool only ever looks up
        # the dangerous one because benign ones get filtered out first.
        def _resolve(pid):
            return {
                "sp-danger": {"id": "sp-danger", "appId": "app-1",
                              "displayName": "danger-sp",
                              "servicePrincipalType": "Application"},
            }.get(pid, {})

        monkeypatch.setattr(graph_permissions, "_paged_get", _paged)
        monkeypatch.setattr(graph_permissions, "_resolve_service_principal_summary", _resolve)

        result = graph_permissions.list_dangerous_graph_app_role_assignments("sub")
        assert result["total_findings"] == 1
        finding = result["findings"][0]
        assert finding["detector"] == "dangerous_graph_app_role"
        assert finding["principal_id"] == "sp-danger"
        assert finding["risk"] == "Critical"
        assert finding["evidence"]["graph_permission_name"] == "RoleManagement.ReadWrite.Directory"
        assert finding["evidence"]["assignment_id"] == "assign-1"
        assert finding["mitre_technique_id"] == "T1098.003"


class TestIllicitOAuthConsentGrantDetection:
    def test_admin_consent_high_risk_scope_fires(self, monkeypatch):
        def _paged(url):
            if url == f"{graph_permissions.GRAPH}/oauth2PermissionGrants":
                return [{
                    "clientId": "sp-3rdparty",
                    "resourceId": "graph-sp-obj",
                    "consentType": "AllPrincipals",
                    "scope": "Mail.Read Files.Read.All openid",
                }]
            return []
        monkeypatch.setattr(graph_permissions, "_paged_get", _paged)

        result = graph_permissions.list_illicit_oauth_consent_grants("sub")
        assert result["total_findings"] == 1
        finding = result["findings"][0]
        assert finding["detector"] == "illicit_oauth_consent_grant"
        # Admin consent + high-risk scope escalates.
        assert finding["risk"] == "Critical"
        assert "Mail.Read" in finding["evidence"]["matched_scopes"]
        assert "Files.Read.All" in finding["evidence"]["matched_scopes"]

    def test_low_risk_scopes_do_not_fire(self, monkeypatch):
        def _paged(url):
            if url == f"{graph_permissions.GRAPH}/oauth2PermissionGrants":
                return [{
                    "clientId": "sp-benign",
                    "resourceId": "graph-sp-obj",
                    "consentType": "Principal",
                    "principalId": "user-1",
                    "scope": "openid profile",
                }]
            return []
        monkeypatch.setattr(graph_permissions, "_paged_get", _paged)

        result = graph_permissions.list_illicit_oauth_consent_grants("sub")
        assert result["total_findings"] == 0
