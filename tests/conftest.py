"""
Shared pytest fixtures and helpers.

TokenMesh talks to real Azure APIs via requests + azure-* SDKs. Tests avoid
touching the wire — every test either uses pure fixture data (JSON files
under tests/fixtures/) or monkey-patches the module-level functions that
hit the wire.
"""

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock

import pytest


# Ensure the project root is importable so `import tools.foo` works when
# pytest is invoked from anywhere.
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))


FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture
def sample_subscription_id() -> str:
    return "11111111-2222-3333-4444-555555555555"


@pytest.fixture
def sample_tenant_id() -> str:
    return "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


def _load_fixture(name: str) -> Dict[str, Any]:
    path = FIXTURES_DIR / name
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture
def load_fixture():
    return _load_fixture


@pytest.fixture(autouse=True)
def _no_wire_calls(monkeypatch):
    """Fail fast if a test accidentally makes a real HTTP call."""
    def _blocked(*args, **kwargs):
        raise RuntimeError(
            "Real HTTP call attempted during tests. "
            "Patch the tool's data-fetching function or use a fixture."
        )
    # Only block if AZURE_LIVE_TESTS is not set.
    if not os.environ.get("AZURE_LIVE_TESTS"):
        monkeypatch.setattr("requests.get", _blocked, raising=True)
        monkeypatch.setattr("requests.post", _blocked, raising=True)


@pytest.fixture
def stub_azure_auth(monkeypatch):
    """Neutralize DefaultAzureCredential and env-var checks."""
    monkeypatch.setattr("azure_auth.get_management_token", lambda: "fake-arm-token")
    monkeypatch.setattr("azure_auth.get_graph_token", lambda: "fake-graph-token")
    monkeypatch.setattr("azure_auth.get_credential", lambda: MagicMock(name="FakeCred"))


class GraphStub:
    """
    Test double for `resolve_principal` that dispatches by principal_id.

    Each test builds a map: {object_id: {name, upn, principal_type}}. Any ID
    not in the map resolves to Unknown — this is exactly how the real Graph
    behaves for deleted objects, so orphan-detection tests work naturally.
    """

    def __init__(self, mapping: Optional[Dict[str, Dict[str, Any]]] = None):
        self.mapping: Dict[str, Dict[str, Any]] = mapping or {}

    def resolve(self, principal_id: str, authoritative_type: Optional[str] = None) -> Dict[str, Any]:
        from tools.principal_types import UNKNOWN, normalize
        if principal_id in self.mapping:
            entry = self.mapping[principal_id]
            return {
                "id": principal_id,
                "name": entry.get("name"),
                "userPrincipalName": entry.get("upn"),
                "principal_type": normalize(entry.get("principal_type")) if entry.get("principal_type") else (
                    normalize(authoritative_type) if authoritative_type else UNKNOWN
                ),
            }
        # Deleted / not found
        return {
            "id": principal_id,
            "name": "Unknown",
            "userPrincipalName": None,
            "principal_type": normalize(authoritative_type) if authoritative_type else UNKNOWN,
        }


@pytest.fixture
def graph_stub() -> GraphStub:
    return GraphStub()


@pytest.fixture
def patch_resolve_principal(monkeypatch):
    """
    Convenience: install a GraphStub into `tools.intelligence.resolve_principal`.
    Usage:
        def test_x(patch_resolve_principal):
            stub = patch_resolve_principal({"id-1": {"name": "Alice", "principal_type": "User"}})
            ...
    """
    def _apply(mapping: Dict[str, Dict[str, Any]]) -> GraphStub:
        stub = GraphStub(mapping)
        monkeypatch.setattr("tools.intelligence.resolve_principal", stub.resolve)
        return stub
    return _apply


@pytest.fixture
def patch_role_assignments(monkeypatch):
    """
    Install a mock for `tools.rbac.list_role_assignments`.
    Pass a list of assignment dicts (with role_name, principal_id, principal_type,
    scope). The mock ignores the principal_type filter — tests focus on
    the code paths under test, not on retesting the filter.
    """
    def _apply(items: List[Dict[str, Any]]):
        def _mock(*args, **kwargs):
            filt = kwargs.get("principal_type")
            filtered = items
            if filt:
                filtered = [i for i in items if i.get("principal_type") == filt]
            return {
                "count": len(filtered),
                "principal_type_filter": filt,
                "items": filtered,
            }
        monkeypatch.setattr("tools.rbac.list_role_assignments", _mock)
        # Also patch downstream call paths that already imported the name.
        monkeypatch.setattr("tools.intelligence.summarize_high_privilege_assignments",
                            _build_summarize_mock(items))
    return _apply


def _build_summarize_mock(items):
    from tools.principal_types import matches

    def _mock(subscription_id=None, principal_type=None):
        high_priv = {"Owner", "Contributor", "User Access Administrator"}
        findings = [
            i for i in items
            if i.get("role_name") in high_priv and matches(i.get("principal_type"), principal_type)
        ]
        return {
            "total_assignments": len(items),
            "high_privilege_count": len(findings),
            "principal_type_filter": principal_type,
            "by_role": {},
            "by_principal_type": {},
            "findings": findings,
        }
    return _mock


@pytest.fixture
def patch_entra_roles(monkeypatch):
    def _apply(entra_roles: List[Dict[str, Any]]):
        monkeypatch.setattr(
            "tools.intelligence.get_entra_roles",
            lambda: {"entra_roles": entra_roles},
        )
    return _apply
