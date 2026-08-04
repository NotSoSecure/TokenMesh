LAST_RESULT = None
import argparse
import json
import os
from typing import Any, Callable, Dict, Optional

from tools.appservice import (
    check_appservice_connection_strings,
    check_appservice_hardening,
    check_appservice_managed_identity_exposure,
    check_appservice_scm_exposure,
    list_web_apps,
)
from tools.attack_vectors import analyze_attack_vectors, map_role_to_attacks
from tools.backdoor import detect_backdoors, AVAILABLE_DETECTORS
from tools.compute import (
    check_compute_extensions,
    check_compute_hardening,
    check_compute_managed_identity_exposure,
    list_arc_machines,
    list_virtual_machines,
)
from tools.graph_permissions import (
    list_dangerous_graph_app_role_assignments,
    list_illicit_oauth_consent_grants,
    list_third_party_apps_with_admin_consent,
)
from tools.identity import list_groups, list_service_principals, list_users
from tools.intelligence import (
    get_high_privileged_identities,
    list_guest_users_with_azure_roles,
    list_high_privileged_service_principals,
    list_orphaned_role_assignments,
)
from tools.keyvault import (
    check_keyvault_access_policies,
    check_keyvault_hardening,
    check_keyvault_object_expiration,
    list_key_vaults,
)
from tools.rbac import (
    list_role_assignments,
    list_subscription_scoped_assignments,
    summarize_high_privilege_assignments,
)
from tools.report import generate_pdf_report
from tools.storage import (
    check_storage_hardening,
    check_storage_public_access,
    list_storage_accounts,
)
from openai_client import MODEL, TOOLS, client


def _list_available_backdoor_detectors(**_):
    return {"available_detectors": AVAILABLE_DETECTORS}


FUNCTION_MAP: Dict[str, Callable[..., Dict[str, Any]]] = {
    # Storage
    "list_storage_accounts": list_storage_accounts,
    "check_storage_public_access": check_storage_public_access,
    "check_storage_hardening": check_storage_hardening,

    # Key Vault
    "list_key_vaults": list_key_vaults,
    "check_keyvault_hardening": check_keyvault_hardening,
    "check_keyvault_access_policies": check_keyvault_access_policies,
    "check_keyvault_object_expiration": check_keyvault_object_expiration,

    # Compute
    "list_virtual_machines": list_virtual_machines,
    "check_compute_managed_identity_exposure": check_compute_managed_identity_exposure,
    "check_compute_extensions": check_compute_extensions,
    "check_compute_hardening": check_compute_hardening,
    "list_arc_machines": list_arc_machines,

    # Identity
    "list_users": list_users,
    "list_groups": list_groups,
    "list_service_principals": list_service_principals,

    # RBAC
    "list_role_assignments": list_role_assignments,
    "summarize_high_privilege_assignments": summarize_high_privilege_assignments,
    "list_subscription_scoped_assignments": list_subscription_scoped_assignments,

    # Intelligence + intent-mapped
    "get_high_privileged_identities": get_high_privileged_identities,
    "list_high_privileged_service_principals": list_high_privileged_service_principals,
    "list_guest_users_with_azure_roles": list_guest_users_with_azure_roles,
    "list_orphaned_role_assignments": list_orphaned_role_assignments,

    # Attack vectors
    "analyze_attack_vectors": analyze_attack_vectors,
    "map_role_to_attacks": map_role_to_attacks,

    # Backdoor
    "detect_backdoors": detect_backdoors,
    "list_available_backdoor_detectors": _list_available_backdoor_detectors,

    # App Service
    "list_web_apps": list_web_apps,
    "check_appservice_hardening": check_appservice_hardening,
    "check_appservice_scm_exposure": check_appservice_scm_exposure,
    "check_appservice_managed_identity_exposure": check_appservice_managed_identity_exposure,
    "check_appservice_connection_strings": check_appservice_connection_strings,

    # Microsoft Graph app-role + OAuth consent
    "list_dangerous_graph_app_role_assignments": list_dangerous_graph_app_role_assignments,
    "list_illicit_oauth_consent_grants": list_illicit_oauth_consent_grants,
    "list_third_party_apps_with_admin_consent": list_third_party_apps_with_admin_consent,

    # Report
    "generate_pdf_report": generate_pdf_report,
}


SYSTEM_PROMPT = """
You are an Azure security analyst. Your users are defenders — SOC analysts,
incident responders, and security engineers running TokenMesh against their
own tenant. Every answer must be evidence-based and actionable, never a
summary the user has to re-parse to understand what they're looking at.

VOCABULARY — Microsoft canonical only:
- Principal types are always PascalCase singular: 'User', 'ServicePrincipal',
  'Group'. These match ARM roleAssignments.properties.principalType, the
  Azure Portal, `az role assignment list`, and Sentinel KQL
  (PrincipalType == "ServicePrincipal"). Never say 'servicePrincipals' or
  'users' — those are Graph URL shapes, not defender vocabulary.
- Role names are the exact display names: 'Owner', 'Contributor', 'User Access
  Administrator', 'Storage Blob Data Contributor', 'Key Vault Administrator',
  'Virtual Machine Contributor', 'Global Administrator', etc.
- Scopes are ARM paths: '/subscriptions/{id}', '/subscriptions/{id}/resourceGroups/{rg}'.

FILTERING — never return mixed types when the question was about one:
- If the defender asks about a specific principal type ("service principals with
  Owner", "guest users with high privilege"), pass principal_type='ServicePrincipal'
  or principal_type='User' to the tool. Do not filter in prose after the fact.
- Prefer the intent-mapped tools when they exist:
  * list_high_privileged_service_principals — SPs with Owner/Contributor/UAA.
  * list_guest_users_with_azure_roles — guest users with high-priv RBAC.
  * list_orphaned_role_assignments — deleted-principal persistence.

OUTPUT — every finding is defender-actionable:
- Always show full identity-level detail. Never summarize away identities.
- For each finding include: principal_type, azure_role, scope, risk_level,
  MITRE technique ID, KQL detection signal (Sentinel-friendly), remediation.
- Every finding must include the MITRE ATT&CK for Cloud technique ID from
  the tool output. If missing, ask the tool for attack vectors via
  analyze_attack_vectors or map_role_to_attacks.

RENDERING — every TokenMesh tool result carries a `_display` field with
pre-rendered markdown (severity emojis, MITRE grids, Unicode attack-path
diagrams, findings tables). When you see `_display` in a tool result:
- Emit that markdown VERBATIM as your reply to the user.
- Add at most one short lead sentence and one short closing suggestion.
- Never re-summarize the same information as prose the tool already put in
  the table — the visual rendering IS the answer.
- Preserve every emoji, box-drawing character, and code fence exactly.

REPORTS — generate_pdf_report captures the last analysis. If the user asks
for a report or export, call generate_pdf_report after running the relevant
analysis tool. PDFs land in tools/reports/ (alongside the tool code).
Do not summarize the PDF — return the path the tool reported.

Do not hallucinate MITRE IDs or KQL. Only use what the tool returned.
""".strip()


def _serialize_tool_call(tool_call) -> Dict[str, Any]:
    return {
        "id": tool_call.id,
        "type": tool_call.type,
        "function": {
            "name": tool_call.function.name,
            "arguments": tool_call.function.arguments,
        },
    }


def _run_tool(name, args, subscription_id):
    global LAST_RESULT

    if name not in FUNCTION_MAP:
        return {"error": f"Unknown tool: {name}"}

    func = FUNCTION_MAP[name]

    try:
        if name == "generate_pdf_report":
            if LAST_RESULT is None:
                return {"error": "No data available to generate report"}
            return func(LAST_RESULT)

        if name == "map_role_to_attacks":
            # This tool doesn't need subscription_id.
            return func(**args)

        if name == "analyze_attack_vectors":
            return func(subscription_id=subscription_id, **args)

        if name == "list_available_backdoor_detectors":
            return func()

        result = func(subscription_id=subscription_id, **args)
        LAST_RESULT = result
        return result

    except TypeError as exc:
        # A tool was called with wrong kwargs — surface the reason to the LLM.
        return {"error": f"Invalid arguments for {name}: {exc}"}
    except ValueError as exc:
        return {"error": str(exc)}
    except Exception as exc:
        return {"error": str(exc)}


def run_agent(prompt: str, subscription_id: Optional[str] = None, max_rounds: int = 8) -> str:
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": prompt},
    ]

    for _ in range(max_rounds):
        response = client.chat.completions.create(
            model=MODEL,
            messages=messages,
            tools=TOOLS,
            tool_choice="auto",
        )

        assistant = response.choices[0].message

        if not assistant.tool_calls:
            return assistant.content or ""

        messages.append({
            "role": "assistant",
            "content": assistant.content,
            "tool_calls": [_serialize_tool_call(tc) for tc in assistant.tool_calls],
        })

        for tool_call in assistant.tool_calls:
            try:
                args = json.loads(tool_call.function.arguments or "{}")
            except json.JSONDecodeError:
                args = {}
            result = _run_tool(tool_call.function.name, args, subscription_id)
            messages.append({
                "role": "tool",
                "tool_call_id": tool_call.id,
                "content": json.dumps(result, default=str),
            })

    return "Stopped after too many tool rounds. Try a narrower question."


def main():
    parser = argparse.ArgumentParser(
        description="TokenMesh — Cloud Security AI Assistant",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py
  python main.py --subscription-id <sub-id> --openai-key <key>
  python main.py --subscription-id <sub-id> --openai-key <key> --prompt "Every service principal with Owner access"
        """,
    )
    parser.add_argument("--subscription-id", default=None,
                        help="Azure subscription ID. Falls back to AZURE_SUBSCRIPTION_ID env var.")
    parser.add_argument("--openai-key", default=None,
                        help="OpenAI API key. Falls back to OPENAI_API_KEY env var.")
    parser.add_argument("--model", default=None,
                        help="OpenAI model to use. Falls back to OPENAI_MODEL env var.")
    parser.add_argument("--prompt", default=None,
                        help="Run one prompt and exit instead of interactive mode.")
    args = parser.parse_args()

    if args.openai_key:
        os.environ["OPENAI_API_KEY"] = args.openai_key
    if args.model:
        os.environ["OPENAI_MODEL"] = args.model

    if not os.environ.get("OPENAI_API_KEY"):
        print("Error: OpenAI API key required.")
        print("  Pass --openai-key <key>  OR  set OPENAI_API_KEY env var.")
        return

    if args.prompt:
        print(run_agent(args.prompt, subscription_id=args.subscription_id))
        return

    banner = r"""
  ████████╗ ██████╗ ██╗  ██╗███████╗███╗   ██╗███╗   ███╗███████╗███████╗██╗  ██╗
  ╚══██╔══╝██╔═══██╗██║ ██╔╝██╔════╝████╗  ██║████╗ ████║██╔════╝██╔════╝██║  ██║
     ██║   ██║   ██║█████╔╝ █████╗  ██╔██╗ ██║██╔████╔██║█████╗  ███████╗███████║
     ██║   ██║   ██║██╔═██╗ ██╔══╝  ██║╚██╗██║██║╚██╔╝██║██╔══╝  ╚════██║██╔══██║
     ██║   ╚██████╔╝██║  ██╗███████╗██║ ╚████║██║ ╚═╝ ██║███████╗███████║██║  ██║
     ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚═╝     ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝
  Cloud Security AI Assistant for Azure
  """
    print(banner)
    print("  Developed by Saksham Agrawal  |  linkedin.com/in/saksham-agrawal-6530661b3")
    print("  ─" * 40)
    print("  Type a question and press Enter. Type 'exit' to quit.\n")

    while True:
        user_input = input("TokenMesh >> ").strip()
        if user_input.lower() in {"exit", "quit"}:
            break
        if not user_input:
            continue
        print(f"\n{run_agent(user_input, subscription_id=args.subscription_id)}\n")


if __name__ == "__main__":
    main()
