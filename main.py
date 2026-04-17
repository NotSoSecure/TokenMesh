LAST_RESULT = None
import argparse
import inspect
import json
import os
from typing import Any, Callable, Dict, Optional

from tools.intelligence import get_high_privileged_identities
from tools.report import generate_pdf_report
from openai_client import MODEL, TOOLS, client
from tools.identity import list_groups, list_service_principals, list_users
from tools.rbac import (
    list_role_assignments,
    list_subscription_scoped_assignments,
    summarize_high_privilege_assignments,
)
from tools.storage import (
    check_storage_hardening,
    check_storage_public_access,
    list_storage_accounts,
)

FUNCTION_MAP: Dict[str, Callable[..., Dict[str, Any]]] = {
    "get_high_privileged_identities": get_high_privileged_identities,
    "generate_pdf_report": generate_pdf_report,
    "list_storage_accounts": list_storage_accounts,
    "check_storage_public_access": check_storage_public_access,
    "check_storage_hardening": check_storage_hardening,
    "list_users": list_users,
    "list_groups": list_groups,
    "list_service_principals": list_service_principals,
    "list_role_assignments": list_role_assignments,
    "list_subscription_scoped_assignments": list_subscription_scoped_assignments,
    "summarize_high_privilege_assignments": summarize_high_privilege_assignments,
}

SYSTEM_PROMPT = """
You are an Azure security analyst.

STRICT RULES:
- Always show FULL identity-level details (never summaries like "7 out of 4")
- Always include:
    Name
    Role
    Scope
    Risk
    Evidence
    Attack paths

- If user asks for report → MUST call generate_pdf_report

- Never skip details for brevity

Your output must be detailed, evidence-based, and client-ready.
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

        result = func(subscription_id=subscription_id, **args)

        # store last result for report
        LAST_RESULT = result

        return result

    except Exception as e:
        return {"error": str(e)}


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

        messages.append(
            {
                "role": "assistant",
                "content": assistant.content,
                "tool_calls": [_serialize_tool_call(tc) for tc in assistant.tool_calls],
            }
        )

        for tool_call in assistant.tool_calls:
            try:
                args = json.loads(tool_call.function.arguments or "{}")
            except json.JSONDecodeError:
                args = {}

            result = _run_tool(tool_call.function.name, args, subscription_id)

            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": json.dumps(result),
                }
            )

    return "Stopped after too many tool rounds. Try a narrower question."


def main():
    parser = argparse.ArgumentParser(
        description="TokenMesh — Cloud Security AI Assistant",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive mode (uses env vars)
  python main.py

  # Pass everything inline — no env vars needed
  python main.py --subscription-id <sub-id> --openai-key <key>

  # One-shot query
  python main.py --subscription-id <sub-id> --openai-key <key> --prompt "Find all Owner roles"
        """,
    )
    parser.add_argument(
        "--subscription-id",
        help="Azure subscription ID. Falls back to AZURE_SUBSCRIPTION_ID env var.",
        default=None,
    )
    parser.add_argument(
        "--openai-key",
        help="OpenAI API key. Falls back to OPENAI_API_KEY env var.",
        default=None,
    )
    parser.add_argument(
        "--model",
        help="OpenAI model to use (default: gpt-4o-mini). Falls back to OPENAI_MODEL env var.",
        default=None,
    )
    parser.add_argument(
        "--prompt",
        help="Run one prompt and exit instead of interactive mode.",
        default=None,
    )
    args = parser.parse_args()

    # Apply CLI overrides to environment so openai_client picks them up
    if args.openai_key:
        os.environ["OPENAI_API_KEY"] = args.openai_key
    if args.model:
        os.environ["OPENAI_MODEL"] = args.model

    # Validate OpenAI key is available
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

        output = run_agent(user_input, subscription_id=args.subscription_id)
        print(f"\n{output}\n")


if __name__ == "__main__":
    main()
