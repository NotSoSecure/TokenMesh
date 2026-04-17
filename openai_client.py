from openai import OpenAI
import os

# =========================
# CONFIG
# =========================

MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
client = OpenAI()

# =========================
# TOOL DEFINITIONS
# =========================

TOOLS = [

    # =========================
    # STORAGE
    # =========================

    {
        "type": "function",
        "function": {
            "name": "list_storage_accounts",
            "description": "List all Azure storage accounts in the subscription.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
                "additionalProperties": False
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "check_storage_public_access",
            "description": "Find storage accounts that allow public blob access.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
                "additionalProperties": False
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "check_storage_hardening",
            "description": "Check storage accounts for misconfigurations like public access, weak TLS, or HTTP usage.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
                "additionalProperties": False
            }
        }
    },

    # =========================
    # IDENTITY (ENTRA ID)
    # =========================

    {
        "type": "function",
        "function": {
            "name": "list_users",
            "description": "List Microsoft Entra ID users.",
            "parameters": {
                "type": "object",
                "properties": {
                    "top": {
                        "type": "integer",
                        "description": "Number of users to fetch (max 999)",
                        "minimum": 1,
                        "maximum": 999
                    }
                },
                "required": ["top"],
                "additionalProperties": False
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "list_groups",
            "description": "List Microsoft Entra ID groups.",
            "parameters": {
                "type": "object",
                "properties": {
                    "top": {
                        "type": "integer",
                        "description": "Number of groups to fetch (max 999)",
                        "minimum": 1,
                        "maximum": 999
                    }
                },
                "required": ["top"],
                "additionalProperties": False
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "list_service_principals",
            "description": "List Microsoft Entra ID service principals.",
            "parameters": {
                "type": "object",
                "properties": {
                    "top": {
                        "type": "integer",
                        "description": "Number of service principals to fetch (max 999)",
                        "minimum": 1,
                        "maximum": 999
                    }
                },
                "required": ["top"],
                "additionalProperties": False
            }
        }
    },

    # =========================
    # RBAC
    # =========================

    {
        "type": "function",
        "function": {
            "name": "list_role_assignments",
            "description": "List Azure RBAC role assignments at subscription or custom scope.",
            "parameters": {
                "type": "object",
                "properties": {
                    "scope": {
                        "type": "string",
                        "description": "Optional Azure scope like /subscriptions/<id> or resource group scope"
                    }
                },
                "required": [],
                "additionalProperties": False
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "summarize_high_privilege_assignments",
            "description": "Summarize high privilege Azure RBAC roles such as Owner, Contributor, and User Access Administrator.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
                "additionalProperties": False
            }
        }
    },

    # =========================
    # INTELLIGENCE ENGINE 🔥
    # =========================

    {
        "type": "function",
        "function": {
            "name": "get_high_privileged_identities",
            "description": "Get high privileged identities with Azure RBAC + Entra roles, risk level, evidence, and attack paths.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
                "additionalProperties": False
            }
        }
    },

    # =========================
    # BACKDOOR DETECTION 🔥🔥
    # =========================

    {
        "type": "function",
        "function": {
            "name": "detect_backdoors",
            "description": "Detect potential backdoors such as high privilege service principals, public storage, and unknown identities.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
                "additionalProperties": False
            }
        }
    },

    # =========================
    # REPORT GENERATION 📄
    # =========================

    {
        "type": "function",
        "function": {
            "name": "generate_pdf_report",
            "description": "Generate a detailed PDF security report for findings like high privileged identities.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
                "additionalProperties": False
            }
        }
    }
]
