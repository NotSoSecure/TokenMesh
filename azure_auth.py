import os
import re
from functools import lru_cache
from typing import Optional

from azure.identity import DefaultAzureCredential


@lru_cache(maxsize=1)
def get_credential() -> DefaultAzureCredential:
    return DefaultAzureCredential()


def get_subscription_id(subscription_id: Optional[str] = None) -> str:
    sub_id = (subscription_id or os.getenv("AZURE_SUBSCRIPTION_ID") or "").strip()
    if not sub_id:
        raise ValueError(
            "Missing subscription ID. Pass --subscription-id or set AZURE_SUBSCRIPTION_ID."
        )
    return sub_id


def get_management_token() -> str:
    return get_credential().get_token("https://management.azure.com/.default").token


def get_graph_token() -> str:
    return get_credential().get_token("https://graph.microsoft.com/.default").token


def subscription_scope(subscription_id: Optional[str] = None) -> str:
    return f"/subscriptions/{get_subscription_id(subscription_id)}"


def resource_group_from_id(resource_id: Optional[str]) -> Optional[str]:
    if not resource_id:
        return None

    match = re.search(r"/resourceGroups/([^/]+)/providers/", resource_id, flags=re.IGNORECASE)
    if match:
        return match.group(1)

    return None


def safe_str(value):
    if value is None:
        return None
    if isinstance(value, (str, int, float, bool)):
        return value
    return str(value)
