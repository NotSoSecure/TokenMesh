"""
Markdown formatters — render tool output for in-conversation display.

Every MCP tool result carries a `_display` field with pre-rendered
markdown that Claude renders verbatim to the user. This keeps the JSON
data intact (so the LLM can still reason over it) while giving the user
a defender-friendly presentation with:

  - Emoji severity badges (🔴🟠🟡🟢⚪)
  - Confidence pills
  - Unicode attack-path box diagrams (in code blocks)
  - MITRE ATT&CK coverage grids
  - Kill-chain arrow chains
  - Severity histograms as Unicode bar sparklines

Design choice: pure markdown + Unicode. No HTML tags, no embedded images.
Renders correctly in every Claude client (Code, Desktop, Web, terminal).
"""

from collections import Counter
from typing import Any, Dict, Iterable, List, Optional


# ---------------------------------------------------------------------------
# Visual vocabulary
# ---------------------------------------------------------------------------

_RISK_EMOJI = {
    "Critical": "🔴",
    "High":     "🟠",
    "Medium":   "🟡",
    "Low":      "🟢",
    "Info":     "⚪",
}

_CONFIDENCE_MARK = {"high": "◆", "medium": "◈", "low": "◇"}

_SCOPE_LABEL = {
    "management_group": "MG",
    "subscription":     "Sub",
    "resource_group":   "RG",
    "resource":         "Res",
}


def _risk_badge(risk: Optional[str]) -> str:
    return f"{_RISK_EMOJI.get(str(risk or ''), '⚪')} `{risk or '—'}`"


def _confidence_badge(conf: Optional[str]) -> str:
    return f"{_CONFIDENCE_MARK.get(str(conf or ''), '·')} {conf or 'unknown'}"


def _score_bar(score: int, width: int = 10) -> str:
    filled = round(width * max(0, min(100, score)) / 100)
    return "█" * filled + "░" * (width - filled)


def _truncate(s: Optional[str], n: int) -> str:
    if not s:
        return "—"
    s = str(s)
    return s if len(s) <= n else s[: n - 1] + "…"


def _scope_short(scope: Optional[str]) -> str:
    if not scope:
        return "—"
    s = str(scope)
    if "/managementGroups/" in s:
        return "MG:" + s.rsplit("/", 1)[-1]
    if "/resourceGroups/" in s and "/providers/" in s:
        # /subscriptions/{id}/resourceGroups/{rg}/providers/{...}/name
        parts = s.split("/providers/", 1)
        rg = parts[0].rsplit("/", 1)[-1]
        res = parts[1].rsplit("/", 1)[-1]
        return f"Res:{rg}/{res}"
    if "/resourceGroups/" in s:
        return "RG:" + s.rsplit("/", 1)[-1]
    if s.startswith("/subscriptions/"):
        return "Sub:" + s.rsplit("/", 1)[-1][:8] + "…"
    return _truncate(s, 40)


# ---------------------------------------------------------------------------
# Severity histogram
# ---------------------------------------------------------------------------


def severity_histogram(findings: Iterable[Dict[str, Any]]) -> str:
    counts: Counter = Counter()
    for f in findings:
        counts[str(f.get("risk") or "Info")] += 1

    order = ["Critical", "High", "Medium", "Low", "Info"]
    total = sum(counts.values())
    if total == 0:
        return "_No findings_"

    max_c = max(counts.values())
    lines = []
    for risk in order:
        n = counts.get(risk, 0)
        if n == 0:
            continue
        bar_len = round(30 * n / max_c) if max_c else 0
        bar = "█" * bar_len
        lines.append(f"{_RISK_EMOJI[risk]} `{risk:<8}` {bar} **{n}**")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# MITRE ATT&CK coverage grid
# ---------------------------------------------------------------------------


_MITRE_TILES = [
    ("Initial Access", [("T1078.004", "Valid Cloud Accts"), ("T1199", "Trusted Rel")]),
    ("Persistence",     [("T1098.001", "Add Cloud Creds"), ("T1098.003", "Add Cloud Roles"), ("T1136.003", "Create Account")]),
    ("Cred Access",     [("T1528", "Steal App Token"), ("T1552.001", "Creds in Config"), ("T1552.005", "IMDS Theft"), ("T1555.006", "Cloud Secrets")]),
    ("Defense Evasion", [("T1562.008", "Disable Logs"), ("T1556", "Modify Auth"), ("T1556.009", "CA Bypass")]),
    ("Execution",       [("T1651", "Cloud Admin Cmd"), ("T1505.003", "Web Shell")]),
    ("Discovery",       [("T1580", "Cloud Infra Discovery")]),
    ("Collection",      [("T1530", "Cloud Storage Exfil"), ("T1213", "Info Repos"), ("T1114", "Email Collection")]),
]


def mitre_coverage_grid(findings: Iterable[Dict[str, Any]]) -> str:
    counts: Counter = Counter()
    for f in findings:
        mitre = str(f.get("mitre_technique_id") or "")
        for tok in mitre.replace("->", " ").replace("→", " ").split():
            tok = tok.strip(" ,;.")
            if tok.startswith("T"):
                counts[tok] += 1

    if not counts:
        return "_No MITRE techniques covered by current findings_"

    lines = ["| Tactic | Technique | Hits |", "|---|---|---|"]
    for tactic, tiles in _MITRE_TILES:
        for tid, name in tiles:
            n = counts.get(tid, 0)
            marker = "🎯" if n > 0 else "·"
            hits = f"**{n}**" if n > 0 else "_0_"
            lines.append(f"| {tactic} | {marker} `{tid}` {name} | {hits} |")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Unicode attack path diagram
# ---------------------------------------------------------------------------


def _box(lines: List[str], min_width: int = 24) -> List[str]:
    """Return a list of strings drawing a rounded box around `lines`."""
    width = max(min_width, max((len(l) for l in lines), default=0) + 2)
    top = "╭" + "─" * width + "╮"
    body = ["│ " + l.ljust(width - 1) + "│" for l in lines]
    bot = "╰" + "─" * width + "╯"
    return [top] + body + [bot]


def attack_path_diagram(finding: Dict[str, Any]) -> str:
    """
    Three-node horizontal attack-path in Unicode box-drawing.

        ╭──────────────╮    ╭─────────────╮    ╭──────────────────╮
        │ IDENTITY     │───▶│ ROLE @ SCOPE│───▶│ TECHNIQUE (MITRE)│
        │ …            │    │ …           │    │ …                │
        ╰──────────────╯    ╰─────────────╯    ╰──────────────────╯
    """
    identity = _truncate(
        finding.get("display_name") or finding.get("name") or finding.get("principal_id"),
        22,
    )
    ptype = str(finding.get("principal_type") or "?")
    pid = _truncate(finding.get("principal_id") or "", 22)

    role = _truncate(finding.get("azure_role") or finding.get("granting_role") or "—", 22)
    scope = _scope_short(finding.get("scope") or finding.get("granting_scope"))

    mitre = str(finding.get("mitre_technique_id") or "—")
    attack = _truncate(finding.get("attack_name") or "Attack", 24)
    risk = str(finding.get("risk") or finding.get("risk_level") or "Medium")
    risk_emoji = _RISK_EMOJI.get(risk, "⚪")

    n1 = _box(["IDENTITY", identity, f"({ptype})", pid], min_width=26)
    n2 = _box(["ROLE @ SCOPE", role, scope], min_width=26)
    n3 = _box(["TECHNIQUE", mitre, attack, f"{risk_emoji} {risk}"], min_width=28)

    # Pad shorter columns to the tallest.
    height = max(len(n1), len(n2), len(n3))
    for col in (n1, n2, n3):
        while len(col) < height:
            col.append(" " * len(col[0]))

    mid = height // 2
    out_lines = []
    for i in range(height):
        connector1 = " ──▶ " if i == mid else "     "
        connector2 = " ──▶ " if i == mid else "     "
        out_lines.append(n1[i] + connector1 + n2[i] + connector2 + n3[i])

    return "```\n" + "\n".join(out_lines) + "\n```"


def kill_chain_arrow(steps: List[Dict[str, str]]) -> str:
    """
    Inline kill-chain: T1552.005 (IMDS) ─▶ T1098.003 (RBAC Write) ─▶ 🎯 Takeover
    """
    if not steps:
        return "_(no chain)_"
    parts = []
    for step in steps:
        parts.append(f"`{step.get('technique_id', '—')}` ({_truncate(step.get('name'), 22)})")
    return " ─▶ ".join(parts) + " ─▶ 🎯"


# ---------------------------------------------------------------------------
# Compact at-a-glance table (screenshot style)
# ---------------------------------------------------------------------------
#
# Renders the whole finding list in ONE compact 7-column markdown table:
#   #  |  Name  |  Type  |  Role  |  Scope  |  Risk  |  Notable attack paths
#
# This is what defenders actually scan first: everything on one page,
# comparable at a glance. Detailed cards and MITRE grid still render below
# for the finding they want to drill into.


_SCOPE_TIER_LABELS = {
    "management_group": "MG",
    "subscription":     "Sub",
    "resource_group":   "RG",
    "resource":         "Res",
}


def _scope_tier_short(scope: Optional[str]) -> str:
    """Return a compact scope tier label: MG / Sub / RG / Res."""
    if not scope:
        return "—"
    s = str(scope).lower()
    if "/providers/microsoft.management/managementgroups" in s:
        return "MG"
    if "/resourcegroups/" in s and "/providers/" in s:
        return "Res"
    if "/resourcegroups/" in s:
        return "RG"
    if s.startswith("/subscriptions/") and s.count("/") == 2:
        return "Sub"
    return "Res"


def _principal_type_display(ptype: Optional[str]) -> str:
    """Human-readable principal type (Service Principal, not ServicePrincipal)."""
    if not ptype:
        return "—"
    if ptype == "ServicePrincipal":
        return "Service Principal"
    return ptype


def _attack_paths_inline(f: Dict[str, Any], limit: int = 3) -> str:
    """
    Compact inline representation of attack paths for a table cell:
      "T1098.003 Subscription Takeover, T1562.008 Disable Logs"
    Falls back to attack_vectors if attack_paths is empty.
    """
    paths = f.get("attack_paths") or []
    inline_paths: List[str] = []

    if paths:
        for p in paths[:limit]:
            inline_paths.append(_truncate(str(p), 55))
    else:
        for v in (f.get("attack_vectors") or [])[:limit]:
            tid = v.get("technique_id") or ""
            name = v.get("attack_name") or ""
            if tid and name:
                inline_paths.append(_truncate(f"{tid} {name}", 55))
            elif name:
                inline_paths.append(_truncate(name, 55))
            elif tid:
                inline_paths.append(tid)

    if not inline_paths:
        mitre = f.get("mitre_technique_id")
        return f"`{mitre}`" if mitre else "—"

    return ", ".join(inline_paths)


def _short_id(principal_id: Optional[str], keep: int = 8) -> str:
    """
    Truncate a principal ID to a defender-friendly pill.
        '62542cd4-1645-4116-9688-ac22530fe59e'  →  '62542cd4...'
    Long enough to be unique-ish in a subscription; short enough to fit
    inline in narrative text.
    """
    if not principal_id:
        return "unknown"
    s = str(principal_id)
    if len(s) <= keep + 3:
        return s
    return s[:keep] + "..."


def _scope_description(scope: Optional[str]) -> str:
    """Human phrase for a scope tier — 'subscription', 'resource group', etc."""
    tier = _scope_tier_short(scope)
    return {
        "MG":  "management group root",
        "Sub": "subscription",
        "RG":  "resource group",
        "Res": "resource",
    }.get(tier, "resource")


def _format_role_and_entra(f: Dict[str, Any]) -> str:
    """
    Compose the Role bullet, folding Entra directory roles into one line:
        **Owner** @ subscription, plus Entra Global Administrator
        **Contributor** @ resource group
    """
    role = f.get("azure_role")
    scope_phrase = _scope_description(f.get("scope"))
    evidence = f.get("evidence") or {}
    entra = f.get("entra_roles") or evidence.get("entra_roles") or []

    parts: List[str] = []
    if role:
        parts.append(f"**{role}** @ {scope_phrase}")

    if entra:
        clean = [str(r) for r in entra if r]
        if clean:
            parts.append("plus Entra " + ", ".join(clean))

    return ", ".join(parts) if parts else "—"


def _format_attack_paths_prose(f: Dict[str, Any]) -> str:
    """
    Compose the Attack paths bullet as inline prose with MITRE IDs.
        "Subscription Takeover (T1098.003), Disable Cloud Security Controls (T1562.008)"
    """
    paths = f.get("attack_paths") or []
    if paths:
        return ", ".join(str(p) for p in paths[:6])

    vectors = f.get("attack_vectors") or []
    if vectors:
        parts = []
        for v in vectors[:6]:
            name = v.get("attack_name") or ""
            tid = v.get("technique_id") or ""
            if name and tid:
                parts.append(f"{name} ({tid})")
            elif name:
                parts.append(name)
            elif tid:
                parts.append(tid)
        if parts:
            return ", ".join(parts)

    mitre = f.get("mitre_technique_id")
    if mitre:
        return f"See MITRE `{mitre}`"
    return "—"


_SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}


def _severity_group_label(risk: str, findings_in_group: List[Dict[str, Any]]) -> str:
    """
    Build the section divider label like the screenshot:
        "CRITICAL — OWNER + GLOBAL ADMINISTRATOR"
    Uses the dominant Azure role + primary Entra role from findings in the group.
    """
    label_bits = [risk.upper()]
    # Dominant Azure role in this severity group
    role_counts = Counter(f.get("azure_role") for f in findings_in_group if f.get("azure_role"))
    if role_counts:
        top_role = role_counts.most_common(1)[0][0]
        # Look for a distinguishing Entra role too
        entra_all: List[str] = []
        for f in findings_in_group:
            entra_all.extend(f.get("entra_roles") or (f.get("evidence") or {}).get("entra_roles") or [])
        if entra_all:
            top_entra = Counter(entra_all).most_common(1)[0][0]
            label_bits.append(f"{top_role.upper()} + {str(top_entra).upper()}")
        else:
            label_bits.append(top_role.upper())
    return " — ".join(label_bits)


def narrative_identity_list(
    findings: List[Dict[str, Any]],
    subtitle: Optional[str] = None,
    header: str = "Detailed Findings",
    limit: int = 30,
    group_by_severity: bool = True,
) -> str:
    """
    Narrative-list presentation — the detailed explanation section.
    Findings grouped under severity dividers like the screenshot's

        CRITICAL — OWNER + GLOBAL ADMINISTRATOR

    Within each group, numbered paragraphs:

        **1. {name}** — {type} ( `{id-short}` ) — 🔴 Critical
        - **Role:** **Owner** @ subscription, plus Entra Global Administrator
        - **Attack paths:** Subscription Takeover (T1098.003), ...

    The expert-glance summary and stat tiles are rendered separately ABOVE
    this by format_identity_result / format_backdoor_result. This section is
    the "if you want to dig in, here's every finding" layer.
    """
    if not findings:
        return f"### 🔬 {header}\n\n_No identities to show._"

    lines: List[str] = []
    lines.append(f"### 🔬 {header}")
    lines.append("")

    # Order findings by severity, then bucket into groups.
    ordered = sorted(
        findings[:limit],
        key=lambda f: _SEVERITY_ORDER.get(
            str(f.get("risk") or f.get("risk_level") or "Info"), 99
        ),
    )

    if group_by_severity:
        groups: Dict[str, List[Dict[str, Any]]] = {}
        for f in ordered:
            risk = str(f.get("risk") or f.get("risk_level") or "Info")
            groups.setdefault(risk, []).append(f)

        idx = 0
        for risk in ("Critical", "High", "Medium", "Low", "Info"):
            group = groups.get(risk, [])
            if not group:
                continue
            emoji = _RISK_EMOJI.get(risk, "⚪")
            label = _severity_group_label(risk, group)
            lines.append("---")
            lines.append("")
            lines.append(f"#### {emoji} {label}")
            lines.append("")
            for f in group:
                idx += 1
                lines.extend(_render_narrative_entry(idx, f))
    else:
        for i, f in enumerate(ordered, 1):
            lines.extend(_render_narrative_entry(i, f))

    if len(findings) > limit:
        lines.append(f"_…{len(findings) - limit} more not shown. See the full table at the bottom._")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Attack Path Analysis (kill-chain style)
# ---------------------------------------------------------------------------


def _chain_prefix_from_role(azure_role: Optional[str], entra_roles: List[str]) -> str:
    """
    Initial-access step is always T1078.004 (Valid Cloud Accounts) — the
    identity has been compromised. Prefix is the role that got weaponized.
    """
    parts = []
    if azure_role:
        parts.append(azure_role)
    for r in entra_roles or []:
        parts.append(str(r))
    return " + ".join(parts) if parts else "the identity's permissions"


def _kill_chain_for_finding(f: Dict[str, Any]) -> List[Dict[str, str]]:
    """
    Build a step-by-step kill chain for a finding based on its attack_vectors.

    Every chain starts with T1078.004 (Valid Cloud Accounts — attacker
    compromises the identity), then walks each attack_vector as the next
    step. If the tool didn't attach structured attack_vectors, we synthesize
    a lightweight chain from `attack_paths` strings.
    """
    role = f.get("azure_role")
    evidence = f.get("evidence") or {}
    entra = f.get("entra_roles") or evidence.get("entra_roles") or []
    role_phrase = _chain_prefix_from_role(role, entra)

    chain: List[Dict[str, str]] = [
        {
            "step": "Initial access",
            "mitre": "T1078.004",
            "prose": (
                f"Attacker acquires the identity's credentials (phishing, session token theft, "
                f"leaked secret) and authenticates as this principal — now wielding "
                f"**{role_phrase}**."
            ),
        }
    ]

    vectors = f.get("attack_vectors") or []
    if vectors:
        for v in vectors[:4]:
            step_name = v.get("attack_name") or "Weaponize permissions"
            mitre = v.get("technique_id") or "—"
            primitive = v.get("primitive") or v.get("detection_signal") or ""
            prose = primitive if primitive else f"Use the granted role to execute **{step_name}**."
            chain.append({
                "step": step_name,
                "mitre": mitre,
                "prose": prose,
                "detection_signal": v.get("detection_signal") or "",
                "remediation": v.get("remediation") or "",
            })
        return chain

    # Fallback: synthesize chain from attack_paths strings
    for p in (f.get("attack_paths") or [])[:4]:
        chain.append({
            "step": _truncate(str(p), 60),
            "mitre": f.get("mitre_technique_id") or "—",
            "prose": str(p),
        })
    return chain


def _chain_ascii_diagram(chain: List[Dict[str, str]]) -> str:
    """
    Render a compact horizontal kill-chain diagram:
        [T1078.004] ──▶ [T1098.003] ──▶ [T1562.008]
        Initial       Add Cloud Roles   Disable Logs
    """
    if not chain:
        return ""
    mitre_line_bits = []
    label_line_bits = []
    for step in chain:
        mitre = step.get("mitre") or "—"
        label = _truncate(step.get("step") or "", 18)
        cell_width = max(len(mitre), len(label)) + 2
        mitre_line_bits.append(f"`{mitre.center(cell_width - 2)}`")
        label_line_bits.append(f"{label.center(cell_width - 2)}")
    arrow = "  ──▶  "
    mitre_line = arrow.join(mitre_line_bits)
    return "```\n" + mitre_line + "\n```"


def format_attack_path_analysis(
    findings: List[Dict[str, Any]],
    min_risk: str = "High",
) -> str:
    """
    Detailed kill-chain analysis section, appearing after the narrative.
    Shows how an attacker actually exploits each Critical/High-risk identity.

    Structure per identity:
        ### PATH N — Emoji Attack goal
        **Prerequisite:** compromise `name` (Owner + Global Administrator)
        **Kill chain:** `T1078.004` ──▶ `T1098.003` ──▶ `T1562.008`

        1. **Initial access** — prose (T1078.004)
        2. **{attack step}** — prose (Txxxx.yyy)
        3. …

        **Detect (Sentinel KQL):** ...
        **Prevent:** ...
    """
    threshold = _SEVERITY_ORDER.get(min_risk, _SEVERITY_ORDER["High"])
    relevant = [
        f for f in findings
        if _SEVERITY_ORDER.get(
            str(f.get("risk") or f.get("risk_level") or "Info"), 99,
        ) <= threshold
    ]
    if not relevant:
        return "### 🎯 Attack Path Analysis\n\n_No Critical or High-risk identities to analyze._"

    lines = ["### 🎯 Attack Path Analysis", ""]
    lines.append(
        f"How an attacker would actually exploit each "
        f"Critical/High-risk identity. **{len(relevant)}** attack paths below."
    )
    lines.append("")

    for idx, f in enumerate(relevant[:10], 1):
        chain = _kill_chain_for_finding(f)
        if not chain:
            continue

        name = f.get("display_name") or f.get("name") or f.get("principal_id") or "Unknown"
        pid_short = _short_id(f.get("principal_id"))
        ptype = _principal_type_display(f.get("principal_type"))
        risk = str(f.get("risk") or f.get("risk_level") or "High")
        emoji = _RISK_EMOJI.get(risk, "🟠")
        goal = chain[-1]["step"] if len(chain) > 1 else "Weaponize compromised identity"
        role = f.get("azure_role") or ""
        evidence = f.get("evidence") or {}
        entra = f.get("entra_roles") or evidence.get("entra_roles") or []
        role_phrase = _chain_prefix_from_role(role, entra)

        lines.append("---")
        lines.append("")
        lines.append(f"#### PATH {idx} — {emoji} {goal}")
        lines.append("")
        lines.append(f"**Prerequisite:** compromise **{name}** ( `{pid_short}` · {ptype} ) — wielding {role_phrase}")
        lines.append("")

        # ASCII kill-chain diagram
        diagram = _chain_ascii_diagram(chain)
        if diagram:
            lines.append("**Kill chain:**")
            lines.append(diagram)
            lines.append("")

        # Step-by-step prose
        lines.append("**Steps:**")
        for step_idx, step in enumerate(chain, 1):
            step_name = step.get("step") or ""
            mitre = step.get("mitre") or "—"
            prose = step.get("prose") or ""
            lines.append(f"{step_idx}. **{step_name}** (`{mitre}`) — {prose}")
        lines.append("")

        # Detection signal — take the last vector's signal, or the finding's own
        detection = None
        for step in reversed(chain):
            if step.get("detection_signal"):
                detection = step["detection_signal"]
                break
        if not detection:
            detection = f.get("detection_signal")
        if detection:
            lines.append("**Detect (Sentinel KQL):**")
            lines.append(f"```kusto\n{detection}\n```")
            lines.append("")

        # Prevention — last vector's remediation, or finding's own
        prevent = None
        for step in reversed(chain):
            if step.get("remediation"):
                prevent = step["remediation"]
                break
        if not prevent:
            prevent = f.get("remediation")
        if prevent:
            lines.append(f"**Prevent:** {prevent}")
            lines.append("")

    if len(relevant) > 10:
        lines.append(f"_…{len(relevant) - 10} more Critical/High-risk identities. See detailed findings above._")

    return "\n".join(lines)


def _render_narrative_entry(idx: int, f: Dict[str, Any]) -> List[str]:
    """Render one numbered narrative paragraph for a finding."""
    name = f.get("display_name") or f.get("name") or "Unknown"
    ptype = _principal_type_display(f.get("principal_type"))
    pid_short = _short_id(f.get("principal_id"))
    risk = str(f.get("risk") or f.get("risk_level") or "Info")
    emoji = _RISK_EMOJI.get(risk, "⚪")

    evidence = f.get("evidence") or {}
    guest_suffix = " (Guest)" if evidence.get("user_type") == "Guest" else ""

    entry = [
        f"**{idx}. {name}** — {ptype}{guest_suffix} "
        f"( `{pid_short}` ) — {emoji} **{risk}**",
        f"- **Role:** {_format_role_and_entra(f)}",
        f"- **Attack paths:** {_format_attack_paths_prose(f)}",
    ]

    # Optional deeper context — only if the tool has it, no invention
    if f.get("attack_name"):
        entry.append(f"- **Attack:** {f['attack_name']}")
    if f.get("remediation"):
        entry.append(f"- **Fix:** {f['remediation']}")

    entry.append("")
    return entry


def compact_identity_table(
    findings: List[Dict[str, Any]],
    subtitle: Optional[str] = None,
    header: str = "High-Privileged Identities",
    limit: int = 20,
) -> str:
    """
    Screenshot-style compact overview:
      ### 🛡 {header} — `{subtitle}`

      **N identities** hold high-privilege roles at `{scope}`.

      | # | Name | Type | Role | Scope | Risk | Notable attack paths |
      ...

    All the essentials on one page. Detailed cards render below in the
    same message but this is what you skim first.
    """
    if not findings:
        return f"### 🛡 {header}\n\n_No identities to show._"

    # Header + one-sentence summary
    lines: List[str] = []
    if subtitle:
        lines.append(f"### 🛡 {header} — `{subtitle}`")
    else:
        lines.append(f"### 🛡 {header}")
    lines.append("")

    n = len(findings)
    filt = None  # future: could accept a "role filter" label
    scope_hint = subtitle or "subscription"
    if filt:
        lines.append(f"**{n} identities** hold {filt} at scope `{scope_hint}`.")
    else:
        lines.append(f"**{n} identities** hold high-privilege roles at scope `{scope_hint}`.")
    lines.append("")

    # The 7-column table
    lines.append("| # | Name | Type | Role | Scope | Risk | Notable attack paths |")
    lines.append("|---|---|---|---|---|---|---|")

    shown = findings[:limit]
    for i, f in enumerate(shown, 1):
        name = _truncate(
            f.get("display_name") or f.get("name") or f.get("principal_id") or "—",
            40,
        )
        # Bold Critical identities to draw the eye (screenshot did the same)
        risk = str(f.get("risk") or f.get("risk_level") or "Info")
        if risk == "Critical":
            name_display = f"**{name}**"
        else:
            name_display = name

        # Guest badge inline with the name
        evidence = f.get("evidence") or {}
        if evidence.get("user_type") == "Guest":
            name_display = f"{name_display} `External`"

        ptype = _principal_type_display(f.get("principal_type"))
        role = f.get("azure_role") or "—"
        scope = _scope_tier_short(f.get("scope"))
        risk_display = f"{_RISK_EMOJI.get(risk, '⚪')} {risk}"
        attack_display = _attack_paths_inline(f, limit=3)

        lines.append(
            f"| {i} | {name_display} | {ptype} | {role} | {scope} | {risk_display} | {attack_display} |"
        )

    if n > limit:
        lines.append("")
        lines.append(f"_…{n - limit} more not shown in this table. See detailed sections below._")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Hero header + stat tiles (presentable summary at the very top)
# ---------------------------------------------------------------------------


def hero_stat_tiles(
    result: Dict[str, Any],
    title: str,
    subtitle: Optional[str] = None,
    extra_stat: Optional[tuple] = None,
) -> str:
    """
    Render a bold title + a 4-column stat-tile grid.

    Renders as a two-row markdown table so clients that support tables get a
    visual grid; clients that don't still see the numbers cleanly labeled.

    Structure:
        ### 🛡 {title}
        `{subtitle}`   (e.g. subscription id)

        |  |  |  |  |
        |:---:|:---:|:---:|:---:|
        | **N** | **N** | **N** | **N** |
        | 🔴 Critical | 🟠 High-risk | ⚫ Ghost / unresolved | 📋 Total findings |

    `extra_stat` is an optional (label, count, emoji) tuple that replaces the
    default "Total findings" tile — useful when a specific count matters more
    (e.g. "Owner assignments" for backdoor detection).
    """
    findings = result.get("findings") or result.get("identities") or \
               result.get("service_principals") or \
               result.get("guest_users_with_high_privilege") or \
               result.get("orphaned_role_assignments") or []

    n_crit  = sum(1 for f in findings if str(f.get("risk") or f.get("risk_level") or "") == "Critical")
    n_high  = sum(1 for f in findings if str(f.get("risk") or f.get("risk_level") or "") == "High")
    n_ghost = sum(
        1 for f in findings
        if f.get("principal_type") == "Unknown"
        or f.get("name") == "Unknown"
        or f.get("display_name") == "Unknown"
    )
    n_total = len(findings)

    if extra_stat is None:
        # Default: use Owner-role assignment count if any Owner is present, else total.
        n_owner = sum(
            1 for f in findings
            if str(f.get("azure_role") or "") == "Owner"
        )
        if n_owner:
            extra_stat = ("Owner assignments", n_owner, "🔴")
        else:
            extra_stat = ("Total findings", n_total, "📋")

    lines = [f"### 🛡 {title}"]
    if subtitle:
        lines.append("")
        lines.append(f"`{subtitle}`")
    lines.append("")

    # Two-row table: numbers on top, labels below.
    lines.append("|  |  |  |  |")
    lines.append("|:---:|:---:|:---:|:---:|")
    lines.append(
        f"| **{n_crit}** | **{n_high}** | **{n_ghost}** | **{extra_stat[1]}** |"
    )
    lines.append(
        f"| 🔴 Critical identities | 🟠 High-risk identities "
        f"| ⚪ Ghost / unresolved | {extra_stat[2]} {extra_stat[0]} |"
    )
    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Executive summary
# ---------------------------------------------------------------------------


def executive_summary(result: Dict[str, Any], title: str = "Analysis") -> str:
    findings = result.get("findings") or result.get("identities") or []
    total = len(findings)
    counts = Counter(str(f.get("risk") or "Info") for f in findings)

    # Only add the 📋 icon when caller didn't pass their own emoji.
    prefix = "" if any(c in title for c in "🔎📋🎯🛡🔬🏆") else "📋 "
    lines = [f"### {prefix}{title} — Executive Summary", ""]
    lines.append(f"- **Total findings:** {total}")
    for risk in ("Critical", "High", "Medium", "Low", "Info"):
        n = counts.get(risk, 0)
        if n:
            lines.append(f"- {_RISK_EMOJI[risk]} **{risk}:** {n}")

    filt = result.get("principal_type_filter")
    if filt:
        lines.append(f"- **Principal type filter:** `{filt}`")

    top_score = result.get("top_severity_score")
    if top_score:
        lines.append(f"- **Top severity score:** `{top_score}/100`")

    by_det = result.get("by_detector") or {}
    if by_det:
        active = [d for d, n in by_det.items() if n > 0]
        lines.append(f"- **Detectors that fired:** {len(active)} of {len(by_det)}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Top findings cards
# ---------------------------------------------------------------------------


def _identity_badge(f: Dict[str, Any]) -> str:
    """Return a short badge like 'External', 'SP', 'User' — placed next to the name."""
    evidence = f.get("evidence") or {}
    if evidence.get("user_type") == "Guest":
        return "`External`"
    ptype = f.get("principal_type")
    if ptype == "ServicePrincipal":
        return "`SP`"
    if ptype == "User":
        return "`User`"
    if ptype == "Group":
        return "`Group`"
    if ptype == "Unknown":
        return "`Ghost`"
    return ""


def _pill_tags(f: Dict[str, Any]) -> str:
    """
    Compose the pill-tag row for a finding:
      `Owner — subscription` · `Global Administrator` · `Principal type: User (Guest)` · `MITRE T1078.004` · `CIS Azure 1.24`
    """
    tags: List[str] = []
    evidence = f.get("evidence") or {}

    role = f.get("azure_role")
    scope = f.get("scope")
    if role and scope:
        tags.append(f"{role} — {_scope_short(scope)}")
    elif role:
        tags.append(str(role))

    # Entra directory roles — one pill each (short list)
    entra = evidence.get("entra_roles") or []
    for r in entra[:3]:
        tags.append(str(r))

    # Principal type — with Guest qualifier where relevant
    ptype = f.get("principal_type")
    if ptype:
        label = ptype
        if evidence.get("user_type") == "Guest":
            label = f"{ptype} (Guest)"
        tags.append(f"Principal type: {label}")

    # Duplicate assignment count if evidence says so
    dup = evidence.get("duplicate_count") or evidence.get("assignment_count")
    if isinstance(dup, int) and dup > 1:
        tags.append(f"Duplicate assignment ×{dup}")

    # MITRE — always prominent
    mitre = f.get("mitre_technique_id")
    if mitre:
        tags.append(f"MITRE {mitre}")

    # CIS controls — one pill each
    for c in (f.get("cis_controls") or [])[:3]:
        tags.append(str(c))

    return " · ".join(f"`{t}`" for t in tags)


def _attack_paths_arrows(f: Dict[str, Any], limit: int = 6) -> List[str]:
    """
    Return lines rendering the attack paths section with ➤ arrow prefix.
    Falls back to attack_vectors if attack_paths is empty.
    """
    lines: List[str] = []
    paths = f.get("attack_paths") or []

    if not paths:
        vectors = f.get("attack_vectors") or []
        for v in vectors[:limit]:
            name = v.get("attack_name") or ""
            tid = v.get("technique_id") or ""
            if name and tid:
                paths.append(f"{name} `{tid}`")
            elif name:
                paths.append(name)

    if not paths:
        return lines

    lines.append("")
    lines.append("**ATTACK PATHS**")
    for p in paths[:limit]:
        lines.append(f"- ➤ {p}")
    return lines


def _finding_card(idx: int, f: Dict[str, Any]) -> str:
    risk = str(f.get("risk") or f.get("risk_level") or "Info")
    emoji = _RISK_EMOJI.get(risk, "⚪")
    score = f.get("severity_score")
    conf = f.get("confidence")
    name = _truncate(f.get("display_name") or f.get("name") or f.get("principal_id") or "—", 60)
    detector = f.get("detector") or "—"
    attack = f.get("attack_name") or "—"

    # Header — prominent name + identity badge (External / SP / User / Ghost)
    badge = _identity_badge(f)
    header_bits = [f"#### {emoji} #{idx} · **{name}**"]
    if badge:
        header_bits.append(badge)
    body = [" ".join(header_bits)]

    # Pill tags row — role@scope, Entra roles, principal type, MITRE, CIS
    pills = _pill_tags(f)
    if pills:
        body.append(pills)

    # Severity + confidence + detector row
    meta_bits = []
    if score is not None:
        meta_bits.append(f"Severity `{_score_bar(int(score))}` **{score}/100**")
    if conf:
        meta_bits.append(f"Confidence `{conf}`")
    if detector and detector != "—":
        meta_bits.append(f"Detector `{detector}`")
    if meta_bits:
        body.append(" · ".join(meta_bits))

    if attack and attack != "—":
        body.append(f"\n> **Attack:** {attack}")

    # ATTACK PATHS with ➤ arrow prefix (the presentable version)
    body.extend(_attack_paths_arrows(f))

    ds = f.get("detection_signal")
    if ds:
        body.append("\n**Detection (Sentinel KQL):**")
        body.append(f"```kusto\n{ds}\n```")

    remediation = f.get("remediation")
    if remediation:
        body.append(f"> **Fix:** {remediation}")

    evidence = f.get("evidence") or {}
    if evidence:
        keys = list(evidence.keys())[:5]
        ev_pairs = []
        for k in keys:
            v = evidence[k]
            if isinstance(v, (list, dict)):
                v = str(v)[:60]
            ev_pairs.append(f"`{k}={_truncate(str(v), 40)}`")
        if ev_pairs:
            body.append("\n**Evidence:** " + " · ".join(ev_pairs))

    return "\n".join(body)


def findings_top_cards(findings: List[Dict[str, Any]], n: int = 5) -> str:
    if not findings:
        return "_No findings to show_"
    lines = [f"### 🎯 Top {min(n, len(findings))} Findings (by severity)", ""]
    for i, f in enumerate(findings[:n], 1):
        lines.append(_finding_card(i, f))
        lines.append("")
        # Add attack path diagram for the top 3 only (keeps output tight)
        if i <= 3:
            lines.append(attack_path_diagram(f))
            lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Findings table (full)
# ---------------------------------------------------------------------------


def findings_table(findings: List[Dict[str, Any]], limit: Optional[int] = 25) -> str:
    if not findings:
        return "_No findings_"

    rows = ["| # | Sev | Score | Detector | Principal | Role | Scope | MITRE | CIS |",
            "|---|---|---|---|---|---|---|---|---|"]
    shown = findings[: limit or len(findings)]
    for i, f in enumerate(shown, 1):
        risk = str(f.get("risk") or "Info")
        emoji = _RISK_EMOJI.get(risk, "⚪")
        score = f.get("severity_score", "—")
        detector = f.get("detector") or "—"
        principal = _truncate(f.get("display_name") or f.get("name") or f.get("principal_id"), 24)
        role = _truncate(f.get("azure_role") or f.get("granting_role") or "—", 20)
        scope = _scope_short(f.get("scope"))
        mitre = f.get("mitre_technique_id") or "—"
        cis = ", ".join(f.get("cis_controls") or []) or "—"
        rows.append(
            f"| {i} | {emoji} | `{score}` | `{detector}` | {principal} | {role} | {scope} | `{mitre}` | {cis} |"
        )
    if limit and len(findings) > limit:
        rows.append(f"\n_…{len(findings) - limit} more findings not shown. Use `mcp_top_findings` for the highest-severity subset._")
    return "\n".join(rows)


# ---------------------------------------------------------------------------
# Top-level result formatters (dispatch by shape)
# ---------------------------------------------------------------------------


def format_backdoor_result(result: Dict[str, Any]) -> str:
    findings = result.get("findings") or []
    sub_id = result.get("subscription_id") or result.get("scope")

    # ------------------------------------------------------------------
    # LAYER 1 — SUMMARY (for the expert who can act on numbers alone)
    # ------------------------------------------------------------------
    sections = [
        hero_stat_tiles(result, title="Backdoor Detection — Azure Subscription",
                        subtitle=sub_id),
        executive_summary(result, title="🔎 Backdoor Detection"),
        "\n### 📊 Severity Distribution\n",
        severity_histogram(findings),
        "\n### 🎯 MITRE ATT&CK for Cloud — Coverage\n",
        mitre_coverage_grid(findings),
    ]

    # ------------------------------------------------------------------
    # LAYER 2 — DETAILED EXPLANATION (grouped by severity, screenshot style)
    # ------------------------------------------------------------------
    sections.append("")
    sections.append(narrative_identity_list(
        findings,
        subtitle=sub_id,
        header="Detailed Findings",
        group_by_severity=True,
    ))

    # ------------------------------------------------------------------
    # LAYER 3 — ATTACK PATH ANALYSIS (kill-chain, MITRE-per-step)
    # ------------------------------------------------------------------
    sections.append("")
    sections.append(format_attack_path_analysis(findings, min_risk="High"))

    # ------------------------------------------------------------------
    # LAYER 4 — DEEP-DIVE (full cards + reference table)
    # ------------------------------------------------------------------
    sections.append("\n" + findings_top_cards(findings, n=5))
    sections.append("\n### 📋 All Findings\n")
    sections.append(findings_table(findings, limit=25))

    detector_errors = result.get("detector_errors") or {}
    if detector_errors:
        sections.append("\n### ⚠️ Detector Errors")
        for name, err in detector_errors.items():
            sections.append(f"- `{name}`: {_truncate(err, 120)}")
    return "\n".join(sections)


def format_identity_result(result: Dict[str, Any]) -> str:
    identities = result.get("identities") or result.get("service_principals") or \
                 result.get("guest_users_with_high_privilege") or \
                 result.get("orphaned_role_assignments") or []
    # Normalize into finding-shaped dicts for the top-cards / table helpers.
    findings = [
        {
            "risk": i.get("risk_level") or "High",
            "detector": "high_privileged_identity",
            "display_name": i.get("name"),
            "principal_id": i.get("principal_id"),
            "principal_type": i.get("principal_type"),
            "azure_role": i.get("azure_role"),
            "scope": i.get("scope"),
            "mitre_technique_id": (i.get("attack_vectors") or [{}])[0].get("technique_id") if i.get("attack_vectors") else None,
            "attack_name": (i.get("attack_vectors") or [{}])[0].get("attack_name") if i.get("attack_vectors") else None,
            "detection_signal": (i.get("attack_vectors") or [{}])[0].get("detection_signal") if i.get("attack_vectors") else None,
            "remediation": (i.get("attack_vectors") or [{}])[0].get("remediation") if i.get("attack_vectors") else None,
            "evidence": i.get("evidence"),
            # Preserve the fields the compact table + finding cards need.
            "attack_paths": i.get("attack_paths") or [],
            "attack_vectors": i.get("attack_vectors") or [],
            "entra_roles": i.get("entra_roles") or [],
        }
        for i in identities
    ]

    sub_id = result.get("subscription_id") or result.get("scope")

    # ------------------------------------------------------------------
    # LAYER 1 — SUMMARY (for the expert who can act on numbers alone)
    # ------------------------------------------------------------------
    sections = [
        hero_stat_tiles(
            {"findings": findings},
            title="High-Privileged Identities",
            subtitle=sub_id,
        ),
        executive_summary(
            {"findings": findings, "principal_type_filter": result.get("principal_type_filter")},
            title="🔎 High-Privileged Identities",
        ),
    ]

    # Principal-type breakdown (preserves "**N** ServicePrincipal" phrasing).
    ptypes = Counter(i.get("principal_type") for i in identities)
    if ptypes:
        sections.append("\n**By principal type:** " + " · ".join(
            f"**{n}** {t}" for t, n in ptypes.most_common()
        ))

    sections.append("\n### 📊 Severity Distribution\n")
    sections.append(severity_histogram(findings))

    # ------------------------------------------------------------------
    # LAYER 2 — DETAILED EXPLANATION (grouped by severity, screenshot style)
    # For anyone who wants to understand each finding rather than skim.
    # ------------------------------------------------------------------
    sections.append("")
    sections.append(narrative_identity_list(
        findings,
        subtitle=sub_id,
        header="Detailed Findings",
        group_by_severity=True,
    ))

    # ------------------------------------------------------------------
    # LAYER 3 — ATTACK PATH ANALYSIS (kill-chain, MITRE-per-step)
    # ------------------------------------------------------------------
    sections.append("")
    sections.append(format_attack_path_analysis(findings, min_risk="High"))

    # ------------------------------------------------------------------
    # LAYER 4 — DEEP-DIVE (full cards + reference table)
    # ------------------------------------------------------------------
    sections.append("\n" + findings_top_cards(findings, n=5))
    sections.append("\n### 📋 All Identities\n")
    sections.append(findings_table(findings, limit=25))
    return "\n".join(sections)


def format_attack_vector_analysis(result: Dict[str, Any]) -> str:
    principal = result.get("principal") or {}
    analysis = result.get("analysis") or {}
    vectors = analysis.get("attack_vectors") or []

    lines = [
        f"### 🔬 Attack Vector Analysis · {_truncate(principal.get('name') or principal.get('id'), 40)}",
        "",
        f"- **Principal ID:** `{principal.get('id')}`",
        f"- **Type:** {analysis.get('principal_type', 'Unknown')}",
        f"- **Attack vectors:** **{analysis.get('attack_vector_count', 0)}** across "
        f"**{len(analysis.get('unique_techniques') or [])}** unique techniques",
        f"- **Highest scope tier:** `{analysis.get('highest_scope_tier', '—')}`",
        "",
        "### 🎯 MITRE Techniques Covered",
        "",
        " · ".join(f"`{t}`" for t in (analysis.get("unique_techniques") or [])) or "_none_",
        "",
        "### 🛣 Attack Vectors",
        "",
    ]
    for i, v in enumerate(vectors[:15], 1):
        risk_emoji = _RISK_EMOJI.get(str(v.get("risk", "High")), "🟠")
        lines.append(
            f"{i}. {risk_emoji} `{v.get('technique_id', '—')}` **{v.get('attack_name', '—')}**  "
            f"— via `{v.get('granting_role', '—')}` @ `{_scope_short(v.get('granting_scope'))}`"
        )
        if v.get("primitive"):
            lines.append(f"   > {v['primitive']}")
    if len(vectors) > 15:
        lines.append(f"\n_…{len(vectors) - 15} more vectors_")
    return "\n".join(lines)


def format_hardening_result(result: Dict[str, Any], resource_kind: str = "Resource") -> str:
    items = result.get("items") or []
    findings: List[Dict[str, Any]] = []
    for item in items:
        for issue in (item.get("issues") or []):
            findings.append({
                "detector": f"{resource_kind.lower()}_hardening",
                "risk": _risk_for_issue(issue),
                "display_name": item.get("name"),
                "scope": item.get("resource_id"),
                "mitre_technique_id": (issue.get("mitre_technique_id") if isinstance(issue, dict) else None),
                "attack_name": (issue.get("issue") if isinstance(issue, dict) else str(issue)),
                "remediation": (issue.get("remediation") if isinstance(issue, dict) else None),
                "cis_controls": [issue.get("cis_control")] if isinstance(issue, dict) and issue.get("cis_control") else [],
            })

    lines = [f"### 🛡 {resource_kind} Hardening", ""]
    lines.append(f"- **{resource_kind}s scanned:** {len(items)}")
    lines.append(f"- **With issues:** {result.get('high_risk_count', sum(1 for i in items if i.get('issue_count')))}")
    lines.append(f"- **Total issues:** {len(findings)}")
    lines.append("")
    if findings:
        lines.append(severity_histogram(findings))
        lines.append("")
        lines.append(findings_table(findings, limit=20))
    else:
        lines.append("✅ _No hardening issues found_")
    return "\n".join(lines)


def _risk_for_issue(issue: Any) -> str:
    """Heuristic risk label based on the issue text."""
    if isinstance(issue, dict):
        text = str(issue.get("issue", "")).lower()
    else:
        text = str(issue).lower()
    if "public" in text or "disabled" in text or "allow" in text:
        return "High"
    if "weak tls" in text or "legacy" in text or "no expir" in text:
        return "Medium"
    return "Medium"


def format_attack_vectors_role_lookup(result: Dict[str, Any]) -> str:
    vectors = result.get("attack_vectors") or []
    role = result.get("role_name")
    scope = result.get("scope")
    lines = [
        f"### 🔎 Attack Vectors for `{role}`",
        "",
        f"- **Scope evaluated:** `{_scope_short(scope) if scope else 'any'}`",
        f"- **Vectors enabled:** **{len(vectors)}**",
        "",
    ]
    for i, v in enumerate(vectors, 1):
        lines.append(
            f"**{i}. `{v.get('technique_id')}` — {v.get('attack_name')}**  ({v.get('scope_tier')})"
        )
        lines.append(f"> {v.get('primitive', '')}")
        if v.get("detection_signal"):
            lines.append(f"```kusto\n{v['detection_signal']}\n```")
        if v.get("remediation"):
            lines.append(f"_Remediation: {v['remediation']}_")
        lines.append("")
    return "\n".join(lines)


def format_top_findings(result: Dict[str, Any]) -> str:
    findings = result.get("findings") or []
    n = result.get("top_n") or len(findings)
    lines = [f"### 🏆 Top {n} Findings by Severity", ""]
    if not findings:
        return "\n".join(lines) + "_No findings to rank._"
    lines.append(severity_histogram(findings))
    lines.append("")
    lines.append(findings_top_cards(findings, n=n))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------


def render(result: Dict[str, Any], hint: Optional[str] = None) -> str:
    """
    Auto-dispatch to the right formatter based on the tool result shape.
    `hint` is optionally set by the MCP wrapper for tools whose shape is
    ambiguous (e.g. list_web_apps vs list_key_vaults both return `items`).
    """
    if not isinstance(result, dict):
        return ""

    if hint == "backdoor" or ("by_detector" in result and "findings" in result):
        return format_backdoor_result(result)
    if hint == "identity" or "identities" in result or "service_principals" in result \
       or "guest_users_with_high_privilege" in result or "orphaned_role_assignments" in result:
        return format_identity_result(result)
    if hint == "attack_analysis" or ("principal" in result and "analysis" in result):
        return format_attack_vector_analysis(result)
    if hint == "role_lookup" or ("role_name" in result and "attack_vectors" in result):
        return format_attack_vectors_role_lookup(result)
    if hint == "top_findings" or "top_n" in result:
        return format_top_findings(result)
    if hint and hint.endswith("_hardening"):
        return format_hardening_result(result, resource_kind=hint.replace("_hardening", "").title())
    if "items" in result and result.get("items") and isinstance(result["items"], list):
        # Generic resource inventory — decide by fields on first item.
        first = result["items"][0]
        if "enable_soft_delete" in first or "access_policies" in first:
            return format_hardening_result(result, resource_kind="Key Vault")
        if "identity" in first and "boot_diagnostics" in first:
            return format_hardening_result(result, resource_kind="Virtual Machine")
        if "https_only" in first or "kind" in first:
            return format_hardening_result(result, resource_kind="App Service")
        if "allow_blob_public_access" in first:
            return format_hardening_result(result, resource_kind="Storage Account")
    return ""
