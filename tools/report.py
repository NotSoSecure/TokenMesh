"""
PDF report renderer.

Detects the shape of the last analysis result and renders accordingly:
  - identities           -> high-privileged identity report
  - findings + by_detector -> backdoor detection report
  - analysis.attack_vectors -> per-identity attack surface report
  - items (KV vaults / VMs) -> resource inventory + issues report

One PDF per call. Filename encodes the timestamp.

All PDFs are written to the "reports" directory that lives alongside this
module (i.e. tools/reports/), so every report stays inside the tool's own
folder regardless of where the process was launched from.
"""

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


REPORTS_DIR = Path(__file__).resolve().parent / "reports"


def reports_dir() -> Path:
    """Directory every generated PDF lands in — always tools/reports/."""
    return REPORTS_DIR


def _styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="Small", fontSize=8, leading=10))
    styles.add(ParagraphStyle(name="Mono", fontName="Courier", fontSize=8, leading=10))
    return styles


def _summary_row(label: str, value: str, styles) -> List:
    return [Paragraph(f"<b>{label}</b>", styles["Small"]), Paragraph(str(value), styles["Small"])]


def _render_identity_section(content: List, data: Dict[str, Any], styles) -> None:
    identities = data.get("identities", [])
    content.append(Paragraph("High-Privileged Identities", styles["Heading1"]))
    filt = data.get("principal_type_filter")
    content.append(Paragraph(
        f"Count: {len(identities)} &nbsp;&nbsp; Principal type filter: {filt or 'None (all types)'}",
        styles["Small"],
    ))
    content.append(Spacer(1, 12))

    for idx, item in enumerate(identities, 1):
        header = (
            f"<b>#{idx}. {item.get('name') or 'Unknown'}</b> "
            f"({item.get('principal_type', 'Unknown')})"
        )
        content.append(Paragraph(header, styles["Heading3"]))

        summary = [
            _summary_row("Principal Type", item.get("principal_type"), styles),
            _summary_row("UPN", item.get("upn") or "-", styles),
            _summary_row("Azure Role", item.get("azure_role"), styles),
            _summary_row("Scope", item.get("scope"), styles),
            _summary_row("Risk", item.get("risk_level"), styles),
            _summary_row("Entra Roles", ", ".join(item.get("entra_roles") or []) or "None", styles),
        ]
        table = Table(summary, colWidths=[100, 400])
        table.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
        ]))
        content.append(table)

        vectors = item.get("attack_vectors") or []
        if vectors:
            content.append(Spacer(1, 4))
            content.append(Paragraph("<b>Attack Vectors</b>", styles["Small"]))
            rows = [["MITRE", "Attack", "Detection Signal", "Remediation"]]
            for v in vectors:
                rows.append([
                    v.get("technique_id", ""),
                    v.get("attack_name", ""),
                    v.get("detection_signal", "")[:200],
                    v.get("remediation", "")[:200],
                ])
            av_table = Table(rows, colWidths=[60, 100, 200, 140])
            av_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("FONTSIZE", (0, 0), (-1, -1), 7),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
            ]))
            content.append(av_table)

        content.append(Spacer(1, 12))


def _render_backdoor_section(content: List, data: Dict[str, Any], styles) -> None:
    findings = data.get("findings", [])
    content.append(Paragraph("Backdoor & Persistence Findings", styles["Heading1"]))
    content.append(Paragraph(
        f"Total: {len(findings)} &nbsp;&nbsp; "
        f"Principal type filter: {data.get('principal_type_filter') or 'None (all types)'}",
        styles["Small"],
    ))
    content.append(Spacer(1, 12))

    by_det = data.get("by_detector") or {}
    if by_det:
        content.append(Paragraph("<b>Findings by Detector</b>", styles["Heading3"]))
        rows = [["Detector", "Count"]]
        for det, count in sorted(by_det.items(), key=lambda kv: kv[1], reverse=True):
            rows.append([det, str(count)])
        t = Table(rows, colWidths=[300, 60])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
        ]))
        content.append(t)
        content.append(Spacer(1, 12))

    for idx, f in enumerate(findings, 1):
        risk = f.get("risk", "")
        risk_color = {"Critical": colors.red, "High": colors.orange, "Medium": colors.gold}.get(risk, colors.black)
        header = f"<b>#{idx}. [{f.get('detector', 'unknown')}] {f.get('attack_name', '')}</b>"
        content.append(Paragraph(header, styles["Heading3"]))
        content.append(Paragraph(
            f"<font color='{risk_color.hexval()}'>Risk: {risk}</font> &nbsp;&nbsp; MITRE: {f.get('mitre_technique_id', '-')}",
            styles["Small"],
        ))
        rows = [
            _summary_row("Principal Type", f.get("principal_type", "-"), styles),
            _summary_row("Display Name", f.get("display_name", "-"), styles),
            _summary_row("Principal ID", f.get("principal_id", "-"), styles),
            _summary_row("Scope", f.get("scope", "-"), styles),
            _summary_row("Detection Signal", f.get("detection_signal", "-"), styles),
            _summary_row("Remediation", f.get("remediation", "-"), styles),
        ]
        t = Table(rows, colWidths=[100, 400])
        t.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
        ]))
        content.append(t)
        content.append(Spacer(1, 10))


def _render_attack_analysis_section(content: List, data: Dict[str, Any], styles) -> None:
    principal = data.get("principal", {})
    analysis = data.get("analysis", {})
    content.append(Paragraph("Attack Vector Analysis", styles["Heading1"]))
    content.append(Paragraph(
        f"Principal: {principal.get('name') or 'Unknown'} ({analysis.get('principal_type', 'Unknown')})",
        styles["Small"],
    ))
    content.append(Paragraph(f"Principal ID: {principal.get('id')}", styles["Small"]))
    content.append(Paragraph(
        f"Attack vector count: {analysis.get('attack_vector_count', 0)} &nbsp;&nbsp; "
        f"Highest scope tier: {analysis.get('highest_scope_tier', '-')}",
        styles["Small"],
    ))
    content.append(Spacer(1, 12))

    vectors = analysis.get("attack_vectors") or []
    rows = [["MITRE", "Attack", "Granting Role", "Scope Tier", "Detection Signal"]]
    for v in vectors:
        rows.append([
            v.get("technique_id", ""),
            v.get("attack_name", ""),
            v.get("granting_role", "") or "-",
            v.get("scope_tier", ""),
            v.get("detection_signal", "")[:180],
        ])
    if len(rows) > 1:
        t = Table(rows, colWidths=[60, 100, 100, 60, 180])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
        ]))
        content.append(t)


def _render_resource_inventory_section(content: List, data: Dict[str, Any], styles, title: str) -> None:
    items = data.get("items", [])
    content.append(Paragraph(title, styles["Heading1"]))
    content.append(Paragraph(f"Count: {len(items)}", styles["Small"]))
    content.append(Spacer(1, 12))

    for item in items:
        name = item.get("name", "Unknown")
        content.append(Paragraph(f"<b>{name}</b>", styles["Heading3"]))
        summary = [
            _summary_row("Resource Group", item.get("resource_group", "-"), styles),
            _summary_row("Location", item.get("location", "-"), styles),
            _summary_row("Resource ID", item.get("resource_id", "-"), styles),
        ]
        content.append(Table(summary, colWidths=[100, 400]))
        issues = item.get("issues") or []
        if issues:
            content.append(Paragraph("<b>Issues</b>", styles["Small"]))
            for i in issues:
                if isinstance(i, dict):
                    txt = f"• [{i.get('mitre_technique_id', '-')}] {i.get('issue', '')} — {i.get('remediation', '')}"
                else:
                    txt = f"• {i}"
                content.append(Paragraph(txt, styles["Small"]))
        content.append(Spacer(1, 8))


def generate_pdf_report(data: Dict[str, Any]) -> Dict[str, str]:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"report_{timestamp}.pdf"

    out_dir = reports_dir()
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / filename

    # Two reports inside the same second would otherwise silently overwrite.
    seq = 1
    while path.exists():
        seq += 1
        filename = f"report_{timestamp}_{seq}.pdf"
        path = out_dir / filename

    doc = SimpleDocTemplate(str(path), pagesize=letter)
    styles = _styles()

    content: List = [Paragraph("Azure Security Assessment Report", styles["Title"]), Spacer(1, 20)]

    # Dispatch on data shape.
    if "identities" in data:
        _render_identity_section(content, data, styles)
    elif "service_principals" in data:
        # list_high_privileged_service_principals shape
        _render_identity_section(
            content,
            {"identities": data["service_principals"], "principal_type_filter": "ServicePrincipal"},
            styles,
        )
    elif "guest_users_with_high_privilege" in data:
        _render_identity_section(
            content,
            {"identities": data["guest_users_with_high_privilege"], "principal_type_filter": "User (Guest)"},
            styles,
        )
    elif "orphaned_role_assignments" in data:
        _render_identity_section(
            content,
            {"identities": data["orphaned_role_assignments"], "principal_type_filter": "Unknown"},
            styles,
        )
    elif "by_detector" in data or ("findings" in data and "detectors_run" in data):
        _render_backdoor_section(content, data, styles)
    elif "analysis" in data and "principal" in data:
        _render_attack_analysis_section(content, data, styles)
    elif "items" in data:
        first = data["items"][0] if data["items"] else {}
        if "enable_soft_delete" in first or "access_policies" in first:
            _render_resource_inventory_section(content, data, styles, "Key Vault Inventory")
        elif "identity" in first or "boot_diagnostics" in first:
            _render_resource_inventory_section(content, data, styles, "Virtual Machine Inventory")
        else:
            _render_resource_inventory_section(content, data, styles, "Resource Inventory")
    else:
        content.append(Paragraph(
            "No renderer matched this analysis shape. The tool result is embedded below.",
            styles["Normal"],
        ))
        content.append(Paragraph(str(data)[:5000], styles["Mono"]))

    doc.build(content)
    return {
        "status": "Report generated successfully",
        "file": filename,
        "directory": str(out_dir),
        "path": str(path),
    }
