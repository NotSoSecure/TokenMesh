from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from datetime import datetime


def generate_pdf_report(data):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"report_{timestamp}.pdf"

    doc = SimpleDocTemplate(filename)
    styles = getSampleStyleSheet()

    content = []

    # Title
    content.append(Paragraph("Azure Security Assessment Report", styles["Title"]))
    content.append(Spacer(1, 20))

    identities = data.get("identities", [])

    # Summary
    content.append(Paragraph(f"Total High Privileged Identities: {len(identities)}", styles["Heading2"]))
    content.append(Spacer(1, 10))

    # Detailed Section
    for idx, item in enumerate(identities, 1):
        text = f"""
        <b>Identity #{idx}</b><br/>
        Name: {item.get('name')}<br/>
        UPN: {item.get('upn')}<br/>
        Type: {item.get('type')}<br/>
        Azure Role: {item.get('azure_role')}<br/>
        Entra Roles: {', '.join(item.get('entra_roles', [])) or 'None'}<br/>
        Scope: {item.get('scope')}<br/>
        Risk Level: {item.get('risk_level')}<br/><br/>

        <b>Evidence:</b><br/>
        Role: {item.get('evidence', {}).get('role')}<br/>
        Principal Type: {item.get('evidence', {}).get('principal_type')}<br/><br/>

        <b>Attack Paths:</b><br/>
        {'<br/>'.join(item.get('attack_paths', []))}
        <br/><br/>
        """

        content.append(Paragraph(text, styles["Normal"]))
        content.append(Spacer(1, 12))

    doc.build(content)

    return {
        "status": "Report generated successfully",
        "file": filename
    }
