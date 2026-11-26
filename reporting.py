from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from xml.sax.saxutils import escape
from datetime import datetime

def create_case_report(case, evidence, artifacts, output):
    doc = SimpleDocTemplate(str(output), pagesize=A4, rightMargin=16*mm, leftMargin=16*mm, topMargin=16*mm, bottomMargin=16*mm)
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="Small", parent=styles["BodyText"], fontSize=8, leading=10))
    story = [
        Paragraph("Android Cybercrime Investigation Report", styles["Title"]),
        Paragraph("AI-Based Android Cybercrime Investigation and Mobile Evidence Analysis System", styles["Heading2"]),
        Spacer(1, 8),
        Paragraph(f"<b>Case:</b> {escape(case['case_code'])} — {escape(case['title'])}", styles["BodyText"]),
        Paragraph(f"<b>Investigator:</b> {escape(case['investigator'])}", styles["BodyText"]),
        Paragraph(f"<b>Created:</b> {escape(case['created_at'])}", styles["BodyText"]),
        Paragraph(f"<b>Description:</b> {escape(case.get('description') or '')}", styles["BodyText"]),
        Spacer(1, 12), Paragraph("1. Evidence inventory", styles["Heading1"])
    ]
    data = [["File", "Type", "Size (bytes)", "SHA-256"]]
    for e in evidence:
        data.append([e["original_name"][:35], e["file_type"], str(e["size"]), e["sha256"][:24] + "…"])
    t = Table(data, repeatRows=1, colWidths=[48*mm, 18*mm, 25*mm, 75*mm])
    t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#173451")),("TEXTCOLOR",(0,0),(-1,0),colors.white),
                           ("GRID",(0,0),(-1,-1),0.35,colors.grey),("FONTSIZE",(0,0),(-1,-1),7),("VALIGN",(0,0),(-1,-1),"TOP")]))
    story += [t, Spacer(1, 12), Paragraph("2. Analysis findings", styles["Heading1"])]
    for a in artifacts:
        story.append(Paragraph(f"<b>{escape(a['artifact_type'].upper())}</b> — {escape((a.get('content') or '')[:350])}", styles["BodyText"]))
        if a.get("indicator"):
            story.append(Paragraph(f"Indicator: {escape(a['indicator'])}; screening score: {a.get('risk_score')}%", styles["Small"]))
        story.append(Spacer(1, 5))
    story += [Spacer(1, 12), Paragraph("3. Interpretation and limitations", styles["Heading1"]),
              Paragraph("AI classifications and lexical indicators are investigative leads only. They do not establish criminal activity, identity, intent, or legal guilt. Findings require human review and corroboration. Evidence availability depends on acquisition method, Android version, application protections, device configuration and lawful access. This prototype does not guarantee deleted-data recovery and does not execute APK files.", styles["BodyText"]),
              Spacer(1, 10), Paragraph("Report generated: " + datetime.utcnow().isoformat() + " UTC", styles["Small"])]
    doc.build(story)
