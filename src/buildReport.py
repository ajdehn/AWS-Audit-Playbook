from datetime import datetime, timezone
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, LETTER
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, ListFlowable, ListItem, PageBreak, KeepTogether
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

BASE_STYLES = getSampleStyleSheet()

# Define style constants
LABEL_STYLE = ParagraphStyle(name="Label", fontSize=9, fontName="Helvetica-Bold")
VALUE_STYLE = ParagraphStyle(name="Value", fontSize=9, fontName="Helvetica")
LIST_STYLE = ParagraphStyle(name="List", parent=VALUE_STYLE, spaceAfter=6)
CENTER_STYLE = ParagraphStyle(name="Center", parent=VALUE_STYLE, alignment=1)
HEADER_BG = colors.lightgrey
PASS_COLOR = "green"
FAIL_COLOR = "red"

"""
    Render 2-column control summary table.
"""
def render_control_summary(control, page_width):
    test_procedures = [
        Paragraph(f"{i+1}. {item}", LIST_STYLE)
        for i, item in enumerate(control.test_procedures)
    ]
    test_attributes = [
        Paragraph(f"• {item}", LIST_STYLE)
        for item in control.test_attributes
    ]

    # Conclusion
    conclusion = Paragraph(
        f"<font color='{PASS_COLOR if control.result else FAIL_COLOR}'><b>{'Pass' if control.result else 'Fail'}</b></font>",
        VALUE_STYLE
    )
    
    # Build summary table
    table_data = [ 
        [Paragraph("Control ID", LABEL_STYLE), Paragraph(control.control_id, VALUE_STYLE)], 
        [Paragraph("Control Description", LABEL_STYLE), Paragraph(control.control_description, VALUE_STYLE)],
        [Paragraph("Risk Rating", LABEL_STYLE), Paragraph(control.risk_rating_str, VALUE_STYLE)],
        [Paragraph("Test Procedures", LABEL_STYLE), test_procedures], 
        [Paragraph("Test Attributes", LABEL_STYLE), test_attributes],
        [Paragraph("Conclusion", LABEL_STYLE), conclusion],
    ]

        # Add row to summary table if control failed and result_description is populated.
    if not control.result and control.result_description:
        table_data.append([Paragraph("Comments", LABEL_STYLE), Paragraph(control.result_description, VALUE_STYLE)])

    table_width = page_width - 2 * 72
    table = Table(table_data, colWidths=[table_width * 0.25, table_width * 0.75])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.lightgrey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.black),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 6),
    ]))

    return table

"""
    Render sample results table (if present).
"""
def render_sample_table(control, page_width):
    if not control.table_headers:
        return None

    table_data = []
    # Header row
    table_data.append([
        Paragraph(h, LABEL_STYLE) for h in control.table_headers
    ])
    for i, sample in enumerate(control.samples, 1):
        row = []
        if control.include_sample_number:
            row.append(Paragraph(str(i), CENTER_STYLE))
        row.extend([
            Paragraph(str(v), VALUE_STYLE)
            for v in sample.sample_id.values()
        ])

        # Document Result
        if not sample.is_excluded:
            result_text = "Pass" if sample.result else "Fail"
            result_color = PASS_COLOR if sample.result else FAIL_COLOR
            row.append(Paragraph(f"<font color='{result_color}'>{result_text}</font>", CENTER_STYLE))
        else:
            sample.result = False
            row.append(Paragraph("Excluded", CENTER_STYLE))

        if not sample.result:
            # Fail control if one sample fails
            # TODO: Consider if this is necessary. I thought this would be completed in controlTesting.py
            control.result = False
            row.append(Paragraph(str(sample.comments), VALUE_STYLE))

        table_data.append(row)

    table_width = page_width - 2 * 72
    col_width = table_width / len(table_data[0]) # divide evenly across columns
    col_widths = [col_width] * len(table_data[0])
    table = Table(table_data, colWidths=col_widths)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))

    return table

def render_summary_page(controls, styles):
    """Build summary page with pass/fail counts."""
    total = len(controls)
    passed = sum(1 for c in controls if c.result)
    excluded = sum(1 for c in controls if c.is_excluded)
    failed = total - passed - excluded

    elements = []

    elements.append(Paragraph("Audit Summary", styles["Heading1"]))
    elements.append(Spacer(1, 12))

    summary_data = [
        ["Total Controls", str(total)],
        ["Passed", str(passed)],
        ["Failed", str(failed)],
        ["Out of Scope", str(excluded)],
    ]

    table = Table(summary_data, colWidths=[200, 100])

    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.lightgrey),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
        ("PADDING", (0, 0), (-1, -1), 6),
    ]))

    elements.append(table)
    elements.append(Spacer(1, 24))

    control_summary_data = []
    # Header row
    control_summary_data.append([
        Paragraph("Control ID", LABEL_STYLE), Paragraph("Control Description", LABEL_STYLE), 
        Paragraph("Results", LABEL_STYLE), Paragraph("Comments", LABEL_STYLE)
    ])
    # Detailed Findings
    for control in controls:
        row = []
        row.append(Paragraph(str(control.control_id), VALUE_STYLE))
        row.append(Paragraph(str(control.control_description), VALUE_STYLE))
        if control.is_excluded:
            control_result = "Out of Scope"
        else:     
            control_result = "Pass" if control.result else "Fail"
        row.append(Paragraph(control_result, VALUE_STYLE))
        # TODO: Add control exclusion rationale to table.
        row.append(Paragraph("", VALUE_STYLE))
        
        control_summary_data.append(row)

    table = Table(control_summary_data, colWidths=[100, 200, 100, 100])

    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
        ("PADDING", (0, 0), (-1, -1), 6),
    ]))

    elements.append(KeepTogether(table))
    elements.append(Spacer(1, 24))

    return elements


"""
Build audit report summarizing findings.

Structure:
    1. Header
    2. Summary Page
    3. Detailed Findings
        - Control Summary
        - Sample Findings
        - TODO: Exclusions (Option to select summary or detail version)
"""
def generate_pdf_report(audit, controls, tool_name, file_name="tmp/audit_report.pdf"):
    doc = SimpleDocTemplate(file_name, pagesize=letter,
    title=f"{tool_name} Audit Report", author="AJ Dehn", subject=f"Summarizes audit findings from {tool_name}")
    styles = getSampleStyleSheet()
    page_width, _ = LETTER
    elements = []

    # ---------------------------
    # Header
    # ---------------------------
    elements.append(Paragraph(f"{tool_name} Audit Report", styles["Title"]))
    elements.append(Spacer(1, 12))
    elements.append(
        Paragraph(
            f"<b>Date:</b> {datetime.now(timezone.utc).strftime('%Y-%m-%d')}",
            styles["Normal"]
        )
    )
    elements.append(Spacer(1, 12))

    # Summary Page
    elements.extend(render_summary_page(controls, styles))
    elements.append(PageBreak())

    # Detailed Findings
    for control in controls:
        if not control.is_excluded:
            summary_table = render_control_summary(control, page_width)
            elements.append(KeepTogether(summary_table))
            elements.append(Spacer(1, 16))
            sample_table = render_sample_table(control, page_width)
            if sample_table:
                elements.append(KeepTogether(sample_table))
                # Create new page if control includes sample table.
                elements.append(PageBreak())
            else:
                elements.append(Spacer(1, 30))

    doc.build(elements)
    print(f"Report generated: {file_name}")


def parse_dt(dt_str):
    if not dt_str:
        return None
    return datetime.fromisoformat(dt_str.replace("Z", "+00:00"))